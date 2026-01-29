//! LocInt - Local Incident Compiler (Thin Router)
//!
//! This is the refactored thin router version of locint.
//! All business logic has been moved to services/ and team/ modules.
//! Handlers are thin wrappers that delegate to service functions.
//!
//! **Architecture:**
//! - main() / run_server(): Entry point and server lifecycle
//! - build_locint_router(): Route registration only
//! - Handlers: Parse params, apply tier gate, call service, wrap response
//! - Services: All business logic in crates/server/src/services/*
//! - Team: Team tier logic in crates/server/src/team/*

// Hide console window on Windows release builds
#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use edr_server::server_core::{ShippedResources, StartupError};
use edr_server::flight_recorder::{
    self, InstanceIdentity, SharedFlightRecorder,
};
use edr_server::instance_lock::{InstanceLock, LockResult, InstanceConflictError};
use edr_server::db;
use edr_server::run_coverage;
use edr_server::playbook_scope::{
    PlaybookScope, PlaybookEvalResult, PlaybookEvalStatus, PlaybooksEvalResponse,
    EvalReasonCode, SlotEvalResult, SlotEvalStatus, VisibilitySummary, PermissionState,
    SlotSearchHints, ScopeMode, generate_narrative, MatchTrace, EvidenceRef,
};
use edr_server::services::{
    self,
    types::{ProductTier, RouteInfo, SharedState, LocintState},
};
use std::collections::HashMap;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

// ============================================================================
// ROUTE BINDINGS (Handler → Service Map)
// ============================================================================
//
// GET  /health                          -> health_handler (inline)
// GET  /api/health                      -> health_handler (inline)
// POST /api/run/start                   -> services::run_control
// POST /api/run/stop                    -> services::run_control
// GET  /api/run/status                  -> services::run_control
// GET  /api/run/metrics                 -> services::run_control
// GET  /api/runs                        -> services::run_control
// GET  /api/runs/:run_id                -> services::run_control
// POST /api/runs/:run_id/rename         -> services::run_control
// POST /api/runs/:run_id/delete         -> services::run_control
// POST /api/runs/:run_id/baseline       -> services::baseline (Pro)
// GET  /api/runs/:run_id/coverage       -> services::run_control
// GET  /api/runs/:run_id/changes        -> services::diff
// GET  /api/runs/:run_id/diff           -> services::diff
// GET  /api/runs/:run_id/playbooks      -> services::packs
// GET  /api/runs/:run_id/state          -> services::run_control
// GET  /api/runs/:run_id/next_steps     -> services::run_control
// GET  /api/runs/:run_id/case_summary   -> services::export_import (Pro)
// GET  /api/runs/:run_id/entities       -> services::run_control (Pro)
// GET  /api/runs/:run_id/pivot          -> services::run_control (Pro)
// POST /api/runs/:run_id/export/case_pack -> services::export_import (Pro)
// GET  /api/baselines                   -> services::baseline (Pro)
// GET  /api/signals                     -> services::signals
// GET  /api/signals/stats               -> services::signals
// GET  /api/signals/explainability_stats -> services::signals
// GET  /api/signals/:id                 -> services::signals
// GET  /api/signals/:id/explain         -> services::signals
// GET  /api/app/state                   -> services::meta
// POST /api/app/restart_admin           -> platform (inline)
// GET  /api/selfcheck                   -> services::capability
// GET  /api/capability/status           -> services::capability
// GET  /api/capability/detection_plan   -> services::capability
// GET  /api/capability/gaps             -> services::capability (Dev)
// GET  /api/playbooks/catalog           -> services::packs
// GET  /api/features                    -> services::meta
// GET  /api/capture/profiles            -> services::meta
// POST /api/export/bundle               -> services::export_import
// POST /api/import/bundle               -> services::export_import
// POST /api/import/validate             -> services::export_import
// GET  /api/packs                       -> services::packs
// GET  /api/packs/:pack_name            -> services::packs
// POST /api/packs/rescan                -> services::packs
// GET  /api/evidence/deref              -> services::evidence
// GET  /api/meta/routes                 -> services::meta
// GET  /api/meta/contract               -> services::meta
// GET  /api/meta/features               -> services::meta
// GET  /api/meta/dataflow_snapshot      -> services::meta (Dev)
// GET  /api/run/debug_counts            -> services::run_control (Dev)
// GET  /api/team/store/status           -> team::store (Team)
// POST /api/team/store/configure        -> team::store (Team)
// GET  /api/team/cases                  -> team::cases (Team)
// POST /api/team/cases                  -> team::cases (Team)
// GET  /api/team/cases/:case_id         -> team::cases (Team)
// GET  /api/team/cases/:case_id/aggregate -> team::aggregate (Team)
// POST /api/team/cases/:case_id/tags    -> team::cases (Team)
// POST /api/team/cases/:case_id/notes   -> team::cases (Team)
// POST /api/team/cases/:case_id/publish_run -> team::publish (Team)
// POST /api/team/cases/:case_id/import_run  -> team::publish (Team)
//
// ============================================================================

fn main() {
    // Step 1: Resolve and validate shipped resources
    let resources = match ShippedResources::resolve() {
        Ok(r) => r,
        Err(e) => {
            show_error("Startup Error", &e);
            std::process::exit(1);
        }
    };
    
    let missing = resources.validate();
    if !missing.is_empty() {
        let err = StartupError::MissingResources(missing);
        show_error("Missing Resources", &err.to_string());
        std::process::exit(1);
    }
    
    // Step 2: Set environment variables for child processes
    std::env::set_var("EDR_CAPTURE_BINARY", &resources.capture_binary);
    std::env::set_var("EDR_LOCALD_BINARY", &resources.locald_binary);
    std::env::set_var("EDR_PLAYBOOKS_DIR", &resources.playbooks_dir);
    std::env::set_var("EDR_UI_DIR", &resources.ui_dir);
    
    // Step 3: Build server config with optional UI dir override
    let port: u16 = std::env::var("EDR_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    
    let mut config = resources.to_server_config(port);
    
    // UI_SYNC_HARDENED-1: Dev mode serving - LOCINT_DEV_UI=1 serves directly from repo ui/
    // This ensures UI changes are instantly reflected without manual sync
    let dev_ui_mode = std::env::var("LOCINT_DEV_UI").map(|v| v == "1").unwrap_or(false);
    if dev_ui_mode {
        // Find repo root by looking for Cargo.toml upward from exe
        if let Some(repo_root) = find_repo_root(&resources.exe_dir) {
            let source_ui = repo_root.join("ui");
            if source_ui.exists() && source_ui.join("index.html").exists() {
                eprintln!("[UI] ==========================================");
                eprintln!("[UI] DEV MODE: Serving from source ui/");
                eprintln!("[UI] Path: {:?}", source_ui);
                eprintln!("[UI] ==========================================");
                config.ui_dir = source_ui;
            } else {
                eprintln!("[UI] WARN: LOCINT_DEV_UI=1 but repo ui/ not found at {:?}", source_ui);
            }
        } else {
            eprintln!("[UI] WARN: LOCINT_DEV_UI=1 but couldn't find repo root (no Cargo.toml)");
        }
    }
    
    // UI dir override - LOCINT_UI_DIR takes precedence over dev mode
    // This allows pointing to a specific UI directory for debugging
    if let Ok(override_ui_dir) = std::env::var("LOCINT_UI_DIR") {
        let override_path = std::path::PathBuf::from(&override_ui_dir);
        eprintln!("[UI] LOCINT_UI_DIR override detected: {:?}", override_path);
        config.ui_dir = override_path;
    } else if !dev_ui_mode {
        // Only check EDR_UI_DIR if not in dev mode
        if let Ok(override_ui_dir) = std::env::var("EDR_UI_DIR") {
            // Only use EDR_UI_DIR if it differs from the default (resources.ui_dir)
            let override_path = std::path::PathBuf::from(&override_ui_dir);
            if override_path != resources.ui_dir {
                eprintln!("[UI] EDR_UI_DIR override detected: {:?}", override_path);
                config.ui_dir = override_path;
            }
        }
    }
    
    // Step 4: Create data directory
    if let Err(e) = std::fs::create_dir_all(&config.data_dir) {
        let err = StartupError::DataDirCreation {
            path: config.data_dir.clone(),
            error: e.to_string(),
        };
        show_error("Data Directory Error", &err.to_string());
        std::process::exit(1);
    }
    
    // Step 5: SINGLE-INSTANCE LOCK (prevent split-brain)
    let instance_lock = match InstanceLock::try_acquire(&config.data_dir, port) {
        LockResult::Acquired(lock) => {
            tracing::info!("Instance lock acquired");
            Some(lock)
        }
        LockResult::StaleCleanedUp(lock) => {
            tracing::info!("Cleaned up stale instance lock");
            Some(lock)
        }
        LockResult::Conflict(existing) => {
            let err = InstanceConflictError::new(&existing);
            let ui_url = format!("{}ui/", existing.api_base.trim_end_matches("/api"));
            tracing::info!("Another instance detected at {}, attempting to open", ui_url);
            let _ = open::that(&ui_url);
            show_error(
                "Another Instance Running",
                &format!(
                    "{}\n\nExisting instance:\n  Port: {}\n  PID: {}\n  URL: {}\n\nOpening existing instance in browser...",
                    err.message, err.existing_port, err.existing_pid, ui_url
                ),
            );
            std::process::exit(0);
        }
        LockResult::Error(e) => {
            tracing::warn!("Failed to acquire instance lock: {}", e);
            None
        }
    };
    
    // Step 6: Initialize logging to file
    let log_path = resources.exe_dir.join("locint.log");
    init_file_logging(&log_path);
    
    tracing::info!("LocInt starting...");
    
    // === UI ORIGIN PROOF (UI_ORIGIN_PROOF-1) ===
    let exe_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let ui_index_path = config.ui_dir.join("index.html");
    let ui_app_js_path = config.ui_dir.join("app.js");
    let ui_index_exists = ui_index_path.exists();
    let ui_app_js_exists = ui_app_js_path.exists();
    
    tracing::info!("[UI] exe_path={}", exe_path);
    tracing::info!("[UI] ui_dir={:?}", config.ui_dir);
    tracing::info!("[UI] index={:?} (exists={})", ui_index_path, ui_index_exists);
    tracing::info!("[UI] app.js={:?} (exists={})", ui_app_js_path, ui_app_js_exists);
    
    if let Ok(override_val) = std::env::var("LOCINT_UI_DIR") {
        tracing::info!("[UI] LOCINT_UI_DIR override active: {}", override_val);
    } else if let Ok(override_val) = std::env::var("EDR_UI_DIR") {
        tracing::info!("[UI] EDR_UI_DIR override active: {}", override_val);
    }
    // === END UI ORIGIN PROOF ===
    
    tracing::info!("Data dir: {:?}", config.data_dir);
    tracing::info!("Port: {}", config.port);
    
    // Step 7: Run the async server
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");
    
    if let Err(e) = rt.block_on(run_server(config, instance_lock)) {
        show_error("Server Error", &e.to_string());
        std::process::exit(1);
    }
}

/// Run the server (same as edr-server but with GUI error handling)
async fn run_server(
    config: edr_server::server_core::ServerConfig,
    _instance_lock: Option<InstanceLock>,
) -> Result<(), StartupError> {
    // Initialize flight recorder FIRST
    let flight_recorder = flight_recorder::create_flight_recorder(&config.data_dir, config.port);
    
    // Record boot event
    let pid = std::process::id();
    let exe_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let is_admin = is_elevated();
    
    flight_recorder.record_boot(InstanceIdentity {
        pid,
        port: config.port,
        is_admin,
        exe_path,
        api_base: format!("http://127.0.0.1:{}/api", config.port),
        ui_origin: format!("http://127.0.0.1:{}/ui/", config.port),
        data_dir: config.data_dir.display().to_string(),
        started_at: chrono::Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    });
    
    tracing::info!("Flight recorder initialized: {}", flight_recorder.file_path().display());
    
    let db_path = config.data_dir.join("workbench.db");
    tracing::info!("Database: {:?}", db_path);
    
    // Check if port fallback is enabled (dev mode only)
    // In production, we want hard fail with PID diagnostic for port conflicts
    let port_fallback_enabled = std::env::var("LOCINT_DEV_PORT_FALLBACK")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);
    
    // Bind to port - try fallback ports only if LOCINT_DEV_PORT_FALLBACK=1
    let ports_to_try: Vec<u16> = if port_fallback_enabled {
        vec![config.port, config.port + 1, config.port + 2, config.port + 3]
    } else {
        vec![config.port]  // Production: only try the configured port
    };
    let mut bound_port = config.port;
    let mut listener_opt: Option<tokio::net::TcpListener> = None;
    let mut last_error = String::new();
    
    for port in ports_to_try.iter().copied() {
        let addr = format!("0.0.0.0:{}", port);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => {
                if port != config.port {
                    tracing::warn!("Primary port {} unavailable, using fallback port {}", config.port, port);
                }
                bound_port = port;
                listener_opt = Some(l);
                break;
            }
            Err(e) => {
                let port_diag = diagnose_port_owner(port);
                tracing::warn!("Port {} bind failed: {} - {}", port, e, port_diag.lines().next().unwrap_or(""));
                last_error = format!("{}\n\nPort diagnostics:\n{}", e, port_diag);
            }
        }
    }
    
    let listener = match listener_opt {
        Some(l) => l,
        None => {
            tracing::error!("All ports {:?} unavailable", ports_to_try);
            return Err(StartupError::PortInUse {
                port: config.port,
                error: format!("All ports {:?} in use.\n\n{}", ports_to_try, last_error),
            });
        }
    };
    
    // Update config.port to the actual bound port for the rest of startup
    let config = edr_server::server_core::ServerConfig { port: bound_port, ..config };
    
    // Build router with CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    
    let app = build_locint_router(&config, flight_recorder).layer(cors);
    
    let ui_url = format!("http://127.0.0.1:{}/ui/", config.port);
    
    // Debug-only: Log route count and contract hash for quick parity verification
    #[cfg(debug_assertions)]
    {
        let routes = services::meta::get_registered_routes();
        let contract = services::meta::get_api_contract();
        tracing::debug!(
            "Contract parity check: routes={}, version={}, hash={}",
            routes.len(),
            contract["contract_version"].as_str().unwrap_or("?"),
            contract["contract_hash"].as_str().unwrap_or("?")
        );
    }
    
    // Auto-open browser - try multiple methods for reliability
    // When running elevated (admin), open::that may fail, so use cmd fallback
    tracing::info!("Opening browser: {}", ui_url);
    let browser_opened = open::that(&ui_url).is_ok() || {
        // Fallback: use cmd /c start which works better when elevated
        #[cfg(target_os = "windows")]
        {
            std::process::Command::new("cmd")
                .args(["/c", "start", "", &ui_url])
                .spawn()
                .is_ok()
        }
        #[cfg(not(target_os = "windows"))]
        false
    };
    
    if !browser_opened {
        tracing::warn!("Failed to open browser. Navigate to {} manually.", ui_url);
    }
    
    // Log chain registry at startup
    let chain_count = services::chains::get_chain_count();
    tracing::info!("[CHAINS] Registry loaded {} chains", chain_count);
    tracing::info!("[STEP_STATUS] Backend-canonical step satisfaction enabled (GET /api/runs/:run_id/step_status)");
    
    tracing::info!("Server listening on 0.0.0.0:{}", config.port);
    
    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| StartupError::Other(format!("Server error: {}", e)))?;
    
    Ok(())
}

/// Build the locint router - THIN LAYER
/// 
/// All routes are registered here. Handlers delegate to services.
fn build_locint_router(
    config: &edr_server::server_core::ServerConfig,
    flight_recorder: SharedFlightRecorder,
) -> Router {
    // Open database
    let db_path = config.data_dir.join("workbench.db");
    let db = edr_server::db::Database::open(&db_path)
        .expect("Failed to open database");
    
    // Create supervisor with flight recorder
    let supervisor = edr_server::supervisor::Supervisor::with_flight_recorder(
        config.data_dir.clone(),
        flight_recorder.clone(),
    );
    
    // Shared state
    let state = Arc::new(LocintState {
        data_dir: config.data_dir.clone(),
        ui_dir: config.ui_dir.clone(),
        exe_dir: config.exe_dir.clone(),
        port: config.port,
        supervisor,
        db,
        flight_recorder,
    });
    
    Router::new()
        // Root redirect
        .route("/", get(|| async { axum::response::Redirect::to("/ui/") }))
        // Health
        .route("/health", get(health_handler))
        .route("/api/health", get(health_handler))
        // Run control
        .route("/api/run/start", post(run_start_handler))
        .route("/api/run/stop", post(run_stop_handler))
        .route("/api/run/status", get(run_status_handler))
        .route("/api/run/metrics", get(run_metrics_handler))
        // Runs CRUD
        .route("/api/runs", get(list_runs_handler))
        .route("/api/runs/:run_id", get(get_run_handler))
        .route("/api/runs/:run_id/rename", post(rename_run_handler))
        .route("/api/runs/:run_id/delete", post(delete_run_handler))
        .route("/api/runs/:run_id/baseline", post(set_baseline_handler))
        .route("/api/runs/:run_id/coverage", get(run_coverage_handler))
        .route("/api/runs/:run_id/facts", get(run_facts_handler))
        .route("/api/runs/:run_id/facts/resolve", post(facts_resolve_handler))
        .route("/api/runs/:run_id/evidence_summary", get(run_evidence_summary_handler))
        .route("/api/runs/:run_id/brief", get(run_brief_handler))
        // Evidence Browse Modes - canonical surfaces for events/signals/segments
        .route("/api/runs/:run_id/events", get(run_events_handler))
        .route("/api/runs/:run_id/signals", get(run_signals_handler))
        .route("/api/runs/:run_id/segments", get(run_segments_handler))
        .route("/api/runs/:run_id/changes", get(run_changes_handler))
        .route("/api/runs/:run_id/discovery_summary", get(run_discovery_summary_handler))
        .route("/api/runs/:run_id/diff", get(run_diff_v2_handler))
        .route("/api/runs/:run_id/playbooks", get(run_playbooks_handler))
        .route("/api/runs/:run_id/playbooks/eval", get(run_playbooks_eval_handler))
        .route("/api/runs/:run_id/state", get(run_state_handler))
        .route("/api/runs/:run_id/next_steps", get(run_next_steps_handler))
        .route("/api/runs/:run_id/case_summary", get(case_summary_handler))
        // Pro: Entity Explorer
        .route("/api/runs/:run_id/entities", get(run_entities_handler))
        .route("/api/runs/:run_id/pivot", get(run_pivot_handler))
        .route("/api/runs/:run_id/export/case_pack", post(export_case_pack_handler))
        // Baselines
        .route("/api/baselines", get(list_baselines_handler))
        // Signals
        .route("/api/signals", get(signals_handler))
        .route("/api/signals/stats", get(signal_stats_handler))
        .route("/api/signals/explainability_stats", get(explainability_stats_handler))
        .route("/api/signals/:id", get(get_signal_handler))
        .route("/api/signals/:id/explain", get(signal_explain_handler))
        // App state
        .route("/api/app/state", get(app_state_handler))
        .route("/api/app/restart_admin", post(restart_admin_handler))
        // Selfcheck
        .route("/api/selfcheck", get(selfcheck_handler))
        // Capability Model
        .route("/api/capability/status", get(capability_status_handler))
        .route("/api/capability/detection_plan", get(capability_detection_plan_handler))
        .route("/api/capability/gaps", get(capability_gaps_handler))
        // Micro Chains (canonical backend source of truth)
        .route("/api/chains", get(chains_list_handler))
        .route("/api/chains/compile", post(chains_compile_handler))
        // Run Step Status (backend-canonical satisfaction)
        .route("/api/runs/:run_id/step_status", get(run_step_status_handler))
        // Playbook catalog
        .route("/api/playbooks/catalog", get(playbooks_catalog_handler))
        .route("/api/playbooks/:playbook_id/yaml", get(playbook_yaml_handler))
        .route("/api/playbooks/:playbook_id/duplicate", post(playbook_duplicate_handler))
        // Playbook selection (presets and defaults)
        .route("/api/playbooks/presets", get(playbook_presets_handler))
        .route("/api/playbooks/selection", get(get_playbook_selection_handler))
        .route("/api/playbooks/selection", post(save_playbook_selection_handler))
        // Features
        .route("/api/features", get(features_handler))
        .route("/api/capture/profiles", get(capture_profiles_handler))
        // Export/Import
        .route("/api/export/bundle", post(export_bundle_handler))
        .route("/api/import/bundle", post(import_bundle_handler))
        .route("/api/import/validate", post(import_validate_handler))
        // Content packs
        .route("/api/packs", get(list_packs_handler))
        .route("/api/packs/:pack_name", get(get_pack_handler))
        .route("/api/packs/rescan", post(rescan_packs_handler))
        // Evidence
        .route("/api/evidence/deref", get(evidence_deref_handler))
        // Meta
        .route("/api/meta/routes", get(meta_routes_handler))
        .route("/api/meta/contract", get(meta_contract_handler))
        .route("/api/meta/features", get(meta_features_handler))
        .route("/api/meta/dataflow_snapshot", get(dataflow_snapshot_handler))
        .route("/api/meta/ui_dir", get(meta_ui_dir_handler))
        // Debug (dev only)
        .route("/api/run/debug_counts", get(debug_counts_handler))
        // Team Case Store (Team tier)
        .route("/api/team/store/status", get(team_store_status_handler))
        .route("/api/team/store/configure", post(team_store_configure_handler))
        .route("/api/team/cases", get(team_list_cases_handler))
        .route("/api/team/cases", post(team_create_case_handler))
        .route("/api/team/cases/:case_id", get(team_get_case_handler))
        .route("/api/team/cases/:case_id/aggregate", get(team_case_aggregate_handler))
        .route("/api/team/cases/:case_id/tags", post(team_update_tags_handler))
        .route("/api/team/cases/:case_id/notes", post(team_add_note_handler))
        .route("/api/team/cases/:case_id/publish_run", post(team_publish_run_handler))
        .route("/api/team/cases/:case_id/import_run", post(team_import_run_handler))
        // Static UI with no-cache headers for dev mode (UI_ORIGIN_PROOF-1)
        .nest_service("/ui", 
            ServeDir::new(&config.ui_dir)
                .append_index_html_on_directories(true)
        )
        .layer(axum::middleware::from_fn(dev_no_cache_middleware))
        .with_state(state)
}

// ============================================================================
// Dev Mode Cache Control (UI_ORIGIN_PROOF-1)
// ============================================================================

/// Middleware that adds Cache-Control: no-store headers for /ui/* requests
/// This prevents browser caching issues during development
async fn dev_no_cache_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_string();
    let mut response = next.run(req).await;
    
    // Only apply no-cache to /ui/* paths
    if path.starts_with("/ui/") {
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
        );
        response.headers_mut().insert(
            axum::http::header::PRAGMA,
            axum::http::HeaderValue::from_static("no-cache"),
        );
    }
    
    response
}

// ============================================================================
// Route Registry for UI Wiring Audit
// ============================================================================

/// Returns authoritative list of all registered API routes.
fn get_registered_routes() -> Vec<RouteInfo> {
    services::meta::get_registered_routes()
}

// ============================================================================
// Tier Gating Helpers
// ============================================================================

/// Resolve current tier from environment/license
fn resolve_current_tier() -> ProductTier {
    services::types::resolve_current_tier()
}

/// Helper to return 403 with FEATURE_LOCKED body
fn feature_locked_403(feature: &str, required_tier: ProductTier) -> (StatusCode, Json<serde_json::Value>) {
    services::types::feature_locked_403(feature, required_tier)
}

// ============================================================================
// Platform Helpers (must remain in binary)
// ============================================================================

/// Initialize file-based logging
fn init_file_logging(log_path: &std::path::Path) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .expect("Failed to open log file");
    
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(file).with_ansi(false))
        .init();
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl+c");
    tracing::info!("Shutdown signal received");
}

#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        
        let result = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        );
        
        result != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(target_os = "windows"))]
fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Diagnose what process owns a port when bind fails
/// Uses netstat to find the owning PID and process name
#[cfg(target_os = "windows")]
fn diagnose_port_owner(port: u16) -> String {
    use std::process::Command;
    
    // Run netstat to find what's using the port
    let output = match Command::new("netstat")
        .args(["-ano"])
        .output() {
        Ok(o) => o,
        Err(e) => return format!("Failed to run netstat: {}", e),
    };
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let port_str = format!(":{}", port);
    
    let mut results = Vec::new();
    let mut pids_seen = std::collections::HashSet::new();
    
    for line in stdout.lines() {
        if line.contains(&port_str) {
            results.push(line.trim().to_string());
            // Extract PID from end of line
            if let Some(pid_str) = line.split_whitespace().last() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    pids_seen.insert(pid);
                }
            }
        }
    }
    
    if results.is_empty() {
        return format!(
            "No process found listening on port {}.\n\
             This may be TIME_WAIT connections from a recently closed process.\n\
             Wait 30-60 seconds or use a different port (EDR_SERVER_PORT env var).",
            port
        );
    }
    
    // Get process names for the PIDs
    let mut pid_info = Vec::new();
    for pid in &pids_seen {
        if *pid == 0 {
            continue; // System idle process
        }
        let proc_name = get_process_name(*pid).unwrap_or_else(|| "unknown".to_string());
        pid_info.push(format!("PID {} = {}", pid, proc_name));
    }
    
    format!(
        "Port {} is in use:\n{}\n\nProcess info:\n{}",
        port,
        results.join("\n"),
        pid_info.join("\n")
    )
}

#[cfg(target_os = "windows")]
fn get_process_name(pid: u32) -> Option<String> {
    use std::process::Command;
    
    // Use tasklist to get process name
    let output = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
        .output()
        .ok()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    // CSV format: "process.exe","PID","Session Name","Session#","Mem Usage"
    let first_line = stdout.lines().next()?;
    let name = first_line.split(',').next()?;
    Some(name.trim_matches('"').to_string())
}

#[cfg(not(target_os = "windows"))]
fn diagnose_port_owner(port: u16) -> String {
    use std::process::Command;
    
    // Try lsof or ss on Unix
    let output = Command::new("lsof")
        .args(["-i", &format!(":{}", port)])
        .output()
        .or_else(|_| {
            Command::new("ss")
                .args(["-tlnp", &format!("sport = :{}", port)])
                .output()
        });
    
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.trim().is_empty() {
                format!("No process found on port {}. May be TIME_WAIT.", port)
            } else {
                format!("Port {} in use:\n{}", port, stdout)
            }
        }
        Err(e) => format!("Failed to diagnose port: {}", e),
    }
}

/// Show error dialog on Windows, print to stderr on other platforms
fn show_error(title: &str, message: &str) {
    eprintln!("ERROR [{}]: {}", title, message);
    
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr::null_mut;
        
        let wide_msg: Vec<u16> = OsStr::new(message)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let wide_title: Vec<u16> = OsStr::new(&format!("LocInt - {}", title))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        
        unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
                null_mut(),
                wide_msg.as_ptr(),
                wide_title.as_ptr(),
                windows_sys::Win32::UI::WindowsAndMessaging::MB_OK
                    | windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONERROR,
            );
        }
    }
}

/// Find repository root by looking for Cargo.toml upward from a starting directory
/// UI_SYNC_HARDENED-1: Used to locate source ui/ for dev mode serving
fn find_repo_root(start: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut current = start.to_path_buf();
    // Walk up to 10 levels (enough for target/release/build/... depth)
    for _ in 0..10 {
        if current.join("Cargo.toml").exists() && current.join("ui").exists() {
            return Some(current);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

// ============================================================================
// Debug Guardrails (scope violation detection)
// ============================================================================

/// Debug-only: Warn when a run-scoped handler calls live capability probes.
/// This catches SSoT violations where run handlers use /api/selfcheck data
/// instead of run_meta.json readiness_snapshot.
#[cfg(debug_assertions)]
fn debug_warn_live_probe_in_run_scope(handler_name: &str, run_id: &str) {
    tracing::warn!(
        target: "scope_guard",
        "⚠️ SCOPE VIOLATION: {} (run={}) called live capability probe. \
         Run-scoped handlers should use run_meta.json readiness_snapshot, not live probes.",
        handler_name, run_id
    );
}

/// Release stub - no-op in release builds
#[cfg(not(debug_assertions))]
fn debug_warn_live_probe_in_run_scope(_handler_name: &str, _run_id: &str) {}

// ============================================================================
// Handler Stubs - TODO: Implement with service calls
// ============================================================================

// Health (inline - no service needed)
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "success": true,
        "data": {
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "binary": "locint"
        }
    }))
}

// Meta handlers (inline - use services::meta)
async fn meta_routes_handler() -> Json<serde_json::Value> {
    let routes = get_registered_routes();
    Json(serde_json::json!({
        "success": true,
        "data": routes
    }))
}

async fn meta_contract_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "success": true,
        "data": services::meta::get_api_contract()
    }))
}

async fn meta_features_handler() -> Json<serde_json::Value> {
    let tier = resolve_current_tier();
    Json(serde_json::json!({
        "success": true,
        "data": services::meta::get_feature_flags(tier)
    }))
}

/// UI directory diagnostics endpoint (UI_ORIGIN_PROOF-1, UI_SYNC_HARDENED-1)
/// Returns information about where the UI is being served from, including file hashes
/// Also includes source UI info for mismatch detection
async fn meta_ui_dir_handler(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let ui_index_path = state.ui_dir.join("index.html");
    let ui_app_js_path = state.ui_dir.join("app.js");
    
    // Compute SHA256 hashes for identity verification (served files)
    let ui_index_sha256 = compute_file_sha256(&ui_index_path);
    let ui_app_js_sha256 = compute_file_sha256(&ui_app_js_path);
    
    let exe_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    // UI_SYNC_HARDENED-1: Check for source ui/ in repo and compute its hash
    // This enables the UI to detect stale served files
    let dev_mode = std::env::var("LOCINT_DEV_UI").map(|v| v == "1").unwrap_or(false);
    let (source_ui_dir, source_ui_app_js_sha256) = find_repo_root(&state.exe_dir)
        .map(|repo| {
            let source_ui = repo.join("ui");
            let source_sha = compute_file_sha256(&source_ui.join("app.js"));
            (Some(source_ui.display().to_string()), source_sha)
        })
        .unwrap_or((None, None));
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "exe_path": exe_path,
            "exe_dir": state.exe_dir.display().to_string(),
            "ui_dir": state.ui_dir.display().to_string(),
            "ui_index_path": ui_index_path.display().to_string(),
            "ui_index_exists": ui_index_path.exists(),
            "ui_index_sha256": ui_index_sha256,
            "ui_app_js_path": ui_app_js_path.display().to_string(),
            "ui_app_js_exists": ui_app_js_path.exists(),
            "ui_app_js_sha256": ui_app_js_sha256,
            "locint_ui_dir_override": std::env::var("LOCINT_UI_DIR").ok(),
            // UI_SYNC_HARDENED-1: Source ui info for mismatch detection
            "dev_mode": dev_mode,
            "source_ui_dir": source_ui_dir,
            "source_ui_app_js_sha256": source_ui_app_js_sha256,
        }
    }))
}

/// Compute SHA256 hash of a file (returns None if file doesn't exist or can't be read)
fn compute_file_sha256(path: &std::path::Path) -> Option<String> {
    use sha2::{Sha256, Digest};
    let content = std::fs::read(path).ok()?;
    let hash = Sha256::digest(&content);
    Some(format!("{:x}", hash))
}

// Run control handlers
async fn run_start_handler(
    State(state): State<SharedState>,
    Json(req): Json<services::types::StartRunRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use edr_server::supervisor::SupervisorError;
    
    // Build start config using service helper
    let config = services::run_control::build_start_config(
        req.run_label,
        req.profile,
        req.duration_seconds,
        req.playbook_selection,
    );
    
    // Delegate to Supervisor
    match state.supervisor.start(config).await {
        Ok(result) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": {
                    "run_id": result.run_id,
                    "run_dir": result.run_dir,
                    "capture_pid": result.capture_pid,
                    "locald_pid": result.locald_pid,
                    "started_at": result.started_at.to_rfc3339(),
                    "playbooks_enabled": result.playbooks_enabled,
                    "playbooks_dir": result.playbooks_dir,
                    "playbook_selection": {
                        "mode": result.selection_mode,
                        "preset": result.selection_preset,
                        "selected_count": result.selected_playbooks_count,
                    }
                }
            })))
        }
        Err(e) => {
            let status = match e {
                SupervisorError::BinaryNotFound { .. } => StatusCode::PRECONDITION_FAILED,
                SupervisorError::RunAlreadyActive { .. } => StatusCode::CONFLICT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            Err((status, serde_json::json!({
                "success": false,
                "error": e.to_string(),
                "code": e.error_code(),
            }).to_string()))
        }
    }
}

async fn run_stop_handler(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    use edr_server::supervisor::SupervisorError;
    
    match state.supervisor.stop_and_finalize().await {
        Ok(result) => {
            Json(serde_json::json!({
                "success": true,
                "data": {
                    "stopped": result.stopped,
                    "run_id": result.run_id,
                    "run_dir": result.run_dir,
                    "stopped_at": result.stopped_at.to_rfc3339(),
                    "finalized": result.finalized,
                    "phase": "completed",
                    "events_total": result.events_total,
                    "segments_count": result.segments_count,
                    "facts_extracted": result.facts_extracted,
                    "signals_fired": result.signals_fired,
                }
            }))
        }
        Err(SupervisorError::NoActiveRun) => {
            // Legacy cleanup fallback
            legacy_stop_processes().await;
            Json(serde_json::json!({
                "success": true,
                "data": {
                    "stopped": true,
                    "stopped_at": chrono::Utc::now().to_rfc3339(),
                    "finalized": false,
                    "phase": "no_active_run",
                    "note": "No active run tracked by supervisor, performed legacy cleanup"
                }
            }))
        }
        Err(e) => {
            Json(serde_json::json!({
                "success": false,
                "error": e.to_string(),
                "code": e.error_code(),
            }))
        }
    }
}

/// Legacy fallback for stopping processes when supervisor doesn't have tracking
async fn legacy_stop_processes() {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd1 = std::process::Command::new("taskkill");
        cmd1.creation_flags(0x08000000); // CREATE_NO_WINDOW
        let _ = cmd1.args(["/F", "/IM", "capture_windows_rotating.exe"]).output();
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        let mut cmd2 = std::process::Command::new("taskkill");
        cmd2.creation_flags(0x08000000);
        let _ = cmd2.args(["/F", "/IM", "edr-locald.exe"]).output();
    }
}

async fn run_status_handler(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let status = state.supervisor.status().await;
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "running": status.running,
            "run_id": status.run_id,
            "started_at": status.started_at,
            "elapsed_seconds": status.elapsed_seconds,
            "capture_running": status.capture_running,
            "locald_running": status.locald_running,
            "is_admin": status.is_admin,
            "phase": status.phase,
        }
    }))
}

async fn run_metrics_handler(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let metrics = state.supervisor.metrics().await;
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "running": metrics.running,
            "run_id": metrics.run_id,
            "segments_count": metrics.segments_count,
            "bytes_written": metrics.bytes_written,
            "events_total": metrics.events_total,
            "facts_extracted": metrics.facts_extracted,
            "signals_fired": metrics.signals_fired,
            "elapsed_seconds": metrics.elapsed_seconds,
            "capture_errors": 0,
            "locald_errors": 0,
        }
    }))
}

async fn list_runs_handler(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let runs_dir = state.data_dir.join("runs");
    let mut runs = Vec::new();
    
    // Get run names from the master DB if available
    let run_names: std::collections::HashMap<String, Option<String>> = state.db
        .list_runs(1000)
        .map(|records| records.into_iter().map(|r| (r.run_id, r.name)).collect())
        .unwrap_or_default();
    
    if let Ok(entries) = std::fs::read_dir(&runs_dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let run_id = entry.file_name().to_string_lossy().to_string();
                let run_dir = entry.path();
                let db_path = run_dir.join("workbench.db");
                let meta_path = run_dir.join("run_meta.json");
                
                let (started_at, stopped_at, status) = services::run_control::read_run_meta(&meta_path, &run_id);
                let (events, segments, facts, signals, earliest_ts, latest_ts, _) = 
                    if db_path.exists() {
                        services::run_control::read_run_stats(&db_path)
                    } else {
                        (0, 0, 0, 0, started_at.as_ref().map(|t| t.timestamp_millis()).unwrap_or(0), 0, None)
                    };
                
                let name = run_names.get(&run_id).cloned().flatten();
                
                runs.push(serde_json::json!({
                    "run_id": run_id,
                    "name": name,
                    "signal_count": signals,
                    "earliest_ts": earliest_ts,
                    "latest_ts": latest_ts,
                    "hosts": [],
                    "profile": "extended",
                    "started_at": started_at.map(|t| t.to_rfc3339()),
                    "stopped_at": stopped_at.map(|t| t.to_rfc3339()),
                    "events_total": events,
                    "segments_count": segments,
                    "facts_extracted": facts,
                    "status": status,
                }));
            }
        }
    }
    
    runs.sort_by(|a, b| {
        let a_id = a["run_id"].as_str().unwrap_or("");
        let b_id = b["run_id"].as_str().unwrap_or("");
        b_id.cmp(a_id)
    });
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "runs": runs,
            "count": runs.len()
        }
    }))
}

async fn get_run_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Json<serde_json::Value> {
    // Try DB first, fall back to filesystem (for runs discovered via scan)
    let (run_dir, run_record) = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok(r) => r,
        Err(_) => {
            // Fallback: construct path from data_dir (for filesystem-discovered runs)
            let run_dir = state.data_dir.join("runs").join(&run_id);
            if !run_dir.exists() {
                return Json(serde_json::json!({
                    "code": "RUN_NOT_FOUND",
                    "error": format!("Run '{}' not found", run_id)
                }));
            }
            // Create minimal run record for runs not in DB
            let run_record = db::RunRecord {
                run_id: run_id.clone(),
                name: None,
                profile: None,
                started_at: String::new(),
                stopped_at: None,
                run_dir: Some(run_dir.display().to_string()),
                events_total: 0,
                segments_count: 0,
                facts_extracted: 0,
                signals_fired: 0,
                bytes_written: 0,
                status: "unknown".to_string(),
                baseline_scope: None,
                baseline_enabled: false,
                baseline_set_at: None,
                chain_ids: None,
            };
            (run_dir, run_record)
        }
    };
    
    let db_path = run_dir.join("workbench.db");
    let meta_path = run_dir.join("run_meta.json");
    
    let (started_at, stopped_at, status) = services::run_control::read_run_meta(&meta_path, &run_id);
    let (events, segments, facts, signals, earliest_ts, latest_ts, _) = 
        if db_path.exists() {
            services::run_control::read_run_stats(&db_path)
        } else {
            (0, 0, 0, 0, started_at.as_ref().map(|t| t.timestamp_millis()).unwrap_or(0), 0, None)
        };
    
    // Read run readiness fields from run_meta.json
    let readiness = read_run_readiness(&meta_path);
    
    // Read playbook scope from run_meta.json (D2: include in run detail response)
    let playbook_scope = read_playbook_scope(&meta_path);
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "run_id": run_id,
            "name": run_record.name,
            "signal_count": signals,
            "earliest_ts": earliest_ts,
            "latest_ts": latest_ts,
            "hosts": [],
            "profile": "extended",
            "started_at": started_at.map(|t| t.to_rfc3339()),
            "stopped_at": stopped_at.map(|t| t.to_rfc3339()),
            "events_total": events,
            "segments_count": segments,
            "facts_extracted": facts,
            "status": status,
            // Run readiness fields (A: endpoint consistency)
            "compile_status": readiness.compile_status.as_deref().unwrap_or(if status == "running" { "compiling" } else { "finalized" }),
            "facts_ready": readiness.facts_ready,
            "facts_partial": readiness.facts_partial,
            "abandoned_reason": readiness.abandoned_reason,
            "last_activity_at": readiness.last_activity_at,
            "metadata_unavailable": readiness.metadata_unavailable,
            // Playbook scope (D2: playbook scope visibility)
            "playbook_scope": playbook_scope,
        }
    }))
}

#[derive(serde::Deserialize)]
struct RenameRunRequest {
    name: Option<String>,
}

async fn rename_run_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Json(body): Json<RenameRunRequest>,
) -> Json<serde_json::Value> {
    let run_dir = state.data_dir.join("runs").join(&run_id);
    
    if !run_dir.exists() {
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Run '{}' not found", run_id)
        }));
    }
    
    match state.db.rename_run(&run_id, body.name.as_deref()) {
        Ok(true) => Json(serde_json::json!({
            "success": true,
            "data": {
                "run_id": run_id,
                "name": body.name,
                "message": "Run renamed successfully"
            }
        })),
        Ok(false) => Json(serde_json::json!({
            "success": false,
            "error": "Run not found in database"
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e.to_string()
        })),
    }
}

async fn delete_run_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    _body: Option<Json<serde_json::Value>>,
) -> Json<serde_json::Value> {
    // Try DB first, fall back to filesystem path (for runs discovered via scan)
    let run_dir = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok((dir, _)) => dir,
        Err(_) => {
            // Fallback: construct path from data_dir
            let fallback_dir = state.data_dir.join("runs").join(&run_id);
            if !fallback_dir.exists() {
                return Json(serde_json::json!({
                    "success": false,
                    "error": format!("Run '{}' not found", run_id),
                    "code": "RUN_NOT_FOUND"
                }));
            }
            fallback_dir
        }
    };
    
    // Delete from filesystem
    if let Err(e) = std::fs::remove_dir_all(&run_dir) {
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Failed to delete run directory: {}", e)
        }));
    }
    
    // Remove from database (may not exist, that's OK)
    let _ = state.db.delete_run(&run_id);
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "run_id": run_id,
            "deleted": true,
            "message": "Run deleted successfully"
        }
    }))
}

/// S6 FIX: Helper to read run readiness fields from run_meta.json
/// Returns RunReadinessFields struct with all 5 readiness fields
#[derive(Default, Clone)]
struct RunReadinessFields {
    compile_status: Option<String>,
    facts_ready: bool,
    facts_partial: bool,
    abandoned_reason: Option<String>,
    last_activity_at: Option<String>,
    /// True if run_meta.json doesn't exist (pre-readiness metadata run)
    metadata_unavailable: bool,
}

fn read_run_readiness(meta_path: &std::path::Path) -> RunReadinessFields {
    if !meta_path.exists() {
        // OLD RUN: No run_meta.json means this is a legacy run from before readiness metadata.
        // Do NOT assume interrupted - default to finalized (graceful degradation).
        return RunReadinessFields {
            compile_status: None, // Don't claim any status for old runs
            facts_ready: true,    // Assume facts are ready (legacy runs completed)
            facts_partial: false, // Don't claim partial
            abandoned_reason: None,
            last_activity_at: None,
            metadata_unavailable: true, // Mark that we don't have metadata
        };
    }
    
    let content = match std::fs::read_to_string(meta_path) {
        Ok(c) => c,
        Err(_) => return RunReadinessFields {
            metadata_unavailable: true,
            facts_ready: true, // Default to ready for old runs
            ..Default::default()
        },
    };
    
    let meta: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return RunReadinessFields {
            metadata_unavailable: true,
            facts_ready: true,
            ..Default::default()
        },
    };
    
    let compile_status = meta.get("compile_status")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    let status = meta.get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    
    let abandoned_reason = meta.get("abandoned_reason")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    // Determine facts_ready: true if finalized, false if compiling/interrupted/abandoned
    let facts_ready = match compile_status.as_deref() {
        Some("finalized") => true,
        Some("compiling") => false,
        Some("interrupted") => false, // Partial data may exist
        _ => status != "running" && status != "abandoned", // Default based on status
    };
    
    // facts_partial: true only if interrupted (has some data but incomplete)
    let facts_partial = compile_status.as_deref() == Some("interrupted") || status == "abandoned";
    
    // Get last_activity_at from stopped_at or phase timestamp
    let last_activity_at = meta.get("stopped_at")
        .or_else(|| meta.get("last_activity"))
        .or_else(|| meta.get("started_at"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    RunReadinessFields {
        compile_status,
        facts_ready,
        facts_partial,
        abandoned_reason,
        last_activity_at,
        metadata_unavailable: false,
    }
}

/// Read playbook_scope from run_meta.json
/// Returns a default scope if not present (for backward compatibility with old runs)
fn read_playbook_scope(meta_path: &std::path::Path) -> PlaybookScope {
    if !meta_path.exists() {
        // Old run without playbook_scope - default to general discovery for backward compat
        return PlaybookScope::compute(None, Some("extended".to_string()), Some("preset".to_string()));
    }
    
    let content = match std::fs::read_to_string(meta_path) {
        Ok(c) => c,
        Err(_) => return PlaybookScope::compute(None, Some("extended".to_string()), Some("preset".to_string())),
    };
    
    let meta: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return PlaybookScope::compute(None, Some("extended".to_string()), Some("preset".to_string())),
    };
    
    // Try to read playbook_scope directly
    if let Some(scope_val) = meta.get("playbook_scope") {
        if let Ok(scope) = serde_json::from_value::<PlaybookScope>(scope_val.clone()) {
            return scope;
        }
    }
    
    // Fall back to legacy playbook_selection
    if let Some(selection) = meta.get("playbook_selection") {
        let selected = selection.get("selected_playbooks")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect());
        let preset = selection.get("preset")
            .and_then(|v| v.as_str())
            .map(String::from);
        let mode = selection.get("mode")
            .and_then(|v| v.as_str())
            .map(String::from);
        
        return PlaybookScope::compute(selected, preset, mode);
    }
    
    // Default fallback
    PlaybookScope::compute(None, Some("extended".to_string()), Some("preset".to_string()))
}

/// Build visibility summary from run_meta readiness snapshot
fn build_visibility_summary(meta_path: &std::path::Path) -> VisibilitySummary {
    let capability = services::capability::get_capability_snapshot_from_meta(meta_path);
    
    let sysmon_installed = capability.get("sysmon_installed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let security_log_accessible = capability.get("security_log_accessible")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_admin = capability.get("is_admin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    
    let mut sensors_present = vec!["etw".to_string()];
    let mut sensors_missing = vec![];
    
    if sysmon_installed {
        sensors_present.push("sysmon".to_string());
    } else {
        sensors_missing.push("sysmon".to_string());
    }
    
    VisibilitySummary {
        sensors_present,
        sensors_missing,
        permissions: PermissionState {
            security_log: if security_log_accessible { "ok".to_string() } else { "denied".to_string() },
            system_log: "ok".to_string(),
            sysmon_log: if sysmon_installed { Some("ok".to_string()) } else { None },
        },
    }
}

/// Discover all playbook IDs from filesystem
/// Returns normalized IDs (without "signal_" prefix) sorted alphabetically
fn discover_all_playbook_ids(pb_dir: &std::path::Path) -> Vec<String> {
    let mut ids = Vec::new();
    
    let windows_dir = pb_dir.join("windows");
    let target_dir = if windows_dir.exists() { windows_dir } else { pb_dir.to_path_buf() };
    let custom_dir = pb_dir.join("custom");
    
    for dir in [target_dir, custom_dir] {
        if !dir.exists() {
            continue;
        }
        
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                    continue;
                }
                if path.to_string_lossy().contains("unsupported") {
                    continue;
                }
                
                let raw_id = path.file_stem()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                // Normalize: strip "signal_" prefix
                let id = raw_id.strip_prefix("signal_")
                    .unwrap_or(&raw_id)
                    .to_string();
                
                // Skip test playbooks
                if id.ends_with("_test") {
                    continue;
                }
                
                ids.push(id);
            }
        }
    }
    
    ids.sort();
    ids
}

/// Legacy wrapper for backward compatibility
fn read_run_meta_fields(meta_path: &std::path::Path) -> (Option<String>, Option<String>) {
    let fields = read_run_readiness(meta_path);
    (fields.compile_status, fields.abandoned_reason)
}

async fn run_coverage_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Json<serde_json::Value> {
    // Try to get full coverage data using run_coverage module
    let run_dir = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok((dir, _)) => dir,
        Err(_) => {
            // Fallback: construct path from data_dir
            let fallback_dir = state.data_dir.join("runs").join(&run_id);
            if !fallback_dir.exists() {
                return Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "available": false,
                        "reason": "RUN_NOT_FOUND",
                        "run_id": run_id
                    }
                }));
            }
            fallback_dir
        }
    };
    
    // Read run_meta.json to get status and persisted compile_status
    let meta_path = run_dir.join("run_meta.json");
    let (_, stopped_at, status) = services::run_control::read_run_meta(&meta_path, &run_id);
    
    // S6 FIX: Read persisted compile_status and abandoned_reason from run_meta.json
    let (persisted_compile_status, abandoned_reason) = read_run_meta_fields(&meta_path);
    
    // Check if this run's processes are actually running
    let current_supervisor_status = state.supervisor.status().await;
    let is_this_run_active = current_supervisor_status.run_id.as_deref() == Some(&run_id) 
        && current_supervisor_status.running;
    
    // S6 FIX: Derive compile_status with priority:
    // 1) Use persisted compile_status from run_meta.json if present (most authoritative)
    // 2) Else infer from status + process liveness
    let compile_status = if let Some(ref persisted) = persisted_compile_status {
        // Trust the persisted value - it was written at the time of the event
        persisted.as_str()
    } else {
        // Infer from current state
        match status.as_str() {
            "running" => {
                if is_this_run_active {
                    "compiling"  // Actually still running
                } else {
                    "interrupted"  // Status says running but processes are dead
                }
            },
            "stopped" => "finalized",
            "abandoned" => "interrupted",
            _ => if stopped_at.is_some() { "finalized" } else { "unknown" }
        }
    };
    let facts_ready = compile_status == "finalized";
    let facts_partial = compile_status == "interrupted";  // S6: Facts exist but incomplete
    let last_compiled_at = stopped_at.map(|t| t.to_rfc3339());
    
    let db_path = run_dir.join("workbench.db");
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason": "MISSING_DB",
                "reason_message": "workbench.db not found",
                "run_id": run_id,
                "compile_status": compile_status,
                "facts_ready": facts_ready
            }
        }));
    }
    
    // Use the full load_run_coverage function which includes pipeline_diagnostics
    match run_coverage::load_run_coverage(&run_dir, &run_id) {
        Ok(coverage) => {
            // Merge compile status into coverage response
            let mut data = serde_json::to_value(&coverage).unwrap_or_default();
            if let Some(obj) = data.as_object_mut() {
                obj.insert("compile_status".to_string(), serde_json::json!(compile_status));
                obj.insert("facts_ready".to_string(), serde_json::json!(facts_ready));
                obj.insert("facts_partial".to_string(), serde_json::json!(facts_partial));  // S6 FIX
                if let Some(ts) = &last_compiled_at {
                    obj.insert("last_compiled_at".to_string(), serde_json::json!(ts));
                }
                // S6 FIX: Include abandoned_reason if present
                if let Some(reason) = &abandoned_reason {
                    obj.insert("abandoned_reason".to_string(), serde_json::json!(reason));
                }
            }
            Json(serde_json::json!({
                "success": true,
                "data": data
            }))
        }
        Err(e) => {
            // Fall back to minimal response on error
            let (events, segments, facts, signals, earliest_ts, latest_ts, _) = 
                services::run_control::read_run_stats(&db_path);
            
            let error_msg = match e {
                run_coverage::CoverageLoadError::MissingDb(p) => format!("Missing DB: {}", p.display()),
                run_coverage::CoverageLoadError::MissingTable(t) => format!("Missing table: {}", t),
                run_coverage::CoverageLoadError::DbError(msg) => msg,
            };
            
            Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": true,
                    "run_id": run_id,
                    "compile_status": compile_status,
                    "facts_ready": facts_ready,
                    "last_compiled_at": last_compiled_at,
                    "events_total": events,
                    "segments_count": segments,
                    "facts_total": facts,
                    "facts_extracted": facts,
                    "signals_count": signals,
                    "earliest_ts": earliest_ts,
                    "latest_ts": latest_ts,
                    "fact_types": [],
                    "top_hosts": [],
                    "_error": error_msg
                }
            }))
        }
    }
}

/// Fact Inspector query parameters
#[derive(serde::Deserialize)]
struct FactsQuery {
    /// Filter by fact_type (e.g., "Exec", "FileCreate")
    fact_type: Option<String>,
    /// Filter by host
    host: Option<String>,
    /// Filter by category (e.g., "persistence", "network", "process")
    category: Option<String>,
    /// Limit results (default 100, max 500)
    limit: Option<u32>,
    /// Offset for pagination
    offset: Option<u32>,
    /// Search text in details JSON
    search: Option<String>,
}

/// GET /api/runs/:run_id/facts - Fact Inspector endpoint
/// Returns actual fact rows with filtering, sorting, and pagination
async fn run_facts_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Query(params): Query<FactsQuery>,
) -> Json<serde_json::Value> {
    // Resolve run directory
    let run_dir = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok((dir, _)) => dir,
        Err(_) => {
            let fallback_dir = state.data_dir.join("runs").join(&run_id);
            if !fallback_dir.exists() {
                return Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "available": false,
                        "reason": "RUN_NOT_FOUND",
                        "run_id": run_id,
                        // Readiness fields for unavailable runs
                        "compile_status": null,
                        "facts_ready": false,
                        "facts_partial": false,
                        "abandoned_reason": null,
                        "last_activity_at": null
                    }
                }));
            }
            fallback_dir
        }
    };
    
    // Read run readiness fields from run_meta.json
    let meta_path = run_dir.join("run_meta.json");
    let readiness = read_run_readiness(&meta_path);
    
    let db_path = run_dir.join("workbench.db");
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason": "MISSING_DB",
                "run_id": run_id,
                // Readiness fields (A: endpoint consistency)
                "compile_status": readiness.compile_status,
                "facts_ready": readiness.facts_ready,
                "facts_partial": readiness.facts_partial,
                "abandoned_reason": readiness.abandoned_reason,
                "last_activity_at": readiness.last_activity_at,
                "metadata_unavailable": readiness.metadata_unavailable
            }
        }));
    }
    
    let conn = match rusqlite::Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to open database: {}", e)
            }));
        }
    };
    
    // Build query with optional filters
    let limit = params.limit.unwrap_or(100).min(500);
    let offset = params.offset.unwrap_or(0);
    
    // Build WHERE clause based on filters
    let mut conditions: Vec<String> = Vec::new();
    let mut query_params: Vec<String> = Vec::new();
    
    if let Some(ref ft) = params.fact_type {
        conditions.push("fact_type = ?".to_string());
        query_params.push(ft.clone());
    }
    
    if let Some(ref host) = params.host {
        conditions.push("host = ?".to_string());
        query_params.push(host.clone());
    }
    
    if let Some(ref cat) = params.category {
        conditions.push("category = ?".to_string());
        query_params.push(cat.clone());
    }
    
    if let Some(ref search) = params.search {
        conditions.push("(details_json LIKE ? OR entity_key LIKE ?)".to_string());
        query_params.push(format!("%{}%", search));
        query_params.push(format!("%{}%", search));
    }
    
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    
    // Check if facts_sample table exists (graceful fallback for old runs - TWEAK A)
    let has_facts_sample: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='facts_sample'")
        .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
        .unwrap_or(false);
    
    if !has_facts_sample {
        // Old run without facts_sample - return structured unavailable response
        // Try to get summary from coverage_rollup as fallback
        let coverage_summary: Vec<(String, i64)> = conn
            .prepare("SELECT fact_type, SUM(fact_count) FROM coverage_rollup WHERE fact_type IS NOT NULL GROUP BY fact_type ORDER BY SUM(fact_count) DESC LIMIT 10")
            .and_then(|mut stmt| {
                stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
            })
            .unwrap_or_default();
        
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason": "NO_FACTS_SAMPLE_TABLE",
                "explanation": "This run was created before hybrid fact persistence was implemented. Individual facts are not available, but coverage summaries may be present.",
                "run_id": run_id,
                "facts": [],
                "coverage_summary": coverage_summary.iter().map(|(ft, count)| {
                    serde_json::json!({"fact_type": ft, "count": count})
                }).collect::<Vec<_>>(),
                "pagination": { "total": 0, "limit": limit, "offset": offset, "has_more": false },
                // Readiness fields for old runs (A: endpoint consistency, C: old run degradation)
                "compile_status": readiness.compile_status,
                "facts_ready": readiness.facts_ready, // Still true for old runs - they completed
                "facts_partial": readiness.facts_partial,
                "abandoned_reason": readiness.abandoned_reason,
                "last_activity_at": readiness.last_activity_at,
                "metadata_unavailable": readiness.metadata_unavailable // C: show note for old runs
            }
        }));
    }
    
    // Get total count for pagination from facts_sample table
    let count_sql = format!("SELECT COUNT(*) FROM facts_sample {}", where_clause);
    let total_count: i64 = conn
        .prepare(&count_sql)
        .and_then(|mut stmt| {
            let refs: Vec<&dyn rusqlite::ToSql> = query_params.iter()
                .map(|s| s as &dyn rusqlite::ToSql)
                .collect();
            stmt.query_row(refs.as_slice(), |row| row.get(0))
        })
        .unwrap_or(0);
    
    // Debug: List tables in the database
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .and_then(|mut stmt| {
            stmt.query_map([], |row| row.get(0))
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    tracing::info!("Facts query: run_id={}, total_count={}, tables={:?}", run_id, total_count, tables);
    
    // Get facts with pagination from facts_sample table (including fact_json for inspector - TWEAK B)
    let sql = format!(
        "SELECT fact_id, fact_type, category, ts, host, entity_key, details_json, fact_json, evidence_ptrs
         FROM facts_sample
         {}
         ORDER BY ts DESC
         LIMIT ? OFFSET ?",
        where_clause
    );
    
    let mut facts: Vec<serde_json::Value> = Vec::new();
    
    if let Ok(mut stmt) = conn.prepare(&sql) {
        // Build parameter list dynamically
        let mut all_params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        for p in &query_params {
            all_params.push(Box::new(p.clone()));
        }
        all_params.push(Box::new(limit as i64));
        all_params.push(Box::new(offset as i64));
        
        let refs: Vec<&dyn rusqlite::ToSql> = all_params.iter()
            .map(|b| b.as_ref())
            .collect();
        
        if let Ok(rows) = stmt.query_map(refs.as_slice(), |row| {
            let fact_id: String = row.get(0)?;
            let fact_type: String = row.get(1)?;
            let category: String = row.get(2)?;
            let ts: i64 = row.get(3)?;
            let host: String = row.get(4)?;
            let entity_key: Option<String> = row.get(5)?;
            let details_json_str: String = row.get(6)?;
            let fact_json_str: Option<String> = row.get(7)?;  // Full fact for inspector (TWEAK B)
            let evidence_ptrs_str: Option<String> = row.get(8)?;
            
            // Parse the details JSON (summary view)
            let details: serde_json::Value = serde_json::from_str(&details_json_str)
                .unwrap_or(serde_json::json!({}));
            
            // Parse full fact JSON if present (for Fact Inspector drawer)
            let fact_full: serde_json::Value = fact_json_str
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(serde_json::json!(null));
            
            // Parse evidence pointers if present
            let evidence = evidence_ptrs_str
                .as_ref()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
                .unwrap_or(serde_json::json!(null));
            
            Ok(serde_json::json!({
                "fact_id": fact_id,
                "fact_type": fact_type,
                "category": category,
                "ts": ts,
                "host": host,
                "entity_key": entity_key,
                "details": details,
                "fact_full": fact_full,
                "evidence": evidence
            }))
        }) {
            for fact in rows.flatten() {
                facts.push(fact);
            }
        }
    }
    
    // Get available fact types for filter dropdown (from facts_sample)
    let fact_types: Vec<String> = conn
        .prepare("SELECT DISTINCT fact_type FROM facts_sample ORDER BY fact_type")
        .and_then(|mut stmt| {
            stmt.query_map([], |row| row.get(0))
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    // Get available hosts for filter dropdown (from facts_sample)
    let hosts: Vec<String> = conn
        .prepare("SELECT DISTINCT host FROM facts_sample WHERE host IS NOT NULL ORDER BY host")
        .and_then(|mut stmt| {
            stmt.query_map([], |row| row.get(0))
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    // Get available categories for filter dropdown
    let categories: Vec<String> = conn
        .prepare("SELECT DISTINCT category FROM facts_sample ORDER BY category")
        .and_then(|mut stmt| {
            stmt.query_map([], |row| row.get(0))
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "available": true,
            "run_id": run_id,
            "facts": facts,
            "pagination": {
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "has_more": (offset as i64 + facts.len() as i64) < total_count
            },
            "filters": {
                "fact_type": params.fact_type,
                "host": params.host,
                "category": params.category,
                "search": params.search
            },
            "available_filters": {
                "fact_types": fact_types,
                "hosts": hosts,
                "categories": categories
            },
            "_debug_tables": tables,
            // Readiness fields (A: endpoint consistency)
            "compile_status": readiness.compile_status,
            "facts_ready": readiness.facts_ready,
            "facts_partial": readiness.facts_partial,
            "abandoned_reason": readiness.abandoned_reason,
            "last_activity_at": readiness.last_activity_at,
            "metadata_unavailable": readiness.metadata_unavailable
        }
    }))
}

/// POST /api/runs/:run_id/facts/resolve
/// Resolves EvidenceRef pointers to actual facts
/// 
/// # Request Body
/// ```json
/// { "refs": [EvidenceRef, ...] }
/// ```
/// 
/// # Response (success)
/// ```json
/// {
///   "success": true,
///   "data": {
///     "run_id": "...",
///     "facts": [...],
///     "resolved_count": N,
///     "unresolved": [{ "index": N, "ref": {...}, "reason": "ERROR_CODE" }],
///     "unresolved_count": N,
///     "total_requested": N,
///     "deduplicated_count": N  // if dedup removed any refs
///   }
/// }
/// ```
/// 
/// # Error Reasons (for unresolved refs)
/// - `NOT_FOUND` - Ref had valid fields but no matching fact in DB
/// - `INSUFFICIENT_FIELDS` - Ref missing required fields (need fact_id OR segment_id+record_index OR fact_type+ts)
/// 
/// # Error Responses (for request-level failures)
/// - `RUN_NOT_FOUND` - Run ID does not exist
/// - `MISSING_DB` - Run exists but workbench.db is missing
/// - `NO_FACTS_SAMPLE_TABLE` - DB exists but facts_sample table missing
/// - `TOO_MANY_REFS` - More than 200 refs requested
/// - `EMPTY_REFS` - No refs provided
/// 
/// # Resolution Priority
/// 1. `fact_id` alone (fastest, primary key lookup)
/// 2. `segment_id` + `record_index` (raw log pointer)
/// 3. `fact_type` + `ts` (fallback, approximate ±1s)
#[derive(Debug, Deserialize)]
struct FactsResolveRequest {
    refs: Vec<EvidenceRef>,
}

/// Maximum number of refs allowed in a single resolve request
const MAX_RESOLVE_REFS: usize = 200;

async fn facts_resolve_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Json(payload): Json<FactsResolveRequest>,
) -> Json<serde_json::Value> {
    // Hardening: reject empty requests
    if payload.refs.is_empty() {
        return Json(serde_json::json!({
            "success": false,
            "error": "EMPTY_REFS",
            "message": "No evidence refs provided"
        }));
    }
    
    // Hardening: cap request size to prevent abuse
    if payload.refs.len() > MAX_RESOLVE_REFS {
        return Json(serde_json::json!({
            "success": false,
            "error": "TOO_MANY_REFS",
            "message": format!("Maximum {} refs allowed per request, got {}", MAX_RESOLVE_REFS, payload.refs.len()),
            "max_allowed": MAX_RESOLVE_REFS,
            "requested": payload.refs.len()
        }));
    }
    
    // Hardening: deduplicate refs by creating a stable key
    // Key priority: fact_id > segment+record > type+ts
    let mut seen_keys = std::collections::HashSet::new();
    let mut deduped_refs: Vec<(usize, &EvidenceRef)> = Vec::new();
    let mut deduplicated_count = 0;
    
    for (idx, ref_item) in payload.refs.iter().enumerate() {
        let key = if let Some(ref fact_id) = ref_item.fact_id {
            format!("fid:{}", fact_id)
        } else if let (Some(ref seg), Some(rec)) = (&ref_item.segment_id, ref_item.record_index) {
            format!("seg:{}:{}", seg, rec)
        } else if let (Some(ref ft), Some(ts)) = (&ref_item.fact_type, ref_item.ts) {
            format!("ts:{}:{}", ft, ts)
        } else {
            // No resolvable key - include anyway (will be marked unresolved)
            format!("unresolvable:{}", idx)
        };
        
        if seen_keys.insert(key) {
            deduped_refs.push((idx, ref_item));
        } else {
            deduplicated_count += 1;
        }
    }
    
    // Resolve run directory
    let run_dir = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok((dir, _)) => dir,
        Err(_) => {
            let fallback_dir = state.data_dir.join("runs").join(&run_id);
            if !fallback_dir.exists() {
                return Json(serde_json::json!({
                    "success": false,
                    "error": "RUN_NOT_FOUND",
                    "run_id": run_id
                }));
            }
            fallback_dir
        }
    };
    
    let db_path = run_dir.join("workbench.db");
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": false,
            "error": "MISSING_DB",
            "run_id": run_id
        }));
    }
    
    let conn = match rusqlite::Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to open database: {}", e)
            }));
        }
    };
    
    // Check if facts_sample table exists
    let has_facts_sample: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='facts_sample'")
        .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
        .unwrap_or(false);
    
    if !has_facts_sample {
        return Json(serde_json::json!({
            "success": false,
            "error": "NO_FACTS_SAMPLE_TABLE",
            "run_id": run_id
        }));
    }
    
    let mut resolved_facts: Vec<serde_json::Value> = Vec::new();
    let mut unresolved_refs: Vec<serde_json::Value> = Vec::new();
    
    // Use deduped refs instead of original payload
    for (original_idx, ref_item) in deduped_refs.iter() {
        // Priority 1: Resolve by fact_id (fastest, most reliable)
        if let Some(ref fact_id) = ref_item.fact_id {
            if let Ok(fact) = resolve_fact_by_id(&conn, fact_id) {
                resolved_facts.push(fact);
                continue;
            }
        }
        
        // Priority 2: Resolve by segment_id + record_index (raw log pointer)
        if let (Some(ref segment_id), Some(record_idx)) = (&ref_item.segment_id, ref_item.record_index) {
            if let Ok(fact) = resolve_fact_by_segment(&conn, segment_id, record_idx) {
                resolved_facts.push(fact);
                continue;
            }
        }
        
        // Priority 3: Resolve by fact_type + ts (fallback, may match multiple)
        if let (Some(ref fact_type), Some(ts)) = (&ref_item.fact_type, ref_item.ts) {
            if let Ok(fact) = resolve_fact_by_type_ts(&conn, fact_type, ts) {
                resolved_facts.push(fact);
                continue;
            }
        }
        
        // Could not resolve - add to unresolved list (with original index for client correlation)
        unresolved_refs.push(serde_json::json!({
            "index": original_idx,
            "ref": ref_item,
            "reason": if ref_item.is_resolvable() { "NOT_FOUND" } else { "INSUFFICIENT_FIELDS" }
        }));
    }
    
    let mut response_data = serde_json::json!({
        "run_id": run_id,
        "facts": resolved_facts,
        "resolved_count": resolved_facts.len(),
        "unresolved": unresolved_refs,
        "unresolved_count": unresolved_refs.len(),
        "total_requested": payload.refs.len()
    });
    
    // Only include deduplicated_count if dedup actually removed refs
    if deduplicated_count > 0 {
        response_data["deduplicated_count"] = serde_json::json!(deduplicated_count);
    }
    
    Json(serde_json::json!({
        "success": true,
        "data": response_data
    }))
}

/// Resolve a fact by its fact_id (primary key lookup)
fn resolve_fact_by_id(conn: &rusqlite::Connection, fact_id: &str) -> Result<serde_json::Value, rusqlite::Error> {
    conn.query_row(
        "SELECT fact_id, fact_type, category, ts, host, entity_key, details_json, fact_json
         FROM facts_sample WHERE fact_id = ?",
        [fact_id],
        |row| {
            let details_json_str: String = row.get(6)?;
            let fact_json_str: Option<String> = row.get(7)?;
            
            let details: serde_json::Value = serde_json::from_str(&details_json_str)
                .unwrap_or(serde_json::json!({}));
            let fact_full: serde_json::Value = fact_json_str
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(serde_json::json!(null));
            
            Ok(serde_json::json!({
                "fact_id": row.get::<_, String>(0)?,
                "fact_type": row.get::<_, String>(1)?,
                "category": row.get::<_, String>(2)?,
                "ts": row.get::<_, i64>(3)?,
                "host": row.get::<_, String>(4)?,
                "entity_key": row.get::<_, Option<String>>(5)?,
                "details": details,
                "fact_full": fact_full,
                "resolution_method": "fact_id"
            }))
        }
    )
}

/// Resolve a fact by segment_id and record_index (raw log pointer)
fn resolve_fact_by_segment(conn: &rusqlite::Connection, segment_id: &str, record_index: u32) -> Result<serde_json::Value, rusqlite::Error> {
    // Segment pointers stored in evidence_ptrs JSON array
    conn.query_row(
        r#"SELECT fact_id, fact_type, category, ts, host, entity_key, details_json, fact_json
           FROM facts_sample 
           WHERE evidence_ptrs LIKE ?
           LIMIT 1"#,
        [format!("%\"segment_id\":\"{}%\"record_index\":{}%", segment_id, record_index)],
        |row| {
            let details_json_str: String = row.get(6)?;
            let fact_json_str: Option<String> = row.get(7)?;
            
            let details: serde_json::Value = serde_json::from_str(&details_json_str)
                .unwrap_or(serde_json::json!({}));
            let fact_full: serde_json::Value = fact_json_str
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(serde_json::json!(null));
            
            Ok(serde_json::json!({
                "fact_id": row.get::<_, String>(0)?,
                "fact_type": row.get::<_, String>(1)?,
                "category": row.get::<_, String>(2)?,
                "ts": row.get::<_, i64>(3)?,
                "host": row.get::<_, String>(4)?,
                "entity_key": row.get::<_, Option<String>>(5)?,
                "details": details,
                "fact_full": fact_full,
                "resolution_method": "segment_pointer"
            }))
        }
    )
}

/// Resolve a fact by fact_type and timestamp (fallback, approximate match)
fn resolve_fact_by_type_ts(conn: &rusqlite::Connection, fact_type: &str, ts: i64) -> Result<serde_json::Value, rusqlite::Error> {
    // Allow small timestamp variance (±1000ms) for approximate matching
    conn.query_row(
        "SELECT fact_id, fact_type, category, ts, host, entity_key, details_json, fact_json
         FROM facts_sample 
         WHERE fact_type = ? AND ts BETWEEN ? AND ?
         ORDER BY ABS(ts - ?)
         LIMIT 1",
        rusqlite::params![fact_type, ts - 1000, ts + 1000, ts],
        |row| {
            let details_json_str: String = row.get(6)?;
            let fact_json_str: Option<String> = row.get(7)?;
            
            let details: serde_json::Value = serde_json::from_str(&details_json_str)
                .unwrap_or(serde_json::json!({}));
            let fact_full: serde_json::Value = fact_json_str
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(serde_json::json!(null));
            
            Ok(serde_json::json!({
                "fact_id": row.get::<_, String>(0)?,
                "fact_type": row.get::<_, String>(1)?,
                "category": row.get::<_, String>(2)?,
                "ts": row.get::<_, i64>(3)?,
                "host": row.get::<_, String>(4)?,
                "entity_key": row.get::<_, Option<String>>(5)?,
                "details": details,
                "fact_full": fact_full,
                "resolution_method": "type_ts_fallback"
            }))
        }
    )
}

/// GET /api/runs/:run_id/evidence_summary
/// Returns aggregated summary for Evidence Summary mode:
/// - Top entities by category (processes, scripts, destinations, registry)
/// - Timeline buckets for mini-chart
/// - First/last seen timestamps per fact type
/// 
/// EVIDENCE_GRANULARITY-1: This endpoint powers the Evidence Summary view
/// and is truthful (derives from full facts_sample, not sampling)
async fn run_evidence_summary_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Json<serde_json::Value> {
    // Resolve run directory
    let run_dir = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok((dir, _)) => dir,
        Err(_) => {
            let fallback_dir = state.data_dir.join("runs").join(&run_id);
            if !fallback_dir.exists() {
                return Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "available": false,
                        "reason": "RUN_NOT_FOUND",
                        "run_id": run_id
                    }
                }));
            }
            fallback_dir
        }
    };
    
    let db_path = run_dir.join("workbench.db");
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason": "MISSING_DB",
                "run_id": run_id
            }
        }));
    }
    
    let conn = match rusqlite::Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to open database: {}", e)
            }));
        }
    };
    
    // Check if facts_sample table exists
    let has_facts_sample: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='facts_sample'")
        .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
        .unwrap_or(false);
    
    if !has_facts_sample {
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason": "NO_FACTS_SAMPLE_TABLE",
                "run_id": run_id
            }
        }));
    }
    
    // Get run time bounds for timeline bucketing
    let (min_ts, max_ts): (i64, i64) = conn
        .query_row("SELECT COALESCE(MIN(ts), 0), COALESCE(MAX(ts), 0) FROM facts_sample", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap_or((0, 0));
    
    // Get total facts count
    let total_facts: i64 = conn
        .query_row("SELECT COUNT(*) FROM facts_sample", [], |row| row.get(0))
        .unwrap_or(0);
    
    // === Top Entities by Category ===
    
    // Top Processes (Exec fact type)
    let top_processes: Vec<serde_json::Value> = conn
        .prepare(r#"
            SELECT entity_key, COUNT(*) as cnt 
            FROM facts_sample 
            WHERE fact_type IN ('Exec', 'ProcessCreate', 'ProcessStart')
              AND entity_key IS NOT NULL AND entity_key != ''
            GROUP BY entity_key 
            ORDER BY cnt DESC 
            LIMIT 5
        "#)
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "entity": row.get::<_, String>(0)?,
                    "count": row.get::<_, i64>(1)?
                }))
            }).map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    // Top Scripts (ScriptExec, ScriptBlock fact types)
    let top_scripts: Vec<serde_json::Value> = conn
        .prepare(r#"
            SELECT entity_key, COUNT(*) as cnt 
            FROM facts_sample 
            WHERE fact_type IN ('ScriptExec', 'ScriptBlock', 'ScriptContent')
              AND entity_key IS NOT NULL AND entity_key != ''
            GROUP BY entity_key 
            ORDER BY cnt DESC 
            LIMIT 5
        "#)
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "entity": row.get::<_, String>(0)?,
                    "count": row.get::<_, i64>(1)?
                }))
            }).map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    // Top Destinations (OutboundConnect, NetworkConnect fact types)
    let top_destinations: Vec<serde_json::Value> = conn
        .prepare(r#"
            SELECT entity_key, COUNT(*) as cnt 
            FROM facts_sample 
            WHERE fact_type IN ('OutboundConnect', 'NetworkConnect', 'DnsQuery')
              AND entity_key IS NOT NULL AND entity_key != ''
            GROUP BY entity_key 
            ORDER BY cnt DESC 
            LIMIT 5
        "#)
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "entity": row.get::<_, String>(0)?,
                    "count": row.get::<_, i64>(1)?
                }))
            }).map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    // Top Registry Paths (RegistryMod, RegistryChange fact types)
    let top_registry: Vec<serde_json::Value> = conn
        .prepare(r#"
            SELECT entity_key, COUNT(*) as cnt 
            FROM facts_sample 
            WHERE fact_type IN ('RegistryMod', 'RegistryChange', 'RegistrySet')
              AND entity_key IS NOT NULL AND entity_key != ''
            GROUP BY entity_key 
            ORDER BY cnt DESC 
            LIMIT 5
        "#)
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "entity": row.get::<_, String>(0)?,
                    "count": row.get::<_, i64>(1)?
                }))
            }).map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    // Top Files (FileCreate, FileWrite, FileDelete fact types)
    let top_files: Vec<serde_json::Value> = conn
        .prepare(r#"
            SELECT entity_key, COUNT(*) as cnt 
            FROM facts_sample 
            WHERE fact_type IN ('FileCreate', 'FileWrite', 'FileDelete', 'FileMod')
              AND entity_key IS NOT NULL AND entity_key != ''
            GROUP BY entity_key 
            ORDER BY cnt DESC 
            LIMIT 5
        "#)
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "entity": row.get::<_, String>(0)?,
                    "count": row.get::<_, i64>(1)?
                }))
            }).map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    // === Timeline Buckets ===
    // Create 20 time buckets across the run duration
    let bucket_count = 20;
    let duration = if max_ts > min_ts { max_ts - min_ts } else { 1 };
    let bucket_width = duration / bucket_count;
    
    let timeline_buckets: Vec<serde_json::Value> = if bucket_width > 0 {
        conn.prepare(&format!(r#"
            SELECT 
                (ts - {min_ts}) / {bucket_width} as bucket_idx,
                COUNT(*) as cnt,
                MIN(ts) as bucket_start,
                MAX(ts) as bucket_end
            FROM facts_sample 
            GROUP BY bucket_idx
            ORDER BY bucket_idx
        "#, min_ts = min_ts, bucket_width = bucket_width))
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "bucket": row.get::<_, i64>(0)?,
                    "count": row.get::<_, i64>(1)?,
                    "start_ts": row.get::<_, i64>(2)?,
                    "end_ts": row.get::<_, i64>(3)?
                }))
            }).map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default()
    } else {
        vec![]
    };
    
    // === Fact Type Summary with first/last seen ===
    let fact_type_summary: Vec<serde_json::Value> = conn
        .prepare(r#"
            SELECT 
                fact_type,
                COUNT(*) as cnt,
                MIN(ts) as first_seen,
                MAX(ts) as last_seen,
                (SELECT entity_key FROM facts_sample f2 
                 WHERE f2.fact_type = facts_sample.fact_type 
                   AND f2.entity_key IS NOT NULL 
                 GROUP BY entity_key 
                 ORDER BY COUNT(*) DESC 
                 LIMIT 1) as top_entity
            FROM facts_sample
            GROUP BY fact_type
            ORDER BY cnt DESC
        "#)
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "fact_type": row.get::<_, String>(0)?,
                    "count": row.get::<_, i64>(1)?,
                    "first_seen": row.get::<_, i64>(2)?,
                    "last_seen": row.get::<_, i64>(3)?,
                    "top_entity": row.get::<_, Option<String>>(4)?
                }))
            }).map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "available": true,
            "run_id": run_id,
            "total_facts": total_facts,
            "time_range": {
                "min_ts": min_ts,
                "max_ts": max_ts,
                "duration_ms": duration
            },
            "top_entities": {
                "processes": top_processes,
                "scripts": top_scripts,
                "destinations": top_destinations,
                "registry": top_registry,
                "files": top_files
            },
            "timeline_buckets": timeline_buckets,
            "bucket_width_ms": bucket_width,
            "fact_type_summary": fact_type_summary
        }
    }))
}

// ============================================================================
// RUN BRIEF: Observed Lens (chain-independent run summary)
// BUILD: 2026-01-27-RUN_BRIEF-1
// ============================================================================

/// GET /api/runs/:run_id/brief
/// 
/// Returns a comprehensive "Observed Lens" summary of what happened during the run,
/// independent of any micro chain or playbook selection. This is derived entirely
/// from workbench.db (per-run DB) and run_meta.json, NOT from UI state.
/// 
/// # Data Sources (per RUN_PIPELINE_TRUTH_REPORT.md):
/// - `totals`: coverage_rollup (event_count, fact_count sums), signals count, segments count
/// - `coverage`: run_meta.json capability snapshot (AT run time, not current system)
/// - `timeline`: coverage_rollup bucketed by ts_minute
/// - `top_entities`: entity_rollup table (if populated), fallback to facts_sample
/// - `notable_findings`: signals table with evidence_ptrs
/// - `episodes`: deterministic clustering from signals + time windows
/// - `unmapped_activity`: fact types not associated with any fired signal
/// 
/// # Constraint: facts_sample is sampled (200/type cap) - totals come from coverage_rollup
/// 
/// # Response
/// ```json
/// {
///   "success": true,
///   "data": {
///     "available": true,
///     "run_id": "...",
///     "totals": { events_total, facts_total, signals_fired, segments_count },
///     "coverage": { snapshot_present, sysmon, is_admin, security_log_accessible, gaps[] },
///     "timeline": [{ start_ts, end_ts, count }],
///     "top_entities": { processes: [...], destinations: [...], registry: [...], files: [...] },
///     "notable_findings": [{ signal_id, playbook_id, severity, ts_start, ts_end, evidence_refs_count, evidence_ptrs }],
///     "episodes": [{ episode_id, start_ts, end_ts, primary_entity, labels[], key_fact_types[], evidence_ptrs }],
///     "unmapped_activity": { fact_type_counts: [...] }
///   }
/// }
/// ```
async fn run_brief_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Json<serde_json::Value> {
    // Resolve run directory (Constraint 1: Per-Run DB Isolation)
    let (run_dir, _run_record) = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok(r) => r,
        Err(_) => {
            let fallback_dir = state.data_dir.join("runs").join(&run_id);
            if !fallback_dir.exists() {
                return Json(serde_json::json!({
                    "success": true,
                    "data": services::run_brief::RunBriefUnavailable::not_found(&run_id).to_json()
                }));
            }
            // Construct a minimal run_record for fallback
            (fallback_dir, crate::db::RunRecord {
                run_id: run_id.clone(),
                name: None,
                profile: None,
                started_at: String::new(),
                stopped_at: None,
                run_dir: None,
                events_total: 0,
                segments_count: 0,
                facts_extracted: 0,
                signals_fired: 0,
                bytes_written: 0,
                status: "unknown".to_string(),
                baseline_scope: None,
                baseline_enabled: false,
                baseline_set_at: None,
                chain_ids: None,
            })
        }
    };
    
    // Call the refactored service (RUN_BRIEF-1)
    match services::run_brief::build_run_brief(&run_id, &run_dir) {
        Ok(brief) => Json(serde_json::json!({
            "success": true,
            "data": brief.to_json()
        })),
        Err(services::run_brief::RunBriefError::MissingDb(_)) => Json(serde_json::json!({
            "success": true,
            "data": services::run_brief::RunBriefUnavailable::missing_db(&run_id).to_json()
        })),
        Err(services::run_brief::RunBriefError::DbOpenError(msg)) => Json(serde_json::json!({
            "success": false,
            "error": format!("Failed to open database: {}", msg)
        })),
        Err(services::run_brief::RunBriefError::RunNotFound(_)) => Json(serde_json::json!({
            "success": true,
            "data": services::run_brief::RunBriefUnavailable::not_found(&run_id).to_json()
        })),
    }
}

// ============================================================================
// LEGACY_RUN_BRIEF_INLINE (kept for safety; remove later)
// ============================================================================
// The original inline implementation has been refactored into:
// - services/run_brief.rs (orchestrator)
// - services/run_brief_repo.rs (DB queries)
// - services/episodes.rs (clustering logic)
// - services/evidence_ptrs.rs (parsing utilities)
//
// Original code preserved below for reference during validation:
/*
async fn run_brief_handler_legacy(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Json<serde_json::Value> {
    // Resolve run directory (Constraint 1: Per-Run DB Isolation)
    let (run_dir, _run_record) = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok(r) => r,
        Err(_) => {
            let fallback_dir = state.data_dir.join("runs").join(&run_id);
            if !fallback_dir.exists() {
                return Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "available": false,
                        "reason": "RUN_NOT_FOUND",
                        "run_id": run_id
                    }
                }));
            }
            // Construct a minimal run_record for fallback
            (fallback_dir, crate::db::RunRecord {
                run_id: run_id.clone(),
                name: None,
                profile: None,
                started_at: String::new(),
                stopped_at: None,
                run_dir: None,
                events_total: 0,
                segments_count: 0,
                facts_extracted: 0,
                signals_fired: 0,
                bytes_written: 0,
                status: "unknown".to_string(),
                baseline_scope: None,
                baseline_enabled: false,
                baseline_set_at: None,
                chain_ids: None,
            })
        }
    };
    
    let db_path = run_dir.join("workbench.db");
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason": "MISSING_DB",
                "run_id": run_id
            }
        }));
    }
    
    let conn = match rusqlite::Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to open database: {}", e)
            }));
        }
    };
    
    // === COVERAGE: Capability snapshot from run_meta.json (Constraint 4) ===
    let meta_path = run_dir.join("run_meta.json");
    let capability = services::capability::get_capability_snapshot_from_meta(&meta_path);
    let snapshot_present = capability.get("is_admin").is_some() 
        || capability.get("sysmon_installed").is_some();
    
    let is_admin = capability.get("is_admin").and_then(|v| v.as_bool());
    let sysmon_installed = capability.get("sysmon_installed").and_then(|v| v.as_bool());
    let security_log_accessible = capability.get("security_log_accessible").and_then(|v| v.as_bool());
    
    // Build coverage gaps
    let mut gaps: Vec<serde_json::Value> = Vec::new();
    if is_admin == Some(false) {
        gaps.push(serde_json::json!({
            "gap": "NOT_ADMIN",
            "impact": "Limited access to Security event log"
        }));
    }
    if sysmon_installed == Some(false) {
        gaps.push(serde_json::json!({
            "gap": "NO_SYSMON",
            "impact": "No process command lines, network connections"
        }));
    }
    if security_log_accessible == Some(false) {
        gaps.push(serde_json::json!({
            "gap": "NO_SECURITY_LOG",
            "impact": "No authentication events"
        }));
    }
    
    // === TOTALS: From coverage_rollup (NOT facts_sample which is sampled) ===
    let events_total: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(event_count), 0) FROM coverage_rollup WHERE event_count IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .ok()
        .filter(|&v| v > 0)
        .or_else(|| {
            // Fallback to segments.records if coverage_rollup empty
            conn.query_row("SELECT COALESCE(SUM(records), 0) FROM segments", [], |row| row.get(0)).ok()
        })
        .unwrap_or(0);
    
    let facts_total: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(fact_count), 0) FROM coverage_rollup WHERE fact_count IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .ok()
        .filter(|&v| v > 0)
        .or_else(|| {
            // Fallback to segments.facts if coverage_rollup empty
            conn.query_row("SELECT COALESCE(SUM(facts), 0) FROM segments", [], |row| row.get(0)).ok()
        })
        .unwrap_or(0);
    
    let signals_fired: i64 = conn
        .query_row("SELECT COUNT(*) FROM signals", [], |row| row.get(0))
        .unwrap_or(0);
    
    let segments_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM segments", [], |row| row.get(0))
        .unwrap_or(0);
    
    // ... (remaining ~400 lines of original inline code omitted for brevity)
    // ... Full original code can be found in git history or run_brief_repo.rs
    
    Json(serde_json::json!({"success": false, "error": "Legacy handler - should not be called"}))
}
*/

// ============================================================================
// EVIDENCE BROWSE MODES: Events, Signals, Segments
// ============================================================================

/// Query params for events endpoint
#[derive(Debug, Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
    offset: Option<usize>,
    segment_id: Option<String>,
    event_type: Option<String>,
    query: Option<String>,
}

/// GET /api/runs/:run_id/events - Browse raw events
/// 
/// Returns paginated raw events from segments for the "Events" browse mode.
/// These map to the "705 events" count shown in Overview.
/// 
/// # Query Params
/// - `limit` (default 100, max 500)
/// - `offset` (default 0)
/// - `segment_id` (optional, filter by segment)
/// - `event_type` (optional, filter by type)
/// - `query` (optional, search in summary)
/// 
/// # Response
/// ```json
/// {
///   "success": true,
///   "data": {
///     "events": [{ ts, event_type, summary, segment_id, record_index, host, raw_preview }],
///     "total": 705,
///     "pagination": { limit, offset, has_more }
///   }
/// }
/// ```
async fn run_events_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Query(params): Query<EventsQuery>,
) -> Json<serde_json::Value> {
    let run_dir = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok((dir, _)) => dir,
        Err(_) => {
            let fallback_dir = state.data_dir.join("runs").join(&run_id);
            if !fallback_dir.exists() {
                return Json(serde_json::json!({
                    "success": false,
                    "error": "RUN_NOT_FOUND",
                    "run_id": run_id
                }));
            }
            fallback_dir
        }
    };
    
    let db_path = run_dir.join("workbench.db");
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": false,
            "error": "MISSING_DB",
            "run_id": run_id
        }));
    }
    
    let conn = match rusqlite::Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("DB_OPEN_ERROR: {}", e)
            }));
        }
    };
    
    let limit = params.limit.unwrap_or(100).min(500);
    let offset = params.offset.unwrap_or(0);
    
    // Get total events count (same source as Overview: coverage_rollup.event_count OR segments.records)
    let total_events: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(event_count), 0) FROM coverage_rollup WHERE event_count IS NOT NULL",
            [],
            |row| row.get::<_, i64>(0),
        )
        .ok()
        .filter(|&v| v > 0)
        .or_else(|| {
            conn.query_row("SELECT COALESCE(SUM(records), 0) FROM segments", [], |row| row.get(0)).ok()
        })
        .unwrap_or(0);
    
    // Check if we have canonical_events table (newer runs)
    let has_canonical_events: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='canonical_events'")
        .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
        .unwrap_or(false);
    
    let events: Vec<serde_json::Value> = if has_canonical_events {
        // Newer run: query canonical_events
        let mut sql = String::from(
            "SELECT event_id, ts, event_type, segment_id, record_index, host_id,
                    proc_scope_key, exe_scope_key
             FROM canonical_events WHERE 1=1"
        );
        let mut query_params: Vec<String> = Vec::new();
        
        if let Some(ref seg_id) = params.segment_id {
            sql.push_str(" AND segment_id = ?");
            query_params.push(seg_id.clone());
        }
        if let Some(ref evt_type) = params.event_type {
            sql.push_str(" AND event_type = ?");
            query_params.push(evt_type.clone());
        }
        if let Some(ref q) = params.query {
            sql.push_str(" AND (proc_scope_key LIKE ? OR exe_scope_key LIKE ? OR event_type LIKE ?)");
            query_params.push(format!("%{}%", q));
            query_params.push(format!("%{}%", q));
            query_params.push(format!("%{}%", q));
        }
        
        sql.push_str(" ORDER BY ts DESC LIMIT ? OFFSET ?");
        query_params.push(limit.to_string());
        query_params.push(offset.to_string());
        
        let refs: Vec<&dyn rusqlite::ToSql> = query_params.iter()
            .map(|s| s as &dyn rusqlite::ToSql)
            .collect();
        
        conn.prepare(&sql)
            .and_then(|mut stmt| {
                stmt.query_map(refs.as_slice(), |row| {
                    Ok(serde_json::json!({
                        "event_id": row.get::<_, String>(0)?,
                        "ts": row.get::<_, i64>(1)?,
                        "event_type": row.get::<_, String>(2)?,
                        "segment_id": row.get::<_, String>(3)?,
                        "record_index": row.get::<_, i64>(4)?,
                        "host": row.get::<_, String>(5)?,
                        "summary": format!("{} | {}", 
                            row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                            row.get::<_, Option<String>>(7)?.unwrap_or_default()
                        ),
                        "raw_preview": null // Would need segment file access
                    }))
                })
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
            })
            .unwrap_or_default()
    } else {
        // Older run or no canonical_events: use facts_sample as proxy for browsable events
        // Each fact corresponds to one or more underlying events
        // Also include segment-level summary
        let mut events_proxy: Vec<serde_json::Value> = Vec::new();
        
        // First, add segment summaries (these represent the raw event batches)
        let segments_summary: Vec<serde_json::Value> = conn
            .prepare("SELECT segment_id, stream_id, host_id, 
                             COALESCE(record_count, records, 0) as record_count,
                             start_ts, end_ts
                      FROM segments ORDER BY start_ts DESC")
            .and_then(|mut stmt| {
                stmt.query_map([], |row| {
                    let seg_id: String = row.get(0)?;
                    let stream_id: String = row.get(1)?;
                    let host: String = row.get(2)?;
                    let record_count: i64 = row.get(3)?;
                    let start_ts: i64 = row.get(4)?;
                    let _end_ts: i64 = row.get(5)?;
                    Ok(serde_json::json!({
                        "event_type": format!("Segment: {}", stream_id),
                        "host": host,
                        "ts": start_ts,
                        "segment_id": seg_id,
                        "record_index": null,
                        "count": record_count,
                        "summary": format!("{} events in segment {} from {}", record_count, seg_id, stream_id),
                        "is_summary": true,
                        "is_segment": true
                    }))
                })
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
            })
            .unwrap_or_default();
        
        events_proxy.extend(segments_summary);
        
        // Then add recent facts as event proxies (paginated)
        if events_proxy.len() < limit {
            let remaining = limit - events_proxy.len();
            let facts_as_events: Vec<serde_json::Value> = conn
                .prepare("SELECT fact_id, fact_type, host, ts, entity_key, details_json
                          FROM facts_sample 
                          ORDER BY ts DESC 
                          LIMIT ? OFFSET ?")
                .and_then(|mut stmt| {
                    stmt.query_map(rusqlite::params![remaining as i64, offset as i64], |row| {
                        let details_str: String = row.get(5)?;
                        let details: serde_json::Value = serde_json::from_str(&details_str).unwrap_or(serde_json::json!({}));
                        Ok(serde_json::json!({
                            "event_type": row.get::<_, String>(1)?,
                            "host": row.get::<_, String>(2)?,
                            "ts": row.get::<_, i64>(3)?,
                            "segment_id": null,
                            "record_index": null,
                            "summary": format!("{} on {}", row.get::<_, String>(1)?, row.get::<_, Option<String>>(4)?.unwrap_or_default()),
                            "details": details,
                            "fact_id": row.get::<_, String>(0)?,
                            "is_fact_proxy": true
                        }))
                    })
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
                })
                .unwrap_or_default();
            
            events_proxy.extend(facts_as_events);
        }
        
        events_proxy
    };
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "run_id": run_id,
            "events": events,
            "total": total_events,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "has_more": (offset + events.len()) < total_events as usize
            },
            "has_individual_events": has_canonical_events
        }
    }))
}

/// Query params for signals endpoint  
#[derive(Debug, Deserialize)]
struct SignalsQuery {
    severity: Option<String>,
    playbook_id: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

/// GET /api/runs/:run_id/signals - Browse signals
/// 
/// Returns signals for the "Signals" browse mode.
/// These map to the "1 signal" count shown in Overview.
/// 
/// # Response
/// ```json
/// {
///   "success": true,
///   "data": {
///     "signals": [{ signal_id, signal_type, severity, title, playbook_id, ts, evidence_ptrs, summary }],
///     "total": 1
///   }
/// }
/// ```
async fn run_signals_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Query(params): Query<SignalsQuery>,
) -> Json<serde_json::Value> {
    let run_dir = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok((dir, _)) => dir,
        Err(_) => {
            let fallback_dir = state.data_dir.join("runs").join(&run_id);
            if !fallback_dir.exists() {
                return Json(serde_json::json!({
                    "success": false,
                    "error": "RUN_NOT_FOUND",
                    "run_id": run_id
                }));
            }
            fallback_dir
        }
    };
    
    let db_path = run_dir.join("workbench.db");
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": false,
            "error": "MISSING_DB",
            "run_id": run_id
        }));
    }
    
    let conn = match rusqlite::Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("DB_OPEN_ERROR: {}", e)
            }));
        }
    };
    
    let limit = params.limit.unwrap_or(100).min(500);
    let offset = params.offset.unwrap_or(0);
    
    // Check if signals table exists
    let has_signals: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='signals'")
        .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
        .unwrap_or(false);
    
    if !has_signals {
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "run_id": run_id,
                "signals": [],
                "total": 0,
                "reason": "NO_SIGNALS_TABLE"
            }
        }));
    }
    
    // Get total signals count
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM signals", [], |row| row.get(0))
        .unwrap_or(0);
    
    // Build query - note: playbook_id may not exist, extract from signal_type (format: "playbook:xxx")
    let mut sql = String::from(
        "SELECT signal_id, signal_type, severity, host, ts,
                evidence_ptrs, metadata
         FROM signals WHERE 1=1"
    );
    let mut query_params: Vec<String> = Vec::new();
    
    if let Some(ref sev) = params.severity {
        sql.push_str(" AND severity = ?");
        query_params.push(sev.clone());
    }
    if let Some(ref pb_id) = params.playbook_id {
        sql.push_str(" AND signal_type LIKE ?");
        query_params.push(format!("%{}%", pb_id));
    }
    
    sql.push_str(" ORDER BY ts DESC LIMIT ? OFFSET ?");
    query_params.push(limit.to_string());
    query_params.push(offset.to_string());
    
    let refs: Vec<&dyn rusqlite::ToSql> = query_params.iter()
        .map(|s| s as &dyn rusqlite::ToSql)
        .collect();
    
    let signals: Vec<serde_json::Value> = conn
        .prepare(&sql)
        .and_then(|mut stmt| {
            stmt.query_map(refs.as_slice(), |row| {
                let evidence_ptrs_json: Option<String> = row.get(5)?;
                let metadata_json: Option<String> = row.get(6)?;
                
                let evidence_ptrs: serde_json::Value = evidence_ptrs_json
                    .as_ref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(serde_json::json!([]));
                
                let metadata: serde_json::Value = metadata_json
                    .as_ref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(serde_json::json!({}));
                
                let signal_type: String = row.get(1)?;
                // Extract playbook_id from signal_type (format: "playbook:xxx" or just type)
                let playbook_id = signal_type.strip_prefix("playbook:")
                    .unwrap_or(&signal_type)
                    .to_string();
                
                // Generate title from signal_type/playbook_id
                let title = playbook_id.replace('_', " ")
                    .split_whitespace()
                    .map(|w| {
                        let mut chars = w.chars();
                        match chars.next() {
                            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                            None => String::new()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                
                let evidence_count = evidence_ptrs.as_array().map(|a| a.len()).unwrap_or(0);
                
                Ok(serde_json::json!({
                    "signal_id": row.get::<_, String>(0)?,
                    "signal_type": signal_type,
                    "severity": row.get::<_, String>(2)?,
                    "host": row.get::<_, String>(3)?,
                    "ts": row.get::<_, i64>(4)?,
                    "playbook_id": playbook_id,
                    "title": title,
                    "evidence_ptrs": evidence_ptrs,
                    "evidence_count": evidence_count,
                    "metadata": metadata,
                    "summary": format!("{} detection on {}", title, row.get::<_, String>(3)?)
                }))
            })
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "run_id": run_id,
            "signals": signals,
            "total": total,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "has_more": (offset + signals.len()) < total as usize
            }
        }
    }))
}

/// Query params for segments endpoint
#[derive(Debug, Deserialize)]
struct SegmentsQuery {
    stream_id: Option<String>,
}

/// GET /api/runs/:run_id/segments - Browse segments
/// 
/// Returns segment metadata for the "Segments" browse mode.
/// These map to the "1 segment" count shown in Overview.
/// 
/// # Response
/// ```json
/// {
///   "success": true,
///   "data": {
///     "segments": [{ segment_id, stream_id, start_ts, end_ts, record_count, size_bytes, path, sha256 }],
///     "total": 1
///   }
/// }
/// ```
async fn run_segments_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Query(params): Query<SegmentsQuery>,
) -> Json<serde_json::Value> {
    let run_dir = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok((dir, _)) => dir,
        Err(_) => {
            let fallback_dir = state.data_dir.join("runs").join(&run_id);
            if !fallback_dir.exists() {
                return Json(serde_json::json!({
                    "success": false,
                    "error": "RUN_NOT_FOUND",
                    "run_id": run_id
                }));
            }
            fallback_dir
        }
    };
    
    let db_path = run_dir.join("workbench.db");
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": false,
            "error": "MISSING_DB",
            "run_id": run_id
        }));
    }
    
    let conn = match rusqlite::Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("DB_OPEN_ERROR: {}", e)
            }));
        }
    };
    
    // Check if segments table exists
    let has_segments: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='segments'")
        .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
        .unwrap_or(false);
    
    if !has_segments {
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "run_id": run_id,
                "segments": [],
                "total": 0,
                "reason": "NO_SEGMENTS_TABLE"
            }
        }));
    }
    
    // Get total segments count
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM segments", [], |row| row.get(0))
        .unwrap_or(0);
    
    // Try to detect segment table schema (older runs have different columns)
    // New schema: segment_id, stream_id, host_id, path, sha256, start_ts, end_ts, record_count, size_bytes
    // Old schema: segment_id, segment_path, records, facts, signals, size_bytes, processed_at
    let has_stream_id: bool = conn
        .prepare("SELECT 1 FROM pragma_table_info('segments') WHERE name = 'stream_id'")
        .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
        .unwrap_or(false);
    
    let segments: Vec<serde_json::Value> = if has_stream_id {
        // New schema
        let mut sql = String::from(
            "SELECT segment_id, stream_id, host_id, path, sha256, 
                    start_ts, end_ts, 
                    COALESCE(record_count, records, 0) as record_count,
                    COALESCE(size_bytes, 0) as size_bytes,
                    created_at
             FROM segments WHERE 1=1"
        );
        let mut query_params: Vec<String> = Vec::new();
        
        if let Some(ref stream) = params.stream_id {
            sql.push_str(" AND stream_id = ?");
            query_params.push(stream.clone());
        }
        
        sql.push_str(" ORDER BY start_ts DESC");
        
        let refs: Vec<&dyn rusqlite::ToSql> = query_params.iter()
            .map(|s| s as &dyn rusqlite::ToSql)
            .collect();
        
        conn.prepare(&sql)
            .and_then(|mut stmt| {
                stmt.query_map(refs.as_slice(), |row| {
                    Ok(serde_json::json!({
                        "segment_id": row.get::<_, String>(0)?,
                        "stream_id": row.get::<_, String>(1)?,
                        "host_id": row.get::<_, String>(2)?,
                        "path": row.get::<_, Option<String>>(3)?,
                        "sha256": row.get::<_, Option<String>>(4)?,
                        "start_ts": row.get::<_, i64>(5)?,
                        "end_ts": row.get::<_, i64>(6)?,
                        "record_count": row.get::<_, i64>(7)?,
                        "size_bytes": row.get::<_, i64>(8)?,
                        "created_at": row.get::<_, Option<i64>>(9)?
                    }))
                })
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
            })
            .unwrap_or_default()
    } else {
        // Old schema (locald)
        conn.prepare("SELECT segment_id, segment_path, records, size_bytes, processed_at
                      FROM segments ORDER BY processed_at DESC")
            .and_then(|mut stmt| {
                stmt.query_map([], |row| {
                    let segment_id: String = row.get(0)?;
                    let path: String = row.get(1)?;
                    let records: i64 = row.get(2)?;
                    let size_bytes: i64 = row.get(3)?;
                    let processed_at: Option<String> = row.get(4)?;
                    
                    // Extract stream_id from path (e.g. "segments/Microsoft-Windows-Sysmon%2FOperational_0.jsonl")
                    let stream_id = path.split('/')
                        .last()
                        .and_then(|f| f.split('_').next())
                        .map(|s| s.replace("%2F", "/"))
                        .unwrap_or_else(|| "unknown".to_string());
                    
                    Ok(serde_json::json!({
                        "segment_id": segment_id,
                        "stream_id": stream_id,
                        "host_id": null,
                        "path": path,
                        "sha256": null,
                        "start_ts": null,
                        "end_ts": null,
                        "record_count": records,
                        "size_bytes": size_bytes,
                        "processed_at": processed_at
                    }))
                })
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
            })
            .unwrap_or_default()
    };
    
    // Get unique stream types
    let streams: Vec<String> = if has_stream_id {
        conn.prepare("SELECT DISTINCT stream_id FROM segments ORDER BY stream_id")
            .and_then(|mut stmt| {
                stmt.query_map([], |row| row.get(0))
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
            })
            .unwrap_or_default()
    } else {
        // Extract from paths in old schema
        segments.iter()
            .filter_map(|s| s.get("stream_id").and_then(|v| v.as_str()).map(String::from))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    };
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "run_id": run_id,
            "segments": segments,
            "total": total,
            "streams": streams
        }
    }))
}

async fn run_state_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Json<serde_json::Value> {
    // Try DB first, fall back to filesystem path (for runs discovered via scan)
    let run_dir = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok((dir, _)) => dir,
        Err(_) => {
            // Fallback: construct path from data_dir
            let fallback_dir = state.data_dir.join("runs").join(&run_id);
            if !fallback_dir.exists() {
                return Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "available": false,
                        "reason": "RUN_NOT_FOUND",
                        "run_id": run_id
                    }
                }));
            }
            fallback_dir
        }
    };
    
    let db_path = run_dir.join("workbench.db");
    let meta_path = run_dir.join("run_meta.json");
    
    let (started_at, stopped_at, status) = services::run_control::read_run_meta(&meta_path, &run_id);
    let (events, segments, facts, signals, _, _, _) = 
        if db_path.exists() {
            services::run_control::read_run_stats(&db_path)
        } else {
            (0, 0, 0, 0, 0, 0, None)
        };
    
    // Get top entities from the run's DB (processes with most facts)
    let top_entities = get_top_entities_from_db(&db_path);
    
    // Determine telemetry status based on data presence
    // For historical runs, we derive status from what data exists
    let telemetry_status = if facts > 0 && signals > 0 {
        "full"
    } else if facts > 0 {
        "partial"
    } else {
        "limited"
    };
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "available": true,
            "run_id": run_id,
            "status": status,
            "started_at": started_at.map(|t| t.to_rfc3339()),
            "stopped_at": stopped_at.map(|t| t.to_rfc3339()),
            "events_total": events,
            "segments_count": segments,
            "facts_extracted": facts,
            "facts_total": facts,
            "signals_count": signals,
            "telemetry_status": telemetry_status,
            "top_entities": top_entities
        }
    }))
}

/// Get top entities (processes, users) from a run's workbench.db
/// Enhanced to use multiple strategies for finding process data
fn get_top_entities_from_db(db_path: &std::path::Path) -> serde_json::Value {
    if !db_path.exists() {
        return serde_json::json!({});
    }
    
    let conn = match rusqlite::Connection::open(db_path) {
        Ok(c) => c,
        Err(_) => return serde_json::json!({}),
    };
    
    // Strategy 1: Get top processes by proc_key from entity_keys JSON
    let mut processes: Vec<serde_json::Value> = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT json_extract(entity_keys, '$.proc_key') as proc_key, COUNT(*) as cnt 
         FROM facts 
         WHERE json_extract(entity_keys, '$.proc_key') IS NOT NULL 
         GROUP BY proc_key 
         ORDER BY cnt DESC 
         LIMIT 5"
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            let proc_key: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((proc_key, count))
        }) {
            for row in rows.flatten() {
                processes.push(serde_json::json!({
                    "entity_key": row.0,
                    "fact_count": row.1
                }));
            }
        }
    }
    
    // Strategy 2: If no proc_key data, try to extract from fact_type 'Exec' details
    if processes.is_empty() {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT json_extract(details, '$.proc_key') as proc_key, COUNT(*) as cnt
             FROM facts
             WHERE fact_type = 'Exec' 
               AND json_extract(details, '$.proc_key') IS NOT NULL
             GROUP BY proc_key
             ORDER BY cnt DESC
             LIMIT 5"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let proc_key: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((proc_key, count))
            }) {
                for row in rows.flatten() {
                    processes.push(serde_json::json!({
                        "entity_key": row.0,
                        "fact_count": row.1
                    }));
                }
            }
        }
    }
    
    // Strategy 3: If still no data, try extracting exe/image path from Exec facts
    if processes.is_empty() {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT 
                COALESCE(
                    json_extract(details, '$.image'),
                    json_extract(details, '$.exe'),
                    json_extract(details, '$.process_name'),
                    json_extract(details, '$.cmdline')
                ) as proc_name, 
                COUNT(*) as cnt
             FROM facts
             WHERE fact_type IN ('Exec', 'ProcessCreate', 'ProcSpawn')
               AND COALESCE(
                    json_extract(details, '$.image'),
                    json_extract(details, '$.exe'),
                    json_extract(details, '$.process_name'),
                    json_extract(details, '$.cmdline')
                ) IS NOT NULL
             GROUP BY proc_name
             ORDER BY cnt DESC
             LIMIT 5"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let proc_name: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((proc_name, count))
            }) {
                for row in rows.flatten() {
                    // Truncate long paths for display
                    let display = if row.0.len() > 80 { 
                        format!("...{}", &row.0[row.0.len().saturating_sub(77)..])
                    } else { 
                        row.0.clone() 
                    };
                    processes.push(serde_json::json!({
                        "entity_key": display,
                        "fact_count": row.1,
                        "raw_path": row.0
                    }));
                }
            }
        }
    }
    
    // Get top users by fact count  
    let mut users: Vec<serde_json::Value> = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT json_extract(entity_keys, '$.identity_key') as identity_key, COUNT(*) as cnt 
         FROM facts 
         WHERE json_extract(entity_keys, '$.identity_key') IS NOT NULL 
         GROUP BY identity_key 
         ORDER BY cnt DESC 
         LIMIT 3"
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            let identity_key: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((identity_key, count))
        }) {
            for row in rows.flatten() {
                users.push(serde_json::json!({
                    "entity_key": row.0,
                    "fact_count": row.1
                }));
            }
        }
    }
    
    // Also check if we have any Exec-type facts at all (for diagnostic purposes)
    let exec_fact_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM facts WHERE fact_type IN ('Exec', 'ProcessCreate', 'ProcSpawn')",
            [],
            |row| row.get(0)
        )
        .unwrap_or(0);
    
    serde_json::json!({
        "processes": processes,
        "users": users,
        "has_exec_facts": exec_fact_count > 0,
        "exec_fact_count": exec_fact_count
    })
}

async fn run_next_steps_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Json<serde_json::Value> {
    // Try DB first, fall back to filesystem path (for runs discovered via scan)
    let run_dir = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok((dir, _)) => dir,
        Err(_) => {
            // Fallback: construct path from data_dir
            let fallback_dir = state.data_dir.join("runs").join(&run_id);
            if !fallback_dir.exists() {
                return Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "available": false,
                        "reason": "RUN_NOT_FOUND",
                        "run_id": run_id
                    }
                }));
            }
            fallback_dir
        }
    };
    
    let db_path = run_dir.join("workbench.db");
    
    let (events, _segments, facts, signals, _, _, _) = 
        if db_path.exists() {
            services::run_control::read_run_stats(&db_path)
        } else {
            (0, 0, 0, 0, 0, 0, None)
        };
    
    // Load coverage data for gap analysis
    let coverage = run_coverage::load_run_coverage(&run_dir, &run_id).ok();
    
    // Get run-scoped capability snapshot from run_meta.json (SSoT: no live probes in run-scoped handlers)
    let meta_path = run_dir.join("run_meta.json");
    let capability = services::capability::get_capability_snapshot_from_meta(&meta_path);
    let sysmon_installed = capability.get("sysmon_installed").and_then(|v| v.as_bool()).unwrap_or(false);
    let security_log_accessible = capability.get("security_log_accessible").and_then(|v| v.as_bool()).unwrap_or(false);
    let is_admin = capability.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
    
    // Check for interrupted/abandoned run state from run_meta.json
    let run_status = capability.get("status").and_then(|v| v.as_str()).unwrap_or("");
    let compile_status = capability.get("compile_status").and_then(|v| v.as_str()).unwrap_or("");
    let abandoned_reason = capability.get("abandoned_reason").and_then(|v| v.as_str());
    let is_interrupted = run_status == "abandoned" || compile_status == "interrupted";
    
    // Check PowerShell logging channel from snapshot
    let powershell_accessible = capability.get("channels").and_then(|v| v.as_array()).map(|chs| {
        chs.iter().any(|c| {
            c.get("name").and_then(|n| n.as_str()) == Some("Microsoft-Windows-PowerShell/Operational")
                && c.get("accessible").and_then(|a| a.as_bool()).unwrap_or(false)
        })
    }).unwrap_or(false);
    
    // Analyze gaps based on actual coverage data
    let mut actions: Vec<serde_json::Value> = Vec::new();
    let mut gaps: Vec<String> = Vec::new();
    let mut severity = "info";
    
    // ========================================================================
    // STEP -1: INTERRUPTED RUN RECOVERY ACTION (highest priority)
    // If the run was interrupted/abandoned, always show recovery guidance first
    // ========================================================================
    if is_interrupted {
        severity = "high";
        gaps.push("run_interrupted".to_string());
        
        let reason_text = abandoned_reason.unwrap_or("Server process was terminated unexpectedly");
        let facts_available = if facts > 0 {
            format!("{} facts were extracted before interruption. Pivots and exploration still work.", facts)
        } else {
            "No facts were extracted before the interruption.".to_string()
        };
        
        actions.push(serde_json::json!({
            "action_id": "recover_interrupted_run",
            "title": "🔄 Recover from Interrupted Run",
            "rationale": format!("This run was interrupted: {}. {}", reason_text, facts_available),
            "why": "Incomplete runs may have missing facts and cannot produce accurate detection results.",
            "how": [
                "Go to the Mission tab",
                "Click 'Start Run' to begin a new capture",
                "Let the run complete for at least 2-5 minutes",
                "Click 'Stop Run' to finalize the results"
            ],
            "verify": [
                "New run shows 'FINALIZED' status",
                "Facts count is non-zero",
                "Coverage data is complete"
            ],
            "requires": {},
            "priority": "high",
            "deep_link": { "tab": "mission" }
        }));
    }
    
    // Build Coverage Checklist
    let mut coverage_checklist: Vec<serde_json::Value> = Vec::new();
    
    // Extract fact types from coverage
    let fact_types: std::collections::HashSet<String> = coverage
        .as_ref()
        .map(|c| c.fact_types.iter().map(|ft| ft.fact_type.clone()).collect())
        .unwrap_or_default();
    
    // Get pipeline diagnostics
    let pipeline = coverage.as_ref().and_then(|c| c.pipeline_diagnostics.as_ref());
    
    // ========================================================================
    // STEP 0: EARLY OBSERVED TELEMETRY CHECK
    // Query facts_sample to see what telemetry was ACTUALLY observed.
    // This is used to suppress unlock actions when telemetry is already working
    // (capability snapshot may be stale or sensors enabled mid-run).
    // ========================================================================
    let (observed_ps, observed_exec, observed_network) = if facts > 0 && db_path.exists() {
        if let Ok(obs_conn) = rusqlite::Connection::open(&db_path) {
            let has_table: bool = obs_conn
                .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='facts_sample'")
                .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
                .unwrap_or(false);
            if has_table {
                let ps: bool = obs_conn
                    .prepare("SELECT 1 FROM facts_sample WHERE fact_type = 'ScriptExec' AND entity_key LIKE 'script:powershell%' LIMIT 1")
                    .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
                    .unwrap_or(false);
                let exec: bool = obs_conn
                    .prepare("SELECT 1 FROM facts_sample WHERE fact_type = 'Exec' LIMIT 1")
                    .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
                    .unwrap_or(false);
                let net: bool = obs_conn
                    .prepare("SELECT 1 FROM facts_sample WHERE fact_type = 'OutboundConnect' LIMIT 1")
                    .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
                    .unwrap_or(false);
                (ps, exec, net)
            } else {
                (false, false, false)
            }
        } else {
            (false, false, false)
        }
    } else {
        (false, false, false)
    };
    
    // ========================================================================
    // STEP A: VISIBILITY UNLOCKERS (highest priority)
    // These unlock the biggest detection surface gains
    // Skip actions if telemetry is ALREADY observed (satisfaction logic).
    // ========================================================================
    
    // A1: Security log blocked → Run as Admin
    // SATISFACTION: Skip if is_admin=true OR if process execution telemetry was observed
    if !security_log_accessible && !is_admin && !observed_exec {
        severity = "high";
        gaps.push("security_log_blocked".to_string());
        actions.push(serde_json::json!({
            "action_id": "run_as_admin",
            "title": "🔓 Run as Administrator",
            "rationale": "Security log access requires Administrator privileges. This unlocks 21+ playbooks.",
            "why": "Process execution, logon events, and privilege changes are logged in the Security log.",
            "how": [
                "Close the LocInt application",
                "Right-click locint.exe and select 'Run as administrator'",
                "Re-run your detection mission"
            ],
            "verify": [
                "System Readiness shows 'Security log: Accessible'",
                "Playbooks blocked count should decrease significantly"
            ],
            "requires": { "admin": true },
            "priority": "high"
        }));
        coverage_checklist.push(serde_json::json!({
            "surface": "Process Execution",
            "status": "blocked",
            "reason": "Security log requires Administrator",
            "unlock": "Run as Admin"
        }));
    } else if security_log_accessible || observed_exec {
        // Either capability reports accessible OR we actually observed Exec facts
        coverage_checklist.push(serde_json::json!({
            "surface": "Process Execution",
            "status": "ok",
            "reason": if observed_exec { "Process execution facts observed in run" } else { "Security 4688 events accessible" }
        }));
    }
    
    // A2: Sysmon not installed → Install Sysmon
    // SATISFACTION: Skip network coverage item if network telemetry was observed
    if !sysmon_installed {
        gaps.push("sysmon_not_installed".to_string());
        actions.push(serde_json::json!({
            "action_id": "install_sysmon",
            "title": "⬇️ Install Sysmon",
            "rationale": "Sysmon provides deep process and network telemetry for 3+ additional playbooks.",
            "why": "Process injection, DLL side-loading, and credential access detection require Sysmon.",
            "how": [
                "Download Sysmon from Microsoft Sysinternals",
                "Run as Administrator: sysmon64.exe -accepteula -i sysmonconfig.xml",
                "Restart LocInt after Sysmon is running"
            ],
            "verify": [
                "System Readiness shows 'Sysmon: Installed'",
                "Process Access (Sysmon 10) events appear"
            ],
            "requires": { "admin": true, "sysmon": true },
            "priority": "medium"
        }));
        coverage_checklist.push(serde_json::json!({
            "surface": "Process Injection",
            "status": "blocked",
            "reason": "Sysmon not installed",
            "unlock": "Install Sysmon"
        }));
        // Network: show blocked unless observed
        if !observed_network {
            coverage_checklist.push(serde_json::json!({
                "surface": "Network Connections",
                "status": "blocked", 
                "reason": "Sysmon Event 3 not available",
                "unlock": "Install Sysmon"
            }));
        } else {
            coverage_checklist.push(serde_json::json!({
                "surface": "Network Connections",
                "status": "ok", 
                "reason": "Network facts observed in run"
            }));
        }
    } else {
        coverage_checklist.push(serde_json::json!({
            "surface": "Process Injection",
            "status": "ok",
            "reason": "Sysmon ProcessAccess events available"
        }));
        // Network: ok because Sysmon is installed (or was observed)
        coverage_checklist.push(serde_json::json!({
            "surface": "Network Connections",
            "status": "ok",
            "reason": if observed_network { "Network facts observed in run" } else { "Sysmon Event 3 available" }
        }));
    }
    
    // A3: PowerShell logging not enabled
    // SATISFACTION: Skip if PowerShell telemetry was actually observed (works despite capability snapshot)
    if !powershell_accessible && !observed_ps {
        gaps.push("powershell_logging_disabled".to_string());
        actions.push(serde_json::json!({
            "action_id": "enable_powershell_logging",
            "title": "⚙️ Enable PowerShell Logging",
            "rationale": "PowerShell Script Block Logging captures encoded command execution.",
            "why": "Many attacks use PowerShell with encoded commands (-EncodedCommand) for evasion.",
            "how": [
                "Open Group Policy Editor (gpedit.msc) as Administrator",
                "Navigate to: Computer Configuration → Admin Templates → Windows PowerShell",
                "Enable 'Turn on PowerShell Script Block Logging'",
                "Alternatively set registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging = 1"
            ],
            "verify": [
                "PowerShell/Operational log shows events",
                "Script block text appears in events"
            ],
            "priority": "low"
        }));
        coverage_checklist.push(serde_json::json!({
            "surface": "PowerShell Execution",
            "status": "partial",
            "reason": "Script Block Logging not enabled",
            "unlock": "Enable via Group Policy"
        }));
    } else if powershell_accessible || observed_ps {
        // Either capability reports accessible OR we actually observed PS facts
        coverage_checklist.push(serde_json::json!({
            "surface": "PowerShell Execution",
            "status": "ok",
            "reason": if observed_ps { "PowerShell facts observed in run" } else { "PowerShell Operational log accessible" }
        }));
    }
    
    // System log (always available) - persistence via Service Install
    coverage_checklist.push(serde_json::json!({
        "surface": "Service Persistence",
        "status": "ok",
        "reason": "System Event 7045 always available"
    }));
    
    coverage_checklist.push(serde_json::json!({
        "surface": "Log Tampering",
        "status": "ok",
        "reason": "System Event 104 always available"
    }));
    
    // ========================================================================
    // STEP B: COVERAGE GAPS (based on observed facts)
    // ========================================================================
    
    // CRITICAL GAP: No telemetry at all
    if events == 0 || facts == 0 {
        severity = "high";
        gaps.push("no_telemetry".to_string());
        actions.push(serde_json::json!({
            "action_id": "enable_telemetry",
            "title": "Enable telemetry collection",
            "rationale": "No events were captured. Run as Administrator to access Security logs.",
            "why": "Windows Security and Sysmon logs require elevated privileges to read.",
            "how": [
                "Close LocInt application",
                "Right-click LocInt and select 'Run as administrator'",
                "Re-run your capture"
            ],
            "verify": [
                "Events total should be > 0",
                "Facts extracted should show values"
            ],
            "requires": { "admin": true }
        }));
    }
    
    // COVERAGE GAP: No process execution facts (Exec, ProcessCreate)
    let has_proc_facts = fact_types.iter().any(|ft| 
        ft == "Exec" || ft == "ProcessCreate" || ft == "ImageLoad" || ft.contains("Process")
    );
    if facts > 0 && !has_proc_facts {
        severity = if severity == "high" { "high" } else { "medium" };
        gaps.push("missing_process_telemetry".to_string());
        actions.push(serde_json::json!({
            "action_id": "enable_sysmon",
            "title": "Install Sysmon for process visibility",
            "rationale": "No process execution facts detected. Sysmon provides detailed process telemetry.",
            "why": "Process creation events are essential for detecting malicious execution patterns.",
            "how": [
                "Download Sysmon from Microsoft Sysinternals",
                "Run 'sysmon -accepteula -i' as Administrator",
                "Re-run your capture after Sysmon is active"
            ],
            "verify": [
                "Exec or ProcessCreate fact types should appear",
                "Top Process should show in System State Summary"
            ],
            "requires": { "admin": true, "sysmon": true },
            "deep_link": { "tab": "facts", "run_id": run_id.clone() }
        }));
    }
    
    // COVERAGE GAP: No network facts
    let has_net_facts = fact_types.iter().any(|ft| 
        ft == "NetworkConnect" || ft == "DnsQuery" || ft.contains("Network") || ft.contains("Dns")
    );
    if facts > 50 && !has_net_facts && has_proc_facts {
        gaps.push("missing_network_telemetry".to_string());
        actions.push(serde_json::json!({
            "action_id": "enable_network_logging",
            "title": "Enable network event logging",
            "rationale": "No network connection facts detected. Enable Sysmon network events for C2 detection.",
            "why": "Network events help detect command-and-control (C2) and data exfiltration.",
            "how": [
                "Update Sysmon config to include NetworkConnect events (Event ID 3)",
                "Alternatively, enable Windows Firewall logging"
            ],
            "verify": [
                "NetworkConnect or DnsQuery fact types should appear"
            ]
        }));
    }
    
    // COVERAGE GAP: No file operation facts
    let has_file_facts = fact_types.iter().any(|ft| 
        ft == "FileCreate" || ft == "FileDelete" || ft.contains("File")
    );
    if facts > 50 && !has_file_facts && has_proc_facts {
        gaps.push("missing_file_telemetry".to_string());
        actions.push(serde_json::json!({
            "action_id": "enable_file_logging",
            "title": "Enable file operation logging",
            "rationale": "No file operation facts detected. Sysmon file events aid in detecting malware drops.",
            "why": "File creation events help detect payload drops and persistence mechanisms.",
            "how": [
                "Update Sysmon config to include FileCreate events (Event ID 11)",
                "Consider enabling FileDelete events for ransomware detection"
            ],
            "verify": [
                "FileCreate fact type should appear in Facts tab"
            ]
        }));
    }
    
    // PIPELINE GAP: Low playbook coverage
    let playbooks_loaded = pipeline.and_then(|p| p.playbooks_loaded).unwrap_or(0);
    if playbooks_loaded == 0 && facts > 0 {
        gaps.push("no_playbooks_loaded".to_string());
        severity = "medium";
        actions.push(serde_json::json!({
            "action_id": "check_playbooks",
            "title": "Check playbook configuration",
            "rationale": "No detection playbooks are loaded. Verify playbooks directory exists.",
            "why": "Detection playbooks define the patterns that generate signals.",
            "how": [
                "Verify playbooks directory exists in LocInt installation",
                "Check for YAML parse errors in playbook files",
                "Restart LocInt to reload playbooks"
            ],
            "verify": [
                "Playbook count should be > 0 in Facts tab Playbook Summary"
            ]
        }));
    }
    
    // LINKAGE GAP: Short capture duration
    let coverage_mins = pipeline.map(|p| p.coverage_minutes).unwrap_or(0);
    if coverage_mins < 2 && facts > 0 && facts < 100 {
        gaps.push("short_capture".to_string());
        actions.push(serde_json::json!({
            "action_id": "longer_capture",
            "title": "Run a longer capture",
            "rationale": format!("Capture was only {} minute(s). Longer captures improve pattern detection.", coverage_mins),
            "why": "Some attack patterns unfold over time and require sustained observation.",
            "how": [
                "Start a new capture",
                "Let it run for at least 5 minutes",
                "Generate activity to capture (if testing)"
            ],
            "verify": [
                "Coverage minutes should be >= 5"
            ]
        }));
    }
    
    // ========================================================================
    // STEP C: DISCOVERY PIVOTS (based on observed facts from facts_sample)
    // These surface interesting changes to investigate
    // ========================================================================
    
    // Query for discovery pivots if we have facts AND facts_sample table exists
    let mut discovery_pivots: Vec<serde_json::Value> = Vec::new();
    let mut pivots_unavailable_reason: Option<&str> = None;
    
    if facts > 0 && db_path.exists() {
        if let Ok(pivot_conn) = rusqlite::Connection::open(&db_path) {
            // Check if facts_sample table exists (graceful fallback - TWEAK A)
            let has_facts_sample_for_pivots: bool = pivot_conn
                .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='facts_sample'")
                .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
                .unwrap_or(false);
            
            if !has_facts_sample_for_pivots {
                pivots_unavailable_reason = Some("facts_sample table not present in this run (pre-persistence run)");
            } else {
                // Check for service installations (PersistArtifact with service entity_key)
                if let Ok(mut stmt) = pivot_conn.prepare(
                    "SELECT entity_key, details_json FROM facts_sample 
                     WHERE fact_type = 'PersistArtifact' AND entity_key LIKE 'service:%' LIMIT 3"
                ) {
                    if let Ok(rows) = stmt.query_map([], |row| {
                        let entity_key: Option<String> = row.get(0)?;
                        let _details_str: String = row.get(1)?;
                        Ok(entity_key)
                    }) {
                        for row in rows.flatten().flatten() {
                            if let Some(svc_name) = row.strip_prefix("service:") {
                                discovery_pivots.push(serde_json::json!({
                                    "category": "services",
                                    "entity": svc_name,
                                    "pivot_filter": "fact_type=PersistArtifact&category=persistence"
                                }));
                            }
                        }
                    }
                }
                
                // Check for scheduled tasks (PersistArtifact with task entity_key)
                if let Ok(mut stmt) = pivot_conn.prepare(
                    "SELECT entity_key, details_json FROM facts_sample 
                     WHERE fact_type = 'PersistArtifact' AND entity_key LIKE 'task:%' LIMIT 2"
                ) {
                    if let Ok(rows) = stmt.query_map([], |row| {
                        let entity_key: Option<String> = row.get(0)?;
                        let _details_str: String = row.get(1)?;
                        Ok(entity_key)
                    }) {
                        for row in rows.flatten().flatten() {
                            if let Some(task_name) = row.strip_prefix("task:") {
                                discovery_pivots.push(serde_json::json!({
                                    "category": "scheduled_tasks",
                                    "entity": task_name,
                                    "pivot_filter": "fact_type=PersistArtifact&category=persistence"
                                }));
                            }
                        }
                    }
                }
                
                // Check for log clears (LogTamper)
                let log_clear_count: i64 = pivot_conn.query_row(
                    "SELECT COUNT(*) FROM facts_sample WHERE fact_type = 'LogTamper'",
                    [],
                    |row| row.get(0)
                ).unwrap_or(0);
                if log_clear_count > 0 {
                    discovery_pivots.push(serde_json::json!({
                        "category": "logs_cleared",
                        "entity": format!("{} log(s) cleared", log_clear_count),
                        "sample_count": log_clear_count,
                        "total_count": log_clear_count,  // LogTamper typically not high volume
                        "pivot_filter": "fact_type=LogTamper&category=log_tamper"
                    }));
                }
                
                // Check for PowerShell execution (ScriptExec with powershell interpreter)
                // sample_count = rows in facts_sample (capped by design)
                // total_count = true total from coverage_rollup (if available)
                let ps_sample_count: i64 = pivot_conn.query_row(
                    "SELECT COUNT(*) FROM facts_sample WHERE fact_type = 'ScriptExec' AND entity_key LIKE 'script:powershell%'",
                    [],
                    |row| row.get(0)
                ).unwrap_or(0);
                
                // Try to get true total from coverage_rollup
                let ps_total_count: i64 = pivot_conn.query_row(
                    "SELECT COALESCE(SUM(fact_count), 0) FROM coverage_rollup WHERE fact_type = 'ScriptExec'",
                    [],
                    |row| row.get(0)
                ).unwrap_or(ps_sample_count);  // Fall back to sample if rollup unavailable
                
                if ps_sample_count > 0 {
                    // Build entity label: show "N shown (M total)" if total > sample
                    let entity_label = if ps_total_count > ps_sample_count {
                        format!("{} shown ({} total)", ps_sample_count, ps_total_count)
                    } else {
                        format!("{} PowerShell execution(s)", ps_sample_count)
                    };
                    
                    discovery_pivots.push(serde_json::json!({
                        "category": "powershell",
                        "entity": entity_label,
                        "sample_count": ps_sample_count,
                        "total_count": ps_total_count,
                        "pivot_filter": "fact_type=ScriptExec"  // Omit category - safer for filtering
                    }));
                }
                
                // Check for process execution (Exec facts)
                // sample_count = rows in facts_sample (capped by design)
                // total_count = true total from coverage_rollup (if available)
                let exec_sample_count: i64 = pivot_conn.query_row(
                    "SELECT COUNT(*) FROM facts_sample WHERE fact_type = 'Exec'",
                    [],
                    |row| row.get(0)
                ).unwrap_or(0);
                
                // Try to get true total from coverage_rollup
                let exec_total_count: i64 = pivot_conn.query_row(
                    "SELECT COALESCE(SUM(fact_count), 0) FROM coverage_rollup WHERE fact_type = 'Exec'",
                    [],
                    |row| row.get(0)
                ).unwrap_or(exec_sample_count);  // Fall back to sample if rollup unavailable
                
                if exec_sample_count > 0 {
                    // Build entity label: show "N shown (M total)" if total > sample
                    let entity_label = if exec_total_count > exec_sample_count {
                        format!("{} shown ({} total)", exec_sample_count, exec_total_count)
                    } else {
                        format!("{} process execution(s)", exec_sample_count)
                    };
                    
                    discovery_pivots.push(serde_json::json!({
                        "category": "process",
                        "entity": entity_label,
                        "sample_count": exec_sample_count,
                        "total_count": exec_total_count,
                        "pivot_filter": "fact_type=Exec"
                    }));
                }
            }
        }
    }
    
    // Add discovery pivot actions if interesting things found
    if !discovery_pivots.is_empty() {
        // Add top discovery pivot as an action
        let first_pivot = &discovery_pivots[0];
        let category = first_pivot.get("category").and_then(|v| v.as_str()).unwrap_or("changes");
        let entity = first_pivot.get("entity").and_then(|v| v.as_str()).unwrap_or("unknown");
        let pivot_filter = first_pivot.get("pivot_filter").and_then(|v| v.as_str()).unwrap_or("");
        
        let action_title = match category {
            "services" => format!("🔍 Inspect new service: {}", entity),
            "scheduled_tasks" => format!("🔍 Inspect scheduled task: {}", entity),
            "logs_cleared" => "⚠️ Investigate log clear events".to_string(),
            "powershell" => format!("🔍 Review PowerShell activity: {}", entity),
            "process" => format!("🔍 Review process execution: {}", entity),
            _ => format!("🔍 Investigate {} changes", category)
        };
        
        actions.push(serde_json::json!({
            "action_id": "discovery_pivot",
            "title": action_title,
            "rationale": format!("Discovered {} during this run. Review to assess legitimacy.", category.replace("_", " ")),
            "why": "New services, tasks, and log clears are common persistence and evasion techniques.",
            "how": [
                "Click to open Fact Inspector with filter applied",
                "Review the fact details and entity information",
                "Correlate with other facts from the same timeframe"
            ],
            "verify": [],
            "deep_link": { 
                "tab": "facts", 
                "run_id": run_id.clone(),
                "filter": pivot_filter
            },
            "priority": "medium"
        }));
    }
    
    // ========================================================================
    // STEP D: DRIFT DETECTION & VERIFY CONFIG ACTION
    // If telemetry was observed but capability snapshot says it's unavailable,
    // add a low-priority action to verify configuration.
    // ========================================================================
    
    // Check for observed telemetry drift (only if we have facts_sample)
    let mut has_drift = false;
    let mut drift_surfaces: Vec<String> = Vec::new();
    
    if facts > 0 && db_path.exists() {
        if let Ok(drift_conn) = rusqlite::Connection::open(&db_path) {
            let has_facts_sample_for_drift: bool = drift_conn
                .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='facts_sample'")
                .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
                .unwrap_or(false);
            
            if has_facts_sample_for_drift {
                // Check for PowerShell drift: observed but capability=false
                let obs_ps: bool = drift_conn
                    .prepare("SELECT 1 FROM facts_sample WHERE fact_type = 'ScriptExec' AND entity_key LIKE 'script:powershell%' LIMIT 1")
                    .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
                    .unwrap_or(false);
                if obs_ps && !powershell_accessible {
                    has_drift = true;
                    drift_surfaces.push("PowerShell".to_string());
                }
                
                // Check for Network drift: observed but sysmon=false
                let obs_net: bool = drift_conn
                    .prepare("SELECT 1 FROM facts_sample WHERE fact_type = 'OutboundConnect' LIMIT 1")
                    .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
                    .unwrap_or(false);
                if obs_net && !sysmon_installed {
                    has_drift = true;
                    drift_surfaces.push("Network".to_string());
                }
                
                // Check for Process drift: observed but security_log=false and sysmon=false
                let obs_exec: bool = drift_conn
                    .prepare("SELECT 1 FROM facts_sample WHERE fact_type = 'Exec' LIMIT 1")
                    .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
                    .unwrap_or(false);
                if obs_exec && !security_log_accessible && !sysmon_installed {
                    has_drift = true;
                    drift_surfaces.push("Process Execution".to_string());
                }
            }
        }
    }
    
    // Add verify_config_mismatch action if drift detected (low priority)
    if has_drift {
        actions.push(serde_json::json!({
            "action_id": "verify_config_mismatch",
            "title": "⚙️ Verify telemetry configuration (observed mismatch)",
            "rationale": format!("Telemetry was observed for: {}. However, capability snapshot reports these as unavailable. Verify sensor configuration.", drift_surfaces.join(", ")),
            "why": "The configuration snapshot taken at run start may not reflect current sensor state, or sensors were enabled mid-run.",
            "how": [
                "Re-run System Readiness check to refresh capability snapshot",
                "Confirm logging/provider settings match expectations",
                "Restart the run to capture fresh capability state"
            ],
            "verify": [
                "Drift banner disappears after re-running readiness",
                "Capability snapshot shows sensors as enabled",
                "Or: observed telemetry continues to appear consistently"
            ],
            "priority": "low"
        }));
    }
    
    // IF SIGNALS PRESENT: Add review action
    if signals > 0 {
        severity = if severity == "info" { "medium" } else { severity };
        actions.insert(0, serde_json::json!({
            "action_id": "review_findings",
            "title": format!("Review {} finding(s)", signals),
            "rationale": "Detected signals require review to assess severity and determine response.",
            "why": "Signals indicate potentially malicious patterns were matched by detection playbooks.",
            "how": [
                "Click on a signal row to expand details",
                "Review the Explain tab for evidence and scoring",
                "Check Top Process in the Overview for context"
            ],
            "verify": [
                "Each signal has been reviewed",
                "High-severity signals have been investigated"
            ],
            "deep_link": { "tab": "findings", "run_id": run_id.clone() }
        }));
    }
    
    // Determine scenario and summary
    let (scenario, summary_text) = if events == 0 {
        ("no_telemetry", "No telemetry was captured. Administrative privileges may be required.".to_string())
    } else if facts == 0 {
        ("no_facts", "Events were captured but no facts were extracted. Check pipeline health.".to_string())
    } else if signals > 0 {
        if gaps.is_empty() {
            ("findings_present", format!("{} signal(s) detected. Review findings for investigation.", signals))
        } else {
            ("findings_with_gaps", format!("{} signal(s) detected but coverage gaps exist. Fix gaps for better detection.", signals))
        }
    } else if gaps.is_empty() && playbooks_loaded > 0 {
        ("coverage_good", format!("{} facts extracted, {} playbooks active. No suspicious patterns detected.", facts, playbooks_loaded))
    } else if gaps.is_empty() {
        ("no_findings", format!("{} facts extracted. No signals triggered.", facts))
    } else {
        ("coverage_gaps", format!("{} coverage/capability gap(s) detected. Address these for better detection.", gaps.len()))
    };
    
    // If truly no gaps and no findings, add an "all good" message but still explain why
    if actions.is_empty() && signals == 0 && facts > 0 && playbooks_loaded > 0 {
        actions.push(serde_json::json!({
            "action_id": "coverage_complete",
            "title": "Detection coverage is active",
            "rationale": format!("{} playbooks are monitoring {} facts. No suspicious patterns detected.", playbooks_loaded, facts),
            "why": "All major telemetry categories are present and detection rules are loaded.",
            "how": [],
            "verify": []
        }));
    }
    
    // Ensure actions is never empty
    if actions.is_empty() {
        actions.push(serde_json::json!({
            "action_id": "no_actions",
            "title": "No actions recommended",
            "rationale": "Run appears complete. Review facts if desired.",
            "why": "All telemetry surfaces are available and data was captured.",
            "how": [],
            "verify": [],
            "priority": "info"
        }));
    }
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "available": true,
            "run_id": run_id,
            "scenario": scenario,
            "signals_count": signals,
            "facts_count": facts,
            "events_count": events,
            "summary": {
                "severity": severity,
                "text": summary_text
            },
            "gaps": gaps,
            "coverage": {
                "fact_types_count": fact_types.len(),
                "has_process_facts": has_proc_facts,
                "has_network_facts": has_net_facts,
                "has_file_facts": has_file_facts,
                "playbooks_loaded": playbooks_loaded,
                "coverage_minutes": coverage_mins
            },
            "coverage_checklist": coverage_checklist,
            "capability": {
                "is_admin": is_admin,
                "security_log_accessible": security_log_accessible,
                "sysmon_installed": sysmon_installed,
                "powershell_accessible": powershell_accessible
            },
            // Run readiness fields for crash/interrupt handling (A: endpoint consistency)
            "compile_status": if is_interrupted { "interrupted" } else if compile_status.is_empty() { "finalized" } else { compile_status },
            "facts_ready": !is_interrupted && !compile_status.is_empty() && compile_status != "compiling",
            "facts_partial": is_interrupted,
            "abandoned_reason": abandoned_reason,
            "last_activity_at": capability.get("stopped_at").or_else(|| capability.get("started_at")).and_then(|v| v.as_str()),
            "metadata_unavailable": !meta_path.exists(),
            "discovery_pivots": discovery_pivots,
            "pivots_unavailable_reason": pivots_unavailable_reason,
            "actions": actions
        }
    }))
}

async fn debug_counts_handler(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let metrics = state.supervisor.metrics().await;
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "running": metrics.running,
            "run_id": metrics.run_id,
            "segments_count": metrics.segments_count,
            "events_total": metrics.events_total,
            "facts_extracted": metrics.facts_extracted,
            "signals_fired": metrics.signals_fired
        }
    }))
}

// Baseline handlers (Pro) - TODO
#[derive(serde::Deserialize)]
struct SetBaselineRequest {
    scope: Option<String>,
    is_default: Option<bool>,
}

async fn set_baseline_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Json(body): Json<SetBaselineRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Tier gate: Baselines require Pro
    if !resolve_current_tier().has_access(services::types::ProductTier::Pro) {
        return Err(feature_locked_403("Baselines", services::types::ProductTier::Pro));
    }
    
    // Use SSoT resolver with filesystem fallback and backfill
    let run_ref = match services::run_control::resolve_run_ref(&state.db, &run_id, &state.data_dir, true) {
        Ok(r) => r,
        Err(e) => return Ok(Json(e.to_json())),
    };
    
    let scope = body.scope.unwrap_or_else(|| "host".to_string());
    let is_default = body.is_default.unwrap_or(true);
    
    // Get metrics snapshot
    let db_path = run_ref.run_dir.join("workbench.db");
    let metrics = services::baseline::get_run_metrics_snapshot(&run_ref.run_dir);
    
    // Update database
    if let Err(e) = state.db.set_baseline(&run_id, &scope, is_default) {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": e.to_string()
        })));
    }
    
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "run_id": run_id,
            "scope": scope,
            "is_default": is_default,
            "metrics_snapshot": metrics,
            "message": format!("Run '{}' marked as {} baseline", run_id, scope)
        }
    })))
}

async fn list_baselines_handler(
    State(state): State<SharedState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Tier gate: Baselines require Pro
    if !resolve_current_tier().has_access(services::types::ProductTier::Pro) {
        return Err(feature_locked_403("Baselines", services::types::ProductTier::Pro));
    }
    
    let baselines_from_db = match state.db.list_baselines() {
        Ok(baselines) => baselines,
        Err(e) => {
            tracing::warn!("Failed to list baselines from DB: {}", e);
            vec![]
        }
    };
    
    let host_default = state.db.get_default_baseline("host").ok().flatten();
    let install_default = state.db.get_default_baseline("install").ok().flatten();
    
    let baselines: Vec<serde_json::Value> = baselines_from_db.iter().map(|r| {
        serde_json::json!({
            "run_id": r.run_id,
            "name": r.name,
            "scope": r.baseline_scope,
            "marked_at": r.baseline_set_at,
            "is_default": r.baseline_enabled,
            "metrics_snapshot": {
                "events_count": r.events_total,
                "segments_count": r.segments_count,
                "facts_count": r.facts_extracted,
                "signals_count": r.signals_fired
            }
        })
    }).collect();
    
    let count = baselines.len();
    
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "baselines": baselines,
            "defaults": {
                "host": host_default.map(|r| r.run_id),
                "install": install_default.map(|r| r.run_id)
            },
            "count": count
        }
    })))
}

async fn case_summary_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Tier gate: Case Summary requires Pro
    if !resolve_current_tier().has_access(services::types::ProductTier::Pro) {
        return Err(feature_locked_403("Case Summary Export", services::types::ProductTier::Pro));
    }
    
    // Use SSoT resolver with filesystem fallback and backfill
    let run_ref = match services::run_control::resolve_run_ref(&state.db, &run_id, &state.data_dir, true) {
        Ok(r) => r,
        Err(e) => return Ok(Json(e.to_json())),
    };
    
    let db_path = run_ref.workbench_db_path.clone();
    let meta_path = run_ref.run_meta_path.clone();
    let run_name = run_ref.run_record.as_ref().and_then(|r| r.name.clone());
    
    let (started_at, stopped_at, status) = services::run_control::read_run_meta(&meta_path, &run_id);
    let (events, segments, facts, signals, earliest_ts, latest_ts, _) = 
        if db_path.exists() {
            services::run_control::read_run_stats(&db_path)
        } else {
            (0, 0, 0, 0, 0, 0, None)
        };
    
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "contract_version": "1.1.0",
            "schema_version": "1.1.0",
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "run_id": run_id,
            "name": run_name,
            "summary": {
                "started_at": started_at.map(|t| t.to_rfc3339()),
                "stopped_at": stopped_at.map(|t| t.to_rfc3339()),
                "status": status,
                "events_total": events,
                "segments_count": segments,
                "facts_extracted": facts,
                "signals_count": signals,
                "earliest_ts": earliest_ts,
                "latest_ts": latest_ts
            }
        }
    })))
}

// Diff handlers - TODO
async fn run_changes_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Json<serde_json::Value> {
    // Use canonical helper to open run DB
    let handle = match services::run_control::open_run_db(&state.db, &run_id) {
        Ok(h) => h,
        Err(e) => {
            // If DB missing, return available: false with reason code
            if e.code == services::run_control::RunDbErrorCode::MissingDb {
                return Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "available": false,
                        "reason": "MISSING_DB",
                        "reason_message": e.message,
                        "run_id": run_id,
                        "highlights": [],
                        "categories": {},
                        "stats": { "total_changes": 0, "fact_types": 0, "hosts": 0 }
                    }
                }));
            }
            return Json(e.to_json());
        }
    };
    
    let mut changes: Vec<serde_json::Value> = Vec::new();
    let mut categories: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    
    // Query facts for changes
    if let Ok(mut stmt) = handle.conn.prepare(
        "SELECT fact_id, host_id, ts, fact_type, domain, evidence_ptrs FROM facts ORDER BY ts DESC LIMIT 100"
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        }) {
            for row in rows.flatten() {
                let (fact_id, host_id, ts, fact_type, domain, evidence_ptrs_json) = row;
                let category = services::diff::categorize_fact_type(&fact_type);
                *categories.entry(category.to_string()).or_insert(0) += 1;
                
                let evidence: Vec<serde_json::Value> = serde_json::from_str(&evidence_ptrs_json).unwrap_or_default();
                
                changes.push(serde_json::json!({
                    "change_id": fact_id,
                    "ts": ts,
                    "category": category,
                    "title": format!("{}: {}", domain, fact_type),
                    "entities": { "host": host_id, "fact_type": fact_type },
                    "evidence": evidence,
                    "severity": "info"
                }));
            }
        }
    }
    
    let highlights: Vec<&serde_json::Value> = changes.iter().take(5).collect();
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "available": true,
            "run_id": run_id,
            "highlights": highlights,
            "changes": changes,
            "categories": categories,
            "stats": {
                "total_changes": changes.len()
            }
        }
    }))
}

/// GET /api/runs/:run_id/discovery_summary - Discovery-first run summary
/// Shows what changed, milestones observed, and visibility limits
async fn run_discovery_summary_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Json<serde_json::Value> {
    // Try DB first, fallback to filesystem (for runs discovered via scan but not in master DB)
    let (conn, run_dir) = match services::run_control::open_run_db(&state.db, &run_id) {
        Ok(h) => (h.conn, h.run_dir),
        Err(e) => {
            // Fallback: try direct filesystem path
            match services::run_control::open_run_db_by_path(&state.data_dir, &run_id) {
                Ok((conn, run_dir)) => (conn, run_dir),
                Err(e2) => {
                    if e2.code == services::run_control::RunDbErrorCode::MissingDb {
                        // Read readiness even for unavailable runs
                        let fallback_dir = state.data_dir.join("runs").join(&run_id);
                        let meta_path = fallback_dir.join("run_meta.json");
                        let readiness = read_run_readiness(&meta_path);
                        
                        return Json(serde_json::json!({
                            "success": true,
                            "data": {
                                "available": false,
                                "reason": "MISSING_DB",
                                "run_id": run_id,
                                // Readiness fields (A: endpoint consistency)
                                "compile_status": readiness.compile_status,
                                "facts_ready": readiness.facts_ready,
                                "facts_partial": readiness.facts_partial,
                                "abandoned_reason": readiness.abandoned_reason,
                                "last_activity_at": readiness.last_activity_at,
                                "metadata_unavailable": readiness.metadata_unavailable
                            }
                        }));
                    }
                    return Json(e.to_json());
                }
            }
        }
    };
    
    // Read run readiness fields from run_meta.json
    let meta_path = run_dir.join("run_meta.json");
    let readiness = read_run_readiness(&meta_path);
    
    // Get run-scoped capability snapshot from run_meta.json (SSoT: no live probes in run-scoped handlers)
    let meta_path = run_dir.join("run_meta.json");
    let capability = services::capability::get_capability_snapshot_from_meta(&meta_path);
    let sysmon_installed = capability.get("sysmon_installed").and_then(|v| v.as_bool()).unwrap_or(false);
    let security_log_accessible = capability.get("security_log_accessible").and_then(|v| v.as_bool()).unwrap_or(false);
    let is_admin = capability.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
    
    // Check channel accessibility from snapshot
    let channels = capability.get("channels").and_then(|v| v.as_array());
    let powershell_accessible = channels.map(|chs| {
        chs.iter().any(|c| {
            c.get("name").and_then(|n| n.as_str()) == Some("Microsoft-Windows-PowerShell/Operational")
                && c.get("accessible").and_then(|a| a.as_bool()).unwrap_or(false)
        })
    }).unwrap_or(false);
    
    // ==================== PANEL 1: WHAT CHANGED ====================
    // NOTE: All queries now use facts_sample table (hybrid persistence) with correct column names
    
    // Check if facts_sample table exists (graceful fallback for old runs - TWEAK A)
    let has_facts_sample: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='facts_sample'")
        .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
        .unwrap_or(false);
    
    // If no facts_sample, we can still show coverage-based summary from rollups
    let facts_sample_unavailable_reason = if !has_facts_sample {
        Some("This run was created before fact persistence was implemented. Using coverage rollup summaries.")
    } else {
        None
    };
    
    // ==================== OBSERVED TELEMETRY (Amplifier Fix v2) ====================
    // Separate "what we observed" from "what capability snapshot claims"
    // This avoids false claims like "Sysmon installed" when we only have observed facts
    // observable = observed_telemetry || capability_available
    // Capability remains unchanged (SSoT from run_meta.json)
    
    // Query observed telemetry from facts_sample (run-scoped, truthful)
    let (observed_powershell, observed_network, observed_exec, observed_registry) = if has_facts_sample {
        let obs_ps: bool = conn
            .prepare("SELECT 1 FROM facts_sample WHERE fact_type = 'ScriptExec' AND entity_key LIKE 'script:powershell%' LIMIT 1")
            .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
            .unwrap_or(false);
        
        let obs_net: bool = conn
            .prepare("SELECT 1 FROM facts_sample WHERE fact_type = 'OutboundConnect' LIMIT 1")
            .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
            .unwrap_or(false);
        
        let obs_exec: bool = conn
            .prepare("SELECT 1 FROM facts_sample WHERE fact_type = 'Exec' LIMIT 1")
            .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
            .unwrap_or(false);
        
        let obs_reg: bool = conn
            .prepare("SELECT 1 FROM facts_sample WHERE fact_type = 'RegistryMod' LIMIT 1")
            .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
            .unwrap_or(false);
        
        (obs_ps, obs_net, obs_exec, obs_reg)
    } else {
        (false, false, false, false)
    };
    
    // Compute effective observability: observed || capability
    // This resolves contradictions without mutating capability flags
    let powershell_observable = observed_powershell || powershell_accessible;
    let network_observable = observed_network || sysmon_installed;
    let process_observable = observed_exec || security_log_accessible || sysmon_installed;
    let registry_observable = observed_registry || sysmon_installed || security_log_accessible;
    
    // ==================== TOTAL COUNTS (from coverage_rollup) ====================
    // coverage_rollup.fact_count gives us true totals; facts_sample is capped sample
    // This provides "N shown of M total" UI capability
    let has_coverage_rollup: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='coverage_rollup'")
        .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
        .unwrap_or(false);
    
    let mut total_counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    if has_coverage_rollup {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT fact_type, SUM(fact_count) FROM coverage_rollup WHERE fact_type IS NOT NULL GROUP BY fact_type"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let fact_type: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((fact_type, count))
            }) {
                for row in rows.flatten() {
                    total_counts.insert(row.0, row.1);
                }
            }
        }
    }
    
    // ==================== SOURCE PROVENANCE DETECTION (via evidence_ptrs) ====================
    // Query stream_id from evidence_ptrs to detect actual source (NOT inferred from capability)
    // Only label as "PowerShell 4104" / "Sysmon 3" / "Security 4688" if provably from evidence
    
    // Helper: detect source label from evidence_ptrs stream_id
    fn detect_source_from_evidence(conn: &rusqlite::Connection, fact_type: &str, entity_filter: Option<&str>) -> Option<String> {
        let sql = match entity_filter {
            Some(filter) => format!(
                "SELECT evidence_ptrs FROM facts_sample WHERE fact_type = '{}' AND entity_key LIKE '{}' AND evidence_ptrs IS NOT NULL LIMIT 1",
                fact_type, filter
            ),
            None => format!(
                "SELECT evidence_ptrs FROM facts_sample WHERE fact_type = '{}' AND evidence_ptrs IS NOT NULL LIMIT 1",
                fact_type
            ),
        };
        
        conn.query_row(&sql, [], |row| {
            let evidence_ptrs_str: String = row.get(0)?;
            Ok(evidence_ptrs_str)
        }).ok().and_then(|ptrs_str| {
            // Parse evidence_ptrs JSON to extract stream_id
            let ptrs: Vec<serde_json::Value> = serde_json::from_str(&ptrs_str).unwrap_or_default();
            ptrs.first().and_then(|ptr| {
                ptr.get("stream_id").and_then(|v| v.as_str()).map(|s| s.to_string())
            })
        }).map(|stream_id| {
            // Map stream_id to human-readable source label
            // IMPORTANT: Do NOT claim specific event_id (e.g., "4104") unless proven from evidence
            // We only have stream_id/channel, not the actual event_id from the record
            match stream_id.as_str() {
                "Microsoft-Windows-PowerShell/Operational" => "PowerShell Operational".to_string(),  // Could be 4103, 4104, 4105, 4106
                "Microsoft-Windows-Sysmon/Operational" => "Sysmon".to_string(),  // Could be any Sysmon event
                "Security" => "Security Log".to_string(),
                "System" => "System Log".to_string(),
                s if s.contains("TaskScheduler") => "TaskScheduler".to_string(),
                other => other.to_string()
            }
        })
    }
    
    // Detect actual source for each observed surface
    let powershell_source_provenance = if observed_powershell && has_facts_sample {
        detect_source_from_evidence(&conn, "ScriptExec", Some("script:powershell%"))
    } else { None };
    
    let network_source_provenance = if observed_network && has_facts_sample {
        detect_source_from_evidence(&conn, "OutboundConnect", None)
    } else { None };
    
    let exec_source_provenance = if observed_exec && has_facts_sample {
        detect_source_from_evidence(&conn, "Exec", None)
    } else { None };
    
    let registry_source_provenance = if observed_registry && has_facts_sample {
        detect_source_from_evidence(&conn, "RegistryMod", None)
    } else { None };
    
    // ==================== DRIFT SUMMARY (Hardening Pass) ====================
    // Drift = observed telemetry exists but capability snapshot says unavailable
    // This is run-level summary to avoid per-row spam
    let mut drift_items: Vec<serde_json::Value> = Vec::new();
    
    if observed_powershell && !powershell_accessible {
        drift_items.push(serde_json::json!({
            "surface": "PowerShell",
            "observed": true,
            "capability": false,
            "capability_field": "powershell_accessible",
            "note": "PowerShell telemetry observed during this run; configuration reports ScriptBlock logging disabled."
        }));
    }
    
    if observed_network && !sysmon_installed {
        drift_items.push(serde_json::json!({
            "surface": "Network",
            "observed": true,
            "capability": false,
            "capability_field": "sysmon_installed",
            "note": "Network connection telemetry observed during this run; configuration reports Sysmon not installed."
        }));
    }
    
    if observed_exec && !security_log_accessible && !sysmon_installed {
        drift_items.push(serde_json::json!({
            "surface": "Process Execution",
            "observed": true,
            "capability": false,
            "capability_field": "security_log_accessible",
            "note": "Process execution telemetry observed during this run; configuration reports Security log not accessible."
        }));
    }
    
    if observed_registry && !sysmon_installed && !security_log_accessible {
        drift_items.push(serde_json::json!({
            "surface": "Registry",
            "observed": true,
            "capability": false,
            "capability_field": "sysmon_installed",
            "note": "Registry modification telemetry observed during this run; configuration reports Sysmon not installed."
        }));
    }
    
    let has_drift = !drift_items.is_empty();
    let drift_summary = serde_json::json!({
        "has_drift": has_drift,
        "items": drift_items,
        "banner_message": if has_drift { 
            "Telemetry observed despite configuration mismatch — verify sensor setup for reliable future coverage." 
        } else { 
            "" 
        }
    });
    
    // Query service persistence facts (PersistArtifact with artifact_type=service)
    let mut services: Vec<serde_json::Value> = Vec::new();
    if has_facts_sample {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT fact_id, ts, host, entity_key, details_json FROM facts_sample 
             WHERE fact_type = 'PersistArtifact' AND entity_key LIKE 'service:%' 
             ORDER BY ts DESC LIMIT 50"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let fact_id: String = row.get(0)?;
                let ts: i64 = row.get(1)?;
                let host: String = row.get(2)?;
                let entity_key: Option<String> = row.get(3)?;
                let details_str: String = row.get(4)?;
                let details: serde_json::Value = serde_json::from_str(&details_str).unwrap_or(serde_json::json!({}));
                let service_name = entity_key.as_ref().and_then(|k| k.strip_prefix("service:")).unwrap_or("unknown");
                Ok(serde_json::json!({
                    "id": fact_id,
                    "ts": ts,
                    "host": host,
                    "entity": service_name,
                    "service_name": service_name,
                    "binary_path": details.get("path").and_then(|v| v.as_str()).unwrap_or(""),
                    "start_type": details.get("start_type").and_then(|v| v.as_str()).unwrap_or(""),
                    "evidence_id": fact_id,
                    "pivot_filter": format!("fact_type=PersistArtifact&entity={}", service_name)
                }))
            }) {
                for row in rows.flatten() {
                    services.push(row);
                }
            }
        }
    }
    
    // Query log clear facts (LogTamper)
    let mut logs_cleared: Vec<serde_json::Value> = Vec::new();
    if has_facts_sample {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT fact_id, ts, host, entity_key, details_json FROM facts_sample 
             WHERE fact_type = 'LogTamper' 
             ORDER BY ts DESC LIMIT 50"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let fact_id: String = row.get(0)?;
                let ts: i64 = row.get(1)?;
                let host: String = row.get(2)?;
                let entity_key: Option<String> = row.get(3)?;
                let details_str: String = row.get(4)?;
                let details: serde_json::Value = serde_json::from_str(&details_str).unwrap_or(serde_json::json!({}));
                let log_name = entity_key.as_ref().and_then(|k| k.strip_prefix("log:")).unwrap_or(
                    details.get("log_name").and_then(|v| v.as_str()).unwrap_or("unknown")
                );
                Ok(serde_json::json!({
                    "id": fact_id,
                    "ts": ts,
                    "host": host,
                    "entity": log_name,
                    "log_cleared": log_name,
                    "user": details.get("user").and_then(|v| v.as_str()).unwrap_or(""),
                    "evidence_id": fact_id,
                    "pivot_filter": "fact_type=LogTamper"
                }))
            }) {
                for row in rows.flatten() {
                    logs_cleared.push(row);
                }
            }
        }
    }
    
    // Query scheduled task facts (PersistArtifact with artifact_type=task)
    let mut tasks: Vec<serde_json::Value> = Vec::new();
    if has_facts_sample {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT fact_id, ts, host, entity_key, details_json FROM facts_sample 
             WHERE fact_type = 'PersistArtifact' AND entity_key LIKE 'task:%' 
             ORDER BY ts DESC LIMIT 50"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let fact_id: String = row.get(0)?;
                let ts: i64 = row.get(1)?;
                let host: String = row.get(2)?;
                let entity_key: Option<String> = row.get(3)?;
                let details_str: String = row.get(4)?;
                let details: serde_json::Value = serde_json::from_str(&details_str).unwrap_or(serde_json::json!({}));
                let task_name = entity_key.as_ref().and_then(|k| k.strip_prefix("task:")).unwrap_or("unknown");
                Ok(serde_json::json!({
                    "id": fact_id,
                    "ts": ts,
                    "host": host,
                    "entity": task_name,
                    "task_name": task_name,
                    "user": details.get("user").and_then(|v| v.as_str()).unwrap_or(""),
                    "evidence_id": fact_id,
                    "pivot_filter": format!("fact_type=PersistArtifact&entity={}", task_name)
                }))
            }) {
                for row in rows.flatten() {
                    tasks.push(row);
                }
            }
        }
    }
    
    // Query registry persistence facts (RegistryMod) - if observable (observed OR capability)
    let mut registry: Vec<serde_json::Value> = Vec::new();
    if has_facts_sample && registry_observable {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT fact_id, ts, host, entity_key, details_json FROM facts_sample 
             WHERE fact_type = 'RegistryMod' 
             ORDER BY ts DESC LIMIT 50"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let fact_id: String = row.get(0)?;
                let ts: i64 = row.get(1)?;
                let host: String = row.get(2)?;
                let entity_key: Option<String> = row.get(3)?;
                let details_str: String = row.get(4)?;
                let details: serde_json::Value = serde_json::from_str(&details_str).unwrap_or(serde_json::json!({}));
                let reg_path = entity_key.as_ref().and_then(|k| k.strip_prefix("reg:")).unwrap_or(
                    details.get("key").and_then(|v| v.as_str()).unwrap_or("unknown")
                );
                Ok(serde_json::json!({
                    "id": fact_id,
                    "ts": ts,
                    "host": host,
                    "entity": reg_path,
                    "registry_key": reg_path,
                    "value": details.get("value").and_then(|v| v.as_str()).unwrap_or(""),
                    "evidence_id": fact_id,
                    "pivot_filter": "fact_type=RegistryMod"
                }))
            }) {
                for row in rows.flatten() {
                    registry.push(row);
                }
            }
        }
    }
    
    // Query process execution facts (Exec) - if observable (observed OR capability)
    let mut process_exec: Vec<serde_json::Value> = Vec::new();
    if has_facts_sample && process_observable {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT fact_id, ts, host, entity_key, details_json FROM facts_sample 
             WHERE fact_type = 'Exec' 
             ORDER BY ts DESC LIMIT 50"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let fact_id: String = row.get(0)?;
                let ts: i64 = row.get(1)?;
                let host: String = row.get(2)?;
                let entity_key: Option<String> = row.get(3)?;
                let details_str: String = row.get(4)?;
                let details: serde_json::Value = serde_json::from_str(&details_str).unwrap_or(serde_json::json!({}));
                let image = entity_key.as_ref().and_then(|k| k.strip_prefix("exe:")).unwrap_or(
                    details.get("path").and_then(|v| v.as_str()).unwrap_or("unknown")
                );
                Ok(serde_json::json!({
                    "id": fact_id,
                    "ts": ts,
                    "host": host,
                    "entity": image,
                    "image": image,
                    "command_line": details.get("cmdline").and_then(|v| v.as_str()).unwrap_or(""),
                    "user": details.get("user").and_then(|v| v.as_str()).unwrap_or(""),
                    "evidence_id": fact_id,
                    "pivot_filter": format!("fact_type=Exec&entity={}", image)
                }))
            }) {
                for row in rows.flatten() {
                    process_exec.push(row);
                }
            }
        }
    }
    
    // Query network connection facts (OutboundConnect) - if observable (observed OR sysmon)
    let mut network: Vec<serde_json::Value> = Vec::new();
    if has_facts_sample && network_observable {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT fact_id, ts, host, entity_key, details_json FROM facts_sample 
             WHERE fact_type = 'OutboundConnect' 
             ORDER BY ts DESC LIMIT 50"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let fact_id: String = row.get(0)?;
                let ts: i64 = row.get(1)?;
                let host: String = row.get(2)?;
                let entity_key: Option<String> = row.get(3)?;
                let details_str: String = row.get(4)?;
                let details: serde_json::Value = serde_json::from_str(&details_str).unwrap_or(serde_json::json!({}));
                let dest = entity_key.as_ref().and_then(|k| k.strip_prefix("net:")).unwrap_or("unknown");
                let (dest_ip, dest_port) = dest.split_once(':').unwrap_or((dest, "0"));
                Ok(serde_json::json!({
                    "id": fact_id,
                    "ts": ts,
                    "host": host,
                    "entity": dest_ip,
                    "destination_ip": dest_ip,
                    "destination_port": dest_port.parse::<u64>().unwrap_or(0),
                    "image": details.get("process").and_then(|v| v.as_str()).unwrap_or(""),
                    "evidence_id": fact_id,
                    "pivot_filter": format!("fact_type=OutboundConnect&entity={}", dest_ip)
                }))
            }) {
                for row in rows.flatten() {
                    network.push(row);
                }
            }
        }
    }
    
    // Query PowerShell execution facts (ScriptExec) - if observable (observed OR capability)
    let mut powershell: Vec<serde_json::Value> = Vec::new();
    // sample_count = rows in facts_sample (capped by design, max ~200-500)
    // total_count = true total from coverage_rollup.fact_count for ScriptExec
    let mut powershell_sample_count: usize = 0;
    let powershell_total_count: i64 = total_counts.get("ScriptExec").copied().unwrap_or(0);
    
    if has_facts_sample && powershell_observable {
        // Get sample count from facts_sample (this is the capped persisted sample)
        powershell_sample_count = conn
            .query_row(
                "SELECT COUNT(*) FROM facts_sample WHERE fact_type = 'ScriptExec' AND entity_key LIKE 'script:powershell%'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap_or(0) as usize;
        
        if let Ok(mut stmt) = conn.prepare(
            "SELECT fact_id, ts, host, entity_key, details_json FROM facts_sample 
             WHERE fact_type = 'ScriptExec' AND entity_key LIKE 'script:powershell%' 
             ORDER BY ts DESC LIMIT 50"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let fact_id: String = row.get(0)?;
                let ts: i64 = row.get(1)?;
                let host: String = row.get(2)?;
                let _entity_key: Option<String> = row.get(3)?;
                let details_str: String = row.get(4)?;
                let details: serde_json::Value = serde_json::from_str(&details_str).unwrap_or(serde_json::json!({}));
                
                // Try multiple fields for script content: script, scriptblock, message, path
                let script_raw = details.get("script").and_then(|v| v.as_str())
                    .or_else(|| details.get("scriptblock").and_then(|v| v.as_str()))
                    .or_else(|| details.get("message").and_then(|v| v.as_str()))
                    .or_else(|| details.get("path").and_then(|v| v.as_str()));
                
                let script_preview = match script_raw {
                    Some(s) if !s.trim().is_empty() => {
                        // Normalize: replace newlines with spaces, truncate to 200 chars
                        let normalized = s.replace('\n', " ").replace('\r', "");
                        let normalized = normalized.trim();
                        if normalized.len() > 200 {
                            format!("{}...", &normalized[..200])
                        } else {
                            normalized.to_string()
                        }
                    }
                    _ => "(script content unavailable — enable ScriptBlock logging or ensure event includes message)".to_string()
                };
                
                Ok(serde_json::json!({
                    "id": fact_id,
                    "ts": ts,
                    "host": host,
                    "entity": "PowerShell",
                    "script_preview": script_preview,
                    "evidence_id": fact_id,
                    "pivot_filter": "fact_type=ScriptExec"
                }))
            }) {
                for row in rows.flatten() {
                    powershell.push(row);
                }
            }
        }
    }
    
    // Build "what_changed" grouped summary
    // observable = observed_telemetry || capability_available (v2 fix)
    // observation_note added when observed but capability says unavailable
    // SOURCE LABELS: Use provenance detection from evidence_ptrs when observed; else use capability-based label
    // COUNT FIELDS: sample_count = facts_sample rows (capped), total_count = coverage_rollup (true total)
    
    // Helper to build source label: proven from evidence OR generic with (observed) suffix
    let registry_source_label = if sysmon_installed {
        "Sysmon 12-14".to_string()
    } else if security_log_accessible {
        "Security 4657".to_string()
    } else if observed_registry {
        // Use provenance if available, else generic
        registry_source_provenance.as_ref()
            .map(|s| format!("{} (observed)", s))
            .unwrap_or_else(|| "Registry (observed)".to_string())
    } else {
        "Not available".to_string()
    };
    
    let exec_source_label = if sysmon_installed {
        "Sysmon 1".to_string()
    } else if security_log_accessible {
        "Security 4688".to_string()
    } else if observed_exec {
        exec_source_provenance.as_ref()
            .map(|s| format!("{} (observed)", s))
            .unwrap_or_else(|| "Process Execution (observed)".to_string())
    } else {
        "Not available".to_string()
    };
    
    let network_source_label = if sysmon_installed {
        "Sysmon 3".to_string()
    } else if observed_network {
        network_source_provenance.as_ref()
            .map(|s| format!("{} (observed)", s))
            .unwrap_or_else(|| "Network Connections (observed)".to_string())
    } else {
        "Not available".to_string()
    };
    
    let powershell_source_label = if powershell_accessible {
        "PowerShell 4104".to_string()
    } else if observed_powershell {
        powershell_source_provenance.as_ref()
            .map(|s| format!("{} (observed)", s))
            .unwrap_or_else(|| "PowerShell Execution (observed)".to_string())
    } else {
        "Not available".to_string()
    };
    
    let what_changed = serde_json::json!({
        "services": {
            "items": services,
            "count": services.len(),
            "sample_count": services.len(),
            "total_count": total_counts.get("PersistArtifact").copied().unwrap_or(services.len() as i64),
            "observable": true,
            "source": "System 7045"
        },
        "scheduled_tasks": {
            "items": tasks,
            "count": tasks.len(),
            "sample_count": tasks.len(),
            "total_count": tasks.len(),  // Tasks don't have separate rollup
            "observable": true,
            "source": "TaskScheduler 106"
        },
        "logs_cleared": {
            "items": logs_cleared,
            "count": logs_cleared.len(),
            "sample_count": logs_cleared.len(),
            "total_count": total_counts.get("LogTamper").copied().unwrap_or(logs_cleared.len() as i64),
            "observable": true,
            "source": "System 104 / Security 1102"
        },
        "registry": {
            "items": registry,
            "count": registry.len(),
            "sample_count": registry.len(),
            "total_count": total_counts.get("RegistryMod").copied().unwrap_or(registry.len() as i64),
            "observable": registry_observable,
            "observed_in_run": observed_registry,
            "source": registry_source_label,
            "blocked_reason": if !registry_observable { Some("Requires Sysmon or Security log access") } else { None::<&str> },
            "observation_note": if observed_registry && !sysmon_installed && !security_log_accessible { Some("Registry telemetry observed in this run") } else { None::<&str> }
        },
        "process_execution": {
            "items": process_exec,
            "count": process_exec.len(),
            "sample_count": process_exec.len(),
            "total_count": total_counts.get("Exec").copied().unwrap_or(process_exec.len() as i64),
            "observable": process_observable,
            "observed_in_run": observed_exec,
            "source": exec_source_label,
            "blocked_reason": if !process_observable { Some("Requires Admin or Sysmon") } else { None::<&str> },
            "observation_note": if observed_exec && !security_log_accessible && !sysmon_installed { Some("Process execution telemetry observed in this run") } else { None::<&str> }
        },
        "network_connections": {
            "items": network,
            "count": network.len(),
            "sample_count": network.len(),
            "total_count": total_counts.get("OutboundConnect").copied().unwrap_or(network.len() as i64),
            "observable": network_observable,
            "observed_in_run": observed_network,
            "source": network_source_label,
            "blocked_reason": if !network_observable { Some("Requires Sysmon") } else { None::<&str> },
            "observation_note": if observed_network && !sysmon_installed { Some("Network telemetry observed in this run (verify Sysmon status)") } else { None::<&str> }
        },
        "powershell": {
            "items": powershell,
            "count": powershell.len(),
            "sample_count": powershell_sample_count,
            "total_count": powershell_total_count,  // True total from coverage_rollup
            "observable": powershell_observable,
            "observed_in_run": observed_powershell,
            "source": powershell_source_label,
            "blocked_reason": if !powershell_observable { Some("Requires ScriptBlock logging enabled") } else { None::<&str> },
            "observation_note": if observed_powershell && !powershell_accessible { Some("PowerShell execution telemetry observed in this run") } else { None::<&str> }
        }
    });
    
    // ==================== PANEL 2: MILESTONES OBSERVED ====================
    // Define milestones and check against actual facts
    
    let milestones = vec![
        serde_json::json!({
            "id": "service_installed",
            "name": "Service Installed",
            "description": "New service registered on the system",
            "source": "System 7045",
            "status": if !services.is_empty() { "observed" } else if true { "not_observed" } else { "not_observable" },
            "count": services.len(),
            "evidence": services.first().map(|s| s.get("evidence_id").and_then(|v| v.as_str()).unwrap_or("")),
            "blocked_reason": serde_json::Value::Null
        }),
        serde_json::json!({
            "id": "log_cleared",
            "name": "Log Cleared",
            "description": "Event log was cleared (evasion indicator)",
            "source": "System 104 / Security 1102",
            "status": if !logs_cleared.is_empty() { "observed" } else { "not_observed" },
            "count": logs_cleared.len(),
            "evidence": logs_cleared.first().map(|s| s.get("evidence_id").and_then(|v| v.as_str()).unwrap_or("")),
            "blocked_reason": serde_json::Value::Null
        }),
        serde_json::json!({
            "id": "task_created",
            "name": "Scheduled Task Created/Modified",
            "description": "Task scheduler persistence",
            "source": "TaskScheduler 106 / Security 4698",
            "status": if !tasks.is_empty() { "observed" } else { "not_observed" },
            "count": tasks.len(),
            "evidence": tasks.first().map(|s| s.get("evidence_id").and_then(|v| v.as_str()).unwrap_or("")),
            "blocked_reason": serde_json::Value::Null
        }),
        serde_json::json!({
            "id": "registry_autorun",
            "name": "Registry Autorun Modified",
            "description": "Run key or other autorun registry persistence",
            "source": "Sysmon 12-14 / Security 4657",
            "status": if !registry.is_empty() { "observed" } else if registry_observable { "not_observed" } else { "not_observable" },
            "count": registry.len(),
            "evidence": registry.first().map(|s| s.get("evidence_id").and_then(|v| v.as_str()).unwrap_or("")),
            "blocked_reason": if !registry_observable { Some("Install Sysmon or run as Admin") } else { None::<&str> },
            "observed_in_run": observed_registry
        }),
        serde_json::json!({
            "id": "process_execution",
            "name": "Process Execution",
            "description": "New process creation observed",
            "source": "Sysmon 1 / Security 4688",
            "status": if !process_exec.is_empty() { "observed" } else if process_observable { "not_observed" } else { "not_observable" },
            "count": process_exec.len(),
            "evidence": process_exec.first().map(|s| s.get("evidence_id").and_then(|v| v.as_str()).unwrap_or("")),
            "blocked_reason": if !process_observable { Some("Run as Admin or install Sysmon") } else { None::<&str> },
            "observed_in_run": observed_exec
        }),
        serde_json::json!({
            "id": "powershell_scriptblock",
            "name": "PowerShell ScriptBlock",
            "description": "PowerShell script execution logged",
            "source": "PowerShell 4104",
            "status": if !powershell.is_empty() { "observed" } else if powershell_observable { "not_observed" } else { "not_observable" },
            "count": powershell.len(),
            "evidence": powershell.first().map(|s| s.get("evidence_id").and_then(|v| v.as_str()).unwrap_or("")),
            "blocked_reason": if !powershell_observable { Some("Enable ScriptBlock logging") } else { None::<&str> },
            "observed_in_run": observed_powershell
        }),
        serde_json::json!({
            "id": "network_connection",
            "name": "Outbound Network Connection",
            "description": "Network egress observed",
            "source": "Sysmon 3",
            "status": if !network.is_empty() { "observed" } else if network_observable { "not_observed" } else { "not_observable" },
            "count": network.len(),
            "evidence": network.first().map(|s| s.get("evidence_id").and_then(|v| v.as_str()).unwrap_or("")),
            "blocked_reason": if !network_observable { Some("Install Sysmon") } else { None::<&str> },
            "observed_in_run": observed_network
        })
    ];
    
    // Count milestone statuses
    let observed_count = milestones.iter().filter(|m| m.get("status").and_then(|v| v.as_str()) == Some("observed")).count();
    let not_observed_count = milestones.iter().filter(|m| m.get("status").and_then(|v| v.as_str()) == Some("not_observed")).count();
    let not_observable_count = milestones.iter().filter(|m| m.get("status").and_then(|v| v.as_str()) == Some("not_observable")).count();
    
    // ==================== PANEL 3: VISIBILITY LIMITS ====================
    // Visibility limits are capability-driven (what snapshot says is missing)
    // NOT observed-driven (we don't remove CTAs just because we saw telemetry)
    // But we add observation_note when observed despite capability saying unavailable
    let mut visibility_limits: Vec<serde_json::Value> = Vec::new();
    
    if !security_log_accessible {
        let has_exec_drift = observed_exec;
        let mut limit = serde_json::json!({
            "id": "security_log",
            "title": "Security Log Not Accessible",
            "impact": "Process execution (4688), logon events (4624), and privilege use (4672) not observable",
            "affected_milestones": ["process_execution", "registry_autorun"],
            "unlock_action": "run_as_admin",
            // CTA tone: "Make reliable" when drift, normal otherwise
            "unlock_label": if has_exec_drift { "Make this reliable: Run as Admin" } else { "Run as Administrator" },
            "unlock_subtext": if has_exec_drift { 
                "Process execution telemetry was observed this run, but configuration reports it unavailable." 
            } else { 
                "Security log access requires administrator privileges." 
            },
            "unlock_icon": "🔐",
            "has_drift": has_exec_drift
        });
        visibility_limits.push(limit);
    }
    
    if !sysmon_installed {
        let has_network_drift = observed_network;
        let has_registry_drift = observed_registry;
        let any_drift = has_network_drift || has_registry_drift;
        let mut limit = serde_json::json!({
            "id": "sysmon",
            "title": "Sysmon Not Installed",
            "impact": "Network connections, registry changes, process injection, and file creation not observable",
            "affected_milestones": ["network_connection", "registry_autorun", "process_execution"],
            "unlock_action": "install_sysmon",
            // CTA tone: "Make reliable" when drift, normal otherwise
            "unlock_label": if any_drift { "Make this reliable: Install Sysmon" } else { "Install Sysmon" },
            "unlock_subtext": if any_drift { 
                "Relevant telemetry was observed this run, but configuration reports Sysmon not installed. Verify sensor status." 
            } else { 
                "Sysmon provides detailed process, network, and registry telemetry." 
            },
            "unlock_icon": "🔍",
            "has_drift": any_drift
        });
        visibility_limits.push(limit);
    }
    
    if !powershell_accessible {
        let has_ps_drift = observed_powershell;
        let mut limit = serde_json::json!({
            "id": "powershell_logging",
            "title": "PowerShell Logging Disabled",
            "impact": "PowerShell script execution not observable - fileless attacks may be missed",
            "affected_milestones": ["powershell_scriptblock"],
            "unlock_action": "enable_ps_logging",
            // CTA tone: "Make reliable" when drift, normal otherwise
            "unlock_label": if has_ps_drift { "Make this reliable: Enable Logging" } else { "Enable ScriptBlock Logging" },
            "unlock_subtext": if has_ps_drift { 
                "PowerShell execution telemetry was observed this run, but configuration reports logging disabled." 
            } else { 
                "ScriptBlock logging captures PowerShell commands for detection." 
            },
            "unlock_icon": "⚡",
            "has_drift": has_ps_drift
        });
        visibility_limits.push(limit);
    }
    
    let total_changes = services.len() + logs_cleared.len() + tasks.len() + registry.len() + process_exec.len() + network.len() + powershell.len();
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "available": true,
            "run_id": run_id,
            "what_changed": what_changed,
            "facts_sample_unavailable_reason": facts_sample_unavailable_reason,
            "milestones": {
                "items": milestones,
                "observed": observed_count,
                "not_observed": not_observed_count,
                "not_observable": not_observable_count
            },
            "visibility_limits": visibility_limits,
            "stats": {
                "total_changes": total_changes,
                "services_count": services.len(),
                "tasks_count": tasks.len(),
                "logs_cleared_count": logs_cleared.len(),
                "registry_count": registry.len(),
                "process_exec_count": process_exec.len(),
                "network_count": network.len(),
                "powershell_count": powershell.len()
            },
            // Capability: what the run snapshot claims is available (SSoT, never mutated)
            "capability": {
                "is_admin": is_admin,
                "sysmon_installed": sysmon_installed,
                "security_log_accessible": security_log_accessible,
                "powershell_accessible": powershell_accessible
            },
            // Observed telemetry: what we actually saw in this run (v2 fix)
            "observed_telemetry": {
                "powershell": observed_powershell,
                "network": observed_network,
                "process_execution": observed_exec,
                "registry": observed_registry
            },
            // Drift summary: consolidated mismatch detection (hardening pass)
            // drift = observed_telemetry.X == true && capability.X == false
            "drift_summary": drift_summary,
            // Readiness fields (A: endpoint consistency)
            "compile_status": readiness.compile_status,
            "facts_ready": readiness.facts_ready,
            "facts_partial": readiness.facts_partial,
            "abandoned_reason": readiness.abandoned_reason,
            "last_activity_at": readiness.last_activity_at,
            "metadata_unavailable": readiness.metadata_unavailable
        }
    }))
}

#[derive(serde::Deserialize)]
struct DiffQuery {
    mode: Option<String>,
    baseline_run_id: Option<String>,
    phase_minutes: Option<i64>,
    marker_ts: Option<i64>,
    category: Option<String>,
    direction: Option<String>,
    baseline_filter: Option<bool>,
}

async fn run_diff_v2_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Query(query): Query<DiffQuery>,
) -> Json<serde_json::Value> {
    let mode = query.mode.as_deref().unwrap_or("phase");
    
    // Validate mode first (before tier gate for better UX)
    if mode != "phase" && mode != "baseline" && mode != "marker" {
        return Json(services::diff::DiffError::invalid_mode(mode).to_json());
    }
    
    // Tier gate: Advanced diff modes require Pro
    let is_advanced = mode == "baseline" || mode == "marker" || query.baseline_filter.unwrap_or(false);
    if is_advanced && !resolve_current_tier().has_access(services::types::ProductTier::Pro) {
        let (_, json) = feature_locked_403("Advanced Diff", services::types::ProductTier::Pro);
        return json;
    }
    
    // Use SSoT resolver with filesystem fallback and backfill
    let run_ref = match services::run_control::resolve_run_ref(&state.db, &run_id, &state.data_dir, true) {
        Ok(r) => r,
        Err(e) => return Json(e.to_json()),
    };
    
    let db_path = run_ref.workbench_db_path.clone();
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": "MISSING_DB",
                "message": format!("workbench.db not found for run '{}'", run_id),
                "run_id": run_id,
                "mode": mode
            }
        }));
    }
    
    // Get basic stats from the run (SSoT: run_control::read_run_stats)
    let (events, _segments, facts, _signals, _, _, _) = services::run_control::read_run_stats(&db_path);
    
    // Delegate to services::diff (SSoT for all diff logic)
    let params = services::diff::DiffParams {
        mode: mode.to_string(),
        phase_minutes: query.phase_minutes,
        baseline_run_id: query.baseline_run_id.clone(),
        marker_ts: query.marker_ts,
        baseline_filter: query.baseline_filter,
    };
    
    match services::diff::run_diff(&db_path, &run_id, params, events, facts) {
        Ok(result) => Json(serde_json::json!({
            "success": true,
            "data": result
        })),
        Err(e) => Json(e.to_json()),
    }
}

// Playbooks/Packs handlers - TODO
async fn run_playbooks_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Json<serde_json::Value> {
    // Discover playbooks directory
    let (playbooks_dir, searched_paths, not_found_reason) = services::run_control::discover_playbooks_dir();
    let playbooks_enabled = playbooks_dir.is_some();
    
    if !playbooks_enabled {
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": "PLAYBOOKS_NOT_FOUND",
                "message": not_found_reason.unwrap_or_else(|| "Playbooks directory not found".to_string()),
                "searched_paths": searched_paths,
                "run_id": run_id,
                "loaded_count": 0,
                "fired_count": 0
            }
        }));
    }
    
    // Count playbooks
    let loaded_count = if let Some(ref pb_dir) = playbooks_dir {
        std::fs::read_dir(pb_dir)
            .map(|entries| entries.filter(|e| {
                e.as_ref().ok().map(|e| {
                    e.path().extension().map(|ext| ext == "yaml" || ext == "yml").unwrap_or(false)
                }).unwrap_or(false)
            }).count())
            .unwrap_or(0)
    } else {
        0
    };
    
    // Try DB first, fall back to filesystem path (for runs discovered via scan)
    let db_conn_and_path = match services::run_control::open_run_db(&state.db, &run_id) {
        Ok(h) => Some((h.conn, h.db_path)),
        Err(e) => {
            // Fallback: construct path from data_dir
            let fallback_path = state.data_dir.join("runs").join(&run_id).join("workbench.db");
            if fallback_path.exists() {
                if let Ok(conn) = services::run_control::open_db_with_wal(&fallback_path) {
                    Some((conn, fallback_path))
                } else {
                    None
                }
            } else if e.code == services::run_control::RunDbErrorCode::MissingDb {
                None // Will return with playbooks info but no signals
            } else {
                // Run not found anywhere - still show playbooks info
                None
            }
        }
    };
    
    // If no DB available, return with playbooks info but no signals
    let (conn, _db_path) = match db_conn_and_path {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": true,
                    "run_id": run_id,
                    "playbooks_enabled": playbooks_enabled,
                    "playbooks_dir": playbooks_dir.map(|p| p.display().to_string()),
                    "loaded_count": loaded_count,
                    "fired_count": 0,
                    "matches": [],
                    "message": "Playbooks loaded but no events to evaluate"
                }
            }));
        }
    };
    
    // Query signals to find playbook matches
    let mut fired_count = 0;
    let mut matches: Vec<serde_json::Value> = Vec::new();
    
    if let Ok(mut stmt) = conn.prepare(
        "SELECT signal_id, signal_type, severity, ts, host, metadata FROM signals ORDER BY ts DESC LIMIT 100"
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        }) {
            for row in rows.flatten() {
                let (signal_id, signal_type, severity, ts, host, _metadata) = row;
                fired_count += 1;
                matches.push(serde_json::json!({
                    "signal_id": signal_id,
                    "playbook": signal_type.clone(),
                    "signal_type": signal_type,
                    "severity": severity,
                    "ts": ts,
                    "host": host
                }));
            }
        }
    }
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "available": true,
            "run_id": run_id,
            "playbooks_enabled": playbooks_enabled,
            "playbooks_dir": playbooks_dir.map(|p| p.display().to_string()),
            "loaded_count": loaded_count,
            "fired_count": fired_count,
            "matches": matches,
            "message": if fired_count > 0 { "Playbook matches found" } else { "No playbook matches" }
        }
    }))
}

async fn playbooks_catalog_handler() -> Json<serde_json::Value> {
    let (playbooks_dir, searched_paths, not_found_reason) = services::run_control::discover_playbooks_dir();
    
    if playbooks_dir.is_none() {
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": "PLAYBOOKS_NOT_FOUND",
                "message": not_found_reason.unwrap_or_else(|| "Playbooks directory not found".to_string()),
                "searched_paths": searched_paths,
                "playbooks": [],
                "loaded_count": 0,
                "enabled_count": 0,
                "blocked_count": 0
            }
        }));
    }
    
    // Get capability status to cross-reference telemetry availability
    let capability = services::capability::get_capability_status();
    let sysmon_installed = capability.get("sysmon_installed").and_then(|v| v.as_bool()).unwrap_or(false);
    let security_log_accessible = capability.get("security_log_accessible").and_then(|v| v.as_bool()).unwrap_or(false);
    let is_admin = capability.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
    
    // Check channel accessibility for PowerShell and WMI
    let channels = capability.get("channels").and_then(|v| v.as_array());
    let powershell_accessible = channels.map(|chs| {
        chs.iter().any(|c| {
            c.get("name").and_then(|n| n.as_str()) == Some("Microsoft-Windows-PowerShell/Operational")
                && c.get("accessible").and_then(|a| a.as_bool()).unwrap_or(false)
        })
    }).unwrap_or(false);
    let wmi_accessible = channels.map(|chs| {
        chs.iter().any(|c| {
            c.get("name").and_then(|n| n.as_str()) == Some("Microsoft-Windows-WMI-Activity/Operational")
                && c.get("accessible").and_then(|a| a.as_bool()).unwrap_or(false)
        })
    }).unwrap_or(false);
    
    let pb_dir = playbooks_dir.unwrap();
    let windows_dir = pb_dir.join("windows");
    let target_dir = if windows_dir.exists() { windows_dir } else { pb_dir.clone() };
    
    // Also check for custom playbooks directory
    let custom_dir = pb_dir.join("custom");
    
    let mut playbooks: Vec<serde_json::Value> = Vec::new();
    let mut enabled_count = 0usize;
    let mut blocked_count = 0usize;
    
    // Collect directories to scan: builtin first, then custom
    let mut dirs_to_scan: Vec<(std::path::PathBuf, bool)> = vec![(target_dir.clone(), false)];
    if custom_dir.exists() {
        dirs_to_scan.push((custom_dir.clone(), true));
    }
    
    for (scan_dir, is_custom_dir) in dirs_to_scan {
    if let Ok(entries) = std::fs::read_dir(&scan_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                continue;
            }
            
            // Skip unsupported directory
            if path.to_string_lossy().contains("unsupported") {
                continue;
            }
            
            let playbook_id = path.file_stem()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            
            // Determine if this is a custom playbook
            let is_custom = is_custom_dir || path.to_string_lossy().contains("custom");
            let source = if is_custom { "custom" } else { "builtin" };
            
            // Try to parse the YAML to extract metadata
            let mut name = playbook_id.clone();
            let mut description = String::new();
            let mut category = String::new();
            let mut enabled = true;
            let mut requires: Vec<String> = Vec::new();
            let mut mitre_techniques: Vec<String> = Vec::new();
            let mut mitre_tactics: Vec<String> = Vec::new();
            let mut steps: Vec<serde_json::Value> = Vec::new();
            let mut yaml_content: Option<String> = None;
            let mut parse_error: Option<String> = None;
            
            let content_result = std::fs::read_to_string(&path);
            if let Ok(content) = &content_result {
                // Store raw YAML content for dev view (limit size for safety)
                if content.len() <= 64 * 1024 { // 64KB limit
                    yaml_content = Some(content.clone());
                }
                
                // Parse YAML using serde_yaml
                match serde_yaml::from_str::<serde_yaml::Value>(&content) {
                    Ok(yaml) => {
                    // Extract name
                    if let Some(n) = yaml.get("name").and_then(|v| v.as_str()) {
                        name = n.to_string();
                    } else if let Some(n) = yaml.get("title").and_then(|v| v.as_str()) {
                        name = n.to_string();
                    }
                    
                    // Extract description
                    if let Some(d) = yaml.get("description").and_then(|v| v.as_str()) {
                        description = d.trim().to_string();
                    }
                    
                    // Extract category/family
                    if let Some(c) = yaml.get("family").and_then(|v| v.as_str()) {
                        category = c.to_string();
                    } else if let Some(c) = yaml.get("category").and_then(|v| v.as_str()) {
                        category = c.to_string();
                    }
                    
                    // Extract enabled flag
                    if let Some(e) = yaml.get("enabled").and_then(|v| v.as_bool()) {
                        enabled = e;
                    }
                    
                    // Extract requires array (prerequisites)
                    if let Some(reqs) = yaml.get("requires").and_then(|v| v.as_sequence()) {
                        for req in reqs {
                            if let Some(r) = req.as_str() {
                                requires.push(r.to_lowercase());
                            }
                        }
                    }
                    
                    // Extract step/slot structure (Tier A observability)
                    // Try explicit rules/slots first, then derive from input_facts
                    let mut derived_structure = false;
                    
                    // 1. Check for explicit rules array
                    if let Some(rules) = yaml.get("rules").and_then(|v| v.as_sequence()) {
                        for (idx, rule) in rules.iter().enumerate() {
                            let step_name = rule.get("name").and_then(|v| v.as_str())
                                .unwrap_or(&format!("Rule {}", idx + 1)).to_string();
                            let window = rule.get("window").and_then(|v| v.as_i64());
                            
                            // Extract expected fact types from conditions
                            let mut expected_facts: Vec<String> = Vec::new();
                            if let Some(conditions) = rule.get("conditions").and_then(|v| v.as_sequence()) {
                                for cond in conditions {
                                    if let Some(tag) = cond.get("tag").and_then(|v| v.as_str()) {
                                        expected_facts.push(tag.to_string());
                                    }
                                }
                            }
                            
                            steps.push(serde_json::json!({
                                "id": format!("rule_{}", idx),
                                "name": step_name,
                                "required": true,
                                "window_secs": window,
                                "expected_fact_types": expected_facts,
                                "description": format!("Rule: {}", step_name),
                                "derived_structure": false
                            }));
                        }
                    }
                    
                    // 2. Check for explicit slots
                    if steps.is_empty() {
                        if let Some(slots) = yaml.get("slots") {
                            // Required slots
                            if let Some(req_slots) = slots.get("required").and_then(|v| v.as_sequence()) {
                                for slot in req_slots {
                                    let slot_name = slot.get("name").and_then(|v| v.as_str())
                                        .unwrap_or("unnamed").to_string();
                                    let slot_type = slot.get("type").and_then(|v| v.as_str())
                                        .unwrap_or("string").to_string();
                                    steps.push(serde_json::json!({
                                        "id": format!("slot_{}", slot_name),
                                        "name": slot_name,
                                        "required": true,
                                        "slot_type": slot_type,
                                        "expected_fact_types": [],
                                        "description": format!("Required slot: {}", slot_name),
                                        "derived_structure": false
                                    }));
                                }
                            }
                            // Optional slots
                            if let Some(opt_slots) = slots.get("optional").and_then(|v| v.as_sequence()) {
                                for slot in opt_slots {
                                    let slot_name = slot.get("name").and_then(|v| v.as_str())
                                        .unwrap_or("unnamed").to_string();
                                    let slot_type = slot.get("type").and_then(|v| v.as_str())
                                        .unwrap_or("string").to_string();
                                    steps.push(serde_json::json!({
                                        "id": format!("slot_{}", slot_name),
                                        "name": slot_name,
                                        "required": false,
                                        "slot_type": slot_type,
                                        "expected_fact_types": [],
                                        "description": format!("Optional slot: {}", slot_name),
                                        "derived_structure": false
                                    }));
                                }
                            }
                        }
                    }
                    
                    // 3. Derive from input_facts if no explicit structure
                    if steps.is_empty() {
                        derived_structure = true;
                        if let Some(input_facts) = yaml.get("input_facts") {
                            if let Some(req_facts) = input_facts.get("required").and_then(|v| v.as_sequence()) {
                                for fact in req_facts {
                                    if let Some(fact_type) = fact.as_str() {
                                        steps.push(serde_json::json!({
                                            "id": format!("fact_{}", fact_type.to_lowercase()),
                                            "name": fact_type,
                                            "required": true,
                                            "expected_fact_types": [fact_type],
                                            "description": format!("Required fact type: {}", fact_type),
                                            "derived_structure": true
                                        }));
                                    }
                                }
                            }
                            if let Some(opt_facts) = input_facts.get("optional").and_then(|v| v.as_sequence()) {
                                for fact in opt_facts {
                                    if let Some(fact_type) = fact.as_str() {
                                        steps.push(serde_json::json!({
                                            "id": format!("fact_{}", fact_type.to_lowercase()),
                                            "name": fact_type,
                                            "required": false,
                                            "expected_fact_types": [fact_type],
                                            "description": format!("Optional fact type: {}", fact_type),
                                            "derived_structure": true
                                        }));
                                    }
                                }
                            }
                        }
                    }
                    
                    // 4. Derive from signals if still no structure
                    if steps.is_empty() {
                        derived_structure = true;
                        if let Some(signals) = yaml.get("signals").and_then(|v| v.as_sequence()) {
                            for (idx, signal) in signals.iter().enumerate() {
                                let sig_type = signal.get("type").and_then(|v| v.as_str())
                                    .unwrap_or(&format!("signal_{}", idx)).to_string();
                                let sig_tag = signal.get("tag").and_then(|v| v.as_str());
                                steps.push(serde_json::json!({
                                    "id": format!("signal_{}", idx),
                                    "name": sig_type,
                                    "required": true,
                                    "expected_fact_types": sig_tag.map(|t| vec![t.to_string()]).unwrap_or_default(),
                                    "description": format!("Signal: {}", sig_type),
                                    "derived_structure": true
                                }));
                            }
                        }
                    }
                    
                    // 5. Derive from detection.signals if still no structure
                    if steps.is_empty() {
                        derived_structure = true;
                        if let Some(detection) = yaml.get("detection") {
                            if let Some(signals) = detection.get("signals").and_then(|v| v.as_sequence()) {
                                for (idx, signal) in signals.iter().enumerate() {
                                    let sig_type = signal.get("type").and_then(|v| v.as_str())
                                        .unwrap_or(&format!("detection_{}", idx)).to_string();
                                    steps.push(serde_json::json!({
                                        "id": format!("detection_{}", idx),
                                        "name": sig_type,
                                        "required": true,
                                        "expected_fact_types": [],
                                        "description": format!("Detection: {}", sig_type),
                                        "derived_structure": true
                                    }));
                                }
                            }
                        }
                    }
                    
                    // Mark if structure was derived
                    for step in &mut steps {
                        if derived_structure {
                            if let Some(obj) = step.as_object_mut() {
                                obj.insert("derived_structure".to_string(), serde_json::Value::Bool(true));
                            }
                        }
                    }
                    
                    // Extract MITRE mapping
                    if let Some(mitre) = yaml.get("mitre") {
                        if let Some(techs) = mitre.get("techniques").and_then(|v| v.as_sequence()) {
                            for t in techs {
                                if let Some(s) = t.as_str() {
                                    mitre_techniques.push(s.to_string());
                                }
                            }
                        }
                        if let Some(tacts) = mitre.get("tactics").and_then(|v| v.as_sequence()) {
                            for t in tacts {
                                if let Some(s) = t.as_str() {
                                    mitre_tactics.push(s.to_string());
                                }
                            }
                        }
                    }
                    }
                    Err(e) => {
                        parse_error = Some(format!("YAML parse error: {}", e));
                    }
                }
            }
            
            // Determine telemetry blocking based on prerequisites vs capability
            let mut telemetry_blocked = false;
            let mut blocked_reasons: Vec<String> = Vec::new();
            
            for req in &requires {
                let req_lower = req.to_lowercase();
                match req_lower.as_str() {
                    "sysmon" => {
                        if !sysmon_installed {
                            telemetry_blocked = true;
                            blocked_reasons.push("Sysmon not installed".to_string());
                        }
                    }
                    "security_log" | "security" | "audit_proc_creation" => {
                        if !security_log_accessible {
                            telemetry_blocked = true;
                            if !is_admin {
                                blocked_reasons.push("Security log requires Administrator".to_string());
                            } else {
                                blocked_reasons.push("Security log not accessible".to_string());
                            }
                        }
                    }
                    "powershell_logging" | "powershell" => {
                        if !powershell_accessible {
                            telemetry_blocked = true;
                            blocked_reasons.push("PowerShell logging channel not accessible".to_string());
                        }
                    }
                    "wmi" | "wmi_activity" => {
                        if !wmi_accessible {
                            telemetry_blocked = true;
                            blocked_reasons.push("WMI activity channel not accessible".to_string());
                        }
                    }
                    "admin" | "administrator" => {
                        if !is_admin {
                            telemetry_blocked = true;
                            blocked_reasons.push("Requires Administrator privileges".to_string());
                        }
                    }
                    _ => {
                        // Unknown requirement - log but don't block
                    }
                }
            }
            
            // Remove duplicate blocked reasons
            blocked_reasons.sort();
            blocked_reasons.dedup();
            
            // Compute derived status
            let can_evaluate = enabled && !telemetry_blocked;
            let status = if !enabled {
                "disabled"
            } else if telemetry_blocked {
                "blocked"
            } else {
                "ok"
            };
            
            // Track counts
            if enabled {
                enabled_count += 1;
            }
            if telemetry_blocked && enabled {
                blocked_count += 1;
            }
            
            // Check if parse_error indicates invalid playbook
            let valid = parse_error.is_none();
            
            playbooks.push(serde_json::json!({
                "playbook_id": playbook_id,
                "name": name,
                "description": description,
                "category": category,
                "enabled": enabled,
                "requires": requires,
                "telemetry_blocked": telemetry_blocked,
                "blocked_reasons": blocked_reasons,
                "can_evaluate": can_evaluate,
                "status": if !valid { "invalid" } else { status },
                "mitre_techniques": mitre_techniques,
                "mitre_tactics": mitre_tactics,
                "steps": steps,
                "source": source,
                "editable": is_custom,
                "valid": valid,
                "parse_error": parse_error,
                "file_path": path.display().to_string()
            }));
        }
    }
    } // end for (scan_dir, is_custom_dir)
    
    let total_count = playbooks.len();
    let runnable_count = enabled_count - blocked_count;
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "available": true,
            "playbooks_dir": target_dir.display().to_string(),
            "loaded_count": total_count,
            "enabled_count": enabled_count,
            "blocked_count": blocked_count,
            "runnable_count": runnable_count,
            "playbooks": playbooks,
            "capability_summary": {
                "sysmon_installed": sysmon_installed,
                "security_log_accessible": security_log_accessible,
                "is_admin": is_admin,
                "powershell_accessible": powershell_accessible,
                "wmi_accessible": wmi_accessible
            }
        }
    }))
}

/// GET /api/playbooks/presets - Get available playbook presets with capability-aware resolution
async fn playbook_presets_handler() -> Json<serde_json::Value> {
    // Get current capability status
    let capability = services::capability::get_capability_status();
    let sysmon_installed = capability.get("sysmon_installed").and_then(|v| v.as_bool()).unwrap_or(false);
    let security_log_accessible = capability.get("security_log_accessible").and_then(|v| v.as_bool()).unwrap_or(false);
    let is_admin = capability.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
    
    // Check channel accessibility for PowerShell
    let channels = capability.get("channels").and_then(|v| v.as_array());
    let powershell_accessible = channels.map(|chs| {
        chs.iter().any(|c| {
            c.get("name").and_then(|n| n.as_str()) == Some("Microsoft-Windows-PowerShell/Operational")
                && c.get("accessible").and_then(|a| a.as_bool()).unwrap_or(false)
        })
    }).unwrap_or(false);
    
    // Load catalog to resolve presets
    let (playbooks_dir, _, _) = services::run_control::discover_playbooks_dir();
    let mut all_playbooks: Vec<(String, Vec<String>)> = Vec::new(); // (playbook_id, requires)
    
    if let Some(pb_dir) = playbooks_dir {
        let windows_dir = pb_dir.join("windows");
        let target_dir = if windows_dir.exists() { windows_dir } else { pb_dir };
        
        if let Ok(entries) = std::fs::read_dir(&target_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                    continue;
                }
                
                let playbook_id = path.file_stem()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                // Parse requires from YAML
                let mut requires: Vec<String> = Vec::new();
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                        if let Some(reqs) = yaml.get("requires").and_then(|v| v.as_sequence()) {
                            for req in reqs {
                                if let Some(r) = req.as_str() {
                                    requires.push(r.to_lowercase());
                                }
                            }
                        }
                    }
                }
                
                all_playbooks.push((playbook_id, requires));
            }
        }
    }
    
    // Define presets based on requires metadata
    let mut presets = Vec::new();
    
    // General: playbooks with NO special requirements (works without admin/sysmon/security log)
    // These focus on "system changes" - persistence, service creation, log tampering, etc.
    let general_playbooks: Vec<String> = all_playbooks.iter()
        .filter(|(_, reqs)| {
            !reqs.iter().any(|r| 
                r.contains("sysmon") || 
                r.contains("security") || 
                r.contains("admin") ||
                r.contains("audit_proc")
            )
        })
        .map(|(id, _)| id.clone())
        .collect();
    
    presets.push(serde_json::json!({
        "preset_id": "general",
        "name": "General (System Changes)",
        "description": "Baseline system-change detection: service persistence, log tampering, scheduled tasks",
        "playbook_ids": general_playbooks,
        "count": general_playbooks.len(),
        "runnable_now": true,
        "icon": "🌐",
        "is_default": true,
        "surfaces": {
            "observable": [
                {"id": "services", "name": "Service Installs", "source": "System 7045"},
                {"id": "logs", "name": "Log Cleared Events", "source": "System 104"},
                {"id": "tasks", "name": "Scheduled Tasks", "source": "TaskScheduler 106"}
            ],
            "requires_upgrade": [
                {"id": "registry", "name": "Registry Persistence", "requires": "sysmon", "unlock_preset": "sysmon"},
                {"id": "process_exec", "name": "Process Execution", "requires": "security_log", "unlock_preset": "admin"},
                {"id": "lateral", "name": "Lateral Movement", "requires": "security_log", "unlock_preset": "admin"},
                {"id": "credential", "name": "Credential Access", "requires": "sysmon", "unlock_preset": "sysmon"}
            ]
        }
    }));
    
    // Admin: playbooks requiring Security log (need admin)
    let admin_playbooks: Vec<String> = all_playbooks.iter()
        .filter(|(_, reqs)| {
            reqs.iter().any(|r| r.contains("security") || r.contains("audit_proc") || r.contains("admin"))
                && !reqs.iter().any(|r| r.contains("sysmon"))
        })
        .map(|(id, _)| id.clone())
        .collect();
    
    let admin_combined: Vec<String> = general_playbooks.iter()
        .chain(admin_playbooks.iter())
        .cloned()
        .collect();
    
    presets.push(serde_json::json!({
        "preset_id": "admin",
        "name": "Admin (+ Security Log)",
        "description": "General + process creation, logon events, and credential access detection (requires Administrator)",
        "playbook_ids": admin_combined,
        "count": admin_combined.len(),
        "runnable_now": security_log_accessible,
        "requires": ["security_log"],
        "icon": "🔐",
        "unlocks": admin_playbooks.len()
    }));
    
    // Sysmon: playbooks requiring Sysmon
    let sysmon_playbooks: Vec<String> = all_playbooks.iter()
        .filter(|(_, reqs)| reqs.iter().any(|r| r.contains("sysmon")))
        .map(|(id, _)| id.clone())
        .collect();
    
    let sysmon_combined: Vec<String> = general_playbooks.iter()
        .chain(sysmon_playbooks.iter())
        .cloned()
        .collect();
    
    presets.push(serde_json::json!({
        "preset_id": "sysmon",
        "name": "Sysmon (+ Deep Visibility)",
        "description": "General + process injection, DLL loading, and credential access detection (requires Sysmon)",
        "playbook_ids": sysmon_combined,
        "count": sysmon_combined.len(),
        "runnable_now": sysmon_installed,
        "requires": ["sysmon"],
        "icon": "🔍",
        "unlocks": sysmon_playbooks.len()
    }));
    
    // PowerShell: playbooks requiring PowerShell logging
    let powershell_playbooks: Vec<String> = all_playbooks.iter()
        .filter(|(_, reqs)| reqs.iter().any(|r| r.contains("powershell")))
        .map(|(id, _)| id.clone())
        .collect();
    
    let powershell_combined: Vec<String> = general_playbooks.iter()
        .chain(powershell_playbooks.iter())
        .cloned()
        .collect();
    
    presets.push(serde_json::json!({
        "preset_id": "powershell",
        "name": "PowerShell",
        "description": "General + PowerShell script block logging detection",
        "playbook_ids": powershell_combined,
        "count": powershell_combined.len(),
        "runnable_now": powershell_accessible,
        "requires": ["powershell_logging"],
        "icon": "⚡",
        "unlocks": powershell_playbooks.len()
    }));
    
    // Extended: ALL playbooks (union of everything)
    let extended_playbooks: Vec<String> = all_playbooks.iter()
        .map(|(id, _)| id.clone())
        .collect();
    
    presets.push(serde_json::json!({
        "preset_id": "extended",
        "name": "Extended (All)",
        "description": "All available playbooks - blocked ones will show as unavailable",
        "playbook_ids": extended_playbooks,
        "count": extended_playbooks.len(),
        "runnable_now": true,
        "note": "Blocked playbooks will not evaluate but will show in results",
        "icon": "🔮"
    }));
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "presets": presets,
            "capability": {
                "sysmon_installed": sysmon_installed,
                "security_log_accessible": security_log_accessible,
                "is_admin": is_admin,
                "powershell_accessible": powershell_accessible
            },
            "total_playbooks": all_playbooks.len()
        }
    }))
}

/// GET /api/playbooks/selection - Get saved default playbook selection
async fn get_playbook_selection_handler() -> Json<serde_json::Value> {
    // Load from local config file
    let config_dir = std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("attack-workbench");
    
    let selection_path = config_dir.join("playbook_selection.json");
    
    if let Ok(content) = std::fs::read_to_string(&selection_path) {
        if let Ok(selection) = serde_json::from_str::<serde_json::Value>(&content) {
            return Json(serde_json::json!({
                "success": true,
                "data": selection
            }));
        }
    }
    
    // Return default (general preset - system changes focused)
    Json(serde_json::json!({
        "success": true,
        "data": {
            "mode": "preset",
            "preset": "general",
            "selected_playbooks": []
        }
    }))
}

/// POST /api/playbooks/selection - Save default playbook selection
async fn save_playbook_selection_handler(
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    // Validate request
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("preset");
    let preset = body.get("preset").and_then(|v| v.as_str());
    let selected_playbooks: Vec<String> = body.get("selected_playbooks")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    
    let selection = serde_json::json!({
        "mode": mode,
        "preset": preset,
        "selected_playbooks": selected_playbooks,
        "saved_at": chrono::Utc::now().to_rfc3339()
    });
    
    // Save to local config file
    let config_dir = std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("attack-workbench");
    
    if let Err(e) = std::fs::create_dir_all(&config_dir) {
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Failed to create config directory: {}", e)
        }));
    }
    
    let selection_path = config_dir.join("playbook_selection.json");
    
    match std::fs::write(&selection_path, serde_json::to_string_pretty(&selection).unwrap()) {
        Ok(_) => Json(serde_json::json!({
            "success": true,
            "data": {
                "saved": true,
                "path": selection_path.display().to_string(),
                "selection": selection
            }
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": format!("Failed to save selection: {}", e)
        }))
    }
}

/// GET /api/playbooks/:playbook_id/yaml - Get raw YAML content (dev mode only)
async fn playbook_yaml_handler(
    Path(playbook_id): Path<String>,
) -> Json<serde_json::Value> {
    // Check dev mode via env var
    let dev_mode = std::env::var("LOCINT_DEV_VIEW").unwrap_or_default() == "1";
    
    if !dev_mode {
        return Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "DEV_MODE_REQUIRED",
                "message": "YAML view requires dev mode (LOCINT_DEV_VIEW=1)"
            }
        }));
    }
    
    // Validate playbook_id to prevent path traversal
    if playbook_id.contains("..") || playbook_id.contains('/') || playbook_id.contains('\\') {
        return Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "INVALID_PLAYBOOK_ID",
                "message": "Invalid playbook ID"
            }
        }));
    }
    
    let (playbooks_dir, _, _) = services::run_control::discover_playbooks_dir();
    if playbooks_dir.is_none() {
        return Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "PLAYBOOKS_NOT_FOUND",
                "message": "Playbooks directory not found"
            }
        }));
    }
    
    let pb_dir = playbooks_dir.unwrap();
    
    // Search in both builtin and custom directories
    let dirs_to_search = vec![
        pb_dir.join("windows"),
        pb_dir.clone(),
        pb_dir.join("custom"),
    ];
    
    for dir in dirs_to_search {
        for ext in &["yaml", "yml"] {
            let path = dir.join(format!("{}.{}", playbook_id, ext));
            if path.exists() {
                match std::fs::read_to_string(&path) {
                    Ok(content) => {
                        // Size limit for safety
                        if content.len() > 64 * 1024 {
                            return Json(serde_json::json!({
                                "success": false,
                                "error": {
                                    "code": "FILE_TOO_LARGE",
                                    "message": "Playbook file exceeds size limit (64KB)"
                                }
                            }));
                        }
                        
                        return Json(serde_json::json!({
                            "success": true,
                            "data": {
                                "playbook_id": playbook_id,
                                "yaml_content": content,
                                "file_path": path.display().to_string(),
                                "size_bytes": content.len()
                            }
                        }));
                    }
                    Err(e) => {
                        return Json(serde_json::json!({
                            "success": false,
                            "error": {
                                "code": "READ_ERROR",
                                "message": format!("Failed to read playbook: {}", e)
                            }
                        }));
                    }
                }
            }
        }
    }
    
    Json(serde_json::json!({
        "success": false,
        "error": {
            "code": "NOT_FOUND",
            "message": format!("Playbook '{}' not found", playbook_id)
        }
    }))
}

/// POST /api/playbooks/:playbook_id/duplicate - Duplicate playbook to custom directory
async fn playbook_duplicate_handler(
    Path(playbook_id): Path<String>,
) -> Json<serde_json::Value> {
    // Validate playbook_id to prevent path traversal
    if playbook_id.contains("..") || playbook_id.contains('/') || playbook_id.contains('\\') {
        return Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "INVALID_PLAYBOOK_ID",
                "message": "Invalid playbook ID"
            }
        }));
    }
    
    let (playbooks_dir, _, _) = services::run_control::discover_playbooks_dir();
    if playbooks_dir.is_none() {
        return Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "PLAYBOOKS_NOT_FOUND",
                "message": "Playbooks directory not found"
            }
        }));
    }
    
    let pb_dir = playbooks_dir.unwrap();
    let custom_dir = pb_dir.join("custom");
    
    // Create custom directory if it doesn't exist
    if !custom_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(&custom_dir) {
            return Json(serde_json::json!({
                "success": false,
                "error": {
                    "code": "MKDIR_FAILED",
                    "message": format!("Failed to create custom directory: {}", e)
                }
            }));
        }
    }
    
    // Find the source playbook
    let dirs_to_search = vec![
        pb_dir.join("windows"),
        pb_dir.clone(),
    ];
    
    let mut source_path: Option<std::path::PathBuf> = None;
    let mut source_content: Option<String> = None;
    
    for dir in dirs_to_search {
        for ext in &["yaml", "yml"] {
            let path = dir.join(format!("{}.{}", playbook_id, ext));
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    source_path = Some(path);
                    source_content = Some(content);
                    break;
                }
            }
        }
        if source_path.is_some() {
            break;
        }
    }
    
    if source_path.is_none() || source_content.is_none() {
        return Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "NOT_FOUND",
                "message": format!("Playbook '{}' not found", playbook_id)
            }
        }));
    }
    
    let content = source_content.unwrap();
    
    // Size limit
    if content.len() > 64 * 1024 {
        return Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "FILE_TOO_LARGE",
                "message": "Source playbook exceeds size limit (64KB)"
            }
        }));
    }
    
    // Generate unique filename with timestamp
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let new_filename = format!("{}__custom__{}.yaml", playbook_id, timestamp);
    let new_path = custom_dir.join(&new_filename);
    
    // Check if file already exists (shouldn't happen with timestamp but be safe)
    if new_path.exists() {
        return Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "FILE_EXISTS",
                "message": "A custom playbook with this name already exists"
            }
        }));
    }
    
    // Write atomically via temp file
    let temp_path = custom_dir.join(format!(".tmp_{}", new_filename));
    if let Err(e) = std::fs::write(&temp_path, &content) {
        return Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "WRITE_FAILED",
                "message": format!("Failed to write playbook: {}", e)
            }
        }));
    }
    
    // Rename temp to final
    if let Err(e) = std::fs::rename(&temp_path, &new_path) {
        let _ = std::fs::remove_file(&temp_path); // Clean up
        return Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "RENAME_FAILED",
                "message": format!("Failed to finalize playbook: {}", e)
            }
        }));
    }
    
    // Extract new playbook_id from filename
    let new_playbook_id = new_path.file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or(&new_filename)
        .to_string();
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "original_playbook_id": playbook_id,
            "new_playbook_id": new_playbook_id,
            "file_path": new_path.display().to_string(),
            "custom_dir": custom_dir.display().to_string(),
            "message": "Playbook duplicated successfully. Use Rescan to reload playbooks."
        }
    }))
}

/// GET /api/runs/:run_id/playbooks/eval - Per-run playbook evaluation with scope + reason codes
///
/// Returns ONLY playbooks in effective_playbook_ids (from playbook_scope).
/// Each result includes:
/// - in_scope: whether playbook was in run's scope
/// - scope_mode: explicit|general_discovery|preset_default|none
/// - status: fired|candidate|no_match|blocked|skipped
/// - reason_codes: machine-readable explanations
/// - slots: per-slot match results with reason_codes
async fn run_playbooks_eval_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Json<serde_json::Value> {
    let run_dir = state.data_dir.join("runs").join(&run_id);
    let meta_path = run_dir.join("run_meta.json");
    
    // Get playbook catalog data FIRST (need this for scope expansion)
    let (playbooks_dir, _, _) = services::run_control::discover_playbooks_dir();
    if playbooks_dir.is_none() {
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "run_id": run_id,
                "available": false,
                "reason": "Playbooks directory not found",
                "evaluations": []
            }
        }));
    }
    let pb_dir = playbooks_dir.unwrap();
    
    // Discover ALL playbook IDs from filesystem
    let all_playbook_ids = discover_all_playbook_ids(&pb_dir);
    
    // Read playbook_scope from run_meta.json (SSoT for what was evaluated)
    let mut playbook_scope = read_playbook_scope(&meta_path);
    
    // SCOPE EXPANSION: If mode is GeneralDiscovery, replace effective_playbook_ids with ALL variants
    // This ensures old runs with the 8-item set get expanded to all ~30 variants
    if playbook_scope.mode == ScopeMode::GeneralDiscovery {
        playbook_scope.effective_playbook_ids = all_playbook_ids.clone();
        playbook_scope.rationale.note = format!(
            "Evaluating all {} playbook variants (v2.0.0 - all variants mode)",
            all_playbook_ids.len()
        );
    }
    
    let visibility = build_visibility_summary(&meta_path);
    
    // Get capability details
    let capability = services::capability::get_capability_snapshot_from_meta(&meta_path);
    let sysmon_installed = capability.get("sysmon_installed").and_then(|v| v.as_bool()).unwrap_or(false);
    let security_log_accessible = capability.get("security_log_accessible").and_then(|v| v.as_bool()).unwrap_or(false);
    let is_admin = capability.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
    
    // Build effective playbooks set for fast lookup
    let effective_set = playbook_scope.effective_set();
    
    // Try to open run DB
    let conn = match services::run_control::open_run_db(&state.db, &run_id) {
        Ok(h) => h.conn,
        Err(_) => {
            let fallback_path = run_dir.join("workbench.db");
            if fallback_path.exists() {
                match services::run_control::open_db_with_wal(&fallback_path) {
                    Ok(c) => c,
                    Err(_) => {
                        return Json(serde_json::json!({
                            "success": true,
                            "data": {
                                "run_id": run_id,
                                "available": false,
                                "reason": "Run database not accessible",
                                "playbook_scope": playbook_scope,
                                "visibility": visibility,
                                "evaluations": []
                            }
                        }));
                    }
                }
            } else {
                return Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "run_id": run_id,
                        "available": false,
                        "reason": "Run not found",
                        "playbook_scope": playbook_scope,
                        "visibility": visibility,
                        "evaluations": []
                    }
                }));
            }
        }
    };
    
    // Query signals to find fired playbooks
    let mut fired_playbooks: std::collections::HashMap<String, Vec<serde_json::Value>> = std::collections::HashMap::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT signal_id, signal_type, severity, ts, evidence_ptrs FROM signals ORDER BY ts DESC"
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        }) {
            for row in rows.flatten() {
                let (signal_id, signal_type, severity, ts, evidence_ptrs_json) = row;
                // evidence_ptrs is stored as JSON array in its own column
                let evidence_ptrs: Vec<serde_json::Value> = evidence_ptrs_json
                    .and_then(|json| serde_json::from_str::<Vec<serde_json::Value>>(&json).ok())
                    .unwrap_or_default();
                
                // Strip "playbook:" prefix from signal_type to match playbook_id
                // Signal types are stored as "playbook:defense_evasion" but we match by "defense_evasion"
                let playbook_key = signal_type.strip_prefix("playbook:").unwrap_or(&signal_type).to_string();
                
                let entry = fired_playbooks.entry(playbook_key).or_insert_with(Vec::new);
                entry.push(serde_json::json!({
                    "signal_id": signal_id,
                    "severity": severity,
                    "ts": ts,
                    "evidence_pointers": evidence_ptrs
                }));
            }
        }
    }
    
    // Query available fact types
    let mut available_fact_types: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Ok(mut stmt) = conn.prepare("SELECT DISTINCT fact_type FROM facts") {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
            for ft in rows.flatten() {
                available_fact_types.insert(ft);
            }
        }
    }
    
    // Build evaluations - ONLY for in-scope playbooks
    let windows_dir = pb_dir.join("windows");
    let target_dir = if windows_dir.exists() { windows_dir } else { pb_dir.clone() };
    let custom_dir = pb_dir.join("custom");
    
    let mut evaluations: Vec<PlaybookEvalResult> = Vec::new();
    let mut out_of_scope: Vec<PlaybookEvalResult> = Vec::new();
    
    let dirs = vec![target_dir, custom_dir];
    for dir in dirs {
        if !dir.exists() {
            continue;
        }
        
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                    continue;
                }
                if path.to_string_lossy().contains("unsupported") {
                    continue;
                }
                
                let raw_playbook_id = path.file_stem()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                // Normalize playbook_id by stripping "signal_" prefix for scope matching
                // Files are named signal_foo.yaml but scope uses just "foo"
                let playbook_id = raw_playbook_id.strip_prefix("signal_")
                    .unwrap_or(&raw_playbook_id)
                    .to_string();
                
                // Check if playbook is in scope
                let in_scope = effective_set.contains(&playbook_id);
                
                // Parse YAML for structure
                let mut playbook_name = playbook_id.clone();
                let mut playbook_family: Option<String> = None;
                let mut requires: Vec<String> = Vec::new();
                // Extended slot_defs to include evidence hints: (id, name, fact_types, required, expected_facts_rendered, evidence_hints)
                let mut slot_defs: Vec<(String, String, Vec<String>, bool, Vec<String>, Option<serde_json::Value>)> = Vec::new();
                
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                        if let Some(n) = yaml.get("name").or(yaml.get("title")).and_then(|v| v.as_str()) {
                            playbook_name = n.to_string();
                        }
                        
                        // Read family field from playbook YAML
                        if let Some(f) = yaml.get("family").and_then(|v| v.as_str()) {
                            playbook_family = Some(f.to_string());
                        }
                        
                        if let Some(reqs) = yaml.get("requires").and_then(|v| v.as_sequence()) {
                            for req in reqs {
                                if let Some(r) = req.as_str() {
                                    requires.push(r.to_lowercase());
                                }
                            }
                        }
                        
                        // Extract rules as slots WITH expected facts and evidence hints
                        if let Some(rules) = yaml.get("rules").and_then(|v| v.as_sequence()) {
                            for (idx, rule) in rules.iter().enumerate() {
                                let default_name = format!("Rule {}", idx + 1);
                                let slot_name = rule.get("name").and_then(|v| v.as_str())
                                    .unwrap_or(&default_name).to_string();
                                
                                // Read expected facts from rule.expected.facts
                                let mut expected_facts_rendered: Vec<String> = Vec::new();
                                let mut evidence_hints: Option<serde_json::Value> = None;
                                let mut fact_types: Vec<String> = Vec::new();
                                
                                // Try to access expected using mapping index with String key
                                if let Some(mapping) = rule.as_mapping() {
                                    let expected_key = serde_yaml::Value::String("expected".to_string());
                                    if let Some(expected) = mapping.get(&expected_key) {
                                        // Read human-readable facts
                                        if let Some(facts) = expected.get("facts").and_then(|v| v.as_sequence()) {
                                            for fact in facts {
                                                if let Some(f) = fact.as_str() {
                                                    expected_facts_rendered.push(f.to_string());
                                                }
                                            }
                                        }
                                        
                                        // Read variants if present
                                        if let Some(variants) = expected.get("variants").and_then(|v| v.as_sequence()) {
                                            for variant in variants {
                                                if let Some(label) = variant.get("label").and_then(|v| v.as_str()) {
                                                    if let Some(vfacts) = variant.get("facts").and_then(|v| v.as_sequence()) {
                                                        for vf in vfacts {
                                                            if let Some(f) = vf.as_str() {
                                                                expected_facts_rendered.push(format!("[{}] {}", label, f));
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        
                                        // Read evidence hints
                                        if let Some(evidence) = expected.get("evidence") {
                                            let mut hints = serde_json::Map::new();
                                            
                                            if let Some(lens) = evidence.get("lens").and_then(|v| v.as_str()) {
                                                hints.insert("lens".to_string(), serde_json::json!(lens));
                                            }
                                            if let Some(ft) = evidence.get("fact_types").and_then(|v| v.as_sequence()) {
                                                let types: Vec<String> = ft.iter()
                                                    .filter_map(|t| t.as_str().map(String::from))
                                                    .collect();
                                                fact_types = types.clone();
                                                hints.insert("fact_types".to_string(), serde_json::json!(types));
                                            }
                                            if let Some(qt) = evidence.get("query_terms").and_then(|v| v.as_sequence()) {
                                                let terms: Vec<String> = qt.iter()
                                                    .filter_map(|t| t.as_str().map(String::from))
                                                    .collect();
                                                hints.insert("query_terms".to_string(), serde_json::json!(terms));
                                            }
                                            if let Some(eids) = evidence.get("event_ids").and_then(|v| v.as_sequence()) {
                                                let ids: Vec<i64> = eids.iter()
                                                    .filter_map(|e| e.as_i64())
                                                    .collect();
                                                hints.insert("event_ids".to_string(), serde_json::json!(ids));
                                            }
                                            
                                            if !hints.is_empty() {
                                                evidence_hints = Some(serde_json::Value::Object(hints));
                                            }
                                        }
                                    }
                                }
                                
                                // Fallback: extract fact_type from conditions if not in expected.evidence
                                if fact_types.is_empty() {
                                    if let Some(conditions) = rule.get("conditions").and_then(|v| v.as_sequence()) {
                                        for cond in conditions {
                                            if let Some(ft) = cond.get("fact_type").and_then(|v| v.as_str()) {
                                                if !fact_types.contains(&ft.to_string()) {
                                                    fact_types.push(ft.to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                slot_defs.push((format!("rule_{}", idx), slot_name.clone(), fact_types, true, expected_facts_rendered.clone(), evidence_hints));
                            }
                        }
                        
                        // Derive from input_facts if no rules
                        if slot_defs.is_empty() {
                            if let Some(input_facts) = yaml.get("input_facts") {
                                if let Some(req_facts) = input_facts.get("required").and_then(|v| v.as_sequence()) {
                                    for fact in req_facts {
                                        if let Some(ft) = fact.as_str() {
                                            slot_defs.push((
                                                format!("fact_{}", ft.to_lowercase()),
                                                ft.to_string(),
                                                vec![ft.to_string()],
                                                true,
                                                vec![format!("{} fact required", ft)],
                                                None
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Determine scope reason code
                let scope_reason = match playbook_scope.mode {
                    ScopeMode::Explicit => EvalReasonCode::UserSelectedScope,
                    ScopeMode::GeneralDiscovery => EvalReasonCode::NoSelectionDefaultedToDiscovery,
                    ScopeMode::PresetDefault => EvalReasonCode::PresetDefaultScope,
                    ScopeMode::None => EvalReasonCode::OutOfScopeSkipped,
                };
                
                // If out of scope, create skipped result
                if !in_scope {
                    out_of_scope.push(PlaybookEvalResult::skipped(
                        &run_id,
                        &playbook_id,
                        &playbook_name,
                        visibility.clone(),
                    ));
                    continue;
                }
                
                // Determine visibility-based blocking
                let mut blocked = false;
                let mut block_reason: Option<EvalReasonCode> = None;
                
                for req in &requires {
                    match req.as_str() {
                        "sysmon" if !sysmon_installed => {
                            blocked = true;
                            block_reason = Some(EvalReasonCode::MissingSensorSysmon);
                        }
                        "security_log" | "security" if !security_log_accessible => {
                            blocked = true;
                            block_reason = Some(EvalReasonCode::LogAccessDenied);
                        }
                        "admin" | "administrator" if !is_admin => {
                            blocked = true;
                            block_reason = Some(EvalReasonCode::ProviderUnavailable);
                        }
                        _ => {}
                    }
                    if blocked {
                        break;
                    }
                }
                
                // Determine fired status
                let fired_signals = fired_playbooks.get(&playbook_id);
                let is_fired = fired_signals.map(|s| !s.is_empty()).unwrap_or(false);
                
                // Extract evidence pointers from fired signals for match_trace
                let evidence_refs_from_signal: Vec<EvidenceRef> = fired_signals
                    .and_then(|sigs| sigs.first())
                    .and_then(|s| s.get("evidence_pointers"))
                    .and_then(|v| v.as_array())
                    .map(|ptrs| {
                        ptrs.iter().filter_map(|ptr| {
                            Some(EvidenceRef {
                                fact_id: ptr.get("fact_id").and_then(|v| v.as_str()).map(String::from),
                                segment_id: ptr.get("segment_id").and_then(|v| v.as_str()).map(String::from),
                                record_index: ptr.get("record_index").and_then(|v| v.as_u64()).map(|n| n as u32),
                                fact_type: ptr.get("fact_type").and_then(|v| v.as_str()).map(String::from),
                                ts: ptr.get("ts").and_then(|v| v.as_i64()),
                            })
                        }).collect()
                    })
                    .unwrap_or_default();
                
                // Build slot results
                let mut slots: Vec<SlotEvalResult> = Vec::new();
                let mut slots_matched = 0u32;
                
                for (slot_id, slot_name, fact_types, required, expected_facts_rendered, evidence_hints) in &slot_defs {
                    let has_matching_facts = fact_types.iter()
                        .any(|ft| available_fact_types.contains(ft));
                    
                    // IMPORTANT: is_fired takes precedence over blocked
                    // If a signal fired, the playbook detected something regardless of current visibility
                    let (slot_status, slot_reason, match_count) = if is_fired {
                        slots_matched += 1;
                        // Use evidence count from signal, default to 1 if fired
                        let count = evidence_refs_from_signal.len().max(1) as u32;
                        (SlotEvalStatus::Matched, EvalReasonCode::AllSlotsSatisfied, count)
                    } else if blocked {
                        (SlotEvalStatus::Blocked, block_reason.clone().unwrap_or(EvalReasonCode::ProviderUnavailable), 0)
                    } else if has_matching_facts {
                        // Facts exist but playbook didn't fire - partial
                        (SlotEvalStatus::Missing, EvalReasonCode::NoMatchingFacts, 0)
                    } else {
                        (SlotEvalStatus::Missing, EvalReasonCode::NoMatchingFacts, 0)
                    };
                    
                    // Build search hints from evidence_hints if available
                    // IMPORTANT: Always provide search_hints (not Option) to eliminate UI inference
                    // EVIDENCE TAB UPGRADE: Populate query_terms for reliable tokenized search
                    let search_hints = if let Some(hints) = evidence_hints {
                        let raw_terms: Vec<String> = hints.get("query_terms").and_then(|v| v.as_array())
                            .map(|arr| arr.iter().filter_map(|t| t.as_str().map(String::from)).collect())
                            .unwrap_or_default();
                        SlotSearchHints {
                            lens: hints.get("lens").and_then(|v| v.as_str()).map(String::from),
                            query: if raw_terms.is_empty() { 
                                Some(slot_name.replace('_', " "))
                            } else {
                                Some(raw_terms.join(" "))
                            },
                            query_terms: if raw_terms.is_empty() {
                                // Fallback: tokenize slot_name 
                                slot_name.split('_').map(String::from).collect()
                            } else {
                                raw_terms
                            },
                            fact_types: hints.get("fact_types").and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(|t| t.as_str().map(String::from)).collect())
                                .unwrap_or_else(|| fact_types.clone()),
                            host: hints.get("host").and_then(|v| v.as_str()).map(String::from),
                            time_range: None, // TODO: Extract from hints if present
                        }
                    } else {
                        // No explicit evidence hints - synthesize from slot_name + fact_types
                        // This ensures UI NEVER has to infer
                        SlotSearchHints {
                            lens: None,
                            query: Some(slot_name.replace('_', " ")), // Convert snake_case to words
                            query_terms: slot_name.split('_').map(String::from).collect(),
                            fact_types: if fact_types.is_empty() && !expected_facts_rendered.is_empty() {
                                // Use expected_facts as hint if no fact_types available
                                expected_facts_rendered.iter().take(3).cloned().collect()
                            } else {
                                fact_types.clone()
                            },
                            host: None,
                            time_range: None,
                        }
                    };
                    
                    // Build match_trace - backend-authored proof of evidence
                    let match_trace = if slot_status == SlotEvalStatus::Matched {
                        MatchTrace::matched_with_count(match_count, evidence_refs_from_signal.clone())
                    } else {
                        MatchTrace::unmatched()
                    };
                    
                    slots.push(SlotEvalResult {
                        slot_id: slot_id.clone(),
                        slot_name: slot_name.clone(),
                        required: *required,
                        status: slot_status,
                        match_count,
                        reason_code: slot_reason,
                        search_hints,
                        expected_fact_types: expected_facts_rendered.clone(),
                        match_trace,
                    });
                }
                
                // Determine overall status
                // IMPORTANT: is_fired takes precedence - if signal exists, playbook fired
                let (status, reason_codes) = if is_fired {
                    (PlaybookEvalStatus::Fired, vec![scope_reason, EvalReasonCode::AllSlotsSatisfied])
                } else if blocked {
                    (PlaybookEvalStatus::Blocked, vec![block_reason.unwrap()])
                } else if slots_matched > 0 {
                    (PlaybookEvalStatus::Candidate, vec![scope_reason, EvalReasonCode::PartialSlotsSatisfied])
                } else {
                    (PlaybookEvalStatus::NoMatch, vec![scope_reason, EvalReasonCode::NoMatchingFacts])
                };
                
                // Get severity from fired signals
                let severity = fired_signals
                    .and_then(|sigs| sigs.first())
                    .and_then(|s| s.get("severity"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
                
                // Generate backend-authored narrative (explainability contract)
                let narrative = generate_narrative(
                    &playbook_name,
                    &status,
                    &reason_codes,
                    &visibility,
                    &slots,
                    slots_matched,
                    slot_defs.len() as u32,
                );
                
                evaluations.push(PlaybookEvalResult {
                    run_id: run_id.clone(),
                    playbook_id,
                    playbook_name,
                    family: playbook_family,
                    in_scope: true,
                    scope_mode: playbook_scope.mode.clone(),
                    status,
                    severity,
                    slots_matched,
                    total_slots: slot_defs.len() as u32,
                    window_remark: None,
                    visibility: visibility.clone(),
                    reason_codes,
                    slots,
                    narrative: Some(narrative),
                });
            }
        }
    }
    
    // Build response with new format
    let response = PlaybooksEvalResponse {
        run_id: run_id.clone(),
        available: true,
        reason: None,
        playbook_scope,
        visibility: visibility.clone(),
        evaluations: evaluations.clone(),
        out_of_scope: if out_of_scope.is_empty() { None } else { Some(out_of_scope.clone()) },
    };
    
    // Return in backward-compatible wrapper format
    Json(serde_json::json!({
        "success": true,
        "data": {
            "run_id": run_id,
            "available": true,
            "playbook_scope": response.playbook_scope,
            "visibility": response.visibility,
            "evaluations": response.evaluations,
            "out_of_scope_count": out_of_scope.len(),
            // Legacy fields for backward compatibility
            "capability": {
                "sysmon_installed": sysmon_installed,
                "security_log_accessible": security_log_accessible,
                "is_admin": is_admin
            },
            "available_fact_types": available_fact_types.into_iter().collect::<Vec<_>>()
        }
    }))
}

async fn list_packs_handler(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let packs_dir = state.data_dir.join("packs");
    let packs = services::packs::list_packs(&packs_dir);
    let tier_allows_custom = services::packs::tier_allows_custom_packs();
    
    // Always include built-in pack
    let (builtin_count, builtin_hash) = {
        let (playbooks_dir, _, _) = services::run_control::discover_playbooks_dir();
        if let Some(pb_dir) = playbooks_dir {
            let count = std::fs::read_dir(&pb_dir)
                .map(|e| e.filter(|e| e.as_ref().ok().map(|e| 
                    e.path().extension().map(|ext| ext == "yaml" || ext == "yml").unwrap_or(false)
                ).unwrap_or(false)).count())
                .unwrap_or(0);
            let hash = services::packs::compute_playbooks_hash(&pb_dir);
            (count, hash)
        } else {
            (0, "none".to_string())
        }
    };
    
    let mut all_packs = vec![serde_json::json!({
        "name": "builtin",
        "display_name": "Built-in Detections",
        "version": "1.0.0",
        "playbook_count": builtin_count,
        "is_builtin": true,
        "enabled": true,
        "integrity": { "playbooks_sha256": builtin_hash }
    })];
    all_packs.extend(packs);
    
    let count = all_packs.len();
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "packs": all_packs,
            "count": count,
            "tier_allows_custom": tier_allows_custom
        }
    }))
}

async fn get_pack_handler(
    State(state): State<SharedState>,
    Path(pack_name): Path<String>,
) -> Json<serde_json::Value> {
    // Handle built-in pack (always allowed)
    if pack_name == "builtin" {
        let (playbooks_dir, _, _) = services::run_control::discover_playbooks_dir();
        let (count, hash) = if let Some(pb_dir) = playbooks_dir {
            let count = std::fs::read_dir(&pb_dir)
                .map(|e| e.filter(|e| e.as_ref().ok().map(|e| 
                    e.path().extension().map(|ext| ext == "yaml" || ext == "yml").unwrap_or(false)
                ).unwrap_or(false)).count())
                .unwrap_or(0);
            let hash = services::packs::compute_playbooks_hash(&pb_dir);
            (count, hash)
        } else {
            (0, "none".to_string())
        };
        
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "name": "builtin",
                "display_name": "Built-in Detections",
                "version": "1.0.0",
                "playbook_count": count,
                "is_builtin": true,
                "enabled": true,
                "integrity": { "playbooks_sha256": hash }
            }
        }));
    }
    
    // Tier gate: Custom packs require Pro
    if !resolve_current_tier().has_access(services::types::ProductTier::Pro) {
        let (_, json) = feature_locked_403("Custom Content Packs", services::types::ProductTier::Pro);
        return json;
    }
    
    let packs_dir = state.data_dir.join("packs");
    match services::packs::get_pack_details(&packs_dir, &pack_name) {
        Some(pack) => Json(serde_json::json!({
            "success": true,
            "data": pack
        })),
        None => Json(serde_json::json!({
            "success": false,
            "error": format!("Pack '{}' not found", pack_name),
            "code": "PACK_NOT_FOUND"
        })),
    }
}

async fn rescan_packs_handler(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let packs_dir = state.data_dir.join("packs");
    let pack_count = if packs_dir.exists() {
        std::fs::read_dir(&packs_dir)
            .map(|entries| entries.filter_map(|e| e.ok()).filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false)).count())
            .unwrap_or(0)
    } else {
        0
    };
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "rescanned": true,
            "pack_count": pack_count,
            "message": "Packs directory rescanned"
        }
    }))
}

// Entity Explorer (Pro) - TODO
async fn run_entities_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Tier gate: Entity Explorer requires Pro
    if !resolve_current_tier().has_access(services::types::ProductTier::Pro) {
        return Err(feature_locked_403("Entity Explorer", services::types::ProductTier::Pro));
    }
    
    // Use canonical helper to open run DB
    let handle = match services::run_control::open_run_db(&state.db, &run_id) {
        Ok(h) => h,
        Err(e) => {
            // If DB missing, return available: false with reason code
            if e.code == services::run_control::RunDbErrorCode::MissingDb {
                return Ok(Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "available": false,
                        "reason": "MISSING_DB",
                        "reason_message": e.message,
                        "run_id": run_id,
                        "entities": []
                    }
                })));
            }
            return Ok(Json(e.to_json()));
        }
    };
    
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "available": true,
            "run_id": run_id,
            "entities": [],
            "total": 0
        }
    })))
}

async fn run_pivot_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Tier gate: Pivot requires Pro
    if !resolve_current_tier().has_access(services::types::ProductTier::Pro) {
        return Err(feature_locked_403("Entity Pivot", services::types::ProductTier::Pro));
    }
    
    // Use canonical helper to open run DB
    let handle = match services::run_control::open_run_db(&state.db, &run_id) {
        Ok(h) => h,
        Err(e) => {
            // If DB missing, return available: false with reason code
            if e.code == services::run_control::RunDbErrorCode::MissingDb {
                return Ok(Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "available": false,
                        "reason": "MISSING_DB",
                        "reason_message": e.message,
                        "run_id": run_id
                    }
                })));
            }
            return Ok(Json(e.to_json()));
        }
    };
    
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "available": true,
            "run_id": run_id,
            "findings": [],
            "changes": [],
            "timeline": []
        }
    })))
}

async fn export_case_pack_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> Result<axum::response::Response, (StatusCode, Json<serde_json::Value>)> {
    use axum::response::IntoResponse;
    
    // Tier gate: Case Pack Export requires Pro
    if !resolve_current_tier().has_access(services::types::ProductTier::Pro) {
        let (status, json) = feature_locked_403("Case Pack Export", services::types::ProductTier::Pro);
        return Err((status, json));
    }
    
    // Use canonical helper to resolve run_dir from DB
    let (run_dir, _) = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok(r) => r,
        Err(e) => {
            let code = match e.code {
                services::run_control::RunDbErrorCode::RunNotFound => StatusCode::NOT_FOUND,
                services::run_control::RunDbErrorCode::MissingRunDir => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return Err((code, Json(e.to_json())));
        }
    };
    
    // Create a simple ZIP with case summary
    let mut zip_buffer = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut zip_buffer);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        
        let manifest = serde_json::json!({
            "contract_version": "1.0.0",
            "run_id": run_id,
            "created_at": chrono::Utc::now().to_rfc3339()
        });
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap_or_default();
        let _ = zip.start_file("manifest.json", options);
        let _ = std::io::Write::write_all(&mut zip, manifest_json.as_bytes());
        let _ = zip.finish();
    }
    
    let filename = format!("case_pack_{}_{}.zip", run_id, chrono::Utc::now().format("%Y%m%d_%H%M%S"));
    
    Ok((
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/zip"),
            (axum::http::header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}\"", filename)),
        ],
        zip_buffer
    ).into_response())
}

// Signals handlers
async fn signals_handler(
    State(state): State<SharedState>,
    Query(query): Query<services::types::SignalsQuery>,
) -> Json<serde_json::Value> {
    let run_id = match query.run_id {
        Some(id) => id,
        None => return Json(serde_json::json!({
            "success": false,
            "error": "run_id query parameter required",
            "code": "MISSING_PARAM"
        })),
    };
    
    // Try DB first, fall back to filesystem path (for runs discovered via scan)
    let db_path = match services::run_control::open_run_db(&state.db, &run_id) {
        Ok(h) => h.db_path,
        Err(e) => {
            // Fallback: construct path from data_dir
            let fallback_path = state.data_dir.join("runs").join(&run_id).join("workbench.db");
            if fallback_path.exists() {
                fallback_path
            } else if e.code == services::run_control::RunDbErrorCode::MissingDb {
                return Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "signals": [],
                        "run_id": run_id,
                        "available": false,
                        "reason_code": "MISSING_DB",
                        "cursor": null
                    }
                }));
            } else {
                return Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "signals": [],
                        "run_id": run_id,
                        "available": false,
                        "reason_code": "RUN_NOT_FOUND",
                        "cursor": null
                    }
                }));
            }
        }
    };
    
    match services::signals::query_signals(&db_path, query.since_ts_ms, 100) {
        Ok((signals, next_since_ts_ms)) => {
            Json(serde_json::json!({
                "success": true,
                "data": {
                    "signals": signals,
                    "run_id": run_id,
                    "available": true,
                    "next_since_ts_ms": next_since_ts_ms
                }
            }))
        }
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "DB_ERROR"
        })),
    }
}

async fn get_signal_handler(
    State(state): State<SharedState>,
    Path(signal_id): Path<String>,
    Query(query): Query<services::types::SignalsQuery>,
) -> Json<serde_json::Value> {
    let run_id = match query.run_id {
        Some(id) => id,
        None => return Json(serde_json::json!({
            "success": false,
            "error": "run_id query parameter required",
            "code": "MISSING_PARAM"
        })),
    };
    
    let db_path = state.data_dir.join("runs").join(&run_id).join("workbench.db");
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Run '{}' not found", run_id),
            "code": "RUN_NOT_FOUND"
        }));
    }
    
    match services::signals::get_signal(&db_path, &signal_id) {
        Ok(Some(signal)) => Json(serde_json::json!({
            "success": true,
            "data": signal
        })),
        Ok(None) => Json(serde_json::json!({
            "success": false,
            "error": format!("Signal '{}' not found", signal_id),
            "code": "SIGNAL_NOT_FOUND"
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "DB_ERROR"
        })),
    }
}

async fn signal_explain_handler(
    State(state): State<SharedState>,
    Path(signal_id): Path<String>,
    Query(query): Query<services::types::SignalsQuery>,
) -> Json<serde_json::Value> {
    let run_id = match query.run_id {
        Some(id) => id,
        None => return Json(serde_json::json!({
            "success": false,
            "error": "run_id query parameter required",
            "code": "MISSING_PARAM"
        })),
    };
    
    let db_path = state.data_dir.join("runs").join(&run_id).join("workbench.db");
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Run '{}' not found", run_id),
            "code": "RUN_NOT_FOUND"
        }));
    }
    
    match services::signals::get_signal_explanation(&db_path, &signal_id) {
        Ok(explanation_data) => Json(serde_json::json!({
            "success": true,
            "data": explanation_data
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "DB_ERROR"
        })),
    }
}

async fn signal_stats_handler(
    State(state): State<SharedState>,
    Query(query): Query<services::types::SignalsQuery>,
) -> Json<serde_json::Value> {
    let run_id = match query.run_id {
        Some(id) => id,
        None => return Json(serde_json::json!({
            "success": true,
            "data": { "total": 0, "by_type": {}, "by_severity": {} }
        })),
    };
    
    let db_path = state.data_dir.join("runs").join(&run_id).join("workbench.db");
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": true,
            "data": { "total": 0, "by_type": {}, "by_severity": {} }
        }));
    }
    
    match services::signals::get_signal_stats(&db_path) {
        Ok(stats) => Json(serde_json::json!({
            "success": true,
            "data": stats
        })),
        Err(_) => Json(serde_json::json!({
            "success": true,
            "data": { "total": 0, "by_type": {}, "by_severity": {} }
        })),
    }
}

async fn explainability_stats_handler(
    State(state): State<SharedState>,
    Query(query): Query<services::types::SignalsQuery>,
) -> Json<serde_json::Value> {
    let run_id = match query.run_id {
        Some(id) => id,
        None => return Json(serde_json::json!({
            "success": false,
            "error": "run_id query parameter is required",
            "code": "MISSING_RUN_ID"
        })),
    };
    
    let db_path = state.data_dir.join("runs").join(&run_id).join("workbench.db");
    if !db_path.exists() {
        return Json(serde_json::json!({
            "success": true,
            "data": {
                "total_signals": 0,
                "explanations_available": 0,
                "explanations_unavailable": 0,
                "availability_rate": 0.0,
                "unavailable_by_reason": {}
            }
        }));
    }
    
    match services::signals::get_explainability_stats(&db_path) {
        Ok(stats) => Json(serde_json::json!({
            "success": true,
            "data": stats
        })),
        Err(_) => Json(serde_json::json!({
            "success": true,
            "data": {
                "total_signals": 0,
                "explanations_available": 0,
                "explanations_unavailable": 0,
                "availability_rate": 0.0,
                "unavailable_by_reason": {}
            }
        })),
    }
}

// App state - TODO
async fn app_state_handler() -> Json<serde_json::Value> {
    let tier = resolve_current_tier();
    let is_admin = is_elevated();
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "tier": tier.display_name(),
            "is_admin": is_admin,
            "version": env!("CARGO_PKG_VERSION"),
            "binary": "locint"
        }
    }))
}

async fn restart_admin_handler() -> Json<serde_json::Value> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(exe_path) = std::env::current_exe() {
            use std::os::windows::process::CommandExt;
            let mut cmd = std::process::Command::new("powershell");
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
            cmd.args([
                "-Command",
                &format!("Start-Process -FilePath '{}' -Verb RunAs", exe_path.display())
            ]);
            
            if cmd.spawn().is_ok() {
                return Json(serde_json::json!({
                    "success": true,
                    "data": {
                        "restarting": true,
                        "message": "Restarting as Administrator"
                    }
                }));
            }
        }
    }
    
    Json(serde_json::json!({
        "success": false,
        "error": "Failed to restart as Administrator",
        "code": "RESTART_FAILED"
    }))
}

// Selfcheck - TODO
async fn selfcheck_handler() -> Json<serde_json::Value> {
    let status = services::capability::get_capability_status();
    
    Json(serde_json::json!({
        "success": true,
        "data": status
    }))
}

// Capability - TODO
async fn capability_status_handler(
    State(_state): State<SharedState>,
) -> Json<serde_json::Value> {
    let status = services::capability::get_capability_status();
    
    Json(serde_json::json!({
        "success": true,
        "data": status
    }))
}

async fn capability_detection_plan_handler(
    State(_state): State<SharedState>,
) -> Json<serde_json::Value> {
    let status = services::capability::get_capability_status();
    let (playbooks_dir, _, _) = services::run_control::discover_playbooks_dir();
    let detection_plan = services::capability::get_detection_plan(playbooks_dir.as_deref());
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "capability": status,
            "detection_plan": detection_plan
        }
    }))
}

async fn capability_gaps_handler(
    State(_state): State<SharedState>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let status = services::capability::get_capability_status();
    
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "capability": status,
            "gaps": [],
            "recommendations": []
        }
    })))
}

// ============================================================================
// MICRO CHAINS - Canonical backend source of truth
// ============================================================================

/// GET /api/chains - List all chain definitions
async fn chains_list_handler() -> Json<serde_json::Value> {
    let chains = services::chains::get_all_chains();
    
    // Convert to JSON-friendly format
    let chains_json: Vec<serde_json::Value> = chains.iter().map(|c| {
        serde_json::json!({
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "icon": c.icon,
            "category": c.category,
            "steps": c.steps.iter().map(|s| serde_json::json!({
                "id": s.id,
                "title": s.title,
                "description": s.description,
                "icon": s.icon
            })).collect::<Vec<_>>(),
            "match_rules": {
                "include_patterns": c.match_rules.include_patterns,
                "include_ids": c.match_rules.include_ids,
                "exclude_patterns": c.match_rules.exclude_patterns
            },
            "requirements": c.requirements
        })
    }).collect();
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "chains": chains_json,
            "count": chains.len()
        }
    }))
}

/// POST /api/chains/compile - Compile chain stack to playbook selections
/// Body: { "chain_ids": ["process-injection", "credential-dump"], "preset_id": null }
async fn chains_compile_handler(
    Json(req): Json<services::chains::CompileRequest>,
) -> Json<serde_json::Value> {
    // Get playbook catalog for pattern matching
    let playbooks = get_playbook_catalog_for_chains();
    
    // Compile chain stack
    let result = services::chains::compile_chain_stack(&req.chain_ids, &playbooks);
    
    // Convert to JSON format expected by frontend
    let chains_json: Vec<serde_json::Value> = result.baseline.chains.iter().map(|c| {
        let step_to_playbooks: HashMap<String, serde_json::Value> = c.step_to_playbooks.iter()
            .map(|(k, v)| (k.clone(), serde_json::json!({
                "stepId": v.step_id,
                "chainId": v.chain_id,
                "title": v.title,
                "icon": v.icon,
                "description": v.description,
                "playbookIds": v.playbook_ids
            })))
            .collect();
        
        serde_json::json!({
            "chainId": c.chain_id,
            "title": c.title,
            "icon": c.icon,
            "steps": c.steps.iter().map(|s| serde_json::json!({
                "id": s.id,
                "title": s.title,
                "description": s.description,
                "icon": s.icon
            })).collect::<Vec<_>>(),
            "compiledPlaybookIds": c.compiled_playbook_ids,
            "stepToPlaybooks": step_to_playbooks
        })
    }).collect();
    
    Json(serde_json::json!({
        "success": result.success,
        "baseline": {
            "type": result.baseline.baseline_type,
            "chains": chains_json,
            "baselinePlaybookIds": result.baseline.baseline_playbook_ids
        },
        "errors": result.errors
    }))
}

/// Helper: Get playbook catalog in format needed for chain compilation
fn get_playbook_catalog_for_chains() -> Vec<services::chains::PlaybookInfo> {
    let (playbooks_dir, _, _) = services::run_control::discover_playbooks_dir();
    
    if playbooks_dir.is_none() {
        return Vec::new();
    }
    
    let pb_dir = playbooks_dir.unwrap();
    let windows_dir = pb_dir.join("windows");
    let target_dir = if windows_dir.exists() { windows_dir } else { pb_dir.clone() };
    
    let mut playbooks: Vec<services::chains::PlaybookInfo> = Vec::new();
    
    // Scan playbooks directory
    if let Ok(entries) = std::fs::read_dir(&target_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                continue;
            }
            
            let playbook_id = path.file_stem()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            
            // Parse YAML to extract metadata
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                    let title = yaml.get("name")
                        .or_else(|| yaml.get("title"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(&playbook_id)
                        .to_string();
                    
                    let category = yaml.get("family")
                        .or_else(|| yaml.get("category"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    
                    let family = yaml.get("family")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    
                    playbooks.push(services::chains::PlaybookInfo {
                        playbook_id,
                        title,
                        category,
                        family,
                    });
                }
            }
        }
    }
    
    playbooks
}

// ============================================================================
// RUN STEP STATUS - Backend-canonical satisfaction tracking
// ============================================================================

/// GET /api/runs/:run_id/step_status
/// Computes step satisfaction for a chain stack based on actual run evidence.
/// This is the canonical source of truth - frontend must NOT duplicate this logic.
///
/// Query params:
/// - chain_ids: comma-separated list of chain IDs (required)
///
/// Response:
/// {
///   "success": bool,
///   "run_id": string,
///   "chains": [{ chain_id, title, steps: [{ step_id, state, evidence_refs_count, ... }] }],
///   "is_live": bool,  // true if run is still capturing
///   "generated_at": string
/// }
async fn run_step_status_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    // Parse chain_ids from query params
    let chain_ids: Vec<String> = params.get("chain_ids")
        .map(|s| s.split(',').map(|id| id.trim().to_string()).filter(|id| !id.is_empty()).collect())
        .unwrap_or_default();
    
    if chain_ids.is_empty() {
        return Json(serde_json::json!({
            "success": false,
            "error": "chain_ids query parameter required",
            "hint": "Usage: /api/runs/:run_id/step_status?chain_ids=process-injection,credential-dump"
        }));
    }
    
    // Check if run exists and get run_dir
    let (run_dir, run_record) = match services::run_control::resolve_run_dir(&state.db, &run_id) {
        Ok(r) => r,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": e.message,
                "code": format!("{:?}", e.code)
            }));
        }
    };
    
    // Determine if run is live (still capturing)
    let is_live = run_record.status == "capturing" || run_record.status == "active";
    
    // Open workbench DB
    let workbench_db_path = run_dir.join("workbench.db");
    let workbench_conn = match rusqlite::Connection::open(&workbench_db_path) {
        Ok(c) => c,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to open workbench DB: {}", e),
                "is_live": is_live
            }));
        }
    };
    
    // Query signals from workbench DB
    let signals = query_run_signals_for_step_status(&workbench_conn);
    
    // Get capability snapshot from run facts
    let capability = get_capability_snapshot_from_run(&workbench_conn);
    
    // Get playbook catalog
    let playbooks = get_playbook_catalog_for_chains();
    
    // Compute step status using canonical backend logic
    let chain_statuses = services::chains::compute_step_status(
        &chain_ids,
        &signals,
        &capability,
        &playbooks,
    );
    
    // Convert to JSON response
    let chains_json: Vec<serde_json::Value> = chain_statuses.iter().map(|cs| {
        let steps_json: Vec<serde_json::Value> = cs.steps.iter().map(|ss| {
            serde_json::json!({
                "step_id": ss.step_id,
                "title": ss.title,
                "icon": ss.icon,
                "state": ss.state.as_str(),
                "evidence_refs_count": ss.evidence_refs_count,
                "matched_playbooks": ss.matched_playbooks,
                "matched_signals": ss.matched_signals.iter().map(|sm| serde_json::json!({
                    "signal_id": sm.signal_id,
                    "playbook_id": sm.playbook_id,
                    "severity": sm.severity,
                    "evidence_count": sm.evidence_count
                })).collect::<Vec<_>>(),
                "why": ss.why,
                "coverage_gaps": ss.coverage_gaps
            })
        }).collect();
        
        serde_json::json!({
            "chain_id": cs.chain_id,
            "title": cs.title,
            "icon": cs.icon,
            "steps": steps_json
        })
    }).collect();
    
    Json(serde_json::json!({
        "success": true,
        "run_id": run_id,
        "chains": chains_json,
        "is_live": is_live,
        "generated_at": chrono::Utc::now().to_rfc3339()
    }))
}

/// Query signals from workbench DB for step status computation
fn query_run_signals_for_step_status(conn: &rusqlite::Connection) -> Vec<services::chains::RunSignal> {
    let mut signals: Vec<services::chains::RunSignal> = Vec::new();
    
    let query = r#"
        SELECT 
            signal_id,
            signal_type,
            severity,
            evidence_ptrs
        FROM signals
        ORDER BY timestamp DESC
    "#;
    
    let result: Result<Vec<_>, _> = conn.prepare(query)
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                let signal_id: String = row.get(0)?;
                let signal_type: String = row.get(1)?;
                let severity: String = row.get(2)?;
                let evidence_ptrs_json: Option<String> = row.get(3)?;
                
                Ok((signal_id, signal_type, severity, evidence_ptrs_json))
            })?.collect()
        });
    
    if let Ok(rows) = result {
        for (signal_id, signal_type, severity, evidence_ptrs_json) in rows {
            // Extract playbook_id from signal_type (format: "playbook:xxx")
            let playbook_id = signal_type
                .strip_prefix("playbook:")
                .unwrap_or(&signal_type)
                .to_string();
            
            // Parse evidence_ptrs JSON
            let evidence_refs: Vec<serde_json::Value> = evidence_ptrs_json
                .and_then(|json| serde_json::from_str(&json).ok())
                .unwrap_or_default();
            
            signals.push(services::chains::RunSignal {
                signal_id,
                signal_type,
                playbook_id,
                severity,
                evidence_refs,
            });
        }
    }
    
    signals
}

/// Get capability snapshot from run facts
fn get_capability_snapshot_from_run(conn: &rusqlite::Connection) -> services::chains::CapabilitySnapshot {
    let mut snapshot = services::chains::CapabilitySnapshot::default();
    
    // Query facts table for capability information
    let query = r#"
        SELECT fact_type, fact_value FROM facts
        WHERE fact_type IN ('sysmon_installed', 'is_admin', 'security_log_accessible', 'channel_status')
    "#;
    
    let result: Result<Vec<_>, _> = conn.prepare(query)
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                let fact_type: String = row.get(0)?;
                let fact_value: String = row.get(1)?;
                Ok((fact_type, fact_value))
            })?.collect()
        });
    
    if let Ok(facts) = result {
        for (fact_type, fact_value) in facts {
            match fact_type.as_str() {
                "sysmon_installed" => {
                    snapshot.sysmon_installed = fact_value.to_lowercase() == "true" 
                        || fact_value == "1" 
                        || fact_value.to_lowercase() == "yes";
                }
                "is_admin" => {
                    snapshot.is_admin = fact_value.to_lowercase() == "true" 
                        || fact_value == "1" 
                        || fact_value.to_lowercase() == "yes";
                }
                "security_log_accessible" => {
                    snapshot.security_log_accessible = fact_value.to_lowercase() == "true" 
                        || fact_value == "1" 
                        || fact_value.to_lowercase() == "yes";
                }
                "channel_status" => {
                    // Parse channel status JSON
                    if let Ok(channels) = serde_json::from_str::<HashMap<String, bool>>(&fact_value) {
                        snapshot.channels = channels;
                    }
                }
                _ => {}
            }
        }
    }
    
    // Fallback: Try to infer from event sources if facts not available
    if !snapshot.sysmon_installed {
        // Check if any Sysmon events exist
        let sysmon_check = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE provider_name LIKE '%Sysmon%' LIMIT 1",
            [],
            |row| row.get::<_, i64>(0)
        );
        if let Ok(count) = sysmon_check {
            snapshot.sysmon_installed = count > 0;
        }
    }
    
    snapshot
}

// Features - TODO
async fn features_handler() -> Json<serde_json::Value> {
    let tier = resolve_current_tier();
    let features = services::meta::get_feature_flags(tier);
    
    Json(serde_json::json!({
        "success": true,
        "data": features
    }))
}

async fn capture_profiles_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "success": true,
        "data": {
            "profiles": [
                {
                    "id": "extended",
                    "name": "Extended",
                    "description": "Full telemetry capture",
                    "default": true
                },
                {
                    "id": "minimal",
                    "name": "Minimal",
                    "description": "Reduced telemetry capture",
                    "default": false
                }
            ]
        }
    }))
}

// Export/Import - TODO
#[derive(serde::Deserialize)]
struct ExportBundleRequest {
    run_id: String,
    include_segments: Option<bool>,
}

async fn export_bundle_handler(
    State(state): State<SharedState>,
    Json(body): Json<ExportBundleRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<serde_json::Value>)> {
    use axum::response::IntoResponse;
    
    // Use canonical helper to resolve run_dir from DB
    let (run_dir, _) = match services::run_control::resolve_run_dir(&state.db, &body.run_id) {
        Ok(r) => r,
        Err(e) => {
            let code = match e.code {
                services::run_control::RunDbErrorCode::RunNotFound => StatusCode::NOT_FOUND,
                services::run_control::RunDbErrorCode::MissingRunDir => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return Err((code, Json(e.to_json())));
        }
    };
    
    let include_segments = body.include_segments.unwrap_or(true);
    
    match services::export_import::create_run_bundle(&run_dir, &body.run_id, include_segments) {
        Ok(zip_data) => {
            let filename = format!("bundle_{}_{}.zip", body.run_id, chrono::Utc::now().format("%Y%m%d_%H%M%S"));
            Ok((
                StatusCode::OK,
                [
                    (axum::http::header::CONTENT_TYPE, "application/zip"),
                    (axum::http::header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}\"", filename)),
                ],
                zip_data
            ).into_response())
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "EXPORT_FAILED"
        })))),
    }
}

async fn import_bundle_handler(
    State(state): State<SharedState>,
    mut multipart: axum::extract::Multipart,
) -> Json<serde_json::Value> {
    // Read the uploaded ZIP file
    let mut zip_data: Option<Vec<u8>> = None;
    
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") || field.name() == Some("bundle") {
            if let Ok(bytes) = field.bytes().await {
                zip_data = Some(bytes.to_vec());
                break;
            }
        }
    }
    
    let zip_data = match zip_data {
        Some(d) => d,
        None => return Json(serde_json::json!({
            "success": false,
            "error": "No file uploaded",
            "code": "NO_FILE"
        })),
    };
    
    match services::export_import::import_bundle(&zip_data, &state.data_dir, None) {
        Ok(result) => Json(serde_json::json!({
            "success": true,
            "data": {
                "run_id": result.run_id,
                "run_dir": result.run_dir,
                "files_extracted": result.files_extracted,
                "bytes_written": result.bytes_written
            }
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "IMPORT_FAILED"
        })),
    }
}

async fn import_validate_handler(
    State(_state): State<SharedState>,
    mut multipart: axum::extract::Multipart,
) -> Json<serde_json::Value> {
    // Read the uploaded ZIP file
    let mut zip_data: Option<Vec<u8>> = None;
    
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") || field.name() == Some("bundle") {
            if let Ok(bytes) = field.bytes().await {
                zip_data = Some(bytes.to_vec());
                break;
            }
        }
    }
    
    let zip_data = match zip_data {
        Some(d) => d,
        None => return Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": "NO_FILE_UPLOADED",
                "missing_artifacts": ["bundle file"]
            }
        })),
    };
    
    let validation = services::export_import::validate_bundle(&zip_data);
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "available": validation.available,
            "reason_code": validation.reason_code,
            "missing_artifacts": validation.missing_artifacts,
            "found_artifacts": validation.found_artifacts,
            "schema_version": validation.schema_version,
            "suggested_fix": validation.suggested_fix,
            "can_compile": validation.can_compile,
            "can_diff": validation.can_diff,
            "can_case_summary": validation.can_case_summary,
            "evidence_deref_available": validation.evidence_deref_available,
            "segment_count": validation.segment_count,
            "has_workbench_db": validation.has_workbench_db
        }
    }))
}

// Evidence handler
async fn evidence_deref_handler(
    State(state): State<SharedState>,
    Query(query): Query<services::types::EvidenceDerefQuery>,
) -> Json<serde_json::Value> {
    use services::types::EvidenceDerefReasonCode;
    
    // Validate required fields
    let run_id = match &query.run_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => return Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": EvidenceDerefReasonCode::MissingRunId,
                "message": "Missing required field: run_id",
                "evidence_ptr": { "run_id": query.run_id }
            }
        })),
    };
    
    let segment_id = match &query.segment_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => return Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": EvidenceDerefReasonCode::MissingSegmentId,
                "message": "Missing required field: segment_id",
                "evidence_ptr": { "run_id": run_id }
            }
        })),
    };
    
    let offset = query.offset.unwrap_or(0);
    let context_lines = query.context_lines.unwrap_or(0);
    
    // Build evidence_ptr echo
    let evidence_ptr = serde_json::json!({
        "run_id": run_id,
        "segment_id": segment_id,
        "offset": offset
    });
    
    // Delegate to service
    let result = services::evidence::dereference_evidence(
        &state.data_dir,
        &run_id,
        &segment_id,
        offset,
        context_lines,
    );
    
    if result.success {
        Json(serde_json::json!({
            "success": true,
            "data": {
                "available": true,
                "evidence_ptr": evidence_ptr,
                "resolved": {
                    "record": result.record,
                    "context": result.context,
                    "segment_info": result.segment_info.map(|s| serde_json::json!({
                        "segment_id": s.segment_id,
                        "total_lines": s.total_lines,
                        "file_size": s.file_size
                    }))
                }
            }
        }))
    } else {
        Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": result.reason_code,
                "message": result.message,
                "evidence_ptr": evidence_ptr
            }
        }))
    }
}

// Dataflow snapshot (Dev) - debug endpoint for dataflow diagnosis
async fn dataflow_snapshot_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    // Check debug flag (allow in dev, require ?debug=1 in release)
    let debug_enabled = cfg!(debug_assertions) || params.get("debug").map(|v| v == "1").unwrap_or(false);
    
    if !debug_enabled {
        return Json(serde_json::json!({
            "success": false,
            "error": "Debug endpoint requires ?debug=1 query parameter",
            "code": "DEBUG_REQUIRED"
        }));
    }
    
    // Get instance identity
    let identity = state.flight_recorder.get_identity().unwrap_or_else(|| {
        InstanceIdentity {
            pid: std::process::id(),
            port: state.port,
            is_admin: is_elevated(),
            exe_path: std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default(),
            api_base: format!("http://127.0.0.1:{}/api", state.port),
            ui_origin: format!("http://127.0.0.1:{}/ui/", state.port),
            data_dir: state.data_dir.display().to_string(),
            started_at: "unknown".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    });
    
    // Get active run info from supervisor
    let status = state.supervisor.status().await;
    let active_run = if status.running || status.run_id.is_some() {
        Some(serde_json::json!({
            "run_id": status.run_id.clone().unwrap_or_default(),
            "run_dir": status.run_dir.clone().unwrap_or_default(),
            "phase": status.phase,
            "started_at": status.started_at.clone().unwrap_or_default(),
            "elapsed_seconds": status.elapsed_seconds.unwrap_or(0)
        }))
    } else {
        None
    };
    
    // Get paths
    let run_dir = state.supervisor.current_run_dir().await;
    let db_path = run_dir.as_ref().map(|d| d.join("workbench.db"));
    let segments_path = run_dir.as_ref().map(|d| d.join("segments"));
    let logs_path = run_dir.as_ref().map(|d| d.join("logs"));
    
    let paths = serde_json::json!({
        "data_dir": state.data_dir.display().to_string(),
        "db_path_for_live_queries": db_path.as_ref().map(|p| p.display().to_string()),
        "segments_path": segments_path.as_ref().map(|p| p.display().to_string()),
        "logs_path": logs_path.as_ref().map(|p| p.display().to_string()),
        "flight_log": state.flight_recorder.file_path().display().to_string()
    });
    
    // Get spawn status
    let (capture_pid, locald_pid) = state.supervisor.get_pids().await;
    let spawn_status = serde_json::json!({
        "capture_running": status.capture_running,
        "capture_pid": capture_pid,
        "locald_running": status.locald_running,
        "locald_pid": locald_pid
    });
    
    // Get recent events
    let recent_events = state.flight_recorder.recent_events(20);
    
    Json(serde_json::json!({
        "success": true,
        "data": {
            "instance": identity,
            "active_run": active_run,
            "paths": paths,
            "spawn_status": spawn_status,
            "recent_events": recent_events,
            "snapshot_ts": chrono::Utc::now().to_rfc3339()
        }
    }))
}

// Team handlers (Team tier) - TODO
async fn team_store_status_handler(
    State(state): State<SharedState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Team tier gate
    if !resolve_current_tier().has_access(services::types::ProductTier::Team) {
        return Err(feature_locked_403("Case Store", services::types::ProductTier::Team));
    }
    
    let status = edr_server::team::store::get_store_status(&state.data_dir);
    
    Ok(Json(serde_json::json!({
        "success": true,
        "data": status
    })))
}

#[derive(serde::Deserialize)]
struct ConfigureStoreRequest {
    case_store_dir: String,
}

async fn team_store_configure_handler(
    State(state): State<SharedState>,
    Json(req): Json<ConfigureStoreRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Team tier gate
    if !resolve_current_tier().has_access(services::types::ProductTier::Team) {
        return Err(feature_locked_403("Case Store", services::types::ProductTier::Team));
    }
    
    match edr_server::team::store::configure_store(&state.data_dir, &req.case_store_dir) {
        Ok(result) => Ok(Json(serde_json::json!({
            "success": true,
            "data": result
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "CONFIGURE_FAILED"
        }))),
    }
}

async fn team_list_cases_handler(
    State(state): State<SharedState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Team tier gate
    if !resolve_current_tier().has_access(services::types::ProductTier::Team) {
        return Err(feature_locked_403("Case Store", services::types::ProductTier::Team));
    }
    
    let store_dir = match edr_server::team::store::get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Case store not configured",
            "code": "STORE_NOT_CONFIGURED"
        }))),
    };
    
    match edr_server::team::cases::list_cases(&store_dir) {
        Ok(cases) => {
            let count = cases.len();
            Ok(Json(serde_json::json!({
                "success": true,
                "data": {
                    "cases": cases,
                    "count": count
                }
            })))
        }
        Err(e) => Ok(Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "LIST_FAILED"
        }))),
    }
}

#[derive(serde::Deserialize)]
struct CreateCaseRequest {
    name: String,
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

async fn team_create_case_handler(
    State(state): State<SharedState>,
    Json(req): Json<CreateCaseRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Team tier gate
    if !resolve_current_tier().has_access(services::types::ProductTier::Team) {
        return Err(feature_locked_403("Case Store", services::types::ProductTier::Team));
    }
    
    let store_dir = match edr_server::team::store::get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Case store not configured",
            "code": "STORE_NOT_CONFIGURED"
        }))),
    };
    
    // Get install ID from flight recorder or generate one
    let install_id = state.flight_recorder.get_identity()
        .map(|i| format!("{}:{}", i.pid, i.port))
        .unwrap_or_else(|| "unknown".to_string());
    
    match edr_server::team::cases::create_case(&store_dir, &req.name, req.description, req.tags, &install_id) {
        Ok(case_meta) => Ok(Json(serde_json::json!({
            "success": true,
            "data": case_meta
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "CREATE_FAILED"
        }))),
    }
}

async fn team_get_case_handler(
    State(state): State<SharedState>,
    Path(case_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Team tier gate
    if !resolve_current_tier().has_access(services::types::ProductTier::Team) {
        return Err(feature_locked_403("Case Store", services::types::ProductTier::Team));
    }
    
    let store_dir = match edr_server::team::store::get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Case store not configured",
            "code": "STORE_NOT_CONFIGURED"
        }))),
    };
    
    let case_dir = match edr_server::team::cases::get_case_dir(&store_dir, &case_id) {
        Some(d) if d.exists() => d,
        _ => return Ok(Json(serde_json::json!({
            "success": false,
            "error": format!("Case not found: {}", case_id),
            "code": "CASE_NOT_FOUND"
        }))),
    };
    
    match edr_server::team::cases::read_case_meta(&case_dir) {
        Ok(case_meta) => Ok(Json(serde_json::json!({
            "success": true,
            "data": case_meta
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "READ_FAILED"
        }))),
    }
}

async fn team_case_aggregate_handler(
    State(state): State<SharedState>,
    Path(case_id): Path<String>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Team tier gate
    if !resolve_current_tier().has_access(services::types::ProductTier::Team) {
        return Err(feature_locked_403("Case Store", services::types::ProductTier::Team));
    }
    
    let store_dir = match edr_server::team::store::get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Case store not configured",
            "code": "STORE_NOT_CONFIGURED"
        }))),
    };
    
    // Compute basic aggregate: signal stats + entities
    let signal_stats = edr_server::team::aggregate::get_case_signal_stats(&store_dir, &case_id);
    let entities = edr_server::team::aggregate::get_case_entities(&store_dir, &case_id);
    
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "case_id": case_id,
            "signal_stats": signal_stats.ok(),
            "entities": entities.ok(),
            "cache_hit": false
        }
    })))
}

#[derive(serde::Deserialize)]
struct UpdateTagsRequest {
    tags: Vec<String>,
}

async fn team_update_tags_handler(
    State(state): State<SharedState>,
    Path(case_id): Path<String>,
    Json(req): Json<UpdateTagsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Team tier gate
    if !resolve_current_tier().has_access(services::types::ProductTier::Team) {
        return Err(feature_locked_403("Case Store", services::types::ProductTier::Team));
    }
    
    let store_dir = match edr_server::team::store::get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Case store not configured",
            "code": "STORE_NOT_CONFIGURED"
        }))),
    };
    
    let case_dir = match edr_server::team::cases::get_case_dir(&store_dir, &case_id) {
        Some(d) if d.exists() => d,
        _ => return Ok(Json(serde_json::json!({
            "success": false,
            "error": format!("Case not found: {}", case_id),
            "code": "CASE_NOT_FOUND"
        }))),
    };
    
    match edr_server::team::cases::add_tags(&case_dir, &req.tags) {
        Ok(updated_tags) => Ok(Json(serde_json::json!({
            "success": true,
            "data": {
                "tags": updated_tags
            }
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "UPDATE_FAILED"
        }))),
    }
}

#[derive(serde::Deserialize)]
struct AddNoteRequest {
    content: String,
    author: Option<String>,
}

async fn team_add_note_handler(
    State(state): State<SharedState>,
    Path(case_id): Path<String>,
    Json(req): Json<AddNoteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Team tier gate
    if !resolve_current_tier().has_access(services::types::ProductTier::Team) {
        return Err(feature_locked_403("Case Store", services::types::ProductTier::Team));
    }
    
    let store_dir = match edr_server::team::store::get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Case store not configured",
            "code": "STORE_NOT_CONFIGURED"
        }))),
    };
    
    let case_dir = match edr_server::team::cases::get_case_dir(&store_dir, &case_id) {
        Some(d) if d.exists() => d,
        _ => return Ok(Json(serde_json::json!({
            "success": false,
            "error": format!("Case not found: {}", case_id),
            "code": "CASE_NOT_FOUND"
        }))),
    };
    
    let author = req.author.as_deref().unwrap_or("unknown");
    
    match edr_server::team::cases::add_note(&case_dir, &req.content, author, None) {
        Ok(note) => Ok(Json(serde_json::json!({
            "success": true,
            "data": note
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "NOTE_FAILED"
        }))),
    }
}

#[derive(serde::Deserialize)]
struct PublishRunRequest {
    run_id: String,
}

async fn team_publish_run_handler(
    State(state): State<SharedState>,
    Path(case_id): Path<String>,
    Json(req): Json<PublishRunRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Team tier gate
    if !resolve_current_tier().has_access(services::types::ProductTier::Team) {
        return Err(feature_locked_403("Case Store", services::types::ProductTier::Team));
    }
    
    let store_dir = match edr_server::team::store::get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Case store not configured",
            "code": "STORE_NOT_CONFIGURED"
        }))),
    };
    
    // Use canonical helper to resolve run_dir from DB
    let (run_dir, _) = match services::run_control::resolve_run_dir(&state.db, &req.run_id) {
        Ok(r) => r,
        Err(e) => return Ok(Json(e.to_json())),
    };
    
    // Publish with all components: signals, segments, meta
    match edr_server::team::publish::publish_run_to_case(&store_dir, &case_id, &req.run_id, &run_dir, true, true, true) {
        Ok(published_run) => Ok(Json(serde_json::json!({
            "success": true,
            "data": published_run
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "PUBLISH_FAILED"
        }))),
    }
}

#[derive(serde::Deserialize)]
struct ImportRunFromCaseRequest {
    run_id: String,
}

async fn team_import_run_handler(
    State(state): State<SharedState>,
    Path(case_id): Path<String>,
    Json(req): Json<ImportRunFromCaseRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Team tier gate
    if !resolve_current_tier().has_access(services::types::ProductTier::Team) {
        return Err(feature_locked_403("Case Store", services::types::ProductTier::Team));
    }
    
    let store_dir = match edr_server::team::store::get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Case store not configured",
            "code": "STORE_NOT_CONFIGURED"
        }))),
    };
    
// Use export_published_run to get a ZIP and then extract it locally
    let bundle_data = match edr_server::team::publish::export_published_run(&store_dir, &case_id, &req.run_id) {
        Ok(data) => data,
        Err(e) => return Ok(Json(serde_json::json!({
            "success": false,
            "error": format!("Failed to export run from case: {}", e),
            "code": "EXPORT_FAILED"
        }))),
    };
    
    // Import the bundle to local runs
    match services::export_import::import_bundle(&bundle_data, &state.data_dir, Some(&req.run_id)) {
        Ok(result) => Ok(Json(serde_json::json!({
            "success": true,
            "data": {
                "run_id": result.run_id,
                "run_dir": result.run_dir,
                "files_extracted": result.files_extracted,
                "imported_from_case": case_id
            }
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "success": false,
            "error": e,
            "code": "IMPORT_FAILED"
        }))),
    }
}

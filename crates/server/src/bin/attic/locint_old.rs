//! LocInt - Local Incident Compiler
//!
//! Thin wrapper around edr-server for double-click desktop use.
//! 
//! **Differences from edr-server:**
//! - `#![windows_subsystem = "windows"]` - no console window
//! - Exe-relative path resolution for shipped layout
//! - Resource validation with MessageBox errors
//! - Auto-opens browser (no --no-open flag)
//! - Port conflict shown as MessageBox
//!
//! **Shared with edr-server:**
//! - All HTTP endpoints (same router)
//! - All handlers and business logic
//! - Run control and capture lifecycle
//!
//! Usage: Double-click locint.exe
//!
//! Shipped layout:
//! ```text
//! LocInt/
//!   locint.exe
//!   edr-locald.exe
//!   capture_windows_rotating.exe
//!   ui/
//!   playbooks/windows/
//! ```

// Hide console window on Windows release builds
#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

use edr_server::server_core::{ShippedResources, StartupError};
use edr_server::flight_recorder::{
    self, DataflowSnapshot, ActiveRunInfo, ResolvedPaths, SpawnStatus, DbTruth,
    InstanceIdentity, SharedFlightRecorder, SegmentsStatus,
};
use edr_server::instance_lock::{InstanceLock, LockResult, InstanceConflictError};

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
    // These override the default path resolution in run_control
    std::env::set_var("EDR_CAPTURE_BINARY", &resources.capture_binary);
    std::env::set_var("EDR_LOCALD_BINARY", &resources.locald_binary);
    std::env::set_var("EDR_PLAYBOOKS_DIR", &resources.playbooks_dir);
    std::env::set_var("EDR_UI_DIR", &resources.ui_dir);
    
    // Step 3: Build server config
    let port: u16 = std::env::var("EDR_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    
    let config = resources.to_server_config(port);
    
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
            
            // Try to open the existing instance's UI before showing error
            let ui_url = format!("{}ui/", existing.api_base.trim_end_matches("/api"));
            tracing::info!("Another instance detected at {}, attempting to open", ui_url);
            
            // Open existing UI in browser
            let _ = open::that(&ui_url);
            
            show_error(
                "Another Instance Running",
                &format!(
                    "{}\n\nExisting instance:\n  Port: {}\n  PID: {}\n  URL: {}\n\nOpening existing instance in browser...",
                    err.message, err.existing_port, err.existing_pid, 
                    ui_url
                ),
            );
            std::process::exit(0); // Clean exit (not error) since we opened existing
        }
        LockResult::Error(e) => {
            tracing::warn!("Failed to acquire instance lock: {}", e);
            // Continue without lock (fallback for edge cases)
            None
        }
    };
    
    // Step 6: Initialize logging to file (no console in GUI mode)
    let log_path = resources.exe_dir.join("locint.log");
    init_file_logging(&log_path);
    
    tracing::info!("LocInt starting...");
    tracing::info!("Exe dir: {:?}", resources.exe_dir);
    tracing::info!("UI dir: {:?}", config.ui_dir);
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
    use tower_http::cors::{Any, CorsLayer};
    
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
    
    // The database and app state are created the same way as edr-server
    // We delegate to the same internal setup by setting env vars and letting
    // the standard server code find them
    
    let db_path = config.data_dir.join("workbench.db");
    tracing::info!("Database: {:?}", db_path);
    
    // Bind to port first to catch "port in use" errors with good message
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
        StartupError::PortInUse {
            port: config.port,
            error: e.to_string(),
        }
    })?;
    
    // Build the minimal router for locint
    // This is a subset of edr-server routes focused on run control and UI
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    
    // For now, locint serves only the essential endpoints
    // The full router requires the complete AppState from main.rs
    // TODO: Extract full router builder to shared location
    let app = build_locint_router(&config, flight_recorder).layer(cors);
    
    let ui_url = format!("http://127.0.0.1:{}/ui/", config.port);
    
    // Auto-open browser
    tracing::info!("Opening browser: {}", ui_url);
    if let Err(e) = open::that(&ui_url) {
        tracing::warn!("Failed to open browser: {}. Navigate to {} manually.", e, ui_url);
    }
    
    tracing::info!("Server listening on {}", addr);
    
    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| StartupError::Other(format!("Server error: {}", e)))?;
    
    Ok(())
}

/// Build the locint router
/// 
/// IMPORTANT: This should match edr-server's router as closely as possible.
/// The full unification requires extracting main.rs handlers to a shared module.
fn build_locint_router(
    config: &edr_server::server_core::ServerConfig,
    flight_recorder: SharedFlightRecorder,
) -> axum::Router {
    use axum::{routing::get, Router};
    use tower_http::services::ServeDir;
    use std::sync::Arc;
    
    // Open database
    let db_path = config.data_dir.join("workbench.db");
    let db = edr_server::db::Database::open(&db_path)
        .expect("Failed to open database");
    
    // Create supervisor with flight recorder
    let supervisor = edr_server::supervisor::Supervisor::with_flight_recorder(
        config.data_dir.clone(),
        flight_recorder.clone(),
    );
    
    // Shared state with Supervisor for process management
    let state = Arc::new(LocintState {
        data_dir: config.data_dir.clone(),
        port: config.port,
        supervisor,
        db,
        flight_recorder,
    });
    
    Router::new()
        .route("/", get(|| async { axum::response::Redirect::to("/ui/") }))
        .route("/health", get(health_handler))
        .route("/api/health", get(health_handler))
        // Run control endpoints
        .route("/api/run/start", axum::routing::post(run_start_handler))
        .route("/api/run/stop", axum::routing::post(run_stop_handler))
        .route("/api/run/status", get(run_status_handler))
        .route("/api/run/metrics", get(run_metrics_handler))
        .route("/api/runs", get(list_runs_handler))
        .route("/api/runs/:run_id", get(get_run_handler))
        .route("/api/runs/:run_id/rename", axum::routing::post(rename_run_handler))
        .route("/api/runs/:run_id/delete", axum::routing::post(delete_run_handler))
        .route("/api/runs/:run_id/baseline", axum::routing::post(set_baseline_handler))
        .route("/api/runs/:run_id/coverage", get(run_coverage_handler))
        .route("/api/runs/:run_id/changes", get(run_changes_handler))
        .route("/api/runs/:run_id/diff", get(run_diff_v2_handler))
        .route("/api/runs/:run_id/playbooks", get(run_playbooks_handler))
        .route("/api/runs/:run_id/state", get(run_state_handler))
        .route("/api/runs/:run_id/next_steps", get(run_next_steps_handler))
        .route("/api/runs/:run_id/case_summary", get(case_summary_handler))
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
        // App control (admin restart)
        .route("/api/app/restart_admin", axum::routing::post(restart_admin_handler))
        // Selfcheck
        .route("/api/selfcheck", get(selfcheck_handler))
        // Capability Model endpoints (always-on sensor/detection visibility)
        .route("/api/capability/status", get(capability_status_handler))
        .route("/api/capability/detection_plan", get(capability_detection_plan_handler))
        .route("/api/capability/gaps", get(capability_gaps_handler))
        // Playbook catalog (Detection Plan)
        .route("/api/playbooks/catalog", get(playbooks_catalog_handler))
        // Feature flags and capture profiles (parity with edr-server)
        .route("/api/features", get(features_handler))
        .route("/api/capture/profiles", get(capture_profiles_handler))
        // Bundle export/import
        .route("/api/export/bundle", axum::routing::post(export_bundle_handler))
        .route("/api/import/bundle", axum::routing::post(import_bundle_handler))
        .route("/api/import/validate", axum::routing::post(import_validate_handler))
        // Content packs
        .route("/api/packs", get(list_packs_handler))
        .route("/api/packs/:pack_name", get(get_pack_handler))
        .route("/api/packs/rescan", axum::routing::post(rescan_packs_handler))
        // Evidence dereference
        .route("/api/evidence/deref", get(evidence_deref_handler))
        // Pro Entity Explorer (Pro tier only)
        .route("/api/runs/:run_id/entities", get(run_entities_handler))
        .route("/api/runs/:run_id/pivot", get(run_pivot_handler))
        .route("/api/runs/:run_id/export/case_pack", axum::routing::post(export_case_pack_handler))
        // Meta endpoints (UI Wiring Audit + Tier Features)
        .route("/api/meta/routes", get(meta_routes_handler))
        .route("/api/meta/contract", get(meta_contract_handler))
        .route("/api/meta/features", get(meta_features_handler))
        // Dataflow snapshot (debug, dev-only)
        .route("/api/meta/dataflow_snapshot", get(dataflow_snapshot_handler))
        // Team Case Store (Team tier only)
        .route("/api/team/store/status", get(team_store_status_handler))
        .route("/api/team/store/configure", axum::routing::post(team_store_configure_handler))
        .route("/api/team/cases", get(team_list_cases_handler))
        .route("/api/team/cases", axum::routing::post(team_create_case_handler))
        .route("/api/team/cases/:case_id", get(team_get_case_handler))
        .route("/api/team/cases/:case_id/aggregate", get(team_case_aggregate_handler))
        .route("/api/team/cases/:case_id/tags", axum::routing::post(team_update_tags_handler))
        .route("/api/team/cases/:case_id/notes", axum::routing::post(team_add_note_handler))
        .route("/api/team/cases/:case_id/publish_run", axum::routing::post(team_publish_run_handler))
        .route("/api/team/cases/:case_id/import_run", axum::routing::post(team_import_run_handler))
        // Debug endpoints (dev only)
        .route("/api/run/debug_counts", get(debug_counts_handler))
        // Static UI
        .nest_service("/ui", ServeDir::new(&config.ui_dir))
        .with_state(state)
}

// ============================================================================
// Route Registry for UI Wiring Audit
// ============================================================================

/// Returns authoritative list of all registered API routes.
/// This is the single source of truth for UI wiring checks.
fn get_registered_routes() -> Vec<RouteInfo> {
    vec![
        // Core health endpoints
        RouteInfo::new("GET", "/health", "Health check (root)", false),
        RouteInfo::new("GET", "/api/health", "Health check", false),
        
        // Run control (mutating)
        RouteInfo::new("POST", "/api/run/start", "Start capture run", true),
        RouteInfo::new("POST", "/api/run/stop", "Stop capture run", true),
        RouteInfo::new("GET", "/api/run/status", "Get current run status", false),
        RouteInfo::new("GET", "/api/run/metrics", "Get run metrics", false),
        
        // Runs listing
        RouteInfo::new("GET", "/api/runs", "List past runs", false),
        RouteInfo::new("GET", "/api/runs/:run_id", "Get single run details", false),
        RouteInfo::new("POST", "/api/runs/:run_id/rename", "Rename a run", false),
        RouteInfo::new("POST", "/api/runs/:run_id/delete", "Delete a run", false),
        RouteInfo::new("POST", "/api/runs/:run_id/baseline", "Set run as baseline", false),
        RouteInfo::new("GET", "/api/runs/:run_id/coverage", "Get run coverage/facts", false),
        RouteInfo::new("GET", "/api/runs/:run_id/changes", "Get run changes (diff)", false),
        RouteInfo::new("GET", "/api/runs/:run_id/diff", "Diff v2: baseline|phase|marker mode comparison", false),
        RouteInfo::new("GET", "/api/runs/:run_id/playbooks", "Get playbook status for run", false),
        RouteInfo::new("GET", "/api/runs/:run_id/state", "Get system state summary", false),
        RouteInfo::new("GET", "/api/runs/:run_id/next_steps", "Deterministic workflow guidance", false),
        RouteInfo::new("GET", "/api/runs/:run_id/case_summary", "Case summary JSON for export/report", false),
        
        // Baselines
        RouteInfo::new("GET", "/api/baselines", "List baseline runs", false),
        
        // Signals
        RouteInfo::new("GET", "/api/signals", "List signals (findings)", false),
        RouteInfo::new("GET", "/api/signals/stats", "Get signal statistics", false),
        RouteInfo::new("GET", "/api/signals/explainability_stats", "Explainability stats (run_id required)", false),
        RouteInfo::new("GET", "/api/signals/:id", "Get single signal", false),
        RouteInfo::new("GET", "/api/signals/:id/explain", "Get signal explanation", false),
        
        // App state
        RouteInfo::new("GET", "/api/app/state", "Get full app state", false),
        
        // App control
        RouteInfo::new("POST", "/api/app/restart_admin", "Restart as Administrator (UAC)", true),
        
        // Selfcheck
        RouteInfo::new("GET", "/api/selfcheck", "System readiness check", false),
        
        // Capability Model (always-on sensor/detection visibility)
        RouteInfo::new("GET", "/api/capability/status", "Sensor inventory and capability status", false),
        RouteInfo::new("GET", "/api/capability/detection_plan", "Detection plan with dependencies", false),
        RouteInfo::new("GET", "/api/capability/gaps", "Coverage gaps analysis (dev-only)", false),
        
        // Playbook catalog (Detection Plan)
        RouteInfo::new("GET", "/api/playbooks/catalog", "Get all playbook metadata (Detection Plan)", false),
        
        // Features
        RouteInfo::new("GET", "/api/features", "Get feature flags (legacy)", false),
        RouteInfo::new("GET", "/api/capture/profiles", "Get capture profiles", false),
        
        // Export/Import
        RouteInfo::new("POST", "/api/export/bundle", "Export bundle (requires run_id)", true),
        RouteInfo::new("POST", "/api/import/bundle", "Import bundle ZIP", true),
        RouteInfo::new("POST", "/api/import/validate", "Validate import bundle before import", true),
        
        // Content Packs (Pro tier)
        RouteInfo::new("GET", "/api/packs", "List available content packs", false),
        RouteInfo::new("GET", "/api/packs/:pack_name", "Get content pack details", false),
        
        // Evidence dereference
        RouteInfo::new("GET", "/api/evidence/deref", "Dereference evidence pointer to source record", false),
        
        // Meta (wiring audit + tier features)
        RouteInfo::new("GET", "/api/meta/routes", "List all routes (this endpoint)", false),
        RouteInfo::new("GET", "/api/meta/contract", "API contract/wrapper spec", false),
        RouteInfo::new("GET", "/api/meta/features", "Tier-aware feature flags for UI gating", false),
        RouteInfo::new("GET", "/api/meta/dataflow_snapshot", "Dataflow debug snapshot (?debug=1)", false),
        
        // Debug endpoints (dev only)
        RouteInfo::new("GET", "/api/run/debug_counts", "Debug: live signal/fact counts", false),
    ]
}

#[derive(Clone, serde::Serialize)]
struct RouteInfo {
    method: String,
    path: String,
    description: String,
    mutates: bool,
}

impl RouteInfo {
    fn new(method: &str, path: &str, description: &str, mutates: bool) -> Self {
        Self {
            method: method.to_string(),
            path: path.to_string(),
            description: description.to_string(),
            mutates,
        }
    }
}

/// GET /api/meta/routes - Authoritative route inventory for UI wiring audit
async fn meta_routes_handler() -> axum::Json<serde_json::Value> {
    let routes = get_registered_routes();
    axum::Json(serde_json::json!({
        "success": true,
        "data": routes
    }))
}

/// GET /api/meta/contract - API response contract specification
async fn meta_contract_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "contract_version": "1.0.0",
            "contract_hash": "v1-core-202601",
            "wrapper": {
                "success_field": "success",
                "data_field": "data",
                "error_field": "error",
                "code_field": "code"
            },
            "list_convention": "named_array",  // data.{runs|signals|playbooks}, not raw array
            "content_type_required": "application/json",
            "core_endpoints": {
                "GET /api/runs": {
                    "array_field": "runs",
                    "required_keys": ["run_id", "signal_count", "status"]
                },
                "GET /api/signals": {
                    "array_field": "signals",
                    "required_keys": ["signal_id", "signal_type", "severity", "ts"]
                },
                "GET /api/signals/:id/explain": {
                    "required_keys": ["available", "signal", "source", "evidence_ptrs", "evidence_ptrs_count"],
                    "conditional": {
                        "available=false": ["reason_code", "message"],
                        "available=true": ["explanation"]
                    }
                },
                "GET /api/runs/:id/coverage": {
                    "required_keys": ["available", "run_id"]
                },
                "GET /api/runs/:id/playbooks": {
                    "required_keys": ["available", "run_id"]
                }
            },
            "error_codes": {
                "BINARY_NOT_FOUND": "Helper binary missing (HTTP 412)",
                "RUN_ALREADY_ACTIVE": "Run already in progress (HTTP 409)",
                "NO_ACTIVE_RUN": "No run to stop (HTTP 409)",
                "SPAWN_FAILED": "Process spawn failed (HTTP 500)",
                "HTML_RESPONSE": "Got HTML instead of JSON (check same-origin)",
                "EXPLANATION_NOT_FOUND": "Signal exists but no explanation in DB",
                "SIGNAL_NOT_FOUND": "Signal not found in database",
                "PLAYBOOKS_NOT_FOUND": "Playbooks directory not found",
                "PLAYBOOKS_DISABLED": "Playbooks disabled by config",
                "FEATURE_LOCKED": "Feature requires higher tier (see required_tier)"
            },
            "notes": "All API endpoints return JSON with {success, data} or {success:false, error, code}. Binary endpoints (export/bundle) return application/zip. See docs/API_CONTRACT_CORE.md for full spec."
        }
    }))
}

// ============================================================================
// Tier System - Feature Gating Infrastructure
// ============================================================================

/// Product tiers for feature gating
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum ProductTier {
    Free,
    Pro,
    Team,
    Dev,
}

impl ProductTier {
    fn display_name(&self) -> &'static str {
        match self {
            ProductTier::Free => "Free",
            ProductTier::Pro => "Pro",
            ProductTier::Team => "Team",
            ProductTier::Dev => "Developer",
        }
    }
    
    /// Check if this tier has access to a feature requiring `required` tier
    fn has_access(&self, required: ProductTier) -> bool {
        match required {
            ProductTier::Free => true, // Everyone has free
            ProductTier::Dev => *self == ProductTier::Dev, // Dev-only
            ProductTier::Pro => matches!(self, ProductTier::Pro | ProductTier::Team | ProductTier::Dev),
            ProductTier::Team => matches!(self, ProductTier::Team | ProductTier::Dev),
        }
    }
}

/// Resolve current tier from environment/license
fn resolve_current_tier() -> ProductTier {
    // Check for license key in environment
    if let Ok(key) = std::env::var("LOCINT_LICENSE_KEY") {
        // Simple prefix-based detection for now
        // In production, this would validate against a license server
        if key.starts_with("TEAM-") {
            return ProductTier::Team;
        }
        if key.starts_with("PRO-") {
            return ProductTier::Pro;
        }
    }
    
    // Check for license.json file
    if let Ok(contents) = std::fs::read_to_string("license.json") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
            if let Some(tier) = v.get("tier").and_then(|t| t.as_str()) {
                match tier.to_lowercase().as_str() {
                    "team" => return ProductTier::Team,
                    "pro" => return ProductTier::Pro,
                    _ => {}
                }
            }
        }
    }
    
    // Dev tier for debug builds
    if cfg!(debug_assertions) {
        return ProductTier::Dev;
    }
    
    // Default to free
    ProductTier::Free
}

/// GET /api/meta/features - Tier-aware feature flags
/// 
/// Returns the current tier and which features are enabled.
/// UI uses this to show/hide features and display upgrade prompts.
async fn meta_features_handler() -> axum::Json<serde_json::Value> {
    let tier = resolve_current_tier();
    let is_dev = tier == ProductTier::Dev;
    let is_pro_or_above = tier.has_access(ProductTier::Pro);
    let is_team = tier.has_access(ProductTier::Team);
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "tier": tier,
            "tier_display": tier.display_name(),
            "features": {
                // ============================================================
                // Core (Free tier - always enabled)
                // ============================================================
                "run_workflow": true,              // Start/stop/list runs
                "capability_model": true,          // /api/capability/status, detection_plan
                "playbook_system": true,           // Builtin playbooks only
                "signals_explain": true,           // /api/signals/:id/explain
                "evidence_deref": true,            // /api/evidence/deref
                "next_steps": true,                // /api/runs/:id/next_steps
                "import_export": true,             // Basic import/export
                "wiring_audit": true,              // /api/meta/wiring_audit
                "diff_phase": true,                // Diff phase mode (Free)
                
                // ============================================================
                // Pro tier features (gated)
                // ============================================================
                "baselines": is_pro_or_above,      // POST /api/runs/:id/baseline, GET /api/baselines
                "diff_advanced": is_pro_or_above,  // Diff baseline/marker modes, baseline_filter
                "custom_packs": is_pro_or_above,   // Custom content packs (beyond builtin)
                "case_summary": is_pro_or_above,   // GET /api/runs/:id/case_summary
                
                // Planned Pro features
                "pdf_reports": is_pro_or_above,
                "search_similar": is_pro_or_above,
                "cross_run_search": is_pro_or_above,
                "entity_timeline": is_pro_or_above,
                "notes": is_pro_or_above,
                
                // ============================================================
                // Team tier features (planned/reserved)
                // ============================================================
                "case_store": is_team,             // Team case store
                "case_management": is_team,
                "multi_workspace": is_team,
                "integrations": is_team,
                "custom_templates": is_team,
                "audit_log": is_team,
                
                // ============================================================
                // Dev features (debug builds only)
                // ============================================================
                "debug_endpoints": is_dev,
                "gaps_analysis": is_dev,
                "dataflow_snapshot": is_dev,
                "validation_helper": is_dev
            },
            "gating": {
                // Endpoint to tier mapping for UI reference
                "endpoints": {
                    // Pro-gated endpoints
                    "/api/runs/:id/baseline": "pro",
                    "/api/baselines": "pro",
                    "/api/runs/:id/diff?mode=baseline": "pro",
                    "/api/runs/:id/diff?mode=marker": "pro",
                    "/api/runs/:id/diff?baseline_filter=true": "pro",
                    "/api/runs/:id/case_summary": "pro",
                    "/api/packs (custom)": "pro",
                    
                    // Team-gated endpoints
                    "/api/team/store/status": "team",
                    "/api/team/store/configure": "team",
                    "/api/team/cases": "team",
                    "/api/team/cases/:case_id": "team",
                    "/api/team/cases/:case_id/aggregate": "team",
                    "/api/team/cases/:case_id/tags": "team",
                    "/api/team/cases/:case_id/notes": "team",
                    "/api/team/cases/:case_id/publish_run": "team",
                    "/api/team/cases/:case_id/import_run": "team",
                    
                    // Dev-gated endpoints
                    "/api/run/debug_counts": "dev",
                    "/api/capability/gaps": "dev",
                    "/api/meta/dataflow_snapshot": "dev"
                }
            },
            "upgrade_url": "https://locint.io/upgrade"
        }
    }))
}

/// Helper to create a FEATURE_LOCKED error response
/// Use this in Pro/Team gated endpoints
#[allow(dead_code)]
fn feature_locked_response(feature: &str, required_tier: ProductTier) -> axum::Json<serde_json::Value> {
    let current = resolve_current_tier();
    axum::Json(serde_json::json!({
        "success": false,
        "error": {
            "code": "FEATURE_LOCKED",
            "message": format!("{} requires {} tier", feature, required_tier.display_name()),
            "feature": feature,
            "required_tier": required_tier,
            "current_tier": current,
            "upgrade_url": "https://locint.io/upgrade"
        }
    }))
}

/// Helper to return 403 with FEATURE_LOCKED body
/// Use: `return feature_locked_403("PDF Reports", ProductTier::Pro);`
#[allow(dead_code)]
fn feature_locked_403(feature: &str, required_tier: ProductTier) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let current = resolve_current_tier();
    (
        axum::http::StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "FEATURE_LOCKED",
                "message": format!("{} requires {} tier", feature, required_tier.display_name()),
                "feature": feature,
                "required_tier": required_tier,
                "current_tier": current,
                "upgrade_url": "https://locint.io/upgrade"
            }
        }))
    )
}

/// Macro for tier gating at endpoint entry
/// Usage: `tier_gate!(ProductTier::Pro, "PDF Reports");`
#[allow(unused_macros)]
macro_rules! tier_gate {
    ($required:expr, $feature:expr) => {
        if !resolve_current_tier().has_access($required) {
            return feature_locked_403($feature, $required);
        }
    };
}

/// GET /api/meta/dataflow_snapshot - Complete dataflow state for debugging
/// 
/// Returns a single JSON object that merges:
/// - instance identity: pid, port, is_admin
/// - active run: run_id, run_dir, phase  
/// - resolved paths: db_path used for live queries, segments path
/// - spawn status: capture/locald running? pids? last exit?
/// - DB truth: table presence + rowcounts + max ts
/// - last 20 flight recorder events (tail)
///
/// Protected by ?debug=1 query param in production.
async fn dataflow_snapshot_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::Json<serde_json::Value> {
    // Check debug flag (allow in dev, require ?debug=1 in release)
    let debug_enabled = cfg!(debug_assertions) || params.get("debug").map(|v| v == "1").unwrap_or(false);
    
    if !debug_enabled {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": "Debug endpoint requires ?debug=1 query parameter",
            "code": "DEBUG_REQUIRED"
        }));
    }
    
    // Get instance identity from flight recorder
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
        Some(ActiveRunInfo {
            run_id: status.run_id.clone().unwrap_or_default(),
            run_dir: status.run_dir.clone().unwrap_or_default(),
            phase: status.phase.clone(),
            started_at: status.started_at.clone().unwrap_or_default(),
            elapsed_seconds: status.elapsed_seconds.unwrap_or(0),
        })
    } else {
        None
    };
    
    // Get current run directory for path resolution
    let run_dir = state.supervisor.current_run_dir().await;
    let db_path = run_dir.as_ref().map(|d| d.join("workbench.db"));
    let segments_path = run_dir.as_ref().map(|d| d.join("segments"));
    let logs_path = run_dir.as_ref().map(|d| d.join("logs"));
    
    let paths = ResolvedPaths {
        data_dir: state.data_dir.display().to_string(),
        db_path_for_live_queries: db_path.as_ref().map(|p| p.display().to_string()),
        segments_path: segments_path.as_ref().map(|p| p.display().to_string()),
        logs_path: logs_path.as_ref().map(|p| p.display().to_string()),
        flight_log: state.flight_recorder.file_path().display().to_string(),
    };
    
    // Get spawn status
    let (capture_pid, locald_pid) = state.supervisor.get_pids().await;
    let spawn_status = SpawnStatus {
        capture_running: status.capture_running,
        capture_pid,
        capture_last_exit: None, // TODO: track in supervisor
        locald_running: status.locald_running,
        locald_pid,
        locald_last_exit: None, // TODO: track in supervisor
    };
    
    // Get segments status - critical for capture→locald diagnosis
    let segments_status = SegmentsStatus::from_path(segments_path.as_deref());
    
    // Get DB truth
    let db_truth = DbTruth::from_path(db_path.as_deref());
    
    // Generate diagnosis based on observed state
    let diagnosis = generate_diagnosis(&status, &spawn_status, &segments_status, &db_truth);
    
    // Get recent events from flight recorder
    let recent_events = state.flight_recorder.recent_events(20);
    
    let snapshot = DataflowSnapshot {
        instance: identity,
        active_run,
        paths,
        spawn_status,
        segments_status,
        db_truth,
        recent_events,
        snapshot_ts: chrono::Utc::now().to_rfc3339(),
        diagnosis,
    };
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": snapshot
    }))
}

/// Generate diagnosis based on dataflow state
fn generate_diagnosis(
    status: &edr_server::supervisor::RunStatus,
    spawn: &SpawnStatus,
    segments: &SegmentsStatus,
    db: &DbTruth,
) -> Vec<String> {
    let mut issues = vec![];
    
    // Check if run is active but processes aren't running
    if status.running {
        if !spawn.capture_running {
            issues.push("CAPTURE_DEAD: Run is active but capture process is not running".to_string());
        }
        if !spawn.locald_running {
            issues.push("LOCALD_DEAD: Run is active but locald process is not running".to_string());
        }
    }
    
    // Check segments vs locald status
    if segments.segments_count > 0 && !spawn.locald_running {
        issues.push(format!(
            "SEGMENTS_ORPHANED: {} segments exist but locald is not running to process them",
            segments.segments_count
        ));
    }
    
    // Check if segments are being produced but DB has no data
    if segments.segments_count > 0 && db.db_exists {
        let signals_count = db.tables.iter()
            .find(|t| t.name == "signals")
            .map(|t| t.rowcount)
            .unwrap_or(0);
        
        if signals_count == 0 && segments.segments_count > 5 {
            issues.push(format!(
                "LOCALD_NOT_READING: {} segments exist but signals table has 0 rows - locald may not be reading segments",
                segments.segments_count
            ));
        }
    }
    
    // Check for stale segments (newest segment is old)
    if let Some(ref newest) = segments.newest_segment {
        if status.running && newest.age_seconds > 30 {
            issues.push(format!(
                "CAPTURE_STALLED: Newest segment is {} seconds old - capture may have stopped writing",
                newest.age_seconds
            ));
        }
    }
    
    // Check DB existence vs run status
    if status.running && !db.db_exists {
        issues.push("DB_MISSING: Run is active but workbench.db does not exist".to_string());
    }
    
    // Check DB readability
    if db.db_exists && !db.can_read {
        issues.push(format!(
            "DB_LOCKED: DB exists but cannot be read: {}",
            db.error.as_deref().unwrap_or("unknown error")
        ));
    }
    
    if issues.is_empty() {
        issues.push("OK: No obvious dataflow issues detected".to_string());
    }
    
    issues
}

// ============================================================================
// Minimal State and Handlers for locint
// ============================================================================

struct LocintState {
    data_dir: std::path::PathBuf,
    port: u16,
    supervisor: edr_server::supervisor::Supervisor,
    db: edr_server::db::Database,
    flight_recorder: SharedFlightRecorder,
}

type SharedState = std::sync::Arc<LocintState>;

async fn health_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "binary": "locint"
        }
    }))
}

async fn run_start_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(req): axum::Json<StartRunRequest>,
) -> Result<axum::Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    use edr_server::supervisor::{StartConfig, SupervisorError};
    
    // Check if playbooks are explicitly disabled via LOCINT_PLAYBOOKS=off
    let playbooks_disabled = std::env::var("LOCINT_PLAYBOOKS")
        .map(|v| v.to_lowercase() == "off" || v == "0" || v.to_lowercase() == "false")
        .unwrap_or(false);
    
    // Discover playbooks directory using fallback chain (unless disabled)
    let playbooks_dir = if playbooks_disabled {
        None
    } else {
        let (pb_dir, _, _) = discover_playbooks_dir();
        pb_dir
    };
    
    // Build supervisor start config
    let config = StartConfig {
        profile: req.profile.clone(),
        duration_seconds: req.duration_seconds,
        run_label: req.run_label.clone(),
        playbooks_dir,
    };
    
    // Delegate to Supervisor - handles binary discovery, process spawning, and run_meta.json
    match state.supervisor.start(config).await {
        Ok(result) => {
            Ok(axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "run_id": result.run_id,
                    "run_dir": result.run_dir,
                    "capture_pid": result.capture_pid,
                    "locald_pid": result.locald_pid,
                    "started_at": result.started_at.to_rfc3339(),
                    "playbooks_enabled": result.playbooks_enabled,
                    "playbooks_dir": result.playbooks_dir,
                }
            })))
        }
        Err(e) => {
            // Map supervisor errors to HTTP status codes
            let status = match e {
                SupervisorError::BinaryNotFound { .. } => {
                    // HTTP 412 Precondition Failed for missing binaries
                    axum::http::StatusCode::PRECONDITION_FAILED
                }
                SupervisorError::RunAlreadyActive { .. } => {
                    axum::http::StatusCode::CONFLICT
                }
                _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            };
            
            Err((status, serde_json::json!({
                "success": false,
                "error": e.to_string(),
                "code": e.error_code(),
            }).to_string()))
        }
    }
}

#[derive(serde::Deserialize)]
struct StartRunRequest {
    #[serde(default)]
    run_label: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    duration_seconds: Option<u64>,
}

async fn run_stop_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<serde_json::Value> {
    use edr_server::supervisor::SupervisorError;
    
    // Delegate to Supervisor - handles graceful shutdown and finalization
    match state.supervisor.stop_and_finalize().await {
        Ok(result) => {
            axum::Json(serde_json::json!({
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
            // No run to stop - try legacy cleanup as fallback
            legacy_stop_processes().await;
            
            axum::Json(serde_json::json!({
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
            axum::Json(serde_json::json!({
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
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<serde_json::Value> {
    // Delegate to Supervisor for status
    let status = state.supervisor.status().await;
    
    axum::Json(serde_json::json!({
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

/// GET /api/run/metrics - Live metrics from current run
/// Uses Supervisor for DB-derived metrics (no estimates)
async fn run_metrics_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<serde_json::Value> {
    // Delegate to Supervisor for truthful metrics
    let metrics = state.supervisor.metrics().await;
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "running": metrics.running,
            "run_id": metrics.run_id,
            "segments_count": metrics.segments_count,
            "bytes_written": metrics.bytes_written,
            // RD-1 FIX: events_total from DB truth, null if unknown (UI shows "—")
            "events_total": metrics.events_total,
            "facts_extracted": metrics.facts_extracted,
            "signals_fired": metrics.signals_fired,
            "elapsed_seconds": metrics.elapsed_seconds,
            "capture_errors": 0,
            "locald_errors": 0,
        }
    }))
}

/// Count segments in directory (used by various handlers)
#[allow(dead_code)]
fn count_segments(dir: &std::path::Path) -> (u32, u64) {
    let mut count = 0u32;
    let mut bytes = 0u64;
    
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "jsonl") {
                count += 1;
                if let Ok(meta) = entry.metadata() {
                    bytes += meta.len();
                }
            }
        }
    }
    
    (count, bytes)
}

// ============================================================================
// Database Helper: WAL Mode for Concurrent Access
// ============================================================================

/// Open database with WAL pragmas for concurrent read/write access
/// CRITICAL: Both locald (writer) and server (reader) must use WAL mode
/// for live signal visibility during active runs.
fn open_db_with_wal(db_path: &std::path::Path) -> Result<rusqlite::Connection, rusqlite::Error> {
    let conn = rusqlite::Connection::open(db_path)?;
    
    // Apply WAL pragmas for concurrent read while locald writes
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;
         PRAGMA temp_store=MEMORY;"
    )?;
    
    Ok(conn)
}

/// Count signals in database (used by various handlers)
#[allow(dead_code)]
fn count_signals_in_db(db_path: &std::path::Path) -> u64 {
    if !db_path.exists() {
        return 0;
    }
    
    match open_db_with_wal(db_path) {
        Ok(conn) => {
            conn.query_row("SELECT COUNT(*) FROM signals", [], |row| row.get::<_, i64>(0))
                .unwrap_or(0) as u64
        }
        Err(_) => 0,
    }
}

/// RD-1 FIX: Query facts from coverage_rollup table in workbench.db
/// Returns Option<u64> - None if query fails (UI shows "—"), Some(count) if successful
#[allow(dead_code)]
fn query_facts_from_db(db_path: &std::path::Path) -> Option<u64> {
    if !db_path.exists() {
        return None;
    }
    
    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return None,
    };
    
    // Query coverage_rollup for total fact count
    // If table doesn't exist or query fails, return None
    conn.query_row(
        "SELECT SUM(fact_count) FROM coverage_rollup",
        [],
        |row| row.get::<_, Option<i64>>(0),
    )
    .ok()
    .flatten()
    .map(|v| v.max(0) as u64)
}

/// RD-1 FIX: Query events from DB - NO ESTIMATION
/// Returns Option<u64> - None if unknown (UI shows "—"), Some(count) if available
/// Checks coverage_rollup.event_count first, then falls back to segments table
#[allow(dead_code)]
fn query_events_from_db(db_path: &std::path::Path) -> Option<u64> {
    if !db_path.exists() {
        return None;
    }
    
    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return None,
    };
    
    // Try coverage_rollup first (has event counts if locald populates it)
    // Note: locald writes fact_count but may not track events directly
    // Check if coverage_rollup has an event_count column
    let from_coverage: Option<i64> = conn.query_row(
        "SELECT SUM(event_count) FROM coverage_rollup WHERE event_count IS NOT NULL",
        [],
        |row| row.get(0),
    ).ok().flatten();
    
    if let Some(count) = from_coverage {
        if count > 0 {
            return Some(count as u64);
        }
    }
    
    // Fallback: count segments and use record counts from segments table if present
    let from_segments: Option<i64> = conn.query_row(
        "SELECT SUM(records) FROM segments",
        [],
        |row| row.get(0),
    ).ok().flatten();
    
    if let Some(count) = from_segments {
        if count > 0 {
            return Some(count as u64);
        }
    }
    
    // If no DB source available, return None (truthful: we don't know)
    // UI will show "—" instead of fake number
    None
}

async fn list_runs_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<serde_json::Value> {
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
                
                // AUTHORITATIVE SOURCE: Read from run_meta.json if it exists
                let (started_at, stopped_at, status) = read_run_meta(&meta_path, &run_id);
                
                // Try to read stats from the run's workbench.db
                let (events, segments, facts, signals, earliest_ts, latest_ts, _) = 
                    if db_path.exists() {
                        read_run_stats(&db_path)
                    } else {
                        (0, 0, 0, 0, started_at.as_ref().map(|t| t.timestamp_millis()).unwrap_or(0), 0, None)
                    };
                
                // Get name from master DB
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
    
    // Sort by run_id descending (newest first)
    runs.sort_by(|a, b| {
        let a_id = a["run_id"].as_str().unwrap_or("");
        let b_id = b["run_id"].as_str().unwrap_or("");
        b_id.cmp(a_id)
    });
    
    // CONTRACT: List endpoints use named array field (data.runs, not data as array)
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "runs": runs,
            "count": runs.len()
        }
    }))
}

/// Get a single run by ID
async fn get_run_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let run_dir = state.data_dir.join("runs").join(&run_id);
    
    if !run_dir.exists() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Run '{}' not found", run_id)
        }));
    }
    
    let db_path = run_dir.join("workbench.db");
    let meta_path = run_dir.join("run_meta.json");
    
    let (started_at, stopped_at, status) = read_run_meta(&meta_path, &run_id);
    let (events, segments, facts, signals, earliest_ts, latest_ts, _) = 
        if db_path.exists() {
            read_run_stats(&db_path)
        } else {
            (0, 0, 0, 0, started_at.as_ref().map(|t| t.timestamp_millis()).unwrap_or(0), 0, None)
        };
    
    // Get name from master DB
    let name = state.db.get_run(&run_id)
        .ok()
        .flatten()
        .and_then(|r| r.name);
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
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
        }
    }))
}

/// Rename a run
#[derive(serde::Deserialize)]
struct RenameRunRequest {
    name: Option<String>,
}

async fn rename_run_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
    axum::Json(body): axum::Json<RenameRunRequest>,
) -> axum::Json<serde_json::Value> {
    let run_dir = state.data_dir.join("runs").join(&run_id);
    
    if !run_dir.exists() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Run '{}' not found", run_id)
        }));
    }
    
    // Update in master DB
    match state.db.rename_run(&run_id, body.name.as_deref()) {
        Ok(true) => {
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "run_id": run_id,
                    "name": body.name,
                    "message": "Run renamed successfully"
                }
            }))
        }
        Ok(false) => {
            // Run not in master DB - try to insert it first
            if let Ok(Some(_)) = state.db.get_run(&run_id) {
                // Run exists but no update happened (shouldn't occur)
                axum::Json(serde_json::json!({
                    "success": false,
                    "error": "Run exists but rename failed"
                }))
            } else {
                // Run not in master DB, create a basic record
                let now = chrono::Utc::now();
                let record = edr_server::db::RunRecord {
                    run_id: run_id.clone(),
                    name: body.name.clone(),
                    profile: Some("extended".to_string()),
                    started_at: now.to_rfc3339(),
                    stopped_at: None,
                    run_dir: Some(run_dir.to_string_lossy().to_string()),
                    events_total: 0,
                    segments_count: 0,
                    facts_extracted: 0,
                    signals_fired: 0,
                    bytes_written: 0,
                    status: "unknown".to_string(),
                    baseline_scope: None,
                    baseline_enabled: false,
                    baseline_set_at: None,
                };
                if state.db.insert_run(&record).is_ok() {
                    axum::Json(serde_json::json!({
                        "success": true,
                        "data": {
                            "run_id": run_id,
                            "name": body.name,
                            "message": "Run record created and named"
                        }
                    }))
                } else {
                    axum::Json(serde_json::json!({
                        "success": false,
                        "error": "Failed to create run record"
                    }))
                }
            }
        }
        Err(e) => {
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Database error: {}", e)
            }))
        }
    }
}

/// Delete a run (removes from DB and optionally filesystem)
#[derive(serde::Deserialize)]
struct DeleteRunRequest {
    #[serde(default)]
    delete_files: bool,
}

async fn delete_run_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
    body: Option<axum::Json<DeleteRunRequest>>,
) -> axum::Json<serde_json::Value> {
    let delete_files = body.map(|b| b.delete_files).unwrap_or(false);
    let run_dir = state.data_dir.join("runs").join(&run_id);
    
    // Delete from master DB
    let _ = state.db.delete_run(&run_id);
    
    // Optionally delete files
    if delete_files && run_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&run_dir) {
            return axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to delete run directory: {}", e)
            }));
        }
    }
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "run_id": run_id,
            "deleted_files": delete_files,
            "message": if delete_files { "Run and files deleted" } else { "Run record deleted" }
        }
    }))
}

// ============================================================================
// P0 — Baseline System v1 (Pro/Team Foundation)
// ============================================================================

/// Request body for marking a run as baseline
#[derive(serde::Deserialize)]
struct SetBaselineRequest {
    /// Baseline scope: "host" (this machine) or "install" (this LocInt install)
    #[serde(default = "default_baseline_scope")]
    scope: String,
    /// Optional description for this baseline
    #[serde(default)]
    description: String,
    /// Whether this should become the default baseline for the scope
    #[serde(default = "default_true")]
    set_as_default: bool,
}

fn default_baseline_scope() -> String {
    "host".to_string()
}

fn default_true() -> bool {
    true
}

/// Response structure for baseline operations
#[derive(serde::Serialize)]
struct BaselineInfo {
    run_id: String,
    scope: String,
    marked_at: String,
    description: String,
    is_default: bool,
    metrics_snapshot: Option<BaselineMetricsSnapshot>,
}

/// Metrics snapshot for baseline comparison
#[derive(serde::Serialize, Clone)]
struct BaselineMetricsSnapshot {
    events_count: u64,
    segments_count: u32,
    facts_count: u64,
    signals_count: u64,
}

/// POST /api/runs/:run_id/baseline - Mark a run as baseline
/// 
/// **Tier Gated**: Requires Pro tier or higher.
async fn set_baseline_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
    axum::Json(body): axum::Json<SetBaselineRequest>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Tier gate: Baselines require Pro
    if !resolve_current_tier().has_access(ProductTier::Pro) {
        return feature_locked_403("Baselines", ProductTier::Pro);
    }
    
    let run_dir = state.data_dir.join("runs").join(&run_id);
    
    if !run_dir.exists() {
        return (axum::http::StatusCode::NOT_FOUND, axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Run '{}' not found", run_id),
            "reason_code": "RUN_NOT_FOUND"
        })));
    }
    
    // Validate scope
    if body.scope != "host" && body.scope != "install" {
        return (axum::http::StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({
            "success": false,
            "error": "scope must be 'host' or 'install'",
            "reason_code": "INVALID_SCOPE"
        })));
    }
    
    // Get metrics from run's workbench.db
    let db_path = run_dir.join("workbench.db");
    let metrics = if db_path.exists() {
        let (events, segments, facts, signals, _, _, _) = read_run_stats(&db_path);
        Some(BaselineMetricsSnapshot {
            events_count: events,
            segments_count: segments,
            facts_count: facts,
            signals_count: signals as u64,
        })
    } else {
        None
    };
    
    let now = chrono::Utc::now().to_rfc3339();
    
    // PRIMARY: Update in SQLite (transactional, enforces one default per scope)
    match state.db.set_baseline(&run_id, &body.scope, body.set_as_default) {
        Ok(true) => {},
        Ok(false) => {
            // Run not in master DB yet - need to insert it first
            let record = edr_server::db::RunRecord {
                run_id: run_id.clone(),
                name: None,
                profile: Some("extended".to_string()),
                started_at: now.clone(),
                stopped_at: None,
                run_dir: Some(run_dir.to_string_lossy().to_string()),
                events_total: metrics.as_ref().map(|m| m.events_count).unwrap_or(0),
                segments_count: metrics.as_ref().map(|m| m.segments_count).unwrap_or(0),
                facts_extracted: metrics.as_ref().map(|m| m.facts_count).unwrap_or(0),
                signals_fired: metrics.as_ref().map(|m| m.signals_count).unwrap_or(0),
                bytes_written: 0,
                status: "completed".to_string(),
                baseline_scope: Some(body.scope.clone()),
                baseline_enabled: body.set_as_default,
                baseline_set_at: Some(now.clone()),
            };
            if let Err(e) = state.db.insert_run(&record) {
                return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to create run record: {}", e),
                    "reason_code": "DB_ERROR"
                })));
            }
        }
        Err(e) => {
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Database error: {}", e),
                "reason_code": "DB_ERROR"
            })));
        }
    }
    
    // SECONDARY: Write baseline.json to run directory (atomic write with temp file)
    let baseline_data = serde_json::json!({
        "schema_version": "1.1.0",
        "run_id": run_id,
        "scope": body.scope,
        "marked_at": now,
        "description": body.description,
        "is_default": body.set_as_default,
        "metrics_snapshot": metrics,
    });
    
    let baseline_path = run_dir.join("baseline.json");
    let temp_path = run_dir.join(".baseline.json.tmp");
    
    // Atomic write: write to temp file, then rename
    match serde_json::to_string_pretty(&baseline_data) {
        Ok(json_str) => {
            if let Err(e) = std::fs::write(&temp_path, &json_str) {
                tracing::warn!("Failed to write temp baseline file: {}", e);
            } else if let Err(e) = std::fs::rename(&temp_path, &baseline_path) {
                tracing::warn!("Failed to rename baseline file: {}", e);
                // Try direct write as fallback
                let _ = std::fs::write(&baseline_path, &json_str);
            }
        }
        Err(e) => {
            tracing::warn!("Failed to serialize baseline: {}", e);
        }
    }
    
    // TERTIARY: Update baselines.json registry (atomic write)
    let registry_path = state.data_dir.join("baselines.json");
    let temp_registry_path = state.data_dir.join(".baselines.json.tmp");
    
    let mut registry: serde_json::Value = if registry_path.exists() {
        std::fs::read_to_string(&registry_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(serde_json::json!({"schema_version": "1.1.0", "baselines": {}, "defaults": {}}))
    } else {
        serde_json::json!({"schema_version": "1.1.0", "baselines": {}, "defaults": {}})
    };
    
    // Ensure schema version
    registry["schema_version"] = serde_json::json!("1.1.0");
    
    // Add to registry
    registry["baselines"][&run_id] = baseline_data.clone();
    
    // Update default if requested (clear others first)
    if body.set_as_default {
        // Clear existing default for this scope
        if let Some(baselines) = registry["baselines"].as_object_mut() {
            for (_, bl) in baselines.iter_mut() {
                if bl["scope"] == body.scope && bl["is_default"] == true {
                    bl["is_default"] = serde_json::json!(false);
                }
            }
        }
        registry["baselines"][&run_id]["is_default"] = serde_json::json!(true);
        registry["defaults"][&body.scope] = serde_json::json!(run_id);
    }
    
    // Atomic write for registry
    if let Ok(json_str) = serde_json::to_string_pretty(&registry) {
        if let Err(e) = std::fs::write(&temp_registry_path, &json_str) {
            tracing::warn!("Failed to write temp registry: {}", e);
        } else if let Err(e) = std::fs::rename(&temp_registry_path, &registry_path) {
            tracing::warn!("Failed to rename registry: {}", e);
            let _ = std::fs::write(&registry_path, &json_str);
        }
    }
    
    (axum::http::StatusCode::OK, axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "run_id": run_id,
            "scope": body.scope,
            "marked_at": now,
            "description": body.description,
            "is_default": body.set_as_default,
            "metrics_snapshot": metrics,
            "message": format!("Run '{}' marked as {} baseline", run_id, body.scope)
        }
    })))
}

/// GET /api/baselines - List all baseline runs
/// 
/// **Tier Gated**: Requires Pro tier or higher.
async fn list_baselines_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Tier gate: Baselines require Pro
    if !resolve_current_tier().has_access(ProductTier::Pro) {
        return feature_locked_403("Baselines", ProductTier::Pro);
    }
    
    // PRIMARY: Read from SQLite
    let baselines_from_db = match state.db.list_baselines() {
        Ok(baselines) => baselines,
        Err(e) => {
            tracing::warn!("Failed to list baselines from DB: {}", e);
            vec![]
        }
    };
    
    // Get defaults for each scope from DB
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
    
    (axum::http::StatusCode::OK, axum::Json(serde_json::json!({
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

// ============================================================================
// P3 — Case Summary (Reports v1) - Hardened
// ============================================================================

/// Contract version for case summary
const CASE_SUMMARY_CONTRACT_VERSION: &str = "1.1.0";
const CASE_SUMMARY_CONTRACT_HASH: &str = "v1-case-202601";

/// GET /api/runs/:run_id/case_summary - Export case summary JSON
/// 
/// **Tier Gated**: Requires Pro tier or higher.
async fn case_summary_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Tier gate: Case Summary requires Pro
    if !resolve_current_tier().has_access(ProductTier::Pro) {
        return feature_locked_403("Case Summary Export", ProductTier::Pro);
    }
    
    let run_dir = state.data_dir.join("runs").join(&run_id);
    
    if !run_dir.exists() {
        return (axum::http::StatusCode::NOT_FOUND, axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Run '{}' not found", run_id),
            "reason_code": "RUN_NOT_FOUND"
        })));
    }
    
    let db_path = run_dir.join("workbench.db");
    let meta_path = run_dir.join("run_meta.json");
    let segments_dir = run_dir.join("segments");
    
    // Get run metadata
    let (started_at, stopped_at, status) = read_run_meta(&meta_path, &run_id);
    let (events, segments, facts, signals, earliest_ts, latest_ts, _) = 
        if db_path.exists() {
            read_run_stats(&db_path)
        } else {
            (0, 0, 0, 0, 0, 0, None)
        };
    
    // Get capability snapshot from run_meta.json
    let capability_snapshot = get_capability_snapshot_from_meta(&meta_path);
    
    // Compute telemetry caveats based on capability snapshot
    let telemetry_caveats = build_telemetry_caveats(&capability_snapshot);
    
    // Check evidence availability
    let segments_available = segments_dir.exists() && segments_dir.is_dir();
    let segment_file_count = if segments_available {
        std::fs::read_dir(&segments_dir)
            .map(|entries| entries.filter(|e| {
                e.as_ref().ok().map(|e| {
                    e.path().extension().map(|ext| ext == "jsonl").unwrap_or(false)
                }).unwrap_or(false)
            }).count())
            .unwrap_or(0)
    } else {
        0
    };
    
    // Get evidence pointer stats from signals
    let (evidence_ptr_count, evidence_deref_success_count) = get_evidence_stats(&db_path);
    
    // Get top signals (up to 10)
    let top_signals = get_top_signals_for_run(&db_path, 10);
    
    // Get top changes (up to 10)
    let top_changes = get_top_changes_for_run(&db_path, 10);
    
    // Build run story - evidence-backed narrative
    let run_story = build_run_story(started_at, stopped_at, events, facts, signals, &top_signals);
    
    // Build next steps - deterministic, based on actual findings
    let next_steps = build_next_steps(&top_signals, signals);
    
    // Get run name from master DB
    let name = state.db.get_run(&run_id)
        .ok()
        .flatten()
        .and_then(|r| r.name);
    
    let generated_at = chrono::Utc::now().to_rfc3339();
    
    (axum::http::StatusCode::OK, axum::Json(serde_json::json!({
        "success": true,
        "data": {
            // Contract metadata
            "contract_version": CASE_SUMMARY_CONTRACT_VERSION,
            "contract_hash": CASE_SUMMARY_CONTRACT_HASH,
            "schema_version": "1.1.0",
            "generated_at": generated_at,
            
            // Run identification
            "run_id": run_id,
            "name": name,
            
            // Evidence-backed narrative
            "run_story": run_story,
            "next_steps": next_steps,
            
            // Capability snapshot (from run time)
            "capability_snapshot": capability_snapshot,
            
            // Telemetry caveats (what we couldn't observe)
            "telemetry_caveats": telemetry_caveats,
            
            // Summary statistics (all from DB)
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
            },
            
            // Evidence availability stats
            "evidence_availability": {
                "segments_available": segments_available,
                "segment_file_count": segment_file_count,
                "evidence_ptr_count": evidence_ptr_count,
                "evidence_deref_success_count": evidence_deref_success_count,
                "evidence_deref_rate": if evidence_ptr_count > 0 {
                    (evidence_deref_success_count as f64 / evidence_ptr_count as f64) * 100.0
                } else {
                    0.0
                }
            },
            
            // Top findings (from signals table)
            "top_findings": top_signals,
            
            // Top changes (from facts table)
            "top_changes": top_changes
        }
    })))
}

/// Get capability snapshot from run_meta.json
fn get_capability_snapshot_from_meta(meta_path: &std::path::Path) -> serde_json::Value {
    if let Ok(contents) = std::fs::read_to_string(meta_path) {
        if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&contents) {
            // Check for readiness_snapshot or capability_snapshot
            if let Some(snapshot) = meta.get("readiness_snapshot") {
                return snapshot.clone();
            }
            if let Some(snapshot) = meta.get("capability_snapshot") {
                return snapshot.clone();
            }
            // Extract relevant fields
            return serde_json::json!({
                "is_admin": meta.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false),
                "sysmon_installed": meta.get("sysmon_installed").and_then(|v| v.as_bool()).unwrap_or(false),
                "security_log_accessible": meta.get("security_log_accessible").and_then(|v| v.as_bool()).unwrap_or(false),
                "profile": meta.get("profile").and_then(|v| v.as_str())
            });
        }
    }
    // Default: unknown capabilities
    serde_json::json!({
        "is_admin": null,
        "sysmon_installed": null,
        "security_log_accessible": null,
        "note": "Capability snapshot not available in run metadata"
    })
}

/// Build telemetry caveats based on capability snapshot
fn build_telemetry_caveats(capability_snapshot: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut caveats = Vec::new();
    
    let is_admin = capability_snapshot.get("is_admin").and_then(|v| v.as_bool());
    let sysmon_installed = capability_snapshot.get("sysmon_installed").and_then(|v| v.as_bool());
    let security_log = capability_snapshot.get("security_log_accessible").and_then(|v| v.as_bool());
    
    if is_admin == Some(false) {
        caveats.push(serde_json::json!({
            "caveat": "NOT_ADMIN",
            "impact": "Limited access to Security event log and system-level telemetry",
            "affected_detections": ["auth_events", "privileged_operations"]
        }));
    }
    
    if sysmon_installed == Some(false) {
        caveats.push(serde_json::json!({
            "caveat": "NO_SYSMON",
            "impact": "No process command lines, network connections, or file hash data",
            "affected_detections": ["process_injection", "network_c2", "malware_execution"]
        }));
    }
    
    if security_log == Some(false) {
        caveats.push(serde_json::json!({
            "caveat": "NO_SECURITY_LOG",
            "impact": "No authentication events or privilege escalation detection",
            "affected_detections": ["lateral_movement", "credential_access"]
        }));
    }
    
    if is_admin.is_none() && sysmon_installed.is_none() && security_log.is_none() {
        caveats.push(serde_json::json!({
            "caveat": "UNKNOWN_CAPABILITIES",
            "impact": "Run capability snapshot not available; detection coverage unknown",
            "affected_detections": ["all"]
        }));
    }
    
    caveats
}

/// Get evidence statistics from signals table
fn get_evidence_stats(db_path: &std::path::Path) -> (usize, usize) {
    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return (0, 0),
    };
    
    let mut total_ptrs = 0usize;
    let mut valid_ptrs = 0usize;
    
    // Count evidence pointers in signals
    let query = "SELECT evidence_json FROM signals WHERE evidence_json IS NOT NULL";
    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([], |row| {
            let evidence_json: Option<String> = row.get(0)?;
            Ok(evidence_json)
        }) {
            for row in rows.flatten() {
                if let Some(json_str) = row {
                    if let Ok(evidence) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        if let Some(ptrs) = evidence.as_array() {
                            total_ptrs += ptrs.len();
                            // Count pointers with valid segment_id
                            for ptr in ptrs {
                                if ptr.get("segment_id").and_then(|v| v.as_str()).is_some() {
                                    valid_ptrs += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    (total_ptrs, valid_ptrs)
}

/// Helper: Get top signals for a run
fn get_top_signals_for_run(db_path: &std::path::Path, limit: usize) -> Vec<serde_json::Value> {
    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    
    let mut signals = Vec::new();
    let query = r#"
        SELECT id, rule_id, title, severity, category, confidence, ts_start, evidence_json
        FROM signals
        ORDER BY 
            CASE severity 
                WHEN 'critical' THEN 0 
                WHEN 'high' THEN 1 
                WHEN 'medium' THEN 2 
                WHEN 'low' THEN 3 
                ELSE 4 
            END,
            confidence DESC
        LIMIT ?
    "#;
    
    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([limit as i64], |row| {
            let id: String = row.get(0)?;
            let rule_id: String = row.get(1)?;
            let title: String = row.get(2)?;
            let severity: String = row.get(3)?;
            let category: Option<String> = row.get(4)?;
            let confidence: f64 = row.get(5)?;
            let ts_start: i64 = row.get(6)?;
            let evidence_json: Option<String> = row.get(7)?;
            
            Ok(serde_json::json!({
                "id": id,
                "rule_id": rule_id,
                "title": title,
                "severity": severity,
                "category": category,
                "confidence": confidence,
                "ts_start": ts_start,
                "evidence_preview": evidence_json.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            }))
        }) {
            for row in rows.flatten() {
                signals.push(row);
            }
        }
    }
    
    signals
}

/// Helper: Get top changes for a run (from facts with change indicators)
fn get_top_changes_for_run(db_path: &std::path::Path, limit: usize) -> Vec<serde_json::Value> {
    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    
    let mut changes = Vec::new();
    
    // Try to get from facts table - look for registry/file/service changes
    let query = r#"
        SELECT fact_key, fact_type, value_json, ts
        FROM facts
        WHERE fact_type IN ('registry_change', 'file_change', 'service_change', 'process_start', 'network_connection')
        ORDER BY ts DESC
        LIMIT ?
    "#;
    
    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([limit as i64], |row| {
            let fact_key: String = row.get(0)?;
            let fact_type: String = row.get(1)?;
            let value_json: Option<String> = row.get(2)?;
            let ts: i64 = row.get(3)?;
            
            Ok(serde_json::json!({
                "fact_key": fact_key,
                "fact_type": fact_type,
                "value": value_json.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
                "ts": ts
            }))
        }) {
            for row in rows.flatten() {
                changes.push(row);
            }
        }
    }
    
    changes
}

/// Helper: Build run story narrative
fn build_run_story(
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    stopped_at: Option<chrono::DateTime<chrono::Utc>>,
    events: u64,
    facts: u64,
    signals: usize,
    top_signals: &[serde_json::Value],
) -> String {
    let duration_str = match (started_at, stopped_at) {
        (Some(start), Some(stop)) => {
            let duration = stop.signed_duration_since(start);
            let mins = duration.num_minutes();
            let secs = duration.num_seconds() % 60;
            format!("{} minutes {} seconds", mins, secs)
        }
        _ => "unknown duration".to_string(),
    };
    
    let severity_summary = if !top_signals.is_empty() {
        let critical = top_signals.iter().filter(|s| s["severity"] == "critical").count();
        let high = top_signals.iter().filter(|s| s["severity"] == "high").count();
        if critical > 0 {
            format!("{} critical and {} high severity findings", critical, high)
        } else if high > 0 {
            format!("{} high severity findings", high)
        } else {
            format!("{} findings", top_signals.len())
        }
    } else {
        "no significant findings".to_string()
    };
    
    format!(
        "This capture ran for {} and processed {} events, extracting {} facts. \
         Analysis identified {} signals with {}.",
        duration_str, events, facts, signals, severity_summary
    )
}

/// Helper: Build next steps recommendations
fn build_next_steps(top_signals: &[serde_json::Value], total_signals: usize) -> Vec<serde_json::Value> {
    let mut steps = Vec::new();
    
    // Check for critical signals
    let has_critical = top_signals.iter().any(|s| s["severity"] == "critical");
    let has_high = top_signals.iter().any(|s| s["severity"] == "high");
    
    if has_critical {
        steps.push(serde_json::json!({
            "priority": 1,
            "action": "Review critical findings immediately",
            "rationale": "Critical severity findings may indicate active compromise or urgent security issues"
        }));
    }
    
    if has_high {
        steps.push(serde_json::json!({
            "priority": 2,
            "action": "Investigate high severity findings",
            "rationale": "High severity findings warrant prompt investigation"
        }));
    }
    
    if total_signals > 10 {
        steps.push(serde_json::json!({
            "priority": 3,
            "action": "Review signal categories for patterns",
            "rationale": "Multiple signals may indicate related activity or attack chain"
        }));
    }
    
    if steps.is_empty() {
        steps.push(serde_json::json!({
            "priority": 3,
            "action": "Document run results and archive if needed",
            "rationale": "No urgent findings, but results may be valuable for baseline comparison"
        }));
    }
    
    steps
}

// ============================================================================
// P1 — Import Normalization v1
// ============================================================================

/// POST /api/import/validate - Validate import bundle before import
async fn import_validate_handler(
    axum::extract::State(_state): axum::extract::State<SharedState>,
    mut multipart: axum::extract::Multipart,
) -> axum::Json<serde_json::Value> {
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
        None => {
            return axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": "NO_FILE_UPLOADED",
                    "missing_artifacts": ["bundle file"],
                    "found_artifacts": [],
                    "schema_version": null,
                    "suggested_fix": "Upload a valid bundle ZIP file",
                    "can_compile": false,
                    "can_diff": false,
                    "can_case_summary": false,
                    "evidence_deref_available": false
                }
            }));
        }
    };
    
    // Validate ZIP structure
    let cursor = std::io::Cursor::new(&zip_data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(e) => {
            return axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": "INVALID_ZIP",
                    "missing_artifacts": [],
                    "found_artifacts": [],
                    "schema_version": null,
                    "suggested_fix": format!("ZIP file is invalid: {}", e),
                    "can_compile": false,
                    "can_diff": false,
                    "can_case_summary": false,
                    "evidence_deref_available": false
                }
            }));
        }
    };
    
    let mut found_artifacts: Vec<String> = Vec::new();
    let mut schema_version: Option<String> = None;
    let mut run_meta_idx: Option<usize> = None;
    let mut has_workbench_db = false;
    let mut has_run_meta = false;
    let mut has_segments = false;
    let mut segment_count = 0;
    
    // First pass: collect filenames and categorize
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            let name = file.name().to_string();
            
            if name.ends_with("run_meta.json") {
                run_meta_idx = Some(i);
                has_run_meta = true;
            }
            if name.ends_with("workbench.db") {
                has_workbench_db = true;
            }
            if name.contains("segments/") && name.ends_with(".jsonl") {
                has_segments = true;
                segment_count += 1;
            }
            
            found_artifacts.push(name);
        }
    }
    
    // Second pass: read run_meta.json if found
    if let Some(idx) = run_meta_idx {
        if let Ok(mut file) = archive.by_index(idx) {
            let mut contents = String::new();
            if std::io::Read::read_to_string(&mut file, &mut contents).is_ok() {
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&contents) {
                    schema_version = meta["schema_version"].as_str().map(|s| s.to_string());
                }
            }
        }
    }
    
    // Validate schema version if present
    let supported_schemas = vec!["1.0.0", "1.1.0"];
    let schema_supported = schema_version.as_ref()
        .map(|v| supported_schemas.contains(&v.as_str()))
        .unwrap_or(true); // Allow if no schema (legacy)
    
    // Determine what operations are possible
    // - can_compile: needs segments/ (can rebuild workbench.db)
    // - can_diff: needs workbench.db OR segments/
    // - can_case_summary: needs workbench.db (for facts/signals)
    // - evidence_deref: needs segments/
    let can_compile = has_segments;
    let can_diff = has_workbench_db || has_segments;
    let can_case_summary = has_workbench_db;
    let evidence_deref_available = has_segments;
    
    // Determine reason code
    let (available, reason_code, suggested_fix): (bool, String, String) = if !has_run_meta {
        (false, "MISSING_RUN_META".to_string(), "Bundle must contain run_meta.json".to_string())
    } else if !schema_supported {
        (false, "SCHEMA_UNSUPPORTED".to_string(), format!("Schema version '{}' is not supported. Supported: {:?}", 
            schema_version.as_deref().unwrap_or("unknown"), supported_schemas))
    } else if !has_workbench_db && !has_segments {
        (false, "MISSING_DB_AND_SEGMENTS".to_string(), 
         "Bundle must contain either workbench.db (for immediate use) or segments/ directory (for compilation)".to_string())
    } else {
        (true, String::new(), String::new())
    };
    
    // Build missing artifacts list
    let mut missing_artifacts = Vec::new();
    if !has_run_meta {
        missing_artifacts.push("run_meta.json".to_string());
    }
    if !has_workbench_db && !has_segments {
        missing_artifacts.push("workbench.db OR segments/".to_string());
    }
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "available": available,
            "reason_code": if available { serde_json::Value::Null } else { serde_json::json!(reason_code) },
            "missing_artifacts": missing_artifacts,
            "found_artifacts": found_artifacts,
            "schema_version": schema_version,
            "suggested_fix": if available { serde_json::Value::Null } else { serde_json::json!(suggested_fix) },
            "can_compile": can_compile,
            "can_diff": can_diff,
            "can_case_summary": can_case_summary,
            "evidence_deref_available": evidence_deref_available,
            "segment_count": segment_count,
            "has_workbench_db": has_workbench_db
        }
    }))
}

// ============================================================================
// P2 — Content Packs (Custom Playbooks) - Hardened
// ============================================================================

/// Supported pack schema versions
const PACK_SCHEMA_VERSIONS: &[&str] = &["1.0.0", "1.1.0"];

/// Pack validation result
#[derive(serde::Serialize)]
struct PackValidation {
    valid: bool,
    reason_code: Option<String>,
    reason_message: Option<String>,
}

/// Validate a pack and return validation result
fn validate_pack(pack_dir: &std::path::Path, pack: &serde_json::Value) -> PackValidation {
    // Check schema version
    let schema_version = pack.get("schema_version")
        .and_then(|v| v.as_str())
        .unwrap_or("1.0.0");
    
    if !PACK_SCHEMA_VERSIONS.contains(&schema_version) {
        return PackValidation {
            valid: false,
            reason_code: Some("SCHEMA_UNSUPPORTED".to_string()),
            reason_message: Some(format!(
                "Pack schema version '{}' not supported. Supported: {:?}",
                schema_version, PACK_SCHEMA_VERSIONS
            )),
        };
    }
    
    // Check required fields
    if pack.get("name").and_then(|v| v.as_str()).is_none() {
        return PackValidation {
            valid: false,
            reason_code: Some("MISSING_NAME".to_string()),
            reason_message: Some("Pack must have a 'name' field".to_string()),
        };
    }
    
    // Check playbooks directory exists
    let playbooks_dir = pack_dir.join("playbooks").join("windows");
    if !playbooks_dir.exists() {
        return PackValidation {
            valid: false,
            reason_code: Some("MISSING_PLAYBOOKS_DIR".to_string()),
            reason_message: Some("Pack must contain playbooks/windows/ directory".to_string()),
        };
    }
    
    // Count playbooks
    let playbook_count = std::fs::read_dir(&playbooks_dir)
        .map(|entries| entries.filter(|e| {
            e.as_ref().ok().map(|e| {
                e.path().extension().map(|ext| ext == "yaml" || ext == "yml").unwrap_or(false)
            }).unwrap_or(false)
        }).count())
        .unwrap_or(0);
    
    if playbook_count == 0 {
        return PackValidation {
            valid: false,
            reason_code: Some("NO_PLAYBOOKS".to_string()),
            reason_message: Some("Pack contains no playbook files (*.yaml/*.yml)".to_string()),
        };
    }
    
    // If pack has integrity field, verify it
    if let Some(integrity) = pack.get("integrity") {
        if let Some(expected_hash) = integrity.get("playbooks_sha256").and_then(|v| v.as_str()) {
            let computed_hash = compute_playbooks_hash(&playbooks_dir);
            if computed_hash != expected_hash {
                return PackValidation {
                    valid: false,
                    reason_code: Some("INTEGRITY_MISMATCH".to_string()),
                    reason_message: Some(format!(
                        "Playbooks hash mismatch. Expected: {}, Got: {}",
                        expected_hash, computed_hash
                    )),
                };
            }
        }
    }
    
    PackValidation {
        valid: true,
        reason_code: None,
        reason_message: None,
    }
}

/// Compute SHA256 hash of all playbook files in a directory
fn compute_playbooks_hash(playbooks_dir: &std::path::Path) -> String {
    use sha2::{Sha256, Digest};
    use std::io::Read;
    
    let mut hasher = Sha256::new();
    let mut files: Vec<_> = Vec::new();
    
    if let Ok(entries) = std::fs::read_dir(playbooks_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|ext| ext == "yaml" || ext == "yml").unwrap_or(false) {
                files.push(path);
            }
        }
    }
    
    // Sort for deterministic hash
    files.sort();
    
    for file_path in files {
        // Include filename in hash
        if let Some(name) = file_path.file_name() {
            hasher.update(name.to_string_lossy().as_bytes());
        }
        // Include file contents
        if let Ok(mut file) = std::fs::File::open(&file_path) {
            let mut buffer = Vec::new();
            if file.read_to_end(&mut buffer).is_ok() {
                hasher.update(&buffer);
            }
        }
    }
    
    format!("{:x}", hasher.finalize())
}

/// Check if tier allows custom packs (Pro/Team only)
fn tier_allows_custom_packs() -> bool {
    // Check tier from environment or config
    // For now, check LOCINT_TIER env var
    std::env::var("LOCINT_TIER")
        .map(|t| t == "pro" || t == "team" || t == "enterprise")
        .unwrap_or(false) // Default: Free tier (no custom packs)
}

/// GET /api/packs - List available content packs
async fn list_packs_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<serde_json::Value> {
    let packs_dir = state.data_dir.join("packs");
    let mut packs = Vec::new();
    let mut rejected_packs = Vec::new();
    let tier_allows_custom = tier_allows_custom_packs();
    
    // Compute builtin pack info
    let (builtin_playbook_count, builtin_hash) = get_builtin_pack_info();
    
    // Always include built-in pack
    packs.push(serde_json::json!({
        "name": "builtin",
        "display_name": "Built-in Detections",
        "version": "1.0.0",
        "schema_version": "1.1.0",
        "description": "Default detection playbooks included with LocInt",
        "author": "LocInt Team",
        "playbook_count": builtin_playbook_count,
        "is_builtin": true,
        "enabled": true,
        "integrity": {
            "playbooks_sha256": builtin_hash
        }
    }));
    
    // Scan for custom packs (only if tier allows)
    if packs_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&packs_dir) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let pack_dir = entry.path();
                    let pack_json = pack_dir.join("pack.json");
                    let pack_name = entry.file_name().to_string_lossy().to_string();
                    
                    if !pack_json.exists() {
                        rejected_packs.push(serde_json::json!({
                            "name": pack_name,
                            "reason_code": "MISSING_PACK_JSON",
                            "reason_message": "Pack directory missing pack.json"
                        }));
                        continue;
                    }
                    
                    // Read and parse pack.json
                    let contents = match std::fs::read_to_string(&pack_json) {
                        Ok(c) => c,
                        Err(e) => {
                            rejected_packs.push(serde_json::json!({
                                "name": pack_name,
                                "reason_code": "READ_ERROR",
                                "reason_message": format!("Failed to read pack.json: {}", e)
                            }));
                            continue;
                        }
                    };
                    
                    let mut pack: serde_json::Value = match serde_json::from_str(&contents) {
                        Ok(p) => p,
                        Err(e) => {
                            rejected_packs.push(serde_json::json!({
                                "name": pack_name,
                                "reason_code": "INVALID_JSON",
                                "reason_message": format!("Invalid JSON in pack.json: {}", e)
                            }));
                            continue;
                        }
                    };
                    
                    // Validate pack
                    let validation = validate_pack(&pack_dir, &pack);
                    if !validation.valid {
                        rejected_packs.push(serde_json::json!({
                            "name": pack_name,
                            "reason_code": validation.reason_code,
                            "reason_message": validation.reason_message
                        }));
                        continue;
                    }
                    
                    // Check tier gating
                    if !tier_allows_custom {
                        rejected_packs.push(serde_json::json!({
                            "name": pack_name,
                            "reason_code": "TIER_RESTRICTED",
                            "reason_message": "Custom packs require Pro or Team tier"
                        }));
                        continue;
                    }
                    
                    // Count playbooks and compute hash
                    let playbooks_dir = pack_dir.join("playbooks").join("windows");
                    let playbook_count = if playbooks_dir.exists() {
                        std::fs::read_dir(&playbooks_dir)
                            .map(|entries| entries.filter(|e| {
                                e.as_ref().ok().map(|e| {
                                    e.path().extension().map(|ext| ext == "yaml" || ext == "yml").unwrap_or(false)
                                }).unwrap_or(false)
                            }).count())
                            .unwrap_or(0)
                    } else {
                        0
                    };
                    
                    let playbooks_hash = compute_playbooks_hash(&playbooks_dir);
                    
                    pack["playbook_count"] = serde_json::json!(playbook_count);
                    pack["is_builtin"] = serde_json::json!(false);
                    pack["integrity"] = serde_json::json!({
                        "playbooks_sha256": playbooks_hash
                    });
                    
                    // Default enabled to true if not specified
                    if pack.get("enabled").is_none() {
                        pack["enabled"] = serde_json::json!(true);
                    }
                    
                    packs.push(pack);
                }
            }
        }
    }
    
    let count = packs.len();
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "packs": packs,
            "rejected_packs": rejected_packs,
            "count": count,
            "tier_allows_custom": tier_allows_custom
        }
    }))
}

/// Helper: Get built-in playbooks info (count and hash)
fn get_builtin_pack_info() -> (usize, String) {
    let possible_paths = vec![
        std::path::PathBuf::from("playbooks/windows"),
        std::path::PathBuf::from("LocInt/playbooks/windows"),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("playbooks/windows")))
            .unwrap_or_default(),
    ];
    
    for path in possible_paths {
        if path.exists() {
            let count = std::fs::read_dir(&path)
                .map(|entries| entries.filter(|e| {
                    e.as_ref().ok().map(|e| {
                        e.path().extension().map(|ext| ext == "yaml" || ext == "yml").unwrap_or(false)
                    }).unwrap_or(false)
                }).count())
                .unwrap_or(0);
            
            let hash = compute_playbooks_hash(&path);
            return (count, hash);
        }
    }
    
    (0, "none".to_string())
}

/// Helper: Count built-in playbooks (legacy, kept for compatibility)
fn count_builtin_playbooks() -> usize {
    get_builtin_pack_info().0
}

/// GET /api/packs/:pack_name - Get content pack details
/// 
/// **Tier Gated**: Custom packs require Pro tier. Built-in pack always allowed.
async fn get_pack_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(pack_name): axum::extract::Path<String>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Handle built-in pack specially - always allowed
    if pack_name == "builtin" {
        let (playbook_count, playbooks_hash) = get_builtin_pack_info();
        return (axum::http::StatusCode::OK, axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "name": "builtin",
                "display_name": "Built-in Detections",
                "version": "1.0.0",
                "schema_version": "1.1.0",
                "description": "Default detection playbooks included with LocInt",
                "author": "LocInt Team",
                "playbook_count": playbook_count,
                "playbooks": [], // Would list actual playbooks here
                "is_builtin": true,
                "enabled": true,
                "integrity": {
                    "playbooks_sha256": playbooks_hash
                }
            }
        })));
    }
    
    // Tier gate: Custom packs require Pro
    if !resolve_current_tier().has_access(ProductTier::Pro) {
        return feature_locked_403("Custom Content Packs", ProductTier::Pro);
    }
    
    let pack_dir = state.data_dir.join("packs").join(&pack_name);
    let pack_json = pack_dir.join("pack.json");
    
    if !pack_json.exists() {
        return (axum::http::StatusCode::NOT_FOUND, axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Pack '{}' not found", pack_name),
            "reason_code": "PACK_NOT_FOUND"
        })));
    }
    
    match std::fs::read_to_string(&pack_json) {
        Ok(contents) => {
            match serde_json::from_str::<serde_json::Value>(&contents) {
                Ok(mut pack) => {
                    // Validate pack
                    let validation = validate_pack(&pack_dir, &pack);
                    if !validation.valid {
                        return (axum::http::StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({
                            "success": false,
                            "error": validation.reason_message,
                            "reason_code": validation.reason_code
                        })));
                    }
                    
                    // Count and list playbooks with hashes
                    let playbooks_dir = pack_dir.join("playbooks").join("windows");
                    let mut playbooks = Vec::new();
                    
                    if playbooks_dir.exists() {
                        if let Ok(entries) = std::fs::read_dir(&playbooks_dir) {
                            for entry in entries.flatten() {
                                let path = entry.path();
                                if path.extension().map(|ext| ext == "yaml" || ext == "yml").unwrap_or(false) {
                                    // Compute hash for individual playbook
                                    let file_hash = if let Ok(contents) = std::fs::read(&path) {
                                        use sha2::{Sha256, Digest};
                                        format!("{:x}", Sha256::digest(&contents))
                                    } else {
                                        "error".to_string()
                                    };
                                    
                                    playbooks.push(serde_json::json!({
                                        "filename": entry.file_name().to_string_lossy(),
                                        "sha256": file_hash
                                    }));
                                }
                            }
                        }
                    }
                    
                    let playbooks_hash = compute_playbooks_hash(&playbooks_dir);
                    
                    pack["playbook_count"] = serde_json::json!(playbooks.len());
                    pack["playbooks"] = serde_json::json!(playbooks);
                    pack["is_builtin"] = serde_json::json!(false);
                    pack["integrity"] = serde_json::json!({
                        "playbooks_sha256": playbooks_hash
                    });
                    
                    (axum::http::StatusCode::OK, axum::Json(serde_json::json!({
                        "success": true,
                        "data": pack
                    })))
                }
                Err(e) => {
                    (axum::http::StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({
                        "success": false,
                        "error": format!("Invalid pack.json: {}", e),
                        "reason_code": "INVALID_JSON"
                    })))
                }
            }
        }
        Err(e) => {
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to read pack.json: {}", e)
            })))
        }
    }
}

/// POST /api/packs/rescan - Rescan content packs directory
async fn rescan_packs_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Tier gate: Custom packs require Pro
    if !resolve_current_tier().has_access(ProductTier::Pro) {
        return feature_locked_403("Custom Content Packs", ProductTier::Pro);
    }
    
    let packs_dir = state.data_dir.join("packs");
    
    // Just trigger a rescan by returning current state
    // The actual scan happens in list_packs_handler
    let pack_count = if packs_dir.exists() {
        std::fs::read_dir(&packs_dir)
            .map(|entries| entries.filter(|e| {
                e.as_ref().ok().map(|e| e.file_type().ok().map(|t| t.is_dir()).unwrap_or(false)).unwrap_or(false)
            }).count())
            .unwrap_or(0)
    } else {
        0
    };
    
    (axum::http::StatusCode::OK, axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "rescanned": true,
            "packs_dir": packs_dir.to_string_lossy(),
            "pack_count": pack_count,
            "timestamp": chrono::Utc::now().to_rfc3339()
        }
    })))
}

// ============================================================================
// P0 — PRO PIVOT LOOP (Entity Explorer) - Pro Tier Only
// ============================================================================

/// GET /api/runs/:run_id/entities - Run-scoped entity index
/// Returns all entities with counts, first/last seen, top signals/changes
/// 
/// **Tier Gated**: Requires Pro tier or higher.
async fn run_entities_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Tier gate: Entity Explorer requires Pro
    if !resolve_current_tier().has_access(ProductTier::Pro) {
        return feature_locked_403("Entity Explorer", ProductTier::Pro);
    }
    
    let run_dir = state.data_dir.join("runs").join(&run_id);
    let db_path = run_dir.join("workbench.db");
    
    if !db_path.exists() {
        return (axum::http::StatusCode::NOT_FOUND, axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Run '{}' not found or no data available", run_id),
            "code": "RUN_NOT_FOUND"
        })));
    }
    
    let conn = match open_db_with_wal(&db_path) {
        Ok(c) => c,
        Err(e) => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
            "success": false,
            "error": format!("DB error: {}", e),
            "code": "DB_ERROR"
        }))),
    };
    
    // Query entity_rollup for all entity types
    let mut entities = serde_json::Map::new();
    
    // Processes
    let processes = query_entities_by_type(&conn, &run_id, "process", 50);
    entities.insert("processes".to_string(), serde_json::json!(processes));
    
    // Files
    let files = query_entities_by_type(&conn, &run_id, "file", 50);
    entities.insert("files".to_string(), serde_json::json!(files));
    
    // Network (IPs)
    let ips = query_entities_by_type(&conn, &run_id, "network", 50);
    entities.insert("ips".to_string(), serde_json::json!(ips));
    
    // Users
    let users = query_entities_by_type(&conn, &run_id, "user", 50);
    entities.insert("users".to_string(), serde_json::json!(users));
    
    // Hosts
    let hosts = query_entities_by_type(&conn, &run_id, "host", 50);
    entities.insert("hosts".to_string(), serde_json::json!(hosts));
    
    // Get totals
    let facts_total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM facts WHERE run_id = ?1", [&run_id], |row| row.get(0)
    ).unwrap_or(0);
    
    let signals_total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM signals", [], |row| row.get(0)
    ).unwrap_or(0);
    
    let changes_total: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT fact_key) FROM facts WHERE run_id = ?1", [&run_id], |row| row.get(0)
    ).unwrap_or(0);
    
    (axum::http::StatusCode::OK, axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "run_id": run_id,
            "entities": entities,
            "totals": {
                "facts": facts_total,
                "signals": signals_total,
                "changes": changes_total
            }
        }
    })))
}

/// Helper: Query entities by type from entity_rollup
fn query_entities_by_type(
    conn: &rusqlite::Connection,
    run_id: &str,
    entity_type: &str,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut entities = Vec::new();
    
    // First get entity keys and counts
    let query = r#"
        SELECT entity_key, fact_count, first_seen, last_seen
        FROM entity_rollup
        WHERE run_id = ?1 AND entity_type = ?2
        ORDER BY fact_count DESC
        LIMIT ?3
    "#;
    
    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map(rusqlite::params![run_id, entity_type, limit as i64], |row| {
            let entity_key: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            let first_seen: Option<i64> = row.get(2).ok();
            let last_seen: Option<i64> = row.get(3).ok();
            Ok((entity_key, count, first_seen, last_seen))
        }) {
            for row in rows.flatten() {
                let (entity_key, count, first_seen, last_seen) = row;
                
                // Get top signals for this entity
                let top_signals = get_entity_top_signals(conn, &entity_key, entity_type, 3);
                
                entities.push(serde_json::json!({
                    "entity_key": entity_key,
                    "count": count,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "top_signals": top_signals,
                    "top_changes": [] // Could be populated from facts if needed
                }));
            }
        }
    }
    
    entities
}

/// Helper: Get top signals referencing an entity
fn get_entity_top_signals(
    conn: &rusqlite::Connection,
    entity_key: &str,
    entity_type: &str,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut signals = Vec::new();
    
    // Match entity based on type
    let column = match entity_type {
        "process" => "proc_key",
        "file" => "file_key",
        "user" => "identity_key",
        "host" => "host",
        "network" => "metadata", // Will search in metadata JSON
        _ => return signals,
    };
    
    let query = if entity_type == "network" {
        format!(
            r#"SELECT signal_id, signal_type, severity, ts
               FROM signals
               WHERE metadata LIKE '%{}%'
               ORDER BY ts DESC LIMIT {}"#,
            entity_key.replace("'", "''"), limit
        )
    } else {
        format!(
            r#"SELECT signal_id, signal_type, severity, ts
               FROM signals
               WHERE {} = ?1
               ORDER BY ts DESC LIMIT {}"#,
            column, limit
        )
    };
    
    if entity_type == "network" {
        if let Ok(mut stmt) = conn.prepare(&query) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "signal_id": row.get::<_, String>(0)?,
                    "signal_type": row.get::<_, String>(1)?,
                    "severity": row.get::<_, String>(2)?,
                    "ts": row.get::<_, i64>(3)?
                }))
            }) {
                for row in rows.flatten() {
                    signals.push(row);
                }
            }
        }
    } else if let Ok(mut stmt) = conn.prepare(&query) {
        if let Ok(rows) = stmt.query_map([entity_key], |row| {
            Ok(serde_json::json!({
                "signal_id": row.get::<_, String>(0)?,
                "signal_type": row.get::<_, String>(1)?,
                "severity": row.get::<_, String>(2)?,
                "ts": row.get::<_, i64>(3)?
            }))
        }) {
            for row in rows.flatten() {
                signals.push(row);
            }
        }
    }
    
    signals
}

/// Pivot query parameters
#[derive(serde::Deserialize)]
struct PivotQuery {
    kind: String,      // proc|file|ip|user|host
    key: String,       // entity_key to pivot on
    window_ms: Option<i64>, // optional time window around entity activity
}

/// GET /api/runs/:run_id/pivot - Pivot query for entity exploration
/// Returns related findings, changes, evidence pointers, and mini timeline
/// 
/// **Tier Gated**: Requires Pro tier or higher.
async fn run_pivot_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<PivotQuery>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Tier gate: Entity Explorer requires Pro
    if !resolve_current_tier().has_access(ProductTier::Pro) {
        return feature_locked_403("Entity Explorer", ProductTier::Pro);
    }
    
    let run_dir = state.data_dir.join("runs").join(&run_id);
    let db_path = run_dir.join("workbench.db");
    
    if !db_path.exists() {
        return (axum::http::StatusCode::NOT_FOUND, axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Run '{}' not found", run_id),
            "code": "RUN_NOT_FOUND"
        })));
    }
    
    let conn = match open_db_with_wal(&db_path) {
        Ok(c) => c,
        Err(e) => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
            "success": false,
            "error": format!("DB error: {}", e),
            "code": "DB_ERROR"
        }))),
    };
    
    let kind = query.kind.as_str();
    let key = &query.key;
    let window_ms = query.window_ms.unwrap_or(300_000); // default 5 min window
    
    // Get related signals
    let related_findings = pivot_query_signals(&conn, kind, key, window_ms);
    
    // Get related changes (from facts)
    let related_changes = pivot_query_changes(&conn, &run_id, kind, key, window_ms);
    
    // Extract evidence pointers from findings
    let related_evidence_ptrs = extract_pivot_evidence(&conn, &related_findings, 10);
    
    // Build mini timeline (merged findings + changes by timestamp)
    let mini_timeline = build_pivot_timeline(&related_findings, &related_changes, 50);
    
    (axum::http::StatusCode::OK, axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "run_id": run_id,
            "pivot": {
                "kind": kind,
                "key": key,
                "window_ms": window_ms
            },
            "related_findings": related_findings,
            "related_changes": related_changes,
            "related_evidence_ptrs": related_evidence_ptrs,
            "mini_timeline": mini_timeline
        }
    })))
}

/// Helper: Query signals related to an entity
fn pivot_query_signals(
    conn: &rusqlite::Connection,
    kind: &str,
    key: &str,
    _window_ms: i64,
) -> Vec<serde_json::Value> {
    let mut signals = Vec::new();
    
    let column = match kind {
        "proc" | "process" => "proc_key",
        "file" => "file_key",
        "user" => "identity_key",
        "host" => "host",
        "ip" | "network" => {
            // Search in metadata for network entities
            let query = r#"
                SELECT signal_id, signal_type, severity, ts, host, proc_key, metadata, evidence_ptrs
                FROM signals
                WHERE metadata LIKE ?1
                ORDER BY ts DESC
                LIMIT 50
            "#;
            let pattern = format!("%{}%", key.replace("'", "''"));
            if let Ok(mut stmt) = conn.prepare(query) {
                if let Ok(rows) = stmt.query_map([&pattern], |row| {
                    Ok(serde_json::json!({
                        "signal_id": row.get::<_, String>(0)?,
                        "signal_type": row.get::<_, String>(1)?,
                        "severity": row.get::<_, String>(2)?,
                        "ts": row.get::<_, i64>(3)?,
                        "host": row.get::<_, Option<String>>(4)?,
                        "proc_key": row.get::<_, Option<String>>(5)?,
                        "metadata": row.get::<_, Option<String>>(6)?,
                        "evidence_ptrs": row.get::<_, Option<String>>(7)?
                    }))
                }) {
                    for row in rows.flatten() {
                        signals.push(row);
                    }
                }
            }
            return signals;
        }
        _ => return signals,
    };
    
    let query = format!(
        r#"SELECT signal_id, signal_type, severity, ts, host, proc_key, metadata, evidence_ptrs
           FROM signals
           WHERE {} = ?1
           ORDER BY ts DESC
           LIMIT 50"#,
        column
    );
    
    if let Ok(mut stmt) = conn.prepare(&query) {
        if let Ok(rows) = stmt.query_map([key], |row| {
            Ok(serde_json::json!({
                "signal_id": row.get::<_, String>(0)?,
                "signal_type": row.get::<_, String>(1)?,
                "severity": row.get::<_, String>(2)?,
                "ts": row.get::<_, i64>(3)?,
                "host": row.get::<_, Option<String>>(4)?,
                "proc_key": row.get::<_, Option<String>>(5)?,
                "metadata": row.get::<_, Option<String>>(6)?,
                "evidence_ptrs": row.get::<_, Option<String>>(7)?
            }))
        }) {
            for row in rows.flatten() {
                signals.push(row);
            }
        }
    }
    
    signals
}

/// Helper: Query changes (facts) related to an entity
fn pivot_query_changes(
    conn: &rusqlite::Connection,
    run_id: &str,
    kind: &str,
    key: &str,
    _window_ms: i64,
) -> Vec<serde_json::Value> {
    let mut changes = Vec::new();
    
    // Match entity in fact_key or value_json based on kind
    let (column, search_pattern) = match kind {
        "proc" | "process" => ("fact_key", format!("proc:{}%", key)),
        "file" => ("fact_key", format!("file:{}%", key)),
        "user" => ("value_json", format!("%\"user\":\"{}\"%", key)),
        "host" => ("value_json", format!("%\"host\":\"{}\"%", key)),
        "ip" | "network" => ("value_json", format!("%{}%", key)),
        _ => return changes,
    };
    
    let query = format!(
        r#"SELECT fact_key, fact_type, value_json, ts
           FROM facts
           WHERE run_id = ?1 AND {} LIKE ?2
           ORDER BY ts DESC
           LIMIT 50"#,
        column
    );
    
    if let Ok(mut stmt) = conn.prepare(&query) {
        if let Ok(rows) = stmt.query_map(rusqlite::params![run_id, search_pattern], |row| {
            Ok(serde_json::json!({
                "fact_key": row.get::<_, String>(0)?,
                "fact_type": row.get::<_, String>(1)?,
                "value": row.get::<_, Option<String>>(2)?.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
                "ts": row.get::<_, i64>(3)?
            }))
        }) {
            for row in rows.flatten() {
                changes.push(row);
            }
        }
    }
    
    changes
}

/// Helper: Extract evidence pointers from related findings
fn extract_pivot_evidence(
    _conn: &rusqlite::Connection,
    findings: &[serde_json::Value],
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut evidence_ptrs = Vec::new();
    
    for finding in findings {
        if let Some(ptrs_str) = finding.get("evidence_ptrs").and_then(|v| v.as_str()) {
            if let Ok(ptrs) = serde_json::from_str::<Vec<serde_json::Value>>(ptrs_str) {
                for ptr in ptrs {
                    if evidence_ptrs.len() >= limit {
                        break;
                    }
                    evidence_ptrs.push(serde_json::json!({
                        "signal_id": finding.get("signal_id"),
                        "ptr": ptr
                    }));
                }
            }
        }
        if evidence_ptrs.len() >= limit {
            break;
        }
    }
    
    evidence_ptrs
}

/// Helper: Build mini timeline from findings and changes
fn build_pivot_timeline(
    findings: &[serde_json::Value],
    changes: &[serde_json::Value],
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut timeline: Vec<(i64, serde_json::Value)> = Vec::new();
    
    // Add findings
    for f in findings {
        if let Some(ts) = f.get("ts").and_then(|v| v.as_i64()) {
            timeline.push((ts, serde_json::json!({
                "ts_ms": ts,
                "type": "finding",
                "signal_id": f.get("signal_id"),
                "signal_type": f.get("signal_type"),
                "severity": f.get("severity")
            })));
        }
    }
    
    // Add changes
    for c in changes {
        if let Some(ts) = c.get("ts").and_then(|v| v.as_i64()) {
            timeline.push((ts, serde_json::json!({
                "ts_ms": ts,
                "type": "change",
                "fact_key": c.get("fact_key"),
                "fact_type": c.get("fact_type")
            })));
        }
    }
    
    // Sort by timestamp descending and limit
    timeline.sort_by(|a, b| b.0.cmp(&a.0));
    timeline.truncate(limit);
    
    timeline.into_iter().map(|(_, v)| v).collect()
}

// ============================================================================
// P1 — CLIENT-READY EXPORTS (Case Pack v1) - Pro Tier Only
// ============================================================================

/// Case pack export request body
#[derive(serde::Deserialize)]
struct CasePackRequest {
    include: Option<CasePackInclude>,
    evidence: Option<CasePackEvidence>,
}

#[derive(serde::Deserialize)]
struct CasePackInclude {
    summary: Option<bool>,
    findings: Option<bool>,
    changes: Option<bool>,
    next_steps: Option<bool>,
}

#[derive(serde::Deserialize)]
struct CasePackEvidence {
    include_records: Option<bool>,
    max_records: Option<usize>,
    max_bytes: Option<usize>,
}

/// POST /api/runs/:run_id/export/case_pack - Export client-ready case pack
/// 
/// **Tier Gated**: Requires Pro tier or higher.
async fn export_case_pack_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
    axum::extract::Json(request): axum::extract::Json<CasePackRequest>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    
    // Tier gate: Case Pack Export requires Pro
    if !resolve_current_tier().has_access(ProductTier::Pro) {
        let (status, json) = feature_locked_403("Case Pack Export", ProductTier::Pro);
        return (status, json).into_response();
    }
    
    let run_dir = state.data_dir.join("runs").join(&run_id);
    let db_path = run_dir.join("workbench.db");
    let segments_dir = run_dir.join("segments");
    
    if !db_path.exists() {
        return (axum::http::StatusCode::NOT_FOUND, axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Run '{}' not found", run_id),
            "code": "RUN_NOT_FOUND"
        }))).into_response();
    }
    
    // Parse options with defaults
    let include = request.include.unwrap_or(CasePackInclude {
        summary: Some(true),
        findings: Some(true),
        changes: Some(true),
        next_steps: Some(true),
    });
    
    let evidence_opts = request.evidence.unwrap_or(CasePackEvidence {
        include_records: Some(true),
        max_records: Some(100),
        max_bytes: Some(10_000_000),
    });
    
    let include_summary = include.summary.unwrap_or(true);
    let include_findings = include.findings.unwrap_or(true);
    let include_changes = include.changes.unwrap_or(true);
    let include_next_steps = include.next_steps.unwrap_or(true);
    let include_evidence = evidence_opts.include_records.unwrap_or(true);
    let max_records = evidence_opts.max_records.unwrap_or(100);
    let max_bytes = evidence_opts.max_bytes.unwrap_or(10_000_000);
    
    // Build ZIP in memory
    let mut zip_buffer = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut zip_buffer);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        
        let conn = match open_db_with_wal(&db_path) {
            Ok(c) => c,
            Err(e) => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
                "success": false,
                "error": format!("DB error: {}", e)
            }))).into_response(),
        };
        
        let mut evidence_included_count = 0usize;
        let mut evidence_bytes = 0usize;
        let evidence_available = segments_dir.exists() && segments_dir.is_dir();
        let evidence_reason = if !evidence_available {
            Some("SEGMENTS_NOT_AVAILABLE".to_string())
        } else {
            None
        };
        
        // 1. Case summary
        if include_summary {
            let summary = build_case_pack_summary(&conn, &run_id, &state.data_dir);
            let summary_json = serde_json::to_string_pretty(&summary).unwrap_or_default();
            let _ = zip.start_file("case_summary.json", options);
            let _ = std::io::Write::write_all(&mut zip, summary_json.as_bytes());
        }
        
        // 2. Findings
        if include_findings {
            let findings = build_case_pack_findings(&conn);
            let findings_json = serde_json::to_string_pretty(&findings).unwrap_or_default();
            let _ = zip.start_file("findings.json", options);
            let _ = std::io::Write::write_all(&mut zip, findings_json.as_bytes());
        }
        
        // 3. Changes with novelty
        if include_changes {
            let changes = build_case_pack_changes(&conn, &run_id);
            let changes_json = serde_json::to_string_pretty(&changes).unwrap_or_default();
            let _ = zip.start_file("changes.json", options);
            let _ = std::io::Write::write_all(&mut zip, changes_json.as_bytes());
        }
        
        // 4. Next steps
        if include_next_steps {
            let top_signals = get_top_signals_for_run(&db_path, 10);
            let signal_count: i64 = conn.query_row("SELECT COUNT(*) FROM signals", [], |row| row.get(0)).unwrap_or(0);
            let next_steps = build_next_steps(&top_signals, signal_count as usize);
            let next_steps_json = serde_json::to_string_pretty(&serde_json::json!({
                "next_steps": next_steps
            })).unwrap_or_default();
            let _ = zip.start_file("next_steps.json", options);
            let _ = std::io::Write::write_all(&mut zip, next_steps_json.as_bytes());
        }
        
        // 5. Evidence records (if available and requested)
        if include_evidence && evidence_available {
            // Get evidence pointers from signals
            let ptrs = get_all_evidence_pointers(&conn, max_records);
            
            for ptr in ptrs {
                if evidence_bytes >= max_bytes {
                    break;
                }
                
                // Try to dereference the evidence
                if let Some(segment_id) = ptr.get("segment_id").and_then(|v| v.as_str()) {
                    let segment_file = segments_dir.join(format!("{}.jsonl", segment_id));
                    if segment_file.exists() {
                        if let Ok(content) = std::fs::read_to_string(&segment_file) {
                            // Extract just the relevant record if offset is specified
                            let record = if let Some(offset) = ptr.get("offset").and_then(|v| v.as_u64()) {
                                content.lines().nth(offset as usize).unwrap_or(&content).to_string()
                            } else {
                                // Take first line as sample
                                content.lines().next().unwrap_or("").to_string()
                            };
                            
                            if evidence_bytes + record.len() <= max_bytes {
                                let record_path = format!("evidence/records/{}_{}.json", segment_id, evidence_included_count);
                                let _ = zip.start_file(&record_path, options);
                                let _ = std::io::Write::write_all(&mut zip, record.as_bytes());
                                evidence_included_count += 1;
                                evidence_bytes += record.len();
                            }
                        }
                    }
                }
            }
        }
        
        // 6. Manifest (always included)
        let manifest = serde_json::json!({
            "contract_version": "1.0.0",
            "schema_version": "1.0.0",
            "run_id": run_id,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "limits": {
                "max_records": max_records,
                "max_bytes": max_bytes
            },
            "evidence_included_count": evidence_included_count,
            "evidence_bytes_total": evidence_bytes,
            "evidence_available": evidence_available,
            "evidence_unavailable_reason": evidence_reason,
            "contents": {
                "summary": include_summary,
                "findings": include_findings,
                "changes": include_changes,
                "next_steps": include_next_steps,
                "evidence_records": include_evidence && evidence_available
            }
        });
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap_or_default();
        let _ = zip.start_file("manifest.json", options);
        let _ = std::io::Write::write_all(&mut zip, manifest_json.as_bytes());
        
        let _ = zip.finish();
    }
    
    // Return ZIP as download
    let filename = format!("case_pack_{}_{}.zip", run_id, chrono::Utc::now().format("%Y%m%d_%H%M%S"));
    
    (
        axum::http::StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/zip"),
            (axum::http::header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}\"", filename)),
        ],
        zip_buffer
    ).into_response()
}

/// Helper: Build case pack summary
fn build_case_pack_summary(
    conn: &rusqlite::Connection,
    run_id: &str,
    data_dir: &std::path::Path,
) -> serde_json::Value {
    let meta_path = data_dir.join("runs").join(run_id).join("run_meta.json");
    let (started_at, stopped_at, status) = read_run_meta(&meta_path, run_id);
    
    let events: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0)).unwrap_or(0);
    let facts: i64 = conn.query_row("SELECT COUNT(*) FROM facts WHERE run_id = ?1", [run_id], |row| row.get(0)).unwrap_or(0);
    let signals: i64 = conn.query_row("SELECT COUNT(*) FROM signals", [], |row| row.get(0)).unwrap_or(0);
    
    serde_json::json!({
        "run_id": run_id,
        "started_at": started_at.map(|t| t.to_rfc3339()),
        "stopped_at": stopped_at.map(|t| t.to_rfc3339()),
        "status": status,
        "events_total": events,
        "facts_extracted": facts,
        "signals_count": signals,
        "generated_at": chrono::Utc::now().to_rfc3339()
    })
}

/// Helper: Build case pack findings with explanations
fn build_case_pack_findings(conn: &rusqlite::Connection) -> serde_json::Value {
    let mut findings = Vec::new();
    
    let query = r#"
        SELECT signal_id, signal_type, severity, ts, host, proc_key, file_key, identity_key,
               detector_id, metadata, evidence_ptrs
        FROM signals
        ORDER BY ts DESC
        LIMIT 100
    "#;
    
    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([], |row| {
            let signal_id: String = row.get(0)?;
            let signal_type: String = row.get(1)?;
            let severity: String = row.get(2)?;
            let ts: i64 = row.get(3)?;
            let host: Option<String> = row.get(4)?;
            let proc_key: Option<String> = row.get(5)?;
            let file_key: Option<String> = row.get(6)?;
            let identity_key: Option<String> = row.get(7)?;
            let detector_id: String = row.get(8)?;
            let metadata: Option<String> = row.get(9)?;
            let evidence_ptrs: Option<String> = row.get(10)?;
            
            let meta: serde_json::Value = metadata
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::json!({}));
            
            let evidence: Vec<serde_json::Value> = evidence_ptrs
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            
            Ok(serde_json::json!({
                "signal_id": signal_id,
                "signal_type": signal_type,
                "severity": severity,
                "ts": ts,
                "host": host,
                "entities": {
                    "proc_key": proc_key,
                    "file_key": file_key,
                    "identity_key": identity_key
                },
                "detector_id": detector_id,
                "title": meta.get("title"),
                "rule_id": meta.get("rule_id"),
                "playbook_id": meta.get("playbook_id"),
                "evidence_ptr_count": evidence.len(),
                "has_evidence": !evidence.is_empty()
            }))
        }) {
            for row in rows.flatten() {
                findings.push(row);
            }
        }
    }
    
    serde_json::json!({
        "findings": findings,
        "total_count": findings.len()
    })
}

/// Helper: Build case pack changes with novelty markers
fn build_case_pack_changes(
    conn: &rusqlite::Connection,
    run_id: &str,
) -> serde_json::Value {
    let mut changes = Vec::new();
    
    let query = r#"
        SELECT fact_key, fact_type, value_json, ts
        FROM facts
        WHERE run_id = ?1
        ORDER BY ts DESC
        LIMIT 200
    "#;
    
    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([run_id], |row| {
            let fact_key: String = row.get(0)?;
            let fact_type: String = row.get(1)?;
            let value_json: Option<String> = row.get(2)?;
            let ts: i64 = row.get(3)?;
            
            // Compute novelty (simplified - in production would check against baseline)
            let novelty = "new"; // Default to new if no baseline comparison
            let novelty_basis = "first_appearance";
            
            Ok(serde_json::json!({
                "fact_key": fact_key,
                "fact_type": fact_type,
                "value": value_json.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
                "ts": ts,
                "novelty": novelty,
                "novelty_basis": novelty_basis
            }))
        }) {
            for row in rows.flatten() {
                changes.push(row);
            }
        }
    }
    
    serde_json::json!({
        "changes": changes,
        "total_count": changes.len()
    })
}

/// Helper: Get all evidence pointers from signals
fn get_all_evidence_pointers(
    conn: &rusqlite::Connection,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut pointers = Vec::new();
    
    let query = "SELECT evidence_ptrs FROM signals WHERE evidence_ptrs IS NOT NULL AND evidence_ptrs != '[]' LIMIT 100";
    
    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([], |row| {
            let ptrs_str: String = row.get(0)?;
            Ok(ptrs_str)
        }) {
            for row in rows.flatten() {
                if let Ok(ptrs) = serde_json::from_str::<Vec<serde_json::Value>>(&row) {
                    for ptr in ptrs {
                        if pointers.len() >= limit {
                            return pointers;
                        }
                        pointers.push(ptr);
                    }
                }
            }
        }
    }
    
    pointers
}

/// Read run metadata from run_meta.json (authoritative source)
/// Falls back to run_id parsing if file doesn't exist or is invalid
fn read_run_meta(meta_path: &std::path::Path, run_id: &str) -> (
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
    String,
) {
    use chrono::DateTime;
    
    if let Ok(contents) = std::fs::read_to_string(meta_path) {
        if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&contents) {
            let started_at = meta["started_at"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));
            
            let stopped_at = meta["stopped_at"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));
            
            let status = meta["status"]
                .as_str()
                .unwrap_or(if stopped_at.is_some() { "completed" } else { "running" })
                .to_string();
            
            // If we got valid timestamps from run_meta.json, use them
            if started_at.is_some() {
                return (started_at, stopped_at, status);
            }
        }
    }
    
    // FALLBACK: Parse from run_id (backwards compatibility)
    let started_at = parse_run_id_timestamp(run_id);
    let status = if meta_path.with_file_name("workbench.db").exists() {
        "completed".to_string()
    } else {
        "unknown".to_string()
    };
    
    (started_at, None, status)
}

/// Parse run_id to extract timestamp
/// Supports formats:
/// - run_YYYYMMDD_HHMMSS (e.g., run_20260115_143022)
/// - run_YYYYMMDD_HHMMSS_label (e.g., run_20260115_143022_mytest)
fn parse_run_id_timestamp(run_id: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDateTime, TimeZone, Utc};
    
    // Expected format: run_YYYYMMDD_HHMMSS or run_YYYYMMDD_HHMMSS_label
    if !run_id.starts_with("run_") {
        return None;
    }
    
    let after_prefix = &run_id[4..]; // Skip "run_"
    let parts: Vec<&str> = after_prefix.split('_').collect();
    
    if parts.len() >= 2 {
        let date_part = parts[0]; // YYYYMMDD
        let time_part = parts[1]; // HHMMSS or HHMMSS...
        
        if date_part.len() == 8 && time_part.len() >= 6 {
            let time_part = &time_part[..6.min(time_part.len())];
            let datetime_str = format!("{}{}", date_part, time_part);
            if let Ok(naive) = NaiveDateTime::parse_from_str(&datetime_str, "%Y%m%d%H%M%S") {
                return Some(Utc.from_utc_datetime(&naive));
            }
        }
    }
    None
}

/// Read statistics from a run's workbench.db
fn read_run_stats(db_path: &std::path::Path) -> (u64, u32, u64, usize, i64, i64, Option<chrono::DateTime<chrono::Utc>>) {
    use chrono::{TimeZone, Utc};
    
    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return (0, 0, 0, 0, 0, 0, None),
    };
    
    // Count events (from events or process_events table)
    let events: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .or_else(|_| conn.query_row("SELECT COUNT(*) FROM process_events", [], |r| r.get(0)))
        .unwrap_or(0);
    
    // Count segments
    let segments: u32 = conn
        .query_row("SELECT COUNT(*) FROM segments", [], |r| r.get(0))
        .unwrap_or(0);
    
    // Count facts (from coverage_rollup or facts table)
    let facts: u64 = conn
        .query_row("SELECT SUM(fact_count) FROM coverage_rollup", [], |r| r.get::<_, Option<i64>>(0))
        .ok()
        .flatten()
        .map(|v| v as u64)
        .unwrap_or_else(|| {
            conn.query_row("SELECT COUNT(*) FROM facts", [], |r| r.get(0))
                .unwrap_or(0)
        });
    
    // Count signals
    let signals: usize = conn
        .query_row("SELECT COUNT(*) FROM signals", [], |r| r.get::<_, i64>(0))
        .map(|v| v as usize)
        .unwrap_or(0);
    
    // Get earliest/latest timestamps from signals
    let earliest_ts: i64 = conn
        .query_row("SELECT MIN(ts) FROM signals", [], |r| r.get(0))
        .unwrap_or(0);
    let latest_ts: i64 = conn
        .query_row("SELECT MAX(ts) FROM signals", [], |r| r.get(0))
        .unwrap_or(0);
    
    // Try to get stopped_at from run_info table or derive from latest_ts
    let stopped_at = if latest_ts > 0 {
        Some(Utc.timestamp_millis_opt(latest_ts).single().unwrap_or_else(|| Utc::now()))
    } else {
        None
    };
    
    (events, segments, facts, signals, earliest_ts, latest_ts, stopped_at)
}

async fn run_coverage_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let run_dir = state.data_dir.join("runs").join(&run_id);
    let db_path = run_dir.join("workbench.db");
    
    // Load readiness snapshot from run_meta.json (explains missing telemetry)
    let readiness_snapshot = {
        let meta_path = run_dir.join("run_meta.json");
        if let Ok(contents) = std::fs::read_to_string(&meta_path) {
            serde_json::from_str::<serde_json::Value>(&contents)
                .ok()
                .and_then(|v| v.get("readiness_snapshot").cloned())
        } else {
            None
        }
    };
    
    if !db_path.exists() {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason": "workbench.db not found",
                "run_id": run_id,
                "readiness_snapshot": readiness_snapshot,
            }
        }));
    }
    
    match open_db_with_wal(&db_path) {
        Ok(conn) => {
            // Get facts count from coverage_rollup
            let facts_count: i64 = conn
                .query_row("SELECT COALESCE(SUM(fact_count), 0) FROM coverage_rollup", [], |r| r.get(0))
                .unwrap_or(0);
            let coverage_rows: i64 = conn
                .query_row("SELECT COUNT(*) FROM coverage_rollup", [], |r| r.get(0))
                .unwrap_or(0);
            let signals_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM signals", [], |r| r.get(0))
                .unwrap_or(0);
            
            // Get fact types breakdown
            let mut fact_types: Vec<serde_json::Value> = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT fact_type, SUM(fact_count) as total FROM coverage_rollup GROUP BY fact_type ORDER BY total DESC"
            ) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?))
                }) {
                    for row in rows.flatten() {
                        if let (Some(ft), count) = row {
                            fact_types.push(serde_json::json!({
                                "fact_type": ft,
                                "count": count
                            }));
                        }
                    }
                }
            }
            
            // Get hosts list
            let mut hosts: Vec<String> = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT DISTINCT host FROM coverage_rollup WHERE host IS NOT NULL"
            ) {
                if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                    for host in rows.flatten() {
                        hosts.push(host);
                    }
                }
            }
            
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": true,
                    "run_id": run_id,
                    "facts_total": facts_count,
                    "coverage_rows": coverage_rows,
                    "signals_count": signals_count,
                    "fact_types": fact_types,
                    "top_hosts": hosts,
                    "readiness_snapshot": readiness_snapshot,
                }
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": format!("DB error: {}", e),
            "code": "DB_ERROR",
            "data": {
                "available": false,
                "reason": format!("DB error: {}", e),
                "run_id": run_id,
                "readiness_snapshot": readiness_snapshot,
            }
        })),
    }
}

// ============================================================================
// Run State Handler - Part A: System State Summary (Layer 1 Explainability)
// ============================================================================

/// GET /api/runs/:id/state - Comprehensive run state for "System State Summary"
/// Returns: readiness_snapshot, telemetry_status, sensors, fact distribution, top entities, notes
async fn run_state_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let run_dir = state.data_dir.join("runs").join(&run_id);
    let db_path = run_dir.join("workbench.db");
    
    // Load readiness snapshot from run_meta.json
    let (readiness_snapshot, run_phase) = {
        let meta_path = run_dir.join("run_meta.json");
        if let Ok(contents) = std::fs::read_to_string(&meta_path) {
            let v: serde_json::Value = serde_json::from_str(&contents).unwrap_or_default();
            let snapshot = v.get("readiness_snapshot").cloned().unwrap_or(serde_json::json!({}));
            let finalized = v.get("finalized").and_then(|f| f.as_bool()).unwrap_or(false);
            let phase = if finalized { "finalized" } else { "active" };
            (snapshot, phase.to_string())
        } else {
            (serde_json::json!({}), "unknown".to_string())
        }
    };
    
    // Derive telemetry status and issues from readiness_snapshot
    let is_admin = readiness_snapshot.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
    let sysmon_installed = readiness_snapshot.get("sysmon_installed").and_then(|v| v.as_bool()).unwrap_or(false);
    let security_log_accessible = readiness_snapshot.get("security_log_accessible").and_then(|v| v.as_bool()).unwrap_or(is_admin);
    
    let telemetry_status = if security_log_accessible && sysmon_installed {
        "full"
    } else if security_log_accessible || sysmon_installed {
        "partial"
    } else {
        "limited"
    };
    
    let mut telemetry_issues: Vec<String> = Vec::new();
    if !security_log_accessible {
        telemetry_issues.push("No Security log access → no Auth facts".to_string());
    }
    if !sysmon_installed {
        telemetry_issues.push("Sysmon missing → limited detection primitives".to_string());
    }
    
    // Build notes from issues
    let notes = telemetry_issues.clone();
    
    if !db_path.exists() {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": "NO_DB",
                "message": "No workbench.db found for this run",
                "run_id": run_id,
                "run_phase": run_phase,
                "readiness_snapshot": readiness_snapshot,
                "telemetry_status": telemetry_status,
                "telemetry_issues": telemetry_issues,
            }
        }));
    }
    
    match open_db_with_wal(&db_path) {
        Ok(conn) => {
            // Get facts count
            let facts_total: i64 = conn
                .query_row("SELECT COALESCE(SUM(fact_count), 0) FROM coverage_rollup", [], |r| r.get(0))
                .unwrap_or(0);
            let signals_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM signals", [], |r| r.get(0))
                .unwrap_or(0);
            
            // Get fact types breakdown
            let mut fact_types: Vec<serde_json::Value> = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT fact_type, SUM(fact_count) as total FROM coverage_rollup WHERE fact_type IS NOT NULL GROUP BY fact_type ORDER BY total DESC"
            ) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                }) {
                    for row in rows.flatten() {
                        fact_types.push(serde_json::json!({
                            "fact_type": row.0,
                            "count": row.1
                        }));
                    }
                }
            }
            
            // Get top entities from entity_rollup table
            let mut top_entities: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
            
            // Top processes
            let mut processes: Vec<serde_json::Value> = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT entity_key, fact_count FROM entity_rollup WHERE run_id = ?1 AND entity_type = 'process' ORDER BY fact_count DESC LIMIT 10"
            ) {
                if let Ok(rows) = stmt.query_map([&run_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                }) {
                    for row in rows.flatten() {
                        processes.push(serde_json::json!({"entity_key": row.0, "fact_count": row.1}));
                    }
                }
            }
            top_entities.insert("processes".to_string(), serde_json::json!(processes));
            
            // Top users
            let mut users: Vec<serde_json::Value> = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT entity_key, fact_count FROM entity_rollup WHERE run_id = ?1 AND entity_type = 'user' ORDER BY fact_count DESC LIMIT 10"
            ) {
                if let Ok(rows) = stmt.query_map([&run_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                }) {
                    for row in rows.flatten() {
                        users.push(serde_json::json!({"entity_key": row.0, "fact_count": row.1}));
                    }
                }
            }
            top_entities.insert("users".to_string(), serde_json::json!(users));
            
            // Top hosts
            let mut hosts: Vec<serde_json::Value> = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT entity_key, fact_count FROM entity_rollup WHERE run_id = ?1 AND entity_type = 'host' ORDER BY fact_count DESC LIMIT 10"
            ) {
                if let Ok(rows) = stmt.query_map([&run_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                }) {
                    for row in rows.flatten() {
                        hosts.push(serde_json::json!({"entity_key": row.0, "fact_count": row.1}));
                    }
                }
            }
            top_entities.insert("hosts".to_string(), serde_json::json!(hosts));
            
            // Top network destinations
            let mut network: Vec<serde_json::Value> = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT entity_key, fact_count FROM entity_rollup WHERE run_id = ?1 AND entity_type = 'network' ORDER BY fact_count DESC LIMIT 10"
            ) {
                if let Ok(rows) = stmt.query_map([&run_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                }) {
                    for row in rows.flatten() {
                        network.push(serde_json::json!({"entity_key": row.0, "fact_count": row.1}));
                    }
                }
            }
            top_entities.insert("network".to_string(), serde_json::json!(network));
            
            // Build sensors list (synthetic, based on available data)
            // UI expects: name, status (available|unavailable|unknown)
            let mut sensors: Vec<serde_json::Value> = Vec::new();
            sensors.push(serde_json::json!({
                "name": "System Log",
                "status": "available",
                "fact_count": facts_total
            }));
            if security_log_accessible {
                sensors.push(serde_json::json!({
                    "name": "Security Log",
                    "status": "available",
                    "fact_count": 0
                }));
            } else {
                sensors.push(serde_json::json!({
                    "name": "Security Log",
                    "status": "unavailable",
                    "blocked_reason": "Not running as Administrator"
                }));
            }
            if sysmon_installed {
                sensors.push(serde_json::json!({
                    "name": "Sysmon",
                    "status": "available",
                    "fact_count": 0
                }));
            } else {
                sensors.push(serde_json::json!({
                    "name": "Sysmon",
                    "status": "unavailable",
                    "blocked_reason": "Sysmon is not installed"
                }));
            }
            
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": true,
                    "run_id": run_id,
                    "run_phase": run_phase,
                    "readiness_snapshot": readiness_snapshot,
                    "telemetry_status": telemetry_status,
                    "telemetry_issues": telemetry_issues,
                    "sensors": sensors,
                    "facts_total": facts_total,
                    "signals_count": signals_count,
                    "fact_types": fact_types,
                    "top_entities": top_entities,
                    "notes": notes,
                }
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": format!("DB error: {}", e),
            "data": {
                "available": false,
                "reason_code": "DB_ERROR",
                "message": format!("Database error: {}", e),
                "run_id": run_id,
            }
        })),
    }
}

// ============================================================================
// Run Changes Handler - Layer 1 Explainability (What Changed)
// ============================================================================

/// Categorize a fact_type into a high-level change category
fn categorize_fact_type(fact_type: &str) -> &'static str {
    match fact_type.to_lowercase().as_str() {
        // Process-related
        "exec" | "processexec" | "processcreate" | "processexit" | "moduleload" | "memread" => "Process",
        // File operations
        "fileop" | "filecreate" | "filedelete" | "filemodify" | "fileaccess" => "Files",
        // Network activity
        "netconn" | "networkconnection" | "dnsquery" | "dns" => "Network",
        // Persistence mechanisms
        "persistartifact" | "servicecreate" | "schedtask" | "regop" | "registryop" | "wmiop" => "Persistence",
        // Authentication
        "authevent" | "authlogon" | "logon" | "logoff" | "authfailure" => "Auth",
        // Defense evasion / tampering
        "logtamper" | "defenseevasion" | "securityevasion" => "Evasion",
        // Default
        _ => "Other",
    }
}

/// Deterministic severity heuristic based on category, fact_type, and context
/// Returns (severity, severity_basis) tuple
fn compute_severity(category: &str, fact_type: &str, has_signal: bool, evidence_count: usize) -> (&'static str, String) {
    // Base severity from category (Persistence/Evasion are inherently higher risk)
    let (base_severity, category_weight) = match category {
        "Persistence" => ("high", 3),
        "Evasion" => ("high", 3),
        "Auth" => ("medium", 2),
        "Network" => ("medium", 2),
        "Process" => ("low", 1),
        "Files" => ("low", 1),
        _ => ("info", 0),
    };
    
    // Fact-type specific escalations
    let fact_bump = match fact_type.to_lowercase().as_str() {
        // Critical indicators
        "logtamper" | "defenseevasion" => 2,
        "servicecreate" | "schedtask" | "wmiop" => 1,
        "memread" => 1, // Process injection indicator
        // Network indicators
        "dnsquery" => 0, // DNS alone is not high
        "netconn" => 0,
        // Auth indicators  
        "authfailure" => 1, // Failed auth is more interesting
        _ => 0,
    };
    
    // Context modifiers
    let signal_bump = if has_signal { 1 } else { 0 };
    let evidence_bump = if evidence_count >= 3 { 1 } else { 0 };
    
    let total_score = category_weight + fact_bump + signal_bump + evidence_bump;
    
    // Map score to severity
    let (severity, basis_reason) = match total_score {
        0..=1 => ("info", format!("{} activity", category)),
        2 => ("low", format!("{} change", category)),
        3 => ("medium", format!("{} modification", category)),
        4 => ("high", format!("{} indicator", category)),
        _ => ("critical", format!("Critical {} change", category)),
    };
    
    // Build detailed basis
    let basis = if has_signal {
        format!("{} (signal correlated)", basis_reason)
    } else if evidence_bump > 0 {
        format!("{} ({}+ evidence)", basis_reason, evidence_count)
    } else {
        basis_reason
    };
    
    (severity, basis)
}

/// Map severity from signal severity to a hint level
fn severity_hint_from_signal(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" | "crit" => "critical",
        "high" => "high",
        "medium" | "med" => "medium",
        "low" | "info" | "informational" => "low",
        _ => "info",
    }
}

/// GET /api/runs/:run_id/changes - List categorized system changes for a run
async fn run_changes_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let run_dir = state.data_dir.join("runs").join(&run_id);
    let db_path = run_dir.join("workbench.db");
    
    if !db_path.exists() {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason": "workbench.db not found",
                "run_id": run_id,
                "highlights": [],
                "categories": {},
                "stats": { "total_changes": 0, "fact_types": 0, "hosts": 0 }
            }
        }));
    }
    
    match open_db_with_wal(&db_path) {
        Ok(conn) => {
            // Build changes from coverage_rollup or facts tables
            let mut changes: Vec<serde_json::Value> = Vec::new();
            let mut categories: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
            let mut hosts: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut fact_types: std::collections::HashSet<String> = std::collections::HashSet::new();
            
            // First try coverage_rollup (aggregated facts)
            let has_coverage = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='coverage_rollup'",
                [],
                |r| r.get::<_, i64>(0)
            ).unwrap_or(0) > 0;
            
            if has_coverage {
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT ts_minute, host, fact_type, fact_count, signal_type, signal_count, enabled_capabilities 
                     FROM coverage_rollup 
                     ORDER BY ts_minute DESC 
                     LIMIT 200"
                ) {
                    if let Ok(rows) = stmt.query_map([], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,           // ts_minute
                            row.get::<_, String>(1)?,        // host
                            row.get::<_, Option<String>>(2)?, // fact_type
                            row.get::<_, i64>(3)?,            // fact_count
                            row.get::<_, Option<String>>(4)?, // signal_type
                            row.get::<_, i64>(5)?,            // signal_count
                            row.get::<_, Option<String>>(6)?, // enabled_capabilities
                        ))
                    }) {
                        let mut idx = 0u32;
                        for row in rows.flatten() {
                            let (ts_minute, host, fact_type, fact_count, signal_type, signal_count, _capabilities) = row;
                            
                            hosts.insert(host.clone());
                            
                            if let Some(ref ft) = fact_type {
                                if fact_count > 0 {
                                    fact_types.insert(ft.clone());
                                    let category = categorize_fact_type(ft);
                                    *categories.entry(category.to_string()).or_insert(0) += fact_count;
                                    
                                    // Deterministic severity computation
                                    let has_signal = signal_count > 0;
                                    let (severity, severity_basis) = compute_severity(category, ft, has_signal, 0);
                                    let change_id = format!("chg_{}_{}", ts_minute, idx);
                                    idx += 1;
                                    
                                    let title = format!("{} activity detected", ft);
                                    let summary = format!("{} {} events on {}", fact_count, ft, host);
                                    
                                    // Coverage rollup has no direct evidence - note this
                                    changes.push(serde_json::json!({
                                        "change_id": change_id,
                                        "ts": ts_minute * 60 * 1000, // Convert minutes to ms
                                        "category": category,
                                        "title": title,
                                        "summary": summary,
                                        "entities": {
                                            "host": host,
                                            "fact_type": ft,
                                        },
                                        "evidence": [],
                                        "evidence_unavailable_reason": "Aggregated from coverage_rollup (no per-event evidence)",
                                        "supporting_facts_count": fact_count,
                                        "severity": severity,
                                        "severity_basis": severity_basis,
                                        "related_signal_type": signal_type,
                                    }));
                                }
                            }
                        }
                    }
                }
            }
            
            // Also try facts table directly (more detailed)
            let has_facts = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='facts'",
                [],
                |r| r.get::<_, i64>(0)
            ).unwrap_or(0) > 0;
            
            if has_facts && changes.len() < 50 {
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT fact_id, host_id, ts, fact_type, domain, evidence_ptrs, fact_json 
                     FROM facts 
                     ORDER BY ts DESC 
                     LIMIT 100"
                ) {
                    if let Ok(rows) = stmt.query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,  // fact_id
                            row.get::<_, String>(1)?,  // host_id
                            row.get::<_, i64>(2)?,     // ts
                            row.get::<_, String>(3)?,  // fact_type
                            row.get::<_, String>(4)?,  // domain
                            row.get::<_, String>(5)?,  // evidence_ptrs (JSON)
                            row.get::<_, String>(6)?,  // fact_json
                        ))
                    }) {
                        for row in rows.flatten() {
                            let (fact_id, host_id, ts, fact_type, domain, evidence_ptrs_json, fact_json_str) = row;
                            
                            hosts.insert(host_id.clone());
                            fact_types.insert(fact_type.clone());
                            
                            let category = categorize_fact_type(&fact_type);
                            *categories.entry(category.to_string()).or_insert(0) += 1;
                            
                            // Parse evidence pointers
                            let evidence: Vec<serde_json::Value> = serde_json::from_str(&evidence_ptrs_json)
                                .unwrap_or_default();
                            
                            // Parse fact JSON for summary
                            let fact_data: serde_json::Value = serde_json::from_str(&fact_json_str)
                                .unwrap_or(serde_json::json!({}));
                            
                            // Build summary from fact data
                            let summary = if let Some(obj) = fact_data.as_object() {
                                // Try to extract a meaningful summary
                                let proc = obj.get("process_name").or(obj.get("exe_path"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let target = obj.get("target_path").or(obj.get("dest_ip")).or(obj.get("file_path"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                if !proc.is_empty() && !target.is_empty() {
                                    format!("{} → {}", proc, target)
                                } else if !proc.is_empty() {
                                    proc.to_string()
                                } else {
                                    format!("{} on {}", fact_type, host_id)
                                }
                            } else {
                                format!("{} on {}", fact_type, host_id)
                            };
                            
                            // Deterministic severity computation
                            let (severity, severity_basis) = compute_severity(category, &fact_type, false, evidence.len());
                            
                            let mut change_item = serde_json::json!({
                                "change_id": fact_id,
                                "ts": ts,
                                "category": category,
                                "title": format!("{}: {}", domain, fact_type),
                                "summary": summary,
                                "entities": {
                                    "host": host_id,
                                    "fact_type": fact_type,
                                    "domain": domain,
                                },
                                "evidence": evidence,
                                "supporting_facts_count": 1,
                                "severity": severity,
                                "severity_basis": severity_basis,
                            });
                            
                            // Add evidence_unavailable_reason if no evidence
                            if evidence.is_empty() {
                                change_item.as_object_mut().unwrap().insert(
                                    "evidence_unavailable_reason".to_string(),
                                    serde_json::json!("Fact stored without evidence pointers")
                                );
                            }
                            
                            changes.push(change_item);
                        }
                    }
                }
            }
            
            // If still no changes, try to build from signals
            if changes.is_empty() {
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT signal_id, signal_type, severity, ts, host, evidence_ptrs 
                     FROM signals 
                     ORDER BY ts DESC 
                     LIMIT 100"
                ) {
                    if let Ok(rows) = stmt.query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,  // signal_id
                            row.get::<_, String>(1)?,  // signal_type
                            row.get::<_, String>(2)?,  // severity
                            row.get::<_, i64>(3)?,     // ts
                            row.get::<_, Option<String>>(4)?, // host
                            row.get::<_, Option<String>>(5)?, // evidence_ptrs
                        ))
                    }) {
                        for row in rows.flatten() {
                            let (signal_id, signal_type, severity, ts, host, evidence_ptrs_json) = row;
                            
                            if let Some(ref h) = host {
                                hosts.insert(h.clone());
                            }
                            
                            // Map signal_type to category
                            let category = categorize_fact_type(&signal_type);
                            *categories.entry(category.to_string()).or_insert(0) += 1;
                            
                            let evidence: Vec<serde_json::Value> = evidence_ptrs_json
                                .and_then(|s| serde_json::from_str(&s).ok())
                                .unwrap_or_default();
                            
                            // Use signal severity directly with basis
                            let signal_severity = severity_hint_from_signal(&severity);
                            let severity_basis = format!("Signal severity: {}", severity);
                            
                            let mut change_item = serde_json::json!({
                                "change_id": signal_id.clone(),
                                "ts": ts,
                                "category": category,
                                "title": format!("Signal: {}", signal_type),
                                "summary": format!("{} detected on {}", signal_type, host.as_deref().unwrap_or("unknown")),
                                "entities": {
                                    "host": host,
                                    "signal_type": signal_type,
                                },
                                "evidence": evidence,
                                "supporting_facts_count": evidence.len(),
                                "severity": signal_severity,
                                "severity_basis": severity_basis,
                            });
                            
                            // Add evidence_unavailable_reason if no evidence
                            if evidence.is_empty() {
                                change_item.as_object_mut().unwrap().insert(
                                    "evidence_unavailable_reason".to_string(),
                                    serde_json::json!("Signal stored without evidence pointers")
                                );
                            }
                            
                            changes.push(change_item);
                        }
                    }
                }
            }
            
            // Sort changes by severity (critical first) then by timestamp
            changes.sort_by(|a, b| {
                let sev_order = |s: &str| match s {
                    "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4
                };
                let a_sev = a.get("severity").and_then(|v| v.as_str()).unwrap_or("info");
                let b_sev = b.get("severity").and_then(|v| v.as_str()).unwrap_or("info");
                let a_ts = a.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
                let b_ts = b.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
                
                sev_order(a_sev).cmp(&sev_order(b_sev))
                    .then(b_ts.cmp(&a_ts)) // Newer first
            });
            
            // Highlights: only include items with evidence OR evidence_unavailable_reason
            // Filter top changes that have evidence or a valid reason
            let highlights: Vec<serde_json::Value> = changes.iter()
                .filter(|c| {
                    let has_evidence = c.get("evidence")
                        .and_then(|e| e.as_array())
                        .map(|arr| !arr.is_empty())
                        .unwrap_or(false);
                    let has_reason = c.get("evidence_unavailable_reason").is_some();
                    has_evidence || has_reason
                })
                .take(5)
                .cloned()
                .collect();
            
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": true,
                    "run_id": run_id,
                    "highlights": highlights,
                    "changes": changes,
                    "categories": categories,
                    "stats": {
                        "total_changes": changes.len(),
                        "fact_types": fact_types.len(),
                        "hosts": hosts.len(),
                    }
                }
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": format!("DB error: {}", e),
            "code": "DB_ERROR",
            "data": {
                "available": false,
                "reason": format!("DB error: {}", e),
                "run_id": run_id,
                "highlights": [],
                "categories": {},
                "stats": { "total_changes": 0, "fact_types": 0, "hosts": 0 }
            }
        })),
    }
}

// ============================================================================
// Diff v2 - Deterministic, Evidence-Backed Change Detection
// ============================================================================

/// Canonical Change object for Diff v2
/// All fields are deterministic, evidence-backed where possible
#[derive(Debug, Clone, serde::Serialize)]
struct DiffChange {
    /// Stable unique identifier: category_direction_stablekey_hash
    change_id: String,
    /// Timestamp (ms) or window start
    ts_ms: i64,
    /// Optional window end for aggregated changes
    ts_end_ms: Option<i64>,
    /// High-level category
    category: DiffCategory,
    /// Direction of change
    direction: DiffDirection,
    /// Human-readable title
    title: String,
    /// Detailed summary
    summary: String,
    /// Entities involved (host, proc_key, user, etc.)
    entities: DiffEntities,
    /// Deterministic severity
    severity: String,
    /// Explanation for severity
    severity_basis: String,
    /// Evidence pointers (if available)
    evidence_ptrs: Vec<serde_json::Value>,
    /// Why evidence is unavailable (if no evidence_ptrs)
    evidence_unavailable_reason: Option<String>,
    /// Number of facts supporting this change
    supporting_facts_count: i64,
    /// Stable key used for diff matching
    stable_key: String,
    /// P0 Baseline Noise Killer: Novelty classification
    /// "new" | "known" | "changed" | "reappeared"
    novelty: Option<String>,
    /// Explanation for novelty classification
    novelty_basis: Option<String>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DiffCategory {
    Process,
    Persistence,
    Auth,
    Network,
    Evasion,
    File,
    Other,
}

impl DiffCategory {
    fn from_fact_type(fact_type: &str) -> Self {
        match fact_type.to_lowercase().as_str() {
            "exec" | "processexec" | "processcreate" | "processexit" | "moduleload" | "memread" => DiffCategory::Process,
            "fileop" | "filecreate" | "filedelete" | "filemodify" | "fileaccess" => DiffCategory::File,
            "netconn" | "networkconnection" | "dnsquery" | "dns" => DiffCategory::Network,
            "persistartifact" | "servicecreate" | "schedtask" | "regop" | "registryop" | "wmiop" => DiffCategory::Persistence,
            "authevent" | "authlogon" | "logon" | "logoff" | "authfailure" => DiffCategory::Auth,
            "logtamper" | "defenseevasion" | "securityevasion" => DiffCategory::Evasion,
            _ => DiffCategory::Other,
        }
    }
    
    fn as_str(&self) -> &'static str {
        match self {
            DiffCategory::Process => "Process",
            DiffCategory::Persistence => "Persistence",
            DiffCategory::Auth => "Auth",
            DiffCategory::Network => "Network",
            DiffCategory::Evasion => "Evasion",
            DiffCategory::File => "File",
            DiffCategory::Other => "Other",
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DiffDirection {
    Added,
    Removed,
    Increased,
    Decreased,
    Modified,
}

impl DiffDirection {
    fn as_str(&self) -> &'static str {
        match self {
            DiffDirection::Added => "added",
            DiffDirection::Removed => "removed",
            DiffDirection::Increased => "increased",
            DiffDirection::Decreased => "decreased",
            DiffDirection::Modified => "modified",
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
struct DiffEntities {
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proc_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_proc_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logon_type: Option<String>,
}

/// Capability snapshot for comparing telemetry surfaces between runs/phases
#[derive(Debug, Clone, Default, serde::Serialize)]
struct CapabilitySnapshot {
    is_admin: bool,
    sysmon_installed: bool,
    security_log_accessible: bool,
    enabled_sensors: Vec<String>,
    fact_types_observed: Vec<String>,
}

/// Diff mode query parameter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffMode {
    /// Compare current run to a baseline run_id
    Baseline,
    /// Compare first N minutes to rest of run
    Phase,
    /// Compare before/after a timestamp marker
    Marker,
}

/// Query parameters for diff endpoint
#[derive(Debug, serde::Deserialize)]
struct DiffQuery {
    /// Mode: baseline, phase, or marker
    mode: Option<String>,
    /// For baseline mode: the run_id to compare against
    baseline_run_id: Option<String>,
    /// For phase mode: minutes for initial phase (default 2)
    phase_minutes: Option<i64>,
    /// For marker mode: timestamp (ms) to split on
    marker_ts: Option<i64>,
    /// Filter by category (comma-separated)
    category: Option<String>,
    /// Filter by direction (comma-separated)
    direction: Option<String>,
    /// Baseline-as-filter: suppress unchanged keys that exist in baseline (Pro)
    #[serde(default)]
    baseline_filter: Option<bool>,
}

/// Build stable key from fact data for consistent diffing
fn build_stable_key(category: DiffCategory, fact_json: &serde_json::Value, host: &str) -> String {
    match category {
        DiffCategory::Persistence => {
            // Persistence: service_name OR task_name OR registry_path
            if let Some(svc) = fact_json.get("service_name").and_then(|v| v.as_str()) {
                return format!("persistence:service:{}:{}", host, svc);
            }
            if let Some(task) = fact_json.get("task_name").and_then(|v| v.as_str()) {
                return format!("persistence:task:{}:{}", host, task);
            }
            if let Some(reg) = fact_json.get("registry_path").and_then(|v| v.as_str()) {
                return format!("persistence:reg:{}:{}", host, reg);
            }
            format!("persistence:unknown:{}", host)
        }
        DiffCategory::Process => {
            // Process: proc_key (or exe_path + cmdline hash)
            if let Some(pk) = fact_json.get("proc_key").and_then(|v| v.as_str()) {
                let parent = fact_json.get("parent_proc_key").and_then(|v| v.as_str()).unwrap_or("_");
                return format!("process:{}:{}:{}", host, pk, parent);
            }
            if let Some(exe) = fact_json.get("exe_path").and_then(|v| v.as_str()) {
                let cmd_hash = fact_json.get("cmdline")
                    .and_then(|v| v.as_str())
                    .map(|c| format!("{:x}", c.len() as u32)) // Simple hash
                    .unwrap_or_default();
                return format!("process:{}:{}:{}", host, exe, cmd_hash);
            }
            format!("process:unknown:{}", host)
        }
        DiffCategory::Network => {
            // Network: proc_key + remote_ip:port
            let proc = fact_json.get("proc_key").and_then(|v| v.as_str()).unwrap_or("_");
            let ip = fact_json.get("remote_ip").or(fact_json.get("dest_ip")).and_then(|v| v.as_str()).unwrap_or("_");
            let port = fact_json.get("remote_port").or(fact_json.get("dest_port")).and_then(|v| v.as_u64()).unwrap_or(0);
            format!("network:{}:{}:{}:{}", host, proc, ip, port)
        }
        DiffCategory::Auth => {
            // Auth: user + logon_type + host
            let user = fact_json.get("user").or(fact_json.get("username")).and_then(|v| v.as_str()).unwrap_or("_");
            let logon = fact_json.get("logon_type").and_then(|v| v.as_str()).unwrap_or("_");
            format!("auth:{}:{}:{}", host, user, logon)
        }
        DiffCategory::File => {
            // File: file_path + operation
            let path = fact_json.get("file_path").or(fact_json.get("target_path")).and_then(|v| v.as_str()).unwrap_or("_");
            let op = fact_json.get("operation").and_then(|v| v.as_str()).unwrap_or("_");
            format!("file:{}:{}:{}", host, path, op)
        }
        DiffCategory::Evasion => {
            // Evasion: technique + target
            let tech = fact_json.get("technique").and_then(|v| v.as_str()).unwrap_or("_");
            let target = fact_json.get("target").and_then(|v| v.as_str()).unwrap_or("_");
            format!("evasion:{}:{}:{}", host, tech, target)
        }
        DiffCategory::Other => {
            // Other: fact_type + host + first identifying field
            let ft = fact_json.get("fact_type").and_then(|v| v.as_str()).unwrap_or("unknown");
            format!("other:{}:{}", host, ft)
        }
    }
}

/// Extract entities from fact JSON
fn extract_entities(fact_json: &serde_json::Value, host: &str) -> DiffEntities {
    DiffEntities {
        host: Some(host.to_string()),
        proc_key: fact_json.get("proc_key").and_then(|v| v.as_str()).map(String::from),
        parent_proc_key: fact_json.get("parent_proc_key").and_then(|v| v.as_str()).map(String::from),
        file_key: fact_json.get("file_key").or(fact_json.get("file_path")).and_then(|v| v.as_str()).map(String::from),
        user: fact_json.get("user").or(fact_json.get("username")).and_then(|v| v.as_str()).map(String::from),
        ip: fact_json.get("remote_ip").or(fact_json.get("dest_ip")).and_then(|v| v.as_str()).map(String::from),
        port: fact_json.get("remote_port").or(fact_json.get("dest_port")).and_then(|v| v.as_u64()).map(|p| p as u16),
        service_name: fact_json.get("service_name").and_then(|v| v.as_str()).map(String::from),
        task_name: fact_json.get("task_name").and_then(|v| v.as_str()).map(String::from),
        registry_path: fact_json.get("registry_path").and_then(|v| v.as_str()).map(String::from),
        logon_type: fact_json.get("logon_type").and_then(|v| v.as_str()).map(String::from),
    }
}

/// Compute deterministic severity for diff changes
fn compute_diff_severity(category: DiffCategory, direction: DiffDirection, count_delta: i64) -> (&'static str, String) {
    let base_weight = match category {
        DiffCategory::Persistence => 4,
        DiffCategory::Evasion => 4,
        DiffCategory::Auth => 3,
        DiffCategory::Network => 2,
        DiffCategory::Process => 2,
        DiffCategory::File => 1,
        DiffCategory::Other => 1,
    };
    
    let direction_weight = match direction {
        DiffDirection::Added => 2,
        DiffDirection::Removed => 1,
        DiffDirection::Modified => 3,
        DiffDirection::Increased => if count_delta > 10 { 2 } else { 1 },
        DiffDirection::Decreased => 0,
    };
    
    let total = base_weight + direction_weight;
    
    let (severity, basis_prefix) = match total {
        0..=2 => ("info", "Low-impact"),
        3..=4 => ("low", "Minor"),
        5 => ("medium", "Notable"),
        6 => ("high", "Significant"),
        _ => ("critical", "Critical"),
    };
    
    let basis = format!("{} {} {} (score {})", basis_prefix, category.as_str(), direction.as_str(), total);
    (severity, basis)
}

/// Load capability snapshot from run_meta.json
fn load_capability_snapshot(run_dir: &std::path::Path) -> CapabilitySnapshot {
    let meta_path = run_dir.join("run_meta.json");
    if let Ok(contents) = std::fs::read_to_string(&meta_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
            if let Some(rs) = v.get("readiness_snapshot") {
                return CapabilitySnapshot {
                    is_admin: rs.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false),
                    sysmon_installed: rs.get("sysmon_installed").and_then(|v| v.as_bool()).unwrap_or(false),
                    security_log_accessible: rs.get("security_log_accessible").and_then(|v| v.as_bool()).unwrap_or(false),
                    enabled_sensors: rs.get("enabled_sensors")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                        .unwrap_or_default(),
                    fact_types_observed: Vec::new(), // Will be populated from DB
                };
            }
        }
    }
    CapabilitySnapshot::default()
}

/// Build fact type set from coverage_rollup
fn get_observed_fact_types(conn: &rusqlite::Connection) -> Vec<String> {
    let mut fact_types = std::collections::HashSet::new();
    if let Ok(mut stmt) = conn.prepare("SELECT DISTINCT fact_type FROM coverage_rollup WHERE fact_type IS NOT NULL") {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
            for ft in rows.flatten() {
                fact_types.insert(ft);
            }
        }
    }
    fact_types.into_iter().collect()
}

/// Load keyed facts from a run's workbench.db for a given time range
fn load_keyed_facts(
    conn: &rusqlite::Connection,
    ts_start: Option<i64>,
    ts_end: Option<i64>,
) -> std::collections::HashMap<String, (DiffCategory, serde_json::Value, i64, Vec<serde_json::Value>)> {
    let mut keyed: std::collections::HashMap<String, (DiffCategory, serde_json::Value, i64, Vec<serde_json::Value>)> = std::collections::HashMap::new();
    
    // Try facts table first
    let has_facts = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='facts'",
        [],
        |r| r.get::<_, i64>(0)
    ).unwrap_or(0) > 0;
    
    if has_facts {
        let mut query = String::from(
            "SELECT host_id, ts, fact_type, evidence_ptrs, fact_json FROM facts WHERE 1=1"
        );
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        
        if let Some(start) = ts_start {
            query.push_str(" AND ts >= ?");
            params.push(Box::new(start));
        }
        if let Some(end) = ts_end {
            query.push_str(" AND ts <= ?");
            params.push(Box::new(end));
        }
        query.push_str(" ORDER BY ts");
        
        // Use dynamic params
        if let Ok(mut stmt) = conn.prepare(&query) {
            let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
            if let Ok(rows) = stmt.query_map(param_refs.as_slice(), |row| {
                Ok((
                    row.get::<_, String>(0)?,  // host_id
                    row.get::<_, i64>(1)?,     // ts
                    row.get::<_, String>(2)?,  // fact_type
                    row.get::<_, String>(3)?,  // evidence_ptrs
                    row.get::<_, String>(4)?,  // fact_json
                ))
            }) {
                for row in rows.flatten() {
                    let (host, ts, fact_type, evidence_str, fact_json_str) = row;
                    let category = DiffCategory::from_fact_type(&fact_type);
                    let fact_json: serde_json::Value = serde_json::from_str(&fact_json_str).unwrap_or_default();
                    let evidence: Vec<serde_json::Value> = serde_json::from_str(&evidence_str).unwrap_or_default();
                    let stable_key = build_stable_key(category, &fact_json, &host);
                    
                    keyed.entry(stable_key)
                        .and_modify(|(_, _, count, ev)| {
                            *count += 1;
                            if ev.len() < 5 { ev.extend(evidence.clone()); }
                        })
                        .or_insert((category, fact_json, 1, evidence));
                }
            }
        }
    }
    
    // Also try coverage_rollup (aggregated)
    let has_coverage = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='coverage_rollup'",
        [],
        |r| r.get::<_, i64>(0)
    ).unwrap_or(0) > 0;
    
    if has_coverage && keyed.is_empty() {
        let mut query = String::from(
            "SELECT host, ts_minute, fact_type, fact_count FROM coverage_rollup WHERE fact_type IS NOT NULL"
        );
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        
        if let Some(start) = ts_start {
            let start_min = start / 60000;
            query.push_str(" AND ts_minute >= ?");
            params.push(Box::new(start_min));
        }
        if let Some(end) = ts_end {
            let end_min = end / 60000;
            query.push_str(" AND ts_minute <= ?");
            params.push(Box::new(end_min));
        }
        
        if let Ok(mut stmt) = conn.prepare(&query) {
            let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
            if let Ok(rows) = stmt.query_map(param_refs.as_slice(), |row| {
                Ok((
                    row.get::<_, String>(0)?,  // host
                    row.get::<_, i64>(1)?,     // ts_minute
                    row.get::<_, String>(2)?,  // fact_type
                    row.get::<_, i64>(3)?,     // fact_count
                ))
            }) {
                for row in rows.flatten() {
                    let (host, ts_min, fact_type, count) = row;
                    let category = DiffCategory::from_fact_type(&fact_type);
                    let fact_json = serde_json::json!({ "fact_type": fact_type, "host": host });
                    let stable_key = format!("rollup:{}:{}:{}", host, fact_type, ts_min);
                    
                    keyed.entry(stable_key)
                        .and_modify(|(_, _, c, _)| *c += count)
                        .or_insert((category, fact_json, count, Vec::new()));
                }
            }
        }
    }
    
    keyed
}

/// Compare two fact sets and generate changes
fn diff_fact_sets(
    set_a: &std::collections::HashMap<String, (DiffCategory, serde_json::Value, i64, Vec<serde_json::Value>)>,
    set_b: &std::collections::HashMap<String, (DiffCategory, serde_json::Value, i64, Vec<serde_json::Value>)>,
    cap_a: &CapabilitySnapshot,
    cap_b: &CapabilitySnapshot,
    ts_context: i64,
) -> (Vec<DiffChange>, Vec<String>) {
    let mut changes: Vec<DiffChange> = Vec::new();
    let mut caveats: Vec<String> = Vec::new();
    
    // Check capability differences that would invalidate certain diffs
    let sysmon_diff = cap_a.sysmon_installed != cap_b.sysmon_installed;
    let security_diff = cap_a.security_log_accessible != cap_b.security_log_accessible;
    
    if sysmon_diff {
        if cap_a.sysmon_installed && !cap_b.sysmon_installed {
            caveats.push("⚠️ Sysmon was present in set A but missing in set B - Process/Network changes may be incomplete".to_string());
        } else {
            caveats.push("⚠️ Sysmon was missing in set A but present in set B - New detections may be from improved telemetry".to_string());
        }
    }
    
    if security_diff {
        if cap_a.security_log_accessible && !cap_b.security_log_accessible {
            caveats.push("⚠️ Security log was accessible in set A but not in set B - Auth changes may be incomplete".to_string());
        } else {
            caveats.push("⚠️ Security log was not accessible in set A but is in set B - Auth changes may reflect improved access".to_string());
        }
    }
    
    // Keys only in B (new/added)
    for (key, (category, fact_json, count, evidence)) in set_b.iter() {
        if !set_a.contains_key(key) {
            // Check if we should suppress due to capability differences
            let should_suppress = match category {
                DiffCategory::Process | DiffCategory::Network => sysmon_diff && !cap_a.sysmon_installed,
                DiffCategory::Auth => security_diff && !cap_a.security_log_accessible,
                _ => false,
            };
            
            if should_suppress {
                continue; // Don't report as "added" if baseline couldn't observe this surface
            }
            
            let host = fact_json.get("host").or(fact_json.get("host_id"))
                .and_then(|v| v.as_str()).unwrap_or("unknown");
            let (severity, severity_basis) = compute_diff_severity(*category, DiffDirection::Added, *count);
            
            let title = format!("New {} activity", category.as_str());
            let summary = build_change_summary(*category, DiffDirection::Added, fact_json, *count);
            
            let change_id = format!("diff_add_{:x}", key.len() * 31 + count.abs() as usize);
            
            changes.push(DiffChange {
                change_id,
                ts_ms: ts_context,
                ts_end_ms: None,
                category: *category,
                direction: DiffDirection::Added,
                title,
                summary,
                entities: extract_entities(fact_json, host),
                severity: severity.to_string(),
                severity_basis,
                evidence_ptrs: evidence.clone(),
                evidence_unavailable_reason: if evidence.is_empty() {
                    Some("Aggregated data without per-event evidence".to_string())
                } else { None },
                supporting_facts_count: *count,
                stable_key: key.clone(),
                novelty: Some("new".to_string()),
                novelty_basis: Some("first_appearance_in_current_run".to_string()),
            });
        }
    }
    
    // Keys only in A (removed)
    for (key, (category, fact_json, count, evidence)) in set_a.iter() {
        if !set_b.contains_key(key) {
            // Check if we should suppress due to capability differences
            let should_suppress = match category {
                DiffCategory::Process | DiffCategory::Network => sysmon_diff && !cap_b.sysmon_installed,
                DiffCategory::Auth => security_diff && !cap_b.security_log_accessible,
                _ => false,
            };
            
            if should_suppress {
                continue; // Don't report as "removed" if current can't observe this surface
            }
            
            let host = fact_json.get("host").or(fact_json.get("host_id"))
                .and_then(|v| v.as_str()).unwrap_or("unknown");
            let (severity, severity_basis) = compute_diff_severity(*category, DiffDirection::Removed, *count);
            
            let title = format!("{} activity no longer present", category.as_str());
            let summary = build_change_summary(*category, DiffDirection::Removed, fact_json, *count);
            
            let change_id = format!("diff_rem_{:x}", key.len() * 37 + count.abs() as usize);
            
            changes.push(DiffChange {
                change_id,
                ts_ms: ts_context,
                ts_end_ms: None,
                category: *category,
                direction: DiffDirection::Removed,
                title,
                summary,
                entities: extract_entities(fact_json, host),
                severity: severity.to_string(),
                severity_basis,
                evidence_ptrs: evidence.clone(),
                evidence_unavailable_reason: if evidence.is_empty() {
                    Some("Evidence from removed set".to_string())
                } else { None },
                supporting_facts_count: *count,
                stable_key: key.clone(),
                novelty: Some("known".to_string()),
                novelty_basis: Some("present_in_baseline_but_absent_now".to_string()),
            });
        }
    }
    
    // Keys in both (check for count changes)
    for (key, (category, fact_json_b, count_b, evidence_b)) in set_b.iter() {
        if let Some((_, fact_json_a, count_a, _)) = set_a.get(key) {
            let delta = count_b - count_a;
            if delta.abs() > 0 {
                let direction = if delta > 0 { DiffDirection::Increased } else { DiffDirection::Decreased };
                let host = fact_json_b.get("host").or(fact_json_b.get("host_id"))
                    .and_then(|v| v.as_str()).unwrap_or("unknown");
                let (severity, severity_basis) = compute_diff_severity(*category, direction, delta);
                
                let title = format!("{} activity {}", category.as_str(), direction.as_str());
                let summary = format!("{} from {} to {} ({}{})", 
                    build_change_summary(*category, direction, fact_json_b, *count_b),
                    count_a, count_b,
                    if delta > 0 { "+" } else { "" }, delta
                );
                
                let change_id = format!("diff_delta_{:x}", key.len() * 41 + delta.abs() as usize);
                
                // Only include significant deltas
                if delta.abs() >= 2 || (category == &DiffCategory::Persistence || category == &DiffCategory::Evasion) {
                    changes.push(DiffChange {
                        change_id,
                        ts_ms: ts_context,
                        ts_end_ms: None,
                        category: *category,
                        direction,
                        title,
                        summary,
                        entities: extract_entities(fact_json_b, host),
                        severity: severity.to_string(),
                        severity_basis,
                        evidence_ptrs: evidence_b.clone(),
                        evidence_unavailable_reason: if evidence_b.is_empty() {
                            Some("Count delta from aggregated data".to_string())
                        } else { None },
                        supporting_facts_count: *count_b,
                        stable_key: key.clone(),
                        novelty: Some("changed".to_string()),
                        novelty_basis: Some(format!("count_delta_{}", delta)),
                    });
                }
                
                // Check for modifications (e.g., ImagePath changed for service)
                if category == &DiffCategory::Persistence {
                    let path_a = fact_json_a.get("image_path").or(fact_json_a.get("command"))
                        .and_then(|v| v.as_str());
                    let path_b = fact_json_b.get("image_path").or(fact_json_b.get("command"))
                        .and_then(|v| v.as_str());
                    
                    if path_a != path_b && path_a.is_some() && path_b.is_some() {
                        let (mod_sev, mod_basis) = compute_diff_severity(*category, DiffDirection::Modified, 0);
                        changes.push(DiffChange {
                            change_id: format!("diff_mod_{:x}", key.len() * 43),
                            ts_ms: ts_context,
                            ts_end_ms: None,
                            category: *category,
                            direction: DiffDirection::Modified,
                            title: "Persistence mechanism modified".to_string(),
                            summary: format!("Path changed from '{}' to '{}'", 
                                path_a.unwrap_or("?"), path_b.unwrap_or("?")),
                            entities: extract_entities(fact_json_b, host),
                            severity: mod_sev.to_string(),
                            severity_basis: mod_basis,
                            evidence_ptrs: evidence_b.clone(),
                            evidence_unavailable_reason: None,
                            supporting_facts_count: 1,
                            stable_key: format!("{}_mod", key),
                            novelty: Some("changed".to_string()),
                            novelty_basis: Some("persistence_path_modified".to_string()),
                        });
                    }
                }
            }
        }
    }
    
    // Sort by severity then by category importance
    changes.sort_by(|a, b| {
        let sev_order = |s: &str| match s {
            "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4
        };
        sev_order(&a.severity).cmp(&sev_order(&b.severity))
            .then_with(|| {
                let cat_order = |c: &DiffCategory| match c {
                    DiffCategory::Persistence => 0,
                    DiffCategory::Evasion => 1,
                    DiffCategory::Auth => 2,
                    DiffCategory::Network => 3,
                    DiffCategory::Process => 4,
                    DiffCategory::File => 5,
                    DiffCategory::Other => 6,
                };
                cat_order(&a.category).cmp(&cat_order(&b.category))
            })
    });
    
    (changes, caveats)
}

/// Build human-readable summary for a change
fn build_change_summary(category: DiffCategory, direction: DiffDirection, fact_json: &serde_json::Value, count: i64) -> String {
    let action = match direction {
        DiffDirection::Added => "detected",
        DiffDirection::Removed => "no longer observed",
        DiffDirection::Increased => "increased",
        DiffDirection::Decreased => "decreased",
        DiffDirection::Modified => "modified",
    };
    
    match category {
        DiffCategory::Persistence => {
            if let Some(svc) = fact_json.get("service_name").and_then(|v| v.as_str()) {
                format!("Service '{}' {}", svc, action)
            } else if let Some(task) = fact_json.get("task_name").and_then(|v| v.as_str()) {
                format!("Scheduled task '{}' {}", task, action)
            } else if let Some(reg) = fact_json.get("registry_path").and_then(|v| v.as_str()) {
                let short_reg = reg.split('\\').last().unwrap_or(reg);
                format!("Registry key '{}' {}", short_reg, action)
            } else {
                format!("{} persistence artifact(s) {}", count, action)
            }
        }
        DiffCategory::Process => {
            if let Some(exe) = fact_json.get("exe_path").and_then(|v| v.as_str()) {
                let short_exe = exe.split('\\').last().unwrap_or(exe);
                format!("Process '{}' {} ({} events)", short_exe, action, count)
            } else if let Some(pk) = fact_json.get("proc_key").and_then(|v| v.as_str()) {
                format!("Process {} {} ({} events)", pk, action, count)
            } else {
                format!("{} process event(s) {}", count, action)
            }
        }
        DiffCategory::Network => {
            let ip = fact_json.get("remote_ip").or(fact_json.get("dest_ip"))
                .and_then(|v| v.as_str()).unwrap_or("?");
            let port = fact_json.get("remote_port").or(fact_json.get("dest_port"))
                .and_then(|v| v.as_u64()).unwrap_or(0);
            format!("Connection to {}:{} {} ({} events)", ip, port, action, count)
        }
        DiffCategory::Auth => {
            let user = fact_json.get("user").or(fact_json.get("username"))
                .and_then(|v| v.as_str()).unwrap_or("?");
            let logon = fact_json.get("logon_type").and_then(|v| v.as_str()).unwrap_or("");
            if logon.is_empty() {
                format!("Auth event for '{}' {} ({} events)", user, action, count)
            } else {
                format!("Logon type {} for '{}' {} ({} events)", logon, user, action, count)
            }
        }
        DiffCategory::File => {
            if let Some(path) = fact_json.get("file_path").or(fact_json.get("target_path")).and_then(|v| v.as_str()) {
                let short_path = path.split('\\').last().unwrap_or(path);
                format!("File '{}' {} ({} events)", short_path, action, count)
            } else {
                format!("{} file event(s) {}", count, action)
            }
        }
        DiffCategory::Evasion => {
            if let Some(tech) = fact_json.get("technique").and_then(|v| v.as_str()) {
                format!("Evasion technique '{}' {}", tech, action)
            } else {
                format!("{} evasion indicator(s) {}", count, action)
            }
        }
        DiffCategory::Other => {
            let ft = fact_json.get("fact_type").and_then(|v| v.as_str()).unwrap_or("unknown");
            format!("{} '{}' event(s) {}", count, ft, action)
        }
    }
}

/// GET /api/runs/:run_id/diff - Diff v2 endpoint with baseline|phase|marker modes
/// 
/// **Tier Gated**: 
/// - Phase mode (default): Free tier
/// - Baseline mode, Marker mode, baseline_filter: Pro tier required
async fn run_diff_v2_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<DiffQuery>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let run_dir = state.data_dir.join("runs").join(&run_id);
    let db_path = run_dir.join("workbench.db");
    
    // Parse mode
    let mode = match query.mode.as_deref() {
        Some("baseline") => DiffMode::Baseline,
        Some("phase") => DiffMode::Phase,
        Some("marker") => DiffMode::Marker,
        _ => DiffMode::Phase, // Default to phase mode
    };
    
    // Tier gate: Advanced diff modes require Pro
    // - Free tier: Only phase mode allowed
    // - Pro tier: baseline mode, marker mode, baseline_filter
    let is_advanced_diff = matches!(mode, DiffMode::Baseline | DiffMode::Marker) 
        || query.baseline_filter.unwrap_or(false);
    
    if is_advanced_diff && !resolve_current_tier().has_access(ProductTier::Pro) {
        return feature_locked_403("Advanced Diff (baseline/marker modes)", ProductTier::Pro);
    }
    
    // Load current run's capability snapshot
    let cap_current = {
        let mut cap = load_capability_snapshot(&run_dir);
        if let Ok(conn) = open_db_with_wal(&db_path) {
            cap.fact_types_observed = get_observed_fact_types(&conn);
        }
        cap
    };
    
    if !db_path.exists() {
        return (axum::http::StatusCode::OK, axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": "NO_DB",
                "message": "No workbench.db found for this run",
                "run_id": run_id,
                "mode": format!("{:?}", mode).to_lowercase(),
            }
        })));
    }
    
    match open_db_with_wal(&db_path) {
        Ok(conn) => {
            // Get run time bounds
            let (run_start, run_end): (i64, i64) = conn.query_row(
                "SELECT COALESCE(MIN(ts_minute), 0) * 60000, COALESCE(MAX(ts_minute), 0) * 60000 FROM coverage_rollup",
                [],
                |r| Ok((r.get(0)?, r.get(1)?))
            ).unwrap_or((0, 0));
            
            let (set_a, set_b, cap_a, cap_b, comparison_label, ts_context) = match mode {
                DiffMode::Baseline => {
                    // Compare against baseline run
                    let baseline_id = match &query.baseline_run_id {
                        Some(id) => id.clone(),
                        None => {
                            return (axum::http::StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({
                                "success": false,
                                "error": "baseline_run_id required for baseline mode",
                                "code": "MISSING_PARAM"
                            })));
                        }
                    };
                    
                    let baseline_dir = state.data_dir.join("runs").join(&baseline_id);
                    let baseline_db_path = baseline_dir.join("workbench.db");
                    
                    if !baseline_db_path.exists() {
                        return (axum::http::StatusCode::NOT_FOUND, axum::Json(serde_json::json!({
                            "success": false,
                            "error": format!("Baseline run {} not found", baseline_id),
                            "code": "BASELINE_NOT_FOUND"
                        })));
                    }
                    
                    let cap_baseline = {
                        let mut cap = load_capability_snapshot(&baseline_dir);
                        if let Ok(baseline_conn) = open_db_with_wal(&baseline_db_path) {
                            cap.fact_types_observed = get_observed_fact_types(&baseline_conn);
                        }
                        cap
                    };
                    
                    let set_baseline = if let Ok(baseline_conn) = open_db_with_wal(&baseline_db_path) {
                        load_keyed_facts(&baseline_conn, None, None)
                    } else {
                        std::collections::HashMap::new()
                    };
                    
                    let set_current = load_keyed_facts(&conn, None, None);
                    
                    (set_baseline, set_current, cap_baseline, cap_current, 
                     format!("{} vs {}", baseline_id, run_id), run_end)
                }
                
                DiffMode::Phase => {
                    // Compare first N minutes vs rest
                    let phase_mins = query.phase_minutes.unwrap_or(2);
                    let phase_boundary = run_start + (phase_mins * 60 * 1000);
                    
                    let set_early = load_keyed_facts(&conn, Some(run_start), Some(phase_boundary));
                    let set_late = load_keyed_facts(&conn, Some(phase_boundary), Some(run_end));
                    
                    // Same capability for both phases (same run)
                    (set_early, set_late, cap_current.clone(), cap_current, 
                     format!("First {}min vs Rest", phase_mins), phase_boundary)
                }
                
                DiffMode::Marker => {
                    // Compare before/after a timestamp
                    let marker = match query.marker_ts {
                        Some(ts) => ts,
                        None => {
                            return (axum::http::StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({
                                "success": false,
                                "error": "marker_ts required for marker mode",
                                "code": "MISSING_PARAM"
                            })));
                        }
                    };
                    
                    let set_before = load_keyed_facts(&conn, Some(run_start), Some(marker));
                    let set_after = load_keyed_facts(&conn, Some(marker), Some(run_end));
                    
                    (set_before, set_after, cap_current.clone(), cap_current,
                     format!("Before vs After {}", marker), marker)
                }
            };
            
            // Perform the diff
            let (changes, caveats) = diff_fact_sets(&set_a, &set_b, &cap_a, &cap_b, ts_context);
            
            // Apply filters
            let filtered_changes: Vec<&DiffChange> = changes.iter()
                .filter(|c| {
                    // Category filter
                    if let Some(ref cat_filter) = query.category {
                        let cats: Vec<&str> = cat_filter.split(',').collect();
                        if !cats.iter().any(|f| f.eq_ignore_ascii_case(c.category.as_str())) {
                            return false;
                        }
                    }
                    // Direction filter
                    if let Some(ref dir_filter) = query.direction {
                        let dirs: Vec<&str> = dir_filter.split(',').collect();
                        if !dirs.iter().any(|f| f.eq_ignore_ascii_case(c.direction.as_str())) {
                            return false;
                        }
                    }
                    true
                })
                .collect();
            
            // Build highlights (top 5 high-severity, evidence-backed)
            let highlights: Vec<&DiffChange> = filtered_changes.iter()
                .filter(|c| !c.evidence_ptrs.is_empty() || c.evidence_unavailable_reason.is_some())
                .take(5)
                .copied()
                .collect();
            
            // Category counts
            let mut category_counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
            for c in &filtered_changes {
                *category_counts.entry(c.category.as_str().to_string()).or_insert(0) += 1;
            }
            
            // Direction counts
            let mut direction_counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
            for c in &filtered_changes {
                *direction_counts.entry(c.direction.as_str().to_string()).or_insert(0) += 1;
            }
            
            (axum::http::StatusCode::OK, axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": true,
                    "run_id": run_id,
                    "mode": format!("{:?}", mode).to_lowercase(),
                    "comparison": comparison_label,
                    
                    // Capability alignment header
                    "capability_snapshot_a": cap_a,
                    "capability_snapshot_b": cap_b,
                    "telemetry_caveats": caveats,
                    
                    // Diff results
                    "highlights": highlights,
                    "changes": filtered_changes,
                    
                    // Stats
                    "stats": {
                        "total_changes": filtered_changes.len(),
                        "by_category": category_counts,
                        "by_direction": direction_counts,
                        "keys_in_a": set_a.len(),
                        "keys_in_b": set_b.len(),
                    }
                }
            })))
        }
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({
            "success": false,
            "error": format!("DB error: {}", e),
            "code": "DB_ERROR"
        }))),
    }
}

// ============================================================================
// Run Playbooks Handler - Layer 2 Explainability (Attack Chains)
// ============================================================================

/// Discover playbooks directory with deterministic fallback order:
/// 1. <binary_dir>/playbooks
/// 2. %LOCALAPPDATA%/LocInt/playbooks
/// 3. EDR_PLAYBOOKS_DIR environment variable
/// Returns (Option<PathBuf>, searched_paths, reason_if_none)
fn discover_playbooks_dir() -> (Option<std::path::PathBuf>, Vec<String>, Option<String>) {
    let mut searched_paths: Vec<String> = Vec::new();
    
    // 1. Check <binary_dir>/playbooks
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let binary_playbooks = exe_dir.join("playbooks");
            searched_paths.push(binary_playbooks.display().to_string());
            if binary_playbooks.exists() && binary_playbooks.is_dir() {
                return (Some(binary_playbooks), searched_paths, None);
            }
        }
    }
    
    // 2. Check %LOCALAPPDATA%/LocInt/playbooks
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let locint_playbooks = std::path::PathBuf::from(&local_app_data)
            .join("LocInt")
            .join("playbooks");
        searched_paths.push(locint_playbooks.display().to_string());
        if locint_playbooks.exists() && locint_playbooks.is_dir() {
            return (Some(locint_playbooks), searched_paths, None);
        }
    }
    
    // 3. Check EDR_PLAYBOOKS_DIR environment variable
    if let Ok(env_dir) = std::env::var("EDR_PLAYBOOKS_DIR") {
        let env_path = std::path::PathBuf::from(&env_dir);
        searched_paths.push(env_path.display().to_string());
        if env_path.exists() && env_path.is_dir() {
            return (Some(env_path), searched_paths, None);
        }
    }
    
    // None found
    let reason = format!(
        "No playbooks directory found. Searched: {}. Set EDR_PLAYBOOKS_DIR or place playbooks in <binary_dir>/playbooks",
        searched_paths.join(", ")
    );
    (None, searched_paths, Some(reason))
}

/// GET /api/runs/:run_id/playbooks - Playbook evaluation status and matches
async fn run_playbooks_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let run_dir = state.data_dir.join("runs").join(&run_id);
    let db_path = run_dir.join("workbench.db");
    
    // Check if playbooks are explicitly disabled via LOCINT_PLAYBOOKS=off
    let playbooks_disabled_by_config = std::env::var("LOCINT_PLAYBOOKS")
        .map(|v| v.to_lowercase() == "off" || v == "0" || v.to_lowercase() == "false")
        .unwrap_or(false);
    
    // Discover playbooks directory with fallback chain (unless disabled)
    let (playbooks_dir, searched_paths, not_found_reason) = if playbooks_disabled_by_config {
        (None, vec!["(disabled by LOCINT_PLAYBOOKS=off)".to_string()], Some("Playbooks disabled by config (LOCINT_PLAYBOOKS=off)".to_string()))
    } else {
        discover_playbooks_dir()
    };
    
    let playbooks_enabled = playbooks_dir.is_some();
    
    // RD-3 FIX: Return available=false with proper reason when playbooks not configured
    // Using success/data wrapper for consistency
    if !playbooks_enabled {
        let reason_code = if playbooks_disabled_by_config { "PLAYBOOKS_DISABLED" } else { "PLAYBOOKS_NOT_FOUND" };
        let message = not_found_reason.as_deref().unwrap_or("Playbooks directory not found");
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": reason_code,
                "message": message,
                "searched_paths": searched_paths,
                "run_id": run_id,
                "loaded_count": 0,
                "fired_count": 0,
                "skipped_count": 0,
                "skipped_by_reason": {},
            }
        }));
    }
    
    // Count available playbooks (playbooks_enabled is true here)
    let (loaded_count, playbook_names): (usize, Vec<String>) = if let Some(ref pb_dir) = playbooks_dir {
        let mut count = 0usize;
        let mut names: Vec<String> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(pb_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "yaml" || e == "yml") {
                    count += 1;
                    if let Some(name) = path.file_stem() {
                        names.push(name.to_string_lossy().to_string());
                    }
                }
            }
        }
        (count, names)
    } else {
        (0, Vec::new())
    };
    
    // If no DB, return minimal response (playbooks available but no run data)
    if !db_path.exists() {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "available": true,
                "run_id": run_id,
                "playbooks_enabled": playbooks_enabled,
                "playbooks_dir": playbooks_dir.as_ref().map(|p| p.display().to_string()),
                "searched_paths": searched_paths,
                "loaded_count": loaded_count,
                "loaded_playbooks": playbook_names,
                "fired_count": 0,
                "fired_playbooks": [],
                "skipped_count": 0,
                "skipped_by_reason": {},
                "matches": [],
                "mitre_techniques": [],
                "by_category": {},
                "message": "Playbooks loaded but no events to evaluate (no workbench.db)"
            }
        }));
    }
    
    // Query signals to find playbook matches
    match open_db_with_wal(&db_path) {
        Ok(conn) => {
            let mut matches: Vec<serde_json::Value> = Vec::new();
            let mut by_category: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
            let mut fired_playbooks: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut mitre_techniques: std::collections::HashSet<String> = std::collections::HashSet::new();
            
            // Query signals that have playbook references
            if let Ok(mut stmt) = conn.prepare(
                "SELECT signal_id, signal_type, severity, ts, host, metadata 
                 FROM signals 
                 ORDER BY ts DESC 
                 LIMIT 200"
            ) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,           // signal_id
                        row.get::<_, String>(1)?,           // signal_type
                        row.get::<_, String>(2)?,           // severity
                        row.get::<_, i64>(3)?,              // ts
                        row.get::<_, Option<String>>(4)?,   // host
                        row.get::<_, Option<String>>(5)?,   // metadata (JSON)
                    ))
                }) {
                    for row in rows.flatten() {
                        let (signal_id, signal_type, severity, ts, host, metadata_json) = row;
                        
                        // Parse metadata to extract playbook info
                        let metadata: serde_json::Value = metadata_json
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or(serde_json::json!({}));
                        
                        // Check if this signal came from a playbook
                        let playbook_name = metadata.get("playbook")
                            .or(metadata.get("playbook_name"))
                            .or(metadata.get("detector"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(&signal_type);
                        
                        // Track fired playbooks
                        fired_playbooks.insert(playbook_name.to_string());
                        
                        // Categorize by technique/tactic
                        let category = metadata.get("mitre_tactic")
                            .or(metadata.get("category"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("Uncategorized");
                        
                        by_category.entry(category.to_string())
                            .or_default()
                            .push(playbook_name.to_string());
                        
                        // MITRE truthfulness: only include MITRE IDs if they are real strings in metadata
                        // Don't invent or guess MITRE IDs - only use what's actually in playbook metadata
                        let mitre_technique_opt = metadata.get("mitre_technique_id")
                            .and_then(|v| v.as_str())
                            .filter(|s| s.starts_with("T") && s.len() >= 4);
                        
                        if let Some(mitre_id) = mitre_technique_opt {
                            mitre_techniques.insert(mitre_id.to_string());
                        }
                        
                        // Build match entry - only include mitre_technique if truthfully present
                        matches.push(serde_json::json!({
                            "signal_id": signal_id,
                            "playbook": playbook_name,
                            "signal_type": signal_type,
                            "severity": severity,
                            "ts": ts,
                            "host": host,
                            "mitre_technique": mitre_technique_opt,
                            "mitre_tactic": metadata.get("mitre_tactic").and_then(|v| v.as_str()),
                            "description": metadata.get("description").and_then(|v| v.as_str()),
                        }));
                    }
                }
            }
            
            // Also check signal_explanations for more detailed playbook info
            if let Ok(mut stmt) = conn.prepare(
                "SELECT signal_id, explanation_json FROM signal_explanations LIMIT 100"
            ) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,  // signal_id
                        row.get::<_, String>(1)?,  // explanation_json
                    ))
                }) {
                    for row in rows.flatten() {
                        let (_signal_id, explanation_json) = row;
                        if let Ok(exp) = serde_json::from_str::<serde_json::Value>(&explanation_json) {
                            if let Some(pb) = exp.get("playbook").and_then(|v| v.as_str()) {
                                fired_playbooks.insert(pb.to_string());
                            }
                        }
                    }
                }
            }
            
            let fired_count = fired_playbooks.len();
            
            // Convert MITRE techniques HashSet to sorted Vec for deterministic output
            let mut mitre_vec: Vec<String> = mitre_techniques.into_iter().collect();
            mitre_vec.sort();
            
            // Compute skipped_count: loaded_count - fired_count (playbooks loaded but not matched)
            let skipped_count = loaded_count.saturating_sub(fired_count);
            
            // Build skipped_by_reason - truthful accounting of why playbooks didn't fire
            // We can't know the exact reason without deeper analysis, so we just note they had no matches
            let skipped_by_reason: std::collections::HashMap<String, usize> = if skipped_count > 0 {
                let mut reasons = std::collections::HashMap::new();
                reasons.insert("no_matching_events".to_string(), skipped_count);
                reasons
            } else {
                std::collections::HashMap::new()
            };
            
            // Part B: Query playbook_eval_rollup for per-playbook slot progress
            let mut playbook_evals: Vec<serde_json::Value> = Vec::new();
            let mut top_near_misses: Vec<serde_json::Value> = Vec::new();
            let mut telemetry_blocked_count = 0usize;
            
            if let Ok(mut stmt) = conn.prepare(
                "SELECT playbook_id, playbook_name, category, status, total_slots, matched_slots, 
                        completion_ratio, matched_slot_names, missing_slot_names, why_not_fired,
                        requires_sysmon, requires_security_log, telemetry_blocked, evidence_ptrs_sample
                 FROM playbook_eval_rollup
                 ORDER BY completion_ratio DESC, playbook_name ASC"
            ) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,           // playbook_id
                        row.get::<_, String>(1)?,           // playbook_name
                        row.get::<_, Option<String>>(2)?,   // category
                        row.get::<_, String>(3)?,           // status
                        row.get::<_, i32>(4)?,              // total_slots
                        row.get::<_, i32>(5)?,              // matched_slots
                        row.get::<_, f64>(6)?,              // completion_ratio
                        row.get::<_, Option<String>>(7)?,   // matched_slot_names (JSON)
                        row.get::<_, Option<String>>(8)?,   // missing_slot_names (JSON)
                        row.get::<_, Option<String>>(9)?,   // why_not_fired
                        row.get::<_, bool>(10)?,            // requires_sysmon
                        row.get::<_, bool>(11)?,            // requires_security_log
                        row.get::<_, bool>(12)?,            // telemetry_blocked
                        row.get::<_, Option<String>>(13)?,  // evidence_ptrs_sample
                    ))
                }) {
                    for row in rows.flatten() {
                        let (playbook_id, playbook_name, category, status, total_slots, matched_slots,
                             completion_ratio, matched_slot_names_json, missing_slot_names_json, why_not_fired,
                             requires_sysmon, requires_security_log, telemetry_blocked, evidence_ptrs_sample_json) = row;
                        
                        // Parse JSON arrays for slot names
                        let matched_slot_names: Vec<String> = matched_slot_names_json
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default();
                        let missing_slot_names: Vec<String> = missing_slot_names_json
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default();
                        
                        // Parse evidence pointers sample
                        let evidence_ptrs_sample: Vec<serde_json::Value> = evidence_ptrs_sample_json
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default();
                        
                        if telemetry_blocked {
                            telemetry_blocked_count += 1;
                        }
                        
                        let eval_entry = serde_json::json!({
                            "playbook_id": playbook_id,
                            "playbook_name": playbook_name,
                            "category": category,
                            "status": status,
                            "total_slots": total_slots,
                            "matched_slots": matched_slots,
                            "completion_ratio": completion_ratio,
                            "matched_slot_names": matched_slot_names,
                            "missing_slot_names": missing_slot_names,
                            "why_not_fired": why_not_fired,
                            "evidence_ptrs_sample": evidence_ptrs_sample,
                            "requires_sysmon": requires_sysmon,
                            "requires_security_log": requires_security_log,
                            "telemetry_blocked": telemetry_blocked,
                        });
                        
                        // Collect near-misses (partial matches, not fired)
                        if status != "fired" && completion_ratio > 0.0 && completion_ratio < 1.0 {
                            top_near_misses.push(eval_entry.clone());
                        }
                        
                        playbook_evals.push(eval_entry);
                    }
                }
            }
            
            // Keep only top 5 near-misses
            top_near_misses.truncate(5);
            
            // Generate explanation based on available data
            let playbook_explanation = if fired_count > 0 {
                format!("{} playbook(s) matched and produced signals.", fired_count)
            } else if telemetry_blocked_count > 0 {
                format!("{} playbook(s) could not run due to missing telemetry (Sysmon or Security log not available).", telemetry_blocked_count)
            } else if !top_near_misses.is_empty() {
                format!("{} playbook(s) had partial slot matches but did not reach threshold.", top_near_misses.len())
            } else if loaded_count > 0 {
                "Playbooks were evaluated but no events matched any detection criteria.".to_string()
            } else {
                "No playbooks loaded.".to_string()
            };
            
            // RD-3 FIX: Wrap in success/data wrapper for consistency
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": true,
                    "run_id": run_id,
                    "playbooks_enabled": playbooks_enabled,
                    "playbooks_dir": playbooks_dir.map(|p| p.display().to_string()),
                    "searched_paths": searched_paths,
                    "loaded_count": loaded_count,
                    "loaded_playbooks": playbook_names,
                    "fired_count": fired_count,
                    "fired_playbooks": fired_playbooks.into_iter().collect::<Vec<_>>(),
                    "skipped_count": skipped_count,
                    "skipped_by_reason": skipped_by_reason,
                    "matches": matches,
                    "by_category": by_category,
                    "mitre_techniques": mitre_vec,
                    // Part B additions: per-playbook slot progress
                    "playbook_evals": playbook_evals,
                    "top_near_misses": top_near_misses,
                    "telemetry_blocked_count": telemetry_blocked_count,
                    "explanation": playbook_explanation,
                    "message": if fired_count == 0 {
                        "No playbook matches for this run"
                    } else {
                        "Playbook matches found"
                    }
                }
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Database error: {}", e),
            "code": "DB_ERROR",
            "data": {
                "available": false,
                "reason_code": "DB_ERROR",
                "message": format!("Database error: {}", e),
                "run_id": run_id,
                "playbooks_enabled": playbooks_enabled,
                "playbooks_dir": playbooks_dir.map(|p| p.display().to_string()),
                "searched_paths": searched_paths,
                "loaded_count": 0,
                "fired_count": 0,
                "skipped_count": 0,
                "skipped_by_reason": {},
                "matches": [],
                "mitre_techniques": [],
            }
        })),
    }
}

// ============================================================================
// Next Steps Endpoint: /api/runs/:run_id/next_steps
// Deterministic workflow guidance based on observed run data
// ============================================================================

/// Scenario classification for next steps
#[derive(Debug, Clone, PartialEq, Eq)]
enum NextStepsScenario {
    TelemetryBlocked,   // Key sensors blocked (Security log inaccessible, no Sysmon)
    LimitedNoFacts,     // Configured sensors exist but no facts observed
    NoFindings,         // Facts exist but no signals and no near-misses
    NearMiss,           // No signals but partial playbook matches exist
    FindingsPresent,    // Signals were produced
}

impl NextStepsScenario {
    fn as_str(&self) -> &'static str {
        match self {
            NextStepsScenario::TelemetryBlocked => "telemetry_blocked",
            NextStepsScenario::LimitedNoFacts => "limited_no_facts",
            NextStepsScenario::NoFindings => "no_findings",
            NextStepsScenario::NearMiss => "near_miss",
            NextStepsScenario::FindingsPresent => "findings_present",
        }
    }
}

/// Next step action definition
#[derive(Debug, Clone, serde::Serialize)]
struct NextStepAction {
    action_id: String,
    title: String,
    rationale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocking_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deep_link: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requires: Option<serde_json::Value>,
}

/// GET /api/runs/:run_id/next_steps - Deterministic workflow guidance
/// 
/// Computes next steps based on:
/// - Capability snapshot (admin, sysmon, security log)
/// - Facts total
/// - Signals total
/// - Playbook near-misses
/// - Top entities
async fn run_next_steps_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(run_id): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let run_dir = state.data_dir.join("runs").join(&run_id);
    let db_path = run_dir.join("workbench.db");
    
    // Load readiness snapshot from run_meta.json
    let (readiness_snapshot, is_admin, sysmon_installed, security_log_accessible) = {
        let meta_path = run_dir.join("run_meta.json");
        if let Ok(contents) = std::fs::read_to_string(&meta_path) {
            let v: serde_json::Value = serde_json::from_str(&contents).unwrap_or_default();
            let snapshot = v.get("readiness_snapshot").cloned().unwrap_or(serde_json::json!({}));
            let admin = snapshot.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
            let sysmon = snapshot.get("sysmon_installed").and_then(|v| v.as_bool()).unwrap_or(false);
            let sec_log = snapshot.get("security_log_accessible").and_then(|v| v.as_bool()).unwrap_or(admin);
            (snapshot, admin, sysmon, sec_log)
        } else {
            (serde_json::json!({}), false, false, false)
        }
    };
    
    // Derive capability status
    let overall_status = if !is_admin && !sysmon_installed {
        "blocked"
    } else if !security_log_accessible && !sysmon_installed {
        "limited"
    } else if !security_log_accessible || !sysmon_installed {
        "partial"
    } else {
        "full"
    };
    
    // Build blocked_reasons list
    let mut blocked_reasons: Vec<String> = Vec::new();
    if !is_admin {
        blocked_reasons.push("Not running as Administrator".to_string());
    }
    if !security_log_accessible {
        blocked_reasons.push("Security Event Log not accessible".to_string());
    }
    if !sysmon_installed {
        blocked_reasons.push("Sysmon not installed".to_string());
    }
    
    // Query DB for facts, signals, near-misses, entities
    let (facts_total, signals_total, top_near_misses, top_entities, top_signal) = if db_path.exists() {
        match open_db_with_wal(&db_path) {
            Ok(conn) => {
                // Facts count
                let facts: i64 = conn
                    .query_row("SELECT COALESCE(SUM(fact_count), 0) FROM coverage_rollup", [], |r| r.get(0))
                    .unwrap_or(0);
                
                // Signals count
                let signals: i64 = conn
                    .query_row("SELECT COUNT(*) FROM signals", [], |r| r.get(0))
                    .unwrap_or(0);
                
                // Top near-misses from playbook_eval_rollup
                let mut near_misses: Vec<serde_json::Value> = Vec::new();
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT playbook_id, playbook_name, completion_ratio, total_slots - matched_slots as missing_count
                     FROM playbook_eval_rollup 
                     WHERE status != 'fired' AND completion_ratio > 0 AND completion_ratio < 1
                     ORDER BY completion_ratio DESC
                     LIMIT 5"
                ) {
                    if let Ok(rows) = stmt.query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, f64>(2)?,
                            row.get::<_, i32>(3)?,
                        ))
                    }) {
                        for row in rows.flatten() {
                            near_misses.push(serde_json::json!({
                                "playbook_id": row.0,
                                "playbook_name": row.1,
                                "completion_ratio": row.2,
                                "missing_slots_count": row.3,
                            }));
                        }
                    }
                }
                
                // Top entities from entity_rollup
                let mut entities: Vec<serde_json::Value> = Vec::new();
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT entity_type, entity_key, fact_count FROM entity_rollup 
                     WHERE run_id = ?1 
                     ORDER BY fact_count DESC 
                     LIMIT 10"
                ) {
                    if let Ok(rows) = stmt.query_map([&run_id], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    }) {
                        for row in rows.flatten() {
                            entities.push(serde_json::json!({
                                "type": row.0,
                                "key": row.1,
                                "count": row.2,
                            }));
                        }
                    }
                }
                
                // Get top signal for deep-linking
                let top_sig: Option<(String, String)> = conn
                    .query_row(
                        "SELECT signal_id, signal_type FROM signals ORDER BY ts DESC LIMIT 1",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?))
                    )
                    .ok();
                
                (facts, signals, near_misses, entities, top_sig)
            }
            Err(_) => (0, 0, Vec::new(), Vec::new(), None)
        }
    } else {
        (0, 0, Vec::new(), Vec::new(), None)
    };
    
    // Classify scenario
    let scenario = if overall_status == "blocked" || overall_status == "limited" {
        NextStepsScenario::TelemetryBlocked
    } else if facts_total == 0 {
        NextStepsScenario::LimitedNoFacts
    } else if signals_total > 0 {
        NextStepsScenario::FindingsPresent
    } else if !top_near_misses.is_empty() {
        NextStepsScenario::NearMiss
    } else {
        NextStepsScenario::NoFindings
    };
    
    // Build summary text and severity
    let (summary_text, summary_severity) = match &scenario {
        NextStepsScenario::TelemetryBlocked => (
            format!("Telemetry is blocked or limited. {} issue(s) detected: {}", 
                    blocked_reasons.len(), 
                    blocked_reasons.join("; ")),
            "high"
        ),
        NextStepsScenario::LimitedNoFacts => (
            "No facts were observed during this run. Sensors may be configured but not producing events.".to_string(),
            "medium"
        ),
        NextStepsScenario::NoFindings => (
            format!("{} facts observed but no detections fired and no near-misses.", facts_total),
            "info"
        ),
        NextStepsScenario::NearMiss => (
            format!("{} near-miss playbook(s) found. Some detection criteria were partially met.", top_near_misses.len()),
            "low"
        ),
        NextStepsScenario::FindingsPresent => (
            format!("{} finding(s) detected from {} facts. Review findings and evidence.", signals_total, facts_total),
            "info"
        ),
    };
    
    // Build actions based on scenario
    let mut actions: Vec<NextStepAction> = Vec::new();
    
    match &scenario {
        NextStepsScenario::TelemetryBlocked => {
            // restart_admin action
            if !is_admin {
                actions.push(NextStepAction {
                    action_id: "restart_admin".to_string(),
                    title: "Restart as Administrator".to_string(),
                    rationale: "Security Event Log access requires Administrator privileges.".to_string(),
                    blocking_reason: None,
                    deep_link: Some(serde_json::json!({ "tab": "Settings" })),
                    requires: Some(serde_json::json!({ "admin": true })),
                });
            }
            
            // install_sysmon action
            if !sysmon_installed {
                actions.push(NextStepAction {
                    action_id: "install_sysmon".to_string(),
                    title: "Install Sysmon".to_string(),
                    rationale: "Sysmon provides process, network, and file monitoring required for most detections.".to_string(),
                    blocking_reason: None,
                    deep_link: None,
                    requires: Some(serde_json::json!({ "sysmon": true })),
                });
            }
            
            // view_detection_plan
            actions.push(NextStepAction {
                action_id: "view_detection_plan".to_string(),
                title: "View Detection Plan".to_string(),
                rationale: format!("See which playbooks are blocked by missing telemetry. {} reason(s) detected.", blocked_reasons.len()),
                blocking_reason: None,
                deep_link: Some(serde_json::json!({ "tab": "Mission", "section": "detection_plan" })),
                requires: None,
            });
        }
        
        NextStepsScenario::LimitedNoFacts => {
            // review_capability
            actions.push(NextStepAction {
                action_id: "review_capability".to_string(),
                title: "Review Capability Status".to_string(),
                rationale: "Check which sensors are configured and why no facts were collected.".to_string(),
                blocking_reason: None,
                deep_link: Some(serde_json::json!({ "tab": "Mission", "section": "capability" })),
                requires: None,
            });
            
            // rerun_admin_sysmon
            if !is_admin || !sysmon_installed {
                let mut reqs = serde_json::Map::new();
                if !is_admin { reqs.insert("admin".to_string(), serde_json::json!(true)); }
                if !sysmon_installed { reqs.insert("sysmon".to_string(), serde_json::json!(true)); }
                
                actions.push(NextStepAction {
                    action_id: "rerun_with_telemetry".to_string(),
                    title: "Re-run with Better Telemetry".to_string(),
                    rationale: format!("Missing: {}. Enable these and re-run.", blocked_reasons.join(", ")),
                    blocking_reason: None,
                    deep_link: Some(serde_json::json!({ "tab": "Mission" })),
                    requires: Some(serde_json::json!(reqs)),
                });
            }
            
            // validate_trigger (if sensor available)
            actions.push(NextStepAction {
                action_id: "validate_trigger".to_string(),
                title: "Validate with Test Command".to_string(),
                rationale: "Run a known benign command (e.g., encoded PowerShell whoami) to verify detection pipeline.".to_string(),
                blocking_reason: None,
                deep_link: Some(serde_json::json!({ "tab": "Mission", "section": "detection_plan" })),
                requires: None,
            });
        }
        
        NextStepsScenario::NoFindings => {
            // review_top_entities
            if !top_entities.is_empty() {
                let top_entity = top_entities.first();
                let entity_desc = top_entity
                    .map(|e| format!("{}: {} ({} facts)", 
                        e.get("type").and_then(|v| v.as_str()).unwrap_or("unknown"),
                        e.get("key").and_then(|v| v.as_str()).unwrap_or("unknown"),
                        e.get("count").and_then(|v| v.as_i64()).unwrap_or(0)))
                    .unwrap_or_default();
                
                actions.push(NextStepAction {
                    action_id: "review_top_entities".to_string(),
                    title: "Review Top Entities".to_string(),
                    rationale: format!("{} entities observed. Top: {}", top_entities.len(), entity_desc),
                    blocking_reason: None,
                    deep_link: Some(serde_json::json!({ "tab": "Facts", "run_id": run_id })),
                    requires: None,
                });
            }
            
            // view_playbooks
            actions.push(NextStepAction {
                action_id: "view_playbooks".to_string(),
                title: "Review Enabled Playbooks".to_string(),
                rationale: "Check which playbooks evaluated and why none matched.".to_string(),
                blocking_reason: None,
                deep_link: Some(serde_json::json!({ "tab": "Playbooks", "run_id": run_id })),
                requires: None,
            });
            
            // rerun_extended_profile
            actions.push(NextStepAction {
                action_id: "rerun_extended_profile".to_string(),
                title: "Re-run with Extended Profile".to_string(),
                rationale: "Extended profile captures more event types for broader detection coverage.".to_string(),
                blocking_reason: None,
                deep_link: Some(serde_json::json!({ "tab": "Mission" })),
                requires: None,
            });
        }
        
        NextStepsScenario::NearMiss => {
            // inspect_missing_slots for top near-miss
            if let Some(top_nm) = top_near_misses.first() {
                let pb_id = top_nm.get("playbook_id").and_then(|v| v.as_str()).unwrap_or("");
                let pb_name = top_nm.get("playbook_name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let completion = top_nm.get("completion_ratio").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let missing = top_nm.get("missing_slots_count").and_then(|v| v.as_i64()).unwrap_or(0);
                
                actions.push(NextStepAction {
                    action_id: "inspect_missing_slots".to_string(),
                    title: format!("Inspect Near-Miss: {}", pb_name),
                    rationale: format!("{}% complete, {} slot(s) missing. Check what additional evidence is needed.", 
                                       (completion * 100.0).round() as i32, missing),
                    blocking_reason: None,
                    deep_link: Some(serde_json::json!({ 
                        "tab": "Playbooks", 
                        "run_id": run_id, 
                        "playbook_id": pb_id 
                    })),
                    requires: None,
                });
            }
            
            // check_telemetry_blockers
            if !blocked_reasons.is_empty() {
                actions.push(NextStepAction {
                    action_id: "check_telemetry_blockers".to_string(),
                    title: "Address Telemetry Gaps".to_string(),
                    rationale: format!("Some playbooks may be blocked. Issues: {}", blocked_reasons.join("; ")),
                    blocking_reason: None,
                    deep_link: Some(serde_json::json!({ "tab": "Mission", "section": "detection_plan" })),
                    requires: None,
                });
            }
            
            // rerun_with_prerequisites
            actions.push(NextStepAction {
                action_id: "rerun_after_prerequisites".to_string(),
                title: "Re-run After Enabling Prerequisites".to_string(),
                rationale: "Near-misses suggest the attack patterns are present but some telemetry is missing.".to_string(),
                blocking_reason: None,
                deep_link: Some(serde_json::json!({ "tab": "Mission" })),
                requires: None,
            });
        }
        
        NextStepsScenario::FindingsPresent => {
            // open_top_finding
            if let Some((sig_id, sig_type)) = &top_signal {
                actions.push(NextStepAction {
                    action_id: "open_explain".to_string(),
                    title: "Review Top Finding".to_string(),
                    rationale: format!("Examine the '{}' detection and its evidence.", sig_type),
                    blocking_reason: None,
                    deep_link: Some(serde_json::json!({ 
                        "tab": "Explain", 
                        "run_id": run_id, 
                        "signal_id": sig_id 
                    })),
                    requires: None,
                });
            }
            
            // review_all_findings
            if signals_total > 1 {
                actions.push(NextStepAction {
                    action_id: "review_all_findings".to_string(),
                    title: format!("Review All {} Findings", signals_total),
                    rationale: "See the complete list of detections sorted by time.".to_string(),
                    blocking_reason: None,
                    deep_link: Some(serde_json::json!({ "tab": "Findings", "run_id": run_id })),
                    requires: None,
                });
            }
            
            // search_similar (if we have top entity)
            if let Some(top_entity) = top_entities.first() {
                if top_entity.get("type").and_then(|v| v.as_str()) == Some("process") {
                    let proc_key = top_entity.get("key").and_then(|v| v.as_str()).unwrap_or("");
                    actions.push(NextStepAction {
                        action_id: "search_similar_in_run".to_string(),
                        title: "Search Related Activity".to_string(),
                        rationale: format!("Filter facts by top process: {}", proc_key),
                        blocking_reason: None,
                        deep_link: Some(serde_json::json!({ 
                            "tab": "Facts", 
                            "run_id": run_id, 
                            "filter": proc_key 
                        })),
                        requires: None,
                    });
                }
            }
            
            // export_bundle
            actions.push(NextStepAction {
                action_id: "export_bundle".to_string(),
                title: "Export Evidence Bundle".to_string(),
                rationale: format!("Package {} finding(s) and {} facts for sharing or archival.", signals_total, facts_total),
                blocking_reason: None,
                deep_link: Some(serde_json::json!({ "tab": "Export", "run_id": run_id })),
                requires: None,
            });
        }
    }
    
    // Build evidence_basis
    let evidence_basis = serde_json::json!({
        "capability_snapshot": readiness_snapshot,
        "overall_status": overall_status,
        "facts_total": facts_total,
        "signals_total": signals_total,
        "top_near_misses": top_near_misses,
        "top_entities": top_entities,
        "blocked_reasons": blocked_reasons,
    });
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "run_id": run_id,
            "scenario": scenario.as_str(),
            "summary": {
                "text": summary_text,
                "severity": summary_severity,
            },
            "actions": actions,
            "evidence_basis": evidence_basis,
        }
    }))
}

// ============================================================================
// Debug Endpoint: /api/run/debug_counts
// DEV-ONLY: Diagnose live signal visibility issues
// ============================================================================

/// GET /api/run/debug_counts - Debug endpoint to check signal/fact counts
/// Returns raw DB counts to diagnose visibility issues during live run
/// INVARIANT: Uses same supervisor.status() as /api/run/status for consistency
async fn debug_counts_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<serde_json::Value> {
    // Get current run from supervisor - SAME source as /api/run/status
    let status = state.supervisor.status().await;
    
    // MUST check running flag, not just run_id presence
    // A run_id can exist from a previous run even when not running
    if !status.running {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "active_run": false,
                "supervisor_running": status.running,
                "supervisor_run_id": status.run_id,
                "note": "No active run - supervisor.running is false"
            }
        }));
    }
    
    let run_id = match &status.run_id {
        Some(id) => id.clone(),
        None => {
            return axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "active_run": false,
                    "supervisor_running": status.running,
                    "note": "Running but no run_id (should not happen)"
                }
            }));
        }
    };
    
    let db_path = state.data_dir.join("runs").join(&run_id).join("workbench.db");
    
    if !db_path.exists() {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "active_run": true,
                "run_id": run_id,
                "db_exists": false,
                "note": "workbench.db not yet created - locald may still be starting"
            }
        }));
    }
    
    // Open with WAL mode pragmas for read consistency
    match open_db_with_wal(&db_path) {
        Ok(conn) => {
            // Count signals
            let signals_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM signals", [], |row| row.get(0))
                .unwrap_or(0);
            
            // Count explanations
            let explanations_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM signal_explanations", [], |row| row.get(0))
                .unwrap_or(0);
            
            // Count facts
            let facts_count: i64 = conn
                .query_row("SELECT COALESCE(SUM(fact_count), 0) FROM coverage_rollup", [], |row| row.get(0))
                .unwrap_or(0);
            
            // Latest signal timestamp
            let latest_ts: Option<i64> = conn
                .query_row("SELECT MAX(ts) FROM signals", [], |row| row.get(0))
                .ok();
            
            // Get last few signal_ids for verification
            let mut stmt = conn.prepare("SELECT signal_id FROM signals ORDER BY ts DESC LIMIT 3").unwrap();
            let recent_ids: Vec<String> = stmt
                .query_map([], |row| row.get(0))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "active_run": true,
                    "run_id": run_id,
                    "db_exists": true,
                    "db_path": db_path.display().to_string(),
                    "signals_count": signals_count,
                    "explanations_count": explanations_count,
                    "facts_count": facts_count,
                    "latest_signal_ts": latest_ts,
                    "recent_signal_ids": recent_ids,
                    "wal_mode": "enabled_for_read"
                }
            }))
        }
        Err(e) => {
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to open DB: {}", e),
                "code": "DB_ERROR",
                "data": {
                    "run_id": run_id,
                    "db_path": db_path.display().to_string()
                }
            }))
        }
    }
}

#[derive(serde::Deserialize)]
struct SignalsQuery {
    run_id: Option<String>,
    /// Cursor for incremental fetching - only return signals with ts > since_ts_ms
    since_ts_ms: Option<i64>,
}

async fn signals_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Query(query): axum::extract::Query<SignalsQuery>,
) -> axum::Json<serde_json::Value> {
    let run_id = match query.run_id {
        Some(id) => id,
        None => return axum::Json(serde_json::json!({
            "success": false,
            "error": "run_id query parameter required",
            "code": "MISSING_PARAM"
        })),
    };
    
    let db_path = state.data_dir.join("runs").join(&run_id).join("workbench.db");
    if !db_path.exists() {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "signals": [],
                "run_id": run_id,
                "available": false,
                "cursor": null
            }
        }));
    }
    
    match open_db_with_wal(&db_path) {
        Ok(conn) => {
            // Build query with optional cursor filter
            let (query_str, query_params): (String, Vec<i64>) = match query.since_ts_ms {
                Some(since_ts) => (
                    "SELECT signal_id, signal_type, severity, ts, host FROM signals WHERE ts > ? ORDER BY ts DESC LIMIT 100".to_string(),
                    vec![since_ts]
                ),
                None => (
                    "SELECT signal_id, signal_type, severity, ts, host FROM signals ORDER BY ts DESC LIMIT 100".to_string(),
                    vec![]
                )
            };
            
            let mut stmt = conn.prepare(&query_str).unwrap();
            
            let signals: Vec<serde_json::Value> = if query_params.is_empty() {
                stmt.query_map([], |row| {
                    Ok(serde_json::json!({
                        "signal_id": row.get::<_, String>(0)?,
                        "signal_type": row.get::<_, String>(1)?,
                        "severity": row.get::<_, String>(2)?,
                        "ts": row.get::<_, i64>(3)?,
                        "host": row.get::<_, Option<String>>(4)?,
                    }))
                })
                .unwrap()
                .filter_map(|r| r.ok())
                .collect()
            } else {
                stmt.query_map([query_params[0]], |row| {
                    Ok(serde_json::json!({
                        "signal_id": row.get::<_, String>(0)?,
                        "signal_type": row.get::<_, String>(1)?,
                        "severity": row.get::<_, String>(2)?,
                        "ts": row.get::<_, i64>(3)?,
                        "host": row.get::<_, Option<String>>(4)?,
                    }))
                })
                .unwrap()
                .filter_map(|r| r.ok())
                .collect()
            };
            
            // Compute next_since_ts_ms for cursor-based polling
            // If we got signals, advance cursor to max ts seen
            // If no signals, keep the same since_ts_ms (or 0 if initial)
            let max_ts: Option<i64> = signals.iter()
                .filter_map(|s| s.get("ts").and_then(|t| t.as_i64()))
                .max();
            
            let next_since_ts_ms = match (max_ts, query.since_ts_ms) {
                (Some(max), _) => max,           // Got signals, advance to max
                (None, Some(prev)) => prev,       // No signals, keep previous
                (None, None) => 0,                // Initial fetch, no signals yet
            };
            
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "signals": signals,
                    "run_id": run_id,
                    "available": true,
                    "next_since_ts_ms": next_since_ts_ms
                }
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": format!("DB error: {}", e),
            "code": "DB_ERROR"
        })),
    }
}

async fn signal_explain_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(signal_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<SignalsQuery>,
) -> axum::Json<serde_json::Value> {
    let run_id = match query.run_id {
        Some(id) => id,
        None => return axum::Json(serde_json::json!({
            "success": false,
            "error": "run_id query parameter required",
            "code": "MISSING_PARAM"
        })),
    };
    
    let db_path = state.data_dir.join("runs").join(&run_id).join("workbench.db");
    if !db_path.exists() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Run '{}' not found", run_id),
            "code": "RUN_NOT_FOUND"
        }));
    }
    
    match open_db_with_wal(&db_path) {
        Ok(conn) => {
            // Get signal data first (needed for both available=true and available=false)
            let signal_result = conn.query_row(
                "SELECT signal_type, severity, ts, host, metadata, evidence_ptrs 
                 FROM signals WHERE signal_id = ?",
                [&signal_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,           // signal_type
                        row.get::<_, String>(1)?,           // severity
                        row.get::<_, i64>(2)?,              // ts
                        row.get::<_, Option<String>>(3)?,   // host
                        row.get::<_, Option<String>>(4)?,   // metadata
                        row.get::<_, Option<String>>(5)?,   // evidence_ptrs
                    ))
                },
            );
            
            // Signal not found at all
            let (signal_type, severity, ts, host, metadata_json, evidence_json) = match signal_result {
                Ok(data) => data,
                Err(_) => {
                    // CONTRACT: Return canonical ExplainResponse with available=false
                    return axum::Json(serde_json::json!({
                        "success": true,
                        "data": {
                            "available": false,
                            "reason_code": "SIGNAL_NOT_FOUND",
                            "message": "Signal not found in database",
                            "signal": {
                                "signal_id": signal_id,
                                "signal_type": null,
                                "ts_ms": null,
                                "severity": null,
                                "host": null,
                                "run_id": run_id
                            },
                            "source": {
                                "kind": "unknown",
                                "id": null,
                                "version": null
                            },
                            "evidence_ptrs": [],
                            "evidence_ptrs_count": 0,
                            "confidence": null,
                            "matched_slots": null,
                            "narrative": null,
                            "reasons": null,
                            "partial_context": null
                        }
                    }));
                }
            };
            
            // Parse metadata and evidence - these are REAL data from the signal
            let metadata: serde_json::Value = metadata_json
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::json!({}));
            let evidence: Vec<serde_json::Value> = evidence_json
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            let evidence_count = evidence.len();
            
            // Determine source kind from signal_type
            let (source_kind, source_id) = if signal_type.starts_with("playbook:") {
                ("playbook", Some(signal_type.clone()))
            } else if signal_type.starts_with("detector:") {
                ("detector", Some(signal_type.clone()))
            } else if metadata.get("playbook").is_some() || metadata.get("playbook_id").is_some() {
                ("playbook", metadata.get("playbook_id").or(metadata.get("playbook")).and_then(|v| v.as_str()).map(String::from))
            } else {
                ("unknown", None)
            };
            
            // Build canonical signal object
            let signal_obj = serde_json::json!({
                "signal_id": signal_id,
                "signal_type": signal_type,
                "ts_ms": ts,
                "severity": severity,
                "host": host,
                "run_id": run_id
            });
            
            // Try to get explanation from signal_explanations table
            let explanation_result: Result<String, _> = conn.query_row(
                "SELECT explanation_json FROM signal_explanations WHERE signal_id = ?",
                [&signal_id],
                |row| row.get(0),
            );
            
            match explanation_result {
                Ok(json_str) => {
                    // Parse explanation JSON
                    let explanation = serde_json::from_str::<serde_json::Value>(&json_str)
                        .unwrap_or(serde_json::json!({"raw": json_str}));
                    
                    // CHECK: Is this an unavailable stub (has available: false)?
                    let is_unavailable = explanation.get("available")
                        .map(|v| v == &serde_json::json!(false) || v == &serde_json::json!("false"))
                        .unwrap_or(false);
                    
                    if is_unavailable {
                        // This is an unavailable explanation stub stored by locald
                        // Return it with the canonical structure
                        let reason_code = explanation.get("reason_code")
                            .and_then(|v| v.as_str())
                            .unwrap_or("UNKNOWN");
                        let message = explanation.get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Explanation not available");
                        let partial_context = explanation.get("partial_context").cloned();
                        
                        return axum::Json(serde_json::json!({
                            "success": true,
                            "data": {
                                "available": false,
                                "reason_code": reason_code,
                                "message": message,
                                "signal": signal_obj,
                                "source": {
                                    "kind": source_kind,
                                    "id": source_id,
                                    "version": null
                                },
                                "evidence_ptrs": evidence,
                                "evidence_ptrs_count": evidence_count,
                                "confidence": null,
                                "matched_slots": null,
                                "narrative": null,
                                "reasons": null,
                                "partial_context": partial_context
                            }
                        }));
                    }
                    
                    // Full explanation available - extract fields
                    let slots = explanation.get("slots");
                    let summary = explanation.get("summary").and_then(|v| v.as_str());
                    let why_fired = explanation.get("why_fired").and_then(|v| v.as_str());
                    let confidence = explanation.get("confidence").and_then(|v| v.as_f64());
                    let version = explanation.get("detector_version").and_then(|v| v.as_str());
                    let key_fields = explanation.get("key_fields").cloned();
                    let reasons = explanation.get("reasons").cloned();
                    
                    // Build matched_slots if we have slot data
                    let matched_slots = if let Some(slots_arr) = slots.and_then(|s| s.as_array()) {
                        let filled = slots_arr.iter()
                            .filter(|s| s.get("status").and_then(|st| st.as_str()) == Some("filled"))
                            .count();
                        let names: Vec<&str> = slots_arr.iter()
                            .filter(|s| s.get("status").and_then(|st| st.as_str()) == Some("filled"))
                            .filter_map(|s| s.get("name").and_then(|n| n.as_str()))
                            .collect();
                        Some(serde_json::json!({
                            "filled": filled,
                            "total": slots_arr.len(),
                            "names": names
                        }))
                    } else {
                        None
                    };
                    
                    // Use narrative only if we have one - never invent
                    let narrative = why_fired.or(summary);
                    
                    // CONTRACT: Return canonical ExplainResponse with available=true
                    // Phase 2: Include key_fields and reasons for enhanced explanations
                    axum::Json(serde_json::json!({
                        "success": true,
                        "data": {
                            "available": true,
                            "signal": signal_obj,
                            "source": {
                                "kind": source_kind,
                                "id": source_id,
                                "version": version
                            },
                            "evidence_ptrs": evidence,
                            "evidence_ptrs_count": evidence_count,
                            "confidence": confidence,
                            "explanation": explanation,
                            "matched_slots": matched_slots,
                            "narrative": narrative,
                            "reasons": reasons,
                            "key_fields": key_fields
                        }
                    }))
                }
                Err(_) => {
                    // INVARIANT: Every signal gets an ExplainResponse (available: true/false)
                    // This path means no row exists in signal_explanations (legacy data)
                    // New signals always have a row (either full or unavailable stub)
                    
                    // Check playbook_eval_rollup for any context
                    let playbook_context: Option<serde_json::Value> = conn.query_row(
                        "SELECT playbook_id, playbook_name, status, matched_slots, matched_slot_names, evidence_ptrs_sample
                         FROM playbook_eval_rollup WHERE run_id = ? AND status = 'fired' LIMIT 1",
                        [&run_id],
                        |row| {
                            Ok(serde_json::json!({
                                "playbook_id": row.get::<_, Option<String>>(0)?,
                                "playbook_name": row.get::<_, Option<String>>(1)?,
                                "status": row.get::<_, Option<String>>(2)?,
                                "matched_slots": row.get::<_, Option<i32>>(3)?,
                                "matched_slot_names": row.get::<_, Option<String>>(4)?,
                                "evidence_ptrs_sample": row.get::<_, Option<String>>(5)?,
                            }))
                        },
                    ).ok();
                    
                    // CONTRACT: Return canonical ExplainResponse with available=false
                    // Use MISSING_EXPLANATION_ROW for legacy data without explanation rows
                    axum::Json(serde_json::json!({
                        "success": true,
                        "data": {
                            "available": false,
                            "reason_code": "MISSING_EXPLANATION_ROW",
                            "message": "No explanation row exists for this signal (legacy data)",
                            "signal": signal_obj,
                            "source": {
                                "kind": source_kind,
                                "id": source_id,
                                "version": null
                            },
                            "evidence_ptrs": evidence,
                            "evidence_ptrs_count": evidence_count,
                            "confidence": null,
                            "matched_slots": null,
                            "narrative": null,
                            "reasons": null,
                            "partial_context": {
                                "signal_type": signal_type,
                                "severity": severity,
                                "ts": ts,
                                "host": host,
                                "metadata": metadata,
                                "evidence_ptrs": evidence_count,
                                "playbook_eval": playbook_context,
                            }
                        }
                    }))
                }
            }
        }
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": format!("DB error: {}", e),
            "code": "DB_ERROR"
        })),
    }
}

/// GET /api/signals/:id - Get single signal by ID
async fn get_signal_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(signal_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<SignalsQuery>,
) -> axum::Json<serde_json::Value> {
    let run_id = match query.run_id {
        Some(id) => id,
        None => return axum::Json(serde_json::json!({
            "success": false,
            "error": "run_id query parameter required"
        })),
    };
    
    let db_path = state.data_dir.join("runs").join(&run_id).join("workbench.db");
    if !db_path.exists() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": format!("Run '{}' not found", run_id)
        }));
    }
    
    match open_db_with_wal(&db_path) {
        Ok(conn) => {
            let result = conn.query_row(
                "SELECT signal_id, signal_type, severity, ts, host, raw_json FROM signals WHERE signal_id = ?",
                [&signal_id],
                |row| {
                    let raw: Option<String> = row.get(5)?;
                    Ok(serde_json::json!({
                        "signal_id": row.get::<_, String>(0)?,
                        "signal_type": row.get::<_, String>(1)?,
                        "severity": row.get::<_, String>(2)?,
                        "ts": row.get::<_, i64>(3)?,
                        "host": row.get::<_, Option<String>>(4)?,
                        "raw": raw.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
                    }))
                },
            );
            
            match result {
                Ok(signal) => axum::Json(serde_json::json!({
                    "success": true,
                    "data": signal
                })),
                Err(_) => axum::Json(serde_json::json!({
                    "success": false,
                    "error": format!("Signal '{}' not found", signal_id)
                })),
            }
        }
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": format!("DB error: {}", e)
        })),
    }
}

/// GET /api/signals/stats - Signal statistics
async fn signal_stats_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Query(query): axum::extract::Query<SignalsQuery>,
) -> axum::Json<serde_json::Value> {
    let run_id = match query.run_id {
        Some(id) => id,
        None => return axum::Json(serde_json::json!({
            "success": true,
            "data": { "total": 0, "by_type": {}, "by_severity": {} }
        })),
    };
    
    let db_path = state.data_dir.join("runs").join(&run_id).join("workbench.db");
    if !db_path.exists() {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": { "total": 0, "by_type": {}, "by_severity": {} }
        }));
    }
    
    match open_db_with_wal(&db_path) {
        Ok(conn) => {
            let total: i64 = conn.query_row("SELECT COUNT(*) FROM signals", [], |r| r.get(0))
                .unwrap_or(0);
            
            let mut by_type = serde_json::Map::new();
            if let Ok(mut stmt) = conn.prepare("SELECT signal_type, COUNT(*) FROM signals GROUP BY signal_type") {
                if let Ok(rows) = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                }) {
                    for row in rows.flatten() {
                        by_type.insert(row.0, serde_json::json!(row.1));
                    }
                }
            }
            
            let mut by_severity = serde_json::Map::new();
            if let Ok(mut stmt) = conn.prepare("SELECT severity, COUNT(*) FROM signals GROUP BY severity") {
                if let Ok(rows) = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                }) {
                    for row in rows.flatten() {
                        by_severity.insert(row.0, serde_json::json!(row.1));
                    }
                }
            }
            
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "total": total,
                    "by_type": by_type,
                    "by_severity": by_severity
                }
            }))
        }
        Err(_) => axum::Json(serde_json::json!({
            "success": true,
            "data": { "total": 0, "by_type": {}, "by_severity": {} }
        })),
    }
}

/// GET /api/signals/explainability_stats - Explainability availability metrics
///
/// Returns counts of signals with available vs unavailable explanations,
/// broken down by reason_code for unavailable cases.
///
/// CONTRACT: Part of explainability rate improvement - provides visibility
/// into explanation availability to identify and fix upstream issues.
async fn explainability_stats_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Query(query): axum::extract::Query<SignalsQuery>,
) -> axum::Json<serde_json::Value> {
    // CONTRACT: run_id is REQUIRED - stats are always scoped to a run
    let run_id = match query.run_id {
        Some(id) => id,
        None => return axum::Json(serde_json::json!({
            "success": false,
            "error": "run_id query parameter is required",
            "code": "MISSING_RUN_ID"
        })),
    };
    
    let db_path = state.data_dir.join("runs").join(&run_id).join("workbench.db");
    if !db_path.exists() {
        return axum::Json(serde_json::json!({
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
    
    match open_db_with_wal(&db_path) {
        Ok(conn) => {
            // Total signals
            let total_signals: i64 = conn.query_row(
                "SELECT COUNT(*) FROM signals", [], |r| r.get(0)
            ).unwrap_or(0);
            
            // Signals with explanations (available=true)
            let with_explanation: i64 = conn.query_row(
                "SELECT COUNT(*) FROM signal_explanations WHERE explanation_json IS NOT NULL",
                [], |r| r.get(0)
            ).unwrap_or(0);
            
            // Count by reason_code for unavailable explanations
            // reason_code is stored in explanation_json for unavailable rows
            let mut unavailable_by_reason = serde_json::Map::new();
            
            // Query unavailable explanations (those with reason_code in JSON)
            if let Ok(mut stmt) = conn.prepare(
                "SELECT 
                    json_extract(explanation_json, '$.reason_code') as reason_code,
                    COUNT(*) as cnt
                 FROM signal_explanations 
                 WHERE json_extract(explanation_json, '$.available') = 0
                    OR json_extract(explanation_json, '$.available') = 'false'
                 GROUP BY reason_code"
            ) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?.unwrap_or_else(|| "UNKNOWN".to_string()),
                        row.get::<_, i64>(1)?
                    ))
                }) {
                    for row in rows.flatten() {
                        unavailable_by_reason.insert(row.0, serde_json::json!(row.1));
                    }
                }
            }
            
            // Count signals missing from signal_explanations entirely
            let missing_explanation_rows: i64 = conn.query_row(
                "SELECT COUNT(*) FROM signals s 
                 LEFT JOIN signal_explanations se ON s.signal_id = se.signal_id 
                 WHERE se.signal_id IS NULL",
                [], |r| r.get(0)
            ).unwrap_or(0);
            
            if missing_explanation_rows > 0 {
                unavailable_by_reason.insert(
                    "MISSING_EXPLANATION_ROW".to_string(), 
                    serde_json::json!(missing_explanation_rows)
                );
            }
            
            // Calculate available count (rows with explanation_json that have available=true or full content)
            let available_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM signal_explanations 
                 WHERE explanation_json IS NOT NULL
                   AND (json_extract(explanation_json, '$.available') IS NULL 
                        OR json_extract(explanation_json, '$.available') = 1
                        OR json_extract(explanation_json, '$.available') = 'true')",
                [], |r| r.get(0)
            ).unwrap_or(with_explanation);
            
            let unavailable_count = total_signals - available_count;
            let availability_rate = if total_signals > 0 {
                (available_count as f64 / total_signals as f64) * 100.0
            } else {
                0.0
            };
            
            // Structural invariant check: every signal should have an explanation row
            let structural_invariant_ok = missing_explanation_rows == 0;
            
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "run_id": run_id,
                    "total_signals": total_signals,
                    "explanations_available": available_count,
                    "explanations_unavailable": unavailable_count,
                    "unavailable_by_reason": unavailable_by_reason,
                    "structural_invariant": {
                        "every_signal_has_explanation_row": structural_invariant_ok,
                        "missing_rows": missing_explanation_rows
                    }
                }
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": format!("DB error: {}", e),
            "code": "DB_ERROR"
        })),
    }
}

/// GET /api/app/state - App initialization state
async fn app_state_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "initialized": true,
            "binary": "locint",
            "version": env!("CARGO_PKG_VERSION"),
            "is_admin": is_elevated(),
        }
    }))
}

/// POST /api/export/bundle - Export evidence bundle (simplified for locint)
async fn export_bundle_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(req): axum::Json<ExportBundleRequest>,
) -> impl axum::response::IntoResponse {
    use axum::http::{header, StatusCode};
    use edr_server::supervisor::RunPhase;
    
    // RD-4 FIX: Block export while run is active OR finalizing
    // Check Supervisor phase first (most reliable)
    let phase = state.supervisor.current_phase().await;
    if phase != RunPhase::Idle && phase != RunPhase::Completed {
        let phase_str = phase.as_str();
        return (
            StatusCode::CONFLICT,
            [(header::CONTENT_TYPE, "application/json")],
            format!(r#"{{"success":false,"error":"Stop run before export (current phase: {})","code":"RUN_ACTIVE"}}"#, phase_str)
        );
    }
    
    // Fallback: also check process-level (for edge cases where supervisor lost track)
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd1 = std::process::Command::new("tasklist");
        cmd1.creation_flags(0x08000000); // CREATE_NO_WINDOW
        let capture_running = cmd1
            .args(["/FI", "IMAGENAME eq capture_windows_rotating.exe"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("capture_windows_rotating"))
            .unwrap_or(false);
        
        let mut cmd2 = std::process::Command::new("tasklist");
        cmd2.creation_flags(0x08000000);
        let locald_running = cmd2
            .args(["/FI", "IMAGENAME eq edr-locald.exe"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("edr-locald"))
            .unwrap_or(false);
        
        if capture_running || locald_running {
            return (
                StatusCode::CONFLICT,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"success":false,"error":"Stop run before export","code":"RUN_ACTIVE"}"#.to_string()
            );
        }
    }
    
    let run_id = match req.run_id {
        Some(id) => id,
        None => return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"success":false,"error":"run_id required"}"#.to_string()
        ),
    };
    
    let run_dir = state.data_dir.join("runs").join(&run_id);
    if !run_dir.exists() {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            format!(r#"{{"success":false,"error":"Run '{}' not found"}}"#, run_id)
        );
    }
    
    // Create a simple ZIP with the run's key files
    let zip_data = match create_bundle_zip(&run_dir, &run_id) {
        Ok(data) => data,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "application/json")],
            format!(r#"{{"success":false,"error":"{}"}}"#, e)
        ),
    };
    
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/zip")],
        // Note: In real impl, return the binary ZIP. For now, return success
        format!(r#"{{"success":true,"size":{}}}"#, zip_data.len())
    )
}

#[derive(serde::Deserialize)]
struct ExportBundleRequest {
    run_id: Option<String>,
}

fn create_bundle_zip(run_dir: &std::path::Path, run_id: &str) -> Result<Vec<u8>, String> {
    use std::io::Write;
    
    // Simple bundle: just package key files as JSON manifest
    let db_path = run_dir.join("workbench.db");
    let has_db = db_path.exists();
    
    let segments_dir = run_dir.join("segments");
    let segment_count = std::fs::read_dir(&segments_dir)
        .map(|e| e.filter_map(|f| f.ok()).count())
        .unwrap_or(0);
    
    let manifest = serde_json::json!({
        "run_id": run_id,
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "has_db": has_db,
        "segment_count": segment_count,
        "note": "Full ZIP export not implemented in locint. Use edr-server for complete bundles."
    });
    
    let mut buf = Vec::new();
    write!(buf, "{}", serde_json::to_string_pretty(&manifest).unwrap())
        .map_err(|e| e.to_string())?;
    
    Ok(buf)
}

/// POST /api/import/bundle - Import a bundle ZIP (simplified for locint)
/// Returns an import report with normalized_artifacts, dropped_artifacts, evidence_deref_available
async fn import_bundle_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    mut multipart: axum::extract::Multipart,
) -> impl axum::response::IntoResponse {
    use axum::http::{header, StatusCode};
    use std::io::Read;
    
    // Try to read the bundle file from multipart form
    let mut bundle_data: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;
    
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("bundle") {
            filename = field.file_name().map(|s| s.to_string());
            if let Ok(data) = field.bytes().await {
                bundle_data = Some(data.to_vec());
            }
        }
    }
    
    let data = match bundle_data {
        Some(d) => d,
        None => return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"success":false,"error":"No bundle file in request","code":"MISSING_BUNDLE"}"#.to_string()
        ),
    };
    
    // Import report tracking
    let mut normalized_artifacts: Vec<serde_json::Value> = Vec::new();
    let mut dropped_artifacts: Vec<serde_json::Value> = Vec::new();
    let mut evidence_deref_available = false;
    let mut has_manifest = false;
    let mut has_run_meta = false;
    let mut has_db = false;
    let mut segment_count = 0usize;
    let mut total_events = 0u64;
    
    // Inspect ZIP contents
    let cursor = std::io::Cursor::new(&data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(e) => {
            dropped_artifacts.push(serde_json::json!({
                "artifact": filename.as_deref().unwrap_or("bundle.zip"),
                "reason": format!("Invalid ZIP: {}", e),
                "category": "archive"
            }));
            return (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({
                    "success": false,
                    "error": format!("Invalid ZIP archive: {}", e),
                    "code": "INVALID_ZIP",
                    "import_report": {
                        "normalized_artifacts": normalized_artifacts,
                        "dropped_artifacts": dropped_artifacts,
                        "evidence_deref_available": false
                    }
                }).to_string()
            );
        }
    };
    
    // Scan archive contents
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            let name = file.name().to_string();
            let size = file.size();
            
            if name.ends_with("manifest.json") {
                has_manifest = true;
                normalized_artifacts.push(serde_json::json!({
                    "artifact": name,
                    "size": size,
                    "category": "manifest"
                }));
            } else if name.ends_with("run_meta.json") {
                has_run_meta = true;
                normalized_artifacts.push(serde_json::json!({
                    "artifact": name,
                    "size": size,
                    "category": "metadata"
                }));
            } else if name.ends_with("workbench.db") || name.ends_with(".db") {
                has_db = true;
                normalized_artifacts.push(serde_json::json!({
                    "artifact": name,
                    "size": size,
                    "category": "database"
                }));
            } else if name.ends_with(".jsonl") {
                segment_count += 1;
                evidence_deref_available = true;
                normalized_artifacts.push(serde_json::json!({
                    "artifact": name,
                    "size": size,
                    "category": "segment"
                }));
            } else if name.ends_with(".evtx") {
                // Raw EVTX files need conversion
                dropped_artifacts.push(serde_json::json!({
                    "artifact": name,
                    "reason": "Raw EVTX not supported - convert to JSONL first",
                    "category": "evtx"
                }));
            } else if name.ends_with(".json") {
                normalized_artifacts.push(serde_json::json!({
                    "artifact": name,
                    "size": size,
                    "category": "json"
                }));
            } else if name.contains("__MACOSX") || name.starts_with(".") {
                // macOS metadata or hidden files
                dropped_artifacts.push(serde_json::json!({
                    "artifact": name,
                    "reason": "System metadata file",
                    "category": "metadata"
                }));
            } else {
                // Unknown file type - keep but note
                normalized_artifacts.push(serde_json::json!({
                    "artifact": name,
                    "size": size,
                    "category": "other"
                }));
            }
        }
    }
    
    // Create a simple imported run directory
    let import_id = format!("imported_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
    let import_dir = state.data_dir.join("runs").join(&import_id);
    
    if let Err(e) = std::fs::create_dir_all(&import_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "application/json")],
            format!(r#"{{"success":false,"error":"Failed to create import directory: {}","code":"IO_ERROR"}}"#, e)
        );
    }
    
    // Extract bundle contents
    let cursor = std::io::Cursor::new(&data);
    if let Ok(mut archive) = zip::ZipArchive::new(cursor) {
        // Create segments dir
        let segments_dir = import_dir.join("segments");
        let _ = std::fs::create_dir_all(&segments_dir);
        
        for i in 0..archive.len() {
            if let Ok(mut file) = archive.by_index(i) {
                let name = file.name().to_string();
                
                // Determine target path
                let target_path = if name.ends_with(".jsonl") {
                    // Put segments in segments dir
                    let fname = std::path::Path::new(&name).file_name()
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or_else(|| name.clone());
                    Some(segments_dir.join(fname))
                } else if name.ends_with("run_meta.json") || name.ends_with("manifest.json") 
                       || name.ends_with("workbench.db") || name.ends_with(".db") {
                    let fname = std::path::Path::new(&name).file_name()
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or_else(|| name.clone());
                    Some(import_dir.join(fname))
                } else {
                    None
                };
                
                if let Some(path) = target_path {
                    let mut contents = Vec::new();
                    if file.read_to_end(&mut contents).is_ok() {
                        let _ = std::fs::write(&path, &contents);
                    }
                }
            }
        }
    }
    
    // Write a run_meta.json marking this as imported (if not already present)
    let meta_path = import_dir.join("run_meta.json");
    if !meta_path.exists() {
        let meta = serde_json::json!({
            "run_id": import_id,
            "imported": true,
            "imported_at": chrono::Utc::now().to_rfc3339(),
            "source_file": filename,
            "source_size": data.len(),
            "status": "imported",
            "read_only": true,
        });
        let _ = std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap());
    }
    
    // Store raw bundle for reference
    let bundle_path = import_dir.join("bundle.zip");
    if let Err(e) = std::fs::write(&bundle_path, &data) {
        eprintln!("[import_bundle] Warning: Failed to save bundle: {}", e);
    }
    
    // Build import report
    let import_report = serde_json::json!({
        "normalized_artifacts": normalized_artifacts,
        "dropped_artifacts": dropped_artifacts,
        "evidence_deref_available": evidence_deref_available,
        "summary": {
            "total_files": normalized_artifacts.len() + dropped_artifacts.len(),
            "imported_files": normalized_artifacts.len(),
            "dropped_files": dropped_artifacts.len(),
            "segment_count": segment_count,
            "has_manifest": has_manifest,
            "has_run_meta": has_run_meta,
            "has_database": has_db
        }
    });
    
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({
            "success": true,
            "data": {
                "run_id": import_id,
                "imported": true,
                "read_only": true,
                "message": "Bundle imported successfully"
            },
            "import_report": import_report
        }).to_string()
    )
}

// ============================================================================
// Evidence Dereference Handler
// ============================================================================

/// Reason codes for unavailable evidence
#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum EvidenceDerefReasonCode {
    RunNotFound,
    SegmentNotFound,
    RecordIndexOutOfRange,
    JsonParseFailed,
    PathTraversalBlocked,
    EvidenceKindUnsupported,
    ImportedBundleMissingSegments,
    IoError,
    ScanLimitExceeded,
}

/// Query parameters for evidence dereference
#[derive(Debug, serde::Deserialize)]
struct EvidenceDerefQuery {
    run_id: String,
    stream_id: Option<String>,
    /// Segment filename (e.g., "evtx_000001.jsonl") - strictly validated
    segment_id: Option<String>,
    record_index: Option<u32>,
    kind: Option<String>,
}

/// Maximum bytes to return for a single record (256KB)
const MAX_EVIDENCE_BYTES: usize = 256 * 1024;

/// Maximum line size to read (256KB) - lines larger than this are rejected
const MAX_LINE_SIZE: usize = 256 * 1024;

/// Maximum bytes to scan before giving up (32MB)
const MAX_SCAN_BYTES: usize = 32 * 1024 * 1024;

/// Maximum record index allowed (sanity cap)
const MAX_RECORD_INDEX: u32 = 10_000_000;

/// Strict regex for segment_id validation: must be alphanumeric/._- and end with .jsonl
/// This prevents path traversal and injection attacks.
fn is_valid_segment_id(s: &str) -> bool {
    // Must match ^[A-Za-z0-9._-]+\.jsonl$
    if s.is_empty() || !s.ends_with(".jsonl") {
        return false;
    }
    // Must not contain path separators or traversal
    if s.contains('/') || s.contains('\\') || s.contains("..") {
        return false;
    }
    // All chars must be alphanumeric, underscore, hyphen, or dot
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Safely join a base directory with a filename, ensuring result stays under base.
/// Returns None if the resolved path escapes the base directory.
fn safe_join_under(base: &std::path::Path, filename: &str) -> Option<std::path::PathBuf> {
    // Reject any path separators in filename
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        return None;
    }
    let candidate = base.join(filename);
    // Canonicalize both paths and verify containment
    let base_canonical = base.canonicalize().ok()?;
    let candidate_canonical = candidate.canonicalize().ok()?;
    if candidate_canonical.starts_with(&base_canonical) {
        Some(candidate_canonical)
    } else {
        None
    }
}

/// GET /api/evidence/deref - Dereference an evidence pointer to source record
///
/// Query params:
///   - run_id: Required. The run containing the evidence.
///   - stream_id: Required for segment_record kind. The stream identifier.
///   - segment_id: Required for segment_record kind. The segment file ID.
///   - record_index: Required for segment_record kind. Line number (0-based).
///   - kind: Optional. Evidence kind (default: segment_record).
///
/// Response:
///   - success: true
///   - data.available: true|false
///   - data.reason_code: (if unavailable) RUN_NOT_FOUND, SEGMENT_NOT_FOUND, etc.
///   - data.message: (if unavailable) Human-readable error message.
///   - data.evidence_ptr: Echo of the requested pointer.
///   - data.resolved: (if available) The resolved record data.
async fn evidence_deref_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Query(query): axum::extract::Query<EvidenceDerefQuery>,
) -> axum::Json<serde_json::Value> {
    let kind = query.kind.as_deref().unwrap_or("segment_record");
    
    // Build evidence_ptr echo
    let evidence_ptr = serde_json::json!({
        "kind": kind,
        "run_id": query.run_id,
        "stream_id": query.stream_id,
        "segment_id": query.segment_id,
        "record_index": query.record_index,
    });
    
    // Only segment_record kind is supported for now
    if kind != "segment_record" {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": EvidenceDerefReasonCode::EvidenceKindUnsupported,
                "message": format!("Evidence kind '{}' is not supported. Only 'segment_record' is implemented.", kind),
                "evidence_ptr": evidence_ptr,
            }
        }));
    }
    
    // Validate required fields for segment_record
    // Note: stream_id is optional, used only for the evidence_ptr echo
    let _stream_id = query.stream_id.clone().unwrap_or_default();
    
    let segment_id = match &query.segment_id {
        Some(s) if !s.is_empty() => s.clone(),
        _ => {
            return axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": EvidenceDerefReasonCode::EvidenceKindUnsupported,
                    "message": "Missing required field: segment_id",
                    "evidence_ptr": evidence_ptr,
                }
            }));
        }
    };
    
    // SECURITY: Strict segment_id validation
    if !is_valid_segment_id(&segment_id) {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": EvidenceDerefReasonCode::PathTraversalBlocked,
                "message": "Invalid segment_id: must match ^[A-Za-z0-9._-]+\\.jsonl$",
                "evidence_ptr": evidence_ptr,
            }
        }));
    }
    
    let record_index = match query.record_index {
        Some(idx) => idx,
        None => {
            return axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": EvidenceDerefReasonCode::EvidenceKindUnsupported,
                    "message": "Missing required field: record_index",
                    "evidence_ptr": evidence_ptr,
                }
            }));
        }
    };
    
    // SECURITY: Cap record_index to prevent scanning huge files
    if record_index > MAX_RECORD_INDEX {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": EvidenceDerefReasonCode::ScanLimitExceeded,
                "message": format!("Record index {} exceeds maximum allowed ({})", record_index, MAX_RECORD_INDEX),
                "evidence_ptr": evidence_ptr,
            }
        }));
    }
    
    // Resolve run_dir
    let run_dir = state.data_dir.join("runs").join(&query.run_id);
    if !run_dir.exists() {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": EvidenceDerefReasonCode::RunNotFound,
                "message": format!("Run '{}' not found", query.run_id),
                "evidence_ptr": evidence_ptr,
            }
        }));
    }
    
    // Check if this is an imported bundle
    let meta_path = run_dir.join("run_meta.json");
    let is_imported = if let Ok(contents) = std::fs::read_to_string(&meta_path) {
        let v: serde_json::Value = serde_json::from_str(&contents).unwrap_or_default();
        v.get("imported").and_then(|v| v.as_bool()).unwrap_or(false)
    } else {
        false
    };
    
    let segments_dir = run_dir.join("segments");
    
    // Check if segments directory exists
    if !segments_dir.exists() {
        if is_imported {
            return axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": EvidenceDerefReasonCode::ImportedBundleMissingSegments,
                    "message": "This imported bundle does not include segment files. Re-import with segments enabled or export from the original run.",
                    "evidence_ptr": evidence_ptr,
                }
            }));
        } else {
            return axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": EvidenceDerefReasonCode::SegmentNotFound,
                    "message": "Segments directory does not exist for this run",
                    "evidence_ptr": evidence_ptr,
                }
            }));
        }
    }
    
    // SECURITY: Use safe_join_under to prevent path traversal
    // segment_id is already validated to match ^[A-Za-z0-9._-]+\.jsonl$
    let segment_path = match safe_join_under(&segments_dir, &segment_id) {
        Some(p) if p.exists() => p,
        _ => {
            // List available segments for debugging (max 5, sanitized)
            let available: Vec<String> = std::fs::read_dir(&segments_dir)
                .ok()
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .filter_map(|e| e.file_name().into_string().ok())
                        .filter(|n| n.ends_with(".jsonl") && is_valid_segment_id(n))
                        .take(5)
                        .collect()
                })
                .unwrap_or_default();
            
            return axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": EvidenceDerefReasonCode::SegmentNotFound,
                    "message": format!(
                        "Segment file '{}' not found. Available segments (first 5): {:?}",
                        segment_id, available
                    ),
                    "evidence_ptr": evidence_ptr,
                }
            }));
        }
    };
    
    // Compute SHA-256 of segment file (for integrity verification)
    let segment_sha256 = {
        use std::io::Read;
        use sha2::{Sha256, Digest};
        
        match std::fs::File::open(&segment_path) {
            Ok(mut f) => {
                let mut hasher = Sha256::new();
                let mut buffer = [0u8; 8192];
                loop {
                    match f.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => hasher.update(&buffer[..n]),
                        Err(_) => break,
                    }
                }
                Some(format!("{:x}", hasher.finalize()))
            }
            Err(_) => None
        }
    };
    
    // Read the specific line by scanning the JSONL file with guardrails
    let line_result = read_jsonl_line(&segment_path, record_index as usize, MAX_LINE_SIZE, MAX_SCAN_BYTES);
    
    match line_result {
        Ok(line_bytes) => {
            // Try to parse as JSON
            let (json_value, parse_error) = match serde_json::from_slice::<serde_json::Value>(&line_bytes) {
                Ok(v) => (Some(v), None),
                Err(e) => (None, Some(e.to_string())),
            };
            
            // Extract timestamp if present
            let ts_ms = json_value.as_ref().and_then(|v| {
                v.get("ts_ms").and_then(|t| t.as_i64())
            });
            
            // Create preview (first 200 chars, escaped)
            let raw_string = String::from_utf8_lossy(&line_bytes);
            let preview: String = raw_string.chars().take(200).collect();
            
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": true,
                    "evidence_ptr": evidence_ptr,
                    "resolved": {
                        "segment_path": segment_path.display().to_string(),
                        "segment_sha256": segment_sha256,
                        "record_index": record_index,
                        "line_bytes": line_bytes.len(),
                        "json": json_value,
                        "json_parse_error": parse_error,
                        "ts_ms": ts_ms,
                        "preview": preview,
                    }
                }
            }))
        }
        Err(EvidenceReadError::IndexOutOfRange { total_lines }) => {
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": EvidenceDerefReasonCode::RecordIndexOutOfRange,
                    "message": format!(
                        "Record index {} is out of range. Segment has {} lines (0-based indexing).",
                        record_index, total_lines
                    ),
                    "evidence_ptr": evidence_ptr,
                }
            }))
        }
        Err(EvidenceReadError::ScanLimitExceeded { bytes_scanned }) => {
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": EvidenceDerefReasonCode::ScanLimitExceeded,
                    "message": format!(
                        "Scan limit exceeded after {} bytes. Record index {} is too deep in the file.",
                        bytes_scanned, record_index
                    ),
                    "evidence_ptr": evidence_ptr,
                }
            }))
        }
        Err(EvidenceReadError::LineTooLarge { line_size }) => {
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": EvidenceDerefReasonCode::ScanLimitExceeded,
                    "message": format!(
                        "Line at index {} is too large ({} bytes, max {}).",
                        record_index, line_size, MAX_LINE_SIZE
                    ),
                    "evidence_ptr": evidence_ptr,
                }
            }))
        }
        Err(EvidenceReadError::IoError(msg)) => {
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": EvidenceDerefReasonCode::IoError,
                    "message": format!("Failed to read segment file: {}", msg),
                    "evidence_ptr": evidence_ptr,
                }
            }))
        }
    }
}

/// Error type for JSONL line reading
enum EvidenceReadError {
    IndexOutOfRange { total_lines: usize },
    ScanLimitExceeded { bytes_scanned: usize },
    LineTooLarge { line_size: usize },
    IoError(String),
}

/// Read a specific line from a JSONL file by line index (0-based)
/// 
/// Streams through the file without loading it all into memory.
/// Enforces scan guardrails:
/// - max_line_size: reject lines larger than this
/// - max_scan_bytes: stop scanning after this many bytes total
/// Returns the raw line bytes (without trailing newline).
fn read_jsonl_line(
    path: &std::path::Path,
    line_index: usize,
    max_line_size: usize,
    max_scan_bytes: usize,
) -> Result<Vec<u8>, EvidenceReadError> {
    use std::io::{BufRead, BufReader};
    
    let file = std::fs::File::open(path)
        .map_err(|e| EvidenceReadError::IoError(e.to_string()))?;
    
    let reader = BufReader::new(file);
    let mut current_line = 0;
    let mut bytes_scanned: usize = 0;
    
    for line_result in reader.lines() {
        match line_result {
            Ok(line) => {
                let line_len = line.len();
                bytes_scanned = bytes_scanned.saturating_add(line_len).saturating_add(1); // +1 for newline
                
                // Check scan limit BEFORE processing
                if bytes_scanned > max_scan_bytes {
                    return Err(EvidenceReadError::ScanLimitExceeded { bytes_scanned });
                }
                
                if current_line == line_index {
                    // Found the target line - check size limit
                    if line_len > max_line_size {
                        return Err(EvidenceReadError::LineTooLarge { line_size: line_len });
                    }
                    return Ok(line.into_bytes());
                }
                current_line += 1;
            }
            Err(e) => {
                return Err(EvidenceReadError::IoError(e.to_string()));
            }
        }
    }
    
    // Line not found - index out of range
    Err(EvidenceReadError::IndexOutOfRange { total_lines: current_line })
}

async fn selfcheck_handler() -> axum::Json<serde_json::Value> {
    let capture_binary = std::env::var("EDR_CAPTURE_BINARY").unwrap_or_default();
    let locald_binary = std::env::var("EDR_LOCALD_BINARY").unwrap_or_default();
    let playbooks_dir = std::env::var("EDR_PLAYBOOKS_DIR").unwrap_or_default();
    let ui_dir = std::env::var("EDR_UI_DIR").unwrap_or_default();
    
    // Instance identity for UI badge
    let pid = std::process::id();
    let port: u16 = std::env::var("EDR_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    
    let mut issues = Vec::new();
    let mut telemetry_issues = Vec::new();
    
    if !std::path::Path::new(&capture_binary).exists() {
        issues.push(format!("Capture binary missing: {}", capture_binary));
    }
    if !std::path::Path::new(&locald_binary).exists() {
        issues.push(format!("Locald binary missing: {}", locald_binary));
    }
    if !std::path::Path::new(&playbooks_dir).exists() {
        issues.push(format!("Playbooks dir missing: {}", playbooks_dir));
    }
    
    let playbook_count = std::fs::read_dir(&playbooks_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .is_some_and(|ext| ext == "yaml" || ext == "yml")
                })
                .count()
        })
        .unwrap_or(0);
    
    // Check telemetry prerequisites (Windows-specific)
    let is_admin = is_elevated();
    let mut security_log_accessible = false;
    let mut sysmon_installed = false;
    
    #[cfg(target_os = "windows")]
    {
        // Check Security log access (requires admin)
        security_log_accessible = is_admin;
        if !security_log_accessible {
            telemetry_issues.push(serde_json::json!({
                "id": "security_log_access",
                "severity": "warning",
                "title": "Security Log: Access Denied",
                "description": "Not running as Administrator. Security event log (logon, process creation) cannot be read.",
                "fix": "Run LocInt as Administrator"
            }));
        }
        
        // Check Sysmon installation by querying the event log channel
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new("wevtutil");
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        let sysmon_check = cmd
            .args(["gli", "Microsoft-Windows-Sysmon/Operational"])
            .output();
        
        sysmon_installed = sysmon_check
            .map(|o| o.status.success())
            .unwrap_or(false);
        
        if !sysmon_installed {
            telemetry_issues.push(serde_json::json!({
                "id": "sysmon_missing",
                "severity": "warning", 
                "title": "Sysmon: Not Installed",
                "description": "Microsoft Sysmon is not installed. Process, network, and file monitoring will be limited.",
                "fix": "Install Sysmon from Microsoft Sysinternals"
            }));
        }
    }
    
    // Determine overall telemetry status
    let telemetry_status = if security_log_accessible && sysmon_installed {
        "full"  // All telemetry sources available
    } else if security_log_accessible || sysmon_installed {
        "partial"  // Some telemetry available
    } else {
        "limited"  // Only System log available
    };
    
    // Overall verdict considers both binary issues and telemetry
    let verdict = if !issues.is_empty() {
        "blocked"
    } else if telemetry_status == "limited" {
        "degraded"
    } else if telemetry_status == "partial" {
        "healthy"  // Partial is acceptable
    } else {
        "healthy"
    };
    
    // Check if restart-as-admin is supported (desktop binary with known exe path)
    let (supports_restart_admin, exe_path_debug) = {
        match std::env::current_exe() {
            Ok(path) => {
                let path_str = path.to_string_lossy().to_string();
                // Only support restart if we're a real exe (not cargo run, etc.)
                let is_real_exe = path_str.ends_with(".exe") && 
                    (path_str.contains("locint") || path_str.contains("LocInt"));
                (is_real_exe, Some(path_str))
            }
            Err(_) => (false, None)
        }
    };
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "overall_status": verdict,  // UI expects this key
            "verdict": verdict,
            "is_admin": is_admin,
            "pid": pid,                 // Instance PID for UI badge
            "port": port,               // Instance port for UI badge
            "supports_restart_admin": supports_restart_admin,
            "exe_path": exe_path_debug,  // Debug only
            "issues": issues,
            "binary": "locint",
            "resources": {
                "capture_binary": capture_binary,
                "capture_exists": std::path::Path::new(&capture_binary).exists(),
                "locald_binary": locald_binary,
                "locald_exists": std::path::Path::new(&locald_binary).exists(),
                "playbooks_dir": playbooks_dir,
                "playbook_count": playbook_count,
                "ui_dir": ui_dir,
            },
            // Telemetry prerequisites (for UI to display warnings)
            "telemetry": {
                "status": telemetry_status,
                "security_log_accessible": security_log_accessible,
                "sysmon_installed": sysmon_installed,
                "issues": telemetry_issues,
            },
        }
    }))
}

// ============================================================================
// Telemetry Check Helpers (for Catalog and Selfcheck)
// ============================================================================

/// Check if Sysmon is installed by querying the event log channel
fn check_sysmon_installed() -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new("wevtutil");
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        cmd.args(["gli", "Microsoft-Windows-Sysmon/Operational"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Check if Security log is accessible (requires admin on Windows)
fn check_security_log_accessible() -> bool {
    #[cfg(target_os = "windows")]
    {
        // Security log access requires admin privileges
        is_elevated()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

// ============================================================================
// Capability Model Handlers - Always-On Sensor/Detection Visibility
// ============================================================================

use edr_server::capability::{
    PlaybookDerivedStatus, PlaybookCapabilityInfo, ActiveRunMetrics,
    check_capability_status_with_pipeline, build_coverage_gaps_report,
    mitre_tactic_to_surface, category_to_surface, generate_user_guidance,
};

/// GET /api/capability/status - Always-on sensor inventory and capability status
///
/// Returns:
/// - overall_status: "full" | "partial" | "limited" | "blocked"
/// - sensors: Array of sensor check results with status, reason_code, message
/// - fact_types_possible: What fact types can be detected with current sensors
/// - attack_surfaces: Coverage by attack surface (process, auth, persistence, etc.)
/// - pipeline: Runtime pipeline component status (binaries, directories, db)
/// - notes: User-actionable guidance
/// - is_admin: Whether running with elevation
///
/// Semantics:
/// - sensors show "configured" status (channel accessible), not "active" (facts observed)
/// - For active/observed status, query run snapshot endpoints after facts are collected
async fn capability_status_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<serde_json::Value> {
    // Get active run metrics from supervisor
    let run_status = state.supervisor.status().await;
    let active_run = if run_status.running {
        // Query metrics for events/facts/signals
        let metrics = state.supervisor.metrics().await;
        Some(ActiveRunMetrics {
            run_id: run_status.run_id.clone().unwrap_or_default(),
            capture_running: run_status.capture_running,
            locald_running: run_status.locald_running,
            segments_count: metrics.segments_count as u64,
            events_total: metrics.events_total.unwrap_or(0),
            facts_extracted: metrics.facts_extracted.unwrap_or(0),
            signals_fired: metrics.signals_fired.unwrap_or(0),
        })
    } else {
        None
    };
    
    let status = check_capability_status_with_pipeline(&state.data_dir, active_run.as_ref());
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "overall_status": status.overall_status.as_str(),
            "is_admin": status.is_admin,
            "sensors": status.sensors,
            "fact_types_possible": status.fact_types_possible,
            "attack_surfaces": status.attack_surfaces,
            "pipeline": status.pipeline,
            "notes": status.notes,
            "guidance": generate_user_guidance(&status),
        }
    }))
}

/// GET /api/capability/detection_plan - Detection plan with playbook dependencies
///
/// Returns:
/// - capability: Overall status from /api/capability/status
/// - playbooks: Categorized by derived_status (enabled, blocked_by_telemetry, etc.)
/// - coverage_by_surface: What attack surfaces are covered by enabled playbooks
/// - user_guidance: Actionable recommendations
///
/// Note: Uses "configured" sensor status for dependency resolution (what's accessible),
/// not "active" (what has produced facts). This is intentional - detection_plan shows
/// what COULD be detected, not what HAS been detected.
async fn capability_detection_plan_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<serde_json::Value> {
    // For detection plan, we use configured status (no active run metrics needed)
    // This shows what playbooks CAN run with current sensor configuration
    let cap_status = check_capability_status_with_pipeline(&state.data_dir, None);
    
    // Get playbooks directory
    let playbooks_dir = std::env::var("EDR_PLAYBOOKS_DIR").unwrap_or_default();
    
    // Parse playbooks and compute derived status
    let mut enabled_playbooks: Vec<PlaybookCapabilityInfo> = Vec::new();
    let mut blocked_playbooks: Vec<PlaybookCapabilityInfo> = Vec::new();
    let mut disabled_playbooks: Vec<PlaybookCapabilityInfo> = Vec::new();
    let mut skipped_playbooks: Vec<PlaybookCapabilityInfo> = Vec::new();
    
    let mut coverage_by_surface: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    
    // Read playbook files
    if let Ok(entries) = std::fs::read_dir(&playbooks_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.extension().is_some_and(|ext| ext == "yaml" || ext == "yml") {
                continue;
            }
            
            let yaml_content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            
            let yaml: CatalogYamlPlaybook = match serde_yaml::from_str(&yaml_content) {
                Ok(y) => y,
                Err(_) => {
                    // Invalid YAML - mark as skipped
                    let filename = path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    skipped_playbooks.push(PlaybookCapabilityInfo {
                        playbook_id: filename.clone(),
                        playbook_name: filename,
                        derived_status: PlaybookDerivedStatus::SkippedInvalid,
                        attack_surfaces: vec![],
                        blocked_by: vec!["YAML_PARSE_ERROR".to_string()],
                        reasons: vec!["Failed to parse playbook YAML".to_string()],
                    });
                    continue;
                }
            };
            
            let playbook_id = yaml.id.clone()
                .or_else(|| path.file_stem().and_then(|s| s.to_str()).map(String::from))
                .unwrap_or_else(|| "unknown".to_string());
            let playbook_name = yaml.name.clone()
                .or(yaml.title.clone())
                .unwrap_or_else(|| playbook_id.clone());
            
            // Determine attack surface from family/mitre
            let mut surfaces: Vec<String> = Vec::new();
            if let Some(ref family) = yaml.family {
                surfaces.push(category_to_surface(family).to_string());
            }
            if let Some(ref mitre) = yaml.mitre {
                for tactic in &mitre.tactics {
                    let surface = mitre_tactic_to_surface(tactic);
                    if !surfaces.contains(&surface.to_string()) {
                        surfaces.push(surface.to_string());
                    }
                }
            }
            if surfaces.is_empty() {
                surfaces.push("other".to_string());
            }
            
            // Compute derived status based on yaml.enabled and telemetry requirements
            let required_sensors = &yaml.requires;
            let mut blocked_by: Vec<String> = Vec::new();
            let mut reasons: Vec<String> = Vec::new();
            
            // Check each required sensor
            for req in required_sensors {
                let req_lower = req.to_lowercase();
                
                // Map requirement strings to sensor checks
                if req_lower.contains("sysmon") {
                    let sysmon = cap_status.sensors.iter().find(|s| s.sensor_id == "sysmon");
                    if let Some(s) = sysmon {
                        if !s.status.is_usable() {
                            blocked_by.push("sysmon".to_string());
                            if let Some(ref msg) = s.message {
                                reasons.push(msg.clone());
                            }
                        }
                    }
                }
                if req_lower.contains("security") || req_lower.contains("admin") {
                    let sec = cap_status.sensors.iter().find(|s| s.sensor_id == "security_log");
                    if let Some(s) = sec {
                        if !s.status.is_usable() {
                            blocked_by.push("security_log".to_string());
                            if let Some(ref msg) = s.message {
                                reasons.push(msg.clone());
                            }
                        }
                    }
                }
            }
            
            // Also check if fact types are available
            let fact_types_required = compute_required_fact_types(&yaml.requires);
            for ft in &fact_types_required {
                if !cap_status.fact_types_possible.contains(ft) {
                    let msg = format!("Fact type {} not available with current sensors", ft);
                    if !reasons.contains(&msg) {
                        reasons.push(msg);
                    }
                }
            }
            
            let derived_status = if !yaml.enabled {
                PlaybookDerivedStatus::DisabledByConfig
            } else if !blocked_by.is_empty() || (!fact_types_required.is_empty() && 
                fact_types_required.iter().any(|ft| !cap_status.fact_types_possible.contains(ft))) {
                PlaybookDerivedStatus::BlockedByTelemetry
            } else {
                PlaybookDerivedStatus::Enabled
            };
            
            let info = PlaybookCapabilityInfo {
                playbook_id: playbook_id.clone(),
                playbook_name: playbook_name.clone(),
                derived_status,
                attack_surfaces: surfaces.clone(),
                blocked_by,
                reasons,
            };
            
            match derived_status {
                PlaybookDerivedStatus::Enabled => {
                    // Track coverage
                    for surface in &surfaces {
                        coverage_by_surface
                            .entry(surface.clone())
                            .or_default()
                            .push(playbook_name.clone());
                    }
                    enabled_playbooks.push(info);
                }
                PlaybookDerivedStatus::BlockedByTelemetry => blocked_playbooks.push(info),
                PlaybookDerivedStatus::DisabledByConfig => disabled_playbooks.push(info),
                PlaybookDerivedStatus::SkippedInvalid => skipped_playbooks.push(info),
            }
        }
    }
    
    let total = enabled_playbooks.len() + blocked_playbooks.len() + disabled_playbooks.len() + skipped_playbooks.len();
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "capability": {
                "overall_status": cap_status.overall_status.as_str(),
                "is_admin": cap_status.is_admin,
                "sensors": cap_status.sensors,
            },
            "playbooks": {
                "total": total,
                "enabled": enabled_playbooks,
                "blocked_by_telemetry": blocked_playbooks,
                "disabled_by_config": disabled_playbooks,
                "skipped_invalid": skipped_playbooks,
            },
            "coverage_by_surface": coverage_by_surface,
            "user_guidance": generate_user_guidance(&cap_status),
        }
    }))
}

/// Helper to compute required fact types from playbook 'requires' field
fn compute_required_fact_types(requires: &[String]) -> Vec<String> {
    let mut fact_types = Vec::new();
    for req in requires {
        let req_lower = req.to_lowercase();
        // Map common requirement patterns to fact types
        if req_lower.contains("procspawn") || req_lower.contains("process") {
            if !fact_types.contains(&"ProcSpawn".to_string()) {
                fact_types.push("ProcSpawn".to_string());
            }
        }
        if req_lower.contains("exec") {
            if !fact_types.contains(&"Exec".to_string()) {
                fact_types.push("Exec".to_string());
            }
        }
        if req_lower.contains("auth") || req_lower.contains("logon") {
            if !fact_types.contains(&"AuthEvent".to_string()) {
                fact_types.push("AuthEvent".to_string());
            }
        }
        if req_lower.contains("network") || req_lower.contains("connect") {
            if !fact_types.contains(&"OutboundConnect".to_string()) {
                fact_types.push("OutboundConnect".to_string());
            }
        }
        if req_lower.contains("dns") {
            if !fact_types.contains(&"DnsResolve".to_string()) {
                fact_types.push("DnsResolve".to_string());
            }
        }
        if req_lower.contains("file") || req_lower.contains("path") {
            if !fact_types.contains(&"WritePath".to_string()) {
                fact_types.push("WritePath".to_string());
            }
        }
        if req_lower.contains("registry") {
            if !fact_types.contains(&"RegistryMod".to_string()) {
                fact_types.push("RegistryMod".to_string());
            }
        }
    }
    fact_types
}

/// GET /api/capability/gaps - Coverage gaps analysis (dev-only planning tool)
///
/// Returns per-attack-surface gap analysis showing:
/// - What's configured vs what's possible
/// - Which playbooks are enabled/blocked per surface
/// - Missing prerequisites (sensors, permissions)
/// - Recommendations to improve coverage
///
/// Optional query params:
/// - run_id: Include observed facts from a specific run
async fn capability_gaps_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::Json<serde_json::Value> {
    // Get capability status
    let cap_status = check_capability_status_with_pipeline(&state.data_dir, None);
    
    // Get playbooks directory
    let playbooks_dir = std::env::var("EDR_PLAYBOOKS_DIR").unwrap_or_default();
    
    // Count playbooks by surface and status
    let mut playbook_counts: std::collections::HashMap<String, (u32, u32, u32)> = std::collections::HashMap::new();
    // Initialize all surfaces
    for surface in ["process", "auth", "persistence", "network", "evasion", "file"] {
        playbook_counts.insert(surface.to_string(), (0, 0, 0));
    }
    
    // Parse playbooks to count by surface
    if let Ok(entries) = std::fs::read_dir(&playbooks_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.extension().is_some_and(|ext| ext == "yaml" || ext == "yml") {
                continue;
            }
            
            let yaml_content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            
            let yaml: CatalogYamlPlaybook = match serde_yaml::from_str(&yaml_content) {
                Ok(y) => y,
                Err(_) => continue,
            };
            
            // Determine surface from family/mitre
            let surface = if let Some(ref family) = yaml.family {
                category_to_surface(family).to_string()
            } else if let Some(ref mitre) = yaml.mitre {
                mitre.tactics.first()
                    .map(|t| mitre_tactic_to_surface(t).to_string())
                    .unwrap_or_else(|| "other".to_string())
            } else {
                "other".to_string()
            };
            
            // Check if blocked by telemetry
            let blocked = yaml.requires.iter().any(|req| {
                let req_lower = req.to_lowercase();
                (req_lower.contains("sysmon") && !cap_status.sensors.iter()
                    .any(|s| s.sensor_id == "sysmon" && s.status.is_usable())) ||
                (req_lower.contains("security") && !cap_status.sensors.iter()
                    .any(|s| s.sensor_id == "security_log" && s.status.is_usable()))
            });
            
            // Update counts
            if let Some(counts) = playbook_counts.get_mut(&surface) {
                if !yaml.enabled {
                    // Disabled by config - don't count
                } else if blocked {
                    counts.1 += 1; // blocked
                } else {
                    counts.0 += 1; // enabled
                }
            }
        }
    }
    
    // Get observed fact types from run if run_id provided
    let run_id = params.get("run_id").cloned();
    let observed_fact_types: Option<Vec<String>> = if let Some(ref rid) = run_id {
        // Query workbench for fact types observed in this run
        let db_path = state.data_dir.join("workbench.db");
        if db_path.exists() {
            if let Ok(conn) = rusqlite::Connection::open(&db_path) {
                let mut stmt = conn.prepare(
                    "SELECT DISTINCT fact_type FROM facts WHERE run_id = ?"
                ).ok();
                if let Some(ref mut s) = stmt {
                    let types: Vec<String> = s.query_map([rid], |row| row.get(0))
                        .ok()
                        .map(|rows| rows.filter_map(|r| r.ok()).collect())
                        .unwrap_or_default();
                    if !types.is_empty() {
                        Some(types)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    
    // Build gaps report
    let report = build_coverage_gaps_report(
        &cap_status,
        Some(&playbook_counts),
        observed_fact_types.as_deref(),
        run_id.as_deref(),
    );
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": report
    }))
}

// ============================================================================
// Playbook Catalog Handler - Detection Plan (System-Wide)
// ============================================================================

/// YAML structure for parsing playbook metadata (catalog view)
#[derive(Debug, Clone, serde::Deserialize)]
struct CatalogYamlPlaybook {
    id: Option<String>,
    name: Option<String>,
    title: Option<String>,
    description: Option<String>,
    family: Option<String>,
    #[serde(default = "default_enabled_true")]
    enabled: bool,
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    mitre: Option<CatalogYamlMitre>,
    #[serde(default)]
    input_facts: Option<CatalogYamlInputFacts>,
    #[serde(default)]
    slots: Option<CatalogYamlSlots>,
    #[serde(default)]
    rules: Option<Vec<CatalogYamlRule>>,
}

fn default_enabled_true() -> bool { true }

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct CatalogYamlMitre {
    #[serde(default)]
    tactics: Vec<String>,
    #[serde(default)]
    techniques: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct CatalogYamlInputFacts {
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    optional: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct CatalogYamlSlots {
    #[serde(default)]
    required: Vec<CatalogYamlSlot>,
    #[serde(default)]
    optional: Vec<CatalogYamlSlot>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct CatalogYamlSlot {
    name: String,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    pattern: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct CatalogYamlRule {
    name: String,
    #[serde(default)]
    conditions: Vec<serde_json::Value>,  // Generic value, we don't need to parse deeply
}

/// Playbook catalog entry (safe to expose to UI)
#[derive(Debug, Clone, serde::Serialize)]
struct PlaybookCatalogEntry {
    playbook_id: String,
    name: String,
    description: String,
    category: String,
    mitre_techniques: Vec<String>,
    mitre_tactics: Vec<String>,
    severity_default: String,
    required_sensors: Vec<String>,
    required_fact_types: Vec<String>,
    slots_summary: Vec<SlotSummary>,
    /// Enhanced slot definitions for UI interaction (no regex exposed)
    slots_ui: Vec<SlotUIDefinition>,
    enabled: bool,
    disabled_reason: Option<String>,
    telemetry_blocked: bool,
    telemetry_blocked_reasons: Vec<String>,
    /// Optional validation hint ID for debug mode benign triggers
    #[serde(skip_serializing_if = "Option::is_none")]
    validation_hint_id: Option<String>,
    /// "How it fires" safe guidance text
    how_it_fires: String,
    /// Prerequisites summary
    prerequisites: PlaybookPrerequisites,
}

/// Enhanced slot definition for UI (no raw regex)
#[derive(Debug, Clone, serde::Serialize)]
struct SlotUIDefinition {
    slot_name: String,
    /// Human-readable intent (e.g., "Encoded PowerShell flags in command line")
    intent: String,
    /// Fields captured as evidence
    required_fields: Vec<String>,
    /// Safe example hints (generic, not full commands)
    examples_hint: Vec<String>,
    /// Telemetry dependencies
    telemetry_dependency: Vec<String>,
    required: bool,
}

/// Prerequisites summary for a playbook
#[derive(Debug, Clone, serde::Serialize)]
struct PlaybookPrerequisites {
    requires_admin: bool,
    requires_sysmon: bool,
    requires_security_log: bool,
    sensors: Vec<String>,
    fact_types: Vec<String>,
}

/// Slot summary (intent-based, no raw regex)
#[derive(Debug, Clone, serde::Serialize)]
struct SlotSummary {
    slot_name: String,
    intent: String,
    evidence_fields: Vec<String>,
    required: bool,
}

/// GET /api/playbooks/catalog - Detection Plan: All available playbooks with metadata
///
/// Returns playbook catalog derived from YAML files, cross-referenced with
/// current selfcheck/telemetry status to show what's actually detectable.
async fn playbooks_catalog_handler() -> axum::Json<serde_json::Value> {
    // Step 1: Discover playbooks directory
    let (playbooks_dir, searched_paths, not_found_reason) = discover_playbooks_dir();
    
    if playbooks_dir.is_none() {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "available": false,
                "reason_code": "PLAYBOOKS_NOT_FOUND",
                "message": not_found_reason.unwrap_or_else(|| "Playbooks directory not found".to_string()),
                "searched_paths": searched_paths,
                "playbooks_dir": null,
                "loaded_count": 0,
                "skipped_count": 0,
                "skipped_by_reason": {},
                "playbooks": [],
                "detection_plan_summary": {
                    "total_enabled": 0,
                    "blocked_by_telemetry": 0,
                    "requires_admin_count": 0,
                    "requires_sysmon_count": 0
                }
            }
        }));
    }
    
    let pb_dir = playbooks_dir.unwrap();
    let windows_dir = pb_dir.join("windows");
    let target_dir = if windows_dir.exists() { windows_dir } else { pb_dir.clone() };
    
    // Step 2: Get current telemetry status from selfcheck
    let is_admin = is_elevated();
    let sysmon_installed = check_sysmon_installed();
    let security_log_accessible = check_security_log_accessible();
    
    // Step 3: Parse all YAML files
    let mut playbooks: Vec<PlaybookCatalogEntry> = Vec::new();
    let mut skipped_count = 0u32;
    let mut skipped_by_reason: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut total_yaml_files = 0u32;
    
    if let Ok(entries) = std::fs::read_dir(&target_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yaml" && ext != "yml" {
                continue;
            }
            
            total_yaml_files += 1;
            let filename = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            
            // Parse YAML
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    match serde_yaml::from_str::<CatalogYamlPlaybook>(&content) {
                        Ok(yaml) => {
                            let playbook_id = yaml.id
                                .or(yaml.name.clone())
                                .unwrap_or_else(|| filename.trim_end_matches(".yaml").trim_end_matches(".yml").to_string());
                            
                            let name = yaml.title
                                .or(yaml.name.clone())
                                .unwrap_or_else(|| playbook_id.clone());
                            
                            // Extract description (first line if multi-line)
                            let description = yaml.description
                                .map(|d: String| d.lines().next().unwrap_or(&d).trim().to_string())
                                .unwrap_or_else(|| format!("Detection for {}", name));
                            
                            let category = yaml.family.unwrap_or_else(|| "unknown".to_string());
                            
                            // MITRE mappings
                            let mitre = yaml.mitre.unwrap_or_default();
                            let mitre_techniques = mitre.techniques;
                            let mitre_tactics = mitre.tactics;
                            
                            // Determine required sensors from `requires` field and fact types
                            let mut required_sensors: Vec<String> = yaml.requires.clone();
                            
                            // Get fact types from input_facts and rules
                            let mut required_fact_types: Vec<String> = Vec::new();
                            if let Some(ref input_facts) = yaml.input_facts {
                                required_fact_types.extend(input_facts.required.clone());
                                required_fact_types.extend(input_facts.optional.clone());
                            }
                            
                            // Infer sensors from fact types
                            for ft in &required_fact_types {
                                let ft_lower = ft.to_lowercase();
                                if ft_lower.contains("exec") || ft_lower.contains("proc") {
                                    if !required_sensors.iter().any(|s: &String| s.to_lowercase() == "sysmon") {
                                        required_sensors.push("Sysmon".to_string());
                                    }
                                }
                                if ft_lower.contains("auth") || ft_lower.contains("logon") {
                                    if !required_sensors.iter().any(|s: &String| s.to_lowercase().contains("security")) {
                                        required_sensors.push("SecurityLog".to_string());
                                    }
                                }
                            }
                            
                            // Parse slots for summary (no raw regex exposed)
                            let mut slots_summary: Vec<SlotSummary> = Vec::new();
                            let mut slots_ui: Vec<SlotUIDefinition> = Vec::new();
                            if let Some(ref slots) = yaml.slots {
                                for slot in &slots.required {
                                    let intent = infer_slot_intent(&slot.name, slot.pattern.as_deref());
                                    let evidence_fields = infer_evidence_fields(&slot.name);
                                    let telemetry_dep = infer_telemetry_dependency(&slot.name, slot.pattern.as_deref());
                                    let examples = infer_examples_hint(&slot.name, slot.pattern.as_deref());
                                    
                                    slots_summary.push(SlotSummary {
                                        slot_name: slot.name.clone(),
                                        intent: intent.clone(),
                                        evidence_fields: evidence_fields.clone(),
                                        required: true,
                                    });
                                    slots_ui.push(SlotUIDefinition {
                                        slot_name: slot.name.clone(),
                                        intent,
                                        required_fields: evidence_fields,
                                        examples_hint: examples,
                                        telemetry_dependency: telemetry_dep,
                                        required: true,
                                    });
                                }
                                for slot in &slots.optional {
                                    let intent = infer_slot_intent(&slot.name, slot.pattern.as_deref());
                                    let evidence_fields = infer_evidence_fields(&slot.name);
                                    let telemetry_dep = infer_telemetry_dependency(&slot.name, slot.pattern.as_deref());
                                    let examples = infer_examples_hint(&slot.name, slot.pattern.as_deref());
                                    
                                    slots_summary.push(SlotSummary {
                                        slot_name: slot.name.clone(),
                                        intent: intent.clone(),
                                        evidence_fields: evidence_fields.clone(),
                                        required: false,
                                    });
                                    slots_ui.push(SlotUIDefinition {
                                        slot_name: slot.name.clone(),
                                        intent,
                                        required_fields: evidence_fields,
                                        examples_hint: examples,
                                        telemetry_dependency: telemetry_dep,
                                        required: false,
                                    });
                                }
                            }
                            
                            // Determine if telemetry is blocked
                            let mut telemetry_blocked = false;
                            let mut telemetry_blocked_reasons: Vec<String> = Vec::new();
                            
                            let requires_sysmon = required_sensors.iter().any(|s: &String| s.to_lowercase() == "sysmon");
                            let requires_security_log = required_sensors.iter().any(|s: &String| s.to_lowercase().contains("security"));
                            let requires_admin = required_sensors.iter().any(|s: &String| s.to_lowercase().contains("admin")) || requires_security_log;
                            
                            if requires_sysmon && !sysmon_installed {
                                telemetry_blocked = true;
                                telemetry_blocked_reasons.push("Sysmon not installed".to_string());
                            }
                            if requires_security_log && !security_log_accessible {
                                telemetry_blocked = true;
                                telemetry_blocked_reasons.push("Security log not accessible".to_string());
                            }
                            if requires_admin && !is_admin {
                                telemetry_blocked = true;
                                telemetry_blocked_reasons.push("Requires administrator privileges".to_string());
                            }
                            
                            // Determine disabled reason
                            let disabled_reason = if !yaml.enabled {
                                Some("Disabled in playbook configuration".to_string())
                            } else if telemetry_blocked {
                                Some(telemetry_blocked_reasons.join("; "))
                            } else {
                                None
                            };
                            
                            // Build "how it fires" safe guidance
                            let how_it_fires = infer_how_it_fires(&playbook_id, &category, &slots_summary);
                            
                            // Build prerequisites summary
                            let prerequisites = PlaybookPrerequisites {
                                requires_admin,
                                requires_sysmon,
                                requires_security_log,
                                sensors: required_sensors.clone(),
                                fact_types: required_fact_types.clone(),
                            };
                            
                            // Get validation hint ID if available (for debug mode)
                            let validation_hint_id = get_validation_hint_id(&playbook_id);
                            
                            playbooks.push(PlaybookCatalogEntry {
                                playbook_id,
                                name,
                                description,
                                category,
                                mitre_techniques,
                                mitre_tactics,
                                severity_default: "MEDIUM".to_string(), // Default, could parse from rules
                                required_sensors,
                                required_fact_types,
                                slots_summary,
                                slots_ui,
                                enabled: yaml.enabled && !telemetry_blocked,
                                disabled_reason,
                                telemetry_blocked,
                                telemetry_blocked_reasons,
                                validation_hint_id,
                                how_it_fires,
                                prerequisites,
                            });
                        }
                        Err(_e) => {
                            skipped_count += 1;
                            *skipped_by_reason.entry("PARSE_ERROR".to_string()).or_insert(0) += 1;
                        }
                    }
                }
                Err(_) => {
                    skipped_count += 1;
                    *skipped_by_reason.entry("READ_ERROR".to_string()).or_insert(0) += 1;
                }
            }
        }
    }
    
    // Step 4: Compute detection plan summary
    let total_enabled = playbooks.iter().filter(|p| p.enabled).count() as u32;
    let blocked_by_telemetry = playbooks.iter().filter(|p| p.telemetry_blocked).count() as u32;
    let requires_admin_count = playbooks.iter().filter(|p| {
        p.required_sensors.iter().any(|s| s.to_lowercase().contains("security") || s.to_lowercase().contains("admin"))
    }).count() as u32;
    let requires_sysmon_count = playbooks.iter().filter(|p| {
        p.required_sensors.iter().any(|s| s.to_lowercase() == "sysmon")
    }).count() as u32;
    
    axum::Json(serde_json::json!({
        "success": true,
        "data": {
            "available": true,
            "playbooks_dir": target_dir.display().to_string(),
            "loaded_count": playbooks.len(),
            "skipped_count": skipped_count,
            "skipped_by_reason": skipped_by_reason,
            "playbooks": playbooks,
            "detection_plan_summary": {
                "total_enabled": total_enabled,
                "blocked_by_telemetry": blocked_by_telemetry,
                "requires_admin_count": requires_admin_count,
                "requires_sysmon_count": requires_sysmon_count
            },
            "current_telemetry": {
                "is_admin": is_admin,
                "sysmon_installed": sysmon_installed,
                "security_log_accessible": security_log_accessible
            }
        }
    }))
}

/// Infer slot intent from name and pattern (do NOT expose raw regex)
fn infer_slot_intent(name: &str, pattern: Option<&str>) -> String {
    let name_lower = name.to_lowercase();
    
    // Check name first
    if name_lower.contains("process") || name_lower.contains("exec") || name_lower.contains("cmd") {
        return "process execution".to_string();
    }
    if name_lower.contains("auth") || name_lower.contains("logon") || name_lower.contains("login") {
        return "authentication".to_string();
    }
    if name_lower.contains("persist") || name_lower.contains("registry") || name_lower.contains("startup") {
        return "persistence".to_string();
    }
    if name_lower.contains("net") || name_lower.contains("connect") || name_lower.contains("url") || name_lower.contains("remote") {
        return "network activity".to_string();
    }
    if name_lower.contains("file") || name_lower.contains("path") || name_lower.contains("write") {
        return "file activity".to_string();
    }
    if name_lower.contains("inject") || name_lower.contains("memory") || name_lower.contains("load") {
        return "memory/injection".to_string();
    }
    if name_lower.contains("script") || name_lower.contains("powershell") || name_lower.contains("encode") {
        return "script execution".to_string();
    }
    if name_lower.contains("service") || name_lower.contains("schtask") || name_lower.contains("task") {
        return "scheduled task/service".to_string();
    }
    
    // Check pattern hints (without exposing regex)
    if let Some(p) = pattern {
        let p_lower = p.to_lowercase();
        if p_lower.contains("powershell") || p_lower.contains("cmd.exe") || p_lower.contains("wscript") {
            return "command execution".to_string();
        }
        if p_lower.contains("http") || p_lower.contains("://") {
            return "URL/network".to_string();
        }
    }
    
    "detection criteria".to_string()
}

/// Infer evidence fields from slot name
fn infer_evidence_fields(name: &str) -> Vec<String> {
    let name_lower = name.to_lowercase();
    let mut fields = Vec::new();
    
    if name_lower.contains("process") || name_lower.contains("exec") {
        fields.extend(["proc_key", "cmdline", "parent_proc"].iter().map(|s| s.to_string()));
    }
    if name_lower.contains("file") || name_lower.contains("path") {
        fields.extend(["file_path", "file_hash"].iter().map(|s| s.to_string()));
    }
    if name_lower.contains("net") || name_lower.contains("url") || name_lower.contains("remote") {
        fields.extend(["dest_ip", "dest_port", "url"].iter().map(|s| s.to_string()));
    }
    if name_lower.contains("registry") {
        fields.extend(["reg_key", "reg_value"].iter().map(|s| s.to_string()));
    }
    if name_lower.contains("user") || name_lower.contains("auth") {
        fields.extend(["user", "domain", "logon_type"].iter().map(|s| s.to_string()));
    }
    
    if fields.is_empty() {
        fields.push("event_data".to_string());
    }
    
    fields
}

/// Infer telemetry dependencies from slot name and pattern
fn infer_telemetry_dependency(name: &str, pattern: Option<&str>) -> Vec<String> {
    let name_lower = name.to_lowercase();
    let mut deps = Vec::new();
    
    // Process execution typically requires Sysmon
    if name_lower.contains("process") || name_lower.contains("exec") || name_lower.contains("cmd") {
        deps.push("Sysmon".to_string());
    }
    // Auth events require Security log
    if name_lower.contains("auth") || name_lower.contains("logon") {
        deps.push("SecurityLog".to_string());
    }
    // Registry events require Sysmon or Security
    if name_lower.contains("registry") || name_lower.contains("run_key") {
        deps.push("Sysmon".to_string());
    }
    // Service/scheduled task events require System or Security
    if name_lower.contains("service") || name_lower.contains("task") || name_lower.contains("schtask") {
        deps.push("SecurityLog".to_string());
    }
    // Network connections require Sysmon
    if name_lower.contains("net") || name_lower.contains("connect") {
        deps.push("Sysmon".to_string());
    }
    
    // Check pattern hints
    if let Some(p) = pattern {
        let p_lower = p.to_lowercase();
        if p_lower.contains("powershell") || p_lower.contains("cmd.exe") {
            if !deps.contains(&"Sysmon".to_string()) {
                deps.push("Sysmon".to_string());
            }
        }
    }
    
    if deps.is_empty() {
        deps.push("ETW".to_string());
    }
    
    deps
}

/// Infer safe example hints from slot name (NO full commands, NO real patterns)
fn infer_examples_hint(name: &str, pattern: Option<&str>) -> Vec<String> {
    let name_lower = name.to_lowercase();
    let mut hints = Vec::new();
    
    // Process/command hints
    if name_lower.contains("process") || name_lower.contains("exec") {
        hints.push("Process creation events".to_string());
    }
    if name_lower.contains("encoded") {
        hints.push("Encoded/obfuscated command flags".to_string());
    }
    if name_lower.contains("bypass") {
        hints.push("Policy bypass flags".to_string());
    }
    if name_lower.contains("hidden") {
        hints.push("Hidden window flags".to_string());
    }
    
    // Pattern-based hints (safe, no regex exposed)
    if let Some(p) = pattern {
        let p_lower = p.to_lowercase();
        if p_lower.contains("powershell") {
            hints.push("PowerShell interpreter activity".to_string());
        }
        if p_lower.contains("schtasks") {
            hints.push("Task scheduler commands".to_string());
        }
        if p_lower.contains("registry") || p_lower.contains("run") {
            hints.push("Registry persistence paths".to_string());
        }
        if p_lower.contains("service") || p_lower.contains("sc.exe") {
            hints.push("Service configuration commands".to_string());
        }
        if p_lower.contains("lsass") {
            hints.push("Credential store access".to_string());
        }
    }
    
    if hints.is_empty() {
        hints.push("Matching event patterns".to_string());
    }
    
    hints
}

/// Generate safe "how it fires" guidance for a playbook
fn infer_how_it_fires(playbook_id: &str, category: &str, slots: &[SlotSummary]) -> String {
    let pb_lower = playbook_id.to_lowercase();
    let cat_lower = category.to_lowercase();
    
    // Specific playbook guidance
    if pb_lower.contains("encoded_powershell") {
        return "Fires when PowerShell is executed with -EncodedCommand or similar obfuscation flags. Requires process creation telemetry (Sysmon Event 1 or Security Event 4688).".to_string();
    }
    if pb_lower.contains("schtasks") {
        return "Fires when schtasks.exe creates or modifies a scheduled task, especially with elevated privileges or on remote systems. Requires process creation and Security Event 4698.".to_string();
    }
    if pb_lower.contains("service_persistence") || pb_lower.contains("sc_abuse") {
        return "Fires when sc.exe creates or modifies a Windows service. Requires process creation and System Event 7045.".to_string();
    }
    if pb_lower.contains("registry_persistence") {
        return "Fires when a program modifies Run/RunOnce registry keys for persistence. Requires Sysmon Event 13 or Security Event 4657.".to_string();
    }
    if pb_lower.contains("credential_access") || pb_lower.contains("lsass") {
        return "Fires when a process accesses LSASS memory, which may indicate credential dumping. Requires Sysmon Event 10 (ProcessAccess).".to_string();
    }
    if pb_lower.contains("certutil") {
        return "Fires when certutil.exe is used to decode or download files, a common LOLBin technique. Requires process creation telemetry.".to_string();
    }
    
    // Category-based fallback
    let slot_intents: Vec<&str> = slots.iter().filter(|s| s.required).map(|s| s.intent.as_str()).collect();
    let required_slots = if !slot_intents.is_empty() {
        format!("Required evidence: {}.", slot_intents.join(", "))
    } else {
        String::new()
    };
    
    match cat_lower.as_str() {
        "execution" => format!("Fires when suspicious command execution patterns are detected. {}", required_slots),
        "persistence" => format!("Fires when persistence mechanisms are created or modified. {}", required_slots),
        "credential_access" => format!("Fires when credential theft indicators are observed. {}", required_slots),
        "defense_evasion" => format!("Fires when defense evasion techniques are detected. {}", required_slots),
        "lateral_movement" => format!("Fires when lateral movement indicators are observed. {}", required_slots),
        _ => format!("Fires when detection criteria are met. {}", required_slots),
    }
}

/// Get validation hint ID for known playbooks (debug mode benign triggers)
/// Only returns IDs for playbooks with vetted safe validation commands
fn get_validation_hint_id(playbook_id: &str) -> Option<String> {
    let pb_lower = playbook_id.to_lowercase();
    
    // Map playbook IDs to validation hint IDs
    // ONLY include playbooks with safe, vetted triggers in VALIDATION_RUN.md
    if pb_lower.contains("encoded_powershell") {
        return Some("encoded_powershell_whoami".to_string());
    }
    if pb_lower.contains("schtasks") || pb_lower.contains("task_persistence") {
        return Some("schtasks_create_delete".to_string());
    }
    if pb_lower.contains("service_persistence") || pb_lower.contains("sc_abuse") {
        return Some("service_create_delete".to_string());
    }
    if pb_lower.contains("registry_persistence") {
        return Some("registry_run_key".to_string());
    }
    if pb_lower.contains("certutil") {
        return Some("certutil_decode".to_string());
    }
    
    None
}

/// POST /api/app/restart_admin - Restart as Administrator
/// 
/// Relaunches the application with elevated privileges via UAC prompt.
/// Only works when running as desktop binary (locint.exe).
///
/// Response:
/// - Already admin: `{success: true, data: {relaunching: false, message: "Already elevated"}}`
/// - Not supported: `{success: false, error: {code: "RESTART_NOT_SUPPORTED", message: "..."}}`
/// - UAC canceled: `{success: false, error: {code: "UAC_CANCELED", message: "..."}}`
/// - UAC failed: `{success: false, error: {code: "UAC_FAILED", message: "..."}}`
/// - Success: `{success: true, data: {relaunching: true}}` (then process exits)
async fn restart_admin_handler() -> axum::Json<serde_json::Value> {
    // Check if already admin
    if is_elevated() {
        return axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "relaunching": false,
                "message": "Already running as Administrator"
            }
        }));
    }
    
    // Get current exe path
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return axum::Json(serde_json::json!({
                "success": false,
                "error": {
                    "code": "RESTART_NOT_SUPPORTED",
                    "message": format!("Cannot determine executable path: {}", e)
                }
            }));
        }
    };
    
    // Verify it's a real exe we can relaunch
    let path_str = exe_path.to_string_lossy().to_string();
    if !path_str.ends_with(".exe") {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "RESTART_NOT_SUPPORTED",
                "message": "Not running as a Windows executable. Please run as Administrator manually."
            }
        }));
    }
    
    // Windows-specific: Use ShellExecuteW with "runas" verb
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr::null_mut;
        
        // Wide string helpers
        fn to_wide(s: &str) -> Vec<u16> {
            OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
        }
        
        let verb = to_wide("runas");
        
        // Preserve ALL relevant environment variables as command-line-style env prefix
        // These are the env vars locint.exe respects:
        let env_vars_to_preserve = [
            "EDR_SERVER_PORT",
            "EDR_CAPTURE_BINARY",
            "EDR_LOCALD_BINARY",
            "EDR_PLAYBOOKS_DIR",
            "EDR_UI_DIR",
            "LOCINT_PLAYBOOKS",
            "RUST_LOG",
        ];
        
        // Build environment block for the new process
        // ShellExecuteW doesn't support env directly, so we use a cmd wrapper
        // that sets env vars then launches the exe
        let mut env_prefix = String::new();
        for var_name in &env_vars_to_preserve {
            if let Ok(val) = std::env::var(var_name) {
                if !val.is_empty() {
                    // Escape double quotes in value for cmd.exe
                    let escaped = val.replace('"', r#""""#);
                    env_prefix.push_str(&format!(r#"set "{}={}" && "#, var_name, escaped));
                }
            }
        }
        
        // If we have env vars to preserve, use cmd /c to set them
        let (launch_file, launch_args) = if env_prefix.is_empty() {
            // No special env vars - launch exe directly
            (path_str.clone(), String::new())
        } else {
            // Use cmd.exe to set env vars then launch
            let cmd_line = format!(r#"{}"{}""#, env_prefix, path_str);
            ("cmd.exe".to_string(), format!("/c {}", cmd_line))
        };
        
        let file_wide = to_wide(&launch_file);
        let args_wide = to_wide(&launch_args);
        
        // Working directory (exe's directory)
        let work_dir = exe_path.parent()
            .map(|p| to_wide(&p.to_string_lossy()))
            .unwrap_or_else(|| to_wide(""));
        
        // Log what we're doing
        tracing::info!("Restarting as Administrator: {}", path_str);
        if !env_prefix.is_empty() {
            tracing::info!("Preserving env vars via cmd wrapper");
        }
        
        let result = unsafe {
            windows_sys::Win32::UI::Shell::ShellExecuteW(
                null_mut(),                     // hwnd
                verb.as_ptr(),                  // lpOperation ("runas")
                file_wide.as_ptr(),             // lpFile
                args_wide.as_ptr(),             // lpParameters
                work_dir.as_ptr(),              // lpDirectory
                windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL as i32,
            )
        };
        
        // ShellExecuteW returns > 32 on success
        if result as usize > 32 {
            // Success - spawn a task to exit after response is fully sent
            // Use a oneshot channel to ensure response completes before exit
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            
            tokio::spawn(async move {
                // Wait for signal that response was sent, or timeout after 2s
                let _ = tokio::time::timeout(
                    tokio::time::Duration::from_secs(2),
                    rx
                ).await;
                
                // Additional small delay to ensure TCP flush
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                tracing::info!("Exiting for admin restart...");
                std::process::exit(0);
            });
            
            // Signal that we're about to return the response
            // (the actual send happens when this function returns)
            let _ = tx.send(());
            
            return axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "relaunching": true,
                    "port": std::env::var("EDR_SERVER_PORT").unwrap_or_else(|_| "4035".to_string())
                }
            }));
        } else {
            // ShellExecuteW failed
            let error_code = result as u32;
            let (code, message) = match error_code {
                // ERROR_CANCELLED (1223) - user clicked No on UAC
                1223 => ("UAC_CANCELED", "User declined the elevation prompt"),
                // Other errors
                _ => ("UAC_FAILED", "Failed to restart with elevation"),
            };
            
            return axum::Json(serde_json::json!({
                "success": false,
                "error": {
                    "code": code,
                    "message": message,
                    "win32_error": error_code
                }
            }));
        }
    }
    
    // Non-Windows: not supported
    #[cfg(not(target_os = "windows"))]
    {
        axum::Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "RESTART_NOT_SUPPORTED",
                "message": "Admin restart is only supported on Windows"
            }
        }))
    }
}

/// GET /api/features - Feature flags
/// Returns compile-time features enabled in this build
/// CORE PRODUCT: Used by UI to show/hide non-core tabs
async fn features_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "success": true,
        "features": {
            // Core features (always enabled)
            "core": true,
            "bundle_exchange": true,
            "pdf_export": true,
            
            // Non-core features (compile-time gated)
            "diff": cfg!(feature = "diff"),
            "narrative": cfg!(feature = "narrative"),
            "watermark": cfg!(feature = "watermark"),
            "golden_bundle": cfg!(feature = "golden_bundle"),
            "support_bundle": cfg!(feature = "support_bundle"),
            "integrations": cfg!(feature = "integrations"),
            
            // UI feature flags (for showing/hiding tabs)
            "diff_mode": cfg!(feature = "diff"),
            "timeline": cfg!(feature = "diff"),  // Timeline requires diff
            "playbook_debug": cfg!(feature = "dev_utils"),
            
            // Legacy (for backward compat)
            "pro_reports": cfg!(feature = "pro")
        }
    }))
}

/// GET /api/capture/profiles - List capture profiles (parity with edr-server)
async fn capture_profiles_handler() -> axum::Json<serde_json::Value> {
    // Return same profile structure as edr-server
    axum::Json(serde_json::json!({
        "success": true,
        "profiles": [
            {
                "id": "core",
                "description": "Essential telemetry for rapid detection",
                "sensors_count": 3,
                "collectors_count": 2,
                "global_event_rate": 5000,
                "global_byte_rate": 10485760
            },
            {
                "id": "extended",
                "description": "Full telemetry coverage",
                "sensors_count": 5,
                "collectors_count": 4,
                "global_event_rate": 10000,
                "global_byte_rate": 52428800
            },
            {
                "id": "forensic",
                "description": "Maximum detail for forensic analysis",
                "sensors_count": 7,
                "collectors_count": 6,
                "global_event_rate": 50000,
                "global_byte_rate": 104857600
            }
        ]
    }))
}

// ============================================================================
// Team Case Store (v1) - Team Tier Only
// ============================================================================
//
// Shared folder-based case management for Team collaboration.
// No cloud, no database server - just filesystem with atomic operations.
//
// Data Model:
//   /locint_case_store/
//     store.json                    # Store metadata + version
//     cases/
//       case_<case_id>/
//         case.json                 # Case metadata
//         notes.jsonl               # Append-only notes
//         runs/
//           run_<run_id>.zip        # Immutable exported bundles
//         index.json                # Optional derived index
//     locks/
//       case_<case_id>.lock         # Lock files for atomic updates
//     audit/
//       events.jsonl                # Append-only audit log

/// Store schema version for forward compatibility
const CASE_STORE_SCHEMA_VERSION: &str = "1.1.0";

/// Lock timeout in seconds (stale lock recovery) - 5 minutes for slow SMB shares
/// Configurable via LOCINT_CASE_LOCK_TIMEOUT_SECS env var
fn case_lock_timeout_secs() -> u64 {
    std::env::var("LOCINT_CASE_LOCK_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300) // 5 minutes default
}

/// Lock heartbeat interval in seconds (must be < timeout)
const CASE_LOCK_HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Resolve case store directory from env or local config
fn resolve_case_store_dir() -> Option<std::path::PathBuf> {
    // Priority 1: Environment variable
    if let Ok(path) = std::env::var("LOCINT_CASE_STORE_DIR") {
        let p = std::path::PathBuf::from(path);
        if !p.as_os_str().is_empty() {
            return Some(p);
        }
    }
    
    // Priority 2: Local config file (team_config.json in data dir)
    // Note: data_dir not available here, so this is checked in handlers
    None
}

/// Safe path join for case store that prevents path traversal
/// More restrictive than the segment deref version - only allows case/run ID patterns
fn safe_case_path_join(base: &std::path::Path, component: &str) -> Option<std::path::PathBuf> {
    // Reject obviously dangerous patterns
    if component.contains("..") 
        || component.contains('/') 
        || component.contains('\\')
        || component.contains('\0')
        || component.starts_with('.')
    {
        return None;
    }
    
    // Basic alphanumeric + underscore + hyphen only
    let is_safe = component.chars().all(|c| 
        c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
    );
    
    if !is_safe || component.is_empty() {
        return None;
    }
    
    let joined = base.join(component);
    
    // Double-check the canonical path is under base (only if base exists)
    if base.exists() {
        if let (Ok(canon_base), Ok(canon_joined)) = (base.canonicalize(), joined.canonicalize()) {
            if !canon_joined.starts_with(&canon_base) {
                return None;
            }
        }
    }
    
    Some(joined)
}

/// Generate a new case ID
fn generate_case_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let rand: u32 = rand::random::<u32>() % 10000;
    format!("case_{}_{:04}", ts, rand)
}

/// Get this install's unique ID for audit trail
fn get_install_id() -> String {
    // Use machine name + data dir hash for uniqueness
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    hostname
}

/// Lock owner info for display in UI
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct LockOwnerInfo {
    install_id: String,
    host_name: String,
    pid: u32,
    acquired_at: String,
    last_heartbeat_at: String,
}

/// Lock acquisition result with reason codes (case-specific, not instance lock)
#[derive(Debug)]
#[allow(dead_code)]
enum CaseLockResult {
    Acquired(CaseStoreLock),
    LockedByOther { owner: LockOwnerInfo, reason_code: &'static str },
    Error { reason_code: &'static str, message: String },
}

/// Case store lock for atomic updates with heartbeat support
#[derive(Debug)]
struct CaseStoreLock {
    lock_path: std::path::PathBuf,
    owner_info: LockOwnerInfo,
}

impl CaseStoreLock {
    /// Try to acquire lock with timeout for stale lock recovery
    fn try_acquire(store_dir: &std::path::Path, case_id: &str) -> Result<Self, (String, &'static str, Option<LockOwnerInfo>)> {
        let locks_dir = store_dir.join("locks");
        std::fs::create_dir_all(&locks_dir)
            .map_err(|e| (format!("Failed to create locks dir: {}", e), "LOCK_DIR_FAILED", None))?;
        
        let lock_file = format!("{}.lock", case_id);
        let lock_path = match safe_case_path_join(&locks_dir, &lock_file) {
            Some(p) => p,
            None => return Err(("Invalid case ID for lock".to_string(), "INVALID_CASE_ID", None)),
        };
        
        let timeout_secs = case_lock_timeout_secs();
        
        // Check for existing lock
        if lock_path.exists() {
            // Try to read and parse lock file
            match std::fs::read_to_string(&lock_path) {
                Ok(content) => {
                    if let Ok(lock_info) = serde_json::from_str::<LockOwnerInfo>(&content) {
                        // Check if lock is stale by last_heartbeat_at
                        if let Ok(heartbeat_time) = chrono::DateTime::parse_from_rfc3339(&lock_info.last_heartbeat_at) {
                            let heartbeat_utc = heartbeat_time.with_timezone(&chrono::Utc);
                            let age = chrono::Utc::now().signed_duration_since(heartbeat_utc);
                            
                            if age.num_seconds() > timeout_secs as i64 {
                                // Stale lock - safe to remove
                                tracing::info!("Removing stale lock for case {} (age: {}s, owner: {})", 
                                    case_id, age.num_seconds(), lock_info.host_name);
                                let _ = std::fs::remove_file(&lock_path);
                            } else {
                                // Active lock - return owner info
                                return Err((
                                    format!("Case locked by {} (PID: {}) since {}", 
                                        lock_info.host_name, lock_info.pid, lock_info.acquired_at),
                                    "CASE_LOCKED",
                                    Some(lock_info)
                                ));
                            }
                        } else {
                            // Can't parse heartbeat time, check file mtime as fallback
                            if let Ok(meta) = std::fs::metadata(&lock_path) {
                                if let Ok(modified) = meta.modified() {
                                    let age = std::time::SystemTime::now()
                                        .duration_since(modified)
                                        .unwrap_or_default();
                                    
                                    if age.as_secs() > timeout_secs {
                                        let _ = std::fs::remove_file(&lock_path);
                                    } else {
                                        return Err((
                                            format!("Case locked by {} (PID: {})", lock_info.host_name, lock_info.pid),
                                            "CASE_LOCKED",
                                            Some(lock_info)
                                        ));
                                    }
                                }
                            }
                        }
                    } else {
                        // Legacy lock format or corrupt - check file mtime
                        if let Ok(meta) = std::fs::metadata(&lock_path) {
                            if let Ok(modified) = meta.modified() {
                                let age = std::time::SystemTime::now()
                                    .duration_since(modified)
                                    .unwrap_or_default();
                                
                                if age.as_secs() > timeout_secs {
                                    let _ = std::fs::remove_file(&lock_path);
                                } else {
                                    return Err((
                                        format!("Case is locked (legacy format): {}", content),
                                        "CASE_LOCKED",
                                        None
                                    ));
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    // Can't read lock file, check if stale by mtime
                    if let Ok(meta) = std::fs::metadata(&lock_path) {
                        if let Ok(modified) = meta.modified() {
                            let age = std::time::SystemTime::now()
                                .duration_since(modified)
                                .unwrap_or_default();
                            
                            if age.as_secs() > timeout_secs {
                                let _ = std::fs::remove_file(&lock_path);
                            } else {
                                return Err((
                                    "Case is locked by another process (lock file unreadable)".to_string(),
                                    "CASE_LOCKED",
                                    None
                                ));
                            }
                        }
                    }
                }
            }
        }
        
        // Create new lock with owner info
        let now = chrono::Utc::now().to_rfc3339();
        let owner_info = LockOwnerInfo {
            install_id: get_install_id(),
            host_name: get_hostname(),
            pid: std::process::id(),
            acquired_at: now.clone(),
            last_heartbeat_at: now,
        };
        
        let lock_content = serde_json::to_string_pretty(&owner_info)
            .map_err(|e| (format!("Failed to serialize lock: {}", e), "LOCK_SERIALIZE_FAILED", None))?;
        
        // Use OpenOptions for exclusive creation
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL equivalent
            .open(&lock_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    ("Case is locked by another process (race condition)".to_string(), "CASE_LOCKED", None)
                } else {
                    (format!("Failed to acquire lock: {}", e), "LOCK_ACQUIRE_FAILED", None)
                }
            })?;
        
        file.write_all(lock_content.as_bytes())
            .map_err(|e| (format!("Failed to write lock: {}", e), "LOCK_WRITE_FAILED", None))?;
        
        Ok(Self { lock_path, owner_info })
    }
    
    /// Update heartbeat timestamp in lock file
    fn heartbeat(&mut self) -> Result<(), String> {
        let now = chrono::Utc::now().to_rfc3339();
        self.owner_info.last_heartbeat_at = now;
        
        let lock_content = serde_json::to_string_pretty(&self.owner_info)
            .map_err(|e| format!("Failed to serialize lock: {}", e))?;
        
        std::fs::write(&self.lock_path, &lock_content)
            .map_err(|e| format!("Failed to update heartbeat: {}", e))?;
        
        Ok(())
    }
}

/// Get hostname for lock owner info
fn get_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Get optional user hint from environment
fn get_user_hint() -> Option<String> {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .ok()
}

impl Drop for CaseStoreLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

/// Write JSON file atomically (write temp + rename)
fn atomic_write_json(path: &std::path::Path, value: &serde_json::Value) -> Result<(), String> {
    let temp_path = path.with_extension("tmp");
    
    let content = serde_json::to_string_pretty(value)
        .map_err(|e| format!("JSON serialize error: {}", e))?;
    
    std::fs::write(&temp_path, &content)
        .map_err(|e| format!("Failed to write temp file: {}", e))?;
    
    std::fs::rename(&temp_path, path)
        .map_err(|e| format!("Failed to rename temp file: {}", e))?;
    
    Ok(())
}

/// Append to JSONL file (atomic append)
fn append_jsonl(path: &std::path::Path, value: &serde_json::Value) -> Result<(), String> {
    use std::io::Write;
    
    let line = serde_json::to_string(value)
        .map_err(|e| format!("JSON serialize error: {}", e))?;
    
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    writeln!(file, "{}", line)
        .map_err(|e| format!("Failed to append: {}", e))?;
    
    Ok(())
}

/// Read JSONL file and parse lines
fn read_jsonl(path: &std::path::Path) -> Vec<serde_json::Value> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    
    content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// Initialize a new case store if it doesn't exist
fn ensure_store_initialized(store_dir: &std::path::Path) -> Result<(), String> {
    let store_json = store_dir.join("store.json");
    
    if store_json.exists() {
        // Already initialized
        return Ok(());
    }
    
    // Create directory structure
    std::fs::create_dir_all(store_dir.join("cases"))
        .map_err(|e| format!("Failed to create cases dir: {}", e))?;
    std::fs::create_dir_all(store_dir.join("locks"))
        .map_err(|e| format!("Failed to create locks dir: {}", e))?;
    std::fs::create_dir_all(store_dir.join("audit"))
        .map_err(|e| format!("Failed to create audit dir: {}", e))?;
    
    // Create store.json
    let store_id = format!("store_{}_{:04}", 
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        rand::random::<u32>() % 10000
    );
    
    let store_meta = serde_json::json!({
        "schema_version": CASE_STORE_SCHEMA_VERSION,
        "store_id": store_id,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "created_by": get_install_id(),
    });
    
    atomic_write_json(&store_json, &store_meta)?;
    
    // Initial audit entry
    let audit_path = store_dir.join("audit").join("events.jsonl");
    let audit_entry = serde_json::json!({
        "event": "store_created",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "by": get_install_id(),
        "store_id": store_id,
    });
    append_jsonl(&audit_path, &audit_entry)?;
    
    Ok(())
}

/// GET /api/team/store/status - Check case store availability
async fn team_store_status_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Team tier gate
    if !resolve_current_tier().has_access(ProductTier::Team) {
        return feature_locked_403("Case Store", ProductTier::Team);
    }
    
    // Check for store directory from env
    let store_dir = match resolve_case_store_dir() {
        Some(p) => p,
        None => {
            // Check local config as fallback
            let config_path = state.data_dir.join("team_config.json");
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(path) = v.get("case_store_dir").and_then(|p| p.as_str()) {
                        std::path::PathBuf::from(path)
                    } else {
                        return (
                            axum::http::StatusCode::OK,
                            axum::Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "available": false,
                                    "reason_code": "STORE_NOT_CONFIGURED",
                                    "message": "Case store not configured. Set LOCINT_CASE_STORE_DIR or configure via Settings.",
                                    "resolved_path": null,
                                    "writable": false,
                                    "schema_version": null
                                }
                            }))
                        );
                    }
                } else {
                    return (
                        axum::http::StatusCode::OK,
                        axum::Json(serde_json::json!({
                            "success": true,
                            "data": {
                                "available": false,
                                "reason_code": "STORE_NOT_CONFIGURED",
                                "message": "Case store not configured. Set LOCINT_CASE_STORE_DIR or configure via Settings.",
                                "resolved_path": null,
                                "writable": false,
                                "schema_version": null
                            }
                        }))
                    );
                }
            } else {
                return (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "success": true,
                        "data": {
                            "available": false,
                            "reason_code": "STORE_NOT_CONFIGURED",
                            "message": "Case store not configured. Set LOCINT_CASE_STORE_DIR or configure via Settings.",
                            "resolved_path": null,
                            "writable": false,
                            "schema_version": null
                        }
                    }))
                );
            }
        }
    };
    
    // Check if path exists and is accessible
    if !store_dir.exists() {
        return (
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": "STORE_UNREACHABLE",
                    "message": format!("Case store path does not exist or is not accessible: {}", store_dir.display()),
                    "resolved_path": store_dir.display().to_string(),
                    "writable": false,
                    "schema_version": null
                }
            }))
        );
    }
    
    // Check if writable
    let test_file = store_dir.join(".write_test");
    let writable = std::fs::write(&test_file, "test").is_ok();
    let _ = std::fs::remove_file(&test_file);
    
    if !writable {
        return (
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": "STORE_READONLY",
                    "message": "Case store is read-only. Check permissions.",
                    "resolved_path": store_dir.display().to_string(),
                    "writable": false,
                    "schema_version": null
                }
            }))
        );
    }
    
    // Initialize store if needed
    if let Err(e) = ensure_store_initialized(&store_dir) {
        return (
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({
                "success": true,
                "data": {
                    "available": false,
                    "reason_code": "STORE_INIT_FAILED",
                    "message": format!("Failed to initialize store: {}", e),
                    "resolved_path": store_dir.display().to_string(),
                    "writable": writable,
                    "schema_version": null
                }
            }))
        );
    }
    
    // Read schema version from store.json
    let store_json = store_dir.join("store.json");
    let schema_version = std::fs::read_to_string(&store_json)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .and_then(|v| v.get("schema_version").and_then(|s| s.as_str()).map(|s| s.to_string()));
    
    // Count cases
    let case_count = std::fs::read_dir(store_dir.join("cases"))
        .map(|entries| entries.filter_map(|e| e.ok()).count())
        .unwrap_or(0);
    
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "available": true,
                "reason_code": null,
                "message": "Case store is available and writable",
                "resolved_path": store_dir.display().to_string(),
                "writable": true,
                "schema_version": schema_version,
                "case_count": case_count
            }
        }))
    )
}

/// POST /api/team/store/configure - Configure case store path (persisted locally)
#[derive(serde::Deserialize)]
struct ConfigureStoreRequest {
    case_store_dir: String,
}

async fn team_store_configure_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(req): axum::Json<ConfigureStoreRequest>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Team tier gate
    if !resolve_current_tier().has_access(ProductTier::Team) {
        return feature_locked_403("Case Store", ProductTier::Team);
    }
    
    let config_path = state.data_dir.join("team_config.json");
    let config = serde_json::json!({
        "case_store_dir": req.case_store_dir,
        "configured_at": chrono::Utc::now().to_rfc3339(),
        "configured_by": get_install_id(),
    });
    
    if let Err(e) = atomic_write_json(&config_path, &config) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to save config: {}", e),
                "code": "CONFIG_WRITE_FAILED"
            }))
        );
    }
    
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "configured": true,
                "case_store_dir": req.case_store_dir
            }
        }))
    )
}

/// Helper to get configured store dir (from env or local config)
fn get_store_dir(data_dir: &std::path::Path) -> Option<std::path::PathBuf> {
    if let Some(p) = resolve_case_store_dir() {
        return Some(p);
    }
    
    // Check local config
    let config_path = data_dir.join("team_config.json");
    std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .and_then(|v| v.get("case_store_dir").and_then(|p| p.as_str()).map(|s| std::path::PathBuf::from(s)))
}

/// GET /api/team/cases - List all cases
async fn team_list_cases_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Team tier gate
    if !resolve_current_tier().has_access(ProductTier::Team) {
        return feature_locked_403("Case Store", ProductTier::Team);
    }
    
    let store_dir = match get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case store not configured or unreachable",
                "code": "STORE_NOT_AVAILABLE"
            }))
        ),
    };
    
    let cases_dir = store_dir.join("cases");
    let mut cases = Vec::new();
    let mut unreadable_count = 0u32;
    
    if let Ok(entries) = std::fs::read_dir(&cases_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let case_dir = entry.path();
            if !case_dir.is_dir() {
                continue;
            }
            
            // Extract case_id from directory name (safe fallback)
            let case_id = case_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            
            let case_json_path = case_dir.join("case.json");
            
            // Try to read and parse case.json with graceful fallback
            match std::fs::read_to_string(&case_json_path) {
                Ok(content) => {
                    match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(case_data) => {
                            cases.push(case_data);
                        }
                        Err(_) => {
                            // Corrupt JSON - include minimal stub
                            unreadable_count += 1;
                            cases.push(serde_json::json!({
                                "case_id": case_id,
                                "title": "(unreadable)",
                                "status": "unreadable",
                                "error": "corrupt_json",
                                "updated_at": "1970-01-01T00:00:00Z"
                            }));
                        }
                    }
                }
                Err(e) => {
                    // Missing or unreadable case.json
                    unreadable_count += 1;
                    let error_type = if e.kind() == std::io::ErrorKind::NotFound {
                        "missing_json"
                    } else {
                        "read_failed"
                    };
                    cases.push(serde_json::json!({
                        "case_id": case_id,
                        "title": "(unreadable)",
                        "status": "unreadable",
                        "error": error_type,
                        "updated_at": "1970-01-01T00:00:00Z"
                    }));
                }
            }
        }
    }
    
    // Sort by updated_at descending (unreadable cases sink to bottom due to 1970 date)
    cases.sort_by(|a, b| {
        let a_ts = a.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
        let b_ts = b.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
        b_ts.cmp(a_ts)
    });
    
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "cases": cases,
                "count": cases.len(),
                "unreadable_count": unreadable_count
            }
        }))
    )
}

/// POST /api/team/cases - Create a new case
#[derive(serde::Deserialize)]
struct CreateCaseRequest {
    title: String,
    description: Option<String>,
    tags: Option<Vec<String>>,
}

async fn team_create_case_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(req): axum::Json<CreateCaseRequest>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Team tier gate
    if !resolve_current_tier().has_access(ProductTier::Team) {
        return feature_locked_403("Case Store", ProductTier::Team);
    }
    
    let store_dir = match get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case store not configured or unreachable",
                "code": "STORE_NOT_AVAILABLE"
            }))
        ),
    };
    
    let case_id = generate_case_id();
    let cases_dir = store_dir.join("cases");
    let case_dir = match safe_case_path_join(&cases_dir, &case_id) {
        Some(p) => p,
        None => return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Failed to generate safe case ID",
                "code": "INVALID_CASE_ID"
            }))
        ),
    };
    
    // Create case directory
    if let Err(e) = std::fs::create_dir_all(&case_dir) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create case directory: {}", e),
                "code": "DIR_CREATE_FAILED"
            }))
        );
    }
    
    // Create runs subdirectory
    let _ = std::fs::create_dir_all(case_dir.join("runs"));
    
    let now = chrono::Utc::now().to_rfc3339();
    let case_data = serde_json::json!({
        "case_id": case_id,
        "title": req.title,
        "description": req.description.unwrap_or_default(),
        "tags": req.tags.unwrap_or_default(),
        "created_at": now,
        "updated_at": now,
        "created_by": get_install_id(),
        "creator_host": get_hostname(),
        "creator_user_hint": get_user_hint(),
        "runs": [],
        "notes_count": 0,
        "last_note_at": null
    });
    
    let case_json_path = case_dir.join("case.json");
    if let Err(e) = atomic_write_json(&case_json_path, &case_data) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to write case.json: {}", e),
                "code": "WRITE_FAILED"
            }))
        );
    }
    
    // Audit log with provenance
    let audit_path = store_dir.join("audit").join("events.jsonl");
    let audit_entry = serde_json::json!({
        "event": "case_created",
        "timestamp": now,
        "install_id": get_install_id(),
        "host_name": get_hostname(),
        "user_hint": get_user_hint(),
        "case_id": case_id,
        "title": req.title
    });
    let _ = append_jsonl(&audit_path, &audit_entry);
    
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "data": case_data
        }))
    )
}

/// GET /api/team/cases/:case_id - Get case details
async fn team_get_case_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(case_id): axum::extract::Path<String>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Team tier gate
    if !resolve_current_tier().has_access(ProductTier::Team) {
        return feature_locked_403("Case Store", ProductTier::Team);
    }
    
    let store_dir = match get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case store not configured or unreachable",
                "code": "STORE_NOT_AVAILABLE"
            }))
        ),
    };
    
    let cases_dir = store_dir.join("cases");
    let case_dir = match safe_case_path_join(&cases_dir, &case_id) {
        Some(p) => p,
        None => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Invalid case ID",
                "code": "INVALID_CASE_ID"
            }))
        ),
    };
    
    let case_json_path = case_dir.join("case.json");
    if !case_json_path.exists() {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Case '{}' not found", case_id),
                "code": "CASE_NOT_FOUND"
            }))
        );
    }
    
    let case_data: serde_json::Value = match std::fs::read_to_string(&case_json_path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to parse case.json: {}", e),
                    "code": "PARSE_FAILED"
                }))
            ),
        },
        Err(e) => return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to read case.json: {}", e),
                "code": "READ_FAILED"
            }))
        ),
    };
    
    // Load recent notes (last 20)
    let notes_path = case_dir.join("notes.jsonl");
    let all_notes = read_jsonl(&notes_path);
    let recent_notes: Vec<_> = all_notes.into_iter().rev().take(20).collect();
    
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "case": case_data,
                "recent_notes": recent_notes
            }
        }))
    )
}

/// GET /api/team/cases/:case_id/aggregate - Get aggregated view across all runs in a case
/// Returns deduplicated findings, merged timeline, and host list
/// This is the Team V2 "case-level story" endpoint
/// 
/// HARDENED V2 FEATURES:
/// - Canonical dedupe_key: rule_key::entity_key (not just rule_id)
/// - Per-case aggregate cache (aggregate_cache.json)
/// - Evidence availability flags per finding
/// - Both per_host and cross_host dedupe sets
async fn team_case_aggregate_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(case_id): axum::extract::Path<String>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Team tier gate
    if !resolve_current_tier().has_access(ProductTier::Team) {
        return feature_locked_403("Case Store", ProductTier::Team);
    }
    
    let store_dir = match get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case store not configured or unreachable",
                "code": "STORE_NOT_AVAILABLE"
            }))
        ),
    };
    
    let cases_dir = store_dir.join("cases");
    let case_dir = match safe_case_path_join(&cases_dir, &case_id) {
        Some(p) => p,
        None => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Invalid case ID",
                "code": "INVALID_CASE_ID"
            }))
        ),
    };
    
    if !case_dir.exists() {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Case '{}' not found", case_id),
                "code": "CASE_NOT_FOUND"
            }))
        );
    }
    
    // Check cache first
    let cache_path = case_dir.join("aggregate_cache.json");
    let case_json_path = case_dir.join("case.json");
    let runs_dir = case_dir.join("runs");
    
    // Gather current run bundle info for cache validation
    let current_run_inputs = gather_run_inputs(&runs_dir);
    let case_mtime = std::fs::metadata(&case_json_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    // Try to use cache if valid
    if let Some(cached) = try_load_aggregate_cache(&cache_path, case_mtime, &current_run_inputs) {
        return (
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({
                "success": true,
                "data": cached,
                "cache_hit": true
            }))
        );
    }
    
    // Cache miss - compute fresh aggregate
    let aggregate = compute_case_aggregate(&case_id, &case_dir, &runs_dir, &case_json_path);
    
    // Try to write cache (atomic)
    if let Err(e) = write_aggregate_cache(&cache_path, case_mtime, &current_run_inputs, &aggregate) {
        eprintln!("[team_case_aggregate] Cache write failed (serving live): {}", e);
    }
    
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "data": aggregate,
            "cache_hit": false
        }))
    )
}

/// Current cache schema version - bump when format changes
const AGGREGATE_CACHE_VERSION: &str = "2.0.0";

/// Run input info for cache validation
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq)]
struct RunInputInfo {
    run_id: String,
    bundle_filename: String,
    sha256: String,
    published_at: Option<String>,
    size_bytes: u64,
}

/// Gather run inputs from the runs directory
fn gather_run_inputs(runs_dir: &std::path::Path) -> Vec<RunInputInfo> {
    let mut inputs = Vec::new();
    
    if !runs_dir.exists() {
        return inputs;
    }
    
    if let Ok(entries) = std::fs::read_dir(runs_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "zip") {
                let filename = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();
                
                let run_id = filename.trim_end_matches(".zip").to_string();
                let size_bytes = std::fs::metadata(&path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                
                // Compute sha256 for cache integrity validation
                let sha256 = compute_file_sha256(&path).unwrap_or_else(|| "unknown".to_string());
                
                inputs.push(RunInputInfo {
                    run_id,
                    bundle_filename: filename,
                    sha256,
                    published_at: None,
                    size_bytes,
                });
            }
        }
    }
    
    // Sort for deterministic comparison
    inputs.sort_by(|a, b| a.run_id.cmp(&b.run_id));
    inputs
}

/// Compute SHA256 hash of a file
fn compute_file_sha256(path: &std::path::Path) -> Option<String> {
    use sha2::{Sha256, Digest};
    use std::io::Read;
    
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    
    loop {
        let bytes_read = file.read(&mut buffer).ok()?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    
    let hash = hasher.finalize();
    Some(format!("{:x}", hash))
}

/// Try to load aggregate from cache if still valid
fn try_load_aggregate_cache(
    cache_path: &std::path::Path,
    case_mtime: u64,
    current_inputs: &[RunInputInfo],
) -> Option<serde_json::Value> {
    let content = std::fs::read_to_string(cache_path).ok()?;
    let cache: serde_json::Value = serde_json::from_str(&content).ok()?;
    
    // Validate cache version
    let version = cache.get("cache_version")?.as_str()?;
    if version != AGGREGATE_CACHE_VERSION {
        return None;
    }
    
    // Validate case.json mtime
    let cached_case_mtime = cache.get("inputs")?
        .get("case_json_mtime")?
        .as_u64()?;
    if cached_case_mtime != case_mtime {
        return None;
    }
    
    // Validate runs list
    let cached_runs: Vec<RunInputInfo> = serde_json::from_value(
        cache.get("inputs")?.get("runs")?.clone()
    ).ok()?;
    
    if cached_runs.len() != current_inputs.len() {
        return None;
    }
    
    for (cached, current) in cached_runs.iter().zip(current_inputs.iter()) {
        if cached.run_id != current.run_id 
            || cached.bundle_filename != current.bundle_filename
            || cached.size_bytes != current.size_bytes
            || cached.sha256 != current.sha256 {
            return None;
        }
    }
    
    // Cache is valid - return aggregate payload
    cache.get("aggregate").cloned()
}

/// Write aggregate cache atomically (tmp + rename)
fn write_aggregate_cache(
    cache_path: &std::path::Path,
    case_mtime: u64,
    run_inputs: &[RunInputInfo],
    aggregate: &serde_json::Value,
) -> Result<(), String> {
    let cache = serde_json::json!({
        "cache_version": AGGREGATE_CACHE_VERSION,
        "computed_at": chrono::Utc::now().to_rfc3339(),
        "inputs": {
            "case_json_mtime": case_mtime,
            "runs": run_inputs
        },
        "aggregate": aggregate
    });
    
    let tmp_path = cache_path.with_extension("json.tmp");
    let content = serde_json::to_string_pretty(&cache)
        .map_err(|e| format!("Serialize failed: {}", e))?;
    
    std::fs::write(&tmp_path, content)
        .map_err(|e| format!("Write tmp failed: {}", e))?;
    
    std::fs::rename(&tmp_path, cache_path)
        .map_err(|e| format!("Rename failed: {}", e))?;
    
    Ok(())
}

/// Compute fresh aggregate for a case
fn compute_case_aggregate(
    case_id: &str,
    case_dir: &std::path::Path,
    runs_dir: &std::path::Path,
    case_json_path: &std::path::Path,
) -> serde_json::Value {
    // Read case.json
    let case_data: serde_json::Value = std::fs::read_to_string(case_json_path)
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or(serde_json::json!({}));
    
    // Collect raw signals from all runs
    let mut all_signals: Vec<AggregateSignal> = Vec::new();
    let mut timeline: Vec<serde_json::Value> = Vec::new();
    let mut hosts: Vec<String> = Vec::new();
    let mut run_infos: Vec<serde_json::Value> = Vec::new();
    let mut run_count = 0;
    
    // Get host from case creator
    if let Some(creator_host) = case_data.get("creator_host").and_then(|v| v.as_str()) {
        if !creator_host.is_empty() && !hosts.contains(&creator_host.to_string()) {
            hosts.push(creator_host.to_string());
        }
    }
    
    // Process each run bundle
    if runs_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(runs_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "zip") {
                    let run_id = path.file_stem()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    
                    match extract_run_aggregate_v2(&path, &run_id) {
                        Ok(info) => {
                            run_count += 1;
                            
                            // Add host
                            if let Some(ref host) = info.host {
                                if !hosts.contains(host) {
                                    hosts.push(host.clone());
                                }
                            }
                            
                            // Add signals
                            all_signals.extend(info.signals);
                            
                            // Add timeline events
                            timeline.extend(info.timeline);
                            
                            // Add run info
                            run_infos.push(serde_json::json!({
                                "run_id": run_id,
                                "host": info.host,
                                "started_at": info.started_at,
                                "signal_count": info.signal_count,
                                "segments_present": info.segments_present,
                                "evidence_deref_available": info.evidence_available,
                                "evidence_reason_code": info.evidence_reason
                            }));
                        }
                        Err(e) => {
                            eprintln!("[compute_case_aggregate] Failed to process {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }
    }
    
    // Dedupe signals with canonical dedupe_key
    let per_host_deduped = dedupe_signals_v2(&all_signals, true);  // Include host in key
    let cross_host_deduped = dedupe_signals_v2(&all_signals, false); // Exclude host from key
    
    // Sort timeline by timestamp
    timeline.sort_by(|a, b| {
        let ts_a = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let ts_b = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ts_a.cmp(ts_b)
    });
    
    serde_json::json!({
        "case_id": case_id,
        "run_count": run_count,
        "hosts": hosts,
        "runs": run_infos,
        "per_host_findings": per_host_deduped,
        "cross_host_findings": cross_host_deduped,
        "timeline": timeline.into_iter().take(100).collect::<Vec<_>>(),
        "merged_at": chrono::Utc::now().to_rfc3339(),
        "dedupe_version": "2.0"
    })
}

/// Signal extracted from a run for aggregation
#[derive(Clone)]
struct AggregateSignal {
    signal_id: String,
    run_id: String,
    host: String,
    ts: i64,
    signal_type: String,
    severity: String,
    detector_id: String,
    proc_key: Option<String>,
    file_key: Option<String>,
    identity_key: Option<String>,
    remote_ip: Option<String>,
    port: Option<u16>,
    title: Option<String>,
    rule_id: Option<String>,
    playbook_id: Option<String>,
    has_evidence: bool,
    evidence_ptr_sample: Option<String>,
}

/// Extended run info for V2 aggregation
struct RunAggregateInfoV2 {
    host: Option<String>,
    started_at: Option<String>,
    signals: Vec<AggregateSignal>,
    timeline: Vec<serde_json::Value>,
    signal_count: usize,
    segments_present: bool,
    evidence_available: bool,
    evidence_reason: Option<String>,
}

/// Extract aggregate info from a run bundle (V2 - reads workbench.db)
fn extract_run_aggregate_v2(bundle_path: &std::path::Path, run_id: &str) -> Result<RunAggregateInfoV2, String> {
    use std::io::Read;
    use zip::ZipArchive;
    
    let file = std::fs::File::open(bundle_path)
        .map_err(|e| format!("Failed to open bundle: {}", e))?;
    
    let mut archive = ZipArchive::new(file)
        .map_err(|e| format!("Failed to read zip: {}", e))?;
    
    let mut host: Option<String> = None;
    let mut started_at: Option<String> = None;
    let mut signals: Vec<AggregateSignal> = Vec::new();
    let mut timeline: Vec<serde_json::Value> = Vec::new();
    let mut segments_present = false;
    let mut evidence_available = false;
    let mut evidence_reason: Option<String> = None;
    
    // Check for segments directory
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            if file.name().starts_with("segments/") && !file.name().ends_with("/") {
                segments_present = true;
                break;
            }
        }
    }
    
    // Read run_meta.json for host info
    if let Ok(mut meta_file) = archive.by_name("run_meta.json") {
        let mut content = String::new();
        if meta_file.read_to_string(&mut content).is_ok() {
            if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&content) {
                host = meta.get("hostname")
                    .or_else(|| meta.get("host"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                
                started_at = meta.get("started_at")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                
                if let Some(ref ts) = started_at {
                    timeline.push(serde_json::json!({
                        "timestamp": ts,
                        "event": "run_started",
                        "host": host.clone().unwrap_or_default(),
                        "run_id": run_id
                    }));
                }
            }
        }
    }
    
    // Try to extract workbench.db to temp and query signals
    let db_signals = extract_signals_from_bundle(&mut archive, run_id, host.as_deref().unwrap_or("unknown"));
    if !db_signals.is_empty() {
        evidence_available = segments_present;
        if !segments_present {
            evidence_reason = Some("SEGMENTS_NOT_IN_BUNDLE".to_string());
        }
        signals = db_signals;
    } else {
        evidence_reason = Some("NO_SIGNALS_IN_BUNDLE".to_string());
    }
    
    // Try to read bundle manifest
    if let Ok(mut manifest_file) = archive.by_name("bundle_manifest.json") {
        let mut content = String::new();
        if manifest_file.read_to_string(&mut content).is_ok() {
            if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(exported_at) = manifest.get("exported_at").and_then(|v| v.as_str()) {
                    timeline.push(serde_json::json!({
                        "timestamp": exported_at,
                        "event": "run_published",
                        "host": host.clone().unwrap_or_default(),
                        "run_id": run_id
                    }));
                }
            }
        }
    }
    
    let signal_count = signals.len();
    
    Ok(RunAggregateInfoV2 {
        host,
        started_at,
        signals,
        timeline,
        signal_count,
        segments_present,
        evidence_available,
        evidence_reason,
    })
}

/// Extract signals from workbench.db inside a ZIP bundle
fn extract_signals_from_bundle(
    archive: &mut zip::ZipArchive<std::fs::File>,
    run_id: &str,
    default_host: &str,
) -> Vec<AggregateSignal> {
    use std::io::Read;
    
    // Try to read workbench.db
    let db_content = match archive.by_name("workbench.db") {
        Ok(mut db_file) => {
            let mut content = Vec::new();
            if db_file.read_to_end(&mut content).is_ok() {
                content
            } else {
                return Vec::new();
            }
        }
        Err(_) => return Vec::new(),
    };
    
    // Write to temp file for SQLite access
    let temp_dir = std::env::temp_dir();
    let temp_db_path = temp_dir.join(format!("aggregate_db_{}.db", run_id));
    
    if std::fs::write(&temp_db_path, &db_content).is_err() {
        return Vec::new();
    }
    
    let signals = query_signals_from_db(&temp_db_path, run_id, default_host);
    
    // Clean up temp file
    let _ = std::fs::remove_file(&temp_db_path);
    
    signals
}

/// Query signals from a SQLite database
fn query_signals_from_db(
    db_path: &std::path::Path,
    run_id: &str,
    default_host: &str,
) -> Vec<AggregateSignal> {
    use rusqlite::Connection;
    
    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    
    let query = r#"
        SELECT 
            signal_id, run_id, signal_type, severity, host, ts,
            proc_key, file_key, identity_key, detector_id,
            metadata, evidence_ptrs
        FROM signals
        ORDER BY ts DESC
        LIMIT 1000
    "#;
    
    let mut stmt = match conn.prepare(query) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    
    let mut signals = Vec::new();
    
    let rows = stmt.query_map([], |row| {
        let signal_id: String = row.get(0)?;
        let row_run_id: String = row.get(1)?;
        let signal_type: String = row.get(2)?;
        let severity: String = row.get(3)?;
        let host: String = row.get(4)?;
        let ts: i64 = row.get(5)?;
        let proc_key: Option<String> = row.get(6).ok();
        let file_key: Option<String> = row.get(7).ok();
        let identity_key: Option<String> = row.get(8).ok();
        let detector_id: String = row.get(9)?;
        let metadata: String = row.get(10)?;
        let evidence_ptrs: String = row.get(11)?;
        
        // Parse metadata for title/rule_id/playbook_id and network info
        let meta: serde_json::Value = serde_json::from_str(&metadata).unwrap_or(serde_json::json!({}));
        let title = meta.get("title").and_then(|v| v.as_str()).map(|s| s.to_string());
        let rule_id = meta.get("rule_id").and_then(|v| v.as_str()).map(|s| s.to_string());
        let playbook_id = meta.get("playbook_id").and_then(|v| v.as_str()).map(|s| s.to_string());
        
        // Extract network endpoint info for dedupe key cascade
        let remote_ip = meta.get("remote_ip")
            .or_else(|| meta.get("ip"))
            .or_else(|| meta.get("dest_ip"))
            .or_else(|| meta.get("destination_ip"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let port = meta.get("port")
            .or_else(|| meta.get("dest_port"))
            .or_else(|| meta.get("destination_port"))
            .or_else(|| meta.get("remote_port"))
            .and_then(|v| v.as_u64())
            .map(|p| p as u16);
        
        // Check if evidence exists
        let has_evidence = !evidence_ptrs.is_empty() && evidence_ptrs != "[]";
        let evidence_ptr_sample = if has_evidence {
            serde_json::from_str::<Vec<serde_json::Value>>(&evidence_ptrs)
                .ok()
                .and_then(|arr| arr.first().map(|v| v.to_string()))
        } else {
            None
        };
        
        Ok(AggregateSignal {
            signal_id,
            run_id: row_run_id,
            host: if host.is_empty() { default_host.to_string() } else { host },
            ts,
            signal_type,
            severity,
            detector_id,
            proc_key,
            file_key,
            identity_key,
            remote_ip,
            port,
            title,
            rule_id,
            playbook_id,
            has_evidence,
            evidence_ptr_sample,
        })
    });
    
    if let Ok(rows) = rows {
        for row in rows.filter_map(|r| r.ok()) {
            signals.push(row);
        }
    }
    
    signals
}

/// Compute canonical dedupe_key for a signal
/// rule_key = playbook_id || rule_id || signal_type || detector_id || "unknown_rule"
/// entity_key priority: proc_key > file_key > ip:port > identity_key > host > "unknown_entity"
fn compute_dedupe_key(signal: &AggregateSignal, include_host: bool) -> String {
    // Rule key
    let rule_key = signal.playbook_id.as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| signal.rule_id.as_deref().filter(|s| !s.is_empty()))
        .or_else(|| Some(signal.signal_type.as_str()).filter(|s| !s.is_empty()))
        .or_else(|| Some(signal.detector_id.as_str()).filter(|s| !s.is_empty()))
        .unwrap_or("unknown_rule");
    
    // Entity key - priority order: proc_key > file_key > ip:port > identity_key > host
    let entity_key = if let Some(ref pk) = signal.proc_key {
        if !pk.is_empty() { pk.clone() } else { compute_entity_fallback(signal, include_host) }
    } else if let Some(ref fk) = signal.file_key {
        if !fk.is_empty() { fk.clone() } else { compute_entity_fallback(signal, include_host) }
    } else if let Some(ref ip) = signal.remote_ip {
        // Network endpoint: format as ip:port when both available
        if !ip.is_empty() {
            if let Some(port) = signal.port {
                format!("{}:{}", ip, port)
            } else {
                ip.clone()
            }
        } else {
            compute_entity_fallback(signal, include_host)
        }
    } else if let Some(ref ik) = signal.identity_key {
        if !ik.is_empty() { ik.clone() } else { compute_entity_fallback(signal, include_host) }
    } else {
        compute_entity_fallback(signal, include_host)
    };
    
    format!("{}::{}", rule_key, entity_key)
}

fn compute_entity_fallback(signal: &AggregateSignal, include_host: bool) -> String {
    if include_host && !signal.host.is_empty() {
        signal.host.clone()
    } else {
        "unknown_entity".to_string()
    }
}

/// Dedupe signals with canonical dedupe_key (V2)
fn dedupe_signals_v2(signals: &[AggregateSignal], include_host_in_key: bool) -> Vec<serde_json::Value> {
    use std::collections::HashMap;
    
    struct DedupeEntry {
        first_signal: AggregateSignal,
        first_seen_ts: i64,
        last_seen_ts: i64,
        run_ids: Vec<String>,
        hosts: Vec<String>,
        total_count: usize,
        evidence_available_count: usize,
    }
    
    let mut by_key: HashMap<String, DedupeEntry> = HashMap::new();
    
    for signal in signals {
        let key = compute_dedupe_key(signal, include_host_in_key);
        
        let entry = by_key.entry(key).or_insert_with(|| DedupeEntry {
            first_signal: signal.clone(),
            first_seen_ts: signal.ts,
            last_seen_ts: signal.ts,
            run_ids: Vec::new(),
            hosts: Vec::new(),
            total_count: 0,
            evidence_available_count: 0,
        });
        
        entry.total_count += 1;
        
        if signal.ts < entry.first_seen_ts {
            entry.first_seen_ts = signal.ts;
            entry.first_signal = signal.clone();
        }
        if signal.ts > entry.last_seen_ts {
            entry.last_seen_ts = signal.ts;
        }
        
        if !entry.run_ids.contains(&signal.run_id) {
            entry.run_ids.push(signal.run_id.clone());
        }
        if !entry.hosts.contains(&signal.host) {
            entry.hosts.push(signal.host.clone());
        }
        
        if signal.has_evidence {
            entry.evidence_available_count += 1;
        }
    }
    
    by_key.into_iter()
        .map(|(dedupe_key, entry)| {
            serde_json::json!({
                "dedupe_key": dedupe_key,
                "rule_id": entry.first_signal.rule_id,
                "playbook_id": entry.first_signal.playbook_id,
                "signal_type": entry.first_signal.signal_type,
                "detector_id": entry.first_signal.detector_id,
                "title": entry.first_signal.title,
                "severity": entry.first_signal.severity,
                "first_seen_ts": entry.first_seen_ts,
                "last_seen_ts": entry.last_seen_ts,
                "total_count": entry.total_count,
                "run_ids_involved": entry.run_ids,
                "hosts_involved": entry.hosts,
                "evidence_available_count": entry.evidence_available_count,
                "evidence_available": entry.evidence_available_count > 0,
                "top_signal_ref": {
                    "run_id": entry.first_signal.run_id,
                    "signal_id": entry.first_signal.signal_id
                },
                "evidence_ptr_sample": entry.first_signal.evidence_ptr_sample
            })
        })
        .collect()
}

/// POST /api/team/cases/:case_id/tags - Update case tags
#[derive(serde::Deserialize)]
struct UpdateTagsRequest {
    add: Option<Vec<String>>,
    remove: Option<Vec<String>>,
}

async fn team_update_tags_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(case_id): axum::extract::Path<String>,
    axum::Json(req): axum::Json<UpdateTagsRequest>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Team tier gate
    if !resolve_current_tier().has_access(ProductTier::Team) {
        return feature_locked_403("Case Store", ProductTier::Team);
    }
    
    let store_dir = match get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case store not configured or unreachable",
                "code": "STORE_NOT_AVAILABLE"
            }))
        ),
    };
    
    let cases_dir = store_dir.join("cases");
    let case_dir = match safe_case_path_join(&cases_dir, &case_id) {
        Some(p) => p,
        None => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Invalid case ID",
                "code": "INVALID_CASE_ID"
            }))
        ),
    };
    
    // Acquire lock
    let _lock = match CaseStoreLock::try_acquire(&store_dir, &case_id) {
        Ok(l) => l,
        Err((msg, reason_code, owner_info)) => return (
            axum::http::StatusCode::CONFLICT,
            axum::Json(serde_json::json!({
                "success": false,
                "error": msg,
                "code": reason_code,
                "lock_owner": owner_info
            }))
        ),
    };
    
    let case_json_path = case_dir.join("case.json");
    let mut case_data: serde_json::Value = match std::fs::read_to_string(&case_json_path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case not found",
                "code": "CASE_NOT_FOUND"
            }))
        ),
    };
    
    // Update tags
    let mut tags: Vec<String> = case_data.get("tags")
        .and_then(|t| t.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    
    // Add new tags
    if let Some(add_tags) = req.add {
        for tag in add_tags {
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
    }
    
    // Remove tags
    if let Some(remove_tags) = req.remove {
        tags.retain(|t| !remove_tags.contains(t));
    }
    
    case_data["tags"] = serde_json::json!(tags.clone());
    let now = chrono::Utc::now().to_rfc3339();
    case_data["updated_at"] = serde_json::json!(&now);
    
    if let Err(e) = atomic_write_json(&case_json_path, &case_data) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to write case.json: {}", e),
                "code": "WRITE_FAILED"
            }))
        );
    }
    
    // Audit log with provenance
    let audit_path = store_dir.join("audit").join("events.jsonl");
    let audit_entry = serde_json::json!({
        "event": "tags_updated",
        "timestamp": now,
        "install_id": get_install_id(),
        "host_name": get_hostname(),
        "user_hint": get_user_hint(),
        "case_id": case_id,
        "tags": tags.clone()
    });
    let _ = append_jsonl(&audit_path, &audit_entry);
    
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "tags": tags
            }
        }))
    )
}

/// POST /api/team/cases/:case_id/notes - Add a note to the case
#[derive(serde::Deserialize)]
struct AddNoteRequest {
    content: String,
}

async fn team_add_note_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(case_id): axum::extract::Path<String>,
    axum::Json(req): axum::Json<AddNoteRequest>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Team tier gate
    if !resolve_current_tier().has_access(ProductTier::Team) {
        return feature_locked_403("Case Store", ProductTier::Team);
    }
    
    let store_dir = match get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case store not configured or unreachable",
                "code": "STORE_NOT_AVAILABLE"
            }))
        ),
    };
    
    let cases_dir = store_dir.join("cases");
    let case_dir = match safe_case_path_join(&cases_dir, &case_id) {
        Some(p) => p,
        None => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Invalid case ID",
                "code": "INVALID_CASE_ID"
            }))
        ),
    };
    
    if !case_dir.exists() {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case not found",
                "code": "CASE_NOT_FOUND"
            }))
        );
    }
    
    let now = chrono::Utc::now().to_rfc3339();
    let note_id = format!("note_{}_{:04}", 
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
        rand::random::<u32>() % 10000
    );
    
    // Note with provenance attribution
    let note = serde_json::json!({
        "note_id": note_id,
        "content": req.content,
        "created_at": now,
        "install_id": get_install_id(),
        "host_name": get_hostname(),
        "user_hint": get_user_hint()
    });
    
    // Append to notes.jsonl (no lock needed - append-only)
    let notes_path = case_dir.join("notes.jsonl");
    if let Err(e) = append_jsonl(&notes_path, &note) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to append note: {}", e),
                "code": "WRITE_FAILED"
            }))
        );
    }
    
    // Update case.json notes_count (needs lock)
    let _lock = match CaseStoreLock::try_acquire(&store_dir, &case_id) {
        Ok(l) => l,
        Err(_) => {
            // Note was appended, just skip count update (non-blocking)
            tracing::debug!("Skipping notes_count update - case {} locked", case_id);
            return (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!({
                    "success": true,
                    "data": note
                }))
            );
        }
    };
    
    let case_json_path = case_dir.join("case.json");
    if let Ok(content) = std::fs::read_to_string(&case_json_path) {
        if let Ok(mut case_data) = serde_json::from_str::<serde_json::Value>(&content) {
            let count = case_data.get("notes_count")
                .and_then(|c| c.as_u64())
                .unwrap_or(0);
            case_data["notes_count"] = serde_json::json!(count + 1);
            case_data["last_note_at"] = serde_json::json!(now);
            case_data["updated_at"] = serde_json::json!(now);
            let _ = atomic_write_json(&case_json_path, &case_data);
        }
    }
    
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "data": note
        }))
    )
}

/// POST /api/team/cases/:case_id/publish_run - Publish a local run to the case
/// Two-phase atomic publish: local bundle creation -> temp file copy -> verify -> atomic rename
#[derive(serde::Deserialize)]
struct PublishRunRequest {
    run_id: String,
}

/// Compute SHA256 hash of data
fn compute_sha256(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

async fn team_publish_run_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(case_id): axum::extract::Path<String>,
    axum::Json(req): axum::Json<PublishRunRequest>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Team tier gate
    if !resolve_current_tier().has_access(ProductTier::Team) {
        return feature_locked_403("Case Store", ProductTier::Team);
    }
    
    // Check store availability
    let store_dir = match get_store_dir(&state.data_dir) {
        Some(p) => p,
        _ => return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case store not configured",
                "code": "STORE_NOT_CONFIGURED"
            }))
        ),
    };
    
    if !store_dir.exists() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case store directory does not exist or is unreachable",
                "code": "STORE_UNREACHABLE"
            }))
        );
    }
    
    // Check if store is writable
    let writable_test = store_dir.join(".write_test");
    match std::fs::write(&writable_test, b"test") {
        Ok(_) => { let _ = std::fs::remove_file(&writable_test); }
        Err(_) => return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case store is read-only",
                "code": "STORE_READONLY"
            }))
        ),
    }
    
    // Validate run exists locally
    let run_dir = state.data_dir.join("runs").join(&req.run_id);
    if !run_dir.exists() {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Run '{}' not found locally", req.run_id),
                "code": "RUN_NOT_FOUND"
            }))
        );
    }
    
    // Validate case exists
    let cases_dir = store_dir.join("cases");
    let case_dir = match safe_case_path_join(&cases_dir, &case_id) {
        Some(p) => p,
        None => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Invalid case ID",
                "code": "INVALID_CASE_ID"
            }))
        ),
    };
    
    if !case_dir.exists() {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case not found",
                "code": "CASE_NOT_FOUND"
            }))
        );
    }
    
    // Create bundle from run (Phase 1: local bundle creation)
    let bundle_data = match create_full_bundle_zip(&run_dir, &req.run_id) {
        Ok(data) => data,
        Err(e) => return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create bundle: {}", e),
                "code": "BUNDLE_FAILED"
            }))
        ),
    };
    
    // Compute SHA256 of the bundle locally
    let bundle_sha256 = compute_sha256(&bundle_data);
    let bundle_size = bundle_data.len();
    
    // Check for duplicate (run already published)
    let runs_dir = case_dir.join("runs");
    let _ = std::fs::create_dir_all(&runs_dir);
    
    let bundle_filename = format!("{}.zip", req.run_id);
    let bundle_safe = match safe_case_path_join(&runs_dir, &bundle_filename) {
        Some(p) => p,
        None => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Invalid run ID",
                "code": "INVALID_RUN_ID"
            }))
        ),
    };
    
    if bundle_safe.exists() {
        return (
            axum::http::StatusCode::CONFLICT,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Run '{}' already published to this case", req.run_id),
                "code": "RUN_ALREADY_PUBLISHED"
            }))
        );
    }
    
    // Acquire lock for case update
    let mut lock = match CaseStoreLock::try_acquire(&store_dir, &case_id) {
        Ok(l) => l,
        Err((msg, reason_code, owner_info)) => return (
            axum::http::StatusCode::CONFLICT,
            axum::Json(serde_json::json!({
                "success": false,
                "error": msg,
                "code": reason_code,
                "lock_owner": owner_info
            }))
        ),
    };
    
    // Phase 2: Write bundle to temp file on store
    let temp_bundle = bundle_safe.with_extension("zip.tmp");
    if let Err(e) = std::fs::write(&temp_bundle, &bundle_data) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to write bundle to store: {}", e),
                "code": "TEMP_WRITE_FAILED"
            }))
        );
    }
    
    // Heartbeat after write (may be slow on SMB)
    let _ = lock.heartbeat();
    
    // Phase 3: Verify the written temp file (size + SHA256)
    let verify_result = (|| -> Result<(), String> {
        // Check size
        let temp_meta = std::fs::metadata(&temp_bundle)
            .map_err(|e| format!("Failed to read temp file metadata: {}", e))?;
        if temp_meta.len() as usize != bundle_size {
            return Err(format!(
                "Size mismatch: expected {}, got {}",
                bundle_size, temp_meta.len()
            ));
        }
        
        // Check SHA256
        let temp_data = std::fs::read(&temp_bundle)
            .map_err(|e| format!("Failed to read temp file: {}", e))?;
        let temp_sha256 = compute_sha256(&temp_data);
        if temp_sha256 != bundle_sha256 {
            return Err(format!(
                "SHA256 mismatch: expected {}, got {}",
                bundle_sha256, temp_sha256
            ));
        }
        
        Ok(())
    })();
    
    if let Err(e) = verify_result {
        let _ = std::fs::remove_file(&temp_bundle);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Bundle verification failed: {}", e),
                "code": "HASH_MISMATCH"
            }))
        );
    }
    
    // Heartbeat after verify
    let _ = lock.heartbeat();
    
    // Phase 4: Atomic rename temp -> final
    if let Err(e) = std::fs::rename(&temp_bundle, &bundle_safe) {
        let _ = std::fs::remove_file(&temp_bundle);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to finalize bundle: {}", e),
                "code": "ATOMIC_RENAME_FAILED"
            }))
        );
    }
    
    // Phase 5: Update case.json with run entry (including sha256)
    let now = chrono::Utc::now().to_rfc3339();
    let case_json_path = case_dir.join("case.json");
    
    let run_entry = serde_json::json!({
        "run_id": req.run_id,
        "published_at": now,
        "bundle_filename": bundle_filename,
        "bundle_size": bundle_size,
        "sha256": bundle_sha256,
        "published_by": get_install_id(),
        "publisher_host": get_hostname()
    });
    
    if let Ok(content) = std::fs::read_to_string(&case_json_path) {
        if let Ok(mut case_data) = serde_json::from_str::<serde_json::Value>(&content) {
            let mut runs = case_data.get("runs")
                .and_then(|r| r.as_array())
                .cloned()
                .unwrap_or_default();
            runs.push(run_entry.clone());
            case_data["runs"] = serde_json::json!(runs);
            case_data["updated_at"] = serde_json::json!(now);
            
            if let Err(e) = atomic_write_json(&case_json_path, &case_data) {
                // Bundle is published but case.json update failed - log warning but don't fail
                eprintln!("Warning: Bundle published but case.json update failed: {}", e);
            }
        }
    }
    
    // Audit log with provenance
    let audit_path = store_dir.join("audit").join("events.jsonl");
    let audit_entry = serde_json::json!({
        "event": "run_published",
        "timestamp": now,
        "install_id": get_install_id(),
        "host_name": get_hostname(),
        "user_hint": get_user_hint(),
        "case_id": case_id,
        "run_id": req.run_id,
        "bundle_size": bundle_size,
        "sha256": bundle_sha256
    });
    let _ = append_jsonl(&audit_path, &audit_entry);
    
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "published": true,
                "run": run_entry
            }
        }))
    )
}

/// Create a complete ZIP bundle for publishing
fn create_full_bundle_zip(run_dir: &std::path::Path, run_id: &str) -> Result<Vec<u8>, String> {
    use std::io::{Write, Read};
    use zip::write::FileOptions;
    use zip::ZipWriter;
    
    let buffer = Vec::new();
    let mut cursor = std::io::Cursor::new(buffer);
    
    {
        let mut zip = ZipWriter::new(&mut cursor);
        
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        
        // Add run_meta.json
        let meta_path = run_dir.join("run_meta.json");
        if meta_path.exists() {
            let content = std::fs::read_to_string(&meta_path)
                .map_err(|e| format!("Failed to read run_meta.json: {}", e))?;
            zip.start_file("run_meta.json", options)
                .map_err(|e| format!("ZIP error: {}", e))?;
            zip.write_all(content.as_bytes())
                .map_err(|e| format!("ZIP write error: {}", e))?;
        }
        
        // Add workbench.db
        let db_path = run_dir.join("workbench.db");
        if db_path.exists() {
            let mut content = Vec::new();
            std::fs::File::open(&db_path)
                .map_err(|e| format!("Failed to open workbench.db: {}", e))?
                .read_to_end(&mut content)
                .map_err(|e| format!("Failed to read workbench.db: {}", e))?;
            zip.start_file("workbench.db", options)
                .map_err(|e| format!("ZIP error: {}", e))?;
            zip.write_all(&content)
                .map_err(|e| format!("ZIP write error: {}", e))?;
        }
        
        // Add segments directory
        let segments_dir = run_dir.join("segments");
        if segments_dir.exists() && segments_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&segments_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            let zip_path = format!("segments/{}", name);
                            let mut content = Vec::new();
                            if let Ok(mut f) = std::fs::File::open(&path) {
                                if f.read_to_end(&mut content).is_ok() {
                                    let _ = zip.start_file(&zip_path, options);
                                    let _ = zip.write_all(&content);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Add bundle manifest
        let manifest = serde_json::json!({
            "run_id": run_id,
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "schema_version": "1.0.0",
            "contract_hash": "v1-bundle-202601"
        });
        zip.start_file("bundle_manifest.json", options)
            .map_err(|e| format!("ZIP error: {}", e))?;
        zip.write_all(serde_json::to_string_pretty(&manifest).unwrap().as_bytes())
            .map_err(|e| format!("ZIP write error: {}", e))?;
        
        // Finish the zip
        zip.finish()
            .map_err(|e| format!("ZIP finish error: {}", e))?;
    } // zip dropped here, releasing the borrow
    
    Ok(cursor.into_inner())
}

/// POST /api/team/cases/:case_id/import_run - Import a run from case store to local
#[derive(serde::Deserialize)]
struct ImportRunRequest {
    run_id: String,
}

async fn team_import_run_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(case_id): axum::extract::Path<String>,
    axum::Json(req): axum::Json<ImportRunRequest>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // Team tier gate
    if !resolve_current_tier().has_access(ProductTier::Team) {
        return feature_locked_403("Case Store", ProductTier::Team);
    }
    
    let store_dir = match get_store_dir(&state.data_dir) {
        Some(p) if p.exists() => p,
        _ => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Case store not configured or unreachable",
                "code": "STORE_NOT_AVAILABLE"
            }))
        ),
    };
    
    // Validate case and run
    let cases_dir = store_dir.join("cases");
    let case_dir = match safe_case_path_join(&cases_dir, &case_id) {
        Some(p) => p,
        None => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Invalid case ID",
                "code": "INVALID_CASE_ID"
            }))
        ),
    };
    
    let bundle_filename = format!("{}.zip", req.run_id);
    let runs_dir = case_dir.join("runs");
    let bundle_path = match safe_case_path_join(&runs_dir, &bundle_filename) {
        Some(p) => p,
        None => return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Invalid run ID",
                "code": "INVALID_RUN_ID"
            }))
        ),
    };
    
    if !bundle_path.exists() {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Run '{}' not found in case", req.run_id),
                "code": "RUN_NOT_FOUND"
            }))
        );
    }
    
    // Check if already imported locally
    let local_run_dir = state.data_dir.join("runs").join(&req.run_id);
    if local_run_dir.exists() {
        return (
            axum::http::StatusCode::CONFLICT,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Run '{}' already exists locally", req.run_id),
                "code": "RUN_EXISTS"
            }))
        );
    }
    
    // Extract bundle to local runs directory
    let bundle_data = match std::fs::read(&bundle_path) {
        Ok(data) => data,
        Err(e) => return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to read bundle: {}", e),
                "code": "READ_FAILED"
            }))
        ),
    };
    
    if let Err(e) = extract_bundle_to_run(&bundle_data, &local_run_dir) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to extract bundle: {}", e),
                "code": "EXTRACT_FAILED"
            }))
        );
    }
    
    // Mark run as imported (read-only) in run_meta.json
    let meta_path = local_run_dir.join("run_meta.json");
    if let Ok(content) = std::fs::read_to_string(&meta_path) {
        if let Ok(mut meta) = serde_json::from_str::<serde_json::Value>(&content) {
            meta["imported_from_case"] = serde_json::json!(case_id);
            meta["imported_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
            meta["read_only"] = serde_json::json!(true);
            let _ = atomic_write_json(&meta_path, &meta);
        }
    }
    
    // Audit log
    let audit_path = store_dir.join("audit").join("events.jsonl");
    let audit_entry = serde_json::json!({
        "event": "run_imported",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "by": get_install_id(),
        "case_id": case_id,
        "run_id": req.run_id
    });
    let _ = append_jsonl(&audit_path, &audit_entry);
    
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "data": {
                "imported": true,
                "run_id": req.run_id,
                "local_path": local_run_dir.display().to_string()
            }
        }))
    )
}

/// Extract a bundle ZIP to a local run directory
fn extract_bundle_to_run(bundle_data: &[u8], run_dir: &std::path::Path) -> Result<(), String> {
    use std::io::Read;
    use zip::ZipArchive;
    
    std::fs::create_dir_all(run_dir)
        .map_err(|e| format!("Failed to create run dir: {}", e))?;
    
    let cursor = std::io::Cursor::new(bundle_data);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| format!("Invalid ZIP: {}", e))?;
    
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)
            .map_err(|e| format!("ZIP read error: {}", e))?;
        
        let name = file.name().to_string();
        
        // Skip directories
        if name.ends_with('/') {
            continue;
        }
        
        // Validate path safety
        if name.contains("..") || name.starts_with('/') || name.starts_with('\\') {
            continue; // Skip unsafe paths
        }
        
        let dest_path = run_dir.join(&name);
        
        // Create parent directories
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create dir: {}", e))?;
        }
        
        // Extract file
        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|e| format!("Failed to read from ZIP: {}", e))?;
        
        std::fs::write(&dest_path, &content)
            .map_err(|e| format!("Failed to write file: {}", e))?;
    }
    
    Ok(())
}

// ============================================================================
// Platform-specific helpers
// ============================================================================

fn init_file_logging(log_path: &std::path::Path) {
    use tracing_subscriber::prelude::*;
    
    if let Ok(file) = std::fs::File::create(log_path) {
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false);
        
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "locint=info,edr_server=info".into()))
            .with(file_layer)
            .init();
    }
}

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

// ============================================================================
// Build verification
// ============================================================================

/// Compile-time assertion that locint uses shared server_core types
/// This ensures locint stays in sync with edr-server infrastructure
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn uses_shared_server_core() {
        // Verify we can construct ShippedResources and ServerConfig
        let resources = ShippedResources::resolve().unwrap();
        let _config = resources.to_server_config(3000);
        
        // Verify StartupError variants exist
        let _e1 = StartupError::MissingResources(vec!["test".into()]);
        let _e2 = StartupError::PortInUse { port: 3000, error: "test".into() };
        let _e3 = StartupError::ChildProcessSpawn { 
            binary: std::path::PathBuf::from("test"), 
            error: "test".into() 
        };
    }
    
    #[test]
    fn router_has_required_routes() {
        // Verify router builds without panic
        let config = edr_server::server_core::ServerConfig::for_development(3000, false);
        let _router = build_locint_router(&config);
    }
    
    /// Test that run_meta.json timestamps take priority over run_id parsing
    /// This proves run_id parsing is ONLY used as a fallback
    #[test]
    fn run_meta_json_takes_priority_over_run_id_parsing() {
        let dir = tempdir().expect("Failed to create temp dir");
        let run_dir = dir.path();
        
        // Create a run_meta.json with authoritative timestamps
        let meta_content = serde_json::json!({
            "run_id": "run_20260101_120000",
            "started_at": "2026-01-11T10:30:00Z",  // Different from run_id timestamp!
            "stopped_at": "2026-01-11T11:00:00Z",
            "status": "completed"
        });
        std::fs::write(
            run_dir.join("run_meta.json"),
            serde_json::to_string_pretty(&meta_content).unwrap()
        ).expect("Failed to write run_meta.json");
        
        // run_id would parse to 2026-01-01 12:00:00 UTC
        // but run_meta.json says 2026-01-11 10:30:00 UTC
        let (started_at, stopped_at, status) = read_run_meta(
            &run_dir.join("run_meta.json"),
            "run_20260101_120000"
        );
        
        // Verify we got the run_meta.json values, not run_id-derived values
        let started = started_at.expect("started_at should be Some");
        assert_eq!(started.to_rfc3339().starts_with("2026-01-11T10:30"), true,
            "started_at should come from run_meta.json (2026-01-11), not run_id (2026-01-01)");
        
        let stopped = stopped_at.expect("stopped_at should be Some");
        assert_eq!(stopped.to_rfc3339().starts_with("2026-01-11T11:00"), true,
            "stopped_at should come from run_meta.json");
        
        assert_eq!(status, "completed");
    }
    
    /// Test that parse_run_id_timestamp is used ONLY when run_meta.json is missing
    #[test]
    fn run_id_parsing_is_fallback_only() {
        let dir = tempdir().expect("Failed to create temp dir");
        let run_dir = dir.path();
        
        // No run_meta.json exists - should fall back to run_id parsing
        let (started_at, stopped_at, status) = read_run_meta(
            &run_dir.join("run_meta.json"),  // doesn't exist
            "run_20260115_143022"
        );
        
        // Fallback: started_at should come from run_id parsing
        let started = started_at.expect("started_at should be Some from run_id fallback");
        assert_eq!(started.to_rfc3339().starts_with("2026-01-15T14:30:22"), true,
            "started_at should come from run_id parsing: run_20260115_143022");
        
        // No run_meta.json means no stopped_at
        assert!(stopped_at.is_none(), "stopped_at should be None when no run_meta.json");
        
        // Status should be "unknown" (no workbench.db either)
        assert_eq!(status, "unknown");
    }
    
    /// Test parse_run_id_timestamp function directly
    #[test]
    fn test_parse_run_id_timestamp() {
        // Valid format: run_YYYYMMDD_HHMMSS
        let ts = parse_run_id_timestamp("run_20260115_143022").expect("Should parse");
        assert_eq!(ts.format("%Y-%m-%d %H:%M:%S").to_string(), "2026-01-15 14:30:22");
        
        // Invalid formats should return None
        assert!(parse_run_id_timestamp("invalid").is_none());
        assert!(parse_run_id_timestamp("run_abc").is_none());
        assert!(parse_run_id_timestamp("").is_none());
    }
}

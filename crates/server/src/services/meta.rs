//! Meta Service
//!
//! Handles route registry, contract, features, and dataflow snapshot.
//! All business logic for meta endpoints lives here.
//!
//! # VERSIONING RULE (Contract Freeze)
//!
//! If you modify the route list or API contract, you MUST:
//! 1. Bump CONTRACT_VERSION below
//! 2. Update docs/parity/routes_snapshot.json
//! 3. Update docs/parity/contract_snapshot.json
//! 4. Document the change in CHANGELOG.md
//!
//! The parity tests (tests/parity_routes_contract.rs) will fail if snapshots
//! don't match the current build. This guards against accidental API drift.

use crate::services::types::{ProductTier, RouteInfo};

// ============================================================================
// Contract Version (BUMP THIS WHEN CHANGING ROUTES OR CONTRACT)
// ============================================================================

/// Contract version - bump when routes or contract schema changes.
/// Format: MAJOR.MINOR.PATCH (semver-ish)
/// - MAJOR: Breaking changes to existing endpoints
/// - MINOR: New endpoints added
/// - PATCH: Documentation/description changes only
pub const CONTRACT_VERSION: &str = "1.1.0";

/// Contract hash - unique identifier for this contract revision.
/// Format: v{major}-{scope}-{YYYYMM}
/// Update this whenever CONTRACT_VERSION changes.
pub const CONTRACT_HASH: &str = "v1-core-202601b";

// ============================================================================
// Route Registry
// ============================================================================

/// Returns authoritative list of all registered API routes.
/// This is the single source of truth for UI wiring checks.
pub fn get_registered_routes() -> Vec<RouteInfo> {
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
        
        // Pro Entity Explorer
        RouteInfo::new("GET", "/api/runs/:run_id/entities", "List entities in run (Pro)", false),
        RouteInfo::new("GET", "/api/runs/:run_id/pivot", "Pivot query for entity (Pro)", false),
        RouteInfo::new("POST", "/api/runs/:run_id/export/case_pack", "Export case pack (Pro)", true),
        
        // Baselines
        RouteInfo::new("GET", "/api/baselines", "List baseline runs", false),
        
        // Micro Chains (canonical backend registry)
        RouteInfo::new("GET", "/api/chains", "List all micro chain definitions", false),
        RouteInfo::new("POST", "/api/chains/compile", "Compile chain stack to playbook selections", true),
        
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
        
        // Capability Model
        RouteInfo::new("GET", "/api/capability/status", "Sensor inventory and capability status", false),
        RouteInfo::new("GET", "/api/capability/detection_plan", "Detection plan with dependencies", false),
        RouteInfo::new("GET", "/api/capability/gaps", "Coverage gaps analysis (dev-only)", false),
        
        // Playbook catalog
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
        RouteInfo::new("POST", "/api/packs/rescan", "Rescan packs directory", true),
        
        // Evidence dereference
        RouteInfo::new("GET", "/api/evidence/deref", "Dereference evidence pointer to source record", false),
        
        // Meta (wiring audit + tier features)
        RouteInfo::new("GET", "/api/meta/routes", "List all routes (this endpoint)", false),
        RouteInfo::new("GET", "/api/meta/contract", "API contract/wrapper spec", false),
        RouteInfo::new("GET", "/api/meta/features", "Tier-aware feature flags for UI gating", false),
        RouteInfo::new("GET", "/api/meta/dataflow_snapshot", "Dataflow debug snapshot (?debug=1)", false),
        
        // Team Case Store (Team tier)
        RouteInfo::new("GET", "/api/team/store/status", "Team store status", false),
        RouteInfo::new("POST", "/api/team/store/configure", "Configure team store", true),
        RouteInfo::new("GET", "/api/team/cases", "List team cases", false),
        RouteInfo::new("POST", "/api/team/cases", "Create team case", true),
        RouteInfo::new("GET", "/api/team/cases/:case_id", "Get team case", false),
        RouteInfo::new("GET", "/api/team/cases/:case_id/aggregate", "Case aggregate view", false),
        RouteInfo::new("POST", "/api/team/cases/:case_id/tags", "Update case tags", true),
        RouteInfo::new("POST", "/api/team/cases/:case_id/notes", "Add case note", true),
        RouteInfo::new("POST", "/api/team/cases/:case_id/publish_run", "Publish run to case", true),
        RouteInfo::new("POST", "/api/team/cases/:case_id/import_run", "Import run from case", true),
        
        // Debug endpoints (dev only)
        RouteInfo::new("GET", "/api/run/debug_counts", "Debug: live signal/fact counts", false),
    ]
}

// ============================================================================
// API Contract
// ============================================================================

/// Get the API contract specification.
/// Uses CONTRACT_VERSION and CONTRACT_HASH constants for consistency.
pub fn get_api_contract() -> serde_json::Value {
    serde_json::json!({
        "contract_version": CONTRACT_VERSION,
        "contract_hash": CONTRACT_HASH,
        "wrapper": {
            "success_field": "success",
            "data_field": "data",
            "error_field": "error",
            "code_field": "code"
        },
        "list_convention": "named_array",
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
    })
}

// ============================================================================
// Feature Flags
// ============================================================================

/// Get tier-aware feature flags
pub fn get_feature_flags(tier: ProductTier) -> serde_json::Value {
    let is_dev = tier == ProductTier::Dev;
    let is_pro_or_above = tier.has_access(ProductTier::Pro);
    let is_team = tier.has_access(ProductTier::Team);

    serde_json::json!({
        "tier": tier,
        "tier_display": tier.display_name(),
        "features": {
            // Core (Free tier - always enabled)
            "run_workflow": true,
            "capability_model": true,
            "playbook_system": true,
            "signals_explain": true,
            "evidence_deref": true,
            "next_steps": true,
            "import_export": true,
            "wiring_audit": true,
            "diff_phase": true,
            
            // Pro tier features
            "baselines": is_pro_or_above,
            "diff_advanced": is_pro_or_above,
            "custom_packs": is_pro_or_above,
            "case_summary": is_pro_or_above,
            "entity_explorer": is_pro_or_above,
            "case_pack_export": is_pro_or_above,
            "pdf_reports": is_pro_or_above,
            "search_similar": is_pro_or_above,
            "cross_run_search": is_pro_or_above,
            "entity_timeline": is_pro_or_above,
            "notes": is_pro_or_above,
            
            // Team tier features
            "case_store": is_team,
            "case_management": is_team,
            "multi_workspace": is_team,
            "integrations": is_team,
            "custom_templates": is_team,
            "audit_log": is_team,
            
            // Dev features
            "debug_endpoints": is_dev,
            "gaps_analysis": is_dev,
            "dataflow_snapshot": is_dev,
            "validation_helper": is_dev
        },
        "gating": {
            "endpoints": {
                // Pro-gated
                "/api/runs/:id/baseline": "pro",
                "/api/baselines": "pro",
                "/api/runs/:id/diff?mode=baseline": "pro",
                "/api/runs/:id/diff?mode=marker": "pro",
                "/api/runs/:id/diff?baseline_filter=true": "pro",
                "/api/runs/:id/case_summary": "pro",
                "/api/runs/:id/entities": "pro",
                "/api/runs/:id/pivot": "pro",
                "/api/runs/:id/export/case_pack": "pro",
                "/api/packs (custom)": "pro",
                
                // Team-gated
                "/api/team/store/status": "team",
                "/api/team/store/configure": "team",
                "/api/team/cases": "team",
                "/api/team/cases/:case_id": "team",
                "/api/team/cases/:case_id/aggregate": "team",
                "/api/team/cases/:case_id/tags": "team",
                "/api/team/cases/:case_id/notes": "team",
                "/api/team/cases/:case_id/publish_run": "team",
                "/api/team/cases/:case_id/import_run": "team",
                
                // Dev-gated
                "/api/run/debug_counts": "dev",
                "/api/capability/gaps": "dev",
                "/api/meta/dataflow_snapshot": "dev"
            }
        },
        "upgrade_url": "https://locint.io/upgrade"
    })
}

// ============================================================================
// Diagnosis Generation
// ============================================================================

use crate::flight_recorder::{SpawnStatus, SegmentsStatus, DbTruth};

/// Generate diagnosis based on dataflow state
pub fn generate_diagnosis(
    running: bool,
    spawn: &SpawnStatus,
    segments: &SegmentsStatus,
    db: &DbTruth,
) -> Vec<String> {
    let mut issues = vec![];

    // Check if run is active but processes aren't running
    if running {
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
        let signals_count = db
            .tables
            .iter()
            .find(|t| t.name == "signals")
            .map(|t| t.rowcount)
            .unwrap_or(0);

        if signals_count == 0 && segments.segments_count > 5 {
            issues.push(format!(
                "LOCALD_NOT_READING: {} segments exist but signals table has 0 rows",
                segments.segments_count
            ));
        }
    }

    // Check for stale segments
    if let Some(ref newest) = segments.newest_segment {
        if running && newest.age_seconds > 30 {
            issues.push(format!(
                "CAPTURE_STALLED: Newest segment is {} seconds old",
                newest.age_seconds
            ));
        }
    }

    // Check DB existence vs run status
    if running && !db.db_exists {
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

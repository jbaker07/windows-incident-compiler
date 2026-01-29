//! Run Coverage API - Exposes fact extraction statistics for runs
//!
//! Provides coverage rollup data showing what fact types were extracted
//! during a run, even when no signals were produced.
//!
//! Returns structured "available" responses:
//! - available=true: coverage data with facts, types, hosts, diagnostics
//! - available=false: reason_code explaining why (MISSING_RUN_DIR, MISSING_DB, etc.)

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::services::types::SharedState;

// =============================================================================
// Response Types
// =============================================================================

/// Reason codes for unavailable coverage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageReasonCode {
    MissingRunDir,
    MissingDb,
    MissingTable,
    PipelineNotFinalized,
    RunNotFound,
    DatabaseError,
}

impl std::fmt::Display for CoverageReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoverageReasonCode::MissingRunDir => write!(f, "MISSING_RUN_DIR"),
            CoverageReasonCode::MissingDb => write!(f, "MISSING_DB"),
            CoverageReasonCode::MissingTable => write!(f, "MISSING_TABLE"),
            CoverageReasonCode::PipelineNotFinalized => write!(f, "PIPELINE_NOT_FINALIZED"),
            CoverageReasonCode::RunNotFound => write!(f, "RUN_NOT_FOUND"),
            CoverageReasonCode::DatabaseError => write!(f, "DATABASE_ERROR"),
        }
    }
}

/// Debug info for unavailable coverage (minimal and safe)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageDebugInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_status: Option<String>,
}

/// Unavailable coverage response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageUnavailable {
    pub available: bool,  // Always false
    pub reason_code: CoverageReasonCode,
    pub message: String,
    pub run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<CoverageDebugInfo>,
    // Run readiness fields for consistency with CoverageAvailable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_status: Option<String>,  // "compiling" | "interrupted" when unavailable
    #[serde(default)]
    pub facts_ready: bool,               // false when coverage unavailable
    #[serde(default)]
    pub facts_partial: bool,             // true if reason_code indicates partial data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abandoned_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<String>,
}

/// Sensor status in a run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorSummary {
    pub sensor_name: String,
    pub status: SensorStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fact_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
}

/// Status of a sensor
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SensorStatus {
    Active,       // Sensor is configured and producing events
    Configured,   // Sensor is configured but produced no events
    Missing,      // Expected sensor not found
}

/// Compile status for run
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CompileStatus {
    Compiling,    // Fact extraction in progress
    Finalized,    // Fact extraction complete
    Interrupted,  // Fact extraction was interrupted (crash/kill)
}

impl Default for CompileStatus {
    fn default() -> Self {
        CompileStatus::Finalized
    }
}

/// Available coverage response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAvailable {
    pub available: bool,  // Always true
    pub run_id: String,
    pub facts_total: u64,
    pub fact_types: Vec<FactTypeSummary>,
    pub top_hosts: Vec<EntitySummary>,
    pub sensor_modes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensors: Option<Vec<SensorSummary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipeline_diagnostics: Option<PipelineDiagnostics>,
    // Run readiness fields for crash/interrupt handling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_status: Option<String>,  // "compiling" | "finalized" | "interrupted"
    #[serde(default)]
    pub facts_ready: bool,               // true if facts are fully extracted
    #[serde(default)]
    pub facts_partial: bool,             // true if only partial facts (interrupted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abandoned_reason: Option<String>, // reason if run was abandoned
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<String>, // ISO timestamp of last activity
}

/// Aggregated fact type statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactTypeSummary {
    pub fact_type: String,
    pub count: u64,
}

/// Entity summary (top entities by activity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySummary {
    pub host: String,
    pub count: u64,
}

/// Pipeline diagnostic info for "why no signals" section
/// TRUTHFUL ACCOUNTING: Shows total/runnable/skipped playbooks with reasons
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineDiagnostics {
    /// Total YAML files found in playbooks directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playbooks_total_yaml: Option<u32>,
    /// Number of playbooks that loaded successfully and can run
    pub playbooks_loaded: Option<u32>,
    /// Number of playbooks skipped (with reasons)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playbooks_skipped: Option<u32>,
    /// Breakdown of skip reasons (e.g., {"TAG_BASED_UNSUPPORTED": 8})
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_by_reason: Option<std::collections::HashMap<String, u32>>,
    /// Examples of skipped playbooks (first few)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_examples: Option<Vec<SkippedPlaybookInfo>>,
    pub playbook_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playbooks_enabled: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playbook_categories: Option<Vec<String>>,
    /// TASK C: Number of distinct signal types fired this run (filtered by run_id)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playbooks_fired_this_run: Option<u32>,
    /// TASK C: Breakdown of fired signals by category (e.g., {"execution": 2, "persistence": 1})
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fired_by_category: Option<std::collections::HashMap<String, u32>>,
    pub scoring_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_thresholds_info: Option<String>,
    pub explanation: String,
    pub coverage_minutes: u32,
}

/// Info about a skipped playbook for diagnostics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedPlaybookInfo {
    pub playbook_id: String,
    pub reason: String,
}

/// Query params for coverage endpoint
#[derive(Debug, Deserialize)]
pub struct CoverageParams {
    #[allow(dead_code)]
    pub limit: Option<usize>,
}

// =============================================================================
// Coverage Loading
// =============================================================================

/// Error types for coverage loading
pub enum CoverageLoadError {
    MissingDb(PathBuf),
    MissingTable(String),
    DbError(String),
}

/// Load coverage data from a run's database (workbench.db or analysis.db)
pub fn load_run_coverage(run_dir: &PathBuf, run_id: &str) -> Result<CoverageAvailable, CoverageLoadError> {
    // Try workbench.db first (used by current locald), then analysis.db (legacy)
    let workbench_path = run_dir.join("workbench.db");
    let analysis_path = run_dir.join("analysis.db");
    
    let db_path = if workbench_path.exists() {
        workbench_path
    } else if analysis_path.exists() {
        analysis_path
    } else {
        return Err(CoverageLoadError::MissingDb(workbench_path));
    };
    
    let conn = Connection::open(&db_path)
        .map_err(|e| CoverageLoadError::DbError(format!("Failed to open {}: {}", db_path.display(), e)))?;
    
    // Check if coverage_rollup table exists
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='coverage_rollup'",
            [],
            |row| row.get::<_, i32>(0),
        )
        .map(|c| c > 0)
        .unwrap_or(false);
    
    if !table_exists {
        return Err(CoverageLoadError::MissingTable("coverage_rollup".to_string()));
    }
    
    // TRUTH FIX: Query TRUE total facts count first (no LIMIT)
    let true_facts_total: u64 = conn
        .query_row(
            "SELECT COALESCE(SUM(fact_count), 0) FROM coverage_rollup",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64;
    
    // TRUTH FIX: Query fact type counts from FULL table (grouped aggregation, no LIMIT)
    let mut fact_type_counts: HashMap<String, u64> = HashMap::new();
    if let Ok(mut stmt) = conn.prepare(
        r#"SELECT fact_type, SUM(fact_count) as total 
           FROM coverage_rollup 
           WHERE fact_type IS NOT NULL AND fact_type != ''
           GROUP BY fact_type
           ORDER BY total DESC"#
    ) {
        if let Ok(mut rows) = stmt.query([]) {
            while let Ok(Some(row)) = rows.next() {
                let fact_type: String = row.get(0).unwrap_or_default();
                let count: u64 = row.get::<_, i64>(1).unwrap_or(0) as u64;
                if !fact_type.is_empty() && count > 0 {
                    fact_type_counts.insert(fact_type, count);
                }
            }
        }
    }
    
    // Query coverage_rollup for host/sensor statistics (sampled for performance)
    let mut host_counts: HashMap<String, u64> = HashMap::new();
    let mut sensor_modes: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut sensor_fact_counts: HashMap<String, u64> = HashMap::new();
    let mut sensor_capabilities: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    let mut seen_minutes: std::collections::HashSet<i64> = std::collections::HashSet::new();
    
    let result = conn.prepare(
        r#"SELECT ts_minute, host, sensor_mode, fact_count, enabled_capabilities
           FROM coverage_rollup
           ORDER BY ts_minute DESC
           LIMIT 1000"#
    );
    
    if let Ok(mut stmt) = result {
        if let Ok(mut rows) = stmt.query([]) {
            while let Ok(Some(row)) = rows.next() {
                let ts_minute: i64 = row.get(0).unwrap_or(0);
                let host: String = row.get(1).unwrap_or_default();
                let sensor_mode: Option<String> = row.get(2).ok();
                let fact_count: u32 = row.get(3).unwrap_or(0);
                let enabled_caps: Option<String> = row.get(4).ok();
                
                // Track unique minutes for coverage_minutes
                if ts_minute > 0 {
                    seen_minutes.insert(ts_minute);
                }
                
                // NOTE: fact_type aggregation is now done via separate full-table query above
                
                // Aggregate host counts (sampled)
                if !host.is_empty() && fact_count > 0 {
                    *host_counts.entry(host.clone()).or_insert(0) += fact_count as u64;
                }
                
                // Track sensor modes and their fact counts
                if let Some(ref sm) = sensor_mode {
                    if !sm.is_empty() {
                        sensor_modes.insert(sm.clone());
                        *sensor_fact_counts.entry(sm.clone()).or_insert(0) += fact_count as u64;
                        
                        // Track capabilities per sensor
                        if let Some(ref caps) = enabled_caps {
                            let caps_set = sensor_capabilities.entry(sm.clone()).or_default();
                            for cap in caps.split(',') {
                                let cap = cap.trim();
                                if !cap.is_empty() {
                                    caps_set.insert(cap.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    let coverage_minutes = seen_minutes.len() as u32;
    
    // Build sensor summaries
    let sensors: Vec<SensorSummary> = sensor_modes.iter().map(|sm| {
        let fact_count = sensor_fact_counts.get(sm).copied();
        let capabilities = sensor_capabilities.get(sm).map(|caps| {
            caps.iter().cloned().collect::<Vec<_>>()
        });
        
        SensorSummary {
            sensor_name: sm.clone(),
            status: if fact_count.unwrap_or(0) > 0 {
                SensorStatus::Active
            } else {
                SensorStatus::Configured
            },
            fact_count,
            capabilities,
        }
    }).collect();
    
    // Sort fact types by count descending
    let mut fact_types: Vec<_> = fact_type_counts
        .into_iter()
        .map(|(fact_type, count)| FactTypeSummary { fact_type, count })
        .collect();
    fact_types.sort_by(|a, b| b.count.cmp(&a.count));
    
    // Sort hosts by count descending, take top 10
    let mut top_hosts: Vec<_> = host_counts
        .into_iter()
        .map(|(host, count)| EntitySummary { host, count })
        .collect();
    top_hosts.sort_by(|a, b| b.count.cmp(&a.count));
    top_hosts.truncate(10);
    
    // Load playbook state for diagnostics
    // TASK C: Pass run_id for filtering signals (use true_facts_total for accuracy)
    let pipeline_diagnostics = load_pipeline_diagnostics(&conn, true_facts_total, coverage_minutes, run_id);
    
    Ok(CoverageAvailable {
        available: true,
        run_id: run_id.to_string(),
        facts_total: true_facts_total,  // TRUTH FIX: Use true total, not sampled
        fact_types,
        top_hosts,
        sensor_modes: sensor_modes.into_iter().collect(),
        sensors: if sensors.is_empty() { None } else { Some(sensors) },
        pipeline_diagnostics,
        // Default to finalized for successfully loaded coverage
        compile_status: Some("finalized".to_string()),
        facts_ready: true,
        facts_partial: false,
        abandoned_reason: None,
        last_activity_at: None,
    })
}

/// Load pipeline diagnostics from analysis.db
/// TASK C: Added run_id parameter to filter playbooks_fired_this_run by run
fn load_pipeline_diagnostics(conn: &Connection, facts_total: u64, coverage_minutes: u32, run_id: &str) -> Option<PipelineDiagnostics> {
    // Try to count playbook states (indicates active detection)
    let playbooks_loaded = conn
        .query_row(
            "SELECT COUNT(DISTINCT playbook_id) FROM playbook_state",
            [],
            |row| row.get::<_, u32>(0),
        )
        .ok();
    
    // Try to get playbook names
    let playbook_names: Vec<String> = conn
        .prepare("SELECT DISTINCT playbook_id FROM playbook_state LIMIT 50")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([], |row| row.get(0))
                .ok()
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    // TASK C: Count fired playbooks for THIS RUN by filtering on run_id
    // Extract playbook family from signal_type (e.g., "windows_encoded_powershell" -> "execution")
    let playbooks_fired = conn
        .query_row(
            "SELECT COUNT(DISTINCT signal_type) FROM signals WHERE run_id = ?1",
            rusqlite::params![run_id],
            |row| row.get::<_, u32>(0),
        )
        .ok()
        .or_else(|| {
            // Fallback: count from signals table without run_id filter (legacy)
            conn.query_row(
                "SELECT COUNT(DISTINCT signal_type) FROM signals",
                [],
                |row| row.get::<_, u32>(0),
            ).ok()
        });
    
    // TASK C: Get fired signal types for category breakdown
    let fired_signal_types: Vec<String> = conn
        .prepare("SELECT DISTINCT signal_type FROM signals WHERE run_id = ?1")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(rusqlite::params![run_id], |row| row.get(0))
                .ok()
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    
    // Extract unique categories from playbook IDs (family part before underscore usually)
    let playbook_categories: Vec<String> = {
        let mut cats = std::collections::HashSet::new();
        // Include categories from loaded playbooks
        for name in &playbook_names {
            // Common family prefixes
            if name.contains("lateral_movement") || name.starts_with("lat_") {
                cats.insert("lateral_movement".to_string());
            } else if name.contains("defense_evasion") || name.starts_with("evasion_") {
                cats.insert("defense_evasion".to_string());
            } else if name.contains("persistence") || name.starts_with("persist_") {
                cats.insert("persistence".to_string());
            } else if name.contains("credential") || name.starts_with("cred_") {
                cats.insert("credential_access".to_string());
            } else if name.contains("execution") || name.starts_with("exec_") || name.contains("powershell") {
                cats.insert("execution".to_string());
            } else if name.contains("discovery") || name.starts_with("disc_") {
                cats.insert("discovery".to_string());
            } else if name.contains("collection") || name.starts_with("coll_") {
                cats.insert("collection".to_string());
            }
        }
        // TASK C: Also include categories from fired signals
        for sig_type in &fired_signal_types {
            if sig_type.contains("lateral") {
                cats.insert("lateral_movement".to_string());
            } else if sig_type.contains("evasion") || sig_type.contains("disable") {
                cats.insert("defense_evasion".to_string());
            } else if sig_type.contains("persist") || sig_type.contains("registry") || sig_type.contains("service") {
                cats.insert("persistence".to_string());
            } else if sig_type.contains("credential") || sig_type.contains("lsass") {
                cats.insert("credential_access".to_string());
            } else if sig_type.contains("powershell") || sig_type.contains("script") || sig_type.contains("exec") {
                cats.insert("execution".to_string());
            }
        }
        let mut v: Vec<_> = cats.into_iter().collect();
        v.sort();
        v
    };
    
    // Build explanation based on what we found
    let explanation = if facts_total == 0 {
        "No facts were extracted during this run. This could indicate no relevant telemetry \
         was captured, or the capture duration was too short."
            .to_string()
    } else if playbooks_loaded.unwrap_or(0) == 0 {
        format!(
            "{} facts were extracted, but no playbook rules matched. \
             Detection rules require specific patterns to produce signals.",
            facts_total
        )
    } else {
        format!(
            "{} facts were extracted and {} playbook rules were active. \
             No signals were produced because the observed facts did not match \
             the detection patterns defined in the playbooks. This is normal \
             for benign activity.",
            facts_total,
            playbooks_loaded.unwrap_or(0)
        )
    };
    
    // TRUTHFUL ACCOUNTING: Load skip info from playbook_load_stats table if available
    let (playbooks_total_yaml, playbooks_skipped, skipped_by_reason, skipped_examples) = 
        load_playbook_skip_info(conn);
    
    // TASK C: Build fired_by_category from fired_signal_types
    let fired_by_category: std::collections::HashMap<String, u32> = {
        let mut cats: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        for sig_type in &fired_signal_types {
            let category = if sig_type.contains("lateral") {
                "lateral_movement"
            } else if sig_type.contains("evasion") || sig_type.contains("disable") {
                "defense_evasion"
            } else if sig_type.contains("persist") || sig_type.contains("registry") || sig_type.contains("service") || sig_type.contains("task") {
                "persistence"
            } else if sig_type.contains("credential") || sig_type.contains("lsass") || sig_type.contains("mimikatz") {
                "credential_access"
            } else if sig_type.contains("powershell") || sig_type.contains("script") || sig_type.contains("encoded") || sig_type.contains("exec") {
                "execution"
            } else if sig_type.contains("discovery") || sig_type.contains("whoami") || sig_type.contains("net_") {
                "discovery"
            } else {
                "other"
            };
            *cats.entry(category.to_string()).or_insert(0) += 1;
        }
        cats
    };
    
    Some(PipelineDiagnostics {
        playbooks_total_yaml,
        playbooks_loaded,
        playbooks_skipped,
        skipped_by_reason,
        skipped_examples,
        playbook_names,
        playbooks_enabled: playbooks_loaded, // For hardcoded, all loaded are enabled
        playbook_categories: if playbook_categories.is_empty() { None } else { Some(playbook_categories) },
        playbooks_fired_this_run: playbooks_fired,
        fired_by_category: if fired_by_category.is_empty() { None } else { Some(fired_by_category) },
        scoring_enabled: true,
        detection_thresholds_info: Some("Signals require matching playbook patterns".to_string()),
        explanation,
        coverage_minutes,
    })
}

/// Load playbook skip info from DB (if table exists)
fn load_playbook_skip_info(conn: &Connection) -> (
    Option<u32>,
    Option<u32>,
    Option<std::collections::HashMap<String, u32>>,
    Option<Vec<SkippedPlaybookInfo>>
) {
    // Check if playbook_load_stats table exists
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='playbook_load_stats'",
            [],
            |row| row.get::<_, i32>(0),
        )
        .map(|c| c > 0)
        .unwrap_or(false);
    
    if !table_exists {
        return (None, None, None, None);
    }
    
    // Load stats from table
    let total_yaml = conn
        .query_row("SELECT total_yaml_files FROM playbook_load_stats LIMIT 1", [], |row| row.get::<_, u32>(0))
        .ok();
    let skipped = conn
        .query_row("SELECT skipped_count FROM playbook_load_stats LIMIT 1", [], |row| row.get::<_, u32>(0))
        .ok();
    
    // Load skip reasons
    let skipped_by_reason: Option<std::collections::HashMap<String, u32>> = conn
        .prepare("SELECT reason, count FROM playbook_skip_reasons")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
            })
            .ok()
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
        });
    
    // Load examples
    let skipped_examples: Option<Vec<SkippedPlaybookInfo>> = conn
        .prepare("SELECT playbook_id, reason FROM playbook_skip_examples LIMIT 10")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok(SkippedPlaybookInfo {
                    playbook_id: row.get(0)?,
                    reason: row.get(1)?,
                })
            })
            .ok()
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
        });
    
    (total_yaml, skipped, skipped_by_reason, skipped_examples)
}

// =============================================================================
// Run Meta Helpers
// =============================================================================

/// Read run readiness fields from run_meta.json
/// Returns (compile_status, facts_ready, facts_partial, abandoned_reason, last_activity_at)
fn read_run_meta_status(run_dir: &PathBuf) -> (Option<String>, bool, bool, Option<String>, Option<String>) {
    let meta_path = run_dir.join("run_meta.json");
    if !meta_path.exists() {
        return (None, true, false, None, None); // Default to finalized if no meta
    }
    
    let meta_str = match std::fs::read_to_string(&meta_path) {
        Ok(s) => s,
        Err(_) => return (None, true, false, None, None),
    };
    
    let meta: serde_json::Value = match serde_json::from_str(&meta_str) {
        Ok(v) => v,
        Err(_) => return (None, true, false, None, None),
    };
    
    let compile_status = meta.get("compile_status")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    let status = meta.get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    
    // Determine facts_ready: true if finalized, false if compiling/interrupted/abandoned
    let facts_ready = match compile_status.as_deref() {
        Some("finalized") => true,
        Some("compiling") => false,
        Some("interrupted") => false, // Partial data may exist
        _ => status != "running" && status != "abandoned", // Default based on status
    };
    
    // facts_partial: true only if interrupted (has some data but incomplete)
    let facts_partial = compile_status.as_deref() == Some("interrupted") || status == "abandoned";
    
    let abandoned_reason = meta.get("abandoned_reason")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    // Get last_activity_at from stopped_at or phase timestamp
    let last_activity_at = meta.get("stopped_at")
        .or_else(|| meta.get("last_activity"))
        .or_else(|| meta.get("started_at"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    (compile_status, facts_ready, facts_partial, abandoned_reason, last_activity_at)
}

// =============================================================================
// HTTP Handler
// =============================================================================

/// GET /api/runs/:run_id/coverage - Get coverage statistics for a run
/// 
/// Returns HTTP 200 with either:
/// - available=true and coverage data
/// - available=false with reason_code and message
pub async fn get_run_coverage(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Query(_params): Query<CoverageParams>,
) -> impl IntoResponse {
    // Get run record to find run_dir
    let run_record = match state.db.get_run(&run_id) {
        Ok(Some(run)) => run,
        Ok(None) => {
            return (
                StatusCode::OK,
                Json(serde_json::json!(CoverageUnavailable {
                    available: false,
                    reason_code: CoverageReasonCode::RunNotFound,
                    message: format!("Run '{}' not found in database", run_id),
                    run_id: run_id.clone(),
                    debug: None,
                    compile_status: None,
                    facts_ready: false,
                    facts_partial: false,
                    abandoned_reason: None,
                    last_activity_at: None,
                })),
            );
        }
        Err(e) => {
            return (
                StatusCode::OK,
                Json(serde_json::json!(CoverageUnavailable {
                    available: false,
                    reason_code: CoverageReasonCode::DatabaseError,
                    message: format!("Database error looking up run: {}", e),
                    run_id: run_id.clone(),
                    debug: None,
                    compile_status: None,
                    facts_ready: false,
                    facts_partial: false,
                    abandoned_reason: None,
                    last_activity_at: None,
                })),
            );
        }
    };
    
    // Check run status - if still running, pipeline may not be finalized
    if run_record.status == "running" {
        return (
            StatusCode::OK,
            Json(serde_json::json!(CoverageUnavailable {
                available: false,
                reason_code: CoverageReasonCode::PipelineNotFinalized,
                message: "Run is still in progress. Stop the run to finalize coverage data.".to_string(),
                run_id: run_id.clone(),
                debug: Some(CoverageDebugInfo {
                    expected_path: run_record.run_dir.clone(),
                    run_status: Some(run_record.status.clone()),
                }),
                compile_status: Some("compiling".to_string()),
                facts_ready: false,
                facts_partial: true,
                abandoned_reason: None,
                last_activity_at: None,
            })),
        );
    }
    
    // Get run directory from persisted metadata
    let run_dir = match run_record.run_dir {
        Some(ref dir) => PathBuf::from(dir),
        None => {
            return (
                StatusCode::OK,
                Json(serde_json::json!(CoverageUnavailable {
                    available: false,
                    reason_code: CoverageReasonCode::MissingRunDir,
                    message: "Run has no associated telemetry directory. This run may have been created before artifact tracking was added.".to_string(),
                    run_id: run_id.clone(),
                    debug: Some(CoverageDebugInfo {
                        expected_path: None,
                        run_status: Some(run_record.status.clone()),
                    }),
                    compile_status: None,
                    facts_ready: false,
                    facts_partial: false,
                    abandoned_reason: None,
                    last_activity_at: None,
                })),
            );
        }
    };
    
    // Check if run_dir exists on disk
    if !run_dir.exists() {
        return (
            StatusCode::OK,
            Json(serde_json::json!(CoverageUnavailable {
                available: false,
                reason_code: CoverageReasonCode::MissingRunDir,
                message: format!("Telemetry directory no longer exists on disk: {}", run_dir.display()),
                run_id: run_id.clone(),
                debug: Some(CoverageDebugInfo {
                    expected_path: Some(run_dir.display().to_string()),
                    run_status: Some(run_record.status.clone()),
                }),
                compile_status: None,
                facts_ready: false,
                facts_partial: false,
                abandoned_reason: None,
                last_activity_at: None,
            })),
        );
    }
    
    // Read run_meta.json for status fields
    let (meta_compile_status, meta_facts_ready, meta_facts_partial, meta_abandoned_reason, meta_last_activity) = 
        read_run_meta_status(&run_dir);
    
    // Load coverage data
    match load_run_coverage(&run_dir, &run_id) {
        Ok(mut coverage) => {
            // Enrich coverage with run_meta status (run_meta is source of truth for interrupted runs)
            if let Some(ref cs) = meta_compile_status {
                coverage.compile_status = Some(cs.clone());
            }
            if meta_compile_status.as_deref() == Some("interrupted") {
                coverage.facts_ready = false;
                coverage.facts_partial = true;
            }
            coverage.abandoned_reason = meta_abandoned_reason.clone();
            if let Some(ref ts) = meta_last_activity {
                coverage.last_activity_at = Some(ts.clone());
            }
            (
                StatusCode::OK,
                Json(serde_json::json!(coverage)),
            )
        },
        Err(CoverageLoadError::MissingDb(path)) => {
            // Missing DB could indicate interrupted run - check run_meta
            let (compile_status, facts_ready, facts_partial) = if meta_compile_status.as_deref() == Some("interrupted") {
                (Some("interrupted".to_string()), false, true)
            } else {
                (meta_compile_status.clone(), meta_facts_ready, meta_facts_partial)
            };
            (
                StatusCode::OK,
                Json(serde_json::json!(CoverageUnavailable {
                    available: false,
                    reason_code: CoverageReasonCode::MissingDb,
                    message: "Analysis database not found. The pipeline may not have completed fact extraction.".to_string(),
                    run_id: run_id.clone(),
                    debug: Some(CoverageDebugInfo {
                        expected_path: Some(path.display().to_string()),
                        run_status: Some(run_record.status.clone()),
                    }),
                    compile_status,
                    facts_ready,
                    facts_partial,
                    abandoned_reason: meta_abandoned_reason,
                    last_activity_at: meta_last_activity,
                })),
            )
        },
        Err(CoverageLoadError::MissingTable(table)) => (
            StatusCode::OK,
            Json(serde_json::json!(CoverageUnavailable {
                available: false,
                reason_code: CoverageReasonCode::MissingTable,
                message: format!("Coverage table '{}' not found in analysis database. The pipeline may not support coverage tracking.", table),
                run_id: run_id.clone(),
                debug: Some(CoverageDebugInfo {
                    expected_path: Some(run_dir.join("analysis.db").display().to_string()),
                    run_status: Some(run_record.status.clone()),
                }),
                compile_status: meta_compile_status,
                facts_ready: meta_facts_ready,
                facts_partial: meta_facts_partial,
                abandoned_reason: meta_abandoned_reason,
                last_activity_at: meta_last_activity,
            })),
        ),
        Err(CoverageLoadError::DbError(err)) => (
            StatusCode::OK,
            Json(serde_json::json!(CoverageUnavailable {
                available: false,
                reason_code: CoverageReasonCode::DatabaseError,
                message: format!("Error reading analysis database: {}", err),
                run_id: run_id.clone(),
                debug: Some(CoverageDebugInfo {
                    expected_path: Some(run_dir.join("analysis.db").display().to_string()),
                    run_status: Some(run_record.status.clone()),
                }),
                compile_status: meta_compile_status,
                facts_ready: meta_facts_ready,
                facts_partial: meta_facts_partial,
                abandoned_reason: meta_abandoned_reason,
                last_activity_at: meta_last_activity,
            })),
        ),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_coverage_available_serialization() {
        let coverage = CoverageAvailable {
            available: true,
            run_id: "run_test123".to_string(),
            facts_total: 100,
            fact_types: vec![
                FactTypeSummary { fact_type: "ProcessCreate".to_string(), count: 50 },
                FactTypeSummary { fact_type: "FileCreate".to_string(), count: 30 },
            ],
            top_hosts: vec![
                EntitySummary { host: "HOST1".to_string(), count: 80 },
            ],
            sensor_modes: vec!["ETW".to_string()],
            sensors: Some(vec![
                SensorSummary {
                    sensor_name: "ETW".to_string(),
                    status: SensorStatus::Active,
                    fact_count: Some(100),
                    capabilities: Some(vec!["proc_exec".to_string(), "file_ops".to_string()]),
                },
            ]),
            pipeline_diagnostics: Some(PipelineDiagnostics {
                playbooks_total_yaml: Some(10),
                playbooks_loaded: Some(5),
                playbooks_skipped: Some(5),
                skipped_by_reason: None,
                skipped_examples: None,
                playbook_names: vec!["encoded_powershell".to_string()],
                playbooks_enabled: Some(5),
                playbook_categories: Some(vec!["execution".to_string()]),
                playbooks_fired_this_run: Some(0),
                fired_by_category: None,
                scoring_enabled: true,
                detection_thresholds_info: Some("Default thresholds".to_string()),
                explanation: "100 facts extracted, 5 playbook rules active".to_string(),
                coverage_minutes: 3,
            }),
            compile_status: Some("finalized".to_string()),
            facts_ready: true,
            facts_partial: false,
            abandoned_reason: None,
            last_activity_at: None,
        };
        
        let json = serde_json::to_string(&coverage).unwrap();
        assert!(json.contains("\"available\":true"));
        assert!(json.contains("run_test123"));
        assert!(json.contains("ProcessCreate"));
        assert!(json.contains("\"compile_status\":\"finalized\""));
        assert!(json.contains("\"facts_ready\":true"));
    }
    
    #[test]
    fn test_coverage_unavailable_serialization() {
        let unavailable = CoverageUnavailable {
            available: false,
            reason_code: CoverageReasonCode::MissingDb,
            message: "Analysis database not found".to_string(),
            run_id: "run_test456".to_string(),
            debug: Some(CoverageDebugInfo {
                expected_path: Some("/path/to/analysis.db".to_string()),
                run_status: Some("stopped".to_string()),
            }),
            compile_status: Some("interrupted".to_string()),
            facts_ready: false,
            facts_partial: true,
            abandoned_reason: Some("Server crashed".to_string()),
            last_activity_at: Some("2026-01-15T10:30:00Z".to_string()),
        };
        
        let json = serde_json::to_string(&unavailable).unwrap();
        assert!(json.contains("\"available\":false"));
        assert!(json.contains("\"reason_code\":\"MISSING_DB\""));
        assert!(json.contains("run_test456"));
        assert!(json.contains("\"compile_status\":\"interrupted\""));
        assert!(json.contains("\"facts_partial\":true"));
    }
    
    #[test]
    fn test_load_coverage_missing_db() {
        let dir = tempdir().unwrap();
        let result = load_run_coverage(&dir.path().to_path_buf(), "test_run");
        assert!(matches!(result, Err(CoverageLoadError::MissingDb(_))));
    }
    
    #[test]
    fn test_reason_code_display() {
        assert_eq!(CoverageReasonCode::MissingRunDir.to_string(), "MISSING_RUN_DIR");
        assert_eq!(CoverageReasonCode::MissingDb.to_string(), "MISSING_DB");
        assert_eq!(CoverageReasonCode::MissingTable.to_string(), "MISSING_TABLE");
    }
}

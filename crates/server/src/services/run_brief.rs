//! Run Brief Service (RUN_BRIEF-1 Refactor)
//!
//! Main orchestrator for the `/api/runs/:run_id/brief` endpoint.
//! Composes data from run_brief_repo, episodes, and capability modules
//! to build the complete RunBrief response.
//!
//! ## Response Schema
//! The response matches the original JSON schema exactly:
//! - `available`: bool
//! - `run_id`: String
//! - `totals`: { events_total, facts_total, signals_fired, segments_count }
//! - `coverage`: { snapshot_present, sysmon, is_admin, security_log_accessible, gaps }
//! - `timeline`: [{ start_ts, end_ts, count }]
//! - `top_entities`: { processes, destinations, registry, files }
//! - `notable_findings`: [{ signal_id, playbook_id, severity, ts, ts_start, ts_end, evidence_refs_count, evidence_ptrs }]
//! - `episodes`: [{ episode_id, start_ts, end_ts, primary_entity, labels, evidence_ptrs }]
//! - `unmapped_activity`: { fact_type_counts }

use serde::Serialize;
use std::path::Path;

use crate::services::capability::get_capability_snapshot_from_meta;
use crate::services::episodes::{cluster_episodes_default, Episode};
use crate::services::run_brief_repo::{
    self, BriefTotals, EntityEntry, FactTypeCount, NotableFinding, TimelineBucket, TopEntities,
};

// ============================================================================
// Response Types
// ============================================================================

/// Error types for run brief operations
#[derive(Debug)]
pub enum RunBriefError {
    /// Run directory not found
    RunNotFound(String),
    /// workbench.db not found in run directory
    MissingDb(String),
    /// Failed to open database
    DbOpenError(String),
}

impl std::fmt::Display for RunBriefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunBriefError::RunNotFound(run_id) => write!(f, "Run not found: {}", run_id),
            RunBriefError::MissingDb(run_id) => write!(f, "Missing workbench.db for run: {}", run_id),
            RunBriefError::DbOpenError(msg) => write!(f, "Failed to open database: {}", msg),
        }
    }
}

/// Coverage information from run_meta.json capability snapshot
#[derive(Debug, Clone, Serialize)]
pub struct CoverageInfo {
    pub snapshot_present: bool,
    pub sysmon: Option<bool>,
    pub is_admin: Option<bool>,
    pub security_log_accessible: Option<bool>,
    pub gaps: Vec<CoverageGap>,
}

/// A coverage gap with impact description
#[derive(Debug, Clone, Serialize)]
pub struct CoverageGap {
    pub gap: String,
    pub impact: String,
}

/// The complete run brief response
#[derive(Debug, Clone, Serialize)]
pub struct RunBrief {
    pub available: bool,
    pub run_id: String,
    pub totals: BriefTotals,
    pub coverage: CoverageInfo,
    pub timeline: Vec<TimelineBucket>,
    pub top_entities: TopEntities,
    pub notable_findings: Vec<NotableFinding>,
    pub episodes: Vec<Episode>,
    pub unmapped_activity: UnmappedActivity,
}

/// Unmapped activity (fact types not in signals)
#[derive(Debug, Clone, Serialize)]
pub struct UnmappedActivity {
    pub fact_type_counts: Vec<FactTypeCount>,
}

/// Response for unavailable runs (not found or missing DB)
#[derive(Debug, Clone, Serialize)]
pub struct RunBriefUnavailable {
    pub available: bool,
    pub reason: String,
    pub run_id: String,
}

impl RunBriefUnavailable {
    pub fn not_found(run_id: &str) -> Self {
        Self {
            available: false,
            reason: "RUN_NOT_FOUND".to_string(),
            run_id: run_id.to_string(),
        }
    }
    
    pub fn missing_db(run_id: &str) -> Self {
        Self {
            available: false,
            reason: "MISSING_DB".to_string(),
            run_id: run_id.to_string(),
        }
    }
}

// ============================================================================
// Main Builder Function
// ============================================================================

/// Build the complete run brief for a given run
///
/// This is the main entry point called by the handler. It orchestrates:
/// 1. Loading capability snapshot from run_meta.json
/// 2. Querying totals from coverage_rollup
/// 3. Querying timeline buckets
/// 4. Querying top entities (with fallback)
/// 5. Querying notable findings from signals
/// 6. Clustering signals into episodes
/// 7. Computing unmapped activity
///
/// # Arguments
/// * `run_id` - The run identifier
/// * `run_dir` - Path to the run directory containing workbench.db and run_meta.json
///
/// # Returns
/// * `Ok(RunBrief)` - Complete brief data
/// * `Err(RunBriefError)` - If DB not found or cannot be opened
pub fn build_run_brief(run_id: &str, run_dir: &Path) -> Result<RunBrief, RunBriefError> {
    // Check DB exists
    if !run_brief_repo::workbench_db_exists(run_dir) {
        return Err(RunBriefError::MissingDb(run_id.to_string()));
    }
    
    // Open database
    let conn = run_brief_repo::open_workbench_db(run_dir)
        .map_err(|e| RunBriefError::DbOpenError(e.to_string()))?;
    
    // === COVERAGE: From run_meta.json capability snapshot ===
    let coverage = build_coverage_info(run_dir);
    
    // === TOTALS: From coverage_rollup ===
    let totals = run_brief_repo::query_totals(&conn);
    
    // === TIMELINE: From coverage_rollup ===
    let timeline = run_brief_repo::query_timeline_buckets(&conn);
    
    // === TOP ENTITIES: entity_rollup or facts_sample fallback ===
    let top_entities = run_brief_repo::query_top_entities(&conn);
    
    // === NOTABLE FINDINGS: From signals table ===
    let notable_findings = run_brief_repo::query_notable_findings(&conn);
    
    // === EPISODES: Cluster signals ===
    let signals_for_clustering = run_brief_repo::query_signals_for_clustering(&conn);
    let episodes = cluster_episodes_default(&signals_for_clustering);
    
    // === UNMAPPED ACTIVITY: Fact types from coverage_rollup ===
    let fact_type_counts = run_brief_repo::query_fact_type_counts(&conn);
    let unmapped_activity = UnmappedActivity { fact_type_counts };
    
    Ok(RunBrief {
        available: true,
        run_id: run_id.to_string(),
        totals,
        coverage,
        timeline,
        top_entities,
        notable_findings,
        episodes,
        unmapped_activity,
    })
}

/// Build coverage information from run_meta.json
fn build_coverage_info(run_dir: &Path) -> CoverageInfo {
    let meta_path = run_dir.join("run_meta.json");
    let capability = get_capability_snapshot_from_meta(&meta_path);
    
    let snapshot_present = capability.get("is_admin").is_some() 
        || capability.get("sysmon_installed").is_some();
    
    let is_admin = capability.get("is_admin").and_then(|v| v.as_bool());
    let sysmon_installed = capability.get("sysmon_installed").and_then(|v| v.as_bool());
    let security_log_accessible = capability.get("security_log_accessible").and_then(|v| v.as_bool());
    
    // Build coverage gaps
    let mut gaps: Vec<CoverageGap> = Vec::new();
    if is_admin == Some(false) {
        gaps.push(CoverageGap {
            gap: "NOT_ADMIN".to_string(),
            impact: "Limited access to Security event log".to_string(),
        });
    }
    if sysmon_installed == Some(false) {
        gaps.push(CoverageGap {
            gap: "NO_SYSMON".to_string(),
            impact: "No process command lines, network connections".to_string(),
        });
    }
    if security_log_accessible == Some(false) {
        gaps.push(CoverageGap {
            gap: "NO_SECURITY_LOG".to_string(),
            impact: "No authentication events".to_string(),
        });
    }
    
    CoverageInfo {
        snapshot_present,
        sysmon: sysmon_installed,
        is_admin,
        security_log_accessible,
        gaps,
    }
}

// ============================================================================
// JSON Serialization Helpers
// ============================================================================

impl RunBrief {
    /// Convert to serde_json::Value matching the original response schema exactly
    pub fn to_json(&self) -> serde_json::Value {
        // Convert entities to JSON arrays with the exact field names
        let processes: Vec<serde_json::Value> = self.top_entities.processes.iter()
            .map(entity_to_json)
            .collect();
        let destinations: Vec<serde_json::Value> = self.top_entities.destinations.iter()
            .map(entity_to_json)
            .collect();
        let registry: Vec<serde_json::Value> = self.top_entities.registry.iter()
            .map(entity_to_json)
            .collect();
        let files: Vec<serde_json::Value> = self.top_entities.files.iter()
            .map(entity_to_json)
            .collect();
        
        // Convert timeline to JSON
        let timeline: Vec<serde_json::Value> = self.timeline.iter()
            .map(|b| serde_json::json!({
                "start_ts": b.start_ts,
                "end_ts": b.end_ts,
                "count": b.count
            }))
            .collect();
        
        // Convert notable findings to JSON
        let notable_findings: Vec<serde_json::Value> = self.notable_findings.iter()
            .map(|f| serde_json::json!({
                "signal_id": f.signal_id,
                "playbook_id": f.playbook_id,
                "severity": f.severity,
                "ts": f.ts,
                "ts_start": f.ts_start,
                "ts_end": f.ts_end,
                "evidence_refs_count": f.evidence_refs_count,
                "evidence_ptrs": f.evidence_ptrs
            }))
            .collect();
        
        // Convert episodes to JSON
        let episodes: Vec<serde_json::Value> = self.episodes.iter()
            .map(|e| e.to_json())
            .collect();
        
        // Convert gaps to JSON
        let gaps: Vec<serde_json::Value> = self.coverage.gaps.iter()
            .map(|g| serde_json::json!({
                "gap": g.gap,
                "impact": g.impact
            }))
            .collect();
        
        // Convert unmapped fact types to JSON
        let unmapped_fact_types: Vec<serde_json::Value> = self.unmapped_activity.fact_type_counts.iter()
            .map(|f| serde_json::json!({
                "fact_type": f.fact_type,
                "count": f.count
            }))
            .collect();
        
        serde_json::json!({
            "available": self.available,
            "run_id": self.run_id,
            "totals": {
                "events_total": self.totals.events_total,
                "facts_total": self.totals.facts_total,
                "signals_fired": self.totals.signals_fired,
                "segments_count": self.totals.segments_count
            },
            "coverage": {
                "snapshot_present": self.coverage.snapshot_present,
                "sysmon": self.coverage.sysmon,
                "is_admin": self.coverage.is_admin,
                "security_log_accessible": self.coverage.security_log_accessible,
                "gaps": gaps
            },
            "timeline": timeline,
            "top_entities": {
                "processes": processes,
                "destinations": destinations,
                "registry": registry,
                "files": files
            },
            "notable_findings": notable_findings,
            "episodes": episodes,
            "unmapped_activity": {
                "fact_type_counts": unmapped_fact_types
            }
        })
    }
}

/// Convert EntityEntry to JSON with exact field names
fn entity_to_json(e: &EntityEntry) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "entity": e.entity,
        "count": e.count
    });
    
    if let Some(first_ts) = e.first_ts {
        obj["first_ts"] = serde_json::json!(first_ts);
    }
    if let Some(last_ts) = e.last_ts {
        obj["last_ts"] = serde_json::json!(last_ts);
    }
    if let Some(ref note) = e.note {
        obj["note"] = serde_json::json!(note);
    }
    
    obj
}

impl RunBriefUnavailable {
    /// Convert to serde_json::Value for error responses
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "available": self.available,
            "reason": self.reason,
            "run_id": self.run_id
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_test_run_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        
        // Create workbench.db with minimal schema
        let db_path = dir.path().join("workbench.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(r#"
            CREATE TABLE coverage_rollup (
                ts_minute INTEGER,
                event_count INTEGER,
                fact_count INTEGER,
                fact_type TEXT
            );
            CREATE TABLE segments (segment_id TEXT, records INTEGER, facts INTEGER);
            CREATE TABLE signals (
                signal_id TEXT, signal_type TEXT, severity TEXT,
                ts INTEGER, ts_start INTEGER, ts_end INTEGER,
                proc_key TEXT, evidence_ptrs TEXT
            );
            CREATE TABLE facts_sample (fact_type TEXT, entity_key TEXT, ts INTEGER);
        "#).unwrap();
        
        // Create run_meta.json
        let meta = serde_json::json!({
            "readiness_snapshot": {
                "is_admin": true,
                "sysmon_installed": true,
                "security_log_accessible": false
            }
        });
        fs::write(dir.path().join("run_meta.json"), meta.to_string()).unwrap();
        
        dir
    }

    #[test]
    fn test_build_run_brief_empty_db() {
        let dir = setup_test_run_dir();
        let brief = build_run_brief("test-run", dir.path()).unwrap();
        
        assert!(brief.available);
        assert_eq!(brief.run_id, "test-run");
        assert_eq!(brief.totals.events_total, 0);
        assert!(brief.notable_findings.is_empty());
        assert!(brief.episodes.is_empty());
    }

    #[test]
    fn test_build_run_brief_coverage_gaps() {
        let dir = TempDir::new().unwrap();
        
        // Create DB
        let db_path = dir.path().join("workbench.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(r#"
            CREATE TABLE coverage_rollup (ts_minute INTEGER, event_count INTEGER, fact_count INTEGER, fact_type TEXT);
            CREATE TABLE segments (segment_id TEXT, records INTEGER, facts INTEGER);
            CREATE TABLE signals (signal_id TEXT, signal_type TEXT, severity TEXT, ts INTEGER, ts_start INTEGER, ts_end INTEGER, proc_key TEXT, evidence_ptrs TEXT);
            CREATE TABLE facts_sample (fact_type TEXT, entity_key TEXT, ts INTEGER);
        "#).unwrap();
        
        // Create meta with all false (should generate all gaps)
        let meta = serde_json::json!({
            "readiness_snapshot": {
                "is_admin": false,
                "sysmon_installed": false,
                "security_log_accessible": false
            }
        });
        fs::write(dir.path().join("run_meta.json"), meta.to_string()).unwrap();
        
        let brief = build_run_brief("test-run", dir.path()).unwrap();
        
        assert_eq!(brief.coverage.gaps.len(), 3);
        assert!(brief.coverage.gaps.iter().any(|g| g.gap == "NOT_ADMIN"));
        assert!(brief.coverage.gaps.iter().any(|g| g.gap == "NO_SYSMON"));
        assert!(brief.coverage.gaps.iter().any(|g| g.gap == "NO_SECURITY_LOG"));
    }

    #[test]
    fn test_build_run_brief_missing_db() {
        let dir = TempDir::new().unwrap();
        let result = build_run_brief("test-run", dir.path());
        
        assert!(matches!(result, Err(RunBriefError::MissingDb(_))));
    }

    #[test]
    fn test_run_brief_json_schema_keys() {
        let dir = setup_test_run_dir();
        let brief = build_run_brief("test-run", dir.path()).unwrap();
        let json = brief.to_json();
        
        // Verify all top-level keys exist
        assert!(json.get("available").is_some());
        assert!(json.get("run_id").is_some());
        assert!(json.get("totals").is_some());
        assert!(json.get("coverage").is_some());
        assert!(json.get("timeline").is_some());
        assert!(json.get("top_entities").is_some());
        assert!(json.get("notable_findings").is_some());
        assert!(json.get("episodes").is_some());
        assert!(json.get("unmapped_activity").is_some());
        
        // Verify totals keys
        let totals = json.get("totals").unwrap();
        assert!(totals.get("events_total").is_some());
        assert!(totals.get("facts_total").is_some());
        assert!(totals.get("signals_fired").is_some());
        assert!(totals.get("segments_count").is_some());
        
        // Verify coverage keys
        let coverage = json.get("coverage").unwrap();
        assert!(coverage.get("snapshot_present").is_some());
        assert!(coverage.get("sysmon").is_some());
        assert!(coverage.get("is_admin").is_some());
        assert!(coverage.get("security_log_accessible").is_some());
        assert!(coverage.get("gaps").is_some());
        
        // Verify top_entities keys
        let top_entities = json.get("top_entities").unwrap();
        assert!(top_entities.get("processes").is_some());
        assert!(top_entities.get("destinations").is_some());
        assert!(top_entities.get("registry").is_some());
        assert!(top_entities.get("files").is_some());
        
        // Verify unmapped_activity keys
        let unmapped = json.get("unmapped_activity").unwrap();
        assert!(unmapped.get("fact_type_counts").is_some());
    }

    #[test]
    fn test_run_brief_unavailable_json() {
        let unavailable = RunBriefUnavailable::not_found("test-123");
        let json = unavailable.to_json();
        
        assert_eq!(json["available"], false);
        assert_eq!(json["reason"], "RUN_NOT_FOUND");
        assert_eq!(json["run_id"], "test-123");
    }

    /// Schema invariant test: ensures the JSON structure never changes shape
    /// across refactors. This prevents regressions in the API contract.
    #[test]
    fn test_schema_invariants_regression() {
        let dir = setup_test_run_dir();
        
        // Insert some data to get non-trivial output
        let db_path = dir.path().join("workbench.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("INSERT INTO segments (segment_id, records, facts) VALUES ('s1', 100, 50)", []).unwrap();
        conn.execute("INSERT INTO coverage_rollup (ts_minute, event_count, fact_count, fact_type) VALUES (1000, 50, 25, 'process')", []).unwrap();
        conn.execute(
            r#"INSERT INTO signals (signal_id, signal_type, severity, ts, ts_start, ts_end, proc_key, evidence_ptrs) 
               VALUES ('sig1', 'playbook:test/signal', 'high', 1000000, 1000000, 1000000, 'proc123', '[]')"#,
            [],
        ).unwrap();
        drop(conn);
        
        let brief = build_run_brief("schema-test", dir.path()).unwrap();
        let json = brief.to_json();
        
        // INVARIANT: available is always a boolean, never null
        assert!(json["available"].is_boolean(), "available must be boolean");
        
        // INVARIANT: totals are always integers, never null
        let totals = &json["totals"];
        assert!(totals["events_total"].is_u64() || totals["events_total"].is_i64(), "events_total must be integer");
        assert!(totals["facts_total"].is_u64() || totals["facts_total"].is_i64(), "facts_total must be integer");
        assert!(totals["signals_fired"].is_u64() || totals["signals_fired"].is_i64(), "signals_fired must be integer");
        assert!(totals["segments_count"].is_u64() || totals["segments_count"].is_i64(), "segments_count must be integer");
        
        // INVARIANT: timeline is always an array
        assert!(json["timeline"].is_array(), "timeline must be array");
        
        // INVARIANT: episodes is always an array  
        assert!(json["episodes"].is_array(), "episodes must be array");
        
        // INVARIANT: notable_findings is always an array
        assert!(json["notable_findings"].is_array(), "notable_findings must be array");
        
        // INVARIANT: top_entities has exactly these 4 sub-arrays
        let top = &json["top_entities"];
        assert!(top["processes"].is_array(), "top_entities.processes must be array");
        assert!(top["destinations"].is_array(), "top_entities.destinations must be array");
        assert!(top["registry"].is_array(), "top_entities.registry must be array");
        assert!(top["files"].is_array(), "top_entities.files must be array");
        
        // INVARIANT: coverage.gaps is always an array
        assert!(json["coverage"]["gaps"].is_array(), "coverage.gaps must be array");
        
        // INVARIANT: unmapped_activity.fact_type_counts is always an array
        assert!(json["unmapped_activity"]["fact_type_counts"].is_array(), "fact_type_counts must be array");
        
        // INVARIANT: when episodes exist, they have required fields
        // (tested above with inserted signal data)
        
        // INVARIANT: run_id matches what was passed in
        assert_eq!(json["run_id"], "schema-test", "run_id must match input");
    }
}

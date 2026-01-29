//! Run Brief Repository (RUN_BRIEF-1 Refactor)
//!
//! Database access layer for the run brief endpoint. All SQL queries for
//! workbench.db are centralized here.
//!
//! ## Design
//! - Single responsibility: DB access only
//! - All SQL queries extracted from original handler
//! - Fallback strategies preserved exactly
//! - Returns typed structs, not raw JSON

use rusqlite::{Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::services::evidence_ptrs::{parse_evidence_ptrs_raw, strip_playbook_prefix};
use crate::services::episodes::SignalForClustering;

// ============================================================================
// Repository Result Types
// ============================================================================

/// Aggregated totals from coverage_rollup table
#[derive(Debug, Clone, Default, Serialize)]
pub struct BriefTotals {
    pub events_total: i64,
    pub facts_total: i64,
    pub signals_fired: i64,
    pub segments_count: i64,
}

/// A single timeline bucket from coverage_rollup
#[derive(Debug, Clone, Serialize)]
pub struct TimelineBucket {
    pub start_ts: i64,
    pub end_ts: i64,
    pub count: i64,
}

/// A single entity with count and time range
#[derive(Debug, Clone, Serialize)]
pub struct EntityEntry {
    pub entity: String,
    pub count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_ts: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ts: Option<i64>,
    /// Present if data came from sampled facts_sample fallback
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Top entities by category
#[derive(Debug, Clone, Default, Serialize)]
pub struct TopEntities {
    pub processes: Vec<EntityEntry>,
    pub destinations: Vec<EntityEntry>,
    pub registry: Vec<EntityEntry>,
    pub files: Vec<EntityEntry>,
}

/// A signal row normalized for the brief endpoint
#[derive(Debug, Clone, Serialize)]
pub struct NotableFinding {
    pub signal_id: String,
    pub playbook_id: String,
    pub severity: String,
    pub ts: i64,
    pub ts_start: i64,
    pub ts_end: i64,
    pub evidence_refs_count: usize,
    pub evidence_ptrs: Vec<serde_json::Value>,
}

/// Fact type count for unmapped activity
#[derive(Debug, Clone, Serialize)]
pub struct FactTypeCount {
    pub fact_type: String,
    pub count: i64,
}

// ============================================================================
// Database Connection
// ============================================================================

/// Open a workbench.db connection from run directory
pub fn open_workbench_db(run_dir: &Path) -> SqlResult<Connection> {
    let db_path = run_dir.join("workbench.db");
    Connection::open(&db_path)
}

/// Check if workbench.db exists in run directory
pub fn workbench_db_exists(run_dir: &Path) -> bool {
    run_dir.join("workbench.db").exists()
}

// ============================================================================
// Totals Queries
// ============================================================================

/// Query totals from coverage_rollup with fallback to segments table
/// 
/// Preserves exact behavior:
/// - Try coverage_rollup SUM(event_count) first
/// - If 0 or missing, fallback to segments SUM(records)
/// - Same for facts: coverage_rollup SUM(fact_count) or segments SUM(facts)
pub fn query_totals(conn: &Connection) -> BriefTotals {
    let events_total = query_events_total(conn);
    let facts_total = query_facts_total(conn);
    let signals_fired = query_signals_count(conn);
    let segments_count = query_segments_count(conn);
    
    BriefTotals {
        events_total,
        facts_total,
        signals_fired,
        segments_count,
    }
}

fn query_events_total(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COALESCE(SUM(event_count), 0) FROM coverage_rollup WHERE event_count IS NOT NULL",
        [],
        |row| row.get(0),
    )
    .ok()
    .filter(|&v: &i64| v > 0)
    .or_else(|| {
        // Fallback to segments.records if coverage_rollup empty
        conn.query_row("SELECT COALESCE(SUM(records), 0) FROM segments", [], |row| row.get(0)).ok()
    })
    .unwrap_or(0)
}

fn query_facts_total(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COALESCE(SUM(fact_count), 0) FROM coverage_rollup WHERE fact_count IS NOT NULL",
        [],
        |row| row.get(0),
    )
    .ok()
    .filter(|&v: &i64| v > 0)
    .or_else(|| {
        // Fallback to segments.facts if coverage_rollup empty
        conn.query_row("SELECT COALESCE(SUM(facts), 0) FROM segments", [], |row| row.get(0)).ok()
    })
    .unwrap_or(0)
}

fn query_signals_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM signals", [], |row| row.get(0))
        .unwrap_or(0)
}

fn query_segments_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM segments", [], |row| row.get(0))
        .unwrap_or(0)
}

// ============================================================================
// Timeline Queries
// ============================================================================

/// Query timeline buckets from coverage_rollup
/// 
/// Returns per-minute event counts, grouped by ts_minute.
pub fn query_timeline_buckets(conn: &Connection) -> Vec<TimelineBucket> {
    conn.prepare(
        r#"SELECT 
            ts_minute * 60000 as start_ts,
            (ts_minute + 1) * 60000 as end_ts,
            SUM(event_count) as count
           FROM coverage_rollup
           WHERE event_count > 0
           GROUP BY ts_minute
           ORDER BY ts_minute"#
    )
    .and_then(|mut stmt| {
        stmt.query_map([], |row| {
            Ok(TimelineBucket {
                start_ts: row.get(0)?,
                end_ts: row.get(1)?,
                count: row.get(2)?,
            })
        }).map(|rows| rows.filter_map(|r| r.ok()).collect())
    })
    .unwrap_or_default()
}

// ============================================================================
// Entity Queries
// ============================================================================

/// Check if entity_rollup table exists
fn has_entity_rollup_table(conn: &Connection) -> bool {
    conn.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='entity_rollup'")
        .and_then(|mut stmt| stmt.query_row([], |_| Ok(true)))
        .unwrap_or(false)
}

/// Query top entities, preferring entity_rollup with facts_sample fallback
pub fn query_top_entities(conn: &Connection) -> TopEntities {
    if has_entity_rollup_table(conn) {
        query_top_entities_from_rollup(conn)
    } else {
        query_top_entities_from_facts_sample(conn)
    }
}

fn query_top_entities_from_rollup(conn: &Connection) -> TopEntities {
    TopEntities {
        processes: query_entity_rollup_category(conn, &["process", "proc", "Exec"]),
        destinations: query_entity_rollup_category(conn, &["network", "destination", "OutboundConnect", "DnsQuery"]),
        registry: query_entity_rollup_category(conn, &["registry", "RegistryMod", "RegistrySet"]),
        files: query_entity_rollup_category(conn, &["file", "FileCreate", "FileWrite", "FileMod"]),
    }
}

fn query_entity_rollup_category(conn: &Connection, entity_types: &[&str]) -> Vec<EntityEntry> {
    let placeholders: String = entity_types.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        r#"SELECT entity_key, fact_count, first_ts, last_ts 
           FROM entity_rollup 
           WHERE entity_type IN ({})
           ORDER BY fact_count DESC LIMIT 10"#,
        placeholders
    );
    
    conn.prepare(&sql)
        .and_then(|mut stmt| {
            let params: Vec<&dyn rusqlite::ToSql> = entity_types
                .iter()
                .map(|s| s as &dyn rusqlite::ToSql)
                .collect();
            stmt.query_map(params.as_slice(), |row| {
                Ok(EntityEntry {
                    entity: row.get(0)?,
                    count: row.get(1)?,
                    first_ts: row.get(2)?,
                    last_ts: row.get(3)?,
                    note: None,
                })
            }).map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default()
}

fn query_top_entities_from_facts_sample(conn: &Connection) -> TopEntities {
    TopEntities {
        processes: query_facts_sample_category(conn, &["Exec", "ProcessCreate", "ProcessStart"]),
        destinations: query_facts_sample_category(conn, &["OutboundConnect", "NetworkConnect", "DnsQuery"]),
        registry: query_facts_sample_category(conn, &["RegistryMod", "RegistryChange", "RegistrySet"]),
        files: query_facts_sample_category(conn, &["FileCreate", "FileWrite", "FileDelete", "FileMod"]),
    }
}

fn query_facts_sample_category(conn: &Connection, fact_types: &[&str]) -> Vec<EntityEntry> {
    let placeholders: String = fact_types.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        r#"SELECT entity_key, COUNT(*) as cnt, MIN(ts) as first_ts, MAX(ts) as last_ts
           FROM facts_sample 
           WHERE fact_type IN ({})
             AND entity_key IS NOT NULL AND entity_key != ''
           GROUP BY entity_key ORDER BY cnt DESC LIMIT 10"#,
        placeholders
    );
    
    conn.prepare(&sql)
        .and_then(|mut stmt| {
            let params: Vec<&dyn rusqlite::ToSql> = fact_types
                .iter()
                .map(|s| s as &dyn rusqlite::ToSql)
                .collect();
            stmt.query_map(params.as_slice(), |row| {
                Ok(EntityEntry {
                    entity: row.get(0)?,
                    count: row.get(1)?,
                    first_ts: row.get(2)?,
                    last_ts: row.get(3)?,
                    note: Some("sampled".to_string()),
                })
            }).map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default()
}

// ============================================================================
// Signals Queries
// ============================================================================

/// Query notable findings from signals table
/// 
/// Returns up to 20 most recent signals with parsed evidence_ptrs.
/// Strips "playbook:" prefix from signal_type per Constraint 5.
pub fn query_notable_findings(conn: &Connection) -> Vec<NotableFinding> {
    conn.prepare(
        r#"SELECT 
            signal_id, signal_type, severity, ts, ts_start, ts_end, evidence_ptrs
           FROM signals 
           ORDER BY ts DESC 
           LIMIT 20"#
    )
    .and_then(|mut stmt| {
        stmt.query_map([], |row| {
            let signal_type: String = row.get(1)?;
            let playbook_id = strip_playbook_prefix(&signal_type).to_string();
            
            let evidence_ptrs_json: Option<String> = row.get(6)?;
            let evidence_ptrs = parse_evidence_ptrs_raw(evidence_ptrs_json.as_deref());
            let evidence_refs_count = evidence_ptrs.len();
            
            Ok(NotableFinding {
                signal_id: row.get(0)?,
                playbook_id,
                severity: row.get(2)?,
                ts: row.get(3)?,
                ts_start: row.get(4)?,
                ts_end: row.get(5)?,
                evidence_refs_count,
                evidence_ptrs,
            })
        }).map(|rows| rows.filter_map(|r| r.ok()).collect())
    })
    .unwrap_or_default()
}

/// Query signals for episode clustering
/// 
/// Returns all signals ordered by ts_start for the clustering algorithm.
pub fn query_signals_for_clustering(conn: &Connection) -> Vec<SignalForClustering> {
    conn.prepare(
        r#"SELECT 
            signal_id, signal_type, ts_start, ts_end, proc_key, evidence_ptrs
           FROM signals 
           ORDER BY ts_start"#
    )
    .and_then(|mut stmt| {
        stmt.query_map([], |row| {
            Ok(SignalForClustering {
                signal_id: row.get(0)?,
                signal_type: row.get(1)?,
                ts_start: row.get(2)?,
                ts_end: row.get(3)?,
                proc_key: row.get(4)?,
                evidence_ptrs_json: row.get(5)?,
            })
        }).map(|rows| rows.filter_map(|r| r.ok()).collect())
    })
    .unwrap_or_default()
}

// ============================================================================
// Unmapped Activity Queries
// ============================================================================

/// Query fact type counts from coverage_rollup
/// 
/// Returns all fact types with their aggregated counts.
/// The caller can filter to determine which are "unmapped".
pub fn query_fact_type_counts(conn: &Connection) -> Vec<FactTypeCount> {
    conn.prepare(
        r#"SELECT fact_type, SUM(fact_count) as total_count
           FROM coverage_rollup
           WHERE fact_type IS NOT NULL AND fact_count > 0
           GROUP BY fact_type
           ORDER BY total_count DESC"#
    )
    .and_then(|mut stmt| {
        stmt.query_map([], |row| {
            Ok(FactTypeCount {
                fact_type: row.get(0)?,
                count: row.get(1)?,
            })
        }).map(|rows| rows.filter_map(|r| r.ok()).collect())
    })
    .unwrap_or_default()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        
        // Create minimal schema
        conn.execute_batch(r#"
            CREATE TABLE coverage_rollup (
                ts_minute INTEGER,
                event_count INTEGER,
                fact_count INTEGER,
                fact_type TEXT
            );
            
            CREATE TABLE segments (
                segment_id TEXT,
                records INTEGER,
                facts INTEGER
            );
            
            CREATE TABLE signals (
                signal_id TEXT,
                signal_type TEXT,
                severity TEXT,
                ts INTEGER,
                ts_start INTEGER,
                ts_end INTEGER,
                proc_key TEXT,
                evidence_ptrs TEXT
            );
            
            CREATE TABLE facts_sample (
                fact_type TEXT,
                entity_key TEXT,
                ts INTEGER
            );
        "#).unwrap();
        
        conn
    }

    #[test]
    fn test_query_totals_empty() {
        let conn = setup_test_db();
        let totals = query_totals(&conn);
        assert_eq!(totals.events_total, 0);
        assert_eq!(totals.facts_total, 0);
        assert_eq!(totals.signals_fired, 0);
        assert_eq!(totals.segments_count, 0);
    }

    #[test]
    fn test_query_totals_with_data() {
        let conn = setup_test_db();
        
        conn.execute("INSERT INTO coverage_rollup (ts_minute, event_count, fact_count) VALUES (1, 100, 50)", []).unwrap();
        conn.execute("INSERT INTO coverage_rollup (ts_minute, event_count, fact_count) VALUES (2, 200, 75)", []).unwrap();
        conn.execute("INSERT INTO segments (segment_id, records, facts) VALUES ('seg1', 10, 5)", []).unwrap();
        conn.execute("INSERT INTO signals (signal_id, signal_type, severity, ts, ts_start, ts_end) VALUES ('sig1', 'playbook:test', 'high', 1000, 1000, 2000)", []).unwrap();
        
        let totals = query_totals(&conn);
        assert_eq!(totals.events_total, 300);
        assert_eq!(totals.facts_total, 125);
        assert_eq!(totals.signals_fired, 1);
        assert_eq!(totals.segments_count, 1);
    }

    #[test]
    fn test_query_totals_fallback_to_segments() {
        let conn = setup_test_db();
        
        // No coverage_rollup data, should fallback to segments
        conn.execute("INSERT INTO segments (segment_id, records, facts) VALUES ('seg1', 100, 50)", []).unwrap();
        conn.execute("INSERT INTO segments (segment_id, records, facts) VALUES ('seg2', 200, 75)", []).unwrap();
        
        let totals = query_totals(&conn);
        assert_eq!(totals.events_total, 300);
        assert_eq!(totals.facts_total, 125);
    }

    #[test]
    fn test_query_timeline_buckets() {
        let conn = setup_test_db();
        
        conn.execute("INSERT INTO coverage_rollup (ts_minute, event_count, fact_count) VALUES (100, 50, 25)", []).unwrap();
        conn.execute("INSERT INTO coverage_rollup (ts_minute, event_count, fact_count) VALUES (101, 30, 15)", []).unwrap();
        
        let buckets = query_timeline_buckets(&conn);
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].start_ts, 100 * 60000);
        assert_eq!(buckets[0].count, 50);
    }

    #[test]
    fn test_query_notable_findings_strips_prefix() {
        let conn = setup_test_db();
        
        conn.execute(
            "INSERT INTO signals (signal_id, signal_type, severity, ts, ts_start, ts_end, evidence_ptrs) VALUES ('sig1', 'playbook:persistence', 'high', 1000, 1000, 2000, '[{\"seg\":\"s1\"}]')",
            []
        ).unwrap();
        
        let findings = query_notable_findings(&conn);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].signal_id, "sig1");
        assert_eq!(findings[0].playbook_id, "persistence"); // stripped
        assert_eq!(findings[0].evidence_refs_count, 1);
    }

    #[test]
    fn test_query_signals_for_clustering() {
        let conn = setup_test_db();
        
        conn.execute(
            "INSERT INTO signals (signal_id, signal_type, ts_start, ts_end, proc_key) VALUES ('sig1', 'playbook:p1', 1000, 2000, 'proc1')",
            []
        ).unwrap();
        conn.execute(
            "INSERT INTO signals (signal_id, signal_type, ts_start, ts_end, proc_key) VALUES ('sig2', 'playbook:p2', 500, 1500, 'proc2')",
            []
        ).unwrap();
        
        let signals = query_signals_for_clustering(&conn);
        assert_eq!(signals.len(), 2);
        // Should be ordered by ts_start
        assert_eq!(signals[0].signal_id, "sig2"); // ts_start=500
        assert_eq!(signals[1].signal_id, "sig1"); // ts_start=1000
    }

    #[test]
    fn test_query_fact_type_counts() {
        let conn = setup_test_db();
        
        conn.execute("INSERT INTO coverage_rollup (fact_type, fact_count) VALUES ('Exec', 100)", []).unwrap();
        conn.execute("INSERT INTO coverage_rollup (fact_type, fact_count) VALUES ('Exec', 50)", []).unwrap();
        conn.execute("INSERT INTO coverage_rollup (fact_type, fact_count) VALUES ('FileCreate', 30)", []).unwrap();
        
        let counts = query_fact_type_counts(&conn);
        assert_eq!(counts.len(), 2);
        assert_eq!(counts[0].fact_type, "Exec");
        assert_eq!(counts[0].count, 150);
    }
}

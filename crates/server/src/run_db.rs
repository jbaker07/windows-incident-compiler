//! Per-Run Database Access
//!
//! Provides functions to query signals and explanations from per-run workbench.db files.
//! This is the source of truth for run artifacts produced by locald.
//!
//! Stage 3 Fix: edr-server now queries the per-run DB for signals/explanations,
//! not the server's master DB.

use rusqlite::{params, Connection};
use std::path::PathBuf;

use crate::db::StoredSignal;

/// Error type for per-run DB operations
#[derive(Debug)]
pub enum RunDbError {
    RunNotFound(String),
    MissingRunDir(String),
    DbNotFound(PathBuf),
    DbError(String),
}

impl std::fmt::Display for RunDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunDbError::RunNotFound(id) => write!(f, "Run '{}' not found", id),
            RunDbError::MissingRunDir(id) => write!(f, "Run '{}' has no run_dir", id),
            RunDbError::DbNotFound(path) => write!(f, "Per-run database not found: {}", path.display()),
            RunDbError::DbError(e) => write!(f, "Database error: {}", e),
        }
    }
}

impl std::error::Error for RunDbError {}

/// Open the per-run workbench.db for a given run_dir
pub fn open_run_db(run_dir: &str) -> Result<Connection, RunDbError> {
    let path = PathBuf::from(run_dir).join("workbench.db");
    if !path.exists() {
        return Err(RunDbError::DbNotFound(path));
    }
    Connection::open(&path).map_err(|e| RunDbError::DbError(e.to_string()))
}

/// Query signals from a per-run database
pub fn query_signals_from_run_db(
    conn: &Connection,
    host: Option<&str>,
    signal_type: Option<&str>,
    severity: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<Vec<StoredSignal>, RunDbError> {
    let mut sql = String::from(
        "SELECT signal_id, run_id, signal_type, severity, host, ts, ts_start, ts_end,
                proc_key, file_key, identity_key, 
                COALESCE(detector_id, 'unknown') as detector_id,
                COALESCE(detector_version, '0.0.0') as detector_version,
                COALESCE(source_sensor, 'unknown') as source_sensor,
                metadata, evidence_ptrs, dropped_evidence_count
         FROM signals WHERE 1=1"
    );

    let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(h) = host {
        sql.push_str(" AND host = ?");
        params_vec.push(Box::new(h.to_string()));
    }
    if let Some(t) = signal_type {
        sql.push_str(" AND signal_type = ?");
        params_vec.push(Box::new(t.to_string()));
    }
    if let Some(s) = severity {
        sql.push_str(" AND severity = ?");
        params_vec.push(Box::new(s.to_string()));
    }

    sql.push_str(" ORDER BY ts DESC LIMIT ? OFFSET ?");
    params_vec.push(Box::new(limit as i64));
    params_vec.push(Box::new(offset as i64));

    let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

    let mut stmt = conn.prepare(&sql).map_err(|e| RunDbError::DbError(e.to_string()))?;
    let mut rows = stmt.query(params_refs.as_slice()).map_err(|e| RunDbError::DbError(e.to_string()))?;

    let mut signals = Vec::new();
    while let Ok(Some(row)) = rows.next() {
        if let Ok(signal) = row_to_signal(row) {
            signals.push(signal);
        }
    }
    Ok(signals)
}

/// Get a single signal from a per-run database
pub fn get_signal_from_run_db(conn: &Connection, signal_id: &str) -> Result<Option<StoredSignal>, RunDbError> {
    let mut stmt = conn.prepare(
        "SELECT signal_id, run_id, signal_type, severity, host, ts, ts_start, ts_end,
                proc_key, file_key, identity_key,
                COALESCE(detector_id, 'unknown') as detector_id,
                COALESCE(detector_version, '0.0.0') as detector_version,
                COALESCE(source_sensor, 'unknown') as source_sensor,
                metadata, evidence_ptrs, dropped_evidence_count
         FROM signals WHERE signal_id = ?1"
    ).map_err(|e| RunDbError::DbError(e.to_string()))?;

    let mut rows = stmt.query(params![signal_id]).map_err(|e| RunDbError::DbError(e.to_string()))?;
    
    if let Ok(Some(row)) = rows.next() {
        Ok(Some(row_to_signal(row).map_err(|e| RunDbError::DbError(e.to_string()))?))
    } else {
        Ok(None)
    }
}

/// Get signal explanation from a per-run database
pub fn get_explanation_from_run_db(
    conn: &Connection,
    signal_id: &str,
) -> Result<Option<serde_json::Value>, RunDbError> {
    // Check if signal_explanations table exists
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='signal_explanations'",
            [],
            |row| row.get::<_, i32>(0),
        )
        .map(|c| c > 0)
        .unwrap_or(false);
    
    if !table_exists {
        return Ok(None);
    }

    let mut stmt = conn
        .prepare("SELECT explanation_json FROM signal_explanations WHERE signal_id = ?1")
        .map_err(|e| RunDbError::DbError(e.to_string()))?;

    let mut rows = stmt.query(params![signal_id]).map_err(|e| RunDbError::DbError(e.to_string()))?;

    if let Ok(Some(row)) = rows.next() {
        let json_str: String = row.get(0).map_err(|e| RunDbError::DbError(e.to_string()))?;
        match serde_json::from_str(&json_str) {
            Ok(json) => Ok(Some(json)),
            Err(e) => {
                tracing::warn!("Failed to parse explanation JSON for {}: {}", signal_id, e);
                Ok(Some(serde_json::json!({
                    "error": "Failed to parse stored explanation",
                    "raw": json_str
                })))
            }
        }
    } else {
        Ok(None)
    }
}

/// Count signals in a per-run database
pub fn count_signals_in_run_db(conn: &Connection) -> Result<u64, RunDbError> {
    conn.query_row("SELECT COUNT(*) FROM signals", [], |row| row.get::<_, i64>(0))
        .map(|c| c as u64)
        .map_err(|e| RunDbError::DbError(e.to_string()))
}

/// Helper to convert a row to StoredSignal
fn row_to_signal(row: &rusqlite::Row) -> Result<StoredSignal, rusqlite::Error> {
    let metadata_str: String = row.get(14)?;
    let evidence_str: String = row.get(15)?;

    Ok(StoredSignal {
        signal_id: row.get(0)?,
        run_id: row.get(1)?,
        signal_type: row.get(2)?,
        severity: row.get(3)?,
        host: row.get(4)?,
        ts: row.get(5)?,
        ts_start: row.get(6)?,
        ts_end: row.get(7)?,
        proc_key: row.get(8)?,
        file_key: row.get(9)?,
        identity_key: row.get(10)?,
        detector_id: row.get(11)?,
        detector_version: row.get(12)?,
        source_sensor: row.get(13)?,
        metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
        evidence_ptrs: serde_json::from_str(&evidence_str).unwrap_or_default(),
        dropped_evidence_count: row.get(16)?,
    })
}

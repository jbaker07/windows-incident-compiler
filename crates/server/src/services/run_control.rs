//! Run Control Service
//!
//! Handles run lifecycle: start, stop, status, metrics, listing, and CRUD operations.
//! All business logic for run management lives here.

use crate::db::{Database, RunRecord};
use crate::supervisor::StartConfig;
use std::path::{Path, PathBuf};

// ============================================================================
// Run DB Error Types (for deterministic error handling)
// ============================================================================

/// Error codes for run-scoped database operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunDbErrorCode {
    /// Run ID not found in runs table
    RunNotFound,
    /// Run exists but run_dir column is NULL
    MissingRunDir,
    /// run_dir exists but workbench.db not found
    MissingDb,
    /// Database open/query failed
    DbError,
}

impl RunDbErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunDbErrorCode::RunNotFound => "RUN_NOT_FOUND",
            RunDbErrorCode::MissingRunDir => "MISSING_RUN_DIR",
            RunDbErrorCode::MissingDb => "MISSING_DB",
            RunDbErrorCode::DbError => "DB_ERROR",
        }
    }
}

/// Error for run-scoped database operations
#[derive(Debug)]
pub struct RunDbError {
    pub code: RunDbErrorCode,
    pub message: String,
    pub run_id: String,
    pub expected_path: Option<String>,
}

impl RunDbError {
    pub fn run_not_found(run_id: &str) -> Self {
        Self {
            code: RunDbErrorCode::RunNotFound,
            message: format!("Run '{}' not found in database", run_id),
            run_id: run_id.to_string(),
            expected_path: None,
        }
    }

    pub fn missing_run_dir(run_id: &str) -> Self {
        Self {
            code: RunDbErrorCode::MissingRunDir,
            message: format!("Run '{}' has no run_dir (NULL in database)", run_id),
            run_id: run_id.to_string(),
            expected_path: None,
        }
    }

    pub fn missing_db(run_id: &str, expected_path: &Path) -> Self {
        Self {
            code: RunDbErrorCode::MissingDb,
            message: format!("workbench.db not found for run '{}'", run_id),
            run_id: run_id.to_string(),
            expected_path: Some(expected_path.display().to_string()),
        }
    }

    pub fn db_error(run_id: &str, error: &str) -> Self {
        Self {
            code: RunDbErrorCode::DbError,
            message: format!("Database error for run '{}': {}", run_id, error),
            run_id: run_id.to_string(),
            expected_path: None,
        }
    }

    /// Convert to JSON response
    pub fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "success": false,
            "code": self.code.as_str(),
            "error": self.message,
            "run_id": self.run_id
        });
        if let Some(ref path) = self.expected_path {
            obj["expected_path"] = serde_json::Value::String(path.clone());
        }
        obj
    }
}

impl std::fmt::Display for RunDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for RunDbError {}

/// Result of opening a run database
pub struct RunDbHandle {
    pub conn: rusqlite::Connection,
    pub run_dir: PathBuf,
    pub db_path: PathBuf,
    pub run_record: RunRecord,
}

// ============================================================================
// Run DB Resolution (CANONICAL HELPER)
// ============================================================================

/// Open the per-run workbench.db using the runs table as source of truth.
///
/// This is the CANONICAL way to access run-scoped data. It:
/// 1. Looks up the run in the runs table
/// 2. Gets the run_dir from the record (no path construction from run_id)
/// 3. Opens {run_dir}/workbench.db with WAL mode
/// 4. Returns deterministic error codes if any step fails
///
/// NO SILENT FALLBACKS. Callers must handle errors explicitly.
pub fn open_run_db(db: &Database, run_id: &str) -> Result<RunDbHandle, RunDbError> {
    // Step 1: Look up run in database
    let run_record = db
        .get_run(run_id)
        .map_err(|e| RunDbError::db_error(run_id, &e.to_string()))?
        .ok_or_else(|| RunDbError::run_not_found(run_id))?;

    // Step 2: Get run_dir from record (MUST be non-NULL)
    let run_dir_str = run_record
        .run_dir
        .as_ref()
        .ok_or_else(|| RunDbError::missing_run_dir(run_id))?;

    let run_dir = PathBuf::from(run_dir_str);

    // Step 3: Check run_dir exists (filesystem validation)
    if !run_dir.exists() {
        return Err(RunDbError::missing_run_dir(run_id));
    }

    // Step 4: Build db path and verify it exists
    let db_path = run_dir.join("workbench.db");
    if !db_path.exists() {
        return Err(RunDbError::missing_db(run_id, &db_path));
    }

    // Step 5: Open with WAL mode
    let conn = open_db_with_wal(&db_path)
        .map_err(|e| RunDbError::db_error(run_id, &e.to_string()))?;

    Ok(RunDbHandle {
        conn,
        run_dir,
        db_path,
        run_record,
    })
}

/// Resolve run_dir from runs table (without opening DB).
/// Use this when you only need the path, not a database connection.
pub fn resolve_run_dir(db: &Database, run_id: &str) -> Result<(PathBuf, RunRecord), RunDbError> {
    // Step 1: Look up run in database
    let run_record = db
        .get_run(run_id)
        .map_err(|e| RunDbError::db_error(run_id, &e.to_string()))?
        .ok_or_else(|| RunDbError::run_not_found(run_id))?;

    // Step 2: Get run_dir from record
    let run_dir_str = run_record
        .run_dir
        .as_ref()
        .ok_or_else(|| RunDbError::missing_run_dir(run_id))?;

    let run_dir = PathBuf::from(run_dir_str);

    // Step 3: Verify it exists
    if !run_dir.exists() {
        return Err(RunDbError::missing_run_dir(run_id));
    }

    Ok((run_dir, run_record))
}

/// Fallback: Open run DB by constructing path from data_dir + run_id.
/// Use ONLY for handlers where run may not be in DB yet (e.g., filesystem scan).
/// Prefer `open_run_db()` for normal operations.
pub fn open_run_db_by_path(data_dir: &Path, run_id: &str) -> Result<(rusqlite::Connection, PathBuf), RunDbError> {
    let run_dir = data_dir.join("runs").join(run_id);
    
    if !run_dir.exists() {
        return Err(RunDbError::run_not_found(run_id));
    }
    
    let db_path = run_dir.join("workbench.db");
    if !db_path.exists() {
        return Err(RunDbError::missing_db(run_id, &db_path));
    }
    
    let conn = open_db_with_wal(&db_path)
        .map_err(|e| RunDbError::db_error(run_id, &e.to_string()))?;
    
    Ok((conn, run_dir))
}

// ============================================================================
// Run Metadata Helpers
// ============================================================================

/// Read run metadata from run_meta.json
/// Returns (started_at, stopped_at, status)
pub fn read_run_meta(
    meta_path: &Path,
    run_id: &str,
) -> (
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
    String,
) {
    if let Ok(contents) = std::fs::read_to_string(meta_path) {
        if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&contents) {
            let started_at = meta
                .get("started_at")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));

            let stopped_at = meta
                .get("stopped_at")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));

            let status = meta
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            return (started_at, stopped_at, status);
        }
    }

    // Try to parse run_id as timestamp for fallback
    let started_at = run_id
        .strip_prefix("run_")
        .and_then(|ts_str| ts_str.parse::<i64>().ok())
        .map(|ts| {
            chrono::DateTime::from_timestamp(ts, 0)
                .unwrap_or_else(|| chrono::Utc::now())
        });

    (started_at, None, "unknown".to_string())
}

/// Read run statistics from workbench.db
/// Returns (events, segments, facts, signals, earliest_ts, latest_ts, db_path)
pub fn read_run_stats(
    db_path: &Path,
) -> (u64, u32, u64, usize, i64, i64, Option<std::path::PathBuf>) {
    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return (0, 0, 0, 0, 0, 0, None),
    };

    // Get segments count and bytes from segments table
    let (segments, _bytes): (u32, u64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM segments",
            [],
            |row| Ok((row.get::<_, i64>(0)? as u32, row.get::<_, i64>(1)? as u64)),
        )
        .unwrap_or((0, 0));

    // Get facts from coverage_rollup
    let facts: u64 = conn
        .query_row(
            "SELECT COALESCE(SUM(fact_count), 0) FROM coverage_rollup",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64;

    // Get signal count
    let signals: usize = conn
        .query_row("SELECT COUNT(*) FROM signals", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0) as usize;

    // Get time range from signals
    let (earliest_ts, latest_ts): (i64, i64) = conn
        .query_row(
            "SELECT COALESCE(MIN(ts), 0), COALESCE(MAX(ts), 0) FROM signals",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or((0, 0));

    // Get events - try coverage_rollup first, then segments
    let events: u64 = conn
        .query_row(
            "SELECT COALESCE(SUM(event_count), 0) FROM coverage_rollup WHERE event_count IS NOT NULL",
            [],
            |row| row.get::<_, i64>(0),
        )
        .ok()
        .filter(|&v| v > 0)
        .or_else(|| {
            conn.query_row(
                "SELECT COALESCE(SUM(records), 0) FROM segments",
                [],
                |row| row.get::<_, i64>(0),
            )
            .ok()
        })
        .unwrap_or(0) as u64;

    (
        events,
        segments,
        facts,
        signals,
        earliest_ts,
        latest_ts,
        Some(db_path.to_path_buf()),
    )
}

// ============================================================================
// Database Helpers
// ============================================================================

/// Open database with WAL pragmas for concurrent read/write access
pub fn open_db_with_wal(db_path: &Path) -> Result<rusqlite::Connection, rusqlite::Error> {
    let conn = rusqlite::Connection::open(db_path)?;

    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;
         PRAGMA temp_store=MEMORY;",
    )?;

    Ok(conn)
}

/// Count signals in database
#[allow(dead_code)]
pub fn count_signals_in_db(db_path: &Path) -> u64 {
    if !db_path.exists() {
        return 0;
    }

    match open_db_with_wal(db_path) {
        Ok(conn) => conn
            .query_row("SELECT COUNT(*) FROM signals", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as u64,
        Err(_) => 0,
    }
}

/// Query facts from coverage_rollup table
#[allow(dead_code)]
pub fn query_facts_from_db(db_path: &Path) -> Option<u64> {
    if !db_path.exists() {
        return None;
    }

    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return None,
    };

    conn.query_row("SELECT SUM(fact_count) FROM coverage_rollup", [], |row| {
        row.get::<_, Option<i64>>(0)
    })
    .ok()
    .flatten()
    .map(|v| v.max(0) as u64)
}

/// Query events from DB - NO ESTIMATION
#[allow(dead_code)]
pub fn query_events_from_db(db_path: &Path) -> Option<u64> {
    if !db_path.exists() {
        return None;
    }

    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return None,
    };

    // Try coverage_rollup first
    let from_coverage: Option<i64> = conn
        .query_row(
            "SELECT SUM(event_count) FROM coverage_rollup WHERE event_count IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .ok()
        .flatten();

    if let Some(count) = from_coverage {
        if count > 0 {
            return Some(count as u64);
        }
    }

    // Fallback: segments table
    let from_segments: Option<i64> = conn
        .query_row("SELECT SUM(records) FROM segments", [], |row| row.get(0))
        .ok()
        .flatten();

    if let Some(count) = from_segments {
        if count > 0 {
            return Some(count as u64);
        }
    }

    None
}

// ============================================================================
// Playbooks Discovery
// ============================================================================

/// Discover playbooks directory using fallback chain
/// Returns (playbooks_dir, source, reason)
pub fn discover_playbooks_dir() -> (Option<std::path::PathBuf>, &'static str, Option<String>) {
    // Priority 1: Environment variable
    if let Ok(path) = std::env::var("EDR_PLAYBOOKS_DIR") {
        let pb = std::path::PathBuf::from(&path);
        if pb.exists() && pb.is_dir() {
            return (Some(pb), "env", None);
        }
        return (
            None,
            "env_invalid",
            Some(format!("EDR_PLAYBOOKS_DIR='{}' does not exist", path)),
        );
    }

    // Priority 2: Relative to exe
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let relative = exe_dir.join("playbooks").join("windows");
            if relative.exists() && relative.is_dir() {
                return (Some(relative), "exe_relative", None);
            }
        }
    }

    // Priority 3: Well-known locations
    let well_known = [
        std::path::PathBuf::from("playbooks/windows"),
        std::path::PathBuf::from("../playbooks/windows"),
        std::path::PathBuf::from("../../playbooks/windows"),
    ];

    for path in &well_known {
        if path.exists() && path.is_dir() {
            return (Some(path.clone()), "well_known", None);
        }
    }

    (
        None,
        "not_found",
        Some("No playbooks directory found".to_string()),
    )
}

// ============================================================================
// Run CRUD Operations
// ============================================================================

/// Build start configuration from request
pub fn build_start_config(
    run_label: Option<String>,
    profile: Option<String>,
    duration_seconds: Option<u64>,
    playbook_selection: Option<super::types::PlaybookSelection>,
) -> StartConfig {
    let playbooks_disabled = std::env::var("LOCINT_PLAYBOOKS")
        .map(|v| v.to_lowercase() == "off" || v == "0" || v.to_lowercase() == "false")
        .unwrap_or(false);

    let playbooks_dir = if playbooks_disabled {
        None
    } else {
        let (pb_dir, _, _) = discover_playbooks_dir();
        pb_dir
    };
    
    // Process playbook selection
    let (selected_playbooks, selection_mode, selection_preset) = if let Some(sel) = playbook_selection {
        let mode = sel.mode.clone();
        let preset = sel.preset.clone();
        
        // If explicit playbooks provided, use them
        // Otherwise, resolve preset to playbook list
        let playbooks = if !sel.selected_playbooks.is_empty() {
            Some(sel.selected_playbooks)
        } else if let Some(ref preset_id) = preset {
            // Resolve preset - this will be done at runtime by locald based on requires metadata
            // We just pass the preset name, locald handles resolution
            None
        } else {
            None
        };
        
        (playbooks, Some(mode), preset)
    } else {
        // Default: general preset (system-changes focused, no special requirements)
        (None, Some("preset".to_string()), Some("general".to_string()))
    };

    StartConfig {
        profile,
        duration_seconds,
        run_label,
        playbooks_dir,
        selected_playbooks,
        selection_mode,
        selection_preset,
    }
}

/// Create a basic run record for insertion
pub fn create_run_record(
    run_id: &str,
    name: Option<String>,
    run_dir: &Path,
) -> RunRecord {
    let now = chrono::Utc::now();
    RunRecord {
        run_id: run_id.to_string(),
        name,
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
    }
}

/// Count segments in a directory
#[allow(dead_code)]
pub fn count_segments(dir: &Path) -> (u32, u64) {
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
// Legacy Cleanup
// ============================================================================

/// Legacy fallback for stopping processes when supervisor doesn't have tracking
#[cfg(target_os = "windows")]
pub async fn legacy_stop_processes() {
    use std::os::windows::process::CommandExt;
    
    let mut cmd1 = std::process::Command::new("taskkill");
    cmd1.creation_flags(0x08000000); // CREATE_NO_WINDOW
    let _ = cmd1
        .args(["/F", "/IM", "capture_windows_rotating.exe"])
        .output();
    
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    
    let mut cmd2 = std::process::Command::new("taskkill");
    cmd2.creation_flags(0x08000000);
    let _ = cmd2.args(["/F", "/IM", "edr-locald.exe"]).output();
}

#[cfg(not(target_os = "windows"))]
pub async fn legacy_stop_processes() {
    // No-op on non-Windows
}

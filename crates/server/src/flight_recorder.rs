//! Flight Recorder: Always-on structured instrumentation for deterministic debugging
//!
//! PURPOSE: When something "doesn't work," answer in <1 minute:
//! - Which instance is the UI talking to (port, pid, elevation)?
//! - What is the authoritative active run_id/run_dir/phase?
//! - Are segments being written?
//! - Is locald reading segments?
//! - Is locald writing to the same workbench.db that server reads?
//! - Are DB counts changing and visible?
//! - If not, exactly where did the chain break?
//!
//! OUTPUT: {DATA_ROOT}/diagnostics/flight_{pid}_{port}.jsonl
//!
//! INVARIANT: This is instrumentation only. NEVER mutates behavior.

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ============================================================================
// Event Types
// ============================================================================

/// Level of the event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventLevel {
    Info,
    Warn,
    Error,
}

/// Component that generated the event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Component {
    Supervisor,
    Server,
    Locald,
    Capture,
    Ui,
    Db,
}

/// Event type discriminator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Application boot
    Boot,
    /// Run lifecycle
    RunStart,
    RunStop,
    /// Process management
    Spawn,
    SpawnFail,
    ProcessExit,
    /// Phase transitions
    PhaseChange,
    /// Database operations
    DbOpen,
    DbError,
    /// Tick events (periodic checks)
    SegmentsTick,
    FactsTick,
    SignalsTick,
    /// API calls
    ApiCall,
    ApiError,
    /// Instance management
    InstanceLock,
    InstanceConflict,
    /// Finalization
    Finalize,
    /// Readiness gates
    ReadinessCheck,
    ReadinessTimeout,
}

/// A single flight recorder event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlightEvent {
    /// Timestamp in milliseconds since epoch
    pub ts_ms: i64,
    /// Timestamp as ISO 8601 string
    pub ts_iso: String,
    /// Event level
    pub level: EventLevel,
    /// Component that generated the event
    pub component: Component,
    /// Event kind
    pub event: EventKind,
    /// Monotonic sequence number
    pub seq: u64,
    /// Event-specific fields
    pub fields: serde_json::Value,
}

// ============================================================================
// Boot Info (captured at startup)
// ============================================================================

/// Identity of the running instance (captured at boot)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceIdentity {
    pub pid: u32,
    pub port: u16,
    pub is_admin: bool,
    pub exe_path: String,
    pub api_base: String,
    pub ui_origin: String,
    pub data_dir: String,
    pub started_at: String,
    pub version: String,
}

// ============================================================================
// Flight Recorder
// ============================================================================

/// The flight recorder: writes events to JSONL file and maintains in-memory ring buffer
pub struct FlightRecorder {
    /// Path to the JSONL file
    file_path: PathBuf,
    /// File writer (lazily opened)
    writer: RwLock<Option<BufWriter<File>>>,
    /// In-memory ring buffer of recent events (for /api/meta/dataflow_snapshot)
    recent_events: RwLock<VecDeque<FlightEvent>>,
    /// Maximum events to keep in memory
    max_recent: usize,
    /// Monotonic sequence counter
    seq_counter: AtomicU64,
    /// Instance identity
    identity: RwLock<Option<InstanceIdentity>>,
}

impl FlightRecorder {
    /// Create a new flight recorder
    /// 
    /// File path: {data_dir}/diagnostics/flight_{pid}_{port}.jsonl
    pub fn new(data_dir: &std::path::Path, pid: u32, port: u16) -> Self {
        let diagnostics_dir = data_dir.join("diagnostics");
        let _ = std::fs::create_dir_all(&diagnostics_dir);
        
        let file_path = diagnostics_dir.join(format!("flight_{}_{}.jsonl", pid, port));
        
        Self {
            file_path,
            writer: RwLock::new(None),
            recent_events: RwLock::new(VecDeque::with_capacity(100)),
            max_recent: 100,
            seq_counter: AtomicU64::new(0),
            identity: RwLock::new(None),
        }
    }
    
    /// Open the file writer (called once on first event)
    fn ensure_writer(&self) -> bool {
        let mut writer_guard = self.writer.write();
        if writer_guard.is_some() {
            return true;
        }
        
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)
        {
            Ok(file) => {
                *writer_guard = Some(BufWriter::new(file));
                true
            }
            Err(e) => {
                tracing::warn!("FlightRecorder: failed to open {}: {}", self.file_path.display(), e);
                false
            }
        }
    }
    
    /// Record an event
    pub fn record(&self, level: EventLevel, component: Component, event: EventKind, fields: serde_json::Value) {
        let now = Utc::now();
        let seq = self.seq_counter.fetch_add(1, Ordering::SeqCst);
        
        let flight_event = FlightEvent {
            ts_ms: now.timestamp_millis(),
            ts_iso: now.to_rfc3339(),
            level,
            component,
            event,
            seq,
            fields,
        };
        
        // Write to file
        if self.ensure_writer() {
            let mut writer_guard = self.writer.write();
            if let Some(ref mut writer) = *writer_guard {
                if let Ok(line) = serde_json::to_string(&flight_event) {
                    let _ = writeln!(writer, "{}", line.as_str());
                    let _ = writer.flush();
                }
            }
        }
        
        // Add to in-memory ring buffer
        {
            let mut recent = self.recent_events.write();
            if recent.len() >= self.max_recent {
                recent.pop_front();
            }
            recent.push_back(flight_event);
        }
    }
    
    /// Record boot event (must be called first)
    pub fn record_boot(&self, identity: InstanceIdentity) {
        *self.identity.write() = Some(identity.clone());
        
        self.record(
            EventLevel::Info,
            Component::Server,
            EventKind::Boot,
            serde_json::json!({
                "pid": identity.pid,
                "port": identity.port,
                "is_admin": identity.is_admin,
                "exe_path": identity.exe_path,
                "api_base": identity.api_base,
                "ui_origin": identity.ui_origin,
                "data_dir": identity.data_dir,
                "version": identity.version,
            }),
        );
    }
    
    /// Get instance identity
    pub fn get_identity(&self) -> Option<InstanceIdentity> {
        self.identity.read().clone()
    }
    
    /// Get recent events (for dataflow snapshot)
    pub fn recent_events(&self, count: usize) -> Vec<FlightEvent> {
        let recent = self.recent_events.read();
        let start = recent.len().saturating_sub(count);
        recent.iter().skip(start).cloned().collect()
    }
    
    /// Get path to the flight log file
    pub fn file_path(&self) -> &PathBuf {
        &self.file_path
    }
    
    // ========================================================================
    // Convenience methods for common events
    // ========================================================================
    
    /// Record run start
    pub fn record_run_start(
        &self,
        run_id: &str,
        run_dir: &str,
        playbooks_dir: Option<&str>,
        capture_binary: &str,
        locald_binary: &str,
    ) {
        self.record(
            EventLevel::Info,
            Component::Supervisor,
            EventKind::RunStart,
            serde_json::json!({
                "run_id": run_id,
                "run_dir": run_dir,
                "playbooks_dir": playbooks_dir,
                "capture_binary": capture_binary,
                "locald_binary": locald_binary,
            }),
        );
    }
    
    /// Record process spawn
    pub fn record_spawn(
        &self,
        process_kind: &str,
        pid: u32,
        binary_path: &str,
    ) {
        self.record(
            EventLevel::Info,
            Component::Supervisor,
            EventKind::Spawn,
            serde_json::json!({
                "process": process_kind,
                "pid": pid,
                "binary": binary_path,
            }),
        );
    }
    
    /// Record spawn failure
    pub fn record_spawn_fail(
        &self,
        process_kind: &str,
        binary_path: &str,
        error: &str,
        stderr_tail: Option<&str>,
    ) {
        self.record(
            EventLevel::Error,
            Component::Supervisor,
            EventKind::SpawnFail,
            serde_json::json!({
                "process": process_kind,
                "binary": binary_path,
                "error": error,
                "stderr_tail": stderr_tail,
            }),
        );
    }
    
    /// Record process exit
    pub fn record_process_exit(
        &self,
        process_kind: &str,
        pid: u32,
        exit_code: Option<i32>,
        reason: &str,
    ) {
        self.record(
            EventLevel::Info,
            Component::Supervisor,
            EventKind::ProcessExit,
            serde_json::json!({
                "process": process_kind,
                "pid": pid,
                "exit_code": exit_code,
                "reason": reason,
            }),
        );
    }
    
    /// Record phase change
    pub fn record_phase_change(&self, from: &str, to: &str, run_id: &str) {
        self.record(
            EventLevel::Info,
            Component::Supervisor,
            EventKind::PhaseChange,
            serde_json::json!({
                "from": from,
                "to": to,
                "run_id": run_id,
            }),
        );
    }
    
    /// Record DB open
    pub fn record_db_open(
        &self,
        db_path: &str,
        journal_mode: &str,
        busy_timeout: u32,
        readonly: bool,
    ) {
        self.record(
            EventLevel::Info,
            Component::Db,
            EventKind::DbOpen,
            serde_json::json!({
                "db_path": db_path,
                "journal_mode": journal_mode,
                "busy_timeout": busy_timeout,
                "readonly": readonly,
            }),
        );
    }
    
    /// Record DB error
    pub fn record_db_error(&self, db_path: &str, operation: &str, error: &str) {
        self.record(
            EventLevel::Error,
            Component::Db,
            EventKind::DbError,
            serde_json::json!({
                "db_path": db_path,
                "operation": operation,
                "error": error,
            }),
        );
    }
    
    /// Record segment tick
    pub fn record_segments_tick(
        &self,
        run_id: &str,
        segments_count: u32,
        newest_segment_mtime: Option<i64>,
        newest_segment_size: Option<u64>,
    ) {
        self.record(
            EventLevel::Info,
            Component::Supervisor,
            EventKind::SegmentsTick,
            serde_json::json!({
                "run_id": run_id,
                "segments_count": segments_count,
                "newest_mtime_ms": newest_segment_mtime,
                "newest_size_bytes": newest_segment_size,
            }),
        );
    }
    
    /// Record facts tick
    pub fn record_facts_tick(&self, run_id: &str, coverage_count: u64, delta: i64) {
        self.record(
            EventLevel::Info,
            Component::Supervisor,
            EventKind::FactsTick,
            serde_json::json!({
                "run_id": run_id,
                "coverage_count": coverage_count,
                "delta": delta,
            }),
        );
    }
    
    /// Record signals tick
    pub fn record_signals_tick(&self, run_id: &str, signals_count: u64, delta: i64, max_ts: Option<i64>) {
        self.record(
            EventLevel::Info,
            Component::Supervisor,
            EventKind::SignalsTick,
            serde_json::json!({
                "run_id": run_id,
                "signals_count": signals_count,
                "delta": delta,
                "max_ts": max_ts,
            }),
        );
    }
    
    /// Record API call
    pub fn record_api_call(
        &self,
        endpoint: &str,
        method: &str,
        status: u16,
        duration_ms: u64,
        error_code: Option<&str>,
    ) {
        let level = if status >= 400 { EventLevel::Warn } else { EventLevel::Info };
        self.record(
            level,
            Component::Server,
            EventKind::ApiCall,
            serde_json::json!({
                "endpoint": endpoint,
                "method": method,
                "status": status,
                "duration_ms": duration_ms,
                "error_code": error_code,
            }),
        );
    }
    
    /// Record API error
    pub fn record_api_error(&self, endpoint: &str, method: &str, error: &str, code: &str) {
        self.record(
            EventLevel::Error,
            Component::Server,
            EventKind::ApiError,
            serde_json::json!({
                "endpoint": endpoint,
                "method": method,
                "error": error,
                "code": code,
            }),
        );
    }
    
    /// Record instance lock acquired
    pub fn record_instance_lock(&self, lock_file: &str) {
        self.record(
            EventLevel::Info,
            Component::Server,
            EventKind::InstanceLock,
            serde_json::json!({
                "lock_file": lock_file,
                "action": "acquired",
            }),
        );
    }
    
    /// Record instance conflict
    pub fn record_instance_conflict(&self, other_port: u16, other_pid: Option<u32>) {
        self.record(
            EventLevel::Warn,
            Component::Server,
            EventKind::InstanceConflict,
            serde_json::json!({
                "other_port": other_port,
                "other_pid": other_pid,
            }),
        );
    }
    
    /// Record run stop/finalize
    pub fn record_run_stop(
        &self,
        run_id: &str,
        finalized: bool,
        events_total: u64,
        facts: u64,
        signals: u64,
    ) {
        self.record(
            EventLevel::Info,
            Component::Supervisor,
            EventKind::RunStop,
            serde_json::json!({
                "run_id": run_id,
                "finalized": finalized,
                "events_total": events_total,
                "facts_extracted": facts,
                "signals_fired": signals,
            }),
        );
    }
    
    /// Record readiness check
    pub fn record_readiness_check(
        &self,
        gate: &str,
        passed: bool,
        details: serde_json::Value,
    ) {
        let level = if passed { EventLevel::Info } else { EventLevel::Warn };
        self.record(
            level,
            Component::Supervisor,
            EventKind::ReadinessCheck,
            serde_json::json!({
                "gate": gate,
                "passed": passed,
                "details": details,
            }),
        );
    }
    
    /// Record readiness timeout
    pub fn record_readiness_timeout(&self, gate: &str, waited_ms: u64, reason: &str) {
        self.record(
            EventLevel::Error,
            Component::Supervisor,
            EventKind::ReadinessTimeout,
            serde_json::json!({
                "gate": gate,
                "waited_ms": waited_ms,
                "reason": reason,
            }),
        );
    }
}

// Thread-safe Arc wrapper for global access
pub type SharedFlightRecorder = Arc<FlightRecorder>;

/// Create the global flight recorder
pub fn create_flight_recorder(data_dir: &std::path::Path, port: u16) -> SharedFlightRecorder {
    let pid = std::process::id();
    Arc::new(FlightRecorder::new(data_dir, pid, port))
}

// ============================================================================
// Dataflow Snapshot (for /api/meta/dataflow_snapshot)
// ============================================================================

/// Complete dataflow snapshot for debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataflowSnapshot {
    /// Instance identity
    pub instance: InstanceIdentity,
    /// Active run info
    pub active_run: Option<ActiveRunInfo>,
    /// Resolved paths
    pub paths: ResolvedPaths,
    /// Spawn status
    pub spawn_status: SpawnStatus,
    /// Segments status - critical for capture→locald diagnosis
    pub segments_status: SegmentsStatus,
    /// DB truth
    pub db_truth: DbTruth,
    /// Last N flight events
    pub recent_events: Vec<FlightEvent>,
    /// Snapshot timestamp
    pub snapshot_ts: String,
    /// Diagnosis: what's likely broken based on state
    pub diagnosis: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveRunInfo {
    pub run_id: String,
    pub run_dir: String,
    pub phase: String,
    pub started_at: String,
    pub elapsed_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedPaths {
    pub data_dir: String,
    pub db_path_for_live_queries: Option<String>,
    pub segments_path: Option<String>,
    pub logs_path: Option<String>,
    pub flight_log: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnStatus {
    pub capture_running: bool,
    pub capture_pid: Option<u32>,
    pub capture_last_exit: Option<String>,
    pub locald_running: bool,
    pub locald_pid: Option<u32>,
    pub locald_last_exit: Option<String>,
}

/// Segments directory status - critical for diagnosing capture→locald pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentsStatus {
    pub dir_exists: bool,
    pub segments_count: u32,
    pub total_bytes: u64,
    pub newest_segment: Option<SegmentInfo>,
    pub oldest_segment: Option<SegmentInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentInfo {
    pub filename: String,
    pub size_bytes: u64,
    pub mtime_iso: String,
    pub age_seconds: u64,
}

impl SegmentsStatus {
    /// Inspect segments directory
    pub fn from_path(segments_path: Option<&std::path::Path>) -> Self {
        let Some(path) = segments_path else {
            return Self {
                dir_exists: false,
                segments_count: 0,
                total_bytes: 0,
                newest_segment: None,
                oldest_segment: None,
            };
        };
        
        if !path.exists() {
            return Self {
                dir_exists: false,
                segments_count: 0,
                total_bytes: 0,
                newest_segment: None,
                oldest_segment: None,
            };
        }
        
        let now = std::time::SystemTime::now();
        let mut segments: Vec<(String, u64, std::time::SystemTime)> = vec![];
        let mut total_bytes = 0u64;
        
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
                    if let Ok(meta) = entry.metadata() {
                        let size = meta.len();
                        let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
                        total_bytes += size;
                        segments.push((
                            entry.file_name().to_string_lossy().to_string(),
                            size,
                            mtime,
                        ));
                    }
                }
            }
        }
        
        // Sort by mtime (oldest first)
        segments.sort_by_key(|(_, _, mtime)| *mtime);
        
        let make_info = |seg: &(String, u64, std::time::SystemTime)| -> SegmentInfo {
            let age = now.duration_since(seg.2).unwrap_or_default();
            let mtime_iso = chrono::DateTime::<chrono::Utc>::from(seg.2).to_rfc3339();
            SegmentInfo {
                filename: seg.0.clone(),
                size_bytes: seg.1,
                mtime_iso,
                age_seconds: age.as_secs(),
            }
        };
        
        Self {
            dir_exists: true,
            segments_count: segments.len() as u32,
            total_bytes,
            oldest_segment: segments.first().map(make_info),
            newest_segment: segments.last().map(make_info),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTruth {
    pub db_exists: bool,
    pub db_path: Option<String>,
    pub tables: Vec<TableInfo>,
    pub can_read: bool,
    pub journal_mode: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableInfo {
    pub name: String,
    pub rowcount: u64,
    pub max_ts: Option<i64>,
}

impl DbTruth {
    /// Query DB truth from a path
    pub fn from_path(db_path: Option<&std::path::Path>) -> Self {
        let Some(path) = db_path else {
            return Self {
                db_exists: false,
                db_path: None,
                tables: vec![],
                can_read: false,
                journal_mode: None,
                error: Some("No active run DB path".to_string()),
            };
        };
        
        if !path.exists() {
            return Self {
                db_exists: false,
                db_path: Some(path.display().to_string()),
                tables: vec![],
                can_read: false,
                journal_mode: None,
                error: Some("DB file does not exist".to_string()),
            };
        }
        
        match rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(conn) => {
                // Get journal mode
                let journal_mode: Option<String> = conn
                    .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                    .ok();
                
                // Query table info
                let mut tables = vec![];
                
                // Check key tables
                for table in &["signals", "coverage_rollup", "segments", "facts"] {
                    if let Ok(count) = conn.query_row::<i64, _, _>(
                        &format!("SELECT COUNT(*) FROM {}", table),
                        [],
                        |r| r.get(0),
                    ) {
                        let max_ts: Option<i64> = conn
                            .query_row(&format!("SELECT MAX(ts) FROM {}", table), [], |r| r.get(0))
                            .ok()
                            .flatten();
                        
                        tables.push(TableInfo {
                            name: table.to_string(),
                            rowcount: count as u64,
                            max_ts,
                        });
                    }
                }
                
                Self {
                    db_exists: true,
                    db_path: Some(path.display().to_string()),
                    tables,
                    can_read: true,
                    journal_mode,
                    error: None,
                }
            }
            Err(e) => Self {
                db_exists: true,
                db_path: Some(path.display().to_string()),
                tables: vec![],
                can_read: false,
                journal_mode: None,
                error: Some(format!("Failed to open: {}", e)),
            },
        }
    }
}

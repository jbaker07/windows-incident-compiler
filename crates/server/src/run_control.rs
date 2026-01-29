//! Run Control: Browser-accessible capture lifecycle management
//!
//! This module provides HTTP endpoints for starting/stopping capture runs,
//! making live capture work from any browser without requiring Tauri.
//!
//! Endpoints:
//! - POST /api/run/start   - Start capture + locald
//! - POST /api/run/stop    - Stop all processes
//! - GET  /api/run/status  - Current run status
//! - GET  /api/run/metrics - Live metrics

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

// ============================================================================
// Types
// ============================================================================

/// Process identity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessKind {
    Capture,
    Locald,
}

impl ProcessKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProcessKind::Capture => "capture",
            ProcessKind::Locald => "locald",
        }
    }

    #[cfg(target_os = "windows")]
    pub fn binary_name(&self) -> &'static str {
        match self {
            ProcessKind::Capture => "capture_windows_rotating.exe",
            ProcessKind::Locald => "edr-locald.exe",
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn binary_name(&self) -> &'static str {
        match self {
            ProcessKind::Capture => "capture_linux_rotating",
            ProcessKind::Locald => "edr-locald",
        }
    }
}

/// Request to start a run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartRunRequest {
    /// Capture profile: "core", "extended", "forensic"
    #[serde(default)]
    pub profile: Option<String>,
    /// Duration in seconds (0 = indefinite)
    #[serde(default)]
    pub duration_s: Option<u64>,
    /// Optional label for the run
    #[serde(default)]
    pub run_label: Option<String>,
    /// Chain IDs for Investigate tab (INVESTIGATE_CHAINS-1)
    /// Stored with run for persistence across reloads
    #[serde(default)]
    pub chain_ids: Option<Vec<String>>,
}

/// Response from start
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartRunResponse {
    pub run_id: String,
    pub run_dir: String,
    pub capture_pid: Option<u32>,
    pub locald_pid: Option<u32>,
    pub started_at: DateTime<Utc>,
}

/// Status of a single process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessStatus {
    pub kind: ProcessKind,
    pub running: bool,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
}

/// Overall run status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunStatus {
    pub running: bool,
    pub run_id: Option<String>,
    pub run_dir: Option<String>,
    pub profile: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub elapsed_seconds: Option<u64>,
    pub duration_limit_seconds: Option<u64>,
    pub processes: Vec<ProcessStatus>,
    pub last_heartbeat: DateTime<Utc>,
    pub is_admin: bool,
}

/// Live metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetrics {
    pub running: bool,
    pub run_id: Option<String>,
    pub segments_count: u32,
    pub events_total: u64,
    pub facts_extracted: u64,
    pub signals_fired: u64,
    pub bytes_written: u64,
    pub last_segment_time: Option<DateTime<Utc>>,
    pub capture_errors: u32,
    pub locald_errors: u32,
}

/// A managed child process
struct ManagedProcess {
    kind: ProcessKind,
    child: Child,
    log_path: PathBuf,
}

impl ManagedProcess {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn exit_code(&mut self) -> Option<i32> {
        self.child.try_wait().ok().flatten().and_then(|s| s.code())
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ============================================================================
// Run Controller
// ============================================================================

/// Browser-accessible run controller
pub struct RunController {
    telemetry_root: PathBuf,
    processes: RwLock<HashMap<ProcessKind, ManagedProcess>>,
    run_id: RwLock<Option<String>>,
    run_dir: RwLock<Option<PathBuf>>,
    run_started: RwLock<Option<Instant>>,
    started_at: RwLock<Option<DateTime<Utc>>>,
    duration_limit: RwLock<Option<u64>>,
    profile: RwLock<Option<String>>,
    shutdown_requested: Arc<AtomicBool>,
    is_admin: bool,
}

impl RunController {
    /// Create a new run controller
    pub fn new(telemetry_root: PathBuf) -> Self {
        let is_admin = is_elevated();
        
        Self {
            telemetry_root,
            processes: RwLock::new(HashMap::new()),
            run_id: RwLock::new(None),
            run_dir: RwLock::new(None),
            run_started: RwLock::new(None),
            started_at: RwLock::new(None),
            duration_limit: RwLock::new(None),
            profile: RwLock::new(None),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            is_admin,
        }
    }

    /// Start a capture run
    pub async fn start(&self, req: StartRunRequest) -> Result<StartRunResponse, String> {
        // Check if already running
        {
            let procs = self.processes.read().await;
            if !procs.is_empty() {
                return Err("Run already in progress. Stop it first.".into());
            }
        }

        // Generate run ID
        let run_id = if let Some(label) = &req.run_label {
            format!("run_{}_{}", chrono::Local::now().format("%Y%m%d_%H%M%S"), label)
        } else {
            format!("run_{}", chrono::Local::now().format("%Y%m%d_%H%M%S"))
        };

        // Create run directory structure
        let run_dir = self.telemetry_root.join("runs").join(&run_id);
        let segments_dir = run_dir.join("segments");
        let logs_dir = run_dir.join("logs");

        for dir in [&segments_dir, &logs_dir] {
            fs::create_dir_all(dir)
                .map_err(|e| format!("Failed to create directory {:?}: {}", dir, e))?;
        }

        // Write pidfile
        let pidfile = run_dir.join("run.pid");
        fs::write(&pidfile, std::process::id().to_string())
            .map_err(|e| format!("Failed to write pidfile: {}", e))?;

        // Real mode: binaries must exist - hard fail with helpful error
        let capture_pid = self.start_capture(&run_dir).await?;

        // Small delay for capture to initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // TASK B: Pass run_id to locald for consistent signal stamping
        let locald_pid = self.start_locald(&run_dir, &run_id).await?;

        let now = Utc::now();

        // Store state
        {
            *self.run_id.write().await = Some(run_id.clone());
            *self.run_dir.write().await = Some(run_dir.clone());
            *self.run_started.write().await = Some(Instant::now());
            *self.started_at.write().await = Some(now);
            *self.duration_limit.write().await = req.duration_s;
            *self.profile.write().await = req.profile;
        }

        tracing::info!(
            "Started run {} at {:?} (capture PID {:?}, locald PID {:?})",
            run_id, run_dir, capture_pid, locald_pid
        );

        Ok(StartRunResponse {
            run_id,
            run_dir: run_dir.display().to_string(),
            capture_pid,
            locald_pid,
            started_at: now,
        })
    }

    /// Start the capture process
    async fn start_capture(&self, run_dir: &PathBuf) -> Result<Option<u32>, String> {
        let binary_path = find_binary(ProcessKind::Capture)?;

        let log_path = run_dir.join("logs").join("capture.log");
        let segments_dir = run_dir.join("segments");

        let log_file = File::create(&log_path)
            .map_err(|e| format!("Failed to create capture log: {}", e))?;

        let mut cmd = Command::new(&binary_path);
        cmd.env("EDR_TELEMETRY_ROOT", run_dir)
            .env("EDR_SEGMENTS_DIR", &segments_dir)
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file));

        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start capture: {}", e))?;

        let pid = child.id();
        tracing::info!("Started capture (PID {})", pid);

        self.processes.write().await.insert(
            ProcessKind::Capture,
            ManagedProcess {
                kind: ProcessKind::Capture,
                child,
                log_path,
            },
        );

        Ok(Some(pid))
    }

    /// Start the locald process
    /// TASK B: Pass RUN_ID and RUN_DIR via env vars for consistent signal stamping
    async fn start_locald(&self, run_dir: &PathBuf, run_id: &str) -> Result<Option<u32>, String> {
        let binary_path = find_binary(ProcessKind::Locald)?;

        let log_path = run_dir.join("logs").join("locald.log");
        let playbooks_dir = self.telemetry_root.join("playbooks").join("windows");

        // Ensure playbooks dir exists
        let _ = fs::create_dir_all(&playbooks_dir);

        let log_file = File::create(&log_path)
            .map_err(|e| format!("Failed to create locald log: {}", e))?;

        let mut cmd = Command::new(&binary_path);
        cmd.env("EDR_TELEMETRY_ROOT", run_dir)
            .env("EDR_PLAYBOOKS_DIR", &playbooks_dir)
            // TASK B: Explicit run_id propagation for consistent signal stamping
            .env("EDR_RUN_ID", run_id)
            .env("EDR_RUN_DIR", run_dir)
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file));

        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start locald: {}", e))?;

        let pid = child.id();
        tracing::info!("Started locald (PID {}) with RUN_ID={}", pid, run_id);

        self.processes.write().await.insert(
            ProcessKind::Locald,
            ManagedProcess {
                kind: ProcessKind::Locald,
                child,
                log_path,
            },
        );

        Ok(Some(pid))
    }

    /// Stop all processes
    pub async fn stop(&self) -> Result<(), String> {
        let mut procs = self.processes.write().await;

        for (kind, proc) in procs.iter_mut() {
            tracing::info!("Stopping {:?} (PID {})", kind, proc.pid());
            proc.kill();
        }

        procs.clear();

        // Clear state
        *self.run_id.write().await = None;
        *self.run_dir.write().await = None;
        *self.run_started.write().await = None;
        *self.started_at.write().await = None;

        tracing::info!("All processes stopped");
        Ok(())
    }

    /// Get current status
    pub async fn status(&self) -> RunStatus {
        let mut procs = self.processes.write().await;

        let process_statuses: Vec<ProcessStatus> = procs
            .iter_mut()
            .map(|(kind, proc)| ProcessStatus {
                kind: *kind,
                running: proc.is_running(),
                pid: Some(proc.pid()),
                exit_code: proc.exit_code(),
            })
            .collect();

        let running = process_statuses.iter().any(|p| p.running);

        let elapsed = self.run_started.read().await
            .map(|s| s.elapsed().as_secs());

        RunStatus {
            running,
            run_id: self.run_id.read().await.clone(),
            run_dir: self.run_dir.read().await.as_ref().map(|p| p.display().to_string()),
            profile: self.profile.read().await.clone(),
            started_at: *self.started_at.read().await,
            elapsed_seconds: elapsed,
            duration_limit_seconds: *self.duration_limit.read().await,
            processes: process_statuses,
            last_heartbeat: Utc::now(),
            is_admin: self.is_admin,
        }
    }

    /// Get live metrics
    pub async fn metrics(&self) -> RunMetrics {
        let run_id = self.run_id.read().await.clone();
        let run_dir = self.run_dir.read().await.clone();
        let procs = self.processes.read().await;
        let running = !procs.is_empty();

        // Count segments from disk
        let (segments_count, bytes_written, last_segment_time) = if let Some(ref dir) = run_dir {
            count_segments(&dir.join("segments"))
        } else {
            (0, 0, None)
        };

        // Count signals from database (locald writes to workbench.db, NOT signals.db)
        let signals_fired = if let Some(ref dir) = run_dir {
            count_signals_in_db(&dir.join("workbench.db"))
        } else {
            0
        };

        // RD-1 FIX: Query facts from DB, NOT from log parsing
        let facts_extracted = if let Some(ref dir) = run_dir {
            query_facts_from_db(&dir.join("workbench.db"))
        } else {
            0
        };

        // RD-1 FIX: events_total is from DB or null (NO ESTIMATION)
        // If DB doesn't track events, return 0 (truthful: we don't know)
        let events_total = if let Some(ref dir) = run_dir {
            query_events_from_db(&dir.join("workbench.db"))
        } else {
            0
        };

        RunMetrics {
            running,
            run_id,
            segments_count,
            events_total,
            facts_extracted,
            signals_fired,
            bytes_written,
            last_segment_time,
            capture_errors: 0,
            locald_errors: 0,
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a Command that won't show a console window on Windows
#[cfg(windows)]
fn no_window_command(program: &str) -> std::process::Command {
    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new(program);
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    cmd
}

#[cfg(not(windows))]
fn no_window_command(program: &str) -> std::process::Command {
    std::process::Command::new(program)
}

/// Check if running as admin/elevated
#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    // Simple heuristic: try to access a protected registry key or use whoami
    no_window_command("net")
        .args(["session"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Find binary in known locations.
/// 
/// Priority order:
/// 1. Environment variable (EDR_CAPTURE_BINARY or EDR_LOCALD_BINARY)
/// 2. Same directory as edr-server executable
/// 3. target/debug
/// 4. target/release
/// 5. PATH
fn find_binary(kind: ProcessKind) -> Result<PathBuf, String> {
    let name = kind.binary_name();
    
    // PRIORITY 1: Check environment variable override (for locint and custom deployments)
    let env_var = match kind {
        ProcessKind::Capture => "EDR_CAPTURE_BINARY",
        ProcessKind::Locald => "EDR_LOCALD_BINARY",
    };
    
    if let Ok(env_path) = std::env::var(env_var) {
        let path = PathBuf::from(&env_path);
        if path.exists() {
            tracing::debug!("Found {} via {} = {:?}", name, env_var, path);
            return Ok(path);
        } else {
            tracing::warn!("{} set to {:?} but file does not exist", env_var, path);
        }
    }

    // PRIORITY 2-5: Search known locations
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    
    let candidates: Vec<(PathBuf, &str)> = vec![
        // Same directory as server
        exe_dir.clone().map(|d| (d.join(name), "alongside edr-server")),
        // Target debug directory
        Some((PathBuf::from(format!("target/debug/{}", name)), "target/debug")),
        // Target release directory
        Some((PathBuf::from(format!("target/release/{}", name)), "target/release")),
        // PATH
        which::which(name).ok().map(|p| (p, "PATH")),
    ].into_iter().flatten().collect();

    for (candidate, _location) in &candidates {
        if candidate.exists() {
            tracing::debug!("Found {} at {:?}", name, candidate);
            return Ok(candidate.clone());
        }
    }

    // Build detailed error message
    let searched_paths = candidates.iter()
        .map(|(p, loc)| format!("  - {} ({})", p.display(), loc))
        .collect::<Vec<_>>()
        .join("\\n");
    
    let (pkg, bin_flag) = match kind {
        ProcessKind::Capture => ("agent-windows", "--bin capture_windows_rotating"),
        ProcessKind::Locald => ("edr-locald", "--bin edr-locald"),
    };

    Err(format!(
        "BINARY NOT FOUND: {}\\n\\n\
         Searched locations:\\n{}\\n\\n\
         To build, run:\\n  cargo build -p {} {}",
        name, searched_paths, pkg, bin_flag
    ))
}

/// Count segments in a directory
fn count_segments(dir: &PathBuf) -> (u32, u64, Option<DateTime<Utc>>) {
    let mut count = 0u32;
    let mut bytes = 0u64;
    let mut latest: Option<DateTime<Utc>> = None;

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "jsonl") {
                count += 1;
                if let Ok(meta) = entry.metadata() {
                    bytes += meta.len();
                    if let Ok(modified) = meta.modified() {
                        let dt: DateTime<Utc> = modified.into();
                        if latest.is_none() || latest.unwrap() < dt {
                            latest = Some(dt);
                        }
                    }
                }
            }
        }
    }

    (count, bytes, latest)
}

/// Count signals in database
fn count_signals_in_db(db_path: &PathBuf) -> u64 {
    if !db_path.exists() {
        return 0;
    }

    match rusqlite::Connection::open(db_path) {
        Ok(conn) => {
            conn.query_row("SELECT COUNT(*) FROM signals", [], |row| row.get::<_, i64>(0))
                .unwrap_or(0) as u64
        }
        Err(_) => 0,
    }
}

/// RD-1 FIX: Query facts from DB coverage_rollup table (TRUTHFUL, NO LOG PARSING)
fn query_facts_from_db(db_path: &PathBuf) -> u64 {
    if !db_path.exists() {
        return 0;
    }

    let conn = match rusqlite::Connection::open(db_path) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    // Query coverage_rollup for total fact count (locald writes this)
    conn.query_row(
        "SELECT COALESCE(SUM(fact_count), 0) FROM coverage_rollup",
        [],
        |row| row.get::<_, i64>(0),
    )
    .map(|v| v.max(0) as u64)
    .unwrap_or(0)
}

/// RD-1 FIX: Query events from DB (TRUTHFUL, NO ESTIMATION)
/// Returns 0 if unknown rather than faking numbers
fn query_events_from_db(db_path: &PathBuf) -> u64 {
    if !db_path.exists() {
        return 0;
    }

    let conn = match rusqlite::Connection::open(db_path) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    // Try event_count from coverage_rollup first
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
            return count as u64;
        }
    }

    // Fallback: count segments records if available
    conn.query_row("SELECT COALESCE(SUM(records), 0) FROM segments", [], |row| {
        row.get::<_, i64>(0)
    })
    .map(|v| v.max(0) as u64)
    .unwrap_or(0)
}

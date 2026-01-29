//! Supervisor: Single-responsibility process manager for LocInt
//!
//! GOAL: User runs ONE binary (locint.exe or edr-server.exe). The Supervisor
//! manages all helper processes (capture_windows_rotating.exe, edr-locald.exe)
//! automatically.
//!
//! LIFECYCLE:
//!   1. User clicks "Start Run" → supervisor.start()
//!   2. Supervisor spawns capture + locald with proper env vars
//!   3. Supervisor tracks PIDs, polls for liveness
//!   4. User clicks "Stop Run" → supervisor.stop_and_finalize()
//!   5. Supervisor stops capture, drains locald, writes final run_meta.json
//!
//! BINARY DISCOVERY (priority order):
//!   1. Environment variable override (EDR_CAPTURE_BINARY, EDR_LOCALD_BINARY)
//!   2. Same directory as locint.exe/edr-server.exe
//!   3. ./bin/ subdirectory (packaged deployment)
//!   4. target/release/ (development)
//!   5. target/debug/ (development)
//!
//! ERROR HANDLING:
//!   - Missing binary → HTTP 412 Precondition Failed with actionable message
//!   - Spawn failure → HTTP 500 with details
//!   - No simulation/demo mode allowed

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::flight_recorder::{
    Component, EventKind, EventLevel, FlightRecorder, SharedFlightRecorder,
};
use crate::capability;
use crate::playbook_scope::PlaybookScope;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// ============================================================================
// Types
// ============================================================================

/// Process kind enumeration
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
    
    pub fn env_var_name(&self) -> &'static str {
        match self {
            ProcessKind::Capture => "EDR_CAPTURE_BINARY",
            ProcessKind::Locald => "EDR_LOCALD_BINARY",
        }
    }
}

/// Run phase for status reporting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunPhase {
    /// No run active
    Idle,
    /// Starting processes
    Starting,
    /// Both capture and locald running
    Running,
    /// Capture stopped, locald draining
    DrainingLocald,
    /// Writing final counts to run_meta.json
    Finalizing,
    /// Run complete
    Completed,
}

impl RunPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunPhase::Idle => "idle",
            RunPhase::Starting => "starting",
            RunPhase::Running => "running",
            RunPhase::DrainingLocald => "draining_locald",
            RunPhase::Finalizing => "finalizing",
            RunPhase::Completed => "completed",
        }
    }
}

/// Error type for supervisor operations
#[derive(Debug)]
pub enum SupervisorError {
    /// Required binary not found - return HTTP 412
    BinaryNotFound {
        kind: ProcessKind,
        searched_paths: Vec<String>,
        build_hint: String,
    },
    /// Run already in progress
    RunAlreadyActive { run_id: String },
    /// No run to stop
    NoActiveRun,
    /// Failed to spawn process
    SpawnFailed {
        kind: ProcessKind,
        error: String,
    },
    /// Failed to create run directory
    DirectoryCreation { path: PathBuf, error: String },
    /// Generic I/O error
    IoError(String),
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupervisorError::BinaryNotFound { kind, searched_paths, build_hint } => {
                writeln!(f, "BINARY NOT FOUND: {}", kind.binary_name())?;
                writeln!(f)?;
                writeln!(f, "Searched locations:")?;
                for path in searched_paths {
                    writeln!(f, "  - {}", path)?;
                }
                writeln!(f)?;
                writeln!(f, "To build: {}", build_hint)
            }
            SupervisorError::RunAlreadyActive { run_id } => {
                write!(f, "Run already in progress: {}. Stop it first.", run_id)
            }
            SupervisorError::NoActiveRun => {
                write!(f, "No active run to stop")
            }
            SupervisorError::SpawnFailed { kind, error } => {
                write!(f, "Failed to spawn {}: {}", kind.binary_name(), error)
            }
            SupervisorError::DirectoryCreation { path, error } => {
                write!(f, "Failed to create directory {}: {}", path.display(), error)
            }
            SupervisorError::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl SupervisorError {
    /// Get HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            SupervisorError::BinaryNotFound { .. } => 412, // Precondition Failed
            SupervisorError::RunAlreadyActive { .. } => 409, // Conflict
            SupervisorError::NoActiveRun => 409, // Conflict
            SupervisorError::SpawnFailed { .. } => 500,
            SupervisorError::DirectoryCreation { .. } => 500,
            SupervisorError::IoError(_) => 500,
        }
    }
    
    /// Get machine-readable error code
    pub fn error_code(&self) -> &'static str {
        match self {
            SupervisorError::BinaryNotFound { .. } => "BINARY_NOT_FOUND",
            SupervisorError::RunAlreadyActive { .. } => "RUN_ALREADY_ACTIVE",
            SupervisorError::NoActiveRun => "NO_ACTIVE_RUN",
            SupervisorError::SpawnFailed { .. } => "SPAWN_FAILED",
            SupervisorError::DirectoryCreation { .. } => "DIRECTORY_CREATION_FAILED",
            SupervisorError::IoError(_) => "IO_ERROR",
        }
    }
}

/// Configuration for starting a run
#[derive(Debug, Clone, Default)]
pub struct StartConfig {
    pub profile: Option<String>,
    pub duration_seconds: Option<u64>,
    pub run_label: Option<String>,
    pub playbooks_dir: Option<PathBuf>,
    /// Selected playbooks for this run (None = all enabled)
    pub selected_playbooks: Option<Vec<String>>,
    /// Selection mode: "preset" or "custom"  
    pub selection_mode: Option<String>,
    /// Preset ID used (for run metadata)
    pub selection_preset: Option<String>,
}

/// Result of starting a run
#[derive(Debug, Clone, Serialize)]
pub struct StartResult {
    pub run_id: String,
    pub run_dir: String,
    pub capture_pid: u32,
    pub locald_pid: u32,
    pub started_at: DateTime<Utc>,
    pub playbooks_enabled: bool,
    pub playbooks_dir: Option<String>,
    /// Number of selected playbooks (None = all)
    pub selected_playbooks_count: Option<usize>,
    /// Selection mode used
    pub selection_mode: Option<String>,
    /// Preset used (if preset mode)
    pub selection_preset: Option<String>,
}

/// Result of stopping a run
#[derive(Debug, Clone, Serialize)]
pub struct StopResult {
    pub stopped: bool,
    pub run_id: String,
    pub run_dir: String,
    pub stopped_at: DateTime<Utc>,
    pub finalized: bool,
    pub events_total: u64,
    pub segments_count: u32,
    pub facts_extracted: u64,
    pub signals_fired: u64,
}

/// Current run status
#[derive(Debug, Clone, Serialize)]
pub struct RunStatus {
    pub running: bool,
    pub run_id: Option<String>,
    pub run_dir: Option<String>,
    pub phase: String,
    pub started_at: Option<String>,
    pub elapsed_seconds: Option<u64>,
    pub capture_running: bool,
    pub locald_running: bool,
    pub is_admin: bool,
}

/// Live metrics (from DB, no estimates)
#[derive(Debug, Clone, Serialize)]
pub struct RunMetrics {
    pub running: bool,
    pub run_id: Option<String>,
    pub segments_count: u32,
    pub bytes_written: u64,
    pub events_total: Option<u64>,  // None = unknown, 0 = genuinely zero
    pub facts_extracted: Option<u64>,
    pub signals_fired: Option<u64>,
    pub elapsed_seconds: Option<u64>,
}

// ============================================================================
// Managed Process
// ============================================================================

#[allow(dead_code)]  // Fields used for debugging/logging
struct ManagedProcess {
    kind: ProcessKind,
    child: Child,
    pid: u32,
    log_path: PathBuf,
}

impl ManagedProcess {
    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
    
    /// Kill the process and wait for it to exit
    fn kill_and_wait(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
    
    /// Graceful termination on Windows using taskkill
    #[cfg(target_os = "windows")]
    fn terminate_graceful(&mut self) -> bool {
        // Try graceful termination first
        let mut cmd = Command::new("taskkill");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        let result = cmd
            .args(["/PID", &self.pid.to_string()])
            .output();
        
        if result.is_ok() {
            // Wait up to 2 seconds for process to exit
            for _ in 0..20 {
                if !self.is_running() {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        
        // Forceful kill if still running
        self.kill_and_wait();
        true
    }
    
    #[cfg(not(target_os = "windows"))]
    fn terminate_graceful(&mut self) -> bool {
        use std::os::unix::process::CommandExt;
        // Send SIGTERM
        unsafe { libc::kill(self.pid as i32, libc::SIGTERM) };
        
        // Wait up to 2 seconds
        for _ in 0..20 {
            if !self.is_running() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        
        // Force kill
        self.kill_and_wait();
        true
    }
}

// ============================================================================
// Supervisor
// ============================================================================

/// The Supervisor manages all helper processes for LocInt
pub struct Supervisor {
    /// Base data directory (contains runs/)
    data_dir: PathBuf,
    /// Currently running processes
    processes: RwLock<HashMap<ProcessKind, ManagedProcess>>,
    /// Current run ID
    run_id: RwLock<Option<String>>,
    /// Current run directory
    run_dir: RwLock<Option<PathBuf>>,
    /// When the run started
    started_at: RwLock<Option<DateTime<Utc>>>,
    /// Current phase
    phase: RwLock<RunPhase>,
    /// Whether running as admin
    is_admin: bool,
    /// Flight recorder for instrumentation (optional)
    flight_recorder: Option<SharedFlightRecorder>,
    /// Process PIDs for status reporting
    capture_pid: RwLock<Option<u32>>,
    locald_pid: RwLock<Option<u32>>,
}

impl Supervisor {
    /// Create a new Supervisor
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            processes: RwLock::new(HashMap::new()),
            run_id: RwLock::new(None),
            run_dir: RwLock::new(None),
            started_at: RwLock::new(None),
            phase: RwLock::new(RunPhase::Idle),
            is_admin: is_elevated(),
            flight_recorder: None,
            capture_pid: RwLock::new(None),
            locald_pid: RwLock::new(None),
        }
    }
    
    /// Create a new Supervisor with flight recorder
    pub fn with_flight_recorder(data_dir: PathBuf, recorder: SharedFlightRecorder) -> Self {
        Self {
            data_dir,
            processes: RwLock::new(HashMap::new()),
            run_id: RwLock::new(None),
            run_dir: RwLock::new(None),
            started_at: RwLock::new(None),
            phase: RwLock::new(RunPhase::Idle),
            is_admin: is_elevated(),
            flight_recorder: Some(recorder),
            capture_pid: RwLock::new(None),
            locald_pid: RwLock::new(None),
        }
    }
    
    /// Set flight recorder after construction
    pub fn set_flight_recorder(&mut self, recorder: SharedFlightRecorder) {
        self.flight_recorder = Some(recorder);
    }
    
    /// Get reference to flight recorder
    pub fn flight_recorder(&self) -> Option<&SharedFlightRecorder> {
        self.flight_recorder.as_ref()
    }
    
    /// Helper: record event to flight recorder if present
    fn record_event(&self, level: EventLevel, event: EventKind, fields: serde_json::Value) {
        if let Some(ref fr) = self.flight_recorder {
            fr.record(level, Component::Supervisor, event, fields);
        }
    }
    
    /// Helper: record phase change
    async fn transition_phase(&self, to: RunPhase) {
        let from = *self.phase.read().await;
        *self.phase.write().await = to;
        
        let run_id = self.run_id.read().await.clone().unwrap_or_default();
        self.record_event(
            EventLevel::Info,
            EventKind::PhaseChange,
            serde_json::json!({
                "from": from.as_str(),
                "to": to.as_str(),
                "run_id": run_id,
            }),
        );
    }
    
    /// Get captured PIDs for status reporting
    pub async fn get_pids(&self) -> (Option<u32>, Option<u32>) {
        (*self.capture_pid.read().await, *self.locald_pid.read().await)
    }
    
    /// Start a new capture run
    /// 
    /// This will:
    /// 1. Validate that helper binaries exist (returns 412 if not)
    /// 2. Create run directory structure
    /// 3. Spawn capture_windows_rotating.exe
    /// 4. Spawn edr-locald.exe
    /// 5. Verify readiness gates (segments dir exists, locald opens DB)
    /// 6. Write initial run_meta.json
    pub async fn start(&self, config: StartConfig) -> Result<StartResult, SupervisorError> {
        // Check if already running
        {
            let run_id = self.run_id.read().await;
            if run_id.is_some() {
                let existing = run_id.clone().unwrap();
                let err = SupervisorError::RunAlreadyActive {
                    run_id: existing.clone(),
                };
                self.record_event(EventLevel::Warn, EventKind::RunStart, serde_json::json!({
                    "error": "run_already_active",
                    "existing_run_id": existing,
                }));
                return Err(err);
            }
        }
        
        // Validate binaries exist BEFORE doing anything else
        let capture_binary = find_binary(ProcessKind::Capture)?;
        let locald_binary = find_binary(ProcessKind::Locald)?;
        
        // Set phase to starting
        self.transition_phase(RunPhase::Starting).await;
        
        // Generate run ID
        let run_id = if let Some(label) = &config.run_label {
            format!("run_{}_{}", chrono::Local::now().format("%Y%m%d_%H%M%S"), label)
        } else {
            format!("run_{}", chrono::Local::now().format("%Y%m%d_%H%M%S"))
        };
        
        // Create run directory structure
        let run_dir = self.data_dir.join("runs").join(&run_id);
        let segments_dir = run_dir.join("segments");
        let logs_dir = run_dir.join("logs");
        
        for dir in [&run_dir, &segments_dir, &logs_dir] {
            fs::create_dir_all(dir).map_err(|e| SupervisorError::DirectoryCreation {
                path: dir.clone(),
                error: e.to_string(),
            })?;
        }
        
        let now = Utc::now();
        
        // Record run start to flight recorder
        self.record_event(EventLevel::Info, EventKind::RunStart, serde_json::json!({
            "run_id": &run_id,
            "run_dir": run_dir.display().to_string(),
            "playbooks_dir": config.playbooks_dir.as_ref().map(|p| p.display().to_string()),
            "capture_binary": capture_binary.display().to_string(),
            "locald_binary": locald_binary.display().to_string(),
        }));
        
        // Start capture process
        let capture_log = File::create(logs_dir.join("capture.log"))
            .map_err(|e| SupervisorError::IoError(format!("Failed to create capture.log: {}", e)))?;
        
        let mut capture_cmd = Command::new(&capture_binary);
        capture_cmd
            .env("EDR_TELEMETRY_ROOT", &run_dir)
            .env("EDR_SEGMENTS_DIR", &segments_dir)
            .env("EDR_RUN_ID", &run_id)
            .stdout(Stdio::from(capture_log.try_clone().unwrap()))
            .stderr(Stdio::from(capture_log));
        
        // Hide console window on Windows
        #[cfg(windows)]
        capture_cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        
        let capture_child = capture_cmd.spawn()
            .map_err(|e| {
                self.record_event(EventLevel::Error, EventKind::SpawnFail, serde_json::json!({
                    "process": "capture",
                    "binary": capture_binary.display().to_string(),
                    "error": e.to_string(),
                }));
                SupervisorError::SpawnFailed {
                    kind: ProcessKind::Capture,
                    error: e.to_string(),
                }
            })?;
        
        let capture_pid = capture_child.id();
        
        // Record spawn success
        self.record_event(EventLevel::Info, EventKind::Spawn, serde_json::json!({
            "process": "capture",
            "pid": capture_pid,
            "binary": capture_binary.display().to_string(),
        }));
        
        // Store capture process and PID
        *self.capture_pid.write().await = Some(capture_pid);
        {
            let mut procs = self.processes.write().await;
            procs.insert(ProcessKind::Capture, ManagedProcess {
                kind: ProcessKind::Capture,
                child: capture_child,
                pid: capture_pid,
                log_path: logs_dir.join("capture.log"),
            });
        }
        
        // Small delay for capture to initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        // Compute canonical playbook scope BEFORE spawning locald
        // This determines exactly which playbooks will be evaluated
        let playbook_scope = PlaybookScope::compute(
            config.selected_playbooks.clone(),
            config.selection_preset.clone(),
            config.selection_mode.clone(),
        );
        
        // Start locald process
        let locald_log = File::create(logs_dir.join("locald.log"))
            .map_err(|e| SupervisorError::IoError(format!("Failed to create locald.log: {}", e)))?;
        
        let mut locald_cmd = Command::new(&locald_binary);
        locald_cmd
            .env("EDR_TELEMETRY_ROOT", &run_dir)  // CRITICAL: locald reads this for workbench.db path
            .env("EDR_RUN_ID", &run_id)
            .env("EDR_RUN_DIR", &run_dir)
            .env("EDR_SEGMENTS_DIR", &segments_dir)
            .stdout(Stdio::from(locald_log.try_clone().unwrap()))
            .stderr(Stdio::from(locald_log));
        
        // Configure playbooks
        let playbooks_enabled = if let Some(ref pb_dir) = config.playbooks_dir {
            if pb_dir.exists() {
                locald_cmd.env("EDR_PLAYBOOKS_DIR", pb_dir);
                true
            } else {
                locald_cmd.env("EDR_ALLOW_NO_PLAYBOOKS", "1");
                false
            }
        } else {
            locald_cmd.env("EDR_ALLOW_NO_PLAYBOOKS", "1");
            false
        };
        
        // Pass EFFECTIVE playbook IDs (from computed scope, not raw selection)
        // This is the SSoT for what locald will evaluate
        let selected_count = if !playbook_scope.effective_playbook_ids.is_empty() {
            let effective_ids = &playbook_scope.effective_playbook_ids;
            locald_cmd.env("EDR_SELECTED_PLAYBOOKS", effective_ids.join(","));
            Some(effective_ids.len())
        } else {
            None
        };
        
        // Pass scope mode so locald can log accurately
        locald_cmd.env("EDR_SCOPE_MODE", format!("{:?}", playbook_scope.mode));
        
        // Pass selection mode for backward compatibility logging
        if let Some(ref mode) = config.selection_mode {
            locald_cmd.env("EDR_SELECTION_MODE", mode);
        }
        if let Some(ref preset) = config.selection_preset {
            locald_cmd.env("EDR_SELECTION_PRESET", preset);
        }
        
        // Hide console window on Windows
        #[cfg(windows)]
        locald_cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        
        let locald_child = locald_cmd.spawn().map_err(|e| {
            self.record_event(EventLevel::Error, EventKind::SpawnFail, serde_json::json!({
                "process": "locald",
                "binary": locald_binary.display().to_string(),
                "error": e.to_string(),
            }));
            SupervisorError::SpawnFailed {
                kind: ProcessKind::Locald,
                error: e.to_string(),
            }
        })?;
        
        let locald_pid = locald_child.id();
        
        // Record spawn success
        self.record_event(EventLevel::Info, EventKind::Spawn, serde_json::json!({
            "process": "locald",
            "pid": locald_pid,
            "binary": locald_binary.display().to_string(),
        }));
        
        // Store locald process and PID
        *self.locald_pid.write().await = Some(locald_pid);
        {
            let mut procs = self.processes.write().await;
            procs.insert(ProcessKind::Locald, ManagedProcess {
                kind: ProcessKind::Locald,
                child: locald_child,
                pid: locald_pid,
                log_path: logs_dir.join("locald.log"),
            });
        }
        
        // ============================================================
        // READINESS GATE: Wait for locald to be ready
        // Conditions: segments dir exists AND (db exists OR timeout)
        // ============================================================
        let db_path = run_dir.join("workbench.db");
        let readiness_timeout_ms = 3000u64;
        let mut waited_ms = 0u64;
        let poll_interval_ms = 100u64;
        
        self.record_event(EventLevel::Info, EventKind::ReadinessCheck, serde_json::json!({
            "gate": "locald_ready",
            "checking": true,
            "db_path": db_path.display().to_string(),
            "segments_dir": segments_dir.display().to_string(),
        }));
        
        while waited_ms < readiness_timeout_ms {
            // Check if locald is still running
            if !is_process_running("edr-locald") {
                self.record_event(EventLevel::Warn, EventKind::ReadinessCheck, serde_json::json!({
                    "gate": "locald_ready",
                    "passed": false,
                    "reason": "locald_exited_early",
                    "waited_ms": waited_ms,
                }));
                // Process died - continue anyway, might have written something
                break;
            }
            
            // Check if DB exists (locald creates it on first write)
            let db_exists = db_path.exists();
            let segments_exist = segments_dir.exists();
            
            if db_exists || waited_ms >= 1000 {
                // Ready: DB exists OR we've waited at least 1 second
                self.record_event(EventLevel::Info, EventKind::ReadinessCheck, serde_json::json!({
                    "gate": "locald_ready",
                    "passed": true,
                    "db_exists": db_exists,
                    "segments_exist": segments_exist,
                    "waited_ms": waited_ms,
                }));
                break;
            }
            
            tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)).await;
            waited_ms += poll_interval_ms;
        }
        
        if waited_ms >= readiness_timeout_ms {
            self.record_event(EventLevel::Warn, EventKind::ReadinessTimeout, serde_json::json!({
                "gate": "locald_ready",
                "waited_ms": waited_ms,
                "reason": "timeout waiting for locald DB",
                "db_exists": db_path.exists(),
            }));
            // Don't fail - just log the timeout
        }
        
        // Write initial run_meta.json with readiness snapshot and playbook scope
        // NOTE: playbook_scope was computed before spawning locald (line ~560)
        let readiness_snapshot = capture_readiness_snapshot();
        let run_meta = serde_json::json!({
            "run_id": run_id,
            "started_at": now.to_rfc3339(),
            "phase": "running",
            "status": "running",
            "capture_pid": capture_pid,
            "locald_pid": locald_pid,
            "playbooks_enabled": playbooks_enabled,
            "playbooks_dir": config.playbooks_dir.as_ref().map(|p| p.display().to_string()),
            "profile": config.profile,
            // CANONICAL playbook scope for this run (SSoT for evaluation)
            "playbook_scope": playbook_scope,
            // Legacy playbook_selection for backward compatibility
            "playbook_selection": {
                "mode": config.selection_mode.as_deref().unwrap_or("preset"),
                "preset": config.selection_preset,
                "selected_playbooks": config.selected_playbooks,
                "selected_count": selected_count,
            },
            // Readiness snapshot at run start (explains telemetry gaps)
            "readiness_snapshot": readiness_snapshot,
        });
        
        fs::write(
            run_dir.join("run_meta.json"),
            serde_json::to_string_pretty(&run_meta).unwrap(),
        ).ok();
        
        // Update state
        *self.run_id.write().await = Some(run_id.clone());
        *self.run_dir.write().await = Some(run_dir.clone());
        *self.started_at.write().await = Some(now);
        self.transition_phase(RunPhase::Running).await;
        
        tracing::info!(
            "Supervisor started run {} (capture PID {}, locald PID {})",
            run_id, capture_pid, locald_pid
        );
        
        Ok(StartResult {
            run_id,
            run_dir: run_dir.display().to_string(),
            capture_pid,
            locald_pid,
            started_at: now,
            playbooks_enabled,
            playbooks_dir: config.playbooks_dir.map(|p| p.display().to_string()),
            selected_playbooks_count: selected_count,
            selection_mode: config.selection_mode,
            selection_preset: config.selection_preset,
        })
    }
    
    /// Stop the current run and finalize
    ///
    /// Finalization phases:
    /// 1. Stop capture first (generates final segments)
    /// 2. Wait for segment flush (300ms)
    /// 3. Stop locald (let it process remaining segments)
    /// 4. Poll for locald termination (up to 2s)
    /// 5. Query final counts from DB
    /// 6. Write finalized run_meta.json
    pub async fn stop_and_finalize(&self) -> Result<StopResult, SupervisorError> {
        let run_id = {
            let rid = self.run_id.read().await;
            rid.clone().ok_or(SupervisorError::NoActiveRun)?
        };
        
        let run_dir = {
            let rd = self.run_dir.read().await;
            rd.clone().ok_or(SupervisorError::NoActiveRun)?
        };
        
        let now = Utc::now();
        
        // Phase 1: Mark as finalizing
        self.transition_phase(RunPhase::Finalizing).await;
        update_run_meta_phase(&run_dir, "finalizing");
        
        // Phase 2: Stop capture first
        let capture_pid_stopped;
        {
            let mut procs = self.processes.write().await;
            if let Some(mut capture) = procs.remove(&ProcessKind::Capture) {
                capture_pid_stopped = Some(capture.pid);
                tracing::info!("Stopping capture (PID {})", capture.pid);
                self.record_event(EventLevel::Info, EventKind::ProcessExit, serde_json::json!({
                    "process": "capture",
                    "pid": capture.pid,
                    "reason": "stop_requested",
                }));
                capture.terminate_graceful();
            } else {
                capture_pid_stopped = None;
            }
        }
        *self.capture_pid.write().await = None;
        
        // Phase 3: Wait for segment flush
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        
        // Phase 4: Update phase to draining
        self.transition_phase(RunPhase::DrainingLocald).await;
        update_run_meta_phase(&run_dir, "draining_locald");
        
        // Phase 5: Stop locald (give it time to process)
        let locald_pid_stopped;
        {
            let mut procs = self.processes.write().await;
            if let Some(mut locald) = procs.remove(&ProcessKind::Locald) {
                locald_pid_stopped = Some(locald.pid);
                tracing::info!("Stopping locald (PID {})", locald.pid);
                self.record_event(EventLevel::Info, EventKind::ProcessExit, serde_json::json!({
                    "process": "locald",
                    "pid": locald.pid,
                    "reason": "stop_requested",
                }));
                locald.terminate_graceful();
            } else {
                locald_pid_stopped = None;
            }
        }
        *self.locald_pid.write().await = None;
        
        // Phase 6: Poll for both processes to be gone (up to 2s)
        let mut drain_waited_ms = 0u64;
        for _ in 0..20 {
            if !is_process_running("capture_windows_rotating") && !is_process_running("edr-locald") {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            drain_waited_ms += 100;
        }
        
        // Record drain result
        let drain_success = !is_process_running("capture_windows_rotating") && !is_process_running("edr-locald");
        self.record_event(EventLevel::Info, EventKind::ReadinessCheck, serde_json::json!({
            "gate": "drain_complete",
            "passed": drain_success,
            "waited_ms": drain_waited_ms,
            "capture_stopped": capture_pid_stopped.is_some(),
            "locald_stopped": locald_pid_stopped.is_some(),
        }));
        
        // Phase 7: Query final counts from DB
        let db_path = run_dir.join("workbench.db");
        let (events_total, facts_extracted, signals_fired) = query_final_counts(&db_path);
        let (segments_count, _bytes) = count_segments(&run_dir.join("segments"));
        
        // Phase 8: Write finalized run_meta.json
        let started_at = self.started_at.read().await.unwrap_or(now);
        let final_meta = serde_json::json!({
            "run_id": run_id,
            "started_at": started_at.to_rfc3339(),
            "stopped_at": now.to_rfc3339(),
            "phase": "completed",
            "status": "completed",
            "finalized": true,
            "events_total": events_total,
            "segments_count": segments_count,
            "facts_extracted": facts_extracted,
            "signals_fired": signals_fired,
        });
        
        fs::write(
            run_dir.join("run_meta.json"),
            serde_json::to_string_pretty(&final_meta).unwrap(),
        ).ok();
        
        // Record run stop to flight recorder
        self.record_event(EventLevel::Info, EventKind::RunStop, serde_json::json!({
            "run_id": &run_id,
            "finalized": true,
            "events_total": events_total,
            "facts_extracted": facts_extracted,
            "signals_fired": signals_fired,
            "segments_count": segments_count,
        }));
        
        // Clear state
        *self.run_id.write().await = None;
        *self.run_dir.write().await = None;
        *self.started_at.write().await = None;
        self.transition_phase(RunPhase::Idle).await;
        
        tracing::info!(
            "Supervisor finalized run {} (events={}, facts={}, signals={})",
            run_id, events_total, facts_extracted, signals_fired
        );
        
        Ok(StopResult {
            stopped: true,
            run_id,
            run_dir: run_dir.display().to_string(),
            stopped_at: now,
            finalized: true,
            events_total,
            segments_count,
            facts_extracted,
            signals_fired,
        })
    }
    
    /// Get current run status
    pub async fn status(&self) -> RunStatus {
        let run_id = self.run_id.read().await.clone();
        let run_dir = self.run_dir.read().await.clone();
        let started_at = *self.started_at.read().await;
        let phase = *self.phase.read().await;
        
        // Check actual process status
        let capture_running = is_process_running("capture_windows_rotating");
        let locald_running = is_process_running("edr-locald");
        let running = capture_running || locald_running;
        
        let elapsed = started_at.map(|s| (Utc::now() - s).num_seconds() as u64);
        
        RunStatus {
            running,
            run_id,
            run_dir: run_dir.map(|p| p.display().to_string()),
            phase: phase.as_str().to_string(),
            started_at: started_at.map(|t| t.to_rfc3339()),
            elapsed_seconds: elapsed,
            capture_running,
            locald_running,
            is_admin: self.is_admin,
        }
    }
    
    /// Get live metrics (from DB, no estimates)
    pub async fn metrics(&self) -> RunMetrics {
        let run_id = self.run_id.read().await.clone();
        let run_dir = self.run_dir.read().await.clone();
        let started_at = *self.started_at.read().await;
        
        let running = is_process_running("capture_windows_rotating") || is_process_running("edr-locald");
        
        let (segments_count, bytes_written) = if let Some(ref dir) = run_dir {
            count_segments(&dir.join("segments"))
        } else {
            (0, 0)
        };
        
        // Query from DB (truthful, no estimates)
        let (events_total, facts_extracted, signals_fired) = if let Some(ref dir) = run_dir {
            let db_path = dir.join("workbench.db");
            if db_path.exists() {
                let (e, f, s) = query_final_counts(&db_path);
                (Some(e), Some(f), Some(s))
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };
        
        let elapsed = started_at.map(|s| (Utc::now() - s).num_seconds() as u64);
        
        RunMetrics {
            running,
            run_id,
            segments_count,
            bytes_written,
            events_total,
            facts_extracted,
            signals_fired,
            elapsed_seconds: elapsed,
        }
    }
    
    /// Check if a run is currently active
    pub async fn is_running(&self) -> bool {
        self.run_id.read().await.is_some()
    }
    
    /// Get current phase
    pub async fn current_phase(&self) -> RunPhase {
        *self.phase.read().await
    }
    
    /// Get data directory
    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }
    
    /// Get current run directory (if running)
    pub async fn current_run_dir(&self) -> Option<PathBuf> {
        self.run_dir.read().await.clone()
    }
    
    /// Get is_admin status
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Find binary in known locations
/// 
/// Priority:
/// 1. Environment variable (EDR_CAPTURE_BINARY or EDR_LOCALD_BINARY)
/// 2. Same directory as current executable
/// 3. ./bin/ subdirectory (packaged deployment)
/// 4. target/release/
/// 5. target/debug/
fn find_binary(kind: ProcessKind) -> Result<PathBuf, SupervisorError> {
    let name = kind.binary_name();
    let env_var = kind.env_var_name();
    
    // Priority 1: Environment variable
    if let Ok(path_str) = std::env::var(env_var) {
        let path = PathBuf::from(&path_str);
        if path.exists() {
            return Ok(path);
        }
    }
    
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    
    let mut searched = Vec::new();
    
    // Priority 2: Same directory as executable
    if let Some(ref dir) = exe_dir {
        let candidate = dir.join(name);
        searched.push(candidate.display().to_string());
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    
    // Priority 3: ./bin/ subdirectory
    if let Some(ref dir) = exe_dir {
        let candidate = dir.join("bin").join(name);
        searched.push(candidate.display().to_string());
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    
    // Priority 4: target/release/
    let release = PathBuf::from(format!("target/release/{}", name));
    searched.push(release.display().to_string());
    if release.exists() {
        return Ok(release);
    }
    
    // Priority 5: target/debug/
    let debug = PathBuf::from(format!("target/debug/{}", name));
    searched.push(debug.display().to_string());
    if debug.exists() {
        return Ok(debug);
    }
    
    // Build hint
    let (pkg, bin_flag) = match kind {
        ProcessKind::Capture => ("agent-windows", "--bin capture_windows_rotating"),
        ProcessKind::Locald => ("locald", "--bin edr-locald"),
    };
    
    Err(SupervisorError::BinaryNotFound {
        kind,
        searched_paths: searched,
        build_hint: format!("cargo build --release -p {} {}", pkg, bin_flag),
    })
}

/// Create a Command that won't show a console window on Windows
#[cfg(windows)]
fn no_window_command(program: &str) -> std::process::Command {
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

/// Check if a process is running by name
#[cfg(target_os = "windows")]
fn is_process_running(name: &str) -> bool {
    let exe_name = if name.ends_with(".exe") {
        name.to_string()
    } else {
        format!("{}.exe", name)
    };
    
    no_window_command("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {}", exe_name)])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&exe_name.replace(".exe", "")))
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn is_process_running(name: &str) -> bool {
    std::process::Command::new("pgrep")
        .arg("-x")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Count segments in directory
fn count_segments(dir: &PathBuf) -> (u32, u64) {
    let mut count = 0u32;
    let mut bytes = 0u64;
    
    if let Ok(entries) = fs::read_dir(dir) {
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

/// Query final counts from workbench.db
fn query_final_counts(db_path: &PathBuf) -> (u64, u64, u64) {
    if !db_path.exists() {
        return (0, 0, 0);
    }
    
    let conn = match rusqlite::Connection::open(db_path) {
        Ok(c) => c,
        Err(_) => return (0, 0, 0),
    };
    
    // Events: from coverage_rollup or segments
    let events: u64 = conn
        .query_row("SELECT COALESCE(SUM(event_count), 0) FROM coverage_rollup", [], |r| r.get(0))
        .or_else(|_| conn.query_row("SELECT COUNT(*) FROM segments", [], |r| r.get(0)))
        .unwrap_or(0);
    
    // Facts: from coverage_rollup or facts table
    let facts: u64 = conn
        .query_row("SELECT COALESCE(SUM(fact_count), 0) FROM coverage_rollup", [], |r| r.get(0))
        .or_else(|_| conn.query_row("SELECT COUNT(*) FROM facts", [], |r| r.get(0)))
        .unwrap_or(0);
    
    // Signals
    let signals: u64 = conn
        .query_row("SELECT COUNT(*) FROM signals", [], |r| r.get::<_, i64>(0))
        .map(|v| v as u64)
        .unwrap_or(0);
    
    (events, facts, signals)
}

/// Update the phase in run_meta.json
fn update_run_meta_phase(run_dir: &PathBuf, phase: &str) {
    let meta_path = run_dir.join("run_meta.json");
    if let Ok(contents) = fs::read_to_string(&meta_path) {
        if let Ok(mut meta) = serde_json::from_str::<serde_json::Value>(&contents) {
            meta["phase"] = serde_json::json!(phase);
            meta["status"] = serde_json::json!(phase);
            let _ = fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap());
        }
    }
}

/// Capture readiness snapshot at run start (telemetry prerequisites)
/// This is stored in run_meta.json so old runs can explain missing telemetry
///
/// Uses the capability module for consistent sensor checking across the app.
fn capture_readiness_snapshot() -> serde_json::Value {
    let cap_status = capability::check_capability_status();
    
    // Build issues list from blocked/missing sensors
    let issues: Vec<serde_json::Value> = cap_status.sensors.iter()
        .filter(|s| !s.status.is_usable())
        .map(|s| {
            serde_json::json!({
                "id": format!("{}_blocked", s.sensor_id),
                "severity": "warning",
                "title": format!("{}: {}", s.sensor_name, s.status.as_str()),
                "description": s.message.clone().unwrap_or_default(),
                "reason_code": s.reason_code.clone(),
            })
        })
        .collect();
    
    // Extract key booleans for backward compatibility
    let sysmon = cap_status.sensors.iter().find(|s| s.sensor_id == "sysmon");
    let security_log = cap_status.sensors.iter().find(|s| s.sensor_id == "security_log");
    
    let sysmon_installed = sysmon.map(|s| s.status.is_usable()).unwrap_or(false);
    let security_log_accessible = security_log.map(|s| s.status.is_usable()).unwrap_or(false);
    
    serde_json::json!({
        "is_admin": cap_status.is_admin,
        "telemetry_status": cap_status.overall_status.as_str(),
        "security_log_accessible": security_log_accessible,
        "sysmon_installed": sysmon_installed,
        "issues": issues,
        // NEW: Full capability snapshot for UI display
        "capability_snapshot": {
            "overall_status": cap_status.overall_status.as_str(),
            "sensors": cap_status.sensors.iter().map(|s| serde_json::json!({
                "sensor_id": s.sensor_id,
                "sensor_name": s.sensor_name,
                "status": s.status.as_str(),
                "reason_code": s.reason_code,
                "capabilities": s.capabilities,
            })).collect::<Vec<_>>(),
            "fact_types_possible": cap_status.fact_types_possible,
            "attack_surface_coverage": cap_status.attack_surfaces.iter().map(|(k, v)| {
                (k.clone(), v.status.clone())
            }).collect::<std::collections::HashMap<_, _>>(),
            "captured_at": chrono::Utc::now().to_rfc3339(),
        }
    })
}

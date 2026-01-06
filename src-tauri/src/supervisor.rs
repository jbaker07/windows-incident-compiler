//! EDR Stack Supervisor - Manages capture, locald, and server processes
//!
//! This module provides a unified supervisor for the entire EDR stack on Windows:
//! - capture_windows_rotating.exe: Windows event telemetry capture
//! - edr-locald.exe: Fact extraction and playbook matching
//! - edr-server.exe: HTTP API and UI server
//!
//! Features:
//! - Admin detection with graceful degradation
//! - Process lifecycle management (start/stop/restart)
//! - Time-windowed capture runs (mission mode)
//! - Per-run telemetry structure: runs/<run_id>/{segments,logs,metrics,playbooks}
//! - Log redirection to run-specific logs folder
//! - Readiness checks (admin, security log, sysmon, audit policy)
//! - Metrics v3.1 GROUNDED with health gates from disk/db/api artifacts
//! - 4-gate validation: Telemetry, Extraction, Detection, Explainability
//! - Health checking and status reporting

// Used by Tauri commands, not CLI binaries
#![allow(dead_code)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

use crate::grounded_gates::{GroundedHealthGates, E2EVerificationResult};

/// Process identity in the stack
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ProcessKind {
    Capture,
    Locald,
    Server,
}

impl ProcessKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProcessKind::Capture => "capture",
            ProcessKind::Locald => "locald",
            ProcessKind::Server => "server",
        }
    }

    pub fn binary_name(&self) -> &'static str {
        match self {
            ProcessKind::Capture => "capture_windows_rotating",
            ProcessKind::Locald => "edr-locald",
            ProcessKind::Server => "edr-server",
        }
    }
}

/// Status of a single managed process
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessStatus {
    pub kind: ProcessKind,
    pub running: bool,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
}

/// Overall stack status returned to UI
#[derive(Debug, Clone, serde::Serialize)]
pub struct StackStatus {
    pub running: bool,
    pub is_admin: bool,
    pub limited_mode: bool,
    pub port: u16,
    pub telemetry_root: String,
    pub api_base_url: String,
    pub processes: Vec<ProcessStatus>,
    pub segments_count: u32,
    pub last_segment_time: Option<String>,
    pub signals_count: u32,
    pub run_id: Option<String>,
    pub run_started: Option<String>,
    pub run_duration_minutes: Option<u32>,
    pub run_remaining_seconds: Option<u32>,
    pub last_error: Option<String>,
    pub crashed_process: Option<String>,
    pub run_dir: Option<String>,
}

/// Readiness check result - what capabilities are available
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessCheck {
    pub is_admin: bool,
    pub can_read_security_log: bool,
    pub sysmon_installed: bool,
    pub sysmon_version: Option<String>,
    pub audit_policy_state: AuditPolicyState,
    pub powershell_logging_enabled: bool,
    pub recommended_fixes: Vec<ReadinessFix>,
    pub overall_readiness: ReadinessLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReadinessLevel {
    Full,      // Admin + Security + Sysmon + Audit OK
    Good,      // Admin + Security, missing some enhancements
    Limited,   // Non-admin, basic telemetry only
    Blocked,   // Cannot capture meaningful telemetry
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicyState {
    pub process_creation: bool,
    pub command_line_logging: bool,
    pub logon_events: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessFix {
    pub id: String,
    pub title: String,
    pub description: String,
    pub command: Option<String>,
    pub requires_admin: bool,
    pub impact: String,
}

/// Run history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunHistoryEntry {
    pub run_id: String,
    pub started: String,
    pub duration_minutes: u32,
    pub segments_count: u32,
    pub signals_count: u32,
    pub is_admin: bool,
    pub run_dir: String,
}

/// Configuration for a mission run
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RunConfig {
    pub duration_minutes: u32,
    pub selected_playbooks: Option<Vec<String>>,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            duration_minutes: 10,
            selected_playbooks: None, // None = all playbooks
        }
    }
}

/// A managed child process
#[allow(dead_code)]
struct ManagedProcess {
    kind: ProcessKind,
    child: Child,
    log_path: PathBuf,
    err_log_path: PathBuf,
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

/// The EDR Stack Supervisor
pub struct Supervisor {
    port: u16,
    telemetry_root: PathBuf,
    processes: HashMap<ProcessKind, ManagedProcess>,
    is_admin: bool,
    run_config: Option<RunConfig>,
    run_id: Option<String>,
    run_dir: Option<PathBuf>,
    run_started: Option<Instant>,
    shutdown_requested: Arc<AtomicBool>,
}

impl Supervisor {
    /// Create a new supervisor
    pub async fn new() -> Result<Self, String> {
        let port = 3000; // Fixed port for consistency

        // Determine telemetry root: prefer %LOCALAPPDATA%\windows-incident-compiler\telemetry
        let telemetry_root = get_telemetry_root();

        // Check if running as admin
        let is_admin = is_elevated();

        tracing::info!(
            "Supervisor initialized: port={}, telemetry_root={:?}, is_admin={}",
            port,
            telemetry_root,
            is_admin
        );

        Ok(Self {
            port,
            telemetry_root,
            processes: HashMap::new(),
            is_admin,
            run_config: None,
            run_id: None,
            run_dir: None,
            run_started: None,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Initialize directories and copy playbooks
    pub fn init_directories(&self) -> Result<(), String> {
        // Create base directory structure (shared across runs)
        let base_dirs = [
            self.telemetry_root.join("runs"),
            self.telemetry_root.join("playbooks").join("windows"),
        ];

        for dir in &base_dirs {
            fs::create_dir_all(dir)
                .map_err(|e| format!("Failed to create directory {:?}: {}", dir, e))?;
        }

        // Copy playbooks from repo if available
        self.copy_playbooks()?;

        tracing::info!("Initialized base directories at {:?}", self.telemetry_root);
        Ok(())
    }

    /// Initialize per-run directory structure
    fn init_run_directories(&self, run_id: &str) -> Result<PathBuf, String> {
        let run_dir = self.telemetry_root.join("runs").join(run_id);
        
        let dirs = [
            run_dir.join("segments"),
            run_dir.join("logs"),
            run_dir.join("metrics"),
            run_dir.join("incidents"),
            run_dir.join("exports"),
        ];

        for dir in &dirs {
            fs::create_dir_all(dir)
                .map_err(|e| format!("Failed to create run directory {:?}: {}", dir, e))?;
        }

        tracing::info!("Created run directory structure at {:?}", run_dir);
        Ok(run_dir)
    }

    /// Copy playbooks from the repo to telemetry root
    fn copy_playbooks(&self) -> Result<(), String> {
        // Find playbooks directory relative to exe or in known locations
        let playbooks_source = find_playbooks_dir()?;
        let playbooks_dest = self.telemetry_root.join("playbooks").join("windows");

        let entries = fs::read_dir(&playbooks_source)
            .map_err(|e| format!("Failed to read playbooks dir: {}", e))?;

        let mut copied = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                let dest = playbooks_dest.join(entry.file_name());
                fs::copy(&path, &dest)
                    .map_err(|e| format!("Failed to copy playbook {:?}: {}", path, e))?;
                copied += 1;
            }
        }

        tracing::info!("Copied {} playbooks to {:?}", copied, playbooks_dest);
        Ok(())
    }

    /// Start a mission run with the given config
    pub async fn start_run(&mut self, config: RunConfig) -> Result<(), String> {
        if !self.processes.is_empty() {
            return Err("Stack already running. Stop it first.".into());
        }

        // Check if port 3000 is already in use
        if !crate::port::is_port_available_sync(self.port) {
            let holder = get_port_holder(self.port);
            return Err(format!(
                "Port {} is already in use{}. Stop the other process first.",
                self.port,
                holder.map(|p| format!(" by PID {}", p)).unwrap_or_default()
            ));
        }

        self.init_directories()?;

        // Generate run ID and create per-run directory structure
        let run_id = format!(
            "run_{}",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        );
        let run_dir = self.init_run_directories(&run_id)?;
        
        self.run_id = Some(run_id.clone());
        self.run_dir = Some(run_dir.clone());
        self.run_config = Some(config.clone());
        self.run_started = Some(Instant::now());
        self.shutdown_requested.store(false, Ordering::SeqCst);

        tracing::info!(
            "Starting run {} for {} minutes at {:?} (playbooks: {:?})",
            run_id,
            config.duration_minutes,
            run_dir,
            config.selected_playbooks
        );

        // Start processes in order: capture -> locald -> server
        // Pass run_dir so each process writes to run-specific folders
        self.start_capture(&config, &run_dir).await?;
        tokio::time::sleep(Duration::from_secs(2)).await;

        self.start_locald(&config, &run_dir).await?;
        tokio::time::sleep(Duration::from_secs(1)).await;

        self.start_server(&run_dir).await?;

        // Wait for server health
        self.wait_for_server_health(Duration::from_secs(30)).await?;

        tracing::info!("Run {} started successfully", run_id);
        Ok(())
    }

    /// Start the capture process
    async fn start_capture(&mut self, _config: &RunConfig, run_dir: &PathBuf) -> Result<(), String> {
        let binary_path = find_binary(ProcessKind::Capture)?;

        let log_path = run_dir.join("logs").join("capture.log");
        let err_log_path = run_dir.join("logs").join("capture_err.log");

        let stdout_file = File::create(&log_path)
            .map_err(|e| format!("Failed to create capture log: {}", e))?;
        let stderr_file = File::create(&err_log_path)
            .map_err(|e| format!("Failed to create capture error log: {}", e))?;

        // Capture writes segments to run-specific segments folder
        let segments_dir = run_dir.join("segments");

        let mut cmd = Command::new(&binary_path);
        cmd.env("EDR_TELEMETRY_ROOT", run_dir)
            .env("EDR_SEGMENTS_DIR", &segments_dir)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));

        // If not admin, capture will run in limited mode automatically
        // (it checks internally and uses only accessible channels)

        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start capture: {}", e))?;

        tracing::info!(
            "Started capture (PID {}) - admin: {}, segments: {:?}",
            child.id(),
            self.is_admin,
            segments_dir
        );

        self.processes.insert(
            ProcessKind::Capture,
            ManagedProcess {
                kind: ProcessKind::Capture,
                child,
                log_path,
                err_log_path,
            },
        );

        Ok(())
    }

    /// Start the locald process
    async fn start_locald(&mut self, config: &RunConfig, run_dir: &PathBuf) -> Result<(), String> {
        let binary_path = find_binary(ProcessKind::Locald)?;

        let log_path = run_dir.join("logs").join("locald.log");
        let err_log_path = run_dir.join("logs").join("locald_err.log");

        let stdout_file = File::create(&log_path)
            .map_err(|e| format!("Failed to create locald log: {}", e))?;
        let stderr_file = File::create(&err_log_path)
            .map_err(|e| format!("Failed to create locald error log: {}", e))?;

        let mut cmd = Command::new(&binary_path);
        cmd.env("EDR_TELEMETRY_ROOT", run_dir)
            .env("EDR_PLAYBOOKS_DIR", self.telemetry_root.join("playbooks").join("windows"))
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));

        // If specific playbooks selected, pass them
        if let Some(ref playbooks) = config.selected_playbooks {
            if !playbooks.is_empty() {
                cmd.env("EDR_SELECTED_PLAYBOOKS", playbooks.join(","));
            }
        }

        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start locald: {}", e))?;

        tracing::info!("Started locald (PID {})", child.id());

        self.processes.insert(
            ProcessKind::Locald,
            ManagedProcess {
                kind: ProcessKind::Locald,
                child,
                log_path,
                err_log_path,
            },
        );

        Ok(())
    }

    /// Start the server process
    async fn start_server(&mut self, run_dir: &PathBuf) -> Result<(), String> {
        let binary_path = find_binary(ProcessKind::Server)?;

        let log_path = run_dir.join("logs").join("server.log");
        let err_log_path = run_dir.join("logs").join("server_err.log");

        let stdout_file = File::create(&log_path)
            .map_err(|e| format!("Failed to create server log: {}", e))?;
        let stderr_file = File::create(&err_log_path)
            .map_err(|e| format!("Failed to create server error log: {}", e))?;

        let child = Command::new(&binary_path)
            .env("EDR_TELEMETRY_ROOT", run_dir)
            .env("EDR_SERVER_PORT", self.port.to_string())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .map_err(|e| format!("Failed to start server: {}", e))?;

        tracing::info!("Started server (PID {}) on port {}", child.id(), self.port);

        self.processes.insert(
            ProcessKind::Server,
            ManagedProcess {
                kind: ProcessKind::Server,
                child,
                log_path,
                err_log_path,
            },
        );

        Ok(())
    }

    /// Wait for server to become healthy
    async fn wait_for_server_health(&self, timeout: Duration) -> Result<(), String> {
        let url = format!("{}/api/health", self.api_base_url());
        let start = Instant::now();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        tracing::info!("Waiting for server health at {}", url);

        loop {
            if start.elapsed() > timeout {
                return Err(format!(
                    "Server did not become healthy within {:?}",
                    timeout
                ));
            }

            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("Server health check passed");
                    return Ok(());
                }
                _ => {}
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Stop all processes
    pub async fn stop_all(&mut self) -> Result<(), String> {
        self.shutdown_requested.store(true, Ordering::SeqCst);

        tracing::info!("Stopping all processes...");

        // Write metrics before shutdown
        if let Err(e) = self.write_metrics().await {
            tracing::warn!("Failed to write metrics: {}", e);
        }

        // Stop in reverse order: server -> locald -> capture
        for kind in [ProcessKind::Server, ProcessKind::Locald, ProcessKind::Capture] {
            if let Some(mut proc) = self.processes.remove(&kind) {
                tracing::info!("Stopping {} (PID {})", kind.as_str(), proc.pid());
                proc.kill();
            }
        }

        self.run_id = None;
        self.run_dir = None;
        self.run_config = None;
        self.run_started = None;

        tracing::info!("All processes stopped");
        Ok(())
    }

    /// Get current status
    pub async fn status(&mut self) -> StackStatus {
        let mut process_statuses = Vec::new();

        for kind in [ProcessKind::Capture, ProcessKind::Locald, ProcessKind::Server] {
            let status = if let Some(proc) = self.processes.get_mut(&kind) {
                ProcessStatus {
                    kind,
                    running: proc.is_running(),
                    pid: Some(proc.pid()),
                    exit_code: proc.exit_code(),
                }
            } else {
                ProcessStatus {
                    kind,
                    running: false,
                    pid: None,
                    exit_code: None,
                }
            };
            process_statuses.push(status);
        }

        let running = process_statuses.iter().any(|p| p.running);

        // Calculate remaining time if in a timed run
        let (remaining_seconds, run_duration) = if let (Some(started), Some(config)) =
            (self.run_started.as_ref(), self.run_config.as_ref())
        {
            let elapsed = started.elapsed();
            let total_duration = Duration::from_secs(config.duration_minutes as u64 * 60);
            let remaining = total_duration.saturating_sub(elapsed);
            (Some(remaining.as_secs() as u32), Some(config.duration_minutes))
        } else {
            (None, None)
        };

        // Count segments - use run_dir if available, otherwise telemetry_root
        let segments_dir = self.run_dir.as_ref()
            .map(|d| d.join("segments"))
            .unwrap_or_else(|| self.telemetry_root.join("segments"));
        let segments_count = count_segments_in_dir(&segments_dir);
        let last_segment_time = get_last_segment_time_in_dir(&segments_dir);

        // Get signals count from API if server is running
        let signals_count = if running {
            fetch_signals_count(&self.api_base_url()).await.unwrap_or(0)
        } else {
            0
        };

        // Check for crashed processes and get last error
        let (crashed_process, last_error) = self.check_for_crashes();

        StackStatus {
            running,
            is_admin: self.is_admin,
            limited_mode: !self.is_admin,
            port: self.port,
            telemetry_root: self.telemetry_root.display().to_string(),
            api_base_url: self.api_base_url(),
            processes: process_statuses,
            segments_count,
            last_segment_time,
            signals_count,
            run_id: self.run_id.clone(),
            run_started: self.run_started.map(|_| {
                chrono::Local::now()
                    .format("%Y-%m-%dT%H:%M:%S")
                    .to_string()
            }),
            run_duration_minutes: run_duration,
            run_remaining_seconds: remaining_seconds,
            last_error,
            crashed_process,
            run_dir: self.run_dir.as_ref().map(|p| p.display().to_string()),
        }
    }

    /// Check for crashed processes and get last error from stderr logs
    fn check_for_crashes(&mut self) -> (Option<String>, Option<String>) {
        let logs_dir = self.run_dir.as_ref()
            .map(|d| d.join("logs"))
            .unwrap_or_else(|| self.telemetry_root.join("logs"));
            
        for kind in [ProcessKind::Capture, ProcessKind::Locald, ProcessKind::Server] {
            if let Some(proc) = self.processes.get_mut(&kind) {
                if !proc.is_running() {
                    // Process crashed - read last lines of stderr
                    let err_log = logs_dir.join(format!("{}_err.log", kind.as_str()));
                    if err_log.exists() {
                        if let Ok(contents) = fs::read_to_string(&err_log) {
                            let last_lines: Vec<&str> = contents.lines().rev().take(5).collect();
                            let error_msg = last_lines.into_iter().rev().collect::<Vec<_>>().join("\n");
                            if !error_msg.trim().is_empty() {
                                return (Some(kind.as_str().to_string()), Some(error_msg));
                            }
                        }
                    }
                    return (Some(kind.as_str().to_string()), Some(format!("{} process exited unexpectedly", kind.as_str())));
                }
            }
        }
        (None, None)
    }

    /// Check if auto-stop should trigger (time window elapsed)
    pub async fn check_auto_stop(&mut self) -> bool {
        if let (Some(started), Some(config)) = (self.run_started.as_ref(), self.run_config.as_ref())
        {
            let elapsed = started.elapsed();
            let total_duration = Duration::from_secs(config.duration_minutes as u64 * 60);

            if elapsed >= total_duration {
                tracing::info!(
                    "Run duration ({} minutes) elapsed, auto-stopping",
                    config.duration_minutes
                );
                if let Err(e) = self.stop_all().await {
                    tracing::error!("Auto-stop failed: {}", e);
                }
                return true;
            }
        }
        false
    }

    /// Write metrics artifact to disk (Metrics v3 schema) - GROUNDED VERSION
    /// 
    /// This version uses GroundedHealthGates which read ONLY from real artifacts:
    /// - run_dir/index.json + segments/*.jsonl
    /// - workbench.db / analysis.db
    /// - Live API
    /// 
    /// NO in-memory counters as source of truth.
    pub async fn write_metrics(&self) -> Result<PathBuf, String> {
        let run_id = self.run_id.as_ref().ok_or("No active run")?;
        let run_dir = self.run_dir.as_ref().ok_or("No run directory")?;

        let elapsed_seconds = self.run_started.map(|s| s.elapsed().as_secs()).unwrap_or(0);
        
        // Count loaded playbooks
        let playbooks_loaded = self.run_config.as_ref()
            .and_then(|c| c.selected_playbooks.as_ref())
            .map(|p| p.len() as u32)
            .unwrap_or(9); // Default to ~9 playbooks

        // ========================================
        // GROUNDED GATES - Single source of truth
        // ========================================
        let grounded_gates = GroundedHealthGates::compute(
            run_dir,
            &self.api_base_url(),
            elapsed_seconds,
            playbooks_loaded,
        ).await;

        // Metrics v3.1 schema with GROUNDED health gates
        let metrics = serde_json::json!({
            "schema_version": "3.1-grounded",
            "run_id": run_id,
            "timestamp": chrono::Local::now().to_rfc3339(),
            "host": hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default(),
            "os": "Windows",
            "os_version": get_windows_version(),
            "arch": std::env::consts::ARCH,
            
            "environment": {
                "is_admin": self.is_admin,
                "limited_mode": !self.is_admin,
                "port": self.port,
                "telemetry_root": self.telemetry_root.display().to_string(),
                "run_dir": run_dir.display().to_string(),
            },
            
            "config": {
                "duration_minutes": self.run_config.as_ref().map(|c| c.duration_minutes),
                "selected_playbooks": self.run_config.as_ref().and_then(|c| c.selected_playbooks.clone()),
            },
            
            // GROUNDED Health Gates (the core of Metrics v3.1)
            "gates": {
                "telemetry": {
                    "status": grounded_gates.telemetry.status.as_str(),
                    "events_count": grounded_gates.telemetry.events_count,
                    "segments_count": grounded_gates.telemetry.segments_count,
                    "channels_active": grounded_gates.telemetry.channels_active,
                    "events_per_second": grounded_gates.telemetry.events_per_second,
                    "diagnosis": grounded_gates.telemetry.diagnosis,
                    "how_computed": grounded_gates.telemetry.how_computed,
                },
                "extraction": {
                    "status": grounded_gates.extraction.status.as_str(),
                    "facts_count": grounded_gates.extraction.facts_count,
                    "extraction_rate": grounded_gates.extraction.extraction_rate,
                    "key_fact_types_present": grounded_gates.extraction.key_fact_types_present,
                    "key_fact_types_missing": grounded_gates.extraction.key_fact_types_missing,
                    "diagnosis": grounded_gates.extraction.diagnosis,
                    "how_computed": grounded_gates.extraction.how_computed,
                },
                "detection": {
                    "status": grounded_gates.detection.status.as_str(),
                    "signals_count": grounded_gates.detection.signals_count,
                    "signals_from_db": grounded_gates.detection.signals_from_db,
                    "signals_from_api": grounded_gates.detection.signals_from_api,
                    "db_api_consistent": grounded_gates.detection.db_api_consistent,
                    "playbooks_matched": grounded_gates.detection.playbooks_matched,
                    "playbooks_loaded": grounded_gates.detection.playbooks_loaded,
                    "match_rate": grounded_gates.detection.match_rate,
                    "diagnosis": grounded_gates.detection.diagnosis,
                    "how_computed": grounded_gates.detection.how_computed,
                },
                "explainability": {
                    "status": grounded_gates.explainability.status.as_str(),
                    "signals_validated": grounded_gates.explainability.signals_validated,
                    "signals_valid": grounded_gates.explainability.signals_valid,
                    "signals_invalid": grounded_gates.explainability.signals_invalid,
                    "explain_valid_rate": grounded_gates.explainability.explain_valid_rate,
                    "evidence_ptr_rate": grounded_gates.explainability.evidence_ptr_rate,
                    "evidence_deref_rate": grounded_gates.explainability.evidence_deref_rate,
                    "required_slot_filled_rate": grounded_gates.explainability.required_slot_filled_rate,
                    "diagnosis": grounded_gates.explainability.diagnosis,
                    "how_computed": grounded_gates.explainability.how_computed,
                },
                "overall_healthy": grounded_gates.overall_healthy,
                "overall_status": grounded_gates.overall_status.as_str(),
                "overall_diagnosis": grounded_gates.overall_diagnosis,
            },
            
            // Detailed breakdowns (from grounded gates)
            "breakdowns": {
                "events_by_channel": grounded_gates.telemetry.events_by_channel,
                "events_by_provider": grounded_gates.telemetry.events_by_provider,
                "facts_by_type": grounded_gates.extraction.facts_by_type,
                "signals_by_playbook": grounded_gates.detection.signals_by_playbook,
                "signals_by_severity": grounded_gates.detection.signals_by_severity,
            },
            
            // Summary rates
            "rates": {
                "explain_valid_rate": grounded_gates.explainability.explain_valid_rate,
                "evidence_ptr_rate": grounded_gates.explainability.evidence_ptr_rate,
                "evidence_deref_rate": grounded_gates.explainability.evidence_deref_rate,
                "required_slot_filled_rate": grounded_gates.explainability.required_slot_filled_rate,
                "extraction_rate": grounded_gates.extraction.extraction_rate,
                "detection_rate": grounded_gates.detection.match_rate,
            },
            
            "timing": {
                "run_duration_minutes": self.run_config.as_ref().map(|c| c.duration_minutes),
                "elapsed_seconds": elapsed_seconds,
                "events_per_second": grounded_gates.telemetry.events_per_second,
            },
            
            // Grounding metadata
            "grounding": {
                "computed_at": grounded_gates.computed_at,
                "source": "disk+db+api",
                "gates_summary": grounded_gates.summary(),
            },
            
            // Legacy validation section for backward compatibility
            "validation": {
                "has_signals": grounded_gates.detection.signals_count > 0,
                "has_segments": grounded_gates.telemetry.segments_count > 0,
                "pipeline_working": grounded_gates.overall_healthy,
            }
        });

        let metrics_path = run_dir
            .join("metrics")
            .join(format!("{}_metrics.json", run_id));

        let json = serde_json::to_string_pretty(&metrics)
            .map_err(|e| format!("Failed to serialize metrics: {}", e))?;

        fs::write(&metrics_path, json)
            .map_err(|e| format!("Failed to write metrics: {}", e))?;

        tracing::info!("Wrote Metrics v3.1 GROUNDED with health gates to {:?}", metrics_path);
        Ok(metrics_path)
    }
    
    /// Get grounded health gates for UI display
    /// 
    /// This is the SAME computation used by write_metrics() - single source of truth
    pub async fn get_grounded_health_gates(&self) -> Result<GroundedHealthGates, String> {
        let run_dir = self.run_dir.as_ref().ok_or("No run directory")?;
        let elapsed_seconds = self.run_started.map(|s| s.elapsed().as_secs()).unwrap_or(0);
        let playbooks_loaded = self.run_config.as_ref()
            .and_then(|c| c.selected_playbooks.as_ref())
            .map(|p| p.len() as u32)
            .unwrap_or(9);
            
        Ok(GroundedHealthGates::compute(
            run_dir,
            &self.api_base_url(),
            elapsed_seconds,
            playbooks_loaded,
        ).await)
    }
    
    /// Run E2E verification of grounded gates
    pub async fn verify_grounded_gates(&self) -> Result<E2EVerificationResult, String> {
        let run_dir = self.run_dir.as_ref().ok_or("No run directory")?;
        Ok(E2EVerificationResult::run(
            run_dir,
            &self.api_base_url(),
        ).await)
    }

    /// Export metrics to a specific path
    pub async fn export_metrics(&self, path: PathBuf) -> Result<(), String> {
        let metrics_path = self.write_metrics().await?;
        fs::copy(&metrics_path, &path)
            .map_err(|e| format!("Failed to export metrics: {}", e))?;
        Ok(())
    }

    /// Get API base URL
    pub fn api_base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Get telemetry root path
    pub fn telemetry_root(&self) -> PathBuf {
        self.telemetry_root.clone()
    }

    /// Get logs folder path
    pub fn logs_folder(&self) -> PathBuf {
        self.telemetry_root.join("logs")
    }

    /// Get metrics folder path
    pub fn metrics_folder(&self) -> PathBuf {
        self.telemetry_root.join("metrics")
    }

    /// Check if running as admin
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }

    /// Read tail of a log file
    pub fn read_log_tail(&self, kind: ProcessKind, lines: usize) -> Result<Vec<String>, String> {
        let logs_dir = self.run_dir.as_ref()
            .map(|d| d.join("logs"))
            .unwrap_or_else(|| self.telemetry_root.join("logs"));
            
        let log_path = logs_dir.join(format!("{}.log", kind.as_str()));

        if !log_path.exists() {
            return Ok(vec![]);
        }

        let file =
            File::open(&log_path).map_err(|e| format!("Failed to open log file: {}", e))?;

        let reader = BufReader::new(file);
        let all_lines: Vec<String> = reader
            .lines()
            .map_while(Result::ok)
            .collect();

        let start = all_lines.len().saturating_sub(lines);
        Ok(all_lines[start..].to_vec())
    }
    
    /// Get current run directory (if running)
    pub fn current_run_dir(&self) -> Option<PathBuf> {
        self.run_dir.clone()
    }

    /// Perform readiness checks
    pub fn get_readiness(&self) -> ReadinessCheck {
        let is_admin = self.is_admin;
        let can_read_security_log = check_security_log_access();
        let (sysmon_installed, sysmon_version) = check_sysmon();
        let audit_policy_state = check_audit_policy();
        let powershell_logging_enabled = check_powershell_logging();
        
        // Determine overall readiness level
        let overall_readiness = if is_admin && can_read_security_log && sysmon_installed && audit_policy_state.process_creation {
            ReadinessLevel::Full
        } else if is_admin && can_read_security_log {
            ReadinessLevel::Good
        } else if is_admin || can_read_security_log {
            ReadinessLevel::Limited
        } else {
            ReadinessLevel::Blocked
        };
        
        // Build recommended fixes
        let mut recommended_fixes = Vec::new();
        
        if !is_admin {
            recommended_fixes.push(ReadinessFix {
                id: "run_as_admin".to_string(),
                title: "Run as Administrator".to_string(),
                description: "Run the application as Administrator to access Security event log and advanced telemetry.".to_string(),
                command: None,
                requires_admin: false,
                impact: "Enables Security log access and full process telemetry".to_string(),
            });
        }
        
        if !sysmon_installed {
            recommended_fixes.push(ReadinessFix {
                id: "install_sysmon".to_string(),
                title: "Install Sysmon".to_string(),
                description: "Install Microsoft Sysmon for enhanced process, network, and file telemetry.".to_string(),
                command: Some("sysmon64.exe -accepteula -i".to_string()),
                requires_admin: true,
                impact: "Enables detailed process creation, network connections, file operations".to_string(),
            });
        }
        
        if !audit_policy_state.command_line_logging {
            recommended_fixes.push(ReadinessFix {
                id: "enable_cmdline".to_string(),
                title: "Enable Command Line Logging".to_string(),
                description: "Enable process command line logging in audit policy.".to_string(),
                command: Some("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f".to_string()),
                requires_admin: true,
                impact: "Captures full command line arguments for process creation events".to_string(),
            });
        }
        
        if !powershell_logging_enabled {
            recommended_fixes.push(ReadinessFix {
                id: "enable_ps_logging".to_string(),
                title: "Enable PowerShell Script Block Logging".to_string(),
                description: "Enable PowerShell script block and module logging.".to_string(),
                command: Some("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f".to_string()),
                requires_admin: true,
                impact: "Captures PowerShell script content for detection".to_string(),
            });
        }
        
        ReadinessCheck {
            is_admin,
            can_read_security_log,
            sysmon_installed,
            sysmon_version,
            audit_policy_state,
            powershell_logging_enabled,
            recommended_fixes,
            overall_readiness,
        }
    }
    
    /// List all previous runs
    pub fn list_runs(&self) -> Result<Vec<RunHistoryEntry>, String> {
        let runs_dir = self.telemetry_root.join("runs");
        
        if !runs_dir.exists() {
            return Ok(vec![]);
        }
        
        let mut entries = Vec::new();
        
        let read_dir = fs::read_dir(&runs_dir)
            .map_err(|e| format!("Failed to read runs directory: {}", e))?;
            
        for entry in read_dir.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            
            let run_id = path.file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string())
                .unwrap_or_default();
                
            if !run_id.starts_with("run_") {
                continue;
            }
            
            // Try to read metrics file for this run
            let metrics_path = path.join("metrics").join(format!("{}_metrics.json", run_id));
            
            let (started, duration_minutes, signals_count, is_admin_run) = 
                if let Ok(contents) = fs::read_to_string(&metrics_path) {
                    if let Ok(metrics) = serde_json::from_str::<serde_json::Value>(&contents) {
                        (
                            metrics.get("timestamp").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            metrics.get("config").and_then(|c| c.get("duration_minutes")).and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                            metrics.get("pipeline").and_then(|p| p.get("signals_count")).and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                            metrics.get("environment").and_then(|e| e.get("is_admin")).and_then(|v| v.as_bool()).unwrap_or(false),
                        )
                    } else {
                        (String::new(), 0, 0, false)
                    }
                } else {
                    // Fall back to directory metadata
                    let started = entry.metadata().ok()
                        .and_then(|m| m.created().ok())
                        .map(|t| chrono::DateTime::<chrono::Local>::from(t).to_rfc3339())
                        .unwrap_or_default();
                    (started, 0, 0, false)
                };
            
            let segments_count = count_segments_in_dir(&path.join("segments"));
            
            entries.push(RunHistoryEntry {
                run_id,
                started,
                duration_minutes,
                segments_count,
                signals_count,
                is_admin: is_admin_run,
                run_dir: path.display().to_string(),
            });
        }
        
        // Sort by run_id (which includes timestamp) descending
        entries.sort_by(|a, b| b.run_id.cmp(&a.run_id));
        
        Ok(entries)
    }
    
    /// Get metrics for a specific run
    pub fn get_run_metrics(&self, run_id: &str) -> Result<serde_json::Value, String> {
        let metrics_path = self.telemetry_root
            .join("runs")
            .join(run_id)
            .join("metrics")
            .join(format!("{}_metrics.json", run_id));
            
        if !metrics_path.exists() {
            return Err(format!("Metrics not found for run: {}", run_id));
        }
        
        let contents = fs::read_to_string(&metrics_path)
            .map_err(|e| format!("Failed to read metrics: {}", e))?;
            
        serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse metrics: {}", e))
    }
    
    /// Open run folder in explorer
    pub fn open_run_folder(&self, run_id: &str) -> Result<(), String> {
        let run_dir = self.telemetry_root.join("runs").join(run_id);
        
        if !run_dir.exists() {
            return Err(format!("Run directory not found: {}", run_id));
        }
        
        Command::new("explorer")
            .arg(&run_dir)
            .spawn()
            .map_err(|e| format!("Failed to open folder: {}", e))?;
            
        Ok(())
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        // Best-effort cleanup
        for (kind, mut proc) in self.processes.drain() {
            tracing::info!("Supervisor dropping, killing {} (PID {})", kind.as_str(), proc.pid());
            proc.kill();
        }
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Get the telemetry root directory
fn get_telemetry_root() -> PathBuf {
    // 1. Check environment variable
    if let Ok(root) = std::env::var("EDR_TELEMETRY_ROOT") {
        return PathBuf::from(root);
    }

    // 2. Use %LOCALAPPDATA%\windows-incident-compiler\telemetry
    if let Some(local_app_data) = dirs::data_local_dir() {
        return local_app_data
            .join("windows-incident-compiler")
            .join("telemetry");
    }

    // 3. Fallback to C:\ProgramData\edr
    PathBuf::from("C:\\ProgramData\\edr")
}

/// Check if running with elevated privileges (Windows)
fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        use std::mem::MaybeUninit;
        use std::ptr;

        unsafe {
            use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
            use windows_sys::Win32::Security::{
                GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
            };
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

            let mut token_handle: HANDLE = ptr::null_mut();
            let current_process = GetCurrentProcess();

            if OpenProcessToken(current_process, TOKEN_QUERY, &mut token_handle) == 0 {
                return false;
            }

            let mut elevation = MaybeUninit::<TOKEN_ELEVATION>::uninit();
            let mut return_length: u32 = 0;

            let result = GetTokenInformation(
                token_handle,
                TokenElevation,
                elevation.as_mut_ptr() as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            );

            CloseHandle(token_handle);

            if result == 0 {
                return false;
            }

            elevation.assume_init().TokenIsElevated != 0
        }
    }

    #[cfg(not(windows))]
    {
        // On non-Windows, check if root
        unsafe { libc::geteuid() == 0 }
    }
}

/// Find a binary in standard locations
fn find_binary(kind: ProcessKind) -> Result<PathBuf, String> {
    let binary_name = kind.binary_name();
    let exe_name = if cfg!(windows) {
        format!("{}.exe", binary_name)
    } else {
        binary_name.to_string()
    };

    // Search locations in order
    let candidates: Vec<PathBuf> = vec![
        // 1. Same directory as this executable (bundled)
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join(&exe_name)))
            .unwrap_or_default(),
        // 2. target/release (development)
        PathBuf::from("target/release").join(&exe_name),
        // 3. target/debug (development)
        PathBuf::from("target/debug").join(&exe_name),
        // 4. Current directory
        PathBuf::from(&exe_name),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate.canonicalize().unwrap_or(candidate));
        }
    }

    Err(format!(
        "Could not find {} binary. Build it with: cargo build --release",
        binary_name
    ))
}

/// Find the playbooks directory
fn find_playbooks_dir() -> Result<PathBuf, String> {
    let candidates = vec![
        // 1. Same dir as exe / playbooks/windows
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("playbooks").join("windows")))
            .unwrap_or_default(),
        // 2. Repo playbooks/windows (development)
        PathBuf::from("playbooks/windows"),
        // 3. Relative to current dir
        std::env::current_dir()
            .ok()
            .map(|p| p.join("playbooks").join("windows"))
            .unwrap_or_default(),
    ];

    for candidate in candidates {
        if candidate.exists() && candidate.is_dir() {
            return Ok(candidate);
        }
    }

    Err("Could not find playbooks directory".into())
}

/// Count segment files
#[allow(dead_code)]
fn count_segments(telemetry_root: &Path) -> u32 {
    let segments_dir = telemetry_root.join("segments");
    count_segments_in_dir(&segments_dir)
}

/// Count segment files in a specific directory
fn count_segments_in_dir(segments_dir: &Path) -> u32 {
    fs::read_dir(segments_dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|e| {
                    e.path()
                        .extension()
                        .is_some_and(|ext| ext == "jsonl")
                })
                .count() as u32
        })
        .unwrap_or(0)
}

/// Get the timestamp of the last segment file
#[allow(dead_code)]
fn get_last_segment_time(telemetry_root: &Path) -> Option<String> {
    let segments_dir = telemetry_root.join("segments");
    get_last_segment_time_in_dir(&segments_dir)
}

/// Get the timestamp of the last segment file in a directory
fn get_last_segment_time_in_dir(segments_dir: &Path) -> Option<String> {
    fs::read_dir(segments_dir)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
        .filter_map(|e| e.metadata().ok().and_then(|m| m.modified().ok()))
        .max()
        .map(|t| {
            chrono::DateTime::<chrono::Local>::from(t)
                .format("%Y-%m-%dT%H:%M:%S")
                .to_string()
        })
}

/// Fetch signals count from the API
async fn fetch_signals_count(api_base_url: &str) -> Option<u32> {
    let url = format!("{}/api/signals", api_base_url);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;

    let response = client.get(&url).send().await.ok()?;
    let data: serde_json::Value = response.json().await.ok()?;

    // Handle both { data: [...] } and direct array
    data.get("data")
        .and_then(|d| d.as_array())
        .or_else(|| data.as_array())
        .map(|arr| arr.len() as u32)
}

/// Fetch signal statistics by playbook and severity from API
#[allow(dead_code)]
async fn fetch_signal_stats(api_base_url: &str) -> Option<(serde_json::Value, serde_json::Value)> {
    let url = format!("{}/api/signals", api_base_url);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;

    let response = client.get(&url).send().await.ok()?;
    let data: serde_json::Value = response.json().await.ok()?;
    
    let signals = data.get("data").and_then(|d| d.as_array())
        .or_else(|| data.as_array())?;
    
    // Count by playbook
    let mut by_playbook: HashMap<String, u32> = HashMap::new();
    let mut by_severity: HashMap<String, u32> = HashMap::new();
    
    for signal in signals {
        if let Some(playbook) = signal.get("playbook_id").and_then(|v| v.as_str()) {
            *by_playbook.entry(playbook.to_string()).or_insert(0) += 1;
        }
        if let Some(severity) = signal.get("severity").and_then(|v| v.as_str()) {
            *by_severity.entry(severity.to_string()).or_insert(0) += 1;
        }
    }
    
    Some((serde_json::to_value(by_playbook).ok()?, serde_json::to_value(by_severity).ok()?))
}

// ============================================================================
// Extended Stats for Health Gates (Metrics v3)
// ============================================================================

/// Telemetry statistics for Gate A
#[allow(dead_code)]
#[derive(Default)]
struct TelemetryStats {
    events_count: u32,
    channels: Vec<String>,
    events_by_channel: HashMap<String, u32>,
    events_by_provider: HashMap<String, u32>,
}

/// Extraction statistics for Gate B
#[allow(dead_code)]
#[derive(Default)]
struct ExtractionStats {
    facts_count: u32,
    facts_by_type: HashMap<String, u32>,
}

/// Explainability statistics for Gate D
#[allow(dead_code)]
#[derive(Default)]
struct ExplainabilityStats {
    validations: Vec<crate::health_gates::SignalExplainability>,
}

/// Fetch telemetry statistics from the API
#[allow(dead_code)]
async fn fetch_telemetry_stats(api_base_url: &str) -> TelemetryStats {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build() {
        Ok(c) => c,
        Err(_) => return TelemetryStats::default(),
    };
    
    // Try to fetch stats from /api/stats endpoint if available
    let stats_url = format!("{}/api/stats", api_base_url);
    if let Ok(response) = client.get(&stats_url).send().await {
        if let Ok(data) = response.json::<serde_json::Value>().await {
            return TelemetryStats {
                events_count: data.get("events_count")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32)
                    .unwrap_or(0),
                channels: data.get("channels")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect())
                    .unwrap_or_default(),
                events_by_channel: data.get("events_by_channel")
                    .and_then(|v| v.as_object())
                    .map(|obj| obj.iter()
                        .filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n as u32)))
                        .collect())
                    .unwrap_or_default(),
                events_by_provider: data.get("events_by_provider")
                    .and_then(|v| v.as_object())
                    .map(|obj| obj.iter()
                        .filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n as u32)))
                        .collect())
                    .unwrap_or_default(),
            };
        }
    }
    
    // Fallback: Try to infer from events endpoint
    let events_url = format!("{}/api/events", api_base_url);
    if let Ok(response) = client.get(&events_url).send().await {
        if let Ok(data) = response.json::<serde_json::Value>().await {
            let events = data.get("data").and_then(|d| d.as_array())
                .or_else(|| data.as_array())
                .cloned()
                .unwrap_or_default();
            
            let mut by_channel: HashMap<String, u32> = HashMap::new();
            let mut by_provider: HashMap<String, u32> = HashMap::new();
            
            for event in &events {
                if let Some(channel) = event.get("channel").and_then(|v| v.as_str()) {
                    *by_channel.entry(channel.to_string()).or_insert(0) += 1;
                }
                if let Some(provider) = event.get("provider").and_then(|v| v.as_str()) {
                    *by_provider.entry(provider.to_string()).or_insert(0) += 1;
                }
            }
            
            let channels: Vec<String> = by_channel.keys().cloned().collect();
            
            return TelemetryStats {
                events_count: events.len() as u32,
                channels,
                events_by_channel: by_channel,
                events_by_provider: by_provider,
            };
        }
    }
    
    TelemetryStats::default()
}

/// Fetch extraction statistics from the API
#[allow(dead_code)]
async fn fetch_extraction_stats(api_base_url: &str) -> ExtractionStats {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build() {
        Ok(c) => c,
        Err(_) => return ExtractionStats::default(),
    };
    
    // Try to fetch from /api/facts endpoint
    let facts_url = format!("{}/api/facts", api_base_url);
    if let Ok(response) = client.get(&facts_url).send().await {
        if let Ok(data) = response.json::<serde_json::Value>().await {
            let facts = data.get("data").and_then(|d| d.as_array())
                .or_else(|| data.as_array())
                .cloned()
                .unwrap_or_default();
            
            let mut by_type: HashMap<String, u32> = HashMap::new();
            
            for fact in &facts {
                if let Some(fact_type) = fact.get("fact_type").and_then(|v| v.as_str()) {
                    *by_type.entry(fact_type.to_string()).or_insert(0) += 1;
                } else if let Some(fact_type) = fact.get("type").and_then(|v| v.as_str()) {
                    *by_type.entry(fact_type.to_string()).or_insert(0) += 1;
                }
            }
            
            return ExtractionStats {
                facts_count: facts.len() as u32,
                facts_by_type: by_type,
            };
        }
    }
    
    // Fallback: Try stats endpoint
    let stats_url = format!("{}/api/stats", api_base_url);
    if let Ok(response) = client.get(&stats_url).send().await {
        if let Ok(data) = response.json::<serde_json::Value>().await {
            return ExtractionStats {
                facts_count: data.get("facts_count")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32)
                    .unwrap_or(0),
                facts_by_type: data.get("facts_by_type")
                    .and_then(|v| v.as_object())
                    .map(|obj| obj.iter()
                        .filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n as u32)))
                        .collect())
                    .unwrap_or_default(),
            };
        }
    }
    
    ExtractionStats::default()
}

/// Fetch explainability statistics from the API
#[allow(dead_code)]
async fn fetch_explainability_stats(api_base_url: &str) -> ExplainabilityStats {
    use crate::health_gates::SignalExplainability;
    
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build() {
        Ok(c) => c,
        Err(_) => return ExplainabilityStats::default(),
    };
    
    // Fetch signals and validate their explanations
    let signals_url = format!("{}/api/signals", api_base_url);
    if let Ok(response) = client.get(&signals_url).send().await {
        if let Ok(data) = response.json::<serde_json::Value>().await {
            let signals = data.get("data").and_then(|d| d.as_array())
                .or_else(|| data.as_array())
                .cloned()
                .unwrap_or_default();
            
            let mut validations = Vec::new();
            
            for signal in &signals {
                let signal_id = signal.get("id")
                    .or_else(|| signal.get("signal_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                    
                let playbook_id = signal.get("playbook_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                // Check for evidence_ptrs
                let evidence_ptrs = signal.get("evidence_ptrs")
                    .or_else(|| signal.get("evidence"))
                    .and_then(|v| v.as_array());
                let has_evidence_ptrs = evidence_ptrs.is_some_and(|arr| !arr.is_empty());
                let evidence_ptr_count = evidence_ptrs.map(|arr| arr.len() as u32).unwrap_or(0);
                
                // Check for entity bundle
                let has_entity_bundle = signal.get("entity_bundle")
                    .or_else(|| signal.get("entities"))
                    .is_some();
                
                // Check for required slots (in explanation or matched_slots)
                let explanation = signal.get("explanation")
                    .or_else(|| signal.get("matched_slots"));
                let required_slots = explanation
                    .and_then(|e| e.as_object())
                    .map(|obj| obj.len() as u32)
                    .unwrap_or(0);
                let required_slots_filled = explanation
                    .and_then(|e| e.as_object())
                    .map(|obj| obj.values()
                        .filter(|v| !v.is_null() && !matches!(v, serde_json::Value::String(s) if s.is_empty()))
                        .count() as u32)
                    .unwrap_or(0);
                let has_required_slots_filled = required_slots_filled > 0 || required_slots == 0;
                
                // Build issues list
                let mut issues = Vec::new();
                if !has_evidence_ptrs {
                    issues.push("Missing evidence_ptrs".to_string());
                }
                if !has_required_slots_filled && required_slots > 0 {
                    issues.push(format!("Only {}/{} required slots filled", required_slots_filled, required_slots));
                }
                
                let is_valid = has_evidence_ptrs && has_required_slots_filled;
                
                validations.push(SignalExplainability {
                    signal_id,
                    playbook_id,
                    has_required_slots_filled,
                    required_slots_filled,
                    required_slots_total: required_slots,
                    has_evidence_ptrs,
                    evidence_ptr_count,
                    has_entity_bundle,
                    is_valid,
                    issues,
                });
            }
            
            return ExplainabilityStats { validations };
        }
    }
    
    ExplainabilityStats::default()
}

/// Get Windows version string
fn get_windows_version() -> String {
    #[cfg(windows)]
    {
        use std::process::Command;
        Command::new("cmd")
            .args(["/c", "ver"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "Windows".to_string())
    }
    #[cfg(not(windows))]
    {
        "Non-Windows".to_string()
    }
}

/// Check if we can read the Security event log
fn check_security_log_access() -> bool {
    #[cfg(windows)]
    {
        use std::process::Command;
        // Try to query Security log - will fail without admin
        let result = Command::new("wevtutil")
            .args(["qe", "Security", "/c:1", "/rd:true", "/f:text"])
            .output();
        
        match result {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Check if Sysmon is installed and get version
fn check_sysmon() -> (bool, Option<String>) {
    #[cfg(windows)]
    {
        use std::process::Command;
        
        // Check if Sysmon service exists
        let result = Command::new("sc")
            .args(["query", "Sysmon64"])
            .output()
            .or_else(|_| Command::new("sc").args(["query", "Sysmon"]).output());
            
        match result {
            Ok(output) if output.status.success() => {
                // Try to get version
                let version = Command::new("reg")
                    .args(["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv", "/v", "ImagePath"])
                    .output()
                    .ok()
                    .and_then(|o| {
                        let stdout = String::from_utf8_lossy(&o.stdout);
                        // Extract version from path if possible
                        if stdout.contains("Sysmon") {
                            Some("installed".to_string())
                        } else {
                            None
                        }
                    });
                (true, version)
            }
            _ => (false, None),
        }
    }
    #[cfg(not(windows))]
    {
        (false, None)
    }
}

/// Check audit policy state
fn check_audit_policy() -> AuditPolicyState {
    #[cfg(windows)]
    {
        use std::process::Command;
        
        // Check process creation auditing
        let process_creation = Command::new("auditpol")
            .args(["/get", "/subcategory:Process Creation"])
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("Success") || stdout.contains("Failure")
            })
            .unwrap_or(false);
        
        // Check if command line logging is enabled
        let command_line = Command::new("reg")
            .args(["query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit", "/v", "ProcessCreationIncludeCmdLine_Enabled"])
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("0x1")
            })
            .unwrap_or(false);
        
        // Check logon auditing
        let logon_events = Command::new("auditpol")
            .args(["/get", "/subcategory:Logon"])
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("Success") || stdout.contains("Failure")
            })
            .unwrap_or(false);
        
        AuditPolicyState {
            process_creation,
            command_line_logging: command_line,
            logon_events,
        }
    }
    #[cfg(not(windows))]
    {
        AuditPolicyState {
            process_creation: false,
            command_line_logging: false,
            logon_events: false,
        }
    }
}

/// Check if PowerShell script block logging is enabled
fn check_powershell_logging() -> bool {
    #[cfg(windows)]
    {
        use std::process::Command;
        
        Command::new("reg")
            .args(["query", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", "/v", "EnableScriptBlockLogging"])
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("0x1")
            })
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Try to find which process is holding a port (Windows only, best effort)
#[cfg(windows)]
fn get_port_holder(port: u16) -> Option<u32> {
    use std::process::Command;
    
    // Use netstat to find the process holding the port
    let output = Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .output()
        .ok()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let port_str = format!(":{}", port);
    
    for line in stdout.lines() {
        if line.contains(&port_str) && line.contains("LISTENING") {
            // Last column is PID
            let pid: u32 = line.split_whitespace().last()?.parse().ok()?;
            return Some(pid);
        }
    }
    None
}

#[cfg(not(windows))]
fn get_port_holder(_port: u16) -> Option<u32> {
    None
}

// ============================================================================
// Shared state wrapper for Tauri
// ============================================================================

/// Thread-safe supervisor wrapper for Tauri state
pub struct SupervisorState {
    pub inner: Arc<RwLock<Supervisor>>,
}

impl SupervisorState {
    pub async fn new() -> Result<Self, String> {
        let supervisor = Supervisor::new().await?;
        Ok(Self {
            inner: Arc::new(RwLock::new(supervisor)),
        })
    }
}

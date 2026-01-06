//! Harmless Probe Runner: Verifies End-to-End Telemetry Pipeline
//!
//! Generates benign, safe activity to prove sensors are working:
//! - Process spawn: /bin/echo (Unix) or cmd.exe /c echo (Windows)  
//! - Temp file write: small file in system temp directory
//! - Localhost connect: TCP connection to 127.0.0.1:0 (ephemeral)
//!
//! All actions are safe, benign, and should not trigger security alerts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use uuid::Uuid;

// ============================================================================
// Probe Configuration
// ============================================================================

/// Probe specification: what actions to perform
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeSpec {
    /// Spawn a benign process (e.g., echo)
    #[serde(default = "default_true")]
    pub do_process_spawn: bool,

    /// Write a small temp file
    #[serde(default = "default_true")]
    pub do_temp_file_write: bool,

    /// Connect to localhost on an ephemeral port
    #[serde(default = "default_true")]
    pub do_localhost_connect: bool,

    /// Timeout for all probe actions (ms)
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,

    /// Number of times to repeat each action (for reliability)
    #[serde(default = "default_repeats")]
    pub repeats: u32,
}

fn default_true() -> bool {
    true
}
fn default_timeout() -> u64 {
    5000
}
fn default_repeats() -> u32 {
    1
}

impl Default for ProbeSpec {
    fn default() -> Self {
        Self {
            do_process_spawn: true,
            do_temp_file_write: true,
            do_localhost_connect: true,
            timeout_ms: 5000,
            repeats: 1,
        }
    }
}

// ============================================================================
// Probe Result Types
// ============================================================================

/// Correlation fingerprints for robust matching
/// Don't rely only on "echo" commandline; match by time window + paths + ports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeCorrelationFingerprints {
    /// Probe time window (start, end + grace period)
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    /// Temp file path pattern (e.g., "/tmp/edr-probe-*.tmp")
    pub temp_file_path: Option<String>,
    /// Localhost port used for network probe
    pub localhost_port: Option<u16>,
    /// Command used for process spawn
    pub process_command: Option<String>,
    /// Process arguments
    pub process_args: Option<String>,
}

/// Result of a probe run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Unique probe ID
    pub probe_id: String,
    /// When the probe started
    pub started_at: DateTime<Utc>,
    /// When the probe completed
    pub completed_at: DateTime<Utc>,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Actions attempted
    pub actions_attempted: Vec<ProbeAction>,
    /// Events observed (populated by caller after waiting)
    pub observed_events: Vec<ObservedEventSummary>,
    /// Streams that matched probe activity
    pub matched_streams: Vec<String>,
    /// Overall success
    pub success: bool,
    /// Failure reasons if not successful
    pub failure_reasons: Vec<String>,
    /// Correlation fingerprints for robust matching
    pub fingerprints: ProbeCorrelationFingerprints,
    /// Match result with partial success details
    pub match_result: Option<ProbeMatchResult>,
    /// Marker: probe events bypass throttle summary generation
    /// (Tier0-ish priority to avoid probe failing when system is throttling)
    pub throttle_bypass_marker: String,
}

/// Result of correlating probe actions with observed events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeMatchResult {
    /// How many of 3 probe actions were observed
    pub actions_observed: u32,
    /// How many of 3 probe actions were attempted
    pub actions_attempted: u32,
    /// Per-action match status
    pub per_action: Vec<ActionMatchStatus>,
    /// Overall match success (all attempted actions observed)
    pub full_match: bool,
    /// Partial match (at least 1 action observed)
    pub partial_match: bool,
    /// Human-readable summary
    pub summary: String,
    /// Recommended fixes if not full match
    pub recommended_fixes: Vec<String>,
}

/// Match status for a single probe action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionMatchStatus {
    pub action_type: ProbeActionType,
    pub action_success: bool,
    pub event_observed: bool,
    pub match_reason: Option<String>,
    pub no_match_reason: Option<String>,
}

/// A single probe action performed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeAction {
    pub action_type: ProbeActionType,
    pub description: String,
    pub success: bool,
    pub error: Option<String>,
    /// Details about what was done
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeActionType {
    ProcessSpawn,
    TempFileWrite,
    LocalhostConnect,
}

impl ProbeActionType {
    pub fn expected_streams(&self) -> Vec<&'static str> {
        match self {
            Self::ProcessSpawn => vec!["process_exec", "process_exit"],
            Self::TempFileWrite => vec!["file_write"],
            Self::LocalhostConnect => vec!["network_connect"],
        }
    }
}

/// Summary of an observed event (from the event sink)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedEventSummary {
    pub stream_id: String,
    pub timestamp: DateTime<Utc>,
    /// Whether this matched probe activity
    pub matched_probe: bool,
    /// Correlation hint (e.g., matched PID, matched path)
    pub correlation: Option<String>,
}

// ============================================================================
// Probe Runner
// ============================================================================

/// Runs probes and collects results
pub struct ProbeRunner {
    /// Event sink for observing results (optional, for testing)
    #[allow(dead_code)]
    event_observer: Option<mpsc::Sender<ObservedEventSummary>>,
}

impl ProbeRunner {
    pub fn new() -> Self {
        Self {
            event_observer: None,
        }
    }

    /// Create with an event observer for testing
    #[allow(dead_code)]
    pub fn with_observer(observer: mpsc::Sender<ObservedEventSummary>) -> Self {
        Self {
            event_observer: Some(observer),
        }
    }

    /// Run the probe with given spec
    pub async fn run(&self, spec: &ProbeSpec) -> ProbeResult {
        let probe_id = Uuid::new_v4().to_string();
        let started_at = Utc::now();
        let start_instant = Instant::now();
        let timeout = Duration::from_millis(spec.timeout_ms);

        let mut actions = Vec::new();
        let mut failure_reasons = Vec::new();

        // Run each probe action
        for _ in 0..spec.repeats {
            if spec.do_process_spawn {
                let result = tokio::time::timeout(timeout, self.probe_process_spawn()).await;

                match result {
                    Ok(action) => {
                        if !action.success {
                            if let Some(ref err) = action.error {
                                failure_reasons.push(format!("process_spawn: {}", err));
                            }
                        }
                        actions.push(action);
                    }
                    Err(_) => {
                        actions.push(ProbeAction {
                            action_type: ProbeActionType::ProcessSpawn,
                            description: "Spawn echo process".to_string(),
                            success: false,
                            error: Some("Timeout".to_string()),
                            details: HashMap::new(),
                        });
                        failure_reasons.push("process_spawn: timeout".to_string());
                    }
                }
            }

            if spec.do_temp_file_write {
                let result =
                    tokio::time::timeout(timeout, self.probe_temp_file_write(&probe_id)).await;

                match result {
                    Ok(action) => {
                        if !action.success {
                            if let Some(ref err) = action.error {
                                failure_reasons.push(format!("temp_file_write: {}", err));
                            }
                        }
                        actions.push(action);
                    }
                    Err(_) => {
                        actions.push(ProbeAction {
                            action_type: ProbeActionType::TempFileWrite,
                            description: "Write temp file".to_string(),
                            success: false,
                            error: Some("Timeout".to_string()),
                            details: HashMap::new(),
                        });
                        failure_reasons.push("temp_file_write: timeout".to_string());
                    }
                }
            }

            if spec.do_localhost_connect {
                let result = tokio::time::timeout(timeout, self.probe_localhost_connect()).await;

                match result {
                    Ok(action) => {
                        if !action.success {
                            if let Some(ref err) = action.error {
                                failure_reasons.push(format!("localhost_connect: {}", err));
                            }
                        }
                        actions.push(action);
                    }
                    Err(_) => {
                        actions.push(ProbeAction {
                            action_type: ProbeActionType::LocalhostConnect,
                            description: "Connect to localhost".to_string(),
                            success: false,
                            error: Some("Timeout".to_string()),
                            details: HashMap::new(),
                        });
                        failure_reasons.push("localhost_connect: timeout".to_string());
                    }
                }
            }
        }

        let completed_at = Utc::now();
        let duration_ms = start_instant.elapsed().as_millis() as u64;

        // Determine which streams should have been triggered
        let expected_streams: Vec<String> = actions
            .iter()
            .filter(|a| a.success)
            .flat_map(|a| a.action_type.expected_streams())
            .map(|s| s.to_string())
            .collect();

        // Success if all actions succeeded
        let success = actions.iter().all(|a| a.success) && !actions.is_empty();

        // Build correlation fingerprints from action details
        let fingerprints = Self::build_fingerprints(&actions, started_at, completed_at);

        ProbeResult {
            probe_id,
            started_at,
            completed_at,
            duration_ms,
            actions_attempted: actions,
            observed_events: Vec::new(), // Populated by caller
            matched_streams: expected_streams,
            success,
            failure_reasons,
            fingerprints,
            match_result: None, // Populated by correlate_events_robust
            throttle_bypass_marker: "probe_events_bypass_summary".to_string(), // Probe events bypass throttle summaries
        }
    }

    /// Build correlation fingerprints from action details
    fn build_fingerprints(
        actions: &[ProbeAction],
        started_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
    ) -> ProbeCorrelationFingerprints {
        let mut temp_file_path = None;
        let mut localhost_port = None;
        let mut process_command = None;
        let mut process_args = None;

        for action in actions {
            match action.action_type {
                ProbeActionType::TempFileWrite => {
                    if let Some(path) = action.details.get("path") {
                        temp_file_path = Some(path.clone());
                    }
                }
                ProbeActionType::LocalhostConnect => {
                    if let Some(addr) = action.details.get("listen_addr") {
                        // Extract port from "127.0.0.1:PORT"
                        if let Some(port_str) = addr.split(':').next_back() {
                            if let Ok(port) = port_str.parse::<u16>() {
                                localhost_port = Some(port);
                            }
                        }
                    }
                }
                ProbeActionType::ProcessSpawn => {
                    if let Some(cmd) = action.details.get("command") {
                        process_command = Some(cmd.clone());
                    }
                    if let Some(args) = action.details.get("args") {
                        process_args = Some(args.clone());
                    }
                }
            }
        }

        ProbeCorrelationFingerprints {
            time_window_start: started_at,
            time_window_end: completed_at + chrono::Duration::seconds(2), // 2s grace
            temp_file_path,
            localhost_port,
            process_command,
            process_args,
        }
    }

    /// Spawn a benign process
    async fn probe_process_spawn(&self) -> ProbeAction {
        use std::process::Command;

        let mut details = HashMap::new();

        #[cfg(unix)]
        let (cmd, args) = ("/bin/echo", vec!["edr-probe-test"]);

        #[cfg(windows)]
        let (cmd, args) = ("cmd.exe", vec!["/c", "echo", "edr-probe-test"]);

        details.insert("command".to_string(), cmd.to_string());
        details.insert("args".to_string(), args.join(" "));

        // Use spawn_blocking to run the process without blocking the async runtime
        let cmd_str = cmd.to_string();
        let args_clone: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        let result =
            tokio::task::spawn_blocking(move || Command::new(&cmd_str).args(&args_clone).output())
                .await;

        match result {
            Ok(Ok(output)) => {
                details.insert(
                    "exit_code".to_string(),
                    output.status.code().unwrap_or(-1).to_string(),
                );
                details.insert("stdout_len".to_string(), output.stdout.len().to_string());

                ProbeAction {
                    action_type: ProbeActionType::ProcessSpawn,
                    description: format!("Spawned {} {}", cmd, args.join(" ")),
                    success: output.status.success(),
                    error: if output.status.success() {
                        None
                    } else {
                        Some(format!("Exit code: {:?}", output.status.code()))
                    },
                    details,
                }
            }
            Ok(Err(e)) => ProbeAction {
                action_type: ProbeActionType::ProcessSpawn,
                description: format!("Failed to spawn {}", cmd),
                success: false,
                error: Some(e.to_string()),
                details,
            },
            Err(e) => ProbeAction {
                action_type: ProbeActionType::ProcessSpawn,
                description: format!("Failed to spawn {}", cmd),
                success: false,
                error: Some(format!("Task join error: {}", e)),
                details,
            },
        }
    }

    /// Write a small temp file
    async fn probe_temp_file_write(&self, probe_id: &str) -> ProbeAction {
        let mut details = HashMap::new();

        let temp_dir = std::env::temp_dir();
        let file_name = format!("edr-probe-{}.tmp", &probe_id[..8]);
        let file_path = temp_dir.join(&file_name);

        details.insert("path".to_string(), file_path.display().to_string());

        let content = format!(
            "EDR Desktop Probe Test\nProbe ID: {}\nTimestamp: {}\n",
            probe_id,
            Utc::now().to_rfc3339()
        );
        details.insert("content_len".to_string(), content.len().to_string());

        match tokio::fs::write(&file_path, &content).await {
            Ok(()) => {
                // Clean up
                let _ = tokio::fs::remove_file(&file_path).await;
                details.insert("cleaned_up".to_string(), "true".to_string());

                ProbeAction {
                    action_type: ProbeActionType::TempFileWrite,
                    description: format!(
                        "Wrote {} bytes to {}",
                        content.len(),
                        file_path.display()
                    ),
                    success: true,
                    error: None,
                    details,
                }
            }
            Err(e) => ProbeAction {
                action_type: ProbeActionType::TempFileWrite,
                description: format!("Failed to write {}", file_path.display()),
                success: false,
                error: Some(e.to_string()),
                details,
            },
        }
    }

    /// Connect to localhost on an ephemeral port
    async fn probe_localhost_connect(&self) -> ProbeAction {
        let mut details = HashMap::new();

        // Bind a listener to get a free port, then connect to it
        match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => {
                let addr = listener.local_addr().unwrap();
                details.insert("listen_addr".to_string(), addr.to_string());

                // Spawn a task to accept one connection
                let accept_handle = tokio::spawn(async move {
                    let _ = listener.accept().await;
                });

                // Small delay to ensure listener is ready
                tokio::time::sleep(Duration::from_millis(10)).await;

                // Connect to it
                match tokio::net::TcpStream::connect(addr).await {
                    Ok(stream) => {
                        details.insert("connected_to".to_string(), addr.to_string());
                        details.insert(
                            "local_addr".to_string(),
                            stream
                                .local_addr()
                                .map(|a| a.to_string())
                                .unwrap_or_default(),
                        );

                        drop(stream);
                        let _ = accept_handle.await;

                        ProbeAction {
                            action_type: ProbeActionType::LocalhostConnect,
                            description: format!("Connected to {}", addr),
                            success: true,
                            error: None,
                            details,
                        }
                    }
                    Err(e) => {
                        let _ = accept_handle.await;

                        ProbeAction {
                            action_type: ProbeActionType::LocalhostConnect,
                            description: format!("Failed to connect to {}", addr),
                            success: false,
                            error: Some(e.to_string()),
                            details,
                        }
                    }
                }
            }
            Err(e) => ProbeAction {
                action_type: ProbeActionType::LocalhostConnect,
                description: "Failed to bind listener".to_string(),
                success: false,
                error: Some(e.to_string()),
                details,
            },
        }
    }

    /// Notify observer of an event (for testing)
    #[allow(dead_code)]
    pub async fn notify_event(&self, event: ObservedEventSummary) {
        if let Some(ref tx) = self.event_observer {
            let _ = tx.send(event).await;
        }
    }
}

impl Default for ProbeRunner {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Probe Correlation
// ============================================================================

/// Correlate observed events with probe actions (legacy simple version)
#[allow(dead_code)]
pub fn correlate_events(
    probe_result: &ProbeResult,
    events: &[ObservedEventSummary],
) -> ProbeResult {
    let mut result = probe_result.clone();

    // Find which streams had events during the probe window
    let probe_start = probe_result.started_at;
    let probe_end = probe_result.completed_at + chrono::Duration::seconds(2); // 2s grace

    let mut matched_streams = Vec::new();
    let mut observed = Vec::new();

    for event in events {
        if event.timestamp >= probe_start && event.timestamp <= probe_end {
            let mut ev = event.clone();
            ev.matched_probe = true;

            // Check if this stream was expected
            if probe_result.matched_streams.contains(&event.stream_id)
                && !matched_streams.contains(&event.stream_id)
            {
                matched_streams.push(event.stream_id.clone());
            }

            observed.push(ev);
        }
    }

    result.observed_events = observed;
    result.matched_streams = matched_streams;

    result
}

/// Robust correlation that uses fingerprints and returns partial success info
#[allow(dead_code)]
pub fn correlate_events_robust(
    probe_result: &ProbeResult,
    events: &[ObservedEventSummary],
    event_details: Option<&[EventCorrelationDetail]>,
) -> ProbeResult {
    let mut result = probe_result.clone();
    let fingerprints = &probe_result.fingerprints;

    let mut matched_streams = Vec::new();
    let mut observed = Vec::new();
    let mut per_action: Vec<ActionMatchStatus> = Vec::new();
    let mut recommended_fixes: Vec<String> = Vec::new();

    // Match events in the time window
    for event in events {
        if event.timestamp >= fingerprints.time_window_start
            && event.timestamp <= fingerprints.time_window_end
        {
            let mut ev = event.clone();
            ev.matched_probe = true;

            if !matched_streams.contains(&event.stream_id) {
                matched_streams.push(event.stream_id.clone());
            }
            observed.push(ev);
        }
    }

    // Determine match status for each action type
    for action in &probe_result.actions_attempted {
        let expected_streams = action.action_type.expected_streams();
        let streams_found: Vec<&str> = expected_streams
            .iter()
            .filter(|s| matched_streams.contains(&s.to_string()))
            .cloned()
            .collect();

        let event_observed = !streams_found.is_empty();
        let mut match_reason = None;
        let mut no_match_reason = None;

        // Try to match using fingerprints for more robust correlation
        match action.action_type {
            ProbeActionType::ProcessSpawn => {
                if event_observed {
                    match_reason = Some("process stream event in time window".to_string());
                } else if action.success {
                    no_match_reason = Some("process spawned successfully but no event observed - check sensor/throttle".to_string());
                    recommended_fixes
                        .push("Verify process sensor is enabled and not throttled".to_string());
                } else {
                    no_match_reason = Some(format!("process spawn failed: {:?}", action.error));
                }
            }
            ProbeActionType::TempFileWrite => {
                if event_observed {
                    // If we have detailed correlation, check the path
                    let path_matched = if let (Some(details), Some(expected_path)) =
                        (event_details, fingerprints.temp_file_path.as_ref())
                    {
                        details.iter().any(|d| {
                            d.action_type == "file_write"
                                && d.observed_path.as_ref() == Some(expected_path)
                        })
                    } else {
                        false
                    };

                    if path_matched {
                        match_reason = Some(format!(
                            "file write to {} observed",
                            fingerprints.temp_file_path.as_deref().unwrap_or("temp")
                        ));
                    } else {
                        match_reason = Some(
                            "file stream event in time window (path not verified)".to_string(),
                        );
                    }
                } else if action.success {
                    no_match_reason = Some(
                        "file written successfully but no event observed - check file sensor"
                            .to_string(),
                    );
                    recommended_fixes
                        .push("Verify file sensor is enabled for temp directory".to_string());
                } else {
                    no_match_reason = Some(format!("file write failed: {:?}", action.error));
                }
            }
            ProbeActionType::LocalhostConnect => {
                if event_observed {
                    // If we have detailed correlation, check the port
                    let expected_port = fingerprints.localhost_port;
                    let port_matched = if let (Some(details), Some(exp_port)) =
                        (event_details, expected_port)
                    {
                        details.iter().any(|d| {
                            d.action_type == "network_connect" && d.observed_port == Some(exp_port)
                        })
                    } else {
                        false
                    };

                    if port_matched {
                        match_reason = Some(format!(
                            "network connect to port {} observed",
                            expected_port.unwrap()
                        ));
                    } else {
                        match_reason = Some(
                            "network stream event in time window (port not verified)".to_string(),
                        );
                    }
                } else if action.success {
                    no_match_reason = Some(
                        "localhost connect succeeded but no event observed - check network sensor"
                            .to_string(),
                    );
                    recommended_fixes.push(
                        "Verify network sensor is enabled for localhost connections".to_string(),
                    );
                } else {
                    no_match_reason = Some(format!("localhost connect failed: {:?}", action.error));
                }
            }
        }

        per_action.push(ActionMatchStatus {
            action_type: action.action_type,
            action_success: action.success,
            event_observed,
            match_reason,
            no_match_reason,
        });
    }

    // Calculate match statistics
    let actions_attempted = per_action.len();
    let actions_observed = per_action.iter().filter(|a| a.event_observed).count();

    let full_match = actions_attempted > 0 && actions_observed == actions_attempted;
    let partial_match = actions_observed > 0 && actions_observed < actions_attempted;

    let summary = if full_match {
        format!(
            "All {} probe actions observed in telemetry",
            actions_attempted
        )
    } else if partial_match {
        format!(
            "{}/{} probe actions observed - partial success",
            actions_observed, actions_attempted
        )
    } else if actions_attempted == 0 {
        "No probe actions attempted".to_string()
    } else {
        "No probe actions observed in telemetry".to_string()
    };

    // Remove duplicate fixes
    recommended_fixes.sort();
    recommended_fixes.dedup();

    result.observed_events = observed;
    result.matched_streams = matched_streams;
    result.match_result = Some(ProbeMatchResult {
        actions_observed: actions_observed as u32,
        actions_attempted: actions_attempted as u32,
        per_action,
        full_match,
        partial_match,
        summary,
        recommended_fixes,
    });

    result
}

/// Detailed event information for robust correlation
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct EventCorrelationDetail {
    pub action_type: String,
    pub observed_path: Option<String>,
    pub observed_port: Option<u16>,
    pub observed_command: Option<String>,
}

// ============================================================================
// Fake Event Sink for Testing
// ============================================================================

/// Fake event sink that simulates events for testing
#[cfg(test)]
pub mod test_support {
    use super::*;

    /// Generate fake events for a probe
    pub fn generate_fake_events(probe_result: &ProbeResult) -> Vec<ObservedEventSummary> {
        let mut events = Vec::new();
        let now = Utc::now();

        for action in &probe_result.actions_attempted {
            if action.success {
                for stream in action.action_type.expected_streams() {
                    events.push(ObservedEventSummary {
                        stream_id: stream.to_string(),
                        timestamp: now,
                        matched_probe: true,
                        correlation: Some(format!("probe:{}", probe_result.probe_id)),
                    });
                }
            }
        }

        events
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_probe_spec_defaults() {
        let spec = ProbeSpec::default();
        assert!(spec.do_process_spawn);
        assert!(spec.do_temp_file_write);
        assert!(spec.do_localhost_connect);
        assert_eq!(spec.timeout_ms, 5000);
        assert_eq!(spec.repeats, 1);
    }

    #[tokio::test]
    async fn test_probe_runner_process_spawn() {
        let runner = ProbeRunner::new();
        let spec = ProbeSpec {
            do_process_spawn: true,
            do_temp_file_write: false,
            do_localhost_connect: false,
            timeout_ms: 5000,
            repeats: 1,
        };

        let result = runner.run(&spec).await;

        assert!(!result.probe_id.is_empty());
        assert_eq!(result.actions_attempted.len(), 1);
        assert!(result.actions_attempted[0].success);
        assert_eq!(
            result.actions_attempted[0].action_type,
            ProbeActionType::ProcessSpawn
        );
    }

    #[tokio::test]
    async fn test_probe_runner_temp_file() {
        let runner = ProbeRunner::new();
        let spec = ProbeSpec {
            do_process_spawn: false,
            do_temp_file_write: true,
            do_localhost_connect: false,
            timeout_ms: 5000,
            repeats: 1,
        };

        let result = runner.run(&spec).await;

        assert_eq!(result.actions_attempted.len(), 1);
        assert!(result.actions_attempted[0].success);
        assert_eq!(
            result.actions_attempted[0].action_type,
            ProbeActionType::TempFileWrite
        );

        // Verify cleanup
        assert_eq!(
            result.actions_attempted[0].details.get("cleaned_up"),
            Some(&"true".to_string())
        );
    }

    #[tokio::test]
    async fn test_probe_runner_localhost_connect() {
        let runner = ProbeRunner::new();
        let spec = ProbeSpec {
            do_process_spawn: false,
            do_temp_file_write: false,
            do_localhost_connect: true,
            timeout_ms: 5000,
            repeats: 1,
        };

        let result = runner.run(&spec).await;

        assert_eq!(result.actions_attempted.len(), 1);
        assert!(result.actions_attempted[0].success);
        assert_eq!(
            result.actions_attempted[0].action_type,
            ProbeActionType::LocalhostConnect
        );
    }

    #[tokio::test]
    async fn test_probe_runner_full() {
        let runner = ProbeRunner::new();
        let spec = ProbeSpec::default();

        let result = runner.run(&spec).await;

        assert_eq!(result.actions_attempted.len(), 3);
        assert!(result.success);
        assert!(result.failure_reasons.is_empty());

        // Should expect all streams
        assert!(result.matched_streams.contains(&"process_exec".to_string()));
        assert!(result.matched_streams.contains(&"file_write".to_string()));
        assert!(result
            .matched_streams
            .contains(&"network_connect".to_string()));
    }

    #[tokio::test]
    async fn test_correlate_events() {
        let runner = ProbeRunner::new();
        let spec = ProbeSpec::default();
        let probe_result = runner.run(&spec).await;

        // Generate fake events
        let events = test_support::generate_fake_events(&probe_result);

        // Correlate
        let correlated = correlate_events(&probe_result, &events);

        assert!(!correlated.observed_events.is_empty());
        assert!(correlated.observed_events.iter().all(|e| e.matched_probe));
    }

    #[tokio::test]
    async fn test_expected_streams() {
        assert_eq!(
            ProbeActionType::ProcessSpawn.expected_streams(),
            vec!["process_exec", "process_exit"]
        );
        assert_eq!(
            ProbeActionType::TempFileWrite.expected_streams(),
            vec!["file_write"]
        );
        assert_eq!(
            ProbeActionType::LocalhostConnect.expected_streams(),
            vec!["network_connect"]
        );
    }

    #[test]
    fn test_probe_spec_serde() {
        let spec = ProbeSpec {
            do_process_spawn: false,
            do_temp_file_write: true,
            do_localhost_connect: false,
            timeout_ms: 3000,
            repeats: 2,
        };

        let json = serde_json::to_string(&spec).unwrap();
        let parsed: ProbeSpec = serde_json::from_str(&json).unwrap();

        assert!(!parsed.do_process_spawn);
        assert!(parsed.do_temp_file_write);
        assert_eq!(parsed.timeout_ms, 3000);
        assert_eq!(parsed.repeats, 2);
    }

    #[tokio::test]
    async fn test_probe_builds_fingerprints() {
        let runner = ProbeRunner::new();
        let spec = ProbeSpec::default();
        let result = runner.run(&spec).await;

        // Should have fingerprints populated
        assert!(result.fingerprints.time_window_start <= result.fingerprints.time_window_end);
        assert!(result.fingerprints.temp_file_path.is_some());
        assert!(result.fingerprints.localhost_port.is_some());
        assert!(result.fingerprints.process_command.is_some());

        // Throttle bypass should be set
        assert!(!result.throttle_bypass_marker.is_empty());
    }

    #[tokio::test]
    async fn test_correlate_robust_full_match() {
        let runner = ProbeRunner::new();
        let spec = ProbeSpec::default();
        let probe_result = runner.run(&spec).await;

        // Generate fake events
        let events = test_support::generate_fake_events(&probe_result);

        // Correlate robustly
        let correlated = correlate_events_robust(&probe_result, &events, None);

        assert!(correlated.match_result.is_some());
        let match_result = correlated.match_result.unwrap();

        assert!(match_result.full_match);
        assert!(!match_result.partial_match);
        assert_eq!(
            match_result.actions_observed,
            match_result.actions_attempted
        );
        assert!(match_result.summary.contains("All"));
    }

    #[tokio::test]
    async fn test_correlate_robust_partial_match() {
        let runner = ProbeRunner::new();
        let spec = ProbeSpec::default();
        let probe_result = runner.run(&spec).await;

        // Generate events for only process (not file or network)
        let events = vec![ObservedEventSummary {
            stream_id: "process_exec".to_string(),
            timestamp: probe_result.fingerprints.time_window_start,
            matched_probe: false,
            correlation: None,
        }];

        let correlated = correlate_events_robust(&probe_result, &events, None);

        assert!(correlated.match_result.is_some());
        let match_result = correlated.match_result.unwrap();

        assert!(!match_result.full_match);
        assert!(match_result.partial_match);
        assert!(match_result.actions_observed > 0);
        assert!(match_result.actions_observed < match_result.actions_attempted);
        assert!(match_result.summary.contains("partial"));

        // Should have recommended fixes for unobserved actions
        assert!(!match_result.recommended_fixes.is_empty());
    }

    #[tokio::test]
    async fn test_correlate_robust_no_match() {
        let runner = ProbeRunner::new();
        let spec = ProbeSpec::default();
        let probe_result = runner.run(&spec).await;

        // No events
        let events: Vec<ObservedEventSummary> = vec![];

        let correlated = correlate_events_robust(&probe_result, &events, None);

        assert!(correlated.match_result.is_some());
        let match_result = correlated.match_result.unwrap();

        assert!(!match_result.full_match);
        assert!(!match_result.partial_match);
        assert_eq!(match_result.actions_observed, 0);
        assert!(match_result.summary.contains("No probe actions observed"));
    }
}

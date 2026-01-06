//! Self-Check v2: Structured, Actionable, Evidence-Based Diagnostics
//!
//! Provides a comprehensive diagnostic system for first-run and ongoing health monitoring.
//! Reports collector/sensor health, last-seen events, permissions, throttling impact,
//! and concrete OS-specific remediation steps.

use crate::capture_control::{
    CaptureProfile, StreamPriority, ThrottleController, ThrottleVisibilityState,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ============================================================================
// Diagnostic Response Types
// ============================================================================

/// Full self-check response with structured diagnostics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfCheckResponse {
    /// Application state summary
    pub app_state: AppStateSummary,
    /// Current timestamp
    pub now_ts: DateTime<Utc>,
    /// Per-stream diagnostics
    pub streams: Vec<StreamDiagnostic>,
    /// Per-collector diagnostics
    pub collectors: Vec<CollectorDiagnostic>,
    /// Throttling state (reused from capture_control)
    pub throttling: ThrottleVisibilityState,
    /// Storage health
    pub storage: StorageDiagnostic,
    /// Overall verdict
    pub verdict: SelfCheckVerdict,
    /// Top issues sorted by severity
    pub top_issues: Vec<Issue>,
    /// Recommended actions with priorities
    pub recommended_actions: Vec<RecommendedAction>,
    /// Evidence basis: explains what data sources were used for this check
    pub evidence_basis: EvidenceBasis,
}

/// Explains what data sources were consulted for the self-check
/// Prevents "it says no events but I see events" confusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBasis {
    /// How far back DB queries looked (e.g., "last 10 minutes")
    pub db_query_window_desc: String,
    /// DB query window in seconds
    pub db_query_window_secs: u64,
    /// Whether last_seen came from DB vs in-memory counters
    pub last_seen_source: LastSeenSource,
    /// In-memory counter window description
    pub in_memory_window_desc: String,
    /// In-memory counter window in seconds (typically SUMMARY_WINDOW_SECS)
    pub in_memory_window_secs: u64,
    /// Number of streams checked
    pub streams_checked: usize,
    /// Number of streams with data from DB
    pub streams_with_db_data: usize,
    /// Number of streams with data from in-memory counters
    pub streams_with_memory_data: usize,
}

/// Where last_seen timestamps came from
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LastSeenSource {
    /// From database queries (signals table)
    Database,
    /// From in-memory throttle counters
    InMemoryCounters,
    /// Combined: DB for historical, memory for recent
    Combined,
    /// No data available
    NoData,
}

/// Application state summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStateSummary {
    pub first_run: bool,
    pub capture_profile: CaptureProfile,
    pub telemetry_root: String,
    pub version: String,
    pub os: String,
    pub uptime_secs: u64,
}

/// Overall self-check verdict
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SelfCheckVerdict {
    /// All systems nominal
    Healthy,
    /// Some issues but telemetry is flowing
    Degraded,
    /// Critical issues preventing telemetry
    Blocked,
}

#[allow(dead_code)]
impl SelfCheckVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Blocked => "blocked",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Healthy => "✅",
            Self::Degraded => "⚠️",
            Self::Blocked => "🚫",
        }
    }
}

// ============================================================================
// Stream Diagnostics
// ============================================================================

/// Diagnostic info for a single stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamDiagnostic {
    pub stream_id: String,
    /// Whether this is a critical/Tier-0 stream
    pub is_critical: bool,
    /// Whether enabled in current capture profile
    pub enabled: bool,
    /// Last event timestamp (None if never seen)
    pub last_seen_ts: Option<DateTime<Utc>>,
    /// Approximate recent event rate (events/sec)
    pub event_rate_recent: f64,
    /// Event count in current session
    pub event_count: u64,
    /// Why events might be missing
    pub missing_reason: Option<MissingReason>,
    /// Priority class
    pub priority: StreamPriority,
}

/// Reason why a stream has no/few events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingReason {
    /// No events received yet (possibly normal on startup)
    NoEventsYet,
    /// Disabled by current capture profile
    DisabledByProfile,
    /// Permission denied for the sensor
    PermissionDenied,
    /// Collector/sensor process not running
    CollectorStopped,
    /// Events being throttled/dropped
    Throttled,
    /// Sensor not attached to kernel/OS
    SensorNotAttached,
    /// OS doesn't support this stream
    UnsupportedOS,
    /// Unknown reason
    Unknown,
}

impl MissingReason {
    pub fn description(&self) -> &'static str {
        match self {
            Self::NoEventsYet => "No events received yet (may be normal on startup)",
            Self::DisabledByProfile => "Stream disabled by current capture profile",
            Self::PermissionDenied => "Permission denied for sensor attachment",
            Self::CollectorStopped => "Collector or sensor process not running",
            Self::Throttled => "Events being throttled due to rate limits",
            Self::SensorNotAttached => "Sensor not attached to kernel/OS",
            Self::UnsupportedOS => "This stream is not supported on current OS",
            Self::Unknown => "Unknown reason; manual investigation required",
        }
    }
}

// ============================================================================
// Collector Diagnostics
// ============================================================================

/// Diagnostic info for a collector/sensor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorDiagnostic {
    pub collector_id: String,
    /// Whether this collector should be running
    pub expected_running: bool,
    /// Whether it appears to be running (best-effort)
    pub running: Option<bool>,
    /// Last heartbeat timestamp
    pub last_heartbeat_ts: Option<DateTime<Utc>>,
    /// Permissions status
    pub permissions_status: PermissionsStatus,
    /// Streams this collector provides
    pub provides_streams: Vec<String>,
    /// OS-specific status details
    pub os_details: Option<String>,
}

/// Permission status for a collector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsStatus {
    pub ok: bool,
    pub details: String,
    pub required_capabilities: Vec<String>,
}

// ============================================================================
// Storage Diagnostics
// ============================================================================

/// Storage health diagnostic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDiagnostic {
    /// Database is reachable and writable
    pub db_ok: bool,
    /// Segment directory is writable
    pub segment_dir_ok: bool,
    /// Telemetry root path
    pub telemetry_root: String,
    /// Free space in bytes (if available)
    pub free_space_bytes: Option<u64>,
    /// Free space as percentage (if available)
    pub free_space_pct: Option<f64>,
    /// Low space warning threshold
    pub low_space_warning: bool,
    /// Error message if any
    pub error: Option<String>,
}

// ============================================================================
// Issues and Actions
// ============================================================================

/// An issue found during self-check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub id: String,
    pub severity: IssueSeverity,
    pub title: String,
    pub description: String,
    /// Affected component (stream_id, collector_id, etc.)
    pub affected: Option<String>,
    /// Related action ID
    pub action_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssueSeverity {
    /// Informational only
    Info,
    /// Warning, but not blocking
    Warning,
    /// Error, may block functionality
    Error,
    /// Critical, definitely blocking
    Critical,
}

/// A recommended action to fix issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub id: String,
    pub title: String,
    pub priority: u8,
    /// Short description
    pub summary: String,
    /// OS this applies to (or "all")
    pub os: String,
    /// Whether this requires admin/root
    pub requires_admin: bool,
    /// Whether this can be done automatically
    pub auto_fixable: bool,
}

/// Full action details (returned by /api/selfcheck/actions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDetails {
    pub id: String,
    pub title: String,
    pub summary: String,
    pub os: String,
    pub requires_admin: bool,
    /// Full step-by-step instructions (markdown)
    pub instructions: String,
    /// Command to run if applicable
    pub command: Option<String>,
    /// Link to documentation
    pub doc_link: Option<String>,
}

// ============================================================================
// Diagnostic Engine
// ============================================================================

/// Critical streams that MUST have events for healthy verdict
pub const CRITICAL_STREAMS: &[&str] = &["process_exec", "process_exit"];

/// Expected collectors by OS
pub fn expected_collectors(os: &str) -> Vec<&'static str> {
    match os {
        "macos" => vec!["esf_monitor", "process_monitor"],
        "linux" => vec!["ebpf_monitor", "process_monitor"],
        "windows" => vec!["etw_monitor", "process_monitor"],
        _ => vec!["process_monitor"],
    }
}

/// Streams provided by each collector
pub fn collector_streams(collector_id: &str) -> Vec<&'static str> {
    match collector_id {
        "esf_monitor" | "ebpf_monitor" | "etw_monitor" => vec![
            "process_exec",
            "process_exit",
            "file_write",
            "file_read",
            "network_connect",
            "dns_query",
        ],
        "process_monitor" => vec!["process_exec", "process_exit"],
        _ => vec![],
    }
}

/// Diagnostic engine that builds SelfCheckResponse
pub struct DiagnosticEngine {
    pub telemetry_root: PathBuf,
    pub version: String,
    pub start_time: DateTime<Utc>,
}

impl DiagnosticEngine {
    pub fn new(telemetry_root: PathBuf, version: String) -> Self {
        Self {
            telemetry_root,
            version,
            start_time: Utc::now(),
        }
    }

    /// Run full diagnostics
    pub fn run_diagnostics(
        &self,
        first_run: bool,
        throttle_controller: &ThrottleController,
        stream_stats: &HashMap<String, StreamStats>,
        db_ok: bool,
    ) -> SelfCheckResponse {
        let now = Utc::now();
        let os = Self::detect_os();
        let throttling = throttle_controller.get_visibility_state();
        let profile = throttle_controller.current_profile();
        let config = throttle_controller.current_config();

        // Build stream diagnostics
        let streams = self.diagnose_streams(&throttling, stream_stats, &config.enabled_sensors);

        // Build collector diagnostics
        let collectors = self.diagnose_collectors(&os, &config.enabled_sensors);

        // Build storage diagnostics
        let storage = self.diagnose_storage(db_ok);

        // Collect issues
        let mut issues = Vec::new();
        self.collect_stream_issues(&streams, &mut issues);
        self.collect_collector_issues(&collectors, &mut issues);
        self.collect_throttle_issues(&throttling, &mut issues);
        self.collect_storage_issues(&storage, &mut issues);

        // Sort issues by severity (highest first)
        issues.sort_by(|a, b| b.severity.cmp(&a.severity));

        // Determine verdict
        let verdict = self.determine_verdict(&streams, &throttling, &storage, &issues);

        // Generate recommended actions
        let actions = self.generate_actions(&os, &issues);

        // Build app state
        let app_state = AppStateSummary {
            first_run,
            capture_profile: profile,
            telemetry_root: self.telemetry_root.display().to_string(),
            version: self.version.clone(),
            os: os.clone(),
            uptime_secs: (now - self.start_time).num_seconds().max(0) as u64,
        };

        // Build evidence basis
        let streams_with_db = stream_stats
            .values()
            .filter(|s| s.last_seen_ts.is_some())
            .count();
        let streams_with_memory = throttling
            .stream_stats
            .values()
            .filter(|s| s.counters.accepted > 0)
            .count();

        let last_seen_source = match (streams_with_db > 0, streams_with_memory > 0) {
            (true, true) => LastSeenSource::Combined,
            (true, false) => LastSeenSource::Database,
            (false, true) => LastSeenSource::InMemoryCounters,
            (false, false) => LastSeenSource::NoData,
        };

        let evidence_basis = EvidenceBasis {
            db_query_window_desc: "last 10 minutes (signals table MAX(ts) by type)".to_string(),
            db_query_window_secs: 600, // 10 minutes
            last_seen_source,
            in_memory_window_desc: "last 30 seconds (throttle controller counters)".to_string(),
            in_memory_window_secs: 30, // SUMMARY_WINDOW_SECS
            streams_checked: streams.len(),
            streams_with_db_data: streams_with_db,
            streams_with_memory_data: streams_with_memory,
        };

        SelfCheckResponse {
            app_state,
            now_ts: now,
            streams,
            collectors,
            throttling,
            storage,
            verdict,
            top_issues: issues.into_iter().take(10).collect(),
            recommended_actions: actions,
            evidence_basis,
        }
    }

    fn detect_os() -> String {
        if cfg!(target_os = "macos") {
            "macos".to_string()
        } else if cfg!(target_os = "linux") {
            "linux".to_string()
        } else if cfg!(target_os = "windows") {
            "windows".to_string()
        } else {
            "unknown".to_string()
        }
    }

    fn diagnose_streams(
        &self,
        throttling: &ThrottleVisibilityState,
        stream_stats: &HashMap<String, StreamStats>,
        enabled_sensors: &[String],
    ) -> Vec<StreamDiagnostic> {
        let all_streams = vec![
            "process_exec",
            "process_exit",
            "file_write",
            "file_read",
            "file_write_critical",
            "network_connect",
            "dns_query",
            "registry_write",
            "registry_read",
            "module_load",
        ];

        all_streams
            .iter()
            .map(|&stream_id| {
                let is_critical = CRITICAL_STREAMS.contains(&stream_id);
                let stats = throttling.stream_stats.get(stream_id);
                let stored_stats = stream_stats.get(stream_id);

                // Determine if enabled by profile
                let enabled = self.stream_enabled_by_profile(stream_id, enabled_sensors);

                // Get counters
                let (event_count, event_rate) = stats
                    .map(|s| (s.counters.accepted, s.counters.accepted as f64 / 60.0))
                    .unwrap_or((0, 0.0));

                // Get last seen from stored stats
                let last_seen_ts = stored_stats.and_then(|s| s.last_seen_ts);

                // Determine priority
                let priority = stats.map(|s| s.priority).unwrap_or(StreamPriority::Normal);

                // Determine missing reason
                let missing_reason = if event_count > 0 {
                    None
                } else if !enabled {
                    Some(MissingReason::DisabledByProfile)
                } else if stats.map(|s| s.counters.dropped > 0).unwrap_or(false) {
                    Some(MissingReason::Throttled)
                } else {
                    Some(MissingReason::NoEventsYet)
                };

                StreamDiagnostic {
                    stream_id: stream_id.to_string(),
                    is_critical,
                    enabled,
                    last_seen_ts,
                    event_rate_recent: event_rate,
                    event_count,
                    missing_reason,
                    priority,
                }
            })
            .collect()
    }

    fn stream_enabled_by_profile(&self, stream_id: &str, enabled_sensors: &[String]) -> bool {
        // Map streams to sensors
        let sensor = match stream_id {
            "process_exec" | "process_exit" => "process_monitor",
            "file_write" | "file_read" | "file_write_critical" => "file_monitor",
            "network_connect" | "dns_query" => "network_monitor",
            "registry_write" | "registry_read" => "registry_monitor",
            "module_load" => "dll_monitor",
            _ => return true, // Unknown streams default to enabled
        };

        enabled_sensors.iter().any(|s| s.contains(sensor))
    }

    fn diagnose_collectors(
        &self,
        os: &str,
        enabled_sensors: &[String],
    ) -> Vec<CollectorDiagnostic> {
        expected_collectors(os)
            .iter()
            .map(|&collector_id| {
                let expected_running = enabled_sensors.iter().any(|_s| {
                    collector_streams(collector_id)
                        .iter()
                        .any(|stream| self.stream_enabled_by_profile(stream, enabled_sensors))
                });

                let (running, permissions_status, os_details) =
                    self.check_collector_status(collector_id, os);

                CollectorDiagnostic {
                    collector_id: collector_id.to_string(),
                    expected_running,
                    running,
                    last_heartbeat_ts: None, // TODO: implement heartbeat tracking
                    permissions_status,
                    provides_streams: collector_streams(collector_id)
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                    os_details,
                }
            })
            .collect()
    }

    fn check_collector_status(
        &self,
        collector_id: &str,
        os: &str,
    ) -> (Option<bool>, PermissionsStatus, Option<String>) {
        // Best-effort status check
        match (collector_id, os) {
            ("esf_monitor", "macos") => {
                let caps = vec![
                    "Full Disk Access".to_string(),
                    "Endpoint Security entitlement".to_string(),
                ];
                (
                    None, // Can't easily detect without process check
                    PermissionsStatus {
                        ok: true, // Assume OK unless we know otherwise
                        details: "Requires Full Disk Access in System Preferences".to_string(),
                        required_capabilities: caps,
                    },
                    Some("macOS Endpoint Security Framework".to_string()),
                )
            }
            ("ebpf_monitor", "linux") => {
                let caps = vec![
                    "CAP_BPF".to_string(),
                    "CAP_SYS_ADMIN".to_string(),
                    "CAP_PERFMON".to_string(),
                ];
                (
                    None,
                    PermissionsStatus {
                        ok: true,
                        details: "Requires CAP_BPF or root for eBPF attachment".to_string(),
                        required_capabilities: caps,
                    },
                    Some("Linux eBPF sensors".to_string()),
                )
            }
            ("etw_monitor", "windows") => {
                let caps = vec![
                    "Administrator".to_string(),
                    "Performance Log Users group".to_string(),
                ];
                (
                    None,
                    PermissionsStatus {
                        ok: true,
                        details: "Requires Administrator or Performance Log Users membership"
                            .to_string(),
                        required_capabilities: caps,
                    },
                    Some("Windows ETW tracing".to_string()),
                )
            }
            ("process_monitor", _) => {
                (
                    Some(true), // Basic process monitoring usually works
                    PermissionsStatus {
                        ok: true,
                        details: "Basic process monitoring typically available".to_string(),
                        required_capabilities: vec![],
                    },
                    None,
                )
            }
            _ => (
                None,
                PermissionsStatus {
                    ok: true,
                    details: "Unknown collector".to_string(),
                    required_capabilities: vec![],
                },
                None,
            ),
        }
    }

    fn diagnose_storage(&self, db_ok: bool) -> StorageDiagnostic {
        let segment_dir = self.telemetry_root.join("segments");
        let segment_dir_ok = segment_dir.exists() || std::fs::create_dir_all(&segment_dir).is_ok();

        // Try to get free space (best-effort)
        let (free_space_bytes, free_space_pct) = self.get_free_space();
        let low_space_warning = free_space_pct.map(|p| p < 10.0).unwrap_or(false);

        StorageDiagnostic {
            db_ok,
            segment_dir_ok,
            telemetry_root: self.telemetry_root.display().to_string(),
            free_space_bytes,
            free_space_pct,
            low_space_warning,
            error: if !db_ok {
                Some("Database not accessible".to_string())
            } else if !segment_dir_ok {
                Some("Cannot create segment directory".to_string())
            } else {
                None
            },
        }
    }

    fn get_free_space(&self) -> (Option<u64>, Option<f64>) {
        // Best-effort disk space check
        // For now, return None - can add platform-specific implementations later
        // using `fs2` or `nix` crate if needed
        (None, None)
    }

    fn collect_stream_issues(&self, streams: &[StreamDiagnostic], issues: &mut Vec<Issue>) {
        for stream in streams {
            if stream.is_critical && stream.event_count == 0 {
                issues.push(Issue {
                    id: format!("stream_missing_{}", stream.stream_id),
                    severity: IssueSeverity::Critical,
                    title: format!("Critical stream '{}' has no events", stream.stream_id),
                    description: stream
                        .missing_reason
                        .map(|r| r.description().to_string())
                        .unwrap_or_else(|| "No events received".to_string()),
                    affected: Some(stream.stream_id.clone()),
                    action_id: Some("run_probe".to_string()),
                });
            } else if stream.enabled && stream.event_count == 0 && stream.missing_reason.is_some() {
                let severity = if stream.is_critical {
                    IssueSeverity::Error
                } else {
                    IssueSeverity::Warning
                };

                issues.push(Issue {
                    id: format!("stream_empty_{}", stream.stream_id),
                    severity,
                    title: format!("Stream '{}' has no events", stream.stream_id),
                    description: stream
                        .missing_reason
                        .map(|r| r.description().to_string())
                        .unwrap_or_default(),
                    affected: Some(stream.stream_id.clone()),
                    action_id: None,
                });
            }
        }
    }

    fn collect_collector_issues(
        &self,
        collectors: &[CollectorDiagnostic],
        issues: &mut Vec<Issue>,
    ) {
        for collector in collectors {
            if collector.expected_running && collector.running == Some(false) {
                issues.push(Issue {
                    id: format!("collector_stopped_{}", collector.collector_id),
                    severity: IssueSeverity::Error,
                    title: format!("Collector '{}' not running", collector.collector_id),
                    description:
                        "The collector process is not running. Telemetry will not be collected."
                            .to_string(),
                    affected: Some(collector.collector_id.clone()),
                    action_id: Some(format!("start_{}", collector.collector_id)),
                });
            }

            if !collector.permissions_status.ok {
                issues.push(Issue {
                    id: format!("collector_perms_{}", collector.collector_id),
                    severity: IssueSeverity::Error,
                    title: format!("Permissions issue for '{}'", collector.collector_id),
                    description: collector.permissions_status.details.clone(),
                    affected: Some(collector.collector_id.clone()),
                    action_id: Some(format!("fix_perms_{}", collector.collector_id)),
                });
            }
        }
    }

    fn collect_throttle_issues(
        &self,
        throttling: &ThrottleVisibilityState,
        issues: &mut Vec<Issue>,
    ) {
        if throttling.critical_gap {
            issues.push(Issue {
                id: "throttle_critical_gap".to_string(),
                severity: IssueSeverity::Critical,
                title: "Critical visibility gap: Tier-0 streams throttled".to_string(),
                description:
                    "Tier-0 (critical) streams are being throttled. Conclusions may be incomplete."
                        .to_string(),
                affected: None,
                action_id: Some("adjust_throttle".to_string()),
            });
        } else if throttling.degraded {
            issues.push(Issue {
                id: "throttle_degraded".to_string(),
                severity: IssueSeverity::Warning,
                title: "Visibility degraded due to throttling".to_string(),
                description: throttling
                    .degraded_reasons
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Some streams are being throttled".to_string()),
                affected: None,
                action_id: Some("adjust_throttle".to_string()),
            });
        }
    }

    fn collect_storage_issues(&self, storage: &StorageDiagnostic, issues: &mut Vec<Issue>) {
        if !storage.db_ok {
            issues.push(Issue {
                id: "storage_db_error".to_string(),
                severity: IssueSeverity::Critical,
                title: "Database not accessible".to_string(),
                description: "Cannot access the database. Telemetry cannot be stored.".to_string(),
                affected: None,
                action_id: Some("check_storage".to_string()),
            });
        }

        if storage.low_space_warning {
            issues.push(Issue {
                id: "storage_low_space".to_string(),
                severity: IssueSeverity::Warning,
                title: "Low disk space".to_string(),
                description: format!(
                    "Only {:.1}% free space remaining",
                    storage.free_space_pct.unwrap_or(0.0)
                ),
                affected: None,
                action_id: Some("free_space".to_string()),
            });
        }
    }

    fn determine_verdict(
        &self,
        streams: &[StreamDiagnostic],
        throttling: &ThrottleVisibilityState,
        storage: &StorageDiagnostic,
        issues: &[Issue],
    ) -> SelfCheckVerdict {
        // Blocked if storage is broken
        if !storage.db_ok || !storage.segment_dir_ok {
            return SelfCheckVerdict::Blocked;
        }

        // Blocked if no critical streams have events
        let critical_ok = streams
            .iter()
            .filter(|s| s.is_critical)
            .any(|s| s.event_count > 0);

        if !critical_ok {
            // Check if this is first run with no events yet
            let all_zero = streams.iter().all(|s| s.event_count == 0);
            if all_zero {
                return SelfCheckVerdict::Blocked;
            }
        }

        // Degraded if critical gap or any critical issues
        if throttling.critical_gap {
            return SelfCheckVerdict::Degraded;
        }

        if issues.iter().any(|i| i.severity == IssueSeverity::Critical) {
            return SelfCheckVerdict::Blocked;
        }

        if issues.iter().any(|i| i.severity == IssueSeverity::Error) {
            return SelfCheckVerdict::Degraded;
        }

        SelfCheckVerdict::Healthy
    }

    fn generate_actions(&self, os: &str, issues: &[Issue]) -> Vec<RecommendedAction> {
        let mut actions = Vec::new();
        let mut seen_actions = std::collections::HashSet::new();

        // Always recommend probe if no telemetry
        if issues
            .iter()
            .any(|i| i.id.starts_with("stream_missing_") || i.id.starts_with("stream_empty_"))
        {
            actions.push(RecommendedAction {
                id: "run_probe".to_string(),
                title: "Run harmless probe".to_string(),
                priority: 1,
                summary: "Generate benign telemetry to verify the pipeline works end-to-end"
                    .to_string(),
                os: "all".to_string(),
                requires_admin: false,
                auto_fixable: true,
            });
            seen_actions.insert("run_probe".to_string());
        }

        // OS-specific actions
        for issue in issues {
            if let Some(ref action_id) = issue.action_id {
                if seen_actions.contains(action_id) {
                    continue;
                }
                seen_actions.insert(action_id.clone());

                if let Some(action) = self.action_for_id(action_id, os) {
                    actions.push(action);
                }
            }
        }

        // Sort by priority
        actions.sort_by_key(|a| a.priority);
        actions
    }

    fn action_for_id(&self, action_id: &str, os: &str) -> Option<RecommendedAction> {
        match (action_id, os) {
            ("adjust_throttle", _) => Some(RecommendedAction {
                id: "adjust_throttle".to_string(),
                title: "Adjust throttling settings".to_string(),
                priority: 2,
                summary: "Increase rate limits or switch to a different capture profile"
                    .to_string(),
                os: "all".to_string(),
                requires_admin: false,
                auto_fixable: false,
            }),
            ("fix_perms_esf_monitor", "macos") => Some(RecommendedAction {
                id: "fix_perms_esf_monitor".to_string(),
                title: "Grant Full Disk Access".to_string(),
                priority: 2,
                summary: "Open System Preferences > Security & Privacy > Full Disk Access"
                    .to_string(),
                os: "macos".to_string(),
                requires_admin: true,
                auto_fixable: false,
            }),
            ("fix_perms_ebpf_monitor", "linux") => Some(RecommendedAction {
                id: "fix_perms_ebpf_monitor".to_string(),
                title: "Grant eBPF capabilities".to_string(),
                priority: 2,
                summary: "Run with CAP_BPF capability or as root".to_string(),
                os: "linux".to_string(),
                requires_admin: true,
                auto_fixable: false,
            }),
            ("fix_perms_etw_monitor", "windows") => Some(RecommendedAction {
                id: "fix_perms_etw_monitor".to_string(),
                title: "Run as Administrator".to_string(),
                priority: 2,
                summary: "ETW tracing requires Administrator privileges".to_string(),
                os: "windows".to_string(),
                requires_admin: true,
                auto_fixable: false,
            }),
            ("check_storage", _) => Some(RecommendedAction {
                id: "check_storage".to_string(),
                title: "Check storage permissions".to_string(),
                priority: 3,
                summary: "Verify the telemetry directory is writable".to_string(),
                os: "all".to_string(),
                requires_admin: false,
                auto_fixable: false,
            }),
            ("free_space", _) => Some(RecommendedAction {
                id: "free_space".to_string(),
                title: "Free disk space".to_string(),
                priority: 4,
                summary: "Delete old files or move telemetry to a larger disk".to_string(),
                os: "all".to_string(),
                requires_admin: false,
                auto_fixable: false,
            }),
            _ => None,
        }
    }

    /// Get full action details by ID
    pub fn get_action_details(&self, action_id: &str, os: &str) -> Option<ActionDetails> {
        match (action_id, os) {
            ("run_probe", _) => Some(ActionDetails {
                id: "run_probe".to_string(),
                title: "Run harmless probe".to_string(),
                summary: "Generate benign telemetry to verify the pipeline works".to_string(),
                os: "all".to_string(),
                requires_admin: false,
                instructions: r#"
# Running the Harmless Probe

The probe will:
1. Spawn a benign process (echo command)
2. Write a small temporary file
3. Attempt a localhost network connection

This verifies that process, file, and network sensors are working.

## What to expect
- The probe should complete in under 5 seconds
- You should see events appear in the timeline
- If no events appear, check the diagnostic recommendations

## Running manually
Click the "Run Probe" button in the UI, or call:
```
POST /api/selfcheck/probe
```
"#.to_string(),
                command: None,
                doc_link: None,
            }),

            ("fix_perms_esf_monitor", "macos") => Some(ActionDetails {
                id: "fix_perms_esf_monitor".to_string(),
                title: "Grant Full Disk Access (macOS)".to_string(),
                summary: "Required for Endpoint Security Framework".to_string(),
                os: "macos".to_string(),
                requires_admin: true,
                instructions: r#"
# Granting Full Disk Access on macOS

The EDR Desktop app needs Full Disk Access to use the Endpoint Security Framework.

## Steps:
1. Open **System Preferences** (or **System Settings** on macOS Ventura+)
2. Go to **Security & Privacy** > **Privacy**
3. Select **Full Disk Access** in the sidebar
4. Click the lock 🔒 to make changes (enter your password)
5. Click **+** and add the EDR Desktop app
6. Restart EDR Desktop

## Why is this needed?
macOS Endpoint Security Framework requires explicit user consent to monitor
process executions, file operations, and network activity. This is a security
feature to prevent unauthorized monitoring.

## Troubleshooting
If the app still doesn't work after granting access:
- Make sure you added the correct app bundle
- Try removing and re-adding the app
- Reboot your Mac if issues persist
"#.to_string(),
                command: Some("open x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles".to_string()),
                doc_link: Some("https://support.apple.com/guide/mac-help/control-access-to-files-and-folders-on-mac-mchld5a35146/mac".to_string()),
            }),

            ("fix_perms_ebpf_monitor", "linux") => Some(ActionDetails {
                id: "fix_perms_ebpf_monitor".to_string(),
                title: "Grant eBPF capabilities (Linux)".to_string(),
                summary: "Required for eBPF-based monitoring".to_string(),
                os: "linux".to_string(),
                requires_admin: true,
                instructions: r#"
# Granting eBPF Capabilities on Linux

eBPF-based monitoring requires specific Linux capabilities.

## Option 1: Run as root (simplest)
```bash
sudo ./edr-desktop
```

## Option 2: Grant capabilities to the binary (recommended)
```bash
# Grant required capabilities
sudo setcap 'cap_bpf,cap_sys_admin,cap_perfmon+ep' /path/to/edr-desktop

# Verify capabilities were set
getcap /path/to/edr-desktop
```

## Option 3: Use unprivileged eBPF (kernel 5.8+)
On newer kernels, you may be able to use unprivileged eBPF:
```bash
# Check current setting
cat /proc/sys/kernel/unprivileged_bpf_disabled

# Enable unprivileged eBPF (requires root, persists until reboot)
echo 0 | sudo tee /proc/sys/kernel/unprivileged_bpf_disabled
```

## Why is this needed?
eBPF programs run inside the kernel and can observe all system activity.
Linux requires elevated privileges to load eBPF programs for security reasons.

## Troubleshooting
- Check kernel version: `uname -r` (need 4.15+ for basic eBPF, 5.8+ for ring buffers)
- Check if BPF is enabled: `cat /boot/config-$(uname -r) | grep BPF`
- Check dmesg for errors: `dmesg | grep -i bpf`
"#.to_string(),
                command: Some("sudo setcap 'cap_bpf,cap_sys_admin,cap_perfmon+ep' ./edr-desktop".to_string()),
                doc_link: None,
            }),

            ("fix_perms_etw_monitor", "windows") => Some(ActionDetails {
                id: "fix_perms_etw_monitor".to_string(),
                title: "Run as Administrator (Windows)".to_string(),
                summary: "Required for ETW tracing".to_string(),
                os: "windows".to_string(),
                requires_admin: true,
                instructions: r#"
# Running as Administrator on Windows

ETW (Event Tracing for Windows) requires Administrator privileges.

## Steps:
1. Right-click on **EDR Desktop** in the Start menu or on the desktop
2. Select **Run as administrator**
3. Click **Yes** in the UAC prompt

## Alternative: Always run as Administrator
1. Right-click on the EDR Desktop shortcut
2. Select **Properties**
3. Go to the **Compatibility** tab
4. Check **Run this program as an administrator**
5. Click **OK**

## Why is this needed?
ETW tracing allows monitoring of system-wide events including process
creation, file operations, and network activity. Windows requires
Administrator privileges to start ETW sessions for security.

## Alternative: Performance Log Users group
For a more limited approach, add your user to the Performance Log Users group:
1. Open Computer Management (compmgmt.msc)
2. Go to Local Users and Groups > Groups
3. Double-click **Performance Log Users**
4. Add your user account
5. Log out and log back in

Note: This may not grant full ETW access for all providers.
"#.to_string(),
                command: None,
                doc_link: Some("https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal".to_string()),
            }),

            ("adjust_throttle", _) => Some(ActionDetails {
                id: "adjust_throttle".to_string(),
                title: "Adjust throttling settings".to_string(),
                summary: "Modify rate limits to reduce dropped events".to_string(),
                os: "all".to_string(),
                requires_admin: false,
                instructions: r#"
# Adjusting Throttle Settings

If events are being dropped due to throttling, you have several options:

## Option 1: Switch Capture Profile
- **Core**: Lowest resource usage, only critical streams (recommended for laptops)
- **Extended**: More streams, moderate resource usage
- **Forensic**: All streams, highest resource usage (use with caution)

To change: Use the Capture Profile selector in the UI or:
```
POST /api/capture/profile
{"profile": "extended"}
```

## Option 2: Accept some throttling
If only non-critical (Tier-2/3) streams are throttled, this may be acceptable.
Critical Tier-0 streams (process_exec, process_exit) have higher limits.

## Understanding the warning
- **Degraded**: Some non-critical events dropped, core visibility intact
- **Critical Gap**: Tier-0 events dropped, conclusions may be incomplete

## Troubleshooting high event rates
- Check if a process is generating excessive telemetry
- Consider filtering noisy processes in playbooks
- Reduce focus window to analyze shorter time periods
"#.to_string(),
                command: None,
                doc_link: None,
            }),

            ("check_storage", _) => Some(ActionDetails {
                id: "check_storage".to_string(),
                title: "Check storage permissions".to_string(),
                summary: "Verify telemetry directory access".to_string(),
                os: "all".to_string(),
                requires_admin: false,
                instructions: r#"
# Checking Storage Permissions

The EDR Desktop needs write access to store telemetry.

## Check the telemetry directory
The current telemetry root is shown in the diagnostic output.

### On macOS/Linux:
```bash
# Check if directory exists and is writable
ls -la ~/.local/share/attack-workbench/

# Create if missing
mkdir -p ~/.local/share/attack-workbench/

# Check permissions
touch ~/.local/share/attack-workbench/test-write && rm ~/.local/share/attack-workbench/test-write
```

### On Windows:
```powershell
# Check AppData directory
Test-Path "$env:LOCALAPPDATA\attack-workbench"

# Create if missing
New-Item -ItemType Directory -Path "$env:LOCALAPPDATA\attack-workbench" -Force
```

## Common issues
- Directory doesn't exist and can't be created
- Directory exists but is read-only
- Disk is full
- Antivirus blocking writes
"#.to_string(),
                command: None,
                doc_link: None,
            }),

            _ => None,
        }
    }
}

// ============================================================================
// Stream Stats (for integration with DB/in-memory storage)
// ============================================================================

/// Stats from database or in-memory ring buffer
#[derive(Debug, Clone, Default)]
pub struct StreamStats {
    pub last_seen_ts: Option<DateTime<Utc>>,
    pub event_count: u64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture_control::ProfileConfig;

    #[test]
    fn test_verdict_healthy() {
        let engine = DiagnosticEngine::new(PathBuf::from("/tmp/test"), "1.0.0".to_string());

        let throttle = ThrottleController::new(ProfileConfig::for_profile(CaptureProfile::Core));
        let mut stream_stats = HashMap::new();
        stream_stats.insert(
            "process_exec".to_string(),
            StreamStats {
                last_seen_ts: Some(Utc::now()),
                event_count: 100,
            },
        );

        // Simulate some events
        for _ in 0..100 {
            throttle.before_store("process_exec", 100);
        }

        let response = engine.run_diagnostics(false, &throttle, &stream_stats, true);

        assert!(response
            .streams
            .iter()
            .any(|s| s.stream_id == "process_exec"));
    }

    #[test]
    fn test_missing_reason_detection() {
        let reason = MissingReason::DisabledByProfile;
        assert!(reason.description().contains("disabled"));

        let reason = MissingReason::PermissionDenied;
        assert!(reason.description().contains("Permission"));
    }

    #[test]
    fn test_action_details_exist() {
        let engine = DiagnosticEngine::new(PathBuf::from("/tmp/test"), "1.0.0".to_string());

        let action = engine.get_action_details("run_probe", "macos");
        assert!(action.is_some());

        let action = engine.get_action_details("fix_perms_esf_monitor", "macos");
        assert!(action.is_some());
        assert!(action.unwrap().requires_admin);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(IssueSeverity::Critical > IssueSeverity::Error);
        assert!(IssueSeverity::Error > IssueSeverity::Warning);
        assert!(IssueSeverity::Warning > IssueSeverity::Info);
    }
}

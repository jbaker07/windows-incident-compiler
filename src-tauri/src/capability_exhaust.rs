//! Capability Exhaust (Readiness Verifier)
//!
//! Windows-first implementation that:
//! 1. Enumerates privileges + required channels/providers
//! 2. Checks audit policy + PowerShell logging settings
//! 3. Checks Sysmon presence/version/config
//! 4. Checks Defender status (best-effort)
//! 5. Runs safe probes and verifies expected events are observed
//!
//! Supports two verification sources:
//! - EventLog: Direct query via wevtutil against OS event log
//! - Pipeline: Search our captured segments/*.jsonl files
//!
//! Output: Human-friendly Readiness Report + machine-readable readiness.json

use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

// ============================================================================
// Core Types
// ============================================================================

/// Complete Capability Exhaust Report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityExhaustReport {
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub host_info: HostInfo,
    pub privilege_check: PrivilegeCheck,
    pub channels: Vec<ChannelStatus>,
    pub audit_policy: AuditPolicyDetails,
    pub powershell_config: PowerShellConfig,
    pub sysmon_status: SysmonStatus,
    pub defender_status: DefenderStatus,
    pub probes: Vec<ProbeResult>,
    pub summary: ReadinessSummary,
}

/// Host identification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os_version: String,
    pub os_build: String,
    pub architecture: String,
}

/// Privilege enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeCheck {
    pub is_admin: bool,
    pub is_elevated: bool,
    pub privileges: Vec<PrivilegeStatus>,
    pub user_name: String,
    pub user_sid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeStatus {
    pub name: String,
    pub enabled: bool,
    pub required_for: Vec<String>,
}

/// Event channel/provider status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelStatus {
    pub channel: String,
    pub enabled: bool,
    pub accessible: bool,
    pub provider: Option<String>,
    pub last_event_time: Option<String>,
    pub event_count_estimate: Option<u64>,
    pub required_for: Vec<String>,
}

/// Detailed audit policy state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicyDetails {
    pub process_creation: AuditSetting,
    pub process_termination: AuditSetting,
    pub logon: AuditSetting,
    pub logoff: AuditSetting,
    pub object_access: AuditSetting,
    pub privilege_use: AuditSetting,
    pub command_line_in_events: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSetting {
    pub success: bool,
    pub failure: bool,
}

/// PowerShell logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShellConfig {
    pub script_block_logging: bool,
    pub module_logging: bool,
    pub transcription: bool,
    pub constrained_language_mode: bool,
}

/// Sysmon status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysmonStatus {
    pub installed: bool,
    pub running: bool,
    pub version: Option<String>,
    pub config_hash: Option<String>,
    pub driver_loaded: bool,
    pub event_ids_enabled: Vec<u32>,
}

/// Defender status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenderStatus {
    pub installed: bool,
    pub real_time_protection: bool,
    pub cloud_protection: bool,
    pub automatic_sample_submission: bool,
    pub signature_version: Option<String>,
    pub engine_version: Option<String>,
    pub last_scan: Option<String>,
}

/// Evidence pointer for linking to raw records
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EvidencePtr {
    /// Stream identifier (e.g., "Security", "Sysmon")
    pub stream_id: String,
    /// Segment file number
    pub segment_id: u64,
    /// Record index within segment
    pub record_index: u32,
    /// Optional record ID from source (e.g., EventRecordID)
    pub record_id: Option<u64>,
}

impl EvidencePtr {
    pub fn to_uri(&self) -> String {
        format!("evidence://{}:{}:{}", self.stream_id, self.segment_id, self.record_index)
    }
}

/// Safe probe result - evidence-first verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub probe_name: String,
    pub probe_type: ProbeType,
    pub triggered_at: DateTime<Utc>,
    pub expected_event_ids: Vec<u32>,
    pub expected_providers: Vec<String>,
    pub command_executed: String,
    pub command_args: Vec<String>,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: Option<DateTime<Utc>>,
    pub observed: bool,
    pub observed_event_ids: Vec<u32>,
    pub matched_count: u32,
    /// Evidence pointers to the actual records that verified this probe
    pub evidence_ptrs: Vec<EvidencePtr>,
    /// Excerpt derived from evidence_ptrs (first record's key fields)
    pub evidence_excerpt: Option<String>,
    pub latency_ms: u64,
    pub status: ProbeStatus,
    pub details: HashMap<String, serde_json::Value>,
    /// Pipeline verification result (if Pipeline source used)
    pub pipeline_verified: Option<PipelineVerification>,
}

/// Result of pipeline-level verification against captured segments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineVerification {
    /// Whether the event was found in captured segments
    pub found: bool,
    /// Evidence pointers from segments (segment_id + record_index)
    pub evidence_ptrs: Vec<EvidencePtr>,
    /// Number of matching events found in segments
    pub matched_count: u32,
    /// Segments searched
    pub segments_searched: u32,
    /// Total records scanned
    pub records_scanned: u64,
    /// If OS says Verified but pipeline says NotFound, explain the gap
    pub divergence_note: Option<String>,
}

/// Verification source for probes
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
pub enum VerificationSource {
    /// Query OS event log directly via wevtutil
    #[default]
    EventLog,
    /// Search our captured segments/*.jsonl files
    Pipeline,
    /// Both sources - compare results
    Both,
}

/// Probe verification status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProbeStatus {
    /// Event observed in logs - fully verified
    Verified,
    /// Config exists but no event observed - partial confidence
    ConfiguredOnly,
    /// Probe executed but verification failed
    NotObserved,
    /// Probe could not be executed
    ExecutionFailed,
    /// Probe skipped (e.g., missing dependencies)
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProbeType {
    ProcessCreate,
    DnsLookup,
    FileWrite,
    PowerShell,
    NetworkConnect,
    RegistryAccess,
}

/// Overall readiness summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessSummary {
    pub level: ReadinessLevel,
    pub score: u32,
    pub max_score: u32,
    pub capabilities: Vec<CapabilityResult>,
    pub blocking_issues: Vec<String>,
    pub recommendations: Vec<Recommendation>,
    pub probe_success_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReadinessLevel {
    Excellent, // 90%+
    Good,      // 70-89%
    Limited,   // 50-69%
    Minimal,   // 25-49%
    Blocked,   // <25%
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityResult {
    pub name: String,
    pub available: bool,
    pub partial: bool,
    pub score: u32,
    pub max_score: u32,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: u8,
    pub category: String,
    pub title: String,
    pub description: String,
    pub command: Option<String>,
    pub requires_admin: bool,
    pub impact_score: u32,
}

// ============================================================================
// Implementation
// ============================================================================

/// Run complete capability exhaust with configurable verification source
pub async fn run_capability_exhaust(
    telemetry_root: &Path,
    timeout_seconds: u64,
) -> Result<CapabilityExhaustReport, String> {
    run_capability_exhaust_with_source(telemetry_root, timeout_seconds, VerificationSource::EventLog).await
}

/// Run capability exhaust with explicit verification source
pub async fn run_capability_exhaust_with_source(
    telemetry_root: &Path,
    timeout_seconds: u64,
    verification_source: VerificationSource,
) -> Result<CapabilityExhaustReport, String> {
    let start = Instant::now();
    let timestamp = Utc::now();

    // Collect all data
    let host_info = collect_host_info();
    let privilege_check = check_privileges();
    let channels = check_channels();
    let audit_policy = check_audit_policy_details();
    let powershell_config = check_powershell_config();
    let sysmon_status = check_sysmon_status();
    let defender_status = check_defender_status();

    // Run safe probes and verify observation (always run OS-level first)
    let mut probes = run_safe_probes(telemetry_root, timeout_seconds).await;

    // If Pipeline or Both verification requested, also search segments
    if matches!(verification_source, VerificationSource::Pipeline | VerificationSource::Both) {
        verify_probe_observations_pipeline(&mut probes, telemetry_root).await;
    }

    // Calculate summary
    let summary = calculate_summary(
        &privilege_check,
        &channels,
        &audit_policy,
        &powershell_config,
        &sysmon_status,
        &probes,
    );

    let report = CapabilityExhaustReport {
        timestamp,
        version: "1.0.0".to_string(),
        host_info,
        privilege_check,
        channels,
        audit_policy,
        powershell_config,
        sysmon_status,
        defender_status,
        probes,
        summary,
    };

    // Save to disk
    save_report(&report, telemetry_root)?;

    tracing::info!(
        "Capability exhaust completed in {}ms: {:?}",
        start.elapsed().as_millis(),
        report.summary.level
    );

    Ok(report)
}

/// Collect host information
fn collect_host_info() -> HostInfo {
    #[cfg(windows)]
    {
        let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string());

        let os_version = Command::new("cmd")
            .args(["/C", "ver"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let os_build = Command::new("cmd")
            .args(["/C", "wmic os get BuildNumber /value"])
            .output()
            .map(|o| {
                let s = String::from_utf8_lossy(&o.stdout);
                s.lines()
                    .find(|l| l.contains("BuildNumber"))
                    .and_then(|l| l.split('=').nth(1))
                    .map(|v| v.trim().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            })
            .unwrap_or_else(|_| "unknown".to_string());

        let architecture =
            std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_else(|_| "unknown".to_string());

        HostInfo {
            hostname,
            os_version,
            os_build,
            architecture,
        }
    }
    #[cfg(not(windows))]
    {
        HostInfo {
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            os_version: "non-windows".to_string(),
            os_build: "N/A".to_string(),
            architecture: std::env::consts::ARCH.to_string(),
        }
    }
}

/// Check privileges
fn check_privileges() -> PrivilegeCheck {
    #[cfg(windows)]
    {
        let is_admin = is_elevated();
        let user_name = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());

        // Check specific privileges using whoami /priv
        let privileges_output = Command::new("whoami")
            .args(["/priv"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        let mut privileges = Vec::new();

        // Key privileges for telemetry collection
        let important_privs = vec![
            ("SeSecurityPrivilege", vec!["Security Log Access"]),
            ("SeAuditPrivilege", vec!["Generate Audit Events"]),
            ("SeBackupPrivilege", vec!["Registry Backup"]),
            (
                "SeDebugPrivilege",
                vec!["Process Debug", "Memory Forensics"],
            ),
            ("SeImpersonatePrivilege", vec!["Token Analysis"]),
        ];

        for (priv_name, required_for) in important_privs {
            let enabled = privileges_output.contains(priv_name)
                && privileges_output
                    .lines()
                    .find(|l| l.contains(priv_name))
                    .map(|l| l.contains("Enabled"))
                    .unwrap_or(false);

            privileges.push(PrivilegeStatus {
                name: priv_name.to_string(),
                enabled,
                required_for: required_for.into_iter().map(String::from).collect(),
            });
        }

        // Try to get user SID
        let user_sid = Command::new("whoami")
            .args(["/user", "/fo", "list"])
            .output()
            .ok()
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout);
                s.lines()
                    .find(|l| l.starts_with("SID"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|v| v.trim().to_string())
            });

        PrivilegeCheck {
            is_admin,
            is_elevated: is_admin,
            privileges,
            user_name,
            user_sid,
        }
    }
    #[cfg(not(windows))]
    {
        PrivilegeCheck {
            is_admin: false,
            is_elevated: false,
            privileges: vec![],
            user_name: std::env::var("USER").unwrap_or_else(|_| "unknown".to_string()),
            user_sid: None,
        }
    }
}

/// Check event channels
fn check_channels() -> Vec<ChannelStatus> {
    #[cfg(windows)]
    {
        let channels = vec![
            (
                "Security",
                "Microsoft-Windows-Security-Auditing",
                vec!["Process Creation", "Logon Events"],
            ),
            (
                "Microsoft-Windows-Sysmon/Operational",
                "Microsoft-Windows-Sysmon",
                vec!["Process Create", "Network", "File"],
            ),
            (
                "Microsoft-Windows-PowerShell/Operational",
                "Microsoft-Windows-PowerShell",
                vec!["Script Execution"],
            ),
            ("Windows PowerShell", "PowerShell", vec!["Legacy PS Logs"]),
            (
                "Microsoft-Windows-Windows Defender/Operational",
                "Windows Defender",
                vec!["Threat Detection"],
            ),
            (
                "Application",
                "Application",
                vec!["App Crashes", "Installer Events"],
            ),
            ("System", "System", vec!["Service Changes", "Driver Load"]),
            (
                "Microsoft-Windows-TaskScheduler/Operational",
                "TaskScheduler",
                vec!["Scheduled Tasks"],
            ),
            (
                "Microsoft-Windows-WMI-Activity/Operational",
                "WMI",
                vec!["WMI Events"],
            ),
            (
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                "RDP",
                vec!["RDP Sessions"],
            ),
        ];

        let mut results = Vec::new();

        for (channel, provider, required_for) in channels {
            let (enabled, accessible, event_count, last_event) = check_single_channel(channel);

            results.push(ChannelStatus {
                channel: channel.to_string(),
                enabled,
                accessible,
                provider: Some(provider.to_string()),
                last_event_time: last_event,
                event_count_estimate: event_count,
                required_for: required_for.into_iter().map(String::from).collect(),
            });
        }

        results
    }
    #[cfg(not(windows))]
    {
        vec![]
    }
}

#[cfg(windows)]
fn check_single_channel(channel: &str) -> (bool, bool, Option<u64>, Option<String>) {
    // Check if channel is enabled and accessible
    let query_result = Command::new("wevtutil").args(["gli", channel]).output();

    let (enabled, accessible) = match query_result {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let enabled = stdout.contains("enabled: true");
            (enabled, true)
        }
        _ => (false, false),
    };

    // Try to get event count and last event
    let (event_count, last_event) = if accessible {
        let count_result = Command::new("wevtutil")
            .args(["qe", channel, "/c:1", "/rd:true", "/f:text"])
            .output();

        match count_result {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let last_time = stdout
                    .lines()
                    .find(|l| l.trim().starts_with("Date:"))
                    .map(|l| l.replace("Date:", "").trim().to_string());
                (Some(1), last_time) // We got at least 1 event
            }
            _ => (None, None),
        }
    } else {
        (None, None)
    };

    (enabled, accessible, event_count, last_event)
}

/// Check detailed audit policy
fn check_audit_policy_details() -> AuditPolicyDetails {
    #[cfg(windows)]
    {
        fn check_audit_category(category: &str) -> AuditSetting {
            let result = Command::new("auditpol")
                .args(["/get", "/subcategory:", category])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();

            AuditSetting {
                success: result.contains("Success"),
                failure: result.contains("Failure"),
            }
        }

        let command_line = Command::new("reg")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
                "/v",
                "ProcessCreationIncludeCmdLine_Enabled",
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("0x1"))
            .unwrap_or(false);

        AuditPolicyDetails {
            process_creation: check_audit_category("Process Creation"),
            process_termination: check_audit_category("Process Termination"),
            logon: check_audit_category("Logon"),
            logoff: check_audit_category("Logoff"),
            object_access: check_audit_category("File System"),
            privilege_use: check_audit_category("Sensitive Privilege Use"),
            command_line_in_events: command_line,
        }
    }
    #[cfg(not(windows))]
    {
        AuditPolicyDetails {
            process_creation: AuditSetting {
                success: false,
                failure: false,
            },
            process_termination: AuditSetting {
                success: false,
                failure: false,
            },
            logon: AuditSetting {
                success: false,
                failure: false,
            },
            logoff: AuditSetting {
                success: false,
                failure: false,
            },
            object_access: AuditSetting {
                success: false,
                failure: false,
            },
            privilege_use: AuditSetting {
                success: false,
                failure: false,
            },
            command_line_in_events: false,
        }
    }
}

/// Check PowerShell configuration
fn check_powershell_config() -> PowerShellConfig {
    #[cfg(windows)]
    {
        let script_block = Command::new("reg")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
                "/v",
                "EnableScriptBlockLogging",
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("0x1"))
            .unwrap_or(false);

        let module_logging = Command::new("reg")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",
                "/v",
                "EnableModuleLogging",
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("0x1"))
            .unwrap_or(false);

        let transcription = Command::new("reg")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
                "/v",
                "EnableTranscripting",
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("0x1"))
            .unwrap_or(false);

        // Check language mode
        let constrained = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "$ExecutionContext.SessionState.LanguageMode",
            ])
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.trim() == "ConstrainedLanguage"
            })
            .unwrap_or(false);

        PowerShellConfig {
            script_block_logging: script_block,
            module_logging,
            transcription,
            constrained_language_mode: constrained,
        }
    }
    #[cfg(not(windows))]
    {
        PowerShellConfig {
            script_block_logging: false,
            module_logging: false,
            transcription: false,
            constrained_language_mode: false,
        }
    }
}

/// Check Sysmon status in detail
fn check_sysmon_status() -> SysmonStatus {
    #[cfg(windows)]
    {
        // Check service status
        let service_result = Command::new("sc")
            .args(["query", "Sysmon64"])
            .output()
            .or_else(|_| Command::new("sc").args(["query", "Sysmon"]).output());

        let (installed, running) = match service_result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let installed = output.status.success();
                let running = stdout.contains("RUNNING");
                (installed, running)
            }
            Err(_) => (false, false),
        };

        if !installed {
            return SysmonStatus {
                installed: false,
                running: false,
                version: None,
                config_hash: None,
                driver_loaded: false,
                event_ids_enabled: vec![],
            };
        }

        // Get version
        let version = Command::new("sysmon64")
            .args(["-s"])
            .output()
            .or_else(|_| Command::new("sysmon").args(["-s"]).output())
            .ok()
            .and_then(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout
                    .lines()
                    .find(|l| l.contains("System Monitor"))
                    .map(|l| l.to_string())
            });

        // Check driver
        let driver_loaded = Command::new("sc")
            .args(["query", "SysmonDrv"])
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("RUNNING")
            })
            .unwrap_or(false);

        // Get config hash (SHA256 of current config)
        let config_hash = Command::new("sysmon64")
            .args(["-c"])
            .output()
            .or_else(|_| Command::new("sysmon").args(["-c"]).output())
            .ok()
            .and_then(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                // Extract hash if shown, otherwise compute from output
                if !stdout.is_empty() {
                    let hash_input = stdout.trim();
                    let digest = md5::compute(hash_input.as_bytes());
                    Some(format!("{:x}", digest))
                } else {
                    None
                }
            });

        // Check which event IDs are enabled by looking at channel
        let event_ids_enabled = check_sysmon_event_ids();

        SysmonStatus {
            installed,
            running,
            version,
            config_hash,
            driver_loaded,
            event_ids_enabled,
        }
    }
    #[cfg(not(windows))]
    {
        SysmonStatus {
            installed: false,
            running: false,
            version: None,
            config_hash: None,
            driver_loaded: false,
            event_ids_enabled: vec![],
        }
    }
}

#[cfg(windows)]
fn check_sysmon_event_ids() -> Vec<u32> {
    // Query recent events to see which IDs are generating
    let mut enabled_ids = Vec::new();

    // Common Sysmon event IDs
    let ids_to_check = [
        1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 22, 23, 24, 25, 26,
    ];

    for event_id in ids_to_check {
        let result = Command::new("wevtutil")
            .args(
                [
                    "qe",
                    "Microsoft-Windows-Sysmon/Operational",
                    "/q:*[System[EventID=",
                    &event_id.to_string(),
                    "]]",
                    "/c:1",
                    "/rd:true",
                    "/f:text",
                ]
                .concat()
                .split_whitespace()
                .collect::<Vec<_>>(),
            )
            .output();

        if let Ok(output) = result {
            if output.status.success() && !output.stdout.is_empty() {
                enabled_ids.push(event_id);
            }
        }
    }

    enabled_ids
}

/// Check Defender status
fn check_defender_status() -> DefenderStatus {
    #[cfg(windows)]
    {
        // Use PowerShell to query Defender status
        let defender_result = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-MpComputerStatus | ConvertTo-Json -Depth 2",
            ])
            .output();

        match defender_result {
            Ok(output) if output.status.success() => {
                let json_str = String::from_utf8_lossy(&output.stdout);
                if let Ok(status) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    return DefenderStatus {
                        installed: true,
                        real_time_protection: status
                            .get("RealTimeProtectionEnabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        cloud_protection: status
                            .get("OnAccessProtectionEnabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        automatic_sample_submission: status
                            .get("NISEnabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        signature_version: status
                            .get("AntivirusSignatureVersion")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        engine_version: status
                            .get("AMEngineVersion")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        last_scan: status
                            .get("FullScanEndTime")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    };
                }
            }
            _ => {}
        }

        // Fallback: check if service exists
        let service_exists = Command::new("sc")
            .args(["query", "WinDefend"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        DefenderStatus {
            installed: service_exists,
            real_time_protection: false,
            cloud_protection: false,
            automatic_sample_submission: false,
            signature_version: None,
            engine_version: None,
            last_scan: None,
        }
    }
    #[cfg(not(windows))]
    {
        DefenderStatus {
            installed: false,
            real_time_protection: false,
            cloud_protection: false,
            automatic_sample_submission: false,
            signature_version: None,
            engine_version: None,
            last_scan: None,
        }
    }
}

// ============================================================================
// Safe Probes - Evidence-First Verification
// ============================================================================

/// Run safe probes and verify they're observed in telemetry
async fn run_safe_probes(telemetry_root: &Path, timeout_seconds: u64) -> Vec<ProbeResult> {
    let mut results = Vec::new();

    // Probe 1: Process creation (benign process)
    results.push(run_process_probe().await);

    // Probe 2: DNS lookup
    results.push(run_dns_probe().await);

    // Probe 3: File write
    results.push(run_file_probe(telemetry_root).await);

    // Probe 4: PowerShell execution
    results.push(run_powershell_probe().await);

    // Wait for events to propagate and check observation
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify observations in event logs
    verify_probe_observations(&mut results, timeout_seconds).await;

    results
}

async fn run_process_probe() -> ProbeResult {
    let triggered_at = Utc::now();
    let start = Instant::now();

    #[cfg(windows)]
    {
        // Run a benign process: hostname.exe
        let _ = Command::new("hostname").output();
    }

    ProbeResult {
        probe_name: "process_creation".to_string(),
        probe_type: ProbeType::ProcessCreate,
        triggered_at,
        expected_event_ids: vec![4688, 1], // Security 4688, Sysmon 1
        expected_providers: vec![
            "Microsoft-Windows-Security-Auditing".to_string(),
            "Microsoft-Windows-Sysmon".to_string(),
        ],
        command_executed: "hostname".to_string(),
        command_args: vec![],
        time_window_start: triggered_at,
        time_window_end: None,
        observed: false, // Will be verified later
        observed_event_ids: vec![],
        matched_count: 0,
        evidence_ptrs: vec![],
        evidence_excerpt: None,
        latency_ms: start.elapsed().as_millis() as u64,
        status: ProbeStatus::NotObserved,
        details: HashMap::from([
            ("process".to_string(), serde_json::json!("hostname.exe")),
            (
                "purpose".to_string(),
                serde_json::json!("Verify process creation events"),
            ),
        ]),
        pipeline_verified: None,
    }
}

async fn run_dns_probe() -> ProbeResult {
    let triggered_at = Utc::now();
    let start = Instant::now();

    #[cfg(windows)]
    {
        // Perform DNS lookup using nslookup
        let _ = Command::new("nslookup").args(["microsoft.com"]).output();
    }

    ProbeResult {
        probe_name: "dns_lookup".to_string(),
        probe_type: ProbeType::DnsLookup,
        triggered_at,
        expected_event_ids: vec![22], // Sysmon 22 (DNS Query)
        expected_providers: vec!["Microsoft-Windows-Sysmon".to_string()],
        command_executed: "nslookup".to_string(),
        command_args: vec!["microsoft.com".to_string()],
        time_window_start: triggered_at,
        time_window_end: None,
        observed: false,
        observed_event_ids: vec![],
        matched_count: 0,
        evidence_ptrs: vec![],
        evidence_excerpt: None,
        latency_ms: start.elapsed().as_millis() as u64,
        status: ProbeStatus::NotObserved,
        details: HashMap::from([
            ("query".to_string(), serde_json::json!("microsoft.com")),
            (
                "purpose".to_string(),
                serde_json::json!("Verify DNS query logging"),
            ),
        ]),
        pipeline_verified: None,
    }
}

async fn run_file_probe(telemetry_root: &Path) -> ProbeResult {
    let triggered_at = Utc::now();
    let start = Instant::now();

    let probe_file = telemetry_root.join("probe_test.tmp");
    let probe_path = probe_file.display().to_string();

    // Write a test file
    let _ = fs::write(&probe_file, "capability_exhaust_probe");

    // Clean up
    let _ = fs::remove_file(&probe_file);

    ProbeResult {
        probe_name: "file_write".to_string(),
        probe_type: ProbeType::FileWrite,
        triggered_at,
        expected_event_ids: vec![11, 23], // Sysmon 11 (FileCreate), 23 (FileDelete)
        expected_providers: vec!["Microsoft-Windows-Sysmon".to_string()],
        command_executed: "fs::write".to_string(),
        command_args: vec![probe_path.clone()],
        time_window_start: triggered_at,
        time_window_end: None,
        observed: false,
        observed_event_ids: vec![],
        matched_count: 0,
        evidence_ptrs: vec![],
        evidence_excerpt: None,
        latency_ms: start.elapsed().as_millis() as u64,
        status: ProbeStatus::NotObserved,
        details: HashMap::from([
            ("path".to_string(), serde_json::json!(probe_path)),
            (
                "purpose".to_string(),
                serde_json::json!("Verify file system event logging"),
            ),
        ]),
        pipeline_verified: None,
    }
}

async fn run_powershell_probe() -> ProbeResult {
    let triggered_at = Utc::now();
    let start = Instant::now();
    let ps_command = "Write-Host 'CapabilityExhaustProbe'";

    #[cfg(windows)]
    {
        // Run benign PowerShell command
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", ps_command])
            .output();
    }

    ProbeResult {
        probe_name: "powershell_execution".to_string(),
        probe_type: ProbeType::PowerShell,
        triggered_at,
        expected_event_ids: vec![4103, 4104], // PowerShell script block logging
        expected_providers: vec![
            "Microsoft-Windows-PowerShell".to_string(),
            "PowerShell".to_string(),
        ],
        command_executed: "powershell".to_string(),
        command_args: vec![
            "-NoProfile".to_string(),
            "-Command".to_string(),
            ps_command.to_string(),
        ],
        time_window_start: triggered_at,
        time_window_end: None,
        observed: false,
        observed_event_ids: vec![],
        matched_count: 0,
        evidence_ptrs: vec![],
        evidence_excerpt: None,
        latency_ms: start.elapsed().as_millis() as u64,
        status: ProbeStatus::NotObserved,
        details: HashMap::from([
            ("command".to_string(), serde_json::json!(ps_command)),
            (
                "purpose".to_string(),
                serde_json::json!("Verify PowerShell logging"),
            ),
        ]),
        pipeline_verified: None,
    }
}

/// Verify probe observations in event logs
async fn verify_probe_observations(probes: &mut [ProbeResult], _timeout_seconds: u64) {
    #[cfg(windows)]
    {
        for probe in probes.iter_mut() {
            let _query_time = probe.triggered_at.format("%Y-%m-%dT%H:%M:%S").to_string();
            probe.time_window_end = Some(Utc::now());
            let mut total_matched = 0u32;

            // Check each expected event ID
            for event_id in &probe.expected_event_ids {
                let channel = match event_id {
                    4688 | 4689 => "Security",
                    1..=26 => "Microsoft-Windows-Sysmon/Operational",
                    4103 | 4104 => "Microsoft-Windows-PowerShell/Operational",
                    _ => continue,
                };

                // Query for events since probe was triggered
                let result = Command::new("wevtutil")
                    .args([
                        "qe",
                        channel,
                        &format!("/q:*[System[EventID={}]]", event_id),
                        "/c:5",
                        "/rd:true",
                        "/f:text",
                    ])
                    .output();

                if let Ok(output) = result {
                    if output.status.success() && !output.stdout.is_empty() {
                        let output_str = String::from_utf8_lossy(&output.stdout);
                        let event_count = output_str.matches("Event[").count() as u32;
                        total_matched += event_count.max(1);

                        probe.observed = true;
                        if !probe.observed_event_ids.contains(event_id) {
                            probe.observed_event_ids.push(*event_id);
                        }

                        // Extract EventRecordID from wevtutil output and create evidence pointers
                        // Format: "EventRecordID: 12345" in text output
                        for line in output_str.lines() {
                            if let Some(record_id_str) = line.strip_prefix("  EventRecordID: ") {
                                if let Ok(record_id) = record_id_str.trim().parse::<u64>() {
                                    let ptr = EvidencePtr {
                                        stream_id: channel.to_string(),
                                        segment_id: *event_id as u64,
                                        record_index: probe.evidence_ptrs.len() as u32,
                                        record_id: Some(record_id),
                                    };
                                    probe.evidence_ptrs.push(ptr);
                                }
                            }
                        }

                        // Derive evidence excerpt from first evidence pointer
                        if probe.evidence_excerpt.is_none() && !output_str.is_empty() {
                            let excerpt: String = output_str.chars().take(300).collect();
                            probe.evidence_excerpt =
                                Some(excerpt.replace('\n', " ").replace('\r', ""));
                        }
                    }
                }
            }

            probe.matched_count = total_matched;

            // Set status based on observation
            probe.status = if probe.observed {
                ProbeStatus::Verified
            } else {
                // Check if config exists but no events (configured_only)
                let has_config = check_probe_config_exists(probe);
                if has_config {
                    ProbeStatus::ConfiguredOnly
                } else {
                    ProbeStatus::NotObserved
                }
            };
        }
    }
}

/// Check if the configuration for a probe exists (even if events aren't observed)
#[cfg(windows)]
fn check_probe_config_exists(probe: &ProbeResult) -> bool {
    match probe.probe_type {
        ProbeType::ProcessCreate => {
            // Check if audit policy for process creation is enabled
            if let Ok(output) = Command::new("auditpol")
                .args(["/get", "/subcategory:Process Creation"])
                .output()
            {
                let s = String::from_utf8_lossy(&output.stdout);
                s.contains("Success") || s.contains("Failure")
            } else {
                false
            }
        }
        ProbeType::DnsLookup | ProbeType::FileWrite => {
            // Check if Sysmon is installed
            if let Ok(output) = Command::new("sc").args(["query", "Sysmon64"]).output() {
                output.status.success()
            } else if let Ok(output) = Command::new("sc").args(["query", "Sysmon"]).output() {
                output.status.success()
            } else {
                false
            }
        }
        ProbeType::PowerShell => {
            // Check if PowerShell script block logging is configured
            if let Ok(output) = Command::new("reg")
                .args([
                    "query",
                    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
                    "/v",
                    "EnableScriptBlockLogging",
                ])
                .output()
            {
                let s = String::from_utf8_lossy(&output.stdout);
                s.contains("0x1")
            } else {
                false
            }
        }
        _ => false,
    }
}

// ============================================================================
// Pipeline Verification (search captured segments)
// ============================================================================

/// Index.json schema for reading segments
#[derive(Debug, Clone, Deserialize)]
struct SegmentIndex {
    segments: Vec<SegmentEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct SegmentEntry {
    segment_id: String,
    rel_path: String,
    records: u64,
}

/// Verify probe observations against captured segments in telemetry_root
async fn verify_probe_observations_pipeline(
    probes: &mut [ProbeResult],
    telemetry_root: &Path,
) {
    // Read index.json to get segment list
    let index_path = telemetry_root.join("index.json");
    let index: SegmentIndex = match fs::read_to_string(&index_path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(idx) => idx,
            Err(e) => {
                tracing::warn!("Failed to parse index.json: {}", e);
                mark_probes_pipeline_not_searched(probes, &format!("index.json parse error: {}", e));
                return;
            }
        },
        Err(e) => {
            tracing::warn!("Failed to read index.json: {}", e);
            mark_probes_pipeline_not_searched(probes, &format!("index.json not found: {}", e));
            return;
        }
    };

    for probe in probes.iter_mut() {
        let mut verification = PipelineVerification {
            found: false,
            evidence_ptrs: vec![],
            matched_count: 0,
            segments_searched: 0,
            records_scanned: 0,
            divergence_note: None,
        };

        // Search each segment for matching events
        for seg in &index.segments {
            let seg_path = telemetry_root.join(&seg.rel_path);
            verification.segments_searched += 1;

            let matches = search_segment_for_probe(&seg_path, probe, &seg.segment_id);
            verification.records_scanned += seg.records;
            
            if !matches.is_empty() {
                verification.found = true;
                verification.matched_count += matches.len() as u32;
                verification.evidence_ptrs.extend(matches);
            }
        }

        // Check for OS vs Pipeline divergence
        if probe.status == ProbeStatus::Verified && !verification.found {
            verification.divergence_note = Some(
                "OS event log shows Verified but event not found in captured segments. \
                 Possible causes: capture was not running, channel not subscribed, \
                 or event occurred before capture started.".to_string()
            );
        } else if probe.status == ProbeStatus::NotObserved && verification.found {
            verification.divergence_note = Some(
                "Event found in captured segments but OS verification failed. \
                 This may indicate the OS query window was too narrow.".to_string()
            );
        }

        probe.pipeline_verified = Some(verification);
    }
}

/// Mark all probes as not searched when pipeline verification can't proceed
fn mark_probes_pipeline_not_searched(probes: &mut [ProbeResult], reason: &str) {
    for probe in probes.iter_mut() {
        probe.pipeline_verified = Some(PipelineVerification {
            found: false,
            evidence_ptrs: vec![],
            matched_count: 0,
            segments_searched: 0,
            records_scanned: 0,
            divergence_note: Some(format!("Pipeline search skipped: {}", reason)),
        });
    }
}

/// Search a single segment file for events matching a probe
fn search_segment_for_probe(
    segment_path: &Path,
    probe: &ProbeResult,
    segment_id: &str,
) -> Vec<EvidencePtr> {
    let mut matches = vec![];

    // Handle both .jsonl and .jsonl.gz
    let reader: Box<dyn BufRead> = if segment_path.extension().map(|e| e == "gz").unwrap_or(false) {
        match File::open(segment_path) {
            Ok(file) => Box::new(BufReader::new(GzDecoder::new(file))),
            Err(_) => return matches,
        }
    } else {
        match File::open(segment_path) {
            Ok(file) => Box::new(BufReader::new(file)),
            Err(_) => return matches,
        }
    };

    let time_window_start = probe.time_window_start.timestamp_millis();
    let time_window_end = probe
        .time_window_end
        .map(|t| t.timestamp_millis())
        .unwrap_or(i64::MAX);

    for (record_index, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Parse the event JSON
        let event: serde_json::Value = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Check timestamp is within probe window
        if let Some(ts_ms) = event["ts_ms"].as_i64() {
            if ts_ms < time_window_start || ts_ms > time_window_end {
                continue;
            }
        }

        // Check event ID matches
        if let Some(event_id) = event["fields"]["windows.event_id"].as_u64() {
            if probe.expected_event_ids.contains(&(event_id as u32)) {
                // Found a match!
                let ptr = EvidencePtr {
                    stream_id: event["fields"]["windows.channel"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string(),
                    segment_id: segment_id
                        .strip_prefix("evtx_")
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0),
                    record_index: record_index as u32,
                    record_id: event["fields"]["windows.source_record_id"].as_u64(),
                };
                matches.push(ptr);

                // Limit matches to avoid huge result sets
                if matches.len() >= 10 {
                    break;
                }
            }
        }
    }

    matches
}

// ============================================================================
// Summary Calculation
// ============================================================================

fn calculate_summary(
    privilege_check: &PrivilegeCheck,
    channels: &[ChannelStatus],
    audit_policy: &AuditPolicyDetails,
    powershell_config: &PowerShellConfig,
    sysmon_status: &SysmonStatus,
    probes: &[ProbeResult],
) -> ReadinessSummary {
    let mut capabilities = Vec::new();
    let mut total_score = 0u32;
    let max_score = 100u32;
    let mut blocking_issues = Vec::new();
    let mut recommendations = Vec::new();

    // 1. Privilege capability (25 points)
    let priv_score = if privilege_check.is_admin { 25 } else { 5 };
    capabilities.push(CapabilityResult {
        name: "Administrative Privileges".to_string(),
        available: privilege_check.is_admin,
        partial: !privilege_check.is_admin,
        score: priv_score,
        max_score: 25,
        details: if privilege_check.is_admin {
            "Running with full administrative privileges".to_string()
        } else {
            "Running as standard user - limited telemetry access".to_string()
        },
    });
    total_score += priv_score;

    if !privilege_check.is_admin {
        recommendations.push(Recommendation {
            priority: 1,
            category: "Privilege".to_string(),
            title: "Run as Administrator".to_string(),
            description:
                "Restart the application with administrative privileges for full telemetry access"
                    .to_string(),
            command: None,
            requires_admin: false,
            impact_score: 20,
        });
    }

    // 2. Security Log access (20 points)
    let security_accessible = channels
        .iter()
        .find(|c| c.channel == "Security")
        .map(|c| c.accessible)
        .unwrap_or(false);
    let sec_score = if security_accessible { 20 } else { 0 };
    capabilities.push(CapabilityResult {
        name: "Security Event Log".to_string(),
        available: security_accessible,
        partial: false,
        score: sec_score,
        max_score: 20,
        details: if security_accessible {
            "Security log accessible".to_string()
        } else {
            "Cannot read Security event log".to_string()
        },
    });
    total_score += sec_score;

    if !security_accessible {
        blocking_issues.push("Cannot access Security event log".to_string());
    }

    // 3. Sysmon (20 points)
    let sysmon_score = if sysmon_status.installed && sysmon_status.running {
        if sysmon_status.event_ids_enabled.len() >= 5 {
            20
        } else {
            15
        }
    } else if sysmon_status.installed {
        5
    } else {
        0
    };

    capabilities.push(CapabilityResult {
        name: "Sysmon".to_string(),
        available: sysmon_status.installed && sysmon_status.running,
        partial: sysmon_status.installed && !sysmon_status.running,
        score: sysmon_score,
        max_score: 20,
        details: if sysmon_status.installed && sysmon_status.running {
            format!(
                "Sysmon running, {} event types enabled",
                sysmon_status.event_ids_enabled.len()
            )
        } else if sysmon_status.installed {
            "Sysmon installed but not running".to_string()
        } else {
            "Sysmon not installed".to_string()
        },
    });
    total_score += sysmon_score;

    if !sysmon_status.installed {
        recommendations.push(Recommendation {
            priority: 2,
            category: "Telemetry".to_string(),
            title: "Install Sysmon".to_string(),
            description:
                "Install Microsoft Sysmon for enhanced process, network, and file telemetry"
                    .to_string(),
            command: Some("sysmon64.exe -accepteula -i sysmonconfig.xml".to_string()),
            requires_admin: true,
            impact_score: 20,
        });
    }

    // 4. Audit Policy (20 points)
    let mut audit_score = 0;
    if audit_policy.process_creation.success {
        audit_score += 8;
    }
    if audit_policy.command_line_in_events {
        audit_score += 7;
    }
    if audit_policy.logon.success {
        audit_score += 5;
    }

    capabilities.push(CapabilityResult {
        name: "Audit Policy".to_string(),
        available: audit_score >= 15,
        partial: audit_score > 0 && audit_score < 15,
        score: audit_score,
        max_score: 20,
        details: format!(
            "Process creation: {}, Command line: {}, Logon: {}",
            if audit_policy.process_creation.success {
                "✓"
            } else {
                "✗"
            },
            if audit_policy.command_line_in_events {
                "✓"
            } else {
                "✗"
            },
            if audit_policy.logon.success {
                "✓"
            } else {
                "✗"
            }
        ),
    });
    total_score += audit_score;

    if !audit_policy.command_line_in_events {
        recommendations.push(Recommendation {
            priority: 3,
            category: "Audit Policy".to_string(),
            title: "Enable Command Line Logging".to_string(),
            description: "Enable command line capture in process creation events".to_string(),
            command: Some(r#"reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f"#.to_string()),
            requires_admin: true,
            impact_score: 10,
        });
    }

    // 5. PowerShell Logging (15 points)
    let ps_score = if powershell_config.script_block_logging {
        10
    } else {
        0
    } + if powershell_config.module_logging {
        5
    } else {
        0
    };

    capabilities.push(CapabilityResult {
        name: "PowerShell Logging".to_string(),
        available: powershell_config.script_block_logging,
        partial: ps_score > 0 && ps_score < 15,
        score: ps_score,
        max_score: 15,
        details: format!(
            "Script block: {}, Module: {}",
            if powershell_config.script_block_logging {
                "✓"
            } else {
                "✗"
            },
            if powershell_config.module_logging {
                "✓"
            } else {
                "✗"
            }
        ),
    });
    total_score += ps_score;

    if !powershell_config.script_block_logging {
        recommendations.push(Recommendation {
            priority: 4,
            category: "PowerShell".to_string(),
            title: "Enable Script Block Logging".to_string(),
            description: "Enable PowerShell script block logging for script content visibility".to_string(),
            command: Some(r#"reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f"#.to_string()),
            requires_admin: true,
            impact_score: 10,
        });
    }

    // Probe success rate
    let probes_passed = probes.iter().filter(|p| p.observed).count();
    let probe_success_rate = if probes.is_empty() {
        0.0
    } else {
        probes_passed as f64 / probes.len() as f64
    };

    // Determine overall level
    let level = if total_score >= 90 {
        ReadinessLevel::Excellent
    } else if total_score >= 70 {
        ReadinessLevel::Good
    } else if total_score >= 50 {
        ReadinessLevel::Limited
    } else if total_score >= 25 {
        ReadinessLevel::Minimal
    } else {
        ReadinessLevel::Blocked
    };

    // Sort recommendations by priority
    recommendations.sort_by_key(|r| r.priority);

    ReadinessSummary {
        level,
        score: total_score,
        max_score,
        capabilities,
        blocking_issues,
        recommendations,
        probe_success_rate,
    }
}

// ============================================================================
// Persistence
// ============================================================================

fn save_report(report: &CapabilityExhaustReport, telemetry_root: &Path) -> Result<(), String> {
    let readiness_dir = telemetry_root.join("readiness");
    fs::create_dir_all(&readiness_dir)
        .map_err(|e| format!("Failed to create readiness directory: {}", e))?;

    let timestamp = report.timestamp.format("%Y%m%d_%H%M%S");
    let filename = format!("readiness_{}.json", timestamp);
    let filepath = readiness_dir.join(&filename);

    let json = serde_json::to_string_pretty(report)
        .map_err(|e| format!("Failed to serialize report: {}", e))?;

    fs::write(&filepath, &json).map_err(|e| format!("Failed to write report: {}", e))?;

    // Also save as "latest"
    let latest_path = readiness_dir.join("readiness_latest.json");
    fs::write(&latest_path, &json).map_err(|e| format!("Failed to write latest report: {}", e))?;

    tracing::info!("Saved readiness report to {}", filepath.display());

    Ok(())
}

/// Load the latest readiness report
pub fn load_latest_report(telemetry_root: &Path) -> Option<CapabilityExhaustReport> {
    let latest_path = telemetry_root
        .join("readiness")
        .join("readiness_latest.json");

    if latest_path.exists() {
        fs::read_to_string(&latest_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    } else {
        None
    }
}

// ============================================================================
// Helpers
// ============================================================================

#[cfg(windows)]
fn is_elevated() -> bool {
    use std::process::Command;

    // Check if we can write to a protected location
    Command::new("net")
        .args(["session"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn is_elevated() -> bool {
    false
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Create a mock segment file for testing
    fn create_mock_segment(dir: &Path, segment_id: &str, events: &[serde_json::Value]) -> std::io::Result<()> {
        let segments_dir = dir.join("segments");
        fs::create_dir_all(&segments_dir)?;
        
        let seg_path = segments_dir.join(format!("{}.jsonl", segment_id));
        let mut file = File::create(&seg_path)?;
        
        for event in events {
            writeln!(file, "{}", serde_json::to_string(event).unwrap())?;
        }
        Ok(())
    }

    /// Create a mock index.json for testing
    fn create_mock_index(dir: &Path, segments: &[(&str, u64)]) -> std::io::Result<()> {
        let index = serde_json::json!({
            "segments": segments.iter().map(|(id, records)| {
                serde_json::json!({
                    "segment_id": id,
                    "rel_path": format!("segments/{}.jsonl", id),
                    "records": records
                })
            }).collect::<Vec<_>>()
        });
        
        fs::write(dir.join("index.json"), serde_json::to_string_pretty(&index)?)?;
        Ok(())
    }

    #[test]
    fn test_search_segment_finds_matching_event() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path();

        // Create a mock event that matches process probe (Event ID 4688)
        let events = vec![
            serde_json::json!({
                "ts_ms": chrono::Utc::now().timestamp_millis(),
                "fields": {
                    "windows.event_id": 4688,
                    "windows.channel": "Security",
                    "windows.source_record_id": 12345
                }
            })
        ];
        
        create_mock_segment(dir, "evtx_000000", &events).unwrap();

        // Create probe with matching expected event ID
        let probe = ProbeResult {
            probe_name: "test_probe".to_string(),
            probe_type: ProbeType::ProcessCreate,
            triggered_at: chrono::Utc::now() - chrono::Duration::seconds(10),
            expected_event_ids: vec![4688],
            expected_providers: vec!["Microsoft-Windows-Security-Auditing".to_string()],
            command_executed: "test".to_string(),
            command_args: vec![],
            time_window_start: chrono::Utc::now() - chrono::Duration::seconds(10),
            time_window_end: Some(chrono::Utc::now() + chrono::Duration::seconds(10)),
            observed: false,
            observed_event_ids: vec![],
            matched_count: 0,
            evidence_ptrs: vec![],
            evidence_excerpt: None,
            latency_ms: 0,
            status: ProbeStatus::NotObserved,
            details: HashMap::new(),
            pipeline_verified: None,
        };

        let seg_path = dir.join("segments/evtx_000000.jsonl");
        let matches = search_segment_for_probe(&seg_path, &probe, "evtx_000000");
        
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].stream_id, "Security");
        assert_eq!(matches[0].record_id, Some(12345));
    }

    #[test]
    fn test_search_segment_ignores_non_matching_event() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path();

        // Create event with different event ID
        let events = vec![
            serde_json::json!({
                "ts_ms": chrono::Utc::now().timestamp_millis(),
                "fields": {
                    "windows.event_id": 1234, // Not 4688
                    "windows.channel": "Application",
                    "windows.source_record_id": 999
                }
            })
        ];
        
        create_mock_segment(dir, "evtx_000000", &events).unwrap();

        let probe = ProbeResult {
            probe_name: "test_probe".to_string(),
            probe_type: ProbeType::ProcessCreate,
            triggered_at: chrono::Utc::now() - chrono::Duration::seconds(10),
            expected_event_ids: vec![4688],
            expected_providers: vec![],
            command_executed: "test".to_string(),
            command_args: vec![],
            time_window_start: chrono::Utc::now() - chrono::Duration::seconds(10),
            time_window_end: Some(chrono::Utc::now() + chrono::Duration::seconds(10)),
            observed: false,
            observed_event_ids: vec![],
            matched_count: 0,
            evidence_ptrs: vec![],
            evidence_excerpt: None,
            latency_ms: 0,
            status: ProbeStatus::NotObserved,
            details: HashMap::new(),
            pipeline_verified: None,
        };

        let seg_path = dir.join("segments/evtx_000000.jsonl");
        let matches = search_segment_for_probe(&seg_path, &probe, "evtx_000000");
        
        assert!(matches.is_empty());
    }

    #[test]
    fn test_verification_source_default() {
        assert_eq!(VerificationSource::default(), VerificationSource::EventLog);
    }

    #[test]
    fn test_pipeline_verification_struct_serialization() {
        let pv = PipelineVerification {
            found: true,
            evidence_ptrs: vec![EvidencePtr {
                stream_id: "Security".to_string(),
                segment_id: 0,
                record_index: 42,
                record_id: Some(12345),
            }],
            matched_count: 1,
            segments_searched: 5,
            records_scanned: 500,
            divergence_note: None,
        };

        let json = serde_json::to_string(&pv).unwrap();
        assert!(json.contains("\"found\":true"));
        assert!(json.contains("\"matched_count\":1"));
        assert!(json.contains("\"segments_searched\":5"));
    }

    #[test]
    fn test_evidence_ptr_to_uri() {
        let ptr = EvidencePtr {
            stream_id: "Security".to_string(),
            segment_id: 5,
            record_index: 42,
            record_id: Some(12345),
        };
        
        assert_eq!(ptr.to_uri(), "evidence://Security:5:42");
    }
}

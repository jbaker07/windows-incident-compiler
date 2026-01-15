//! Capability Service
//!
//! Handles capability model and detection plan.
//! All business logic for sensor/detection visibility lives here.
//!
//! NOTE: Core platform check `is_elevated()` is delegated to crate::capability
//! to ensure Single Source of Truth. The boolean sysmon/security_log checks
//! are kept here as simpler wrappers for API response generation.

use std::path::Path;

// ============================================================================
// Capability Status - SSoT Delegation
// ============================================================================

// Delegate is_elevated() to the authoritative capability module
// This ensures admin status is computed identically everywhere.
pub use crate::capability::is_elevated;

/// Check if Sysmon is installed (simple boolean for API responses)
#[cfg(target_os = "windows")]
pub fn check_sysmon_installed() -> bool {
    use std::process::Command;
    use std::os::windows::process::CommandExt;

    let mut cmd = Command::new("sc");
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    cmd.args(["query", "Sysmon"]);

    match cmd.output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.contains("RUNNING") || stdout.contains("STATE")
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn check_sysmon_installed() -> bool {
    false
}

/// Check if Security event log is accessible (simple boolean for API responses)
#[cfg(target_os = "windows")]
pub fn check_security_log_accessible() -> bool {
    use std::process::Command;
    use std::os::windows::process::CommandExt;

    let mut cmd = Command::new("wevtutil");
    cmd.creation_flags(0x08000000);
    cmd.args(["qe", "Security", "/c:1", "/f:text"]);

    match cmd.output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn check_security_log_accessible() -> bool {
    false
}

/// Channel status with reason code
#[derive(Debug, Clone)]
pub struct ChannelStatus {
    pub name: String,
    pub accessible: bool,
    pub reason: Option<String>,
}

/// Check accessibility of a Windows event log channel
#[cfg(target_os = "windows")]
fn probe_channel(channel: &str) -> ChannelStatus {
    use std::process::Command;
    use std::os::windows::process::CommandExt;

    let mut cmd = Command::new("wevtutil");
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    cmd.args(["qe", channel, "/c:1", "/f:text"]);

    match cmd.output() {
        Ok(output) => {
            if output.status.success() {
                ChannelStatus {
                    name: channel.to_string(),
                    accessible: true,
                    reason: None,
                }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let reason = if stderr.contains("0x80070005") || stderr.contains("Access is denied") {
                    "ACCESS_DENIED (requires admin)"
                } else if stderr.contains("0x80070003") || stderr.contains("cannot find") {
                    "CHANNEL_NOT_FOUND"
                } else if stderr.contains("0x00001069") || stderr.contains("channel is disabled") {
                    "CHANNEL_DISABLED"
                } else {
                    "UNKNOWN_ERROR"
                };
                ChannelStatus {
                    name: channel.to_string(),
                    accessible: false,
                    reason: Some(reason.to_string()),
                }
            }
        }
        Err(e) => ChannelStatus {
            name: channel.to_string(),
            accessible: false,
            reason: Some(format!("PROBE_FAILED: {}", e)),
        },
    }
}

#[cfg(not(target_os = "windows"))]
fn probe_channel(channel: &str) -> ChannelStatus {
    ChannelStatus {
        name: channel.to_string(),
        accessible: false,
        reason: Some("NOT_WINDOWS".to_string()),
    }
}

/// Probe all attack-surface channels
pub fn probe_all_channels() -> Vec<ChannelStatus> {
    let channels = [
        "Security",
        "System",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-WinRM/Operational",
    ];
    channels.iter().map(|c| probe_channel(c)).collect()
}

/// Get supported event IDs for a channel (based on attack_surface.rs parsers)
fn get_supported_event_ids(channel: &str) -> Vec<u32> {
    match channel {
        "Security" => vec![1102, 4624, 4657, 4672, 4688, 4697, 4698, 4702],
        "System" => vec![104, 7045],
        "Microsoft-Windows-Sysmon/Operational" => vec![1, 3, 10, 11, 12, 13, 14, 19, 20, 21],
        "Microsoft-Windows-PowerShell/Operational" => vec![4103, 4104],
        "Microsoft-Windows-WMI-Activity/Operational" => vec![], // Sysmon WMI events handle this
        "Microsoft-Windows-TaskScheduler/Operational" => vec![106],
        "Microsoft-Windows-WinRM/Operational" => vec![91],
        "Microsoft-Windows-Windows Defender/Operational" => vec![1121],
        _ => vec![],
    }
}

/// Get full capability status
pub fn get_capability_status() -> serde_json::Value {
    let is_admin = is_elevated();
    let sysmon_installed = check_sysmon_installed();
    let security_log_accessible = check_security_log_accessible();

    // Probe all attack-surface channels
    let channel_probes = probe_all_channels();
    let channels_json: Vec<serde_json::Value> = channel_probes
        .iter()
        .map(|cs| {
            let supported_ids = get_supported_event_ids(&cs.name);
            serde_json::json!({
                "name": cs.name,
                "accessible": cs.accessible,
                "reason": cs.reason,
                "supported": !supported_ids.is_empty(),
                "supported_event_ids": supported_ids
            })
        })
        .collect();
    let channels_accessible = channel_probes.iter().filter(|c| c.accessible).count();

    // Determine available sensors based on capabilities
    let mut sensors = vec![
        serde_json::json!({
            "id": "process_creation",
            "name": "Process Creation",
            "available": true,
            "source": "Windows Security or Sysmon",
            "required_privileges": "none"
        }),
        serde_json::json!({
            "id": "file_system",
            "name": "File System Activity",
            "available": true,
            "source": "ETW or Sysmon",
            "required_privileges": "none"
        }),
        serde_json::json!({
            "id": "network_connections",
            "name": "Network Connections",
            "available": sysmon_installed,
            "source": "Sysmon",
            "required_privileges": "Sysmon installation"
        }),
        serde_json::json!({
            "id": "registry_operations",
            "name": "Registry Operations",
            "available": true,
            "source": "ETW or Sysmon",
            "required_privileges": "none"
        }),
        serde_json::json!({
            "id": "security_events",
            "name": "Security Events (Auth)",
            "available": security_log_accessible,
            "source": "Security Event Log",
            "required_privileges": "admin"
        }),
    ];

    if sysmon_installed {
        sensors.push(serde_json::json!({
            "id": "process_command_line",
            "name": "Process Command Lines",
            "available": true,
            "source": "Sysmon",
            "required_privileges": "Sysmon installation"
        }));
        sensors.push(serde_json::json!({
            "id": "file_hashes",
            "name": "File Hashes",
            "available": true,
            "source": "Sysmon",
            "required_privileges": "Sysmon installation"
        }));
    }

    let available_count = sensors.iter().filter(|s| {
        s.get("available").and_then(|v| v.as_bool()).unwrap_or(false)
    }).count();

    // Determine overall_status based on capabilities
    let overall_status = if !is_admin {
        "blocked"
    } else if sysmon_installed && security_log_accessible {
        "full"
    } else if security_log_accessible {
        "partial"
    } else {
        "limited"
    };

    serde_json::json!({
        "is_admin": is_admin,
        "sysmon_installed": sysmon_installed,
        "security_log_accessible": security_log_accessible,
        "channels": channels_json,
        "channels_accessible": channels_accessible,
        "channels_total": channel_probes.len(),
        "sensors": sensors,
        "sensors_available": available_count,
        "sensors_total": sensors.len(),
        "readiness_score": (available_count as f64 / sensors.len() as f64 * 100.0).round() as u8,
        "overall_status": overall_status
    })
}

// ============================================================================
// Detection Plan
// ============================================================================

/// Get detection plan with playbook dependencies
pub fn get_detection_plan(playbooks_dir: Option<&Path>) -> serde_json::Value {
    let capability = get_capability_status();
    let is_admin = capability.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
    let sysmon = capability.get("sysmon_installed").and_then(|v| v.as_bool()).unwrap_or(false);
    let security_log = capability.get("security_log_accessible").and_then(|v| v.as_bool()).unwrap_or(false);

    // Count playbooks if directory provided
    let playbook_count = playbooks_dir
        .filter(|p| p.exists())
        .and_then(|p| std::fs::read_dir(p).ok())
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "yaml" || ext == "yml")
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0);

    // Build detection categories with requirements
    let detections = vec![
        serde_json::json!({
            "category": "Process Execution",
            "enabled": true,
            "requirements_met": true,
            "playbooks_available": playbook_count > 0,
            "detections": ["process_injection", "suspicious_spawn", "lolbin_usage"]
        }),
        serde_json::json!({
            "category": "Persistence",
            "enabled": true,
            "requirements_met": true,
            "playbooks_available": playbook_count > 0,
            "detections": ["service_creation", "scheduled_task", "registry_run_key"]
        }),
        serde_json::json!({
            "category": "Network Activity",
            "enabled": sysmon,
            "requirements_met": sysmon,
            "requirements": ["Sysmon"],
            "playbooks_available": playbook_count > 0,
            "detections": ["c2_beacon", "data_exfiltration", "suspicious_dns"]
        }),
        serde_json::json!({
            "category": "Authentication",
            "enabled": is_admin && security_log,
            "requirements_met": is_admin && security_log,
            "requirements": ["Admin", "Security Log Access"],
            "playbooks_available": playbook_count > 0,
            "detections": ["failed_logon", "lateral_movement", "privilege_escalation"]
        }),
        serde_json::json!({
            "category": "Defense Evasion",
            "enabled": sysmon,
            "requirements_met": sysmon,
            "requirements": ["Sysmon"],
            "playbooks_available": playbook_count > 0,
            "detections": ["log_tampering", "timestomping", "process_hollowing"]
        }),
    ];

    let enabled_count = detections.iter().filter(|d| {
        d.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false)
    }).count();

    serde_json::json!({
        "capability_snapshot": capability,
        "playbooks_dir": playbooks_dir.map(|p| p.display().to_string()),
        "playbooks_count": playbook_count,
        "detection_categories": detections,
        "categories_enabled": enabled_count,
        "categories_total": detections.len()
    })
}

// ============================================================================
// Capability Snapshot from Meta
// ============================================================================

/// Get capability snapshot from run_meta.json
pub fn get_capability_snapshot_from_meta(meta_path: &Path) -> serde_json::Value {
    if let Ok(contents) = std::fs::read_to_string(meta_path) {
        if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&contents) {
            if let Some(snapshot) = meta.get("readiness_snapshot") {
                return snapshot.clone();
            }
            if let Some(snapshot) = meta.get("capability_snapshot") {
                return snapshot.clone();
            }
            return serde_json::json!({
                "is_admin": meta.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false),
                "sysmon_installed": meta.get("sysmon_installed").and_then(|v| v.as_bool()).unwrap_or(false),
                "security_log_accessible": meta.get("security_log_accessible").and_then(|v| v.as_bool()).unwrap_or(false),
                "profile": meta.get("profile").and_then(|v| v.as_str())
            });
        }
    }
    serde_json::json!({
        "is_admin": null,
        "sysmon_installed": null,
        "security_log_accessible": null,
        "note": "Capability snapshot not available in run metadata"
    })
}

/// Build telemetry caveats based on capability snapshot
pub fn build_telemetry_caveats(capability_snapshot: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut caveats = Vec::new();

    let is_admin = capability_snapshot.get("is_admin").and_then(|v| v.as_bool());
    let sysmon_installed = capability_snapshot.get("sysmon_installed").and_then(|v| v.as_bool());
    let security_log = capability_snapshot.get("security_log_accessible").and_then(|v| v.as_bool());

    if is_admin == Some(false) {
        caveats.push(serde_json::json!({
            "caveat": "NOT_ADMIN",
            "impact": "Limited access to Security event log and system-level telemetry",
            "affected_detections": ["auth_events", "privileged_operations"]
        }));
    }

    if sysmon_installed == Some(false) {
        caveats.push(serde_json::json!({
            "caveat": "NO_SYSMON",
            "impact": "No process command lines, network connections, or file hash data",
            "affected_detections": ["process_injection", "network_c2", "malware_execution"]
        }));
    }

    if security_log == Some(false) {
        caveats.push(serde_json::json!({
            "caveat": "NO_SECURITY_LOG",
            "impact": "No authentication events or privilege escalation detection",
            "affected_detections": ["lateral_movement", "credential_access"]
        }));
    }

    if is_admin.is_none() && sysmon_installed.is_none() && security_log.is_none() {
        caveats.push(serde_json::json!({
            "caveat": "UNKNOWN_CAPABILITIES",
            "impact": "Run capability snapshot not available; detection coverage unknown",
            "affected_detections": ["all"]
        }));
    }

    caveats
}

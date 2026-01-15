//! Capability Model - Windows Sensor Inventory and Detection Coverage
//!
//! This module provides truthful, always-on visibility into:
//! - What sensors are expected vs present vs active
//! - Which playbooks depend on which sensors/fact types  
//! - What detection coverage is possible in the current state
//! - Runtime pipeline status (binaries, directories, active run)
//!
//! ## Status Semantics
//! - `configured`: Sensor/component exists and is accessible (static check)
//! - `active`: Facts have been observed from this source during a run (dynamic)
//! - Live endpoint `/api/capability/status` reports `configured` status
//! - Run snapshots report `active` only when facts were observed
//!
//! ## Contract (TRUTH_CONTRACT.md)
//! - Never claim a playbook is enabled if telemetry requirements are not met
//! - Never claim attack surface coverage if required sensors are missing/blocked
//! - Every "blocked" state must include reason_code and message
//! - Distinguish "configured" (channel accessible) from "active" (facts observed)
//!
//! ## Attack Surfaces
//! - process: Process creation, command lines, parent-child relationships
//! - auth: Authentication events, logon types, privilege usage
//! - persistence: Registry, scheduled tasks, startup items, services
//! - network: Network connections, DNS, firewall events
//! - evasion: Defense evasion, log tampering, security tool disabling
//! - file: File operations, path access patterns
//! - other: Uncategorized detections

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ============================================================================
// Platform Helpers
// ============================================================================

/// Check if the current process is running with elevated (Administrator) privileges
pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::ptr::null_mut;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
            
            let result = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                size,
                &mut size,
            );
            
            result != 0 && elevation.TokenIsElevated != 0
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        // On Unix, check if running as root
        unsafe { libc::geteuid() == 0 }
    }
}

// ============================================================================
// Sensor Status Types
// ============================================================================

/// Status of a single sensor or pipeline component
/// 
/// ## Semantic Distinction
/// - `Configured`: Channel/component exists and is accessible (static check)
/// - `Active`: Facts have been observed from this source (requires run data)
/// 
/// Live endpoints report `Configured` when channel is accessible.
/// Run snapshots upgrade to `Active` only when facts were observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorStatus {
    /// Facts have been observed from this sensor during a run
    Active,
    /// Sensor is installed and accessible but no facts observed yet
    Configured,
    /// Sensor is not installed or not present on this system
    Missing,
    /// Sensor exists but is blocked (e.g., access denied, requires elevation)
    Blocked,
}

impl SensorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Configured => "configured", 
            Self::Missing => "missing",
            Self::Blocked => "blocked",
        }
    }
    
    /// UI display label with context
    pub fn display_label(&self) -> &'static str {
        match self {
            Self::Active => "Active (events observed)",
            Self::Configured => "Configured (no events observed yet)",
            Self::Missing => "Missing",
            Self::Blocked => "Blocked",
        }
    }
    
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active | Self::Configured)
    }
}

/// Result of checking a sensor's status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorCheckResult {
    pub sensor_name: String,
    pub sensor_id: String,
    pub status: SensorStatus,
    /// UI-friendly status label (e.g., "Configured (no events observed yet)")
    pub status_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Capabilities provided when this sensor is active
    pub capabilities: Vec<String>,
    /// Whether this sensor requires admin privileges
    pub requires_admin: bool,
    /// Whether this sensor requires installation (e.g., Sysmon)
    pub requires_install: bool,
}

// ============================================================================
// Pipeline Component Status
// ============================================================================

/// Runtime pipeline component check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineComponentStatus {
    pub component_id: String,
    pub component_name: String,
    pub status: SensorStatus,
    pub status_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Active run metrics (only populated when a run is active)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveRunMetrics {
    pub run_id: String,
    pub capture_running: bool,
    pub locald_running: bool,
    pub segments_count: u64,
    pub events_total: u64,
    pub facts_extracted: u64,
    pub signals_fired: u64,
}

/// Check if a binary exists at the given path or can be found via env var
pub fn check_binary_present(env_var: &str, fallback_name: &str) -> PipelineComponentStatus {
    let path = std::env::var(env_var).ok();
    let exists = path.as_ref()
        .map(|p| Path::new(p).exists())
        .unwrap_or(false);
    
    if exists {
        PipelineComponentStatus {
            component_id: fallback_name.to_string(),
            component_name: format!("{} binary", fallback_name),
            status: SensorStatus::Configured,
            status_label: "Present".to_string(),
            reason_code: None,
            message: None,
            path,
        }
    } else {
        PipelineComponentStatus {
            component_id: fallback_name.to_string(),
            component_name: format!("{} binary", fallback_name),
            status: SensorStatus::Missing,
            status_label: "Missing".to_string(),
            reason_code: Some("BINARY_NOT_FOUND".to_string()),
            message: Some(format!("{} not found at configured path", fallback_name)),
            path,
        }
    }
}

/// Check if a directory is writable
pub fn check_dir_writable(dir_path: &Path, component_id: &str, component_name: &str) -> PipelineComponentStatus {
    if !dir_path.exists() {
        return PipelineComponentStatus {
            component_id: component_id.to_string(),
            component_name: component_name.to_string(),
            status: SensorStatus::Missing,
            status_label: "Directory missing".to_string(),
            reason_code: Some("DIR_NOT_FOUND".to_string()),
            message: Some(format!("Directory does not exist: {}", dir_path.display())),
            path: Some(dir_path.display().to_string()),
        };
    }
    
    // Try to create a temp file to test writability
    let test_file = dir_path.join(".write_test_capability");
    match std::fs::write(&test_file, b"test") {
        Ok(_) => {
            let _ = std::fs::remove_file(&test_file);
            PipelineComponentStatus {
                component_id: component_id.to_string(),
                component_name: component_name.to_string(),
                status: SensorStatus::Configured,
                status_label: "Writable".to_string(),
                reason_code: None,
                message: None,
                path: Some(dir_path.display().to_string()),
            }
        }
        Err(e) => {
            PipelineComponentStatus {
                component_id: component_id.to_string(),
                component_name: component_name.to_string(),
                status: SensorStatus::Blocked,
                status_label: "Not writable".to_string(),
                reason_code: Some("WRITE_DENIED".to_string()),
                message: Some(format!("Cannot write to directory: {}", e)),
                path: Some(dir_path.display().to_string()),
            }
        }
    }
}

/// Check if a database file is accessible and writable
pub fn check_db_writable(db_path: &Path) -> PipelineComponentStatus {
    if !db_path.exists() {
        // DB doesn't exist yet - that's okay, check parent dir writability
        if let Some(parent) = db_path.parent() {
            let parent_check = check_dir_writable(parent, "db_parent", "Database directory");
            return PipelineComponentStatus {
                component_id: "workbench_db".to_string(),
                component_name: "Workbench database".to_string(),
                status: parent_check.status,
                status_label: if parent_check.status.is_usable() { 
                    "Will be created".to_string() 
                } else { 
                    "Cannot create".to_string() 
                },
                reason_code: parent_check.reason_code,
                message: parent_check.message,
                path: Some(db_path.display().to_string()),
            };
        }
    }
    
    // DB exists - check if we can open it
    match std::fs::OpenOptions::new().read(true).write(true).open(db_path) {
        Ok(_) => PipelineComponentStatus {
            component_id: "workbench_db".to_string(),
            component_name: "Workbench database".to_string(),
            status: SensorStatus::Configured,
            status_label: "Accessible".to_string(),
            reason_code: None,
            message: None,
            path: Some(db_path.display().to_string()),
        },
        Err(e) => PipelineComponentStatus {
            component_id: "workbench_db".to_string(),
            component_name: "Workbench database".to_string(),
            status: SensorStatus::Blocked,
            status_label: "Access denied".to_string(),
            reason_code: Some("DB_ACCESS_DENIED".to_string()),
            message: Some(format!("Cannot open database: {}", e)),
            path: Some(db_path.display().to_string()),
        },
    }
}

// ============================================================================
// Canonical Sensor Registry
// ============================================================================

/// Definition of an expected sensor for Windows
pub struct SensorDefinition {
    pub sensor_id: &'static str,
    pub sensor_name: &'static str,
    pub requires_admin: bool,
    pub requires_install: bool,
    /// Capability tags produced when active
    pub capabilities: &'static [&'static str],
    /// Fact types this sensor enables
    pub fact_types: &'static [&'static str],
    /// Attack surfaces this sensor contributes to
    pub attack_surfaces: &'static [&'static str],
}

/// Canonical list of expected Windows sensors
pub static WINDOWS_SENSORS: &[SensorDefinition] = &[
    SensorDefinition {
        sensor_id: "sysmon",
        sensor_name: "Sysmon (System Monitor)",
        requires_admin: false, // Reading doesn't require admin, just needs to be installed
        requires_install: true,
        capabilities: &["PROC_CREATE", "PROC_TERMINATE", "FILE_CREATE", "NET_CONNECT", "DNS_QUERY", "REG_MOD", "DRIVER_LOAD", "IMAGE_LOAD", "PROC_ACCESS"],
        fact_types: &["ProcSpawn", "Exec", "OutboundConnect", "DnsResolve", "WritePath", "CreatePath", "RegistryMod", "ModuleLoad", "ProcessAccess"],
        attack_surfaces: &["process", "network", "persistence", "evasion", "file", "credential_access"],
    },
    SensorDefinition {
        sensor_id: "security_log",
        sensor_name: "Windows Security Event Log",
        requires_admin: true,
        requires_install: false,
        capabilities: &["AUTH_EVENTS", "LOGON", "LOGOFF", "PRIV_USE", "AUDIT_POLICY"],
        fact_types: &["AuthEvent", "PrivilegeBoundary"],
        attack_surfaces: &["auth", "evasion"],
    },
    SensorDefinition {
        sensor_id: "system_log",
        sensor_name: "Windows System Event Log",
        requires_admin: false,
        requires_install: false,
        capabilities: &["SERVICE_EVENTS", "DRIVER_EVENTS", "SYSTEM_STATE"],
        fact_types: &["PersistArtifact"],
        attack_surfaces: &["persistence"],
    },
    SensorDefinition {
        sensor_id: "powershell_log",
        sensor_name: "PowerShell Script Block Logging",
        requires_admin: false,
        requires_install: false, // Just needs to be enabled via GPO/registry
        capabilities: &["SCRIPT_BLOCK", "SCRIPT_EXEC"],
        fact_types: &["ScriptExec", "ShellCommand"],
        attack_surfaces: &["process", "evasion"],
    },
];

// ============================================================================
// Sensor Check Functions (Windows-specific)
// ============================================================================

/// Check if Sysmon is installed and operational
/// NOTE: Returns `Configured` (not `Active`) because live checks can only confirm
/// the channel is accessible, not that facts have been observed.
pub fn check_sysmon() -> SensorCheckResult {
    let def = &WINDOWS_SENSORS[0]; // sysmon
    
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new("wevtutil");
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        let result = cmd
            .args(["gli", "Microsoft-Windows-Sysmon/Operational"])
            .output();
        
        match result {
            Ok(output) if output.status.success() => {
                // Further check: is the channel enabled?
                let mut cmd2 = std::process::Command::new("wevtutil");
                cmd2.creation_flags(0x08000000);
                let enabled_check = cmd2
                    .args(["gl", "Microsoft-Windows-Sysmon/Operational"])
                    .output();
                    
                let is_enabled = enabled_check
                    .map(|o| String::from_utf8_lossy(&o.stdout).contains("enabled: true"))
                    .unwrap_or(false);
                    
                if is_enabled {
                    // Channel accessible and enabled -> Configured (Active requires observed facts)
                    SensorCheckResult {
                        sensor_name: def.sensor_name.to_string(),
                        sensor_id: def.sensor_id.to_string(),
                        status: SensorStatus::Configured,
                        status_label: SensorStatus::Configured.display_label().to_string(),
                        reason_code: None,
                        message: Some("Channel accessible and enabled".to_string()),
                        capabilities: def.capabilities.iter().map(|s| s.to_string()).collect(),
                        requires_admin: def.requires_admin,
                        requires_install: def.requires_install,
                    }
                } else {
                    SensorCheckResult {
                        sensor_name: def.sensor_name.to_string(),
                        sensor_id: def.sensor_id.to_string(),
                        status: SensorStatus::Configured,
                        status_label: "Installed but channel disabled".to_string(),
                        reason_code: Some("CHANNEL_DISABLED".to_string()),
                        message: Some("Sysmon is installed but the event log channel is disabled".to_string()),
                        capabilities: def.capabilities.iter().map(|s| s.to_string()).collect(),
                        requires_admin: def.requires_admin,
                        requires_install: def.requires_install,
                    }
                }
            }
            _ => SensorCheckResult {
                sensor_name: def.sensor_name.to_string(),
                sensor_id: def.sensor_id.to_string(),
                status: SensorStatus::Missing,
                status_label: SensorStatus::Missing.display_label().to_string(),
                reason_code: Some("NOT_INSTALLED".to_string()),
                message: Some("Sysmon is not installed. Install from Microsoft Sysinternals.".to_string()),
                capabilities: Vec::new(),
                requires_admin: def.requires_admin,
                requires_install: def.requires_install,
            },
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        SensorCheckResult {
            sensor_name: def.sensor_name.to_string(),
            sensor_id: def.sensor_id.to_string(),
            status: SensorStatus::Missing,
            status_label: SensorStatus::Missing.display_label().to_string(),
            reason_code: Some("WRONG_PLATFORM".to_string()),
            message: Some("Sysmon is Windows-only".to_string()),
            capabilities: Vec::new(),
            requires_admin: def.requires_admin,
            requires_install: def.requires_install,
        }
    }
}

/// Check if Security Event Log is accessible
pub fn check_security_log(is_admin: bool) -> SensorCheckResult {
    let def = &WINDOWS_SENSORS[1]; // security_log
    
    if !is_admin {
        return SensorCheckResult {
            sensor_name: def.sensor_name.to_string(),
            sensor_id: def.sensor_id.to_string(),
            status: SensorStatus::Blocked,
            status_label: SensorStatus::Blocked.display_label().to_string(),
            reason_code: Some("REQUIRES_ADMIN".to_string()),
            message: Some("Security Event Log requires Administrator privileges".to_string()),
            capabilities: Vec::new(),
            requires_admin: def.requires_admin,
            requires_install: def.requires_install,
        };
    }
    
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new("wevtutil");
        cmd.creation_flags(0x08000000);
        let result = cmd
            .args(["gl", "Security"])
            .output();
            
        match result {
            Ok(output) if output.status.success() => SensorCheckResult {
                sensor_name: def.sensor_name.to_string(),
                sensor_id: def.sensor_id.to_string(),
                status: SensorStatus::Configured,
                status_label: SensorStatus::Configured.display_label().to_string(),
                reason_code: None,
                message: Some("Channel accessible".to_string()),
                capabilities: def.capabilities.iter().map(|s| s.to_string()).collect(),
                requires_admin: def.requires_admin,
                requires_install: def.requires_install,
            },
            _ => SensorCheckResult {
                sensor_name: def.sensor_name.to_string(),
                sensor_id: def.sensor_id.to_string(),
                status: SensorStatus::Blocked,
                status_label: SensorStatus::Blocked.display_label().to_string(),
                reason_code: Some("ACCESS_DENIED".to_string()),
                message: Some("Cannot access Security Event Log".to_string()),
                capabilities: Vec::new(),
                requires_admin: def.requires_admin,
                requires_install: def.requires_install,
            },
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        SensorCheckResult {
            sensor_name: def.sensor_name.to_string(),
            sensor_id: def.sensor_id.to_string(),
            status: SensorStatus::Missing,
            status_label: SensorStatus::Missing.display_label().to_string(),
            reason_code: Some("WRONG_PLATFORM".to_string()),
            message: Some("Security Event Log is Windows-only".to_string()),
            capabilities: Vec::new(),
            requires_admin: def.requires_admin,
            requires_install: def.requires_install,
        }
    }
}

/// Check System Event Log accessibility
pub fn check_system_log() -> SensorCheckResult {
    let def = &WINDOWS_SENSORS[2]; // system_log
    
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new("wevtutil");
        cmd.creation_flags(0x08000000);
        let result = cmd
            .args(["gl", "System"])
            .output();
            
        match result {
            Ok(output) if output.status.success() => SensorCheckResult {
                sensor_name: def.sensor_name.to_string(),
                sensor_id: def.sensor_id.to_string(),
                status: SensorStatus::Configured,
                status_label: SensorStatus::Configured.display_label().to_string(),
                reason_code: None,
                message: Some("Channel accessible".to_string()),
                capabilities: def.capabilities.iter().map(|s| s.to_string()).collect(),
                requires_admin: def.requires_admin,
                requires_install: def.requires_install,
            },
            _ => SensorCheckResult {
                sensor_name: def.sensor_name.to_string(),
                sensor_id: def.sensor_id.to_string(),
                status: SensorStatus::Blocked,
                status_label: SensorStatus::Blocked.display_label().to_string(),
                reason_code: Some("ACCESS_ERROR".to_string()),
                message: Some("Cannot access System Event Log".to_string()),
                capabilities: Vec::new(),
                requires_admin: def.requires_admin,
                requires_install: def.requires_install,
            },
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        SensorCheckResult {
            sensor_name: def.sensor_name.to_string(),
            sensor_id: def.sensor_id.to_string(),
            status: SensorStatus::Missing,
            status_label: SensorStatus::Missing.display_label().to_string(),
            reason_code: Some("WRONG_PLATFORM".to_string()),
            message: Some("System Event Log is Windows-only".to_string()),
            capabilities: Vec::new(),
            requires_admin: def.requires_admin,
            requires_install: def.requires_install,
        }
    }
}

/// Check PowerShell Script Block Logging
pub fn check_powershell_log() -> SensorCheckResult {
    let def = &WINDOWS_SENSORS[3]; // powershell_log
    
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new("wevtutil");
        cmd.creation_flags(0x08000000);
        let result = cmd
            .args(["gl", "Microsoft-Windows-PowerShell/Operational"])
            .output();
            
        match result {
            Ok(output) if output.status.success() => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                let is_enabled = output_str.contains("enabled: true");
                
                if is_enabled {
                    SensorCheckResult {
                        sensor_name: def.sensor_name.to_string(),
                        sensor_id: def.sensor_id.to_string(),
                        status: SensorStatus::Configured,
                        status_label: SensorStatus::Configured.display_label().to_string(),
                        reason_code: None,
                        message: Some("Channel accessible and enabled".to_string()),
                        capabilities: def.capabilities.iter().map(|s| s.to_string()).collect(),
                        requires_admin: def.requires_admin,
                        requires_install: def.requires_install,
                    }
                } else {
                    SensorCheckResult {
                        sensor_name: def.sensor_name.to_string(),
                        sensor_id: def.sensor_id.to_string(),
                        status: SensorStatus::Configured,
                        status_label: "Installed but logging may be disabled".to_string(),
                        reason_code: Some("LOGGING_DISABLED".to_string()),
                        message: Some("PowerShell Operational log exists but Script Block Logging may not be enabled via GPO".to_string()),
                        capabilities: def.capabilities.iter().map(|s| s.to_string()).collect(),
                        requires_admin: def.requires_admin,
                        requires_install: def.requires_install,
                    }
                }
            }
            _ => SensorCheckResult {
                sensor_name: def.sensor_name.to_string(),
                sensor_id: def.sensor_id.to_string(),
                status: SensorStatus::Missing,
                status_label: SensorStatus::Missing.display_label().to_string(),
                reason_code: Some("LOG_NOT_FOUND".to_string()),
                message: Some("PowerShell Operational log not accessible".to_string()),
                capabilities: Vec::new(),
                requires_admin: def.requires_admin,
                requires_install: def.requires_install,
            },
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        SensorCheckResult {
            sensor_name: def.sensor_name.to_string(),
            sensor_id: def.sensor_id.to_string(),
            status: SensorStatus::Missing,
            status_label: SensorStatus::Missing.display_label().to_string(),
            reason_code: Some("WRONG_PLATFORM".to_string()),
            message: Some("PowerShell logging is Windows-only".to_string()),
            capabilities: Vec::new(),
            requires_admin: def.requires_admin,
            requires_install: def.requires_install,
        }
    }
}

// ============================================================================
// Aggregate Capability Status
// ============================================================================

/// Overall capability status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallCapabilityStatus {
    /// All expected sensors are active
    Full,
    /// Most sensors active, some degraded
    Partial,
    /// Only basic sensors available
    Limited,
    /// Critical sensors blocked, minimal detection possible
    Blocked,
}

impl OverallCapabilityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::Limited => "limited",
            Self::Blocked => "blocked",
        }
    }
}

/// Attack surface coverage status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceStatus {
    pub surface: String,
    /// Coverage status: "configured" (sensors accessible), "partial", "blocked"
    /// Note: "covered" in run views means facts were observed
    pub status: String,
    /// Sensors that are configured and usable
    pub configured_sensors: Vec<String>,
    pub missing_sensors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    /// Status label for UI display
    pub status_label: String,
}

/// Runtime pipeline status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStatus {
    pub components: Vec<PipelineComponentStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_run: Option<ActiveRunMetrics>,
}

/// Complete capability status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityStatus {
    pub overall_status: OverallCapabilityStatus,
    pub sensors: Vec<SensorCheckResult>,
    pub pipeline: PipelineStatus,
    pub fact_types_possible: Vec<String>,
    pub attack_surfaces: HashMap<String, AttackSurfaceStatus>,
    pub notes: Vec<String>,
    pub is_admin: bool,
}

/// Check all sensors and compute aggregate capability status
/// 
/// For pipeline status, pass data_dir for binary/db checks.
/// Pass active_run metrics if a run is active (from Supervisor).
pub fn check_capability_status_with_pipeline(
    data_dir: &Path,
    active_run: Option<&ActiveRunMetrics>,
) -> CapabilityStatus {
    let is_admin = is_elevated();
    
    // Check all sensors
    let sensors = vec![
        check_sysmon(),
        check_security_log(is_admin),
        check_system_log(),
        check_powershell_log(),
    ];
    
    // Check pipeline components
    let mut components: Vec<PipelineComponentStatus> = Vec::new();
    
    // Capture binary
    components.push(check_binary_present("EDR_CAPTURE_BINARY", "capture_windows_rotating"));
    
    // Locald binary
    components.push(check_binary_present("EDR_LOCALD_BINARY", "edr-locald"));
    
    // Data directory writability
    components.push(check_dir_writable(data_dir, "data_dir", "Data directory"));
    components.push(check_db_writable(&data_dir.join("workbench.db")));
    
    let pipeline = PipelineStatus {
        components,
        active_run: active_run.cloned(),
    };
    
    // Compute possible fact types
    let mut fact_types_possible: Vec<String> = Vec::new();
    for sensor in &sensors {
        if sensor.status.is_usable() {
            // Map sensor to fact types
            for def in WINDOWS_SENSORS {
                if def.sensor_id == sensor.sensor_id {
                    for ft in def.fact_types {
                        if !fact_types_possible.contains(&ft.to_string()) {
                            fact_types_possible.push(ft.to_string());
                        }
                    }
                }
            }
        }
    }
    
    // Compute attack surface coverage
    let attack_surface_names = ["process", "auth", "persistence", "network", "evasion", "file"];
    let mut attack_surfaces: HashMap<String, AttackSurfaceStatus> = HashMap::new();
    
    for surface in attack_surface_names {
        let mut configured_sensors: Vec<String> = Vec::new();
        let mut missing_sensors: Vec<String> = Vec::new();
        let mut blocked_reason: Option<String> = None;
        
        for def in WINDOWS_SENSORS {
            if def.attack_surfaces.contains(&surface) {
                // Find corresponding sensor check
                let sensor_result = sensors.iter().find(|s| s.sensor_id == def.sensor_id);
                match sensor_result {
                    Some(s) if s.status.is_usable() => {
                        configured_sensors.push(s.sensor_name.clone());
                    }
                    Some(s) => {
                        missing_sensors.push(s.sensor_name.clone());
                        if blocked_reason.is_none() {
                            blocked_reason = s.message.clone();
                        }
                    }
                    None => {
                        missing_sensors.push(def.sensor_name.to_string());
                    }
                }
            }
        }
        
        // Status semantics: "configured" = sensors accessible, "partial" = some sensors blocked,
        // "blocked" = no sensors accessible. Note: "covered" only used in run views with observed facts.
        let (status, status_label) = if missing_sensors.is_empty() {
            ("configured", "Configured (sensors accessible)")
        } else if configured_sensors.is_empty() {
            ("blocked", "Blocked (no sensors accessible)")
        } else {
            ("partial", "Partial (some sensors blocked)")
        };
        
        attack_surfaces.insert(surface.to_string(), AttackSurfaceStatus {
            surface: surface.to_string(),
            status: status.to_string(),
            configured_sensors,
            missing_sensors,
            blocked_reason,
            status_label: status_label.to_string(),
        });
    }
    
    // Compute overall status based on configured (not active - that requires observed facts)
    let configured_count = sensors.iter().filter(|s| s.status.is_usable()).count();
    let _blocked_count = sensors.iter().filter(|s| s.status == SensorStatus::Blocked || s.status == SensorStatus::Missing).count();
    let total = sensors.len();
    
    let overall_status = if configured_count == total {
        OverallCapabilityStatus::Full
    } else if configured_count >= total / 2 {
        OverallCapabilityStatus::Partial
    } else if configured_count > 0 {
        OverallCapabilityStatus::Limited
    } else {
        OverallCapabilityStatus::Blocked
    };
    
    // Build notes
    let mut notes: Vec<String> = Vec::new();
    
    if !is_admin {
        notes.push("Running without Administrator privileges - Security Event Log is not accessible".to_string());
    }
    
    for sensor in &sensors {
        if sensor.status == SensorStatus::Missing && sensor.requires_install {
            notes.push(format!("Install {} to enable additional detections", sensor.sensor_name));
        }
        if sensor.status == SensorStatus::Blocked {
            if let Some(ref msg) = sensor.message {
                notes.push(msg.clone());
            }
        }
    }
    
    // Check pipeline components for issues
    for comp in &pipeline.components {
        if !comp.status.is_usable() {
            if let Some(ref msg) = comp.message {
                notes.push(msg.clone());
            }
        }
    }
    
    CapabilityStatus {
        overall_status,
        sensors,
        pipeline,
        fact_types_possible,
        attack_surfaces,
        notes,
        is_admin,
    }
}

/// Legacy wrapper that checks capability without full pipeline info
/// 
/// Use check_capability_status_with_pipeline() when you have access to data_dir
/// for complete pipeline component visibility.
pub fn check_capability_status() -> CapabilityStatus {
    // Use a default path if available from env, otherwise empty components
    let data_dir = std::env::var("EDR_DATA_DIR")
        .map(|s| std::path::PathBuf::from(s))
        .ok();
    
    if let Some(ref dir) = data_dir {
        check_capability_status_with_pipeline(dir, None)
    } else {
        // Fallback: minimal check without pipeline
        let is_admin = is_elevated();
        let sensors = vec![
            check_sysmon(),
            check_security_log(is_admin),
            check_system_log(),
            check_powershell_log(),
        ];
        
        // Empty pipeline (no data_dir available)
        let pipeline = PipelineStatus {
            components: vec![],
            active_run: None,
        };
        
        // Build minimal status
        let mut fact_types_possible: Vec<String> = Vec::new();
        for sensor in &sensors {
            if sensor.status.is_usable() {
                for def in WINDOWS_SENSORS {
                    if def.sensor_id == sensor.sensor_id {
                        for ft in def.fact_types {
                            if !fact_types_possible.contains(&ft.to_string()) {
                                fact_types_possible.push(ft.to_string());
                            }
                        }
                    }
                }
            }
        }
        
        // Build attack surfaces
        let attack_surface_names = ["process", "auth", "persistence", "network", "evasion", "file"];
        let mut attack_surfaces: HashMap<String, AttackSurfaceStatus> = HashMap::new();
        for surface in attack_surface_names {
            let mut configured_sensors: Vec<String> = Vec::new();
            let mut missing_sensors: Vec<String> = Vec::new();
            let mut blocked_reason: Option<String> = None;
            
            for def in WINDOWS_SENSORS {
                if def.attack_surfaces.contains(&surface) {
                    let sensor_result = sensors.iter().find(|s| s.sensor_id == def.sensor_id);
                    match sensor_result {
                        Some(s) if s.status.is_usable() => {
                            configured_sensors.push(s.sensor_name.clone());
                        }
                        Some(s) => {
                            missing_sensors.push(s.sensor_name.clone());
                            if blocked_reason.is_none() {
                                blocked_reason = s.message.clone();
                            }
                        }
                        None => {
                            missing_sensors.push(def.sensor_name.to_string());
                        }
                    }
                }
            }
            
            let (status, status_label) = if missing_sensors.is_empty() {
                ("configured", "Configured (sensors accessible)")
            } else if configured_sensors.is_empty() {
                ("blocked", "Blocked (no sensors accessible)")
            } else {
                ("partial", "Partial (some sensors blocked)")
            };
            
            attack_surfaces.insert(surface.to_string(), AttackSurfaceStatus {
                surface: surface.to_string(),
                status: status.to_string(),
                configured_sensors,
                missing_sensors,
                blocked_reason,
                status_label: status_label.to_string(),
            });
        }
        
        let configured_count = sensors.iter().filter(|s| s.status.is_usable()).count();
        let total = sensors.len();
        
        let overall_status = if configured_count == total {
            OverallCapabilityStatus::Full
        } else if configured_count >= total / 2 {
            OverallCapabilityStatus::Partial
        } else if configured_count > 0 {
            OverallCapabilityStatus::Limited
        } else {
            OverallCapabilityStatus::Blocked
        };
        
        let mut notes: Vec<String> = Vec::new();
        if !is_admin {
            notes.push("Running without Administrator privileges - Security Event Log is not accessible".to_string());
        }
        
        CapabilityStatus {
            overall_status,
            sensors,
            pipeline,
            fact_types_possible,
            attack_surfaces,
            notes,
            is_admin,
        }
    }
}

// ============================================================================
// Playbook Dependency Resolution
// ============================================================================

/// Derived status for a playbook based on current capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookDerivedStatus {
    /// All requirements met, playbook will evaluate
    Enabled,
    /// Requirements not met due to missing sensors/telemetry
    BlockedByTelemetry,
    /// Playbook disabled in configuration
    DisabledByConfig,
    /// Playbook YAML is invalid or unsupported
    SkippedInvalid,
}

impl PlaybookDerivedStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::BlockedByTelemetry => "blocked_by_telemetry",
            Self::DisabledByConfig => "disabled_by_config",
            Self::SkippedInvalid => "skipped_invalid",
        }
    }
}

/// Resolved playbook status with dependencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookCapabilityInfo {
    pub playbook_id: String,
    pub playbook_name: String,
    pub derived_status: PlaybookDerivedStatus,
    pub attack_surfaces: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blocked_by: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

/// Map MITRE tactics to attack surfaces
pub fn mitre_tactic_to_surface(tactic: &str) -> &'static str {
    match tactic.to_lowercase().as_str() {
        "execution" | "ta0002" => "process",
        "persistence" | "ta0003" => "persistence",
        "privilege-escalation" | "privilege_escalation" | "ta0004" => "auth",
        "defense-evasion" | "defense_evasion" | "ta0005" => "evasion",
        "credential-access" | "credential_access" | "ta0006" => "auth",
        "discovery" | "ta0007" => "process",
        "lateral-movement" | "lateral_movement" | "ta0008" => "network",
        "collection" | "ta0009" => "file",
        "command-and-control" | "command_and_control" | "ta0011" => "network",
        "exfiltration" | "ta0010" => "network",
        "impact" | "ta0040" => "process",
        "initial-access" | "initial_access" | "ta0001" => "network",
        _ => "other",
    }
}

/// Map playbook family/category to attack surface
pub fn category_to_surface(category: &str) -> &'static str {
    match category.to_lowercase().as_str() {
        "execution" | "process" => "process",
        "persistence" => "persistence",
        "privilege_escalation" | "privilege-escalation" => "auth",
        "defense_evasion" | "defense-evasion" | "evasion" => "evasion",
        "credential_access" | "credential-access" | "auth" => "auth",
        "lateral_movement" | "lateral-movement" | "network" => "network",
        "exfiltration" => "network",
        "file" | "collection" => "file",
        _ => "other",
    }
}

// ============================================================================
// Capability Snapshot for Runs
// ============================================================================

/// Capability snapshot to be stored in run_meta.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    pub overall_status: String,
    pub is_admin: bool,
    pub sensors: Vec<SensorSnapshotEntry>,
    pub fact_types_possible: Vec<String>,
    pub attack_surface_coverage: HashMap<String, String>, // surface -> status
    pub playbook_summary: PlaybookSummary,
    pub critical_blockers: Vec<String>,
    pub captured_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorSnapshotEntry {
    pub sensor_id: String,
    pub sensor_name: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookSummary {
    pub total_loaded: u32,
    pub enabled_count: u32,
    pub blocked_count: u32,
    pub skipped_count: u32,
    pub disabled_count: u32,
}

/// Capture current capability snapshot for run_meta.json
pub fn capture_capability_snapshot() -> CapabilitySnapshot {
    let status = check_capability_status();
    
    let sensors: Vec<SensorSnapshotEntry> = status.sensors.iter().map(|s| SensorSnapshotEntry {
        sensor_id: s.sensor_id.clone(),
        sensor_name: s.sensor_name.clone(),
        status: s.status.as_str().to_string(),
        reason_code: s.reason_code.clone(),
    }).collect();
    
    let attack_surface_coverage: HashMap<String, String> = status.attack_surfaces.iter()
        .map(|(k, v)| (k.clone(), v.status.clone()))
        .collect();
    
    let critical_blockers: Vec<String> = status.sensors.iter()
        .filter(|s| s.status == SensorStatus::Blocked || s.status == SensorStatus::Missing)
        .filter_map(|s| s.message.clone())
        .collect();
    
    CapabilitySnapshot {
        overall_status: status.overall_status.as_str().to_string(),
        is_admin: status.is_admin,
        sensors,
        fact_types_possible: status.fact_types_possible,
        attack_surface_coverage,
        playbook_summary: PlaybookSummary {
            total_loaded: 0, // Will be filled by caller
            enabled_count: 0,
            blocked_count: 0,
            skipped_count: 0,
            disabled_count: 0,
        },
        critical_blockers,
        captured_at: chrono::Utc::now().to_rfc3339(),
    }
}

// ============================================================================
// User Guidance Generation
// ============================================================================

/// Generate user guidance messages based on current capability status
pub fn generate_user_guidance(status: &CapabilityStatus) -> Vec<String> {
    let mut guidance: Vec<String> = Vec::new();
    
    // Check for Sysmon
    let sysmon = status.sensors.iter().find(|s| s.sensor_id == "sysmon");
    if let Some(s) = sysmon {
        if s.status == SensorStatus::Missing {
            guidance.push("Install Sysmon to enable process, network, and file monitoring detections".to_string());
        }
    }
    
    // Check for admin/security log
    if !status.is_admin {
        guidance.push("Run as Administrator to enable Security Event Log detections (authentication, privilege use)".to_string());
    }
    
    // Check PowerShell logging
    let ps = status.sensors.iter().find(|s| s.sensor_id == "powershell_log");
    if let Some(s) = ps {
        if s.status != SensorStatus::Active {
            guidance.push("Enable PowerShell Script Block Logging via Group Policy for script execution visibility".to_string());
        }
    }
    
    guidance
}

// ============================================================================
// Coverage Gaps Analysis (Dev-Only Planning Tool)
// ============================================================================

/// Attack surface coverage gap analysis
/// 
/// This is a dev/planning tool to identify what telemetry is needed
/// for complete coverage of each attack surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceGap {
    /// Surface name (process, auth, persistence, network, evasion, file)
    pub surface: String,
    /// What's possible based on configured sensors
    pub configured_possible: bool,
    /// Facts observed in last run (if run_id provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_in_run: Option<bool>,
    /// Playbooks enabled for this surface
    pub playbooks_enabled_count: u32,
    /// Playbooks blocked due to missing telemetry
    pub playbooks_blocked_count: u32,
    /// Playbooks that fired (if run context)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playbooks_fired_count: Option<u32>,
    /// Fact types required for this surface
    pub required_fact_types: Vec<String>,
    /// Fact types that are available
    pub available_fact_types: Vec<String>,
    /// Missing prerequisites (what's needed to enable)
    pub missing_prerequisites: Vec<String>,
    /// Coverage percentage (0-100)
    pub coverage_percent: u8,
}

/// Complete gaps report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageGapsReport {
    /// Analysis timestamp
    pub analyzed_at: String,
    /// Run ID if analyzing a specific run
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Per-surface gap analysis
    pub attack_surfaces: Vec<AttackSurfaceGap>,
    /// Overall coverage percentage
    pub overall_coverage_percent: u8,
    /// Top recommendations to improve coverage
    pub recommendations: Vec<String>,
    /// Summary counts
    pub summary: GapsSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapsSummary {
    pub surfaces_fully_covered: u32,
    pub surfaces_partially_covered: u32,
    pub surfaces_blocked: u32,
    pub total_playbooks_enabled: u32,
    pub total_playbooks_blocked: u32,
    pub fact_types_available: u32,
    pub fact_types_total: u32,
}

/// Canonical mapping of attack surfaces to required fact types
pub static SURFACE_FACT_REQUIREMENTS: &[(&str, &[&str])] = &[
    ("process", &["ProcSpawn", "Exec", "ShellCommand", "ScriptExec", "ModuleLoad"]),
    ("auth", &["AuthEvent", "PrivilegeBoundary"]),
    ("persistence", &["PersistArtifact", "RegistryMod"]),
    ("network", &["OutboundConnect", "DnsResolve", "InboundConnection"]),
    ("evasion", &["LogTamper", "SecurityDisable", "MemAlloc", "Injection"]),
    ("file", &["WritePath", "CreatePath", "DeletePath", "ReadPath"]),
    ("credential_access", &["ProcessAccess"]), // Requires Sysmon Event ID 10
];

/// All canonical fact types for coverage calculation
pub static ALL_FACT_TYPES: &[&str] = &[
    "ProcSpawn", "Exec", "OutboundConnect", "InboundConnection", "DnsResolve",
    "WritePath", "ReadPath", "CreatePath", "DeletePath", "MovePath",
    "PersistArtifact", "PrivilegeBoundary", "MemViolation", "MemAlloc",
    "ModuleLoad", "Injection", "RegistryMod", "AuthEvent", "LogTamper",
    "SecurityDisable", "ShellCommand", "ScriptExec", "ProcessAccess",
];

/// Build coverage gaps report
/// 
/// If run_id is provided, enriches with observed facts from that run.
/// Otherwise reports based on configured sensors only.
pub fn build_coverage_gaps_report(
    cap_status: &CapabilityStatus,
    playbook_counts: Option<&HashMap<String, (u32, u32, u32)>>, // surface -> (enabled, blocked, fired)
    observed_fact_types: Option<&[String]>,
    run_id: Option<&str>,
) -> CoverageGapsReport {
    let mut attack_surfaces: Vec<AttackSurfaceGap> = Vec::new();
    let mut total_enabled = 0u32;
    let mut total_blocked = 0u32;
    let mut surfaces_full = 0u32;
    let mut surfaces_partial = 0u32;
    let mut surfaces_blocked = 0u32;
    
    for (surface, required_fts) in SURFACE_FACT_REQUIREMENTS {
        let surface_name = surface.to_string();
        
        // Check which required fact types are available
        let available: Vec<String> = required_fts.iter()
            .filter(|ft| cap_status.fact_types_possible.contains(&ft.to_string()))
            .map(|ft| ft.to_string())
            .collect();
        
        let configured_possible = !available.is_empty();
        
        // Check observed facts if run context provided
        let observed_in_run = observed_fact_types.map(|obs| {
            required_fts.iter().any(|ft| obs.contains(&ft.to_string()))
        });
        
        // Get playbook counts for this surface
        let (enabled, blocked, fired) = playbook_counts
            .and_then(|pc| pc.get(*surface))
            .copied()
            .unwrap_or((0, 0, 0));
        
        total_enabled += enabled;
        total_blocked += blocked;
        
        // Identify missing prerequisites
        let mut missing: Vec<String> = Vec::new();
        
        // Check sensor requirements based on surface
        let surface_status = cap_status.attack_surfaces.get(*surface);
        if let Some(ss) = surface_status {
            for sensor in &ss.missing_sensors {
                if sensor.contains("Sysmon") {
                    missing.push("Install Sysmon for process/network/file monitoring".to_string());
                }
                if sensor.contains("Security") {
                    missing.push("Run as Administrator for Security Event Log access".to_string());
                }
                if sensor.contains("PowerShell") {
                    missing.push("Enable PowerShell Script Block Logging via GPO".to_string());
                }
            }
        }
        
        // Calculate coverage percentage
        let coverage_percent = if required_fts.is_empty() {
            100
        } else {
            ((available.len() as f32 / required_fts.len() as f32) * 100.0) as u8
        };
        
        // Track surface coverage level
        if coverage_percent == 100 {
            surfaces_full += 1;
        } else if coverage_percent > 0 {
            surfaces_partial += 1;
        } else {
            surfaces_blocked += 1;
        }
        
        attack_surfaces.push(AttackSurfaceGap {
            surface: surface_name,
            configured_possible,
            observed_in_run,
            playbooks_enabled_count: enabled,
            playbooks_blocked_count: blocked,
            playbooks_fired_count: if run_id.is_some() { Some(fired) } else { None },
            required_fact_types: required_fts.iter().map(|s| s.to_string()).collect(),
            available_fact_types: available,
            missing_prerequisites: missing,
            coverage_percent,
        });
    }
    
    // Calculate overall coverage
    let total_required: usize = SURFACE_FACT_REQUIREMENTS.iter()
        .map(|(_, fts)| fts.len())
        .sum();
    let total_available: usize = attack_surfaces.iter()
        .map(|s| s.available_fact_types.len())
        .sum();
    let overall_coverage = if total_required > 0 {
        ((total_available as f32 / total_required as f32) * 100.0) as u8
    } else {
        100
    };
    
    // Generate recommendations
    let mut recommendations: Vec<String> = Vec::new();
    
    if !cap_status.is_admin {
        recommendations.push("Run as Administrator to unlock Security Event Log and auth detections".to_string());
    }
    
    let sysmon = cap_status.sensors.iter().find(|s| s.sensor_id == "sysmon");
    if sysmon.is_none() || !sysmon.unwrap().status.is_usable() {
        recommendations.push("Install Sysmon from Microsoft Sysinternals for process, network, and file monitoring".to_string());
    }
    
    let ps_log = cap_status.sensors.iter().find(|s| s.sensor_id == "powershell_log");
    if ps_log.is_none() || !ps_log.unwrap().status.is_usable() {
        recommendations.push("Enable PowerShell Script Block Logging for script execution visibility".to_string());
    }
    
    if surfaces_blocked > 0 {
        recommendations.push(format!("{} attack surfaces have no telemetry coverage - review sensor requirements", surfaces_blocked));
    }
    
    CoverageGapsReport {
        analyzed_at: chrono::Utc::now().to_rfc3339(),
        run_id: run_id.map(String::from),
        attack_surfaces,
        overall_coverage_percent: overall_coverage,
        recommendations,
        summary: GapsSummary {
            surfaces_fully_covered: surfaces_full,
            surfaces_partially_covered: surfaces_partial,
            surfaces_blocked,
            total_playbooks_enabled: total_enabled,
            total_playbooks_blocked: total_blocked,
            fact_types_available: cap_status.fact_types_possible.len() as u32,
            fact_types_total: ALL_FACT_TYPES.len() as u32,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sensor_status_usable() {
        assert!(SensorStatus::Active.is_usable());
        assert!(SensorStatus::Configured.is_usable());
        assert!(!SensorStatus::Missing.is_usable());
        assert!(!SensorStatus::Blocked.is_usable());
    }
    
    #[test]
    fn test_mitre_tactic_mapping() {
        assert_eq!(mitre_tactic_to_surface("execution"), "process");
        assert_eq!(mitre_tactic_to_surface("persistence"), "persistence");
        assert_eq!(mitre_tactic_to_surface("lateral-movement"), "network");
    }
    
    #[test]
    fn test_category_mapping() {
        assert_eq!(category_to_surface("process"), "process");
        assert_eq!(category_to_surface("auth"), "auth");
        assert_eq!(category_to_surface("unknown"), "other");
    }
    
    #[test]
    fn test_surface_fact_requirements() {
        // Verify all surfaces have requirements defined
        assert!(!SURFACE_FACT_REQUIREMENTS.is_empty());
        for (surface, fts) in SURFACE_FACT_REQUIREMENTS {
            assert!(!surface.is_empty());
            assert!(!fts.is_empty(), "Surface {} has no fact requirements", surface);
        }
    }
}

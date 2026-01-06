//! Scenario Profiles for Detection Engineer Workflow Harness
//!
//! Defines scenario profiles with expected outcomes for validation testing.
//! Each scenario specifies:
//! - Commands to execute (safe, whitelisted)
//! - Expected Windows event IDs and channels
//! - Expected fact types
//! - Expected playbooks that should match
//! - Required capabilities (admin, sysmon, etc.)

// Used by Tauri commands, not CLI binaries
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Scenario tier indicating risk level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScenarioTier {
    A,  // Safe: whoami, hostname, basic enumeration
    B,  // Moderate: registry query, scheduled task query, wmic
    C,  // Advanced: net user, sc query, credential enum simulation
}

impl ScenarioTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScenarioTier::A => "A",
            ScenarioTier::B => "B",
            ScenarioTier::C => "C",
        }
    }
    
    pub fn description(&self) -> &'static str {
        match self {
            ScenarioTier::A => "Safe: Basic system enumeration",
            ScenarioTier::B => "Moderate: Registry and task queries",
            ScenarioTier::C => "Advanced: User/service enumeration",
        }
    }
}

/// A single command step in a scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioStep {
    pub name: String,
    pub exe: String,
    pub args: Vec<String>,
    pub description: String,
}

/// Expected telemetry from a scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioExpectations {
    /// Expected Windows event IDs (if any)
    pub event_ids: Vec<u32>,
    /// Expected event channels
    pub channels: Vec<String>,
    /// Expected fact types
    pub fact_types: Vec<String>,
    /// Expected playbooks that should match
    pub playbooks: Vec<String>,
    /// Expected signal characteristics
    pub signal_severity: Option<String>,
    /// MITRE ATT&CK techniques expected
    pub mitre_techniques: Vec<String>,
}

/// Capability requirements for a scenario
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScenarioCapabilities {
    pub requires_admin: bool,
    pub requires_sysmon: bool,
    pub requires_audit_policy: bool,
    pub requires_powershell_logging: bool,
}

/// A complete scenario profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioProfile {
    pub id: String,
    pub name: String,
    pub tier: ScenarioTier,
    pub description: String,
    pub steps: Vec<ScenarioStep>,
    pub expectations: ScenarioExpectations,
    pub capabilities: ScenarioCapabilities,
}

/// Result of running a single scenario step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_name: String,
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Observed telemetry during scenario execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedTelemetry {
    pub events_count: u32,
    pub event_ids_seen: Vec<u32>,
    pub channels_seen: Vec<String>,
    pub facts_count: u32,
    pub fact_types_seen: Vec<String>,
}

/// Validation result for a specific expectation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectationResult {
    pub category: String,
    pub expected: String,
    pub observed: String,
    pub passed: bool,
    pub note: Option<String>,
}

/// Complete scenario execution report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioReport {
    pub scenario_id: String,
    pub scenario_name: String,
    pub tier: String,
    pub started_at: String,
    pub completed_at: String,
    pub duration_ms: u64,
    
    /// Step execution results
    pub step_results: Vec<StepResult>,
    
    /// Observed telemetry summary
    pub observed: ObservedTelemetry,
    
    /// Signals created during this scenario
    pub signals_created: Vec<String>,
    
    /// Expectation validation results
    pub expectation_results: Vec<ExpectationResult>,
    
    /// Explainability validation for created signals
    pub explain_validation: Vec<ExplainValidation>,
    
    /// Overall verdict
    pub verdict: ScenarioVerdict,
    
    /// Diagnosis if failed
    pub diagnosis: Option<String>,
    
    /// Capabilities that were missing
    pub missing_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainValidation {
    pub signal_id: String,
    pub playbook_id: String,
    pub has_required_slots_filled: bool,
    pub has_evidence_ptrs: bool,
    pub has_entity_bundle: bool,
    pub valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScenarioVerdict {
    Pass,           // All expectations met
    PartialPass,    // Some expectations met
    CapabilityGap,  // Failed due to missing capabilities
    ExtractionGap,  // Telemetry OK but facts not extracted
    DetectionGap,   // Facts OK but playbooks didn't match
    Fail,           // Complete failure
}

impl ScenarioVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScenarioVerdict::Pass => "PASS",
            ScenarioVerdict::PartialPass => "PARTIAL_PASS",
            ScenarioVerdict::CapabilityGap => "CAPABILITY_GAP",
            ScenarioVerdict::ExtractionGap => "EXTRACTION_GAP",
            ScenarioVerdict::DetectionGap => "DETECTION_GAP",
            ScenarioVerdict::Fail => "FAIL",
        }
    }
    
    pub fn emoji(&self) -> &'static str {
        match self {
            ScenarioVerdict::Pass => "✅",
            ScenarioVerdict::PartialPass => "⚠️",
            ScenarioVerdict::CapabilityGap => "🔒",
            ScenarioVerdict::ExtractionGap => "🔧",
            ScenarioVerdict::DetectionGap => "📋",
            ScenarioVerdict::Fail => "❌",
        }
    }
}

/// Get all built-in scenario profiles
pub fn get_all_scenarios() -> Vec<ScenarioProfile> {
    vec![
        // === TIER A: Safe scenarios ===
        ScenarioProfile {
            id: "tier_a_user_enum".to_string(),
            name: "User Identity Enumeration".to_string(),
            tier: ScenarioTier::A,
            description: "Basic user and system identity queries".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "whoami_all".to_string(),
                    exe: "whoami.exe".to_string(),
                    args: vec!["/all".to_string()],
                    description: "Query current user with all details".to_string(),
                },
                ScenarioStep {
                    name: "hostname".to_string(),
                    exe: "hostname.exe".to_string(),
                    args: vec![],
                    description: "Get machine hostname".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],  // Process creation
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string()],
                playbooks: vec![],  // No playbook expected for benign activity
                signal_severity: None,
                mitre_techniques: vec!["T1033".to_string()],  // System Owner/User Discovery
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        ScenarioProfile {
            id: "tier_a_system_info".to_string(),
            name: "System Information Query".to_string(),
            tier: ScenarioTier::A,
            description: "Query system information via PowerShell".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "ps_sysinfo".to_string(),
                    exe: "powershell.exe".to_string(),
                    args: vec!["-Command".to_string(), "Get-ComputerInfo | Select-Object CsName,OsName,WindowsVersion".to_string()],
                    description: "Get system info via PowerShell".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688, 4103, 4104],
                channels: vec!["Security".to_string(), "Microsoft-Windows-PowerShell/Operational".to_string()],
                fact_types: vec!["Exec".to_string(), "ScriptBlock".to_string()],
                playbooks: vec!["signal_lolbin_abuse".to_string()],
                signal_severity: Some("medium".to_string()),
                mitre_techniques: vec!["T1082".to_string()],  // System Information Discovery
            },
            capabilities: ScenarioCapabilities {
                requires_powershell_logging: true,
                ..Default::default()
            },
        },
        
        // === TIER B: Moderate scenarios ===
        ScenarioProfile {
            id: "tier_b_registry_enum".to_string(),
            name: "Registry Enumeration".to_string(),
            tier: ScenarioTier::B,
            description: "Query registry for installed software and Run keys".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "reg_query_software".to_string(),
                    exe: "reg.exe".to_string(),
                    args: vec!["query".to_string(), "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion".to_string()],
                    description: "Query software registry key".to_string(),
                },
                ScenarioStep {
                    name: "reg_query_run".to_string(),
                    exe: "reg.exe".to_string(),
                    args: vec!["query".to_string(), "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()],
                    description: "Query Run key for persistence".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string()],
                playbooks: vec!["signal_registry_persistence".to_string()],
                signal_severity: Some("medium".to_string()),
                mitre_techniques: vec!["T1012".to_string(), "T1547.001".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        ScenarioProfile {
            id: "tier_b_task_enum".to_string(),
            name: "Scheduled Task Enumeration".to_string(),
            tier: ScenarioTier::B,
            description: "List scheduled tasks for persistence detection".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "schtasks_query".to_string(),
                    exe: "schtasks.exe".to_string(),
                    args: vec!["/Query".to_string(), "/FO".to_string(), "LIST".to_string()],
                    description: "List scheduled tasks".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string()],
                playbooks: vec!["signal_task_persistence".to_string()],
                signal_severity: Some("medium".to_string()),
                mitre_techniques: vec!["T1053.005".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        ScenarioProfile {
            id: "tier_b_wmic_process".to_string(),
            name: "WMI Process Enumeration".to_string(),
            tier: ScenarioTier::B,
            description: "Enumerate processes via WMIC (LOLBin activity)".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "wmic_process".to_string(),
                    exe: "wmic.exe".to_string(),
                    args: vec!["process".to_string(), "list".to_string(), "brief".to_string()],
                    description: "List processes via WMIC".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string()],
                playbooks: vec!["signal_lolbin_abuse".to_string()],
                signal_severity: Some("high".to_string()),
                mitre_techniques: vec!["T1047".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        // === TIER C: Advanced scenarios ===
        ScenarioProfile {
            id: "tier_c_user_account_enum".to_string(),
            name: "User Account Enumeration".to_string(),
            tier: ScenarioTier::C,
            description: "Enumerate local users and admin group".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "net_user".to_string(),
                    exe: "net.exe".to_string(),
                    args: vec!["user".to_string()],
                    description: "Enumerate local user accounts".to_string(),
                },
                ScenarioStep {
                    name: "net_localgroup_admins".to_string(),
                    exe: "net.exe".to_string(),
                    args: vec!["localgroup".to_string(), "Administrators".to_string()],
                    description: "List Administrators group members".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string()],
                playbooks: vec!["signal_lolbin_abuse".to_string(), "signal_lateral_movement_detection".to_string()],
                signal_severity: Some("high".to_string()),
                mitre_techniques: vec!["T1087.001".to_string(), "T1069.001".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        ScenarioProfile {
            id: "tier_c_service_enum".to_string(),
            name: "Service Enumeration".to_string(),
            tier: ScenarioTier::C,
            description: "Enumerate Windows services".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "sc_query".to_string(),
                    exe: "sc.exe".to_string(),
                    args: vec!["query".to_string()],
                    description: "Query all services".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string()],
                playbooks: vec!["signal_service_persistence".to_string()],
                signal_severity: Some("medium".to_string()),
                mitre_techniques: vec!["T1007".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        ScenarioProfile {
            id: "tier_c_certutil_decode".to_string(),
            name: "CertUtil Decode (LOLBin)".to_string(),
            tier: ScenarioTier::C,
            description: "Use certutil for base64 decode (classic LOLBin technique)".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "certutil_help".to_string(),
                    exe: "certutil.exe".to_string(),
                    args: vec!["-?".to_string()],
                    description: "Display certutil help (safe trigger)".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string()],
                playbooks: vec!["signal_lolbin_abuse".to_string(), "signal_certutil_abuse".to_string()],
                signal_severity: Some("high".to_string()),
                mitre_techniques: vec!["T1140".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        ScenarioProfile {
            id: "tier_c_nltest_domain".to_string(),
            name: "Domain Trust Enumeration".to_string(),
            tier: ScenarioTier::C,
            description: "Query domain trusts with nltest".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "nltest_trusts".to_string(),
                    exe: "nltest.exe".to_string(),
                    args: vec!["/domain_trusts".to_string()],
                    description: "Query domain trusts".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string()],
                playbooks: vec!["signal_lolbin_abuse".to_string(), "signal_lateral_movement_detection".to_string()],
                signal_severity: Some("high".to_string()),
                mitre_techniques: vec!["T1482".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        // === TIER B: RELIABLE DETECTION SCENARIOS (Limited mode compatible) ===
        
        ScenarioProfile {
            id: "tier_b_discovery_burst".to_string(),
            name: "Discovery Command Burst".to_string(),
            tier: ScenarioTier::B,
            description: "Execute multiple discovery commands to trigger burst detection".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "whoami".to_string(),
                    exe: "whoami.exe".to_string(),
                    args: vec![],
                    description: "Get current user".to_string(),
                },
                ScenarioStep {
                    name: "hostname".to_string(),
                    exe: "hostname.exe".to_string(),
                    args: vec![],
                    description: "Get hostname".to_string(),
                },
                ScenarioStep {
                    name: "ipconfig".to_string(),
                    exe: "ipconfig.exe".to_string(),
                    args: vec!["/all".to_string()],
                    description: "Network configuration".to_string(),
                },
                ScenarioStep {
                    name: "netstat".to_string(),
                    exe: "netstat.exe".to_string(),
                    args: vec!["-an".to_string()],
                    description: "Network connections".to_string(),
                },
                ScenarioStep {
                    name: "systeminfo".to_string(),
                    exe: "systeminfo.exe".to_string(),
                    args: vec![],
                    description: "System information".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string(), "ShellCommand".to_string()],
                playbooks: vec!["signal_discovery_burst".to_string()],
                signal_severity: Some("high".to_string()),
                mitre_techniques: vec!["T1082".to_string(), "T1016".to_string(), "T1033".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        ScenarioProfile {
            id: "tier_b_net_enum".to_string(),
            name: "Net Command Enumeration".to_string(),
            tier: ScenarioTier::B,
            description: "Execute net commands for user/share enumeration".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "net_user".to_string(),
                    exe: "net.exe".to_string(),
                    args: vec!["user".to_string()],
                    description: "List local users".to_string(),
                },
                ScenarioStep {
                    name: "net_localgroup".to_string(),
                    exe: "net.exe".to_string(),
                    args: vec!["localgroup".to_string()],
                    description: "List local groups".to_string(),
                },
                ScenarioStep {
                    name: "net_share".to_string(),
                    exe: "net.exe".to_string(),
                    args: vec!["share".to_string()],
                    description: "List shares".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string(), "ShellCommand".to_string()],
                playbooks: vec!["signal_net_command_abuse".to_string(), "signal_discovery_burst".to_string()],
                signal_severity: Some("medium".to_string()),
                mitre_techniques: vec!["T1087.001".to_string(), "T1135".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        ScenarioProfile {
            id: "tier_b_powershell_sysinfo".to_string(),
            name: "PowerShell System Discovery".to_string(),
            tier: ScenarioTier::B,
            description: "PowerShell-based system enumeration (no encoding)".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "ps_env".to_string(),
                    exe: "powershell.exe".to_string(),
                    args: vec!["-NoProfile".to_string(), "-Command".to_string(), "$env:COMPUTERNAME".to_string()],
                    description: "Get computer name via PowerShell".to_string(),
                },
                ScenarioStep {
                    name: "ps_user".to_string(),
                    exe: "powershell.exe".to_string(),
                    args: vec!["-NoProfile".to_string(), "-Command".to_string(), "$env:USERNAME".to_string()],
                    description: "Get username via PowerShell".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string()],
                playbooks: vec!["signal_lolbin_abuse".to_string()],
                signal_severity: Some("medium".to_string()),
                mitre_techniques: vec!["T1059.001".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        ScenarioProfile {
            id: "tier_b_task_enum".to_string(),
            name: "Scheduled Task Query".to_string(),
            tier: ScenarioTier::B,
            description: "Query scheduled tasks (persistence detection)".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "schtasks_query".to_string(),
                    exe: "schtasks.exe".to_string(),
                    args: vec!["/Query".to_string(), "/FO".to_string(), "CSV".to_string()],
                    description: "List scheduled tasks".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string()],
                playbooks: vec!["signal_schtasks_abuse".to_string(), "signal_lolbin_abuse".to_string()],
                signal_severity: Some("medium".to_string()),
                mitre_techniques: vec!["T1053.005".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        // === TIER C: ADVANCED SCENARIOS (Some require admin) ===
        
        ScenarioProfile {
            id: "tier_c_wmic_process".to_string(),
            name: "WMIC Process Query".to_string(),
            tier: ScenarioTier::C,
            description: "Query processes via WMIC (LOLBin activity)".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "wmic_process".to_string(),
                    exe: "wmic.exe".to_string(),
                    args: vec!["process".to_string(), "list".to_string(), "brief".to_string()],
                    description: "List processes via WMIC".to_string(),
                },
                ScenarioStep {
                    name: "wmic_os".to_string(),
                    exe: "wmic.exe".to_string(),
                    args: vec!["os".to_string(), "get".to_string(), "caption".to_string()],
                    description: "Get OS info via WMIC".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string(), "ShellCommand".to_string()],
                playbooks: vec!["signal_wmic_abuse".to_string(), "signal_lolbin_abuse".to_string()],
                signal_severity: Some("high".to_string()),
                mitre_techniques: vec!["T1047".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
        
        ScenarioProfile {
            id: "tier_c_reg_persistence_check".to_string(),
            name: "Registry Persistence Query".to_string(),
            tier: ScenarioTier::C,
            description: "Query common registry persistence locations".to_string(),
            steps: vec![
                ScenarioStep {
                    name: "reg_run_hklm".to_string(),
                    exe: "reg.exe".to_string(),
                    args: vec!["query".to_string(), "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()],
                    description: "Query HKLM Run key".to_string(),
                },
                ScenarioStep {
                    name: "reg_run_hkcu".to_string(),
                    exe: "reg.exe".to_string(),
                    args: vec!["query".to_string(), "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()],
                    description: "Query HKCU Run key".to_string(),
                },
            ],
            expectations: ScenarioExpectations {
                event_ids: vec![4688],
                channels: vec!["Security".to_string()],
                fact_types: vec!["Exec".to_string()],
                playbooks: vec!["signal_registry_persistence".to_string(), "signal_lolbin_abuse".to_string()],
                signal_severity: Some("medium".to_string()),
                mitre_techniques: vec!["T1547.001".to_string(), "T1012".to_string()],
            },
            capabilities: ScenarioCapabilities::default(),
        },
    ]
}

/// Get scenarios by tier
pub fn get_scenarios_by_tier(tier: ScenarioTier) -> Vec<ScenarioProfile> {
    get_all_scenarios().into_iter().filter(|s| s.tier == tier).collect()
}

/// Get scenario by ID
pub fn get_scenario_by_id(id: &str) -> Option<ScenarioProfile> {
    get_all_scenarios().into_iter().find(|s| s.id == id)
}

/// Check if scenario can run given capabilities
pub fn check_scenario_capabilities(
    scenario: &ScenarioProfile,
    is_admin: bool,
    sysmon_installed: bool,
    audit_policy_enabled: bool,
    powershell_logging: bool,
) -> Vec<String> {
    let mut missing = Vec::new();
    
    if scenario.capabilities.requires_admin && !is_admin {
        missing.push("Administrator privileges".to_string());
    }
    if scenario.capabilities.requires_sysmon && !sysmon_installed {
        missing.push("Sysmon".to_string());
    }
    if scenario.capabilities.requires_audit_policy && !audit_policy_enabled {
        missing.push("Audit policy (process creation)".to_string());
    }
    if scenario.capabilities.requires_powershell_logging && !powershell_logging {
        missing.push("PowerShell script block logging".to_string());
    }
    
    missing
}

/// Determine verdict based on results
pub fn compute_verdict(
    observed: &ObservedTelemetry,
    signals_count: usize,
    expectations: &ScenarioExpectations,
    missing_capabilities: &[String],
) -> (ScenarioVerdict, Option<String>) {
    // If missing capabilities, it's a capability gap
    if !missing_capabilities.is_empty() {
        return (
            ScenarioVerdict::CapabilityGap,
            Some(format!("Missing: {}", missing_capabilities.join(", "))),
        );
    }
    
    // Check telemetry health (Gate A)
    if observed.events_count == 0 {
        return (
            ScenarioVerdict::Fail,
            Some("No events captured - telemetry not working".to_string()),
        );
    }
    
    // Check extraction health (Gate B)
    if observed.facts_count == 0 && !expectations.fact_types.is_empty() {
        return (
            ScenarioVerdict::ExtractionGap,
            Some(format!(
                "Events captured ({}) but no facts extracted. Expected: {}",
                observed.events_count,
                expectations.fact_types.join(", ")
            )),
        );
    }
    
    // Check detection health (Gate C)
    if signals_count == 0 && !expectations.playbooks.is_empty() {
        return (
            ScenarioVerdict::DetectionGap,
            Some(format!(
                "Facts extracted ({}) but no signals generated. Expected playbooks: {}",
                observed.facts_count,
                expectations.playbooks.join(", ")
            )),
        );
    }
    
    // If signals expected and generated
    if signals_count > 0 && !expectations.playbooks.is_empty() {
        return (ScenarioVerdict::Pass, None);
    }
    
    // If no signals expected and none generated (benign scenario)
    if signals_count == 0 && expectations.playbooks.is_empty() {
        return (ScenarioVerdict::Pass, None);
    }
    
    // Partial pass if some but not all expectations met
    (
        ScenarioVerdict::PartialPass,
        Some("Some expectations met but not all".to_string()),
    )
}

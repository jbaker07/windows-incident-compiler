//! Mission Workflow System
//!
//! Defines mission types, profiles, and the core workflow for running
//! end-to-end detection sessions with quality gates and metrics.
//!
//! Mission Types:
//! - Discovery: Baseline normal activity, should produce minimal noise
//! - Adversary Simulation: Safe actions that trigger specific playbooks
//! - Forensic Import: Import evidence bundle and compile deterministically

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Mission type determines the workflow and quality gates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionType {
    /// Baseline discovery - benign actions, expect low signal noise
    Discovery,
    /// Adversary simulation - safe LOLBin/ATT&CK actions, expect specific detections
    AdversarySimulation,
    /// Forensic import - import bundle and compile, expect deterministic results
    ForensicImport,
}

impl MissionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MissionType::Discovery => "discovery",
            MissionType::AdversarySimulation => "adversary_simulation",
            MissionType::ForensicImport => "forensic_import",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            MissionType::Discovery => "Discovery",
            MissionType::AdversarySimulation => "Adversary Simulation",
            MissionType::ForensicImport => "Forensic Import",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            MissionType::Discovery => "Baseline normal activity. Run benign admin/dev commands. Signals should be minimal - validates noise suppression.",
            MissionType::AdversarySimulation => "Execute safe adversary behaviors. Triggers specific playbooks. Validates detection coverage.",
            MissionType::ForensicImport => "Import pre-captured evidence bundle. Compile and analyze. Validates deterministic processing.",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            MissionType::Discovery => "🔍",
            MissionType::AdversarySimulation => "🎯",
            MissionType::ForensicImport => "📦",
        }
    }
}

/// Capture profile determines telemetry sources and intensity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProfile {
    /// Minimal: Security log only
    Minimal,
    /// Standard: Security + Sysmon + PowerShell
    Standard,
    /// Full: All available sources including ETW
    Full,
}

impl CaptureProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            CaptureProfile::Minimal => "minimal",
            CaptureProfile::Standard => "standard",
            CaptureProfile::Full => "full",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            CaptureProfile::Minimal => "Minimal",
            CaptureProfile::Standard => "Standard",
            CaptureProfile::Full => "Full",
        }
    }

    pub fn sources(&self) -> Vec<&'static str> {
        match self {
            CaptureProfile::Minimal => vec!["Security"],
            CaptureProfile::Standard => vec!["Security", "Sysmon", "PowerShell"],
            CaptureProfile::Full => vec!["Security", "Sysmon", "PowerShell", "WMI", "TaskScheduler", "Defender"],
        }
    }
}

/// Mission configuration for a run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionConfig {
    /// Type of mission
    pub mission_type: MissionType,
    /// Specific profile/pack within the mission type
    pub profile: String,
    /// Capture duration in seconds
    pub duration_seconds: u32,
    /// Capture profile
    pub capture_profile: CaptureProfile,
    /// Specific playbooks to load (None = all)
    pub playbooks: Option<Vec<String>>,
    /// Scenario pack to execute (for adversary simulation)
    pub scenario_pack: Option<String>,
    /// Import bundle path (for forensic import)
    pub import_bundle_path: Option<String>,
}

impl Default for MissionConfig {
    fn default() -> Self {
        Self {
            mission_type: MissionType::Discovery,
            profile: "default".to_string(),
            duration_seconds: 300, // 5 minutes
            capture_profile: CaptureProfile::Standard,
            playbooks: None,
            scenario_pack: None,
            import_bundle_path: None,
        }
    }
}

/// Expected outcomes for quality gate validation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MissionExpectations {
    /// Minimum events expected (0 = no minimum)
    pub min_events: u32,
    /// Maximum signals expected (for Discovery - noise gate)
    pub max_noise_signals: Option<u32>,
    /// Minimum signals expected (for Adversary Simulation)
    pub min_detections: Option<u32>,
    /// Required playbooks that must match
    pub required_playbooks: Vec<String>,
    /// Required MITRE techniques
    pub required_techniques: Vec<String>,
    /// Maximum acceptable parse error rate (0.0 - 1.0)
    pub max_parse_error_rate: f64,
    /// Minimum deref success rate (0.0 - 1.0)
    pub min_deref_success_rate: f64,
    /// Minimum slot fill rate (0.0 - 1.0)
    pub min_slot_fill_rate: f64,
    /// Maximum peak RSS in MB
    pub max_peak_rss_mb: Option<f64>,
}

/// A mission profile bundles config and expectations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub mission_type: MissionType,
    pub config: MissionConfig,
    pub expectations: MissionExpectations,
}

/// Get all built-in mission profiles
pub fn get_builtin_profiles() -> Vec<MissionProfile> {
    vec![
        // === DISCOVERY PROFILES ===
        MissionProfile {
            id: "discovery_benign_admin".to_string(),
            name: "Benign Admin Activity".to_string(),
            description: "Simulates normal admin tasks. Should produce minimal or zero signals.".to_string(),
            mission_type: MissionType::Discovery,
            config: MissionConfig {
                mission_type: MissionType::Discovery,
                profile: "benign_admin".to_string(),
                duration_seconds: 300,
                capture_profile: CaptureProfile::Standard,
                playbooks: None,
                scenario_pack: Some("discovery_benign_admin".to_string()),
                import_bundle_path: None,
            },
            expectations: MissionExpectations {
                min_events: 10,
                max_noise_signals: Some(2), // Allow at most 2 signals for benign activity
                min_detections: None,
                required_playbooks: vec![],
                required_techniques: vec![],
                max_parse_error_rate: 0.01,
                min_deref_success_rate: 0.95,
                min_slot_fill_rate: 0.90,
                max_peak_rss_mb: Some(500.0),
            },
        },
        MissionProfile {
            id: "discovery_dev_workflow".to_string(),
            name: "Developer Workflow".to_string(),
            description: "Simulates typical dev activity (git, cargo, npm). Should not trigger alerts.".to_string(),
            mission_type: MissionType::Discovery,
            config: MissionConfig {
                mission_type: MissionType::Discovery,
                profile: "dev_workflow".to_string(),
                duration_seconds: 300,
                capture_profile: CaptureProfile::Standard,
                playbooks: None,
                scenario_pack: Some("discovery_dev_workflow".to_string()),
                import_bundle_path: None,
            },
            expectations: MissionExpectations {
                min_events: 20,
                max_noise_signals: Some(3),
                min_detections: None,
                required_playbooks: vec![],
                required_techniques: vec![],
                max_parse_error_rate: 0.01,
                min_deref_success_rate: 0.95,
                min_slot_fill_rate: 0.90,
                max_peak_rss_mb: Some(500.0),
            },
        },

        // === ADVERSARY SIMULATION PROFILES ===
        MissionProfile {
            id: "adversary_lolbin_tier_a".to_string(),
            name: "LOLBin Tier A (Safe)".to_string(),
            description: "Executes safe LOLBin commands (whoami, hostname, systeminfo). Validates basic detection.".to_string(),
            mission_type: MissionType::AdversarySimulation,
            config: MissionConfig {
                mission_type: MissionType::AdversarySimulation,
                profile: "lolbin_tier_a".to_string(),
                duration_seconds: 180,
                capture_profile: CaptureProfile::Standard,
                playbooks: None,
                scenario_pack: Some("adversary_lolbin_tier_a".to_string()),
                import_bundle_path: None,
            },
            expectations: MissionExpectations {
                min_events: 50,
                max_noise_signals: None,
                min_detections: Some(3),
                required_playbooks: vec![
                    "signal_discovery_burst".to_string(),
                ],
                required_techniques: vec!["T1033".to_string(), "T1082".to_string()],
                max_parse_error_rate: 0.01,
                min_deref_success_rate: 0.90,
                min_slot_fill_rate: 0.85,
                max_peak_rss_mb: Some(500.0),
            },
        },
        MissionProfile {
            id: "adversary_lolbin_tier_b".to_string(),
            name: "LOLBin Tier B (Moderate)".to_string(),
            description: "Registry queries, scheduled tasks, WMIC. Tests persistence and enumeration detection.".to_string(),
            mission_type: MissionType::AdversarySimulation,
            config: MissionConfig {
                mission_type: MissionType::AdversarySimulation,
                profile: "lolbin_tier_b".to_string(),
                duration_seconds: 240,
                capture_profile: CaptureProfile::Standard,
                playbooks: None,
                scenario_pack: Some("adversary_lolbin_tier_b".to_string()),
                import_bundle_path: None,
            },
            expectations: MissionExpectations {
                min_events: 100,
                max_noise_signals: None,
                min_detections: Some(5),
                required_playbooks: vec![
                    "signal_registry_persistence".to_string(),
                    "signal_schtasks_abuse".to_string(),
                    "signal_wmic_abuse".to_string(),
                ],
                required_techniques: vec!["T1012".to_string(), "T1053.005".to_string()],
                max_parse_error_rate: 0.02,
                min_deref_success_rate: 0.85,
                min_slot_fill_rate: 0.80,
                max_peak_rss_mb: Some(600.0),
            },
        },
        MissionProfile {
            id: "adversary_credential_access".to_string(),
            name: "Credential Access (Safe)".to_string(),
            description: "Safe credential enumeration patterns. Tests credential access playbooks.".to_string(),
            mission_type: MissionType::AdversarySimulation,
            config: MissionConfig {
                mission_type: MissionType::AdversarySimulation,
                profile: "credential_access".to_string(),
                duration_seconds: 180,
                capture_profile: CaptureProfile::Full,
                playbooks: Some(vec![
                    "signal_credential_access".to_string(),
                    "signal_lolbin_abuse".to_string(),
                ]),
                scenario_pack: Some("adversary_credential_access".to_string()),
                import_bundle_path: None,
            },
            expectations: MissionExpectations {
                min_events: 30,
                max_noise_signals: None,
                min_detections: Some(2),
                required_playbooks: vec!["signal_credential_access".to_string()],
                required_techniques: vec!["T1003".to_string()],
                max_parse_error_rate: 0.02,
                min_deref_success_rate: 0.85,
                min_slot_fill_rate: 0.80,
                max_peak_rss_mb: Some(500.0),
            },
        },
        MissionProfile {
            id: "adversary_defense_evasion".to_string(),
            name: "Defense Evasion (Safe)".to_string(),
            description: "Safe evasion patterns (encoded commands, unusual parents). Tests evasion detection.".to_string(),
            mission_type: MissionType::AdversarySimulation,
            config: MissionConfig {
                mission_type: MissionType::AdversarySimulation,
                profile: "defense_evasion".to_string(),
                duration_seconds: 180,
                capture_profile: CaptureProfile::Full,
                playbooks: Some(vec![
                    "signal_defense_evasion".to_string(),
                    "signal_encoded_powershell".to_string(),
                ]),
                scenario_pack: Some("adversary_defense_evasion".to_string()),
                import_bundle_path: None,
            },
            expectations: MissionExpectations {
                min_events: 30,
                max_noise_signals: None,
                min_detections: Some(2),
                required_playbooks: vec!["signal_encoded_powershell".to_string()],
                required_techniques: vec!["T1027".to_string(), "T1059.001".to_string()],
                max_parse_error_rate: 0.02,
                min_deref_success_rate: 0.85,
                min_slot_fill_rate: 0.80,
                max_peak_rss_mb: Some(500.0),
            },
        },

        // === FORENSIC IMPORT PROFILES ===
        MissionProfile {
            id: "forensic_golden_bundle".to_string(),
            name: "Golden Bundle Replay".to_string(),
            description: "Import reference bundle. Results must match golden baseline exactly.".to_string(),
            mission_type: MissionType::ForensicImport,
            config: MissionConfig {
                mission_type: MissionType::ForensicImport,
                profile: "golden_bundle".to_string(),
                duration_seconds: 0, // No capture duration for import
                capture_profile: CaptureProfile::Standard,
                playbooks: None,
                scenario_pack: None,
                import_bundle_path: Some("bundles/golden/credential_access".to_string()),
            },
            expectations: MissionExpectations {
                min_events: 100,
                max_noise_signals: None,
                min_detections: Some(5),
                required_playbooks: vec!["signal_credential_access".to_string()],
                required_techniques: vec![],
                max_parse_error_rate: 0.0, // Zero tolerance for golden bundle
                min_deref_success_rate: 1.0, // Must deref everything
                min_slot_fill_rate: 1.0, // Must fill all slots
                max_peak_rss_mb: Some(300.0),
            },
        },
    ]
}

/// Get profiles by mission type
pub fn get_profiles_by_type(mission_type: MissionType) -> Vec<MissionProfile> {
    get_builtin_profiles()
        .into_iter()
        .filter(|p| p.mission_type == mission_type)
        .collect()
}

/// Get profile by ID
pub fn get_profile_by_id(id: &str) -> Option<MissionProfile> {
    get_builtin_profiles().into_iter().find(|p| p.id == id)
}

/// Source readiness status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceReadiness {
    pub name: String,
    pub available: bool,
    pub reason: Option<String>,
    pub fix_action: Option<String>,
}

/// Overall mission readiness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionReadiness {
    pub ready: bool,
    pub readiness_level: String, // "full", "good", "limited", "blocked"
    pub sources: Vec<SourceReadiness>,
    pub warnings: Vec<String>,
    pub blockers: Vec<String>,
}

/// Mission run state (live during execution)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionRunState {
    pub run_id: String,
    pub mission_type: MissionType,
    pub profile_id: String,
    pub status: MissionRunStatus,
    pub started_at: String,
    pub elapsed_seconds: u32,
    pub remaining_seconds: Option<u32>,
    pub counters: MissionCounters,
    pub phase: MissionPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionRunStatus {
    Starting,
    Running,
    Executing, // Running scenario pack
    Stopping,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionPhase {
    Init,
    Capture,
    ScenarioExecution,
    Compile,
    QualityGates,
    Complete,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MissionCounters {
    pub events_captured: u32,
    pub segments_written: u32,
    pub facts_extracted: u32,
    pub signals_emitted: u32,
    pub scenarios_completed: u32,
    pub scenarios_total: u32,
}

/// End-of-run scoreboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionScoreboard {
    pub run_id: String,
    pub mission_type: MissionType,
    pub profile_id: String,
    pub profile_name: String,
    pub duration_seconds: u32,
    pub overall_verdict: String, // "pass", "warn", "fail"
    pub score: u32, // 0-100
    pub gates: Vec<GateResult>,
    pub key_metrics: HashMap<String, MetricValue>,
    pub recommendations: Vec<String>,
    pub run_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResult {
    pub name: String,
    pub status: String, // "pass", "warn", "fail", "skip"
    pub score: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MetricValue {
    Integer(i64),
    Float(f64),
    String(String),
    Bool(bool),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_profiles() {
        let profiles = get_builtin_profiles();
        assert!(!profiles.is_empty());
        
        // Check we have at least one of each type
        assert!(profiles.iter().any(|p| p.mission_type == MissionType::Discovery));
        assert!(profiles.iter().any(|p| p.mission_type == MissionType::AdversarySimulation));
        assert!(profiles.iter().any(|p| p.mission_type == MissionType::ForensicImport));
    }

    #[test]
    fn test_get_profile_by_id() {
        let profile = get_profile_by_id("adversary_lolbin_tier_a");
        assert!(profile.is_some());
        assert_eq!(profile.unwrap().mission_type, MissionType::AdversarySimulation);
    }
}

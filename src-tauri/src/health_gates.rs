//! Health Gates and Enhanced Metrics for Detection Engineer Workflow
//!
//! This module implements the 4-gate health validation system:
//! - Gate A: Telemetry Health - Events captured from Windows logs
//! - Gate B: Extraction Health - Facts extracted from events
//! - Gate C: Detection Health - Signals generated from facts
//! - Gate D: Explainability Health - Signals have valid explanations
//!
//! Each gate has:
//! - PASS/FAIL status
//! - Breakdown statistics
//! - Diagnosis if failed

// Used by Tauri commands, not CLI binaries
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Gate status indicating health
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateStatus {
    Pass,
    Fail,
    Partial,
    NoData,
}

impl GateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            GateStatus::Pass => "PASS",
            GateStatus::Fail => "FAIL",
            GateStatus::Partial => "PARTIAL",
            GateStatus::NoData => "NO_DATA",
        }
    }
    
    pub fn emoji(&self) -> &'static str {
        match self {
            GateStatus::Pass => "✅",
            GateStatus::Fail => "❌",
            GateStatus::Partial => "⚠️",
            GateStatus::NoData => "⏸️",
        }
    }
    
    pub fn is_healthy(&self) -> bool {
        matches!(self, GateStatus::Pass | GateStatus::Partial)
    }
}

/// Gate A: Telemetry Health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryGate {
    pub status: GateStatus,
    pub events_count: u32,
    pub segments_count: u32,
    pub channels_active: Vec<String>,
    pub events_by_channel: HashMap<String, u32>,
    pub events_by_provider: HashMap<String, u32>,
    pub events_per_second: f64,
    pub diagnosis: Option<String>,
}

impl TelemetryGate {
    pub fn evaluate(
        segments_count: u32,
        events_count: u32,
        channels: Vec<String>,
        events_by_channel: HashMap<String, u32>,
        events_by_provider: HashMap<String, u32>,
        elapsed_seconds: u64,
    ) -> Self {
        let events_per_second = if elapsed_seconds > 0 {
            events_count as f64 / elapsed_seconds as f64
        } else {
            0.0
        };
        
        let (status, diagnosis) = if events_count == 0 {
            (GateStatus::Fail, Some("No events captured. Check: (1) Running as admin, (2) Capture process running, (3) Security log access".to_string()))
        } else if !channels.contains(&"Security".to_string()) {
            (GateStatus::Partial, Some("Security channel not captured. Run as Administrator for full telemetry.".to_string()))
        } else if events_count < 10 {
            (GateStatus::Partial, Some("Very few events captured. Run may be too short or no activity occurred.".to_string()))
        } else {
            (GateStatus::Pass, None)
        };
        
        Self {
            status,
            events_count,
            segments_count,
            channels_active: channels,
            events_by_channel,
            events_by_provider,
            events_per_second,
            diagnosis,
        }
    }
}

/// Gate B: Extraction Health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionGate {
    pub status: GateStatus,
    pub facts_count: u32,
    pub facts_by_type: HashMap<String, u32>,
    pub extraction_rate: f64, // facts / events ratio
    pub key_fact_types_present: Vec<String>,
    pub key_fact_types_missing: Vec<String>,
    pub diagnosis: Option<String>,
}

impl ExtractionGate {
    /// Key fact types that should be present for good detection
    pub const KEY_FACT_TYPES: &'static [&'static str] = &[
        "Exec",
        "ScriptBlock",
        "ServiceInstall",
        "ScheduledTask", 
        "Logon",
        "LogCleared",
        "FileCreate",
        "RegistryMod",
        "NetworkConnect",
    ];
    
    pub fn evaluate(
        facts_count: u32,
        events_count: u32,
        facts_by_type: HashMap<String, u32>,
    ) -> Self {
        let extraction_rate = if events_count > 0 {
            facts_count as f64 / events_count as f64
        } else {
            0.0
        };
        
        let mut key_present = Vec::new();
        let mut key_missing = Vec::new();
        
        for key_type in Self::KEY_FACT_TYPES {
            if facts_by_type.contains_key(*key_type) {
                key_present.push(key_type.to_string());
            } else {
                key_missing.push(key_type.to_string());
            }
        }
        
        let (status, diagnosis) = if events_count == 0 {
            (GateStatus::NoData, Some("No events to extract from (Gate A failed)".to_string()))
        } else if facts_count == 0 {
            (GateStatus::Fail, Some("Events received but no facts extracted. Check fact_extractor configuration.".to_string()))
        } else if key_present.is_empty() {
            (GateStatus::Fail, Some("Facts extracted but none are security-relevant. Missing key types: Exec, ServiceInstall, Logon, etc.".to_string()))
        } else if key_missing.len() > key_present.len() {
            (GateStatus::Partial, Some(format!("Missing key fact types: {}. May need more telemetry or run activity.", key_missing.join(", "))))
        } else {
            (GateStatus::Pass, None)
        };
        
        Self {
            status,
            facts_count,
            facts_by_type,
            extraction_rate,
            key_fact_types_present: key_present,
            key_fact_types_missing: key_missing,
            diagnosis,
        }
    }
}

/// Gate C: Detection Health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionGate {
    pub status: GateStatus,
    pub signals_count: u32,
    pub signals_by_playbook: HashMap<String, u32>,
    pub signals_by_severity: HashMap<String, u32>,
    pub playbooks_matched: Vec<String>,
    pub playbooks_loaded: u32,
    pub match_rate: f64, // signals / facts ratio
    pub diagnosis: Option<String>,
}

impl DetectionGate {
    pub fn evaluate(
        signals_count: u32,
        facts_count: u32,
        signals_by_playbook: HashMap<String, u32>,
        signals_by_severity: HashMap<String, u32>,
        playbooks_loaded: u32,
    ) -> Self {
        let match_rate = if facts_count > 0 {
            signals_count as f64 / facts_count as f64
        } else {
            0.0
        };
        
        let playbooks_matched: Vec<String> = signals_by_playbook.keys().cloned().collect();
        
        let (status, diagnosis) = if facts_count == 0 {
            (GateStatus::NoData, Some("No facts to match against (Gate B failed)".to_string()))
        } else if signals_count == 0 && playbooks_loaded > 0 {
            (GateStatus::Fail, Some(format!("Facts available ({}) but no playbooks matched. Either activity is benign or playbooks need tuning.", facts_count)))
        } else if signals_count == 0 && playbooks_loaded == 0 {
            (GateStatus::Fail, Some("No playbooks loaded. Check playbooks directory.".to_string()))
        } else if playbooks_matched.len() == 1 {
            (GateStatus::Partial, Some(format!("Only 1 playbook matched ({}). Consider running more diverse scenarios.", playbooks_matched[0])))
        } else {
            (GateStatus::Pass, None)
        };
        
        Self {
            status,
            signals_count,
            signals_by_playbook,
            signals_by_severity,
            playbooks_matched,
            playbooks_loaded,
            match_rate,
            diagnosis,
        }
    }
}

/// Explainability validation for a single signal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalExplainability {
    pub signal_id: String,
    pub playbook_id: String,
    pub has_required_slots_filled: bool,
    pub required_slots_filled: u32,
    pub required_slots_total: u32,
    pub has_evidence_ptrs: bool,
    pub evidence_ptr_count: u32,
    pub has_entity_bundle: bool,
    pub is_valid: bool,
    pub issues: Vec<String>,
}

/// Gate D: Explainability Health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainabilityGate {
    pub status: GateStatus,
    pub signals_validated: u32,
    pub signals_valid: u32,
    pub signals_invalid: u32,
    pub explain_valid_rate: f64,
    pub evidence_ptr_rate: f64,
    pub required_slot_filled_rate: f64,
    pub validation_details: Vec<SignalExplainability>,
    pub diagnosis: Option<String>,
}

impl ExplainabilityGate {
    pub fn evaluate(signals: Vec<SignalExplainability>) -> Self {
        let signals_validated = signals.len() as u32;
        let signals_valid = signals.iter().filter(|s| s.is_valid).count() as u32;
        let signals_invalid = signals_validated - signals_valid;
        
        let explain_valid_rate = if signals_validated > 0 {
            signals_valid as f64 / signals_validated as f64
        } else {
            0.0
        };
        
        let with_evidence = signals.iter().filter(|s| s.has_evidence_ptrs).count() as u32;
        let evidence_ptr_rate = if signals_validated > 0 {
            with_evidence as f64 / signals_validated as f64
        } else {
            0.0
        };
        
        let total_required = signals.iter().map(|s| s.required_slots_total).sum::<u32>();
        let total_filled = signals.iter().map(|s| s.required_slots_filled).sum::<u32>();
        let required_slot_filled_rate = if total_required > 0 {
            total_filled as f64 / total_required as f64
        } else {
            1.0 // No required slots means 100% filled
        };
        
        let (status, diagnosis) = if signals_validated == 0 {
            (GateStatus::NoData, Some("No signals to validate (Gate C may have failed)".to_string()))
        } else if explain_valid_rate < 0.5 {
            (GateStatus::Fail, Some(format!("Only {:.0}% of signals have valid explanations. Check evidence_ptrs and required slots.", explain_valid_rate * 100.0)))
        } else if explain_valid_rate < 0.9 {
            (GateStatus::Partial, Some(format!("{} signals missing evidence_ptrs or required slots.", signals_invalid)))
        } else {
            (GateStatus::Pass, None)
        };
        
        Self {
            status,
            signals_validated,
            signals_valid,
            signals_invalid,
            explain_valid_rate,
            evidence_ptr_rate,
            required_slot_filled_rate,
            validation_details: signals,
            diagnosis,
        }
    }
}

/// Complete health gates assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthGates {
    pub telemetry: TelemetryGate,
    pub extraction: ExtractionGate,
    pub detection: DetectionGate,
    pub explainability: ExplainabilityGate,
    pub overall_healthy: bool,
    pub overall_diagnosis: String,
}

impl HealthGates {
    pub fn new(
        telemetry: TelemetryGate,
        extraction: ExtractionGate,
        detection: DetectionGate,
        explainability: ExplainabilityGate,
    ) -> Self {
        let overall_healthy = 
            telemetry.status.is_healthy() &&
            extraction.status.is_healthy() &&
            detection.status.is_healthy() &&
            explainability.status.is_healthy();
            
        let overall_diagnosis = if overall_healthy {
            "All health gates passing - pipeline working correctly".to_string()
        } else {
            let mut issues = Vec::new();
            if !telemetry.status.is_healthy() {
                issues.push(format!("Gate A (Telemetry): {}", telemetry.diagnosis.as_deref().unwrap_or("Failed")));
            }
            if !extraction.status.is_healthy() {
                issues.push(format!("Gate B (Extraction): {}", extraction.diagnosis.as_deref().unwrap_or("Failed")));
            }
            if !detection.status.is_healthy() {
                issues.push(format!("Gate C (Detection): {}", detection.diagnosis.as_deref().unwrap_or("Failed")));
            }
            if !explainability.status.is_healthy() {
                issues.push(format!("Gate D (Explainability): {}", explainability.diagnosis.as_deref().unwrap_or("Failed")));
            }
            issues.join("\n")
        };
        
        Self {
            telemetry,
            extraction,
            detection,
            explainability,
            overall_healthy,
            overall_diagnosis,
        }
    }
    
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "gates": {
                "telemetry": {
                    "status": self.telemetry.status.as_str(),
                    "events_count": self.telemetry.events_count,
                    "segments_count": self.telemetry.segments_count,
                    "channels_active": self.telemetry.channels_active,
                    "events_by_channel": self.telemetry.events_by_channel,
                    "events_by_provider": self.telemetry.events_by_provider,
                    "events_per_second": self.telemetry.events_per_second,
                    "diagnosis": self.telemetry.diagnosis,
                },
                "extraction": {
                    "status": self.extraction.status.as_str(),
                    "facts_count": self.extraction.facts_count,
                    "facts_by_type": self.extraction.facts_by_type,
                    "extraction_rate": self.extraction.extraction_rate,
                    "key_fact_types_present": self.extraction.key_fact_types_present,
                    "key_fact_types_missing": self.extraction.key_fact_types_missing,
                    "diagnosis": self.extraction.diagnosis,
                },
                "detection": {
                    "status": self.detection.status.as_str(),
                    "signals_count": self.detection.signals_count,
                    "signals_by_playbook": self.detection.signals_by_playbook,
                    "signals_by_severity": self.detection.signals_by_severity,
                    "playbooks_matched": self.detection.playbooks_matched,
                    "playbooks_loaded": self.detection.playbooks_loaded,
                    "match_rate": self.detection.match_rate,
                    "diagnosis": self.detection.diagnosis,
                },
                "explainability": {
                    "status": self.explainability.status.as_str(),
                    "signals_validated": self.explainability.signals_validated,
                    "signals_valid": self.explainability.signals_valid,
                    "signals_invalid": self.explainability.signals_invalid,
                    "explain_valid_rate": self.explainability.explain_valid_rate,
                    "evidence_ptr_rate": self.explainability.evidence_ptr_rate,
                    "required_slot_filled_rate": self.explainability.required_slot_filled_rate,
                    "diagnosis": self.explainability.diagnosis,
                },
            },
            "overall_healthy": self.overall_healthy,
            "overall_diagnosis": self.overall_diagnosis,
        })
    }
}

/// Enhanced metrics with health gates (Metrics v3 schema)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedMetrics {
    pub schema_version: String,
    pub run_id: String,
    pub timestamp: String,
    pub host: String,
    pub os: String,
    pub os_version: String,
    pub arch: String,
    
    pub environment: EnvironmentInfo,
    pub config: RunConfig,
    pub health_gates: HealthGates,
    pub timing: TimingInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    pub is_admin: bool,
    pub limited_mode: bool,
    pub port: u16,
    pub telemetry_root: String,
    pub run_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    pub duration_minutes: Option<u32>,
    pub selected_playbooks: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingInfo {
    pub run_duration_minutes: Option<u32>,
    pub elapsed_seconds: u64,
    pub events_per_second: f64,
}

//! Scenario Packs Module
//!
//! Platform-agnostic types and definitions for scenario packs.
//! Execution is platform-specific (see windows.rs).

use serde::{Deserialize, Serialize};

/// A single step in a scenario pack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioStep {
    pub id: String,
    pub name: String,
    pub description: String,
    pub exe: String,
    pub args: Vec<String>,
    pub delay_after_ms: u32,
    pub expected_event_ids: Vec<u32>,
    pub expected_fact_types: Vec<String>,
}

/// A complete scenario pack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioPack {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: ScenarioCategory,
    pub risk_level: RiskLevel,
    pub expected_duration_sec: u32,
    pub steps: Vec<ScenarioStep>,
    pub expected_playbooks: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioCategory {
    Discovery,
    AdversarySimulation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Safe,      // No system changes, read-only queries
    Low,       // Minimal changes, easily reversible
    Moderate,  // Some changes, may trigger AV/EDR
}

/// Result of executing a scenario pack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackExecutionResult {
    pub pack_id: String,
    pub pack_name: String,
    pub platform: String,
    pub total_steps: u32,
    pub successful_steps: u32,
    pub skipped_steps: u32,
    pub total_duration_ms: u64,
    pub step_results: Vec<StepExecutionResult>,
}

/// Result of executing a single step with audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExecutionResult {
    pub step_id: String,
    pub step_name: String,
    pub command: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout_hash: String,
    pub stderr_hash: String,
    pub stdout_preview: String,
    pub stderr_preview: String,
    pub duration_ms: u64,
    pub timestamp: String,
}

impl StepExecutionResult {
    /// Create audit log entry for run_summary
    pub fn to_audit_entry(&self) -> serde_json::Value {
        serde_json::json!({
            "step_id": self.step_id,
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout_hash": self.stdout_hash,
            "stderr_hash": self.stderr_hash,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
        })
    }
}

// Platform-specific modules
#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use windows::{execute_pack, get_all_packs, get_pack_by_id, get_packs_by_category};

// Stub for non-Windows platforms
#[cfg(not(windows))]
pub fn get_all_packs() -> Vec<ScenarioPack> {
    vec![] // No scenario packs on non-Windows
}

#[cfg(not(windows))]
pub fn get_pack_by_id(_id: &str) -> Option<ScenarioPack> {
    None
}

#[cfg(not(windows))]
pub fn get_packs_by_category(_category: ScenarioCategory) -> Vec<ScenarioPack> {
    vec![]
}

#[cfg(not(windows))]
pub async fn execute_pack(_pack: &ScenarioPack) -> Result<PackExecutionResult, String> {
    Err("Scenario packs are only available on Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step_audit_entry() {
        let step = StepExecutionResult {
            step_id: "step_1".to_string(),
            step_name: "test".to_string(),
            command: "whoami.exe".to_string(),
            success: true,
            exit_code: Some(0),
            stdout_hash: "abc123".to_string(),
            stderr_hash: "def456".to_string(),
            stdout_preview: "user".to_string(),
            stderr_preview: "".to_string(),
            duration_ms: 100,
            timestamp: "2026-01-09T12:00:00Z".to_string(),
        };

        let entry = step.to_audit_entry();
        assert_eq!(entry["step_id"], "step_1");
        assert_eq!(entry["exit_code"], 0);
    }
}

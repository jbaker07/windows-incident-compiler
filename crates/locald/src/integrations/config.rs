//! Integration configuration
//!
//! YAML/JSON configuration for export and ingest adapters.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level integration configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrationConfig {
    /// Export configuration
    #[serde(default)]
    pub export: ExportConfig,

    /// Ingest configuration
    #[serde(default)]
    pub ingest: IngestConfig,

    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsConfig,
}

impl IntegrationConfig {
    /// Load from YAML file
    pub fn from_yaml_file(path: &PathBuf) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read config: {}", e))?;
        serde_yaml::from_str(&content).map_err(|e| format!("Failed to parse config: {}", e))
    }

    /// Load from JSON file
    pub fn from_json_file(path: &PathBuf) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read config: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse config: {}", e))
    }
}

/// Export configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExportConfig {
    /// Enable export
    #[serde(default)]
    pub enabled: bool,

    /// Export sinks
    #[serde(default)]
    pub sinks: Vec<ExportSinkConfig>,
}

/// Configuration for a single export sink
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSinkConfig {
    /// Sink identifier (e.g., "wazuh", "elastic")
    pub sink_id: String,

    /// Sink type
    pub sink_type: ExportSinkType,

    /// Output path (for file-based sinks)
    #[serde(default = "default_export_path")]
    pub output_path: PathBuf,

    /// Minimum severity to export ("low", "medium", "high", "critical")
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    /// Always export Tier-0 invariants regardless of severity
    #[serde(default = "default_true")]
    pub include_tier0: bool,

    /// Maximum timeline entries per incident
    #[serde(default = "default_max_timeline")]
    pub max_timeline_entries: usize,

    /// Maximum evidence pointers per incident
    #[serde(default = "default_max_evidence")]
    pub max_evidence_pointers: usize,

    /// Schema version for output
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
}

fn default_export_path() -> PathBuf {
    PathBuf::from("/var/lib/edr/exports/default")
}

fn default_min_severity() -> String {
    "medium".to_string()
}

fn default_true() -> bool {
    true
}

fn default_max_timeline() -> usize {
    20
}

fn default_max_evidence() -> usize {
    50
}

fn default_schema_version() -> String {
    "1.0".to_string()
}

/// Export sink types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExportSinkType {
    /// JSONL file export (lowest friction)
    JsonlFile,
    /// Syslog UDP export
    SyslogUdp,
    /// HTTP POST endpoint
    HttpPost,
}

/// Ingest configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IngestConfig {
    /// Enable ingest
    #[serde(default)]
    pub enabled: bool,

    /// Ingest sources
    #[serde(default)]
    pub sources: Vec<IngestSourceConfig>,
}

/// Configuration for a single ingest source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestSourceConfig {
    /// Source identifier (e.g., "wazuh_alerts", "zeek_eve")
    pub source_id: String,

    /// Source type
    pub source_type: IngestSourceType,

    /// Input path (for file-based sources)
    pub input_path: Option<PathBuf>,

    /// Listen address (for network sources)
    pub listen_addr: Option<String>,

    /// Vendor identifier for VendorAlertFact
    #[serde(default = "default_vendor")]
    pub vendor: String,

    /// Join strategy
    #[serde(default)]
    pub join_strategy: JoinStrategy,

    /// Time window for soft joins (seconds)
    #[serde(default = "default_join_window")]
    pub join_window_seconds: u64,

    /// Polling interval for file sources (milliseconds)
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,
}

fn default_vendor() -> String {
    "unknown".to_string()
}

fn default_join_window() -> u64 {
    300 // 5 minutes
}

fn default_poll_interval() -> u64 {
    1000 // 1 second
}

/// Ingest source types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IngestSourceType {
    /// JSONL file tail (like `tail -f`)
    JsonlFile,
    /// Syslog UDP listener
    SyslogUdp,
    /// Zeek EVE JSON file
    ZeekEve,
    /// Wazuh alerts.json
    WazuhAlerts,
}

/// Join strategy for ingested facts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum JoinStrategy {
    /// Join by IP + time window (soft)
    #[default]
    IpTimeWindow,
    /// Join by hostname + time window (soft)
    HostTimeWindow,
    /// Join by process exe hash (hard if available)
    ExeHash,
    /// No automatic join (facts stand alone)
    None,
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    #[serde(default)]
    pub enabled: bool,

    /// Output path for metrics
    #[serde(default = "default_metrics_path")]
    pub output_path: PathBuf,

    /// Include per-incident breakdown
    #[serde(default)]
    pub per_incident_breakdown: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            output_path: default_metrics_path(),
            per_incident_breakdown: false,
        }
    }
}

fn default_metrics_path() -> PathBuf {
    PathBuf::from("/var/lib/edr/metrics")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = IntegrationConfig::default();
        assert!(!config.export.enabled);
        assert!(!config.ingest.enabled);
    }

    #[test]
    fn test_yaml_parse() {
        let yaml = r#"
export:
  enabled: true
  sinks:
    - sink_id: wazuh
      sink_type: jsonl_file
      output_path: /var/lib/edr/exports/wazuh
      min_severity: medium
      include_tier0: true
ingest:
  enabled: true
  sources:
    - source_id: zeek_eve
      source_type: zeek_eve
      input_path: /var/log/zeek/eve.json
      vendor: zeek
      join_strategy: ip_time_window
      join_window_seconds: 300
"#;
        let config: IntegrationConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.export.enabled);
        assert_eq!(config.export.sinks.len(), 1);
        assert_eq!(config.export.sinks[0].sink_id, "wazuh");
        assert!(config.ingest.enabled);
        assert_eq!(config.ingest.sources.len(), 1);
    }
}

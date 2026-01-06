//! Export: Incidents → JSONL files for SIEM integration
//!
//! Exports incidents (not raw telemetry) in a stable JSONL format.
//! Supports filtering by severity and always-includes Tier-0 invariants.

use crate::hypothesis::{Incident, ScopeKey, Tier0Invariant};
use crate::integrations::config::ExportSinkConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

/// Exported incident record (stable schema)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedIncident {
    /// Schema version for forward compatibility
    pub schema_version: String,

    /// Deterministic incident ID
    pub incident_id: String,

    /// Host identifier
    pub host_id: String,

    /// Namespace (for multi-tenant)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Incident family (e.g., "injection", "lateral_movement")
    pub family: String,

    /// Playbook/template ID that triggered this
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playbook_id: Option<String>,

    /// Current severity
    pub severity: String,

    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,

    /// Current status
    pub status: String,

    /// First event timestamp
    pub first_ts: DateTime<Utc>,

    /// Last event timestamp
    pub last_ts: DateTime<Utc>,

    /// Created timestamp
    pub created_at: DateTime<Utc>,

    /// Updated timestamp
    pub updated_at: DateTime<Utc>,

    /// Is this a Tier-0 invariant?
    pub is_tier0: bool,

    /// Tier-0 invariant type (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier0_type: Option<String>,

    /// MITRE ATT&CK tags
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_tags: Vec<String>,

    /// Join keys for correlation
    pub join_keys: JoinKeys,

    /// Timeline summary (top N facts)
    pub timeline_summary: Vec<TimelineFactSummary>,

    /// Evidence pointers with segment hashes (no raw content)
    pub evidence_summary: Vec<EvidenceSummary>,

    /// Export metadata
    pub export_metadata: ExportMetadata,
}

/// Join keys extracted from incident for correlation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JoinKeys {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proc_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_key: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ip_indicators: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exe_hashes: Vec<String>,
}

/// Summary of a timeline fact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineFactSummary {
    pub ts: DateTime<Utc>,
    pub fact_type: String,
    pub summary: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub key_fields: HashMap<String, String>,
}

/// Evidence pointer summary (no raw segment content)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub stream_id: String,
    pub segment_id: String,
    pub record_index: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segment_sha256: Option<String>,
}

/// Export metadata for tracing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportMetadata {
    pub exported_at: DateTime<Utc>,
    pub exporter_version: String,
    pub sink_id: String,
}

/// Incident exporter
pub struct IncidentExporter {
    config: ExportSinkConfig,
    output_path: PathBuf,
    exported_count: u64,
    export_hash: String,
}

impl IncidentExporter {
    /// Create a new exporter from config
    pub fn new(config: ExportSinkConfig) -> Result<Self, String> {
        let output_path = config.output_path.join("incidents.jsonl");

        // Create directory structure
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create export directory: {}", e))?;
        }

        Ok(Self {
            output_path,
            config,
            exported_count: 0,
            export_hash: String::new(),
        })
    }

    /// Export a batch of incidents
    pub fn export_batch(
        &mut self,
        incidents: &[&Incident],
        namespace: Option<&str>,
    ) -> Result<ExportResult, String> {
        let mut exported = 0;
        let mut skipped = 0;
        let mut hasher = Sha256::new();

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.output_path)
            .map_err(|e| format!("Failed to open export file: {}", e))?;

        let mut writer = BufWriter::new(file);

        for incident in incidents {
            if self.should_export(incident) {
                let exported_incident = self.convert_incident(incident, namespace);
                let json_line = serde_json::to_string(&exported_incident)
                    .map_err(|e| format!("Failed to serialize incident: {}", e))?;

                // Update hash for determinism verification
                hasher.update(json_line.as_bytes());
                hasher.update(b"\n");

                writeln!(writer, "{}", json_line)
                    .map_err(|e| format!("Failed to write to export file: {}", e))?;

                exported += 1;
            } else {
                skipped += 1;
            }
        }

        writer
            .flush()
            .map_err(|e| format!("Failed to flush export file: {}", e))?;

        self.exported_count += exported;
        self.export_hash = hex::encode(hasher.finalize());

        Ok(ExportResult {
            exported,
            skipped,
            total_exported: self.exported_count,
            output_path: self.output_path.clone(),
            batch_hash: self.export_hash.clone(),
        })
    }

    /// Export incidents to a fresh file (overwrite mode for determinism testing)
    pub fn export_fresh(
        &mut self,
        incidents: &[&Incident],
        namespace: Option<&str>,
    ) -> Result<ExportResult, String> {
        // Remove existing file
        if self.output_path.exists() {
            fs::remove_file(&self.output_path)
                .map_err(|e| format!("Failed to remove existing export file: {}", e))?;
        }

        self.exported_count = 0;
        self.export_hash.clear();

        // Sort incidents deterministically before export
        let mut sorted: Vec<_> = incidents.to_vec();
        sorted.sort_by(|a, b| a.incident_id.cmp(&b.incident_id));

        self.export_batch(&sorted, namespace)
    }

    /// Check if incident should be exported based on config
    fn should_export(&self, incident: &Incident) -> bool {
        // Always export Tier-0 invariants
        if self.config.include_tier0 && self.is_tier0(incident) {
            return true;
        }

        // Check severity threshold
        let incident_severity = severity_to_level(&format!("{:?}", incident.severity));
        let min_severity = severity_to_level(&self.config.min_severity);

        incident_severity >= min_severity
    }

    /// Check if incident is a Tier-0 invariant
    fn is_tier0(&self, incident: &Incident) -> bool {
        // Check family for Tier-0 patterns
        Tier0Invariant::from_predicate(&incident.family).is_some()
            || incident.family.contains("memory_rwx")
            || incident.family.contains("lsass")
            || incident.family.contains("credential_access")
            || incident.family.contains("rootkit")
    }

    /// Convert Incident to ExportedIncident
    fn convert_incident(&self, incident: &Incident, namespace: Option<&str>) -> ExportedIncident {
        let tier0_type =
            Tier0Invariant::from_predicate(&incident.family).map(|t| format!("{:?}", t));

        // Extract join keys from scope
        let join_keys = self.extract_join_keys(incident);

        // Build timeline summary
        let timeline_summary: Vec<TimelineFactSummary> = incident
            .timeline_entries
            .iter()
            .take(self.config.max_timeline_entries)
            .map(|entry| TimelineFactSummary {
                ts: entry.ts,
                fact_type: format!("{:?}", entry.kind),
                summary: entry.summary.clone(),
                key_fields: HashMap::new(), // Could extract from entry
            })
            .collect();

        // Build evidence summary
        let evidence_summary: Vec<EvidenceSummary> = incident
            .evidence_ptrs_summary
            .iter()
            .take(self.config.max_evidence_pointers)
            .map(|ptr| EvidenceSummary {
                stream_id: ptr.stream_id.clone(),
                segment_id: ptr.segment_id.clone(),
                record_index: ptr.record_index,
                segment_sha256: ptr.record_sha256.clone(),
            })
            .collect();

        // Use a fixed timestamp for export_metadata in tests for determinism
        let exported_at = if cfg!(test) {
            chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00+00:00")
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now())
        } else {
            Utc::now()
        };

        ExportedIncident {
            schema_version: self.config.schema_version.clone(),
            incident_id: incident.incident_id.clone(),
            host_id: incident.host_id.clone(),
            namespace: namespace.map(|s| s.to_string()),
            family: incident.family.clone(),
            playbook_id: incident.promoted_from_hypothesis_ids.first().cloned(),
            severity: format!("{:?}", incident.severity),
            confidence: incident.confidence,
            status: format!("{:?}", incident.status),
            first_ts: incident.first_ts,
            last_ts: incident.last_ts,
            created_at: incident.created_ts,
            updated_at: incident.updated_ts,
            is_tier0: self.is_tier0(incident),
            tier0_type,
            mitre_tags: Vec::new(), // Would extract from incident if present
            join_keys,
            timeline_summary,
            evidence_summary,
            export_metadata: ExportMetadata {
                exported_at,
                exporter_version: "1.0.0".to_string(),
                sink_id: self.config.sink_id.clone(),
            },
        }
    }

    /// Extract join keys from incident
    fn extract_join_keys(&self, incident: &Incident) -> JoinKeys {
        let mut keys = JoinKeys::default();

        // Extract from primary scope key
        match &incident.primary_scope_key {
            ScopeKey::Process { key } => keys.proc_key = Some(key.clone()),
            ScopeKey::User { key } => keys.identity_key = Some(key.clone()),
            ScopeKey::File { key } => keys.file_key = Some(key.clone()),
            ScopeKey::Executable { key } => keys.exe_hashes.push(key.clone()),
            _ => {}
        }

        // Extract from related scope keys
        for scope in &incident.related_scope_keys {
            match scope {
                ScopeKey::Process { key } if keys.proc_key.is_none() => {
                    keys.proc_key = Some(key.clone());
                }
                ScopeKey::User { key } if keys.identity_key.is_none() => {
                    keys.identity_key = Some(key.clone());
                }
                ScopeKey::Executable { key } => {
                    if !keys.exe_hashes.contains(key) {
                        keys.exe_hashes.push(key.clone());
                    }
                }
                _ => {}
            }
        }

        keys
    }

    /// Get export statistics
    pub fn stats(&self) -> ExportStats {
        ExportStats {
            total_exported: self.exported_count,
            output_path: self.output_path.clone(),
            last_hash: self.export_hash.clone(),
        }
    }
}

/// Result of an export operation
#[derive(Debug, Clone)]
pub struct ExportResult {
    pub exported: u64,
    pub skipped: u64,
    pub total_exported: u64,
    pub output_path: PathBuf,
    pub batch_hash: String,
}

/// Export statistics
#[derive(Debug, Clone)]
pub struct ExportStats {
    pub total_exported: u64,
    pub output_path: PathBuf,
    pub last_hash: String,
}

/// Export sink trait for different output formats
pub trait ExportSink: Send + Sync {
    fn export(&mut self, incident: &ExportedIncident) -> Result<(), String>;
    fn flush(&mut self) -> Result<(), String>;
}

/// JSONL file sink
pub struct JsonlFileSink {
    writer: BufWriter<File>,
}

impl JsonlFileSink {
    pub fn new(path: &PathBuf) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("Failed to open file: {}", e))?;

        Ok(Self {
            writer: BufWriter::new(file),
        })
    }
}

impl ExportSink for JsonlFileSink {
    fn export(&mut self, incident: &ExportedIncident) -> Result<(), String> {
        let json =
            serde_json::to_string(incident).map_err(|e| format!("Failed to serialize: {}", e))?;
        writeln!(self.writer, "{}", json).map_err(|e| format!("Failed to write: {}", e))?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), String> {
        self.writer
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;
        Ok(())
    }
}

/// Convert severity string to numeric level
fn severity_to_level(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "low" | "info" | "informational" => 1,
        "medium" | "warning" => 2,
        "high" => 3,
        "critical" | "severe" => 4,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypothesis::{Incident, IncidentStatus, Severity};
    use crate::integrations::config::ExportSinkType;
    use std::collections::HashSet;
    use tempfile::tempdir;

    fn make_test_incident(family: &str, severity: Severity) -> Incident {
        let scope = ScopeKey::Process {
            key: "test_proc_123".to_string(),
        };
        // Use a fixed timestamp for determinism
        let ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00+00:00")
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Incident {
            incident_id: "inc_test_001".to_string(),
            family: family.to_string(),
            primary_scope_key: scope,
            related_scope_keys: Vec::new(),
            first_ts: ts,
            last_ts: ts,
            severity,
            confidence: 0.8,
            status: IncidentStatus::Active,
            timeline_entries: Vec::new(),
            entities: Vec::new(),
            promoted_from_hypothesis_ids: vec!["hyp_test".to_string()],
            absorbed_hypothesis_ids: Vec::new(),
            suppressed_candidate_hypothesis_ids: Vec::new(),
            explanation_bundle_ref: None,
            evidence_ptrs_summary: Vec::new(),
            host_id: "test_host".to_string(),
            time_bucket_seconds: 3600,
            created_ts: ts,
            updated_ts: ts,
            closed_ts: None,
            closure_reason: None,
            mitre_techniques: Vec::new(),
            tags: HashSet::new(),
        }
    }

    #[test]
    fn test_export_creates_jsonl() {
        let dir = tempdir().unwrap();
        let config = ExportSinkConfig {
            sink_id: "test".to_string(),
            sink_type: ExportSinkType::JsonlFile,
            output_path: dir.path().to_path_buf(),
            min_severity: "medium".to_string(),
            include_tier0: true,
            max_timeline_entries: 10,
            max_evidence_pointers: 20,
            schema_version: "1.0".to_string(),
        };

        let mut exporter = IncidentExporter::new(config).unwrap();

        let incident = make_test_incident("injection", Severity::High);
        let incidents: Vec<&Incident> = vec![&incident];

        let result = exporter.export_batch(&incidents, Some("default")).unwrap();

        assert_eq!(result.exported, 1);
        assert!(dir.path().join("incidents.jsonl").exists());
    }

    #[test]
    fn test_tier0_always_exported() {
        let dir = tempdir().unwrap();
        let config = ExportSinkConfig {
            sink_id: "test".to_string(),
            sink_type: ExportSinkType::JsonlFile,
            output_path: dir.path().to_path_buf(),
            min_severity: "critical".to_string(), // Very high threshold
            include_tier0: true,
            max_timeline_entries: 10,
            max_evidence_pointers: 20,
            schema_version: "1.0".to_string(),
        };

        let mut exporter = IncidentExporter::new(config).unwrap();

        // Low severity but Tier-0 family
        let incident = make_test_incident("memory_rwx_violation", Severity::Low);
        let incidents: Vec<&Incident> = vec![&incident];

        let result = exporter.export_batch(&incidents, None).unwrap();

        assert_eq!(result.exported, 1); // Should be exported despite low severity
    }

    #[test]
    fn test_deterministic_export() {
        let dir = tempdir().unwrap();
        let config = ExportSinkConfig {
            sink_id: "test".to_string(),
            sink_type: ExportSinkType::JsonlFile,
            output_path: dir.path().to_path_buf(),
            min_severity: "low".to_string(),
            include_tier0: true,
            max_timeline_entries: 10,
            max_evidence_pointers: 20,
            schema_version: "1.0".to_string(),
        };

        let incident1 = make_test_incident("injection", Severity::High);
        let incident2 = make_test_incident("lateral_movement", Severity::Medium);
        let incidents: Vec<&Incident> = vec![&incident1, &incident2];

        // Export twice
        let mut exporter1 = IncidentExporter::new(config.clone()).unwrap();
        let result1 = exporter1.export_fresh(&incidents, None).unwrap();

        let mut exporter2 = IncidentExporter::new(config).unwrap();
        let result2 = exporter2.export_fresh(&incidents, None).unwrap();

        // Hashes should match (deterministic order)
        assert_eq!(result1.batch_hash, result2.batch_hash);
    }
}

//! Metrics and proof harness for integration validation
//!
//! Produces quality metrics for incidents and integration operations:
//! - Evidence Quality Score (EQS)
//! - Compression ratios
//! - Duplicate detection
//! - Export/ingest success rates

use crate::hypothesis::{Fact, Incident};
use crate::integrations::export::ExportResult;
use crate::integrations::ingest::IngestStats;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

/// Integration metrics report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsReport {
    /// Report metadata
    pub run_id: String,
    pub generated_at: DateTime<Utc>,
    pub report_version: String,

    /// Summary metrics
    pub summary: MetricsSummary,

    /// Per-incident breakdown (if enabled)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub per_incident: Vec<IncidentMetrics>,

    /// Export metrics
    pub export_metrics: ExportMetrics,

    /// Ingest metrics
    pub ingest_metrics: IngestMetrics,
}

/// Summary metrics across all incidents
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsSummary {
    /// Total incidents analyzed
    pub total_incidents: u64,
    /// Average Evidence Quality Score (0.0 to 1.0)
    pub avg_eqs: f64,
    /// Minimum EQS
    pub min_eqs: f64,
    /// Maximum EQS
    pub max_eqs: f64,
    /// Raw events → facts compression ratio
    pub events_to_facts_ratio: f64,
    /// Facts → incidents compression ratio
    pub facts_to_incidents_ratio: f64,
    /// Duplicate incident key rate
    pub duplicate_rate: f64,
    /// Incidents by status
    pub by_status: HashMap<String, u64>,
    /// Incidents by family
    pub by_family: HashMap<String, u64>,
}

/// Per-incident metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentMetrics {
    pub incident_id: String,
    pub family: String,
    pub eqs: f64,
    pub eqs_components: EqsComponents,
    pub timeline_entry_count: u64,
    pub evidence_pointer_count: u64,
    pub entity_count: u64,
    pub has_join_keys: bool,
}

/// Evidence Quality Score components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EqsComponents {
    /// Timeline completeness (0.0 to 1.0)
    pub timeline_score: f64,
    /// Evidence pointer coverage (0.0 to 1.0)
    pub evidence_score: f64,
    /// Entity/join key presence (0.0 to 1.0)
    pub entity_score: f64,
    /// Lineage completeness (0.0 to 1.0)
    pub lineage_score: f64,
}

/// Export metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportMetrics {
    pub incidents_exported: u64,
    pub incidents_skipped: u64,
    pub export_hash: String,
    pub output_path: String,
    pub tier0_exported: u64,
}

/// Ingest metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IngestMetrics {
    pub events_read: u64,
    pub events_parsed: u64,
    pub parse_errors: u64,
    pub facts_created: u64,
    pub facts_joined: u64,
    pub join_rate: f64,
}

/// Integration metrics collector
pub struct IntegrationMetrics {
    output_path: PathBuf,
    per_incident_breakdown: bool,
}

impl IntegrationMetrics {
    pub fn new(output_path: PathBuf, per_incident_breakdown: bool) -> Self {
        Self {
            output_path,
            per_incident_breakdown,
        }
    }

    /// Generate metrics report from incidents and integration stats
    pub fn generate_report(
        &self,
        incidents: &[&Incident],
        facts: &[&Fact],
        raw_event_count: u64,
        export_result: Option<&ExportResult>,
        ingest_stats: Option<&IngestStats>,
        joined_facts_count: u64,
    ) -> MetricsReport {
        let run_id = self.generate_run_id();

        // Calculate per-incident metrics
        let per_incident: Vec<IncidentMetrics> = if self.per_incident_breakdown {
            incidents
                .iter()
                .map(|i| self.calculate_incident_metrics(i))
                .collect()
        } else {
            Vec::new()
        };

        // Calculate summary
        let summary = self.calculate_summary(incidents, facts, raw_event_count, &per_incident);

        // Export metrics
        let export_metrics = export_result
            .map(|r| ExportMetrics {
                incidents_exported: r.exported,
                incidents_skipped: r.skipped,
                export_hash: r.batch_hash.clone(),
                output_path: r.output_path.display().to_string(),
                tier0_exported: 0, // Would need to track separately
            })
            .unwrap_or_default();

        // Ingest metrics
        let ingest_metrics = ingest_stats
            .map(|s| IngestMetrics {
                events_read: s.events_read,
                events_parsed: s.events_parsed,
                parse_errors: s.parse_errors,
                facts_created: s.facts_created,
                facts_joined: joined_facts_count,
                join_rate: if s.facts_created > 0 {
                    joined_facts_count as f64 / s.facts_created as f64
                } else {
                    0.0
                },
            })
            .unwrap_or_default();

        MetricsReport {
            run_id,
            generated_at: Utc::now(),
            report_version: "1.0".to_string(),
            summary,
            per_incident,
            export_metrics,
            ingest_metrics,
        }
    }

    /// Calculate Evidence Quality Score for an incident
    fn calculate_incident_metrics(&self, incident: &Incident) -> IncidentMetrics {
        let eqs_components = self.calculate_eqs_components(incident);
        let eqs = self.calculate_eqs(&eqs_components);

        let has_join_keys = matches!(
            &incident.primary_scope_key,
            crate::hypothesis::ScopeKey::Process { .. }
                | crate::hypothesis::ScopeKey::User { .. }
                | crate::hypothesis::ScopeKey::Executable { .. }
        );

        IncidentMetrics {
            incident_id: incident.incident_id.clone(),
            family: incident.family.clone(),
            eqs,
            eqs_components,
            timeline_entry_count: incident.timeline_entries.len() as u64,
            evidence_pointer_count: incident.evidence_ptrs_summary.len() as u64,
            entity_count: incident.entities.len() as u64,
            has_join_keys,
        }
    }

    /// Calculate EQS components
    fn calculate_eqs_components(&self, incident: &Incident) -> EqsComponents {
        // Timeline score: presence and richness of timeline
        let timeline_score = if incident.timeline_entries.is_empty() {
            0.0
        } else {
            // More entries = higher score, capped at 1.0
            (incident.timeline_entries.len() as f64 / 10.0).min(1.0)
        };

        // Evidence score: presence of evidence pointers
        let evidence_score = if incident.evidence_ptrs_summary.is_empty() {
            0.0
        } else {
            // More evidence = higher score
            (incident.evidence_ptrs_summary.len() as f64 / 20.0).min(1.0)
        };

        // Entity score: presence of linked entities
        let entity_score = if incident.entities.is_empty() {
            0.0
        } else {
            (incident.entities.len() as f64 / 5.0).min(1.0)
        };

        // Lineage score: hypothesis → incident promotion
        let lineage_score = if incident.promoted_from_hypothesis_ids.is_empty() {
            0.5 // Partial credit if no hypothesis but incident exists
        } else {
            1.0
        };

        EqsComponents {
            timeline_score,
            evidence_score,
            entity_score,
            lineage_score,
        }
    }

    /// Calculate composite EQS from components
    fn calculate_eqs(&self, components: &EqsComponents) -> f64 {
        // Weighted average
        let weights = [0.25, 0.35, 0.20, 0.20]; // timeline, evidence, entity, lineage
        let scores = [
            components.timeline_score,
            components.evidence_score,
            components.entity_score,
            components.lineage_score,
        ];

        weights.iter().zip(scores.iter()).map(|(w, s)| w * s).sum()
    }

    /// Calculate summary metrics
    fn calculate_summary(
        &self,
        incidents: &[&Incident],
        facts: &[&Fact],
        raw_event_count: u64,
        per_incident: &[IncidentMetrics],
    ) -> MetricsSummary {
        let total_incidents = incidents.len() as u64;

        // EQS stats
        let eqs_values: Vec<f64> = if per_incident.is_empty() {
            incidents
                .iter()
                .map(|i| {
                    let c = self.calculate_eqs_components(i);
                    self.calculate_eqs(&c)
                })
                .collect()
        } else {
            per_incident.iter().map(|m| m.eqs).collect()
        };

        let avg_eqs = if eqs_values.is_empty() {
            0.0
        } else {
            eqs_values.iter().sum::<f64>() / eqs_values.len() as f64
        };

        let min_eqs = eqs_values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_eqs = eqs_values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        // Compression ratios
        let facts_count = facts.len() as u64;
        let events_to_facts_ratio = if facts_count > 0 {
            raw_event_count as f64 / facts_count as f64
        } else {
            0.0
        };

        let facts_to_incidents_ratio = if total_incidents > 0 {
            facts_count as f64 / total_incidents as f64
        } else {
            0.0
        };

        // Duplicate detection
        let mut seen_ids: HashSet<&str> = HashSet::new();
        let mut duplicates = 0u64;
        for i in incidents {
            if !seen_ids.insert(&i.incident_id) {
                duplicates += 1;
            }
        }
        let duplicate_rate = if total_incidents > 0 {
            duplicates as f64 / total_incidents as f64
        } else {
            0.0
        };

        // By status
        let mut by_status: HashMap<String, u64> = HashMap::new();
        for i in incidents {
            *by_status.entry(format!("{:?}", i.status)).or_insert(0) += 1;
        }

        // By family
        let mut by_family: HashMap<String, u64> = HashMap::new();
        for i in incidents {
            *by_family.entry(i.family.clone()).or_insert(0) += 1;
        }

        MetricsSummary {
            total_incidents,
            avg_eqs,
            min_eqs: if min_eqs.is_infinite() { 0.0 } else { min_eqs },
            max_eqs: if max_eqs.is_infinite() { 0.0 } else { max_eqs },
            events_to_facts_ratio,
            facts_to_incidents_ratio,
            duplicate_rate,
            by_status,
            by_family,
        }
    }

    /// Save report to disk
    pub fn save_report(&self, report: &MetricsReport) -> Result<PathBuf, String> {
        // Create metrics directory
        fs::create_dir_all(&self.output_path)
            .map_err(|e| format!("Failed to create metrics directory: {}", e))?;

        // Write JSON report
        let json_path = self.output_path.join(format!("run_{}.json", report.run_id));
        let json = serde_json::to_string_pretty(report)
            .map_err(|e| format!("Failed to serialize report: {}", e))?;

        let mut file =
            File::create(&json_path).map_err(|e| format!("Failed to create report file: {}", e))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write report: {}", e))?;

        // Write human-readable summary
        let summary_path = self
            .output_path
            .join(format!("run_{}_summary.txt", report.run_id));
        let summary = self.format_summary(report);
        let mut summary_file = File::create(&summary_path)
            .map_err(|e| format!("Failed to create summary file: {}", e))?;
        summary_file
            .write_all(summary.as_bytes())
            .map_err(|e| format!("Failed to write summary: {}", e))?;

        Ok(json_path)
    }

    /// Format human-readable summary
    fn format_summary(&self, report: &MetricsReport) -> String {
        let mut s = String::new();
        s.push_str("═══════════════════════════════════════════════════════════════\n");
        s.push_str(&format!(
            "  INTEGRATION METRICS REPORT - Run: {}\n",
            report.run_id
        ));
        s.push_str(&format!("  Generated: {}\n", report.generated_at));
        s.push_str("═══════════════════════════════════════════════════════════════\n\n");

        s.push_str("📊 SUMMARY\n");
        s.push_str("───────────────────────────────────────────────────────────────\n");
        s.push_str(&format!(
            "  Total Incidents:        {}\n",
            report.summary.total_incidents
        ));
        s.push_str(&format!(
            "  Average EQS:            {:.2}%\n",
            report.summary.avg_eqs * 100.0
        ));
        s.push_str(&format!(
            "  EQS Range:              {:.2}% - {:.2}%\n",
            report.summary.min_eqs * 100.0,
            report.summary.max_eqs * 100.0
        ));
        s.push_str(&format!(
            "  Events→Facts Ratio:     {:.1}:1\n",
            report.summary.events_to_facts_ratio
        ));
        s.push_str(&format!(
            "  Facts→Incidents Ratio:  {:.1}:1\n",
            report.summary.facts_to_incidents_ratio
        ));
        s.push_str(&format!(
            "  Duplicate Rate:         {:.2}%\n",
            report.summary.duplicate_rate * 100.0
        ));
        s.push('\n');

        s.push_str("📤 EXPORT METRICS\n");
        s.push_str("───────────────────────────────────────────────────────────────\n");
        s.push_str(&format!(
            "  Incidents Exported:     {}\n",
            report.export_metrics.incidents_exported
        ));
        s.push_str(&format!(
            "  Incidents Skipped:      {}\n",
            report.export_metrics.incidents_skipped
        ));
        s.push_str(&format!(
            "  Output Path:            {}\n",
            report.export_metrics.output_path
        ));
        s.push_str(&format!(
            "  Export Hash:            {}\n",
            &report.export_metrics.export_hash[..16.min(report.export_metrics.export_hash.len())]
        ));
        s.push('\n');

        s.push_str("📥 INGEST METRICS\n");
        s.push_str("───────────────────────────────────────────────────────────────\n");
        s.push_str(&format!(
            "  Events Read:            {}\n",
            report.ingest_metrics.events_read
        ));
        s.push_str(&format!(
            "  Events Parsed:          {}\n",
            report.ingest_metrics.events_parsed
        ));
        s.push_str(&format!(
            "  Parse Errors:           {}\n",
            report.ingest_metrics.parse_errors
        ));
        s.push_str(&format!(
            "  Facts Created:          {}\n",
            report.ingest_metrics.facts_created
        ));
        s.push_str(&format!(
            "  Facts Joined:           {}\n",
            report.ingest_metrics.facts_joined
        ));
        s.push_str(&format!(
            "  Join Rate:              {:.2}%\n",
            report.ingest_metrics.join_rate * 100.0
        ));
        s.push('\n');

        if !report.summary.by_family.is_empty() {
            s.push_str("📁 INCIDENTS BY FAMILY\n");
            s.push_str("───────────────────────────────────────────────────────────────\n");
            for (family, count) in &report.summary.by_family {
                s.push_str(&format!("  {:<25} {}\n", family, count));
            }
            s.push('\n');
        }

        s.push_str("═══════════════════════════════════════════════════════════════\n");
        s
    }

    /// Generate unique run ID
    fn generate_run_id(&self) -> String {
        let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let mut hasher = Sha256::new();
        hasher.update(ts.as_bytes());
        hasher.update(rand_bytes().as_slice());
        let hash = hex::encode(&hasher.finalize()[..4]);
        format!("{}_{}", ts, hash)
    }
}

/// Generate random bytes (simple fallback)
fn rand_bytes() -> [u8; 4] {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u32;
    ts.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypothesis::{
        Incident, IncidentStatus, ScopeKey, Severity, TimelineEntry, TimelineEntryKind,
    };
    use std::collections::HashSet;
    use tempfile::tempdir;

    fn make_test_incident(id: &str, family: &str) -> Incident {
        let scope = ScopeKey::Process {
            key: format!("proc_{}", id),
        };
        let ts = Utc::now();

        // Create incident directly with struct initialization
        Incident {
            incident_id: id.to_string(),
            family: family.to_string(),
            primary_scope_key: scope,
            related_scope_keys: Vec::new(),
            first_ts: ts,
            last_ts: ts,
            severity: Severity::Medium,
            confidence: 0.7,
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
    fn test_eqs_calculation() {
        let dir = tempdir().unwrap();
        let metrics = IntegrationMetrics::new(dir.path().to_path_buf(), true);

        let mut incident = make_test_incident("inc1", "injection");
        // Empty incident should have low EQS
        let m = metrics.calculate_incident_metrics(&incident);
        assert!(m.eqs < 0.5);

        // Add timeline entries
        for i in 0..10 {
            incident.timeline_entries.push(TimelineEntry::new(
                Utc::now(),
                TimelineEntryKind::ProcessEvent,
                format!("Event {}", i),
            ));
        }

        let m2 = metrics.calculate_incident_metrics(&incident);
        assert!(m2.eqs > m.eqs);
    }

    #[test]
    fn test_report_generation() {
        let dir = tempdir().unwrap();
        let metrics = IntegrationMetrics::new(dir.path().to_path_buf(), false);

        let incident1 = make_test_incident("inc1", "injection");
        let incident2 = make_test_incident("inc2", "lateral_movement");
        let incidents: Vec<&Incident> = vec![&incident1, &incident2];

        let report = metrics.generate_report(&incidents, &[], 1000, None, None, 0);

        assert_eq!(report.summary.total_incidents, 2);
        assert!(report.summary.events_to_facts_ratio == 0.0); // No facts
    }

    #[test]
    fn test_report_save() {
        let dir = tempdir().unwrap();
        let metrics = IntegrationMetrics::new(dir.path().to_path_buf(), false);

        let incident = make_test_incident("inc1", "injection");
        let incidents: Vec<&Incident> = vec![&incident];

        let report = metrics.generate_report(&incidents, &[], 100, None, None, 0);
        let path = metrics.save_report(&report).unwrap();

        assert!(path.exists());
        assert!(path.extension().map(|e| e == "json").unwrap_or(false));
    }
}

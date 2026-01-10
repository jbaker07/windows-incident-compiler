//! Run Metrics Collection and Instrumentation
//!
//! Collects telemetry metrics throughout a mission run and produces
//! the run_summary.json artifact at completion.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Performance sample taken during run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfSample {
    pub timestamp: String,
    pub cpu_percent: f64,
    pub rss_mb: f64,
}

/// Source breakdown entry
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceMetrics {
    pub events: u64,
    pub bytes: u64,
}

/// Capture metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureMetrics {
    pub events_read: u64,
    pub events_dropped: u64,
    pub bytes_read: u64,
    pub segments_written: u32,
    pub source_breakdown: HashMap<String, SourceMetrics>,
    pub event_id_histogram: HashMap<u32, u64>,
}

/// Compiler (locald) metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompilerMetrics {
    pub events_ingested: u64,
    pub events_parse_errors: u64,
    pub facts_extracted: u64,
    pub fact_type_breakdown: HashMap<String, u64>,
    pub playbooks_loaded: u32,
    pub playbooks_matched: Vec<String>,
    pub signals_emitted: u64,
    pub signals_by_severity: SeverityBreakdown,
    pub incidents_promoted: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub informational: u32,
}

/// Explainability metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExplainMetrics {
    pub signals_with_explain: u32,
    pub deref_attempts: u32,
    pub deref_successes: u32,
    pub excerpt_failures: u32,
    pub slots_required: u32,
    pub slots_filled: u32,
    pub entities_required: u32,
    pub entities_resolved: u32,
    pub narratives_generated: u32,
}

impl ExplainMetrics {
    pub fn deref_success_rate(&self) -> f64 {
        if self.deref_attempts == 0 {
            1.0
        } else {
            self.deref_successes as f64 / self.deref_attempts as f64
        }
    }

    pub fn slot_fill_rate(&self) -> f64 {
        if self.slots_required == 0 {
            1.0
        } else {
            self.slots_filled as f64 / self.slots_required as f64
        }
    }

    pub fn entity_coverage(&self) -> f64 {
        if self.entities_required == 0 {
            1.0
        } else {
            self.entities_resolved as f64 / self.entities_required as f64
        }
    }

    pub fn narrative_rate(&self) -> f64 {
        if self.signals_with_explain == 0 {
            1.0
        } else {
            self.narratives_generated as f64 / self.signals_with_explain as f64
        }
    }
}

/// Performance metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerfMetrics {
    pub cpu_samples: Vec<PerfSample>,
    pub peak_rss_mb: f64,
    pub avg_rss_mb: f64,
    pub disk_written_mb: f64,
    pub events_per_second: f64,
}

/// Environment info captured at run start
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    pub os_version: String,
    pub hostname: String,
    pub is_admin: bool,
    pub sysmon_installed: bool,
    pub sysmon_version: Option<String>,
    pub audit_policy: AuditPolicyInfo,
    pub powershell_logging: bool,
    pub readiness_level: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditPolicyInfo {
    pub process_creation: bool,
    pub command_line_logging: bool,
    pub logon_events: bool,
}

/// Mission info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionInfo {
    #[serde(rename = "type")]
    pub mission_type: String,
    pub profile: String,
    pub duration_requested_sec: u32,
    pub playbooks_selected: Option<Vec<String>>,
}

/// Timing info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingInfo {
    pub started_at: String,
    pub ended_at: String,
    pub duration_actual_sec: u32,
    pub capture_start_delay_ms: Option<u64>,
}

/// Complete run summary (matches run_summary.schema.json)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub schema_version: String,
    pub run_id: String,
    pub mission: MissionInfo,
    pub timing: TimingInfo,
    pub environment: EnvironmentInfo,
    pub capture: CaptureMetrics,
    pub compiler: CompilerMetrics,
    pub explain: ExplainMetrics,
    pub perf: PerfMetrics,
}

impl Default for RunSummary {
    fn default() -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            run_id: String::new(),
            mission: MissionInfo {
                mission_type: "discovery".to_string(),
                profile: "default".to_string(),
                duration_requested_sec: 0,
                playbooks_selected: None,
            },
            timing: TimingInfo {
                started_at: String::new(),
                ended_at: String::new(),
                duration_actual_sec: 0,
                capture_start_delay_ms: None,
            },
            environment: EnvironmentInfo::default(),
            capture: CaptureMetrics::default(),
            compiler: CompilerMetrics::default(),
            explain: ExplainMetrics::default(),
            perf: PerfMetrics::default(),
        }
    }
}

/// Atomic counters for thread-safe increment during run
pub struct AtomicCounters {
    pub events_read: AtomicU64,
    pub events_dropped: AtomicU64,
    pub bytes_read: AtomicU64,
    pub events_ingested: AtomicU64,
    pub events_parse_errors: AtomicU64,
    pub facts_extracted: AtomicU64,
    pub signals_emitted: AtomicU64,
}

impl Default for AtomicCounters {
    fn default() -> Self {
        Self {
            events_read: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            events_ingested: AtomicU64::new(0),
            events_parse_errors: AtomicU64::new(0),
            facts_extracted: AtomicU64::new(0),
            signals_emitted: AtomicU64::new(0),
        }
    }
}

impl AtomicCounters {
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            events_read: self.events_read.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            events_ingested: self.events_ingested.load(Ordering::Relaxed),
            events_parse_errors: self.events_parse_errors.load(Ordering::Relaxed),
            facts_extracted: self.facts_extracted.load(Ordering::Relaxed),
            signals_emitted: self.signals_emitted.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CounterSnapshot {
    pub events_read: u64,
    pub events_dropped: u64,
    pub bytes_read: u64,
    pub events_ingested: u64,
    pub events_parse_errors: u64,
    pub facts_extracted: u64,
    pub signals_emitted: u64,
}

/// Metrics collector that aggregates data throughout a run
pub struct MetricsCollector {
    run_id: String,
    run_dir: PathBuf,
    start_time: Instant,
    started_at: chrono::DateTime<chrono::Utc>,
    counters: Arc<AtomicCounters>,
    perf_samples: RwLock<Vec<PerfSample>>,
    source_breakdown: RwLock<HashMap<String, SourceMetrics>>,
    event_id_histogram: RwLock<HashMap<u32, u64>>,
    fact_type_breakdown: RwLock<HashMap<String, u64>>,
    playbooks_matched: RwLock<Vec<String>>,
    severity_breakdown: RwLock<SeverityBreakdown>,
    explain_metrics: RwLock<ExplainMetrics>,
    environment: RwLock<EnvironmentInfo>,
    mission_info: RwLock<MissionInfo>,
}

impl MetricsCollector {
    pub fn new(run_id: String, run_dir: PathBuf) -> Self {
        Self {
            run_id,
            run_dir,
            start_time: Instant::now(),
            started_at: chrono::Utc::now(),
            counters: Arc::new(AtomicCounters::default()),
            perf_samples: RwLock::new(Vec::new()),
            source_breakdown: RwLock::new(HashMap::new()),
            event_id_histogram: RwLock::new(HashMap::new()),
            fact_type_breakdown: RwLock::new(HashMap::new()),
            playbooks_matched: RwLock::new(Vec::new()),
            severity_breakdown: RwLock::new(SeverityBreakdown::default()),
            explain_metrics: RwLock::new(ExplainMetrics::default()),
            environment: RwLock::new(EnvironmentInfo::default()),
            mission_info: RwLock::new(MissionInfo {
                mission_type: "discovery".to_string(),
                profile: "default".to_string(),
                duration_requested_sec: 0,
                playbooks_selected: None,
            }),
        }
    }

    pub fn counters(&self) -> Arc<AtomicCounters> {
        Arc::clone(&self.counters)
    }

    pub async fn set_environment(&self, env: EnvironmentInfo) {
        let mut guard = self.environment.write().await;
        *guard = env;
    }

    pub async fn set_mission_info(&self, info: MissionInfo) {
        let mut guard = self.mission_info.write().await;
        *guard = info;
    }

    /// Record events from a source
    pub async fn record_source_events(&self, source: &str, events: u64, bytes: u64) {
        let mut guard = self.source_breakdown.write().await;
        let entry = guard.entry(source.to_string()).or_default();
        entry.events += events;
        entry.bytes += bytes;
    }

    /// Record event ID occurrence
    pub async fn record_event_id(&self, event_id: u32, count: u64) {
        let mut guard = self.event_id_histogram.write().await;
        *guard.entry(event_id).or_insert(0) += count;
    }

    /// Record fact type extraction
    pub async fn record_fact_type(&self, fact_type: &str, count: u64) {
        let mut guard = self.fact_type_breakdown.write().await;
        *guard.entry(fact_type.to_string()).or_insert(0) += count;
    }

    /// Record playbook match
    pub async fn record_playbook_match(&self, playbook_id: &str) {
        let mut guard = self.playbooks_matched.write().await;
        if !guard.contains(&playbook_id.to_string()) {
            guard.push(playbook_id.to_string());
        }
    }

    /// Record signal severity
    pub async fn record_signal_severity(&self, severity: &str) {
        let mut guard = self.severity_breakdown.write().await;
        match severity.to_lowercase().as_str() {
            "critical" => guard.critical += 1,
            "high" => guard.high += 1,
            "medium" => guard.medium += 1,
            "low" => guard.low += 1,
            _ => guard.informational += 1,
        }
    }

    /// Record explain metrics update
    pub async fn update_explain_metrics<F>(&self, updater: F)
    where
        F: FnOnce(&mut ExplainMetrics),
    {
        let mut guard = self.explain_metrics.write().await;
        updater(&mut guard);
    }

    /// Add performance sample
    pub async fn add_perf_sample(&self, cpu_percent: f64, rss_mb: f64) {
        let sample = PerfSample {
            timestamp: chrono::Utc::now().to_rfc3339(),
            cpu_percent,
            rss_mb,
        };
        let mut guard = self.perf_samples.write().await;
        guard.push(sample);
    }

    /// Get elapsed seconds
    pub fn elapsed_seconds(&self) -> u32 {
        self.start_time.elapsed().as_secs() as u32
    }

    /// Build final run summary
    pub async fn build_summary(&self, segments_written: u32, playbooks_loaded: u32, incidents_promoted: u32) -> RunSummary {
        let ended_at = chrono::Utc::now();
        let duration_actual_sec = self.start_time.elapsed().as_secs() as u32;

        let snapshot = self.counters.snapshot();
        let source_breakdown = self.source_breakdown.read().await.clone();
        let event_id_histogram = self.event_id_histogram.read().await.clone();
        let fact_type_breakdown = self.fact_type_breakdown.read().await.clone();
        let playbooks_matched = self.playbooks_matched.read().await.clone();
        let severity_breakdown = self.severity_breakdown.read().await.clone();
        let explain_metrics = self.explain_metrics.read().await.clone();
        let environment = self.environment.read().await.clone();
        let mission_info = self.mission_info.read().await.clone();
        let perf_samples = self.perf_samples.read().await.clone();

        // Calculate perf stats
        let peak_rss_mb = perf_samples.iter().map(|s| s.rss_mb).fold(0.0_f64, f64::max);
        let avg_rss_mb = if perf_samples.is_empty() {
            0.0
        } else {
            perf_samples.iter().map(|s| s.rss_mb).sum::<f64>() / perf_samples.len() as f64
        };
        let events_per_second = if duration_actual_sec == 0 {
            0.0
        } else {
            snapshot.events_read as f64 / duration_actual_sec as f64
        };

        // Calculate disk written (approximate from bytes read + overhead)
        let disk_written_mb = (snapshot.bytes_read as f64 * 1.2) / (1024.0 * 1024.0);

        RunSummary {
            schema_version: "1.0.0".to_string(),
            run_id: self.run_id.clone(),
            mission: mission_info,
            timing: TimingInfo {
                started_at: self.started_at.to_rfc3339(),
                ended_at: ended_at.to_rfc3339(),
                duration_actual_sec,
                capture_start_delay_ms: None, // TODO: measure actual delay
            },
            environment,
            capture: CaptureMetrics {
                events_read: snapshot.events_read,
                events_dropped: snapshot.events_dropped,
                bytes_read: snapshot.bytes_read,
                segments_written,
                source_breakdown,
                event_id_histogram,
            },
            compiler: CompilerMetrics {
                events_ingested: snapshot.events_ingested,
                events_parse_errors: snapshot.events_parse_errors,
                facts_extracted: snapshot.facts_extracted,
                fact_type_breakdown,
                playbooks_loaded,
                playbooks_matched,
                signals_emitted: snapshot.signals_emitted,
                signals_by_severity: severity_breakdown,
                incidents_promoted,
            },
            explain: ExplainMetrics {
                signals_with_explain: explain_metrics.signals_with_explain,
                deref_attempts: explain_metrics.deref_attempts,
                deref_successes: explain_metrics.deref_successes,
                excerpt_failures: explain_metrics.excerpt_failures,
                slots_required: explain_metrics.slots_required,
                slots_filled: explain_metrics.slots_filled,
                entities_required: explain_metrics.entities_required,
                entities_resolved: explain_metrics.entities_resolved,
                narratives_generated: explain_metrics.narratives_generated,
            },
            perf: PerfMetrics {
                cpu_samples: perf_samples,
                peak_rss_mb,
                avg_rss_mb,
                disk_written_mb,
                events_per_second,
            },
        }
    }

    /// Write run_summary.json to run directory
    pub async fn write_summary(&self, summary: &RunSummary) -> Result<PathBuf, String> {
        let path = self.run_dir.join("run_summary.json");
        let json = serde_json::to_string_pretty(summary)
            .map_err(|e| format!("Failed to serialize run summary: {}", e))?;
        std::fs::write(&path, json)
            .map_err(|e| format!("Failed to write run summary: {}", e))?;
        Ok(path)
    }
}

/// Sample current process performance
/// Returns (cpu_percent, rss_mb) if available
pub fn sample_process_perf() -> Option<(f64, f64)> {
    // Simple fallback - detailed memory info requires additional features
    // For now return None; can be enhanced with sysinfo crate later
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_metrics_collector() {
        let dir = tempdir().unwrap();
        let collector = MetricsCollector::new("20260107_120000".to_string(), dir.path().to_path_buf());

        // Simulate some activity
        collector.counters().events_read.fetch_add(100, Ordering::Relaxed);
        collector.counters().facts_extracted.fetch_add(50, Ordering::Relaxed);
        collector.counters().signals_emitted.fetch_add(5, Ordering::Relaxed);

        collector.record_source_events("Security", 80, 10000).await;
        collector.record_source_events("Sysmon", 20, 3000).await;
        collector.record_event_id(4688, 50).await;
        collector.record_fact_type("Exec", 40).await;
        collector.record_playbook_match("signal_lolbin_abuse").await;
        collector.record_signal_severity("medium").await;

        let summary = collector.build_summary(3, 10, 1).await;
        
        assert_eq!(summary.capture.events_read, 100);
        assert_eq!(summary.compiler.facts_extracted, 50);
        assert_eq!(summary.compiler.signals_emitted, 5);
        assert!(summary.capture.source_breakdown.contains_key("Security"));
        assert!(summary.compiler.playbooks_matched.contains(&"signal_lolbin_abuse".to_string()));
    }
}

//! Baseline Run Management
//!
//! Provides mechanisms for:
//! - Marking a run as a baseline
//! - Comparing current runs against baselines
//! - Detecting regressions and deltas
//! - Persisting baseline metadata

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

// ============================================================================
// Baseline Types
// ============================================================================

/// Metadata for a baseline run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineMetadata {
    /// Run ID of the baseline
    pub run_id: String,
    /// When the baseline was marked
    pub marked_at: String,
    /// Description/notes for this baseline
    pub description: String,
    /// Mission profile used (if any)
    pub mission_profile: Option<String>,
    /// Environment snapshot
    pub environment: BaselineEnvironment,
    /// Key metrics snapshot at time of baseline
    pub metrics_snapshot: BaselineMetricsSnapshot,
    /// Schema version for forward compatibility
    pub schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEnvironment {
    pub is_admin: bool,
    pub sysmon_installed: bool,
    pub os_version: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineMetricsSnapshot {
    /// Events captured
    pub events_count: u64,
    /// Segments written
    pub segments_count: u32,
    /// Facts extracted
    pub facts_count: u64,
    /// Signals fired
    pub signals_count: u64,
    /// Incidents formed
    pub incidents_count: u64,
    /// Run duration in seconds
    pub duration_seconds: u64,
    /// Events per second rate
    pub events_per_second: f64,
    /// Facts per event ratio
    pub facts_per_event: f64,
}

impl Default for BaselineMetricsSnapshot {
    fn default() -> Self {
        Self {
            events_count: 0,
            segments_count: 0,
            facts_count: 0,
            signals_count: 0,
            incidents_count: 0,
            duration_seconds: 0,
            events_per_second: 0.0,
            facts_per_event: 0.0,
        }
    }
}

// ============================================================================
// Comparison Result Types
// ============================================================================

/// Result of comparing current run against baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineComparison {
    /// The baseline we compared against
    pub baseline_run_id: String,
    /// Current run ID
    pub current_run_id: String,
    /// When comparison was performed
    pub compared_at: String,
    /// Individual metric deltas
    pub deltas: MetricDeltas,
    /// Detected regressions
    pub regressions: Vec<RegressionItem>,
    /// Detected improvements
    pub improvements: Vec<ImprovementItem>,
    /// Overall verdict
    pub verdict: ComparisonVerdict,
    /// Summary message
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDeltas {
    pub events_delta: i64,
    pub events_delta_pct: f64,
    pub segments_delta: i32,
    pub facts_delta: i64,
    pub facts_delta_pct: f64,
    pub signals_delta: i64,
    pub signals_delta_pct: f64,
    pub incidents_delta: i64,
    pub events_per_second_delta: f64,
    pub facts_per_event_delta: f64,
}

impl MetricDeltas {
    fn calculate(current: &BaselineMetricsSnapshot, baseline: &BaselineMetricsSnapshot) -> Self {
        let events_delta = current.events_count as i64 - baseline.events_count as i64;
        let facts_delta = current.facts_count as i64 - baseline.facts_count as i64;
        let signals_delta = current.signals_count as i64 - baseline.signals_count as i64;
        
        Self {
            events_delta,
            events_delta_pct: pct_delta(current.events_count, baseline.events_count),
            segments_delta: current.segments_count as i32 - baseline.segments_count as i32,
            facts_delta,
            facts_delta_pct: pct_delta(current.facts_count, baseline.facts_count),
            signals_delta,
            signals_delta_pct: pct_delta(current.signals_count, baseline.signals_count),
            incidents_delta: current.incidents_count as i64 - baseline.incidents_count as i64,
            events_per_second_delta: current.events_per_second - baseline.events_per_second,
            facts_per_event_delta: current.facts_per_event - baseline.facts_per_event,
        }
    }
}

fn pct_delta(current: u64, baseline: u64) -> f64 {
    if baseline == 0 {
        if current > 0 { 100.0 } else { 0.0 }
    } else {
        ((current as f64 - baseline as f64) / baseline as f64) * 100.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionItem {
    pub metric: String,
    pub severity: RegressionSeverity,
    pub baseline_value: String,
    pub current_value: String,
    pub delta: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegressionSeverity {
    Critical, // >50% drop or signal/incident loss
    Major,    // 20-50% drop
    Minor,    // 10-20% drop
}

impl RegressionSeverity {
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Critical => "🔴",
            Self::Major => "🟠",
            Self::Minor => "🟡",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImprovementItem {
    pub metric: String,
    pub baseline_value: String,
    pub current_value: String,
    pub delta: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComparisonVerdict {
    Stable,       // No significant changes
    Improved,     // Improvements without regressions
    Regressed,    // Has regressions
    Incomparable, // Can't compare (different environments, etc)
}

impl ComparisonVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Improved => "improved",
            Self::Regressed => "regressed",
            Self::Incomparable => "incomparable",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Stable => "✅",
            Self::Improved => "🎉",
            Self::Regressed => "⚠️",
            Self::Incomparable => "❓",
        }
    }
}

// ============================================================================
// Baseline Manager
// ============================================================================

/// Manages baseline runs for a telemetry root
pub struct BaselineManager {
    telemetry_root: PathBuf,
}

impl BaselineManager {
    pub fn new(telemetry_root: PathBuf) -> Self {
        Self { telemetry_root }
    }

    /// Path to baseline registry file
    fn registry_path(&self) -> PathBuf {
        self.telemetry_root.join("baselines.json")
    }

    /// Path to baseline metadata in a run directory
    fn run_baseline_path(&self, run_id: &str) -> PathBuf {
        self.telemetry_root
            .join("runs")
            .join(run_id)
            .join("baseline.json")
    }

    /// Load the baseline registry
    fn load_registry(&self) -> Result<BaselineRegistry, String> {
        let path = self.registry_path();
        if !path.exists() {
            return Ok(BaselineRegistry::default());
        }
        
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read baseline registry: {}", e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse baseline registry: {}", e))
    }

    /// Save the baseline registry
    fn save_registry(&self, registry: &BaselineRegistry) -> Result<(), String> {
        let content = serde_json::to_string_pretty(registry)
            .map_err(|e| format!("Failed to serialize baseline registry: {}", e))?;
        fs::write(self.registry_path(), content)
            .map_err(|e| format!("Failed to write baseline registry: {}", e))
    }

    /// Mark a run as a baseline
    pub fn mark_as_baseline(
        &self,
        run_id: &str,
        description: &str,
        mission_profile: Option<String>,
    ) -> Result<BaselineMetadata, String> {
        let run_dir = self.telemetry_root.join("runs").join(run_id);
        
        if !run_dir.exists() {
            return Err(format!("Run directory not found: {}", run_id));
        }

        // Load run summary to extract metrics
        let summary_path = run_dir.join("run_summary.json");
        let metrics_snapshot = if summary_path.exists() {
            self.extract_metrics_from_summary(&summary_path)?
        } else {
            // Try to compute from artifacts
            self.compute_metrics_from_artifacts(&run_dir)?
        };

        // Get environment info
        let environment = BaselineEnvironment {
            is_admin: is_elevated(),
            sysmon_installed: check_sysmon_installed(),
            os_version: get_os_version(),
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_default(),
        };

        let metadata = BaselineMetadata {
            run_id: run_id.to_string(),
            marked_at: chrono::Utc::now().to_rfc3339(),
            description: description.to_string(),
            mission_profile,
            environment,
            metrics_snapshot,
            schema_version: "1.0.0".to_string(),
        };

        // Save baseline metadata to run directory
        let baseline_json = serde_json::to_string_pretty(&metadata)
            .map_err(|e| format!("Failed to serialize baseline: {}", e))?;
        fs::write(self.run_baseline_path(run_id), &baseline_json)
            .map_err(|e| format!("Failed to write baseline: {}", e))?;

        // Update registry
        let mut registry = self.load_registry()?;
        registry.baselines.insert(run_id.to_string(), metadata.clone());
        if registry.default_baseline.is_none() {
            registry.default_baseline = Some(run_id.to_string());
        }
        self.save_registry(&registry)?;

        Ok(metadata)
    }

    /// Set the default baseline for comparisons
    pub fn set_default_baseline(&self, run_id: &str) -> Result<(), String> {
        let mut registry = self.load_registry()?;
        
        if !registry.baselines.contains_key(run_id) {
            return Err(format!("Run {} is not marked as a baseline", run_id));
        }
        
        registry.default_baseline = Some(run_id.to_string());
        self.save_registry(&registry)
    }

    /// Get the default baseline
    pub fn get_default_baseline(&self) -> Result<Option<BaselineMetadata>, String> {
        let registry = self.load_registry()?;
        
        match &registry.default_baseline {
            Some(run_id) => Ok(registry.baselines.get(run_id).cloned()),
            None => Ok(None),
        }
    }

    /// List all marked baselines
    pub fn list_baselines(&self) -> Result<Vec<BaselineMetadata>, String> {
        let registry = self.load_registry()?;
        Ok(registry.baselines.values().cloned().collect())
    }

    /// Remove baseline marking from a run
    pub fn unmark_baseline(&self, run_id: &str) -> Result<(), String> {
        let mut registry = self.load_registry()?;
        
        registry.baselines.remove(run_id);
        if registry.default_baseline.as_deref() == Some(run_id) {
            registry.default_baseline = None;
        }
        
        // Remove baseline.json from run dir
        let baseline_path = self.run_baseline_path(run_id);
        if baseline_path.exists() {
            fs::remove_file(&baseline_path).ok();
        }
        
        self.save_registry(&registry)
    }

    /// Compare a run against a baseline
    pub fn compare_against_baseline(
        &self,
        current_run_id: &str,
        baseline_run_id: Option<&str>,
    ) -> Result<BaselineComparison, String> {
        // Get baseline to compare against
        let baseline = if let Some(baseline_id) = baseline_run_id {
            let registry = self.load_registry()?;
            registry.baselines.get(baseline_id).cloned()
                .ok_or_else(|| format!("Baseline not found: {}", baseline_id))?
        } else {
            self.get_default_baseline()?
                .ok_or_else(|| "No default baseline set".to_string())?
        };

        // Get current run metrics
        let current_run_dir = self.telemetry_root.join("runs").join(current_run_id);
        if !current_run_dir.exists() {
            return Err(format!("Current run not found: {}", current_run_id));
        }

        let current_metrics = {
            let summary_path = current_run_dir.join("run_summary.json");
            if summary_path.exists() {
                self.extract_metrics_from_summary(&summary_path)?
            } else {
                self.compute_metrics_from_artifacts(&current_run_dir)?
            }
        };

        // Calculate deltas
        let deltas = MetricDeltas::calculate(&current_metrics, &baseline.metrics_snapshot);

        // Detect regressions
        let mut regressions = Vec::new();
        let mut improvements = Vec::new();

        // Events regression
        if deltas.events_delta_pct < -50.0 {
            regressions.push(RegressionItem {
                metric: "events_count".to_string(),
                severity: RegressionSeverity::Critical,
                baseline_value: baseline.metrics_snapshot.events_count.to_string(),
                current_value: current_metrics.events_count.to_string(),
                delta: format!("{:.1}%", deltas.events_delta_pct),
                explanation: "Significant drop in event capture - check telemetry sources".to_string(),
            });
        } else if deltas.events_delta_pct < -20.0 {
            regressions.push(RegressionItem {
                metric: "events_count".to_string(),
                severity: RegressionSeverity::Major,
                baseline_value: baseline.metrics_snapshot.events_count.to_string(),
                current_value: current_metrics.events_count.to_string(),
                delta: format!("{:.1}%", deltas.events_delta_pct),
                explanation: "Notable drop in event capture".to_string(),
            });
        } else if deltas.events_delta_pct > 20.0 {
            improvements.push(ImprovementItem {
                metric: "events_count".to_string(),
                baseline_value: baseline.metrics_snapshot.events_count.to_string(),
                current_value: current_metrics.events_count.to_string(),
                delta: format!("+{:.1}%", deltas.events_delta_pct),
            });
        }

        // Facts regression
        if deltas.facts_delta_pct < -30.0 {
            regressions.push(RegressionItem {
                metric: "facts_count".to_string(),
                severity: RegressionSeverity::Major,
                baseline_value: baseline.metrics_snapshot.facts_count.to_string(),
                current_value: current_metrics.facts_count.to_string(),
                delta: format!("{:.1}%", deltas.facts_delta_pct),
                explanation: "Fewer facts extracted - check fact extractors".to_string(),
            });
        }

        // Signal regression - any loss is concerning
        if deltas.signals_delta < 0 {
            let severity = if deltas.signals_delta_pct < -50.0 {
                RegressionSeverity::Critical
            } else if deltas.signals_delta_pct < -20.0 {
                RegressionSeverity::Major
            } else {
                RegressionSeverity::Minor
            };
            
            regressions.push(RegressionItem {
                metric: "signals_count".to_string(),
                severity,
                baseline_value: baseline.metrics_snapshot.signals_count.to_string(),
                current_value: current_metrics.signals_count.to_string(),
                delta: format!("{}", deltas.signals_delta),
                explanation: "Lost signal detections - check playbook matching".to_string(),
            });
        } else if deltas.signals_delta > 0 && baseline.metrics_snapshot.signals_count > 0 {
            improvements.push(ImprovementItem {
                metric: "signals_count".to_string(),
                baseline_value: baseline.metrics_snapshot.signals_count.to_string(),
                current_value: current_metrics.signals_count.to_string(),
                delta: format!("+{}", deltas.signals_delta),
            });
        }

        // Determine verdict
        let verdict = if !regressions.is_empty() {
            let has_critical = regressions.iter()
                .any(|r| r.severity == RegressionSeverity::Critical);
            if has_critical {
                ComparisonVerdict::Regressed
            } else {
                ComparisonVerdict::Regressed
            }
        } else if !improvements.is_empty() {
            ComparisonVerdict::Improved
        } else {
            ComparisonVerdict::Stable
        };

        // Build summary
        let summary = match verdict {
            ComparisonVerdict::Stable => {
                format!(
                    "Run {} is stable compared to baseline {}",
                    current_run_id, baseline.run_id
                )
            }
            ComparisonVerdict::Improved => {
                format!(
                    "Run {} shows {} improvements over baseline {}",
                    current_run_id, improvements.len(), baseline.run_id
                )
            }
            ComparisonVerdict::Regressed => {
                let critical_count = regressions.iter()
                    .filter(|r| r.severity == RegressionSeverity::Critical)
                    .count();
                format!(
                    "Run {} has {} regressions ({} critical) vs baseline {}",
                    current_run_id, regressions.len(), critical_count, baseline.run_id
                )
            }
            ComparisonVerdict::Incomparable => {
                "Runs cannot be compared due to different configurations".to_string()
            }
        };

        Ok(BaselineComparison {
            baseline_run_id: baseline.run_id.clone(),
            current_run_id: current_run_id.to_string(),
            compared_at: chrono::Utc::now().to_rfc3339(),
            deltas,
            regressions,
            improvements,
            verdict,
            summary,
        })
    }

    /// Extract metrics from a run_summary.json
    fn extract_metrics_from_summary(&self, path: &Path) -> Result<BaselineMetricsSnapshot, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read run summary: {}", e))?;
        let json: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse run summary: {}", e))?;

        let events_count = json["capture"]["events_read"]
            .as_u64()
            .or_else(|| json["capture"]["events_captured"].as_u64())
            .unwrap_or(0);
        let segments_count = json["capture"]["segments_written"]
            .as_u64()
            .unwrap_or(0) as u32;
        let facts_count = json["compiler"]["facts_extracted"]
            .as_u64()
            .or_else(|| json["compiler"]["facts_generated"].as_u64())
            .unwrap_or(0);
        let signals_count = json["compiler"]["signals_emitted"]
            .as_u64()
            .or_else(|| json["compiler"]["signals_fired"].as_u64())
            .unwrap_or(0);
        let incidents_count = json["compiler"]["incidents_formed"]
            .as_u64()
            .unwrap_or(0);
        let duration_seconds = json["timing"]["duration_actual_sec"]
            .as_u64()
            .or_else(|| json["timing"]["duration_seconds"].as_u64())
            .unwrap_or(60);

        let events_per_second = if duration_seconds > 0 {
            events_count as f64 / duration_seconds as f64
        } else {
            0.0
        };
        let facts_per_event = if events_count > 0 {
            facts_count as f64 / events_count as f64
        } else {
            0.0
        };

        Ok(BaselineMetricsSnapshot {
            events_count,
            segments_count,
            facts_count,
            signals_count,
            incidents_count,
            duration_seconds,
            events_per_second,
            facts_per_event,
        })
    }

    /// Compute metrics from raw artifacts (index.json + DB)
    fn compute_metrics_from_artifacts(&self, run_dir: &Path) -> Result<BaselineMetricsSnapshot, String> {
        let mut snapshot = BaselineMetricsSnapshot::default();

        // Read index.json for event/segment counts
        let index_path = run_dir.join("index.json");
        if index_path.exists() {
            if let Ok(content) = fs::read_to_string(&index_path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(segments) = json["segments"].as_array() {
                        snapshot.segments_count = segments.len() as u32;
                        for seg in segments {
                            snapshot.events_count += seg["records"].as_u64().unwrap_or(0);
                        }
                    }
                }
            }
        }

        // Read workbench.db for facts/signals
        let db_path = run_dir.join("workbench.db");
        if db_path.exists() {
            if let Ok(conn) = rusqlite::Connection::open(&db_path) {
                // Count signals
                if let Ok(count) = conn.query_row(
                    "SELECT COUNT(*) FROM signals",
                    [],
                    |row| row.get::<_, i64>(0),
                ) {
                    snapshot.signals_count = count as u64;
                }
            }
        }

        Ok(snapshot)
    }
}

// ============================================================================
// Registry Types
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BaselineRegistry {
    /// Map of run_id -> baseline metadata
    baselines: HashMap<String, BaselineMetadata>,
    /// The default baseline for comparisons
    default_baseline: Option<String>,
    /// Schema version
    schema_version: String,
}

// ============================================================================
// Helper Functions
// ============================================================================

#[cfg(windows)]
fn is_elevated() -> bool {
    use std::mem;
    use std::ptr;
    use windows_sys::Win32::Foundation::{HANDLE, CloseHandle};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        
        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut size = mem::size_of::<TOKEN_ELEVATION>() as u32;
        
        let result = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        );
        
        CloseHandle(token);
        
        result != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
fn is_elevated() -> bool {
    false
}

#[cfg(windows)]
fn check_sysmon_installed() -> bool {
    use std::process::Command;
    Command::new("sc")
        .args(["query", "Sysmon64"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        || Command::new("sc")
            .args(["query", "Sysmon"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

#[cfg(not(windows))]
fn check_sysmon_installed() -> bool {
    false
}

fn get_os_version() -> String {
    #[cfg(windows)]
    {
        std::env::var("OS").unwrap_or_else(|_| "Windows".to_string())
    }
    #[cfg(not(windows))]
    {
        "Unknown".to_string()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pct_delta() {
        assert_eq!(pct_delta(150, 100), 50.0);
        assert_eq!(pct_delta(50, 100), -50.0);
        assert_eq!(pct_delta(100, 100), 0.0);
        assert_eq!(pct_delta(100, 0), 100.0);
        assert_eq!(pct_delta(0, 0), 0.0);
    }

    #[test]
    fn test_metric_deltas() {
        let baseline = BaselineMetricsSnapshot {
            events_count: 1000,
            segments_count: 5,
            facts_count: 500,
            signals_count: 10,
            incidents_count: 2,
            duration_seconds: 60,
            events_per_second: 16.67,
            facts_per_event: 0.5,
        };

        let current = BaselineMetricsSnapshot {
            events_count: 1200,
            segments_count: 6,
            facts_count: 600,
            signals_count: 8,
            incidents_count: 2,
            duration_seconds: 60,
            events_per_second: 20.0,
            facts_per_event: 0.5,
        };

        let deltas = MetricDeltas::calculate(&current, &baseline);
        
        assert_eq!(deltas.events_delta, 200);
        assert_eq!(deltas.signals_delta, -2);
        assert!(deltas.events_delta_pct > 19.0 && deltas.events_delta_pct < 21.0);
    }
}

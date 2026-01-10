//! Quality Gates Engine
//!
//! Evaluates mission runs against quality gates and produces
//! the quality_report.json artifact.

use crate::missions::{MissionExpectations, MissionType};
use crate::run_metrics::RunSummary;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Gate evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResult {
    pub name: String,
    pub status: GateStatus,
    pub score: u32, // 0-100
    pub threshold: u32,
    pub message: String,
    pub details: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GateStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

impl GateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            GateStatus::Pass => "pass",
            GateStatus::Warn => "warn",
            GateStatus::Fail => "fail",
            GateStatus::Skip => "skip",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            GateStatus::Pass => "✅",
            GateStatus::Warn => "⚠️",
            GateStatus::Fail => "❌",
            GateStatus::Skip => "⏭️",
        }
    }
}

/// Delta between current and baseline run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDelta {
    pub metric: String,
    pub baseline_value: f64,
    pub current_value: f64,
    pub delta_absolute: f64,
    pub delta_percent: f64,
    pub direction: DeltaDirection,
    pub significance: Significance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeltaDirection {
    Improved,
    Regressed,
    Stable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Significance {
    High,
    Medium,
    Low,
    None,
}

/// Regression comparison result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionResult {
    pub baseline_run_id: String,
    pub baseline_timestamp: String,
    pub deltas: Vec<MetricDelta>,
    pub improved: Vec<String>,
    pub regressed: Vec<String>,
    pub stable: Vec<String>,
}

/// Mission-specific expectation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectationResult {
    pub required_playbooks: Vec<PlaybookExpectation>,
    pub max_noise_signals: Option<ThresholdResult>,
    pub min_detections: Option<ThresholdResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExpectation {
    pub playbook_id: String,
    pub expected: bool,
    pub matched: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdResult {
    pub threshold: u32,
    pub actual: u32,
    pub passed: bool,
}

/// Recommendation for improvement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub priority: String, // "high", "medium", "low"
    pub title: String,
    pub description: String,
    pub action: String,
}

/// Complete quality report (matches quality_report.schema.json)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityReport {
    pub schema_version: String,
    pub run_id: String,
    pub generated_at: String,
    pub baseline_run_id: Option<String>,
    pub gates: GatesResult,
    pub overall_verdict: String, // "pass", "warn", "fail"
    pub verdict_summary: String,
    pub regression: Option<RegressionResult>,
    pub mission_expectations: Option<ExpectationResult>,
    pub recommendations: Vec<Recommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatesResult {
    pub readiness: GateResult,
    pub telemetry: GateResult,
    pub extraction: GateResult,
    pub detection: GateResult,
    pub explainability: GateResult,
    pub performance: GateResult,
    pub mission_specific: Option<GateResult>,
}

/// Quality gate evaluator
pub struct QualityGatesEngine {
    mission_type: MissionType,
    expectations: MissionExpectations,
}

impl QualityGatesEngine {
    pub fn new(mission_type: MissionType, expectations: MissionExpectations) -> Self {
        Self {
            mission_type,
            expectations,
        }
    }

    /// Evaluate all quality gates against run summary
    pub fn evaluate(&self, summary: &RunSummary) -> QualityReport {
        let gates = GatesResult {
            readiness: self.evaluate_readiness_gate(summary),
            telemetry: self.evaluate_telemetry_gate(summary),
            extraction: self.evaluate_extraction_gate(summary),
            detection: self.evaluate_detection_gate(summary),
            explainability: self.evaluate_explainability_gate(summary),
            performance: self.evaluate_performance_gate(summary),
            mission_specific: self.evaluate_mission_specific_gate(summary),
        };

        let overall_verdict = self.compute_overall_verdict(&gates);
        let verdict_summary = self.generate_verdict_summary(&gates, &overall_verdict);
        let recommendations = self.generate_recommendations(&gates, summary);
        let mission_expectations = self.evaluate_mission_expectations(summary);

        QualityReport {
            schema_version: "1.0.0".to_string(),
            run_id: summary.run_id.clone(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            baseline_run_id: None, // Set by caller if regression comparison
            gates,
            overall_verdict,
            verdict_summary,
            regression: None, // Set by caller if baseline provided
            mission_expectations: Some(mission_expectations),
            recommendations,
        }
    }

    fn evaluate_readiness_gate(&self, summary: &RunSummary) -> GateResult {
        let env = &summary.environment;
        let mut score = 100u32;
        let mut issues = vec![];
        let mut capabilities_missing = 0u32;

        // Track missing capabilities - these cause Skip, not Fail
        if !env.is_admin {
            score = score.saturating_sub(30);
            capabilities_missing += 1;
            issues.push("Not running as administrator");
        }
        if !env.sysmon_installed {
            score = score.saturating_sub(20);
            capabilities_missing += 1;
            issues.push("Sysmon not installed");
        }
        if !env.audit_policy.process_creation {
            score = score.saturating_sub(25);
            capabilities_missing += 1;
            issues.push("Process creation auditing not enabled");
        }
        if !env.audit_policy.command_line_logging {
            score = score.saturating_sub(15);
            issues.push("Command line logging not enabled");
        }
        if !env.powershell_logging {
            score = score.saturating_sub(10);
            issues.push("PowerShell logging not enabled");
        }

        let threshold = 60;
        
        // If critical capabilities missing, Skip instead of Fail
        // This allows the mission to proceed with reduced expectations
        let status = if score >= 80 {
            GateStatus::Pass
        } else if capabilities_missing >= 2 {
            GateStatus::Skip // Skip when major capabilities missing
        } else if score >= threshold {
            GateStatus::Warn
        } else {
            GateStatus::Skip // Skip rather than fail for readiness
        };

        let message = if issues.is_empty() {
            "Full telemetry capability available".to_string()
        } else if status == GateStatus::Skip {
            format!("Reduced capability mode: {}", issues.join(", "))
        } else {
            format!("Limited capability: {}", issues.join(", "))
        };

        GateResult {
            name: "Readiness".to_string(),
            status,
            score,
            threshold,
            message,
            details: HashMap::from([
                ("is_admin".to_string(), serde_json::json!(env.is_admin)),
                ("sysmon_installed".to_string(), serde_json::json!(env.sysmon_installed)),
                ("readiness_level".to_string(), serde_json::json!(env.readiness_level)),
                ("capabilities_missing".to_string(), serde_json::json!(capabilities_missing)),
            ]),
        }
    }

    fn evaluate_telemetry_gate(&self, summary: &RunSummary) -> GateResult {
        let capture = &summary.capture;
        let min_events = self.expectations.min_events;

        let events = capture.events_read;
        let drop_rate = if events == 0 {
            0.0
        } else {
            capture.events_dropped as f64 / events as f64
        };

        // Skip if no segments (capability issue, not pipeline failure)
        if capture.segments_written == 0 {
            return GateResult {
                name: "Telemetry".to_string(),
                status: GateStatus::Skip,
                score: 0,
                threshold: 70,
                message: "No telemetry segments captured (capability issue)".to_string(),
                details: HashMap::from([
                    ("events_read".to_string(), serde_json::json!(events)),
                    ("segments".to_string(), serde_json::json!(0)),
                    ("reason".to_string(), serde_json::json!("no_segments")),
                ]),
            };
        }

        let mut score = 100u32;
        
        // Check minimum events
        if events < min_events as u64 {
            let ratio = events as f64 / min_events.max(1) as f64;
            score = (ratio * 50.0) as u32;
        }

        // Penalize drops
        if drop_rate > 0.05 {
            score = score.saturating_sub(20);
        } else if drop_rate > 0.01 {
            score = score.saturating_sub(10);
        }

        let threshold = 70;
        let status = if score >= 90 {
            GateStatus::Pass
        } else if score >= threshold {
            GateStatus::Warn
        } else {
            GateStatus::Fail
        };

        let message = format!(
            "{} events captured, {} dropped ({:.1}%), {} segments",
            events, capture.events_dropped, drop_rate * 100.0, capture.segments_written
        );

        GateResult {
            name: "Telemetry".to_string(),
            status,
            score,
            threshold,
            message,
            details: HashMap::from([
                ("events_read".to_string(), serde_json::json!(events)),
                ("events_dropped".to_string(), serde_json::json!(capture.events_dropped)),
                ("drop_rate".to_string(), serde_json::json!(drop_rate)),
                ("segments".to_string(), serde_json::json!(capture.segments_written)),
            ]),
        }
    }

    fn evaluate_extraction_gate(&self, summary: &RunSummary) -> GateResult {
        let compiler = &summary.compiler;
        
        // Skip if no events ingested (nothing to extract from)
        if compiler.events_ingested == 0 {
            return GateResult {
                name: "Extraction".to_string(),
                status: GateStatus::Skip,
                score: 0,
                threshold: 70,
                message: "No events ingested for extraction".to_string(),
                details: HashMap::from([
                    ("reason".to_string(), serde_json::json!("no_events")),
                ]),
            };
        }
        
        let parse_error_rate = compiler.events_parse_errors as f64 / compiler.events_ingested as f64;
        let extraction_rate = compiler.facts_extracted as f64 / compiler.events_ingested as f64;

        let mut score = 100u32;

        // Penalize parse errors
        if parse_error_rate > self.expectations.max_parse_error_rate {
            score = score.saturating_sub(30);
        } else if parse_error_rate > 0.01 {
            score = score.saturating_sub(10);
        }

        // Check extraction ratio (some events don't produce facts, so expect ~50%+)
        if extraction_rate < 0.3 {
            score = score.saturating_sub(20);
        }

        // Skip if no facts (may indicate locald not running)
        if compiler.facts_extracted == 0 {
            return GateResult {
                name: "Extraction".to_string(),
                status: GateStatus::Skip,
                score: 0,
                threshold: 70,
                message: "No facts extracted (locald may not be running)".to_string(),
                details: HashMap::from([
                    ("events_ingested".to_string(), serde_json::json!(compiler.events_ingested)),
                    ("reason".to_string(), serde_json::json!("no_facts")),
                ]),
            };
        }

        let threshold = 70;
        let status = if score >= 90 {
            GateStatus::Pass
        } else if score >= threshold {
            GateStatus::Warn
        } else {
            GateStatus::Fail
        };

        let message = format!(
            "{} facts extracted from {} events ({:.1}% extraction, {:.2}% parse errors)",
            compiler.facts_extracted,
            compiler.events_ingested,
            extraction_rate * 100.0,
            parse_error_rate * 100.0
        );

        GateResult {
            name: "Extraction".to_string(),
            status,
            score,
            threshold,
            message,
            details: HashMap::from([
                ("facts_extracted".to_string(), serde_json::json!(compiler.facts_extracted)),
                ("events_ingested".to_string(), serde_json::json!(compiler.events_ingested)),
                ("parse_error_rate".to_string(), serde_json::json!(parse_error_rate)),
            ]),
        }
    }

    fn evaluate_detection_gate(&self, summary: &RunSummary) -> GateResult {
        let compiler = &summary.compiler;
        
        let playbooks_loaded = compiler.playbooks_loaded;
        let signals = compiler.signals_emitted;
        let playbooks_matched = &compiler.playbooks_matched;

        let mut score = 100u32;

        // Must have playbooks loaded
        if playbooks_loaded == 0 {
            return GateResult {
                name: "Detection".to_string(),
                status: GateStatus::Fail,
                score: 0,
                threshold: 70,
                message: "No playbooks loaded".to_string(),
                details: HashMap::new(),
            };
        }

        // For adversary simulation, require minimum detections
        if let Some(min_detections) = self.expectations.min_detections {
            if signals < min_detections as u64 {
                let ratio = signals as f64 / min_detections as f64;
                score = (ratio * 70.0) as u32;
            }
        }

        // Check required playbooks
        let required_matched = self.expectations.required_playbooks.iter()
            .filter(|p| playbooks_matched.contains(p))
            .count();
        let required_total = self.expectations.required_playbooks.len();
        
        if required_total > 0 {
            let match_rate = required_matched as f64 / required_total as f64;
            if match_rate < 1.0 {
                score = score.saturating_sub(((1.0 - match_rate) * 30.0) as u32);
            }
        }

        let threshold = 70;
        let status = if score >= 90 {
            GateStatus::Pass
        } else if score >= threshold {
            GateStatus::Warn
        } else {
            GateStatus::Fail
        };

        let message = format!(
            "{} signals from {} playbooks ({} loaded)",
            signals, playbooks_matched.len(), playbooks_loaded
        );

        GateResult {
            name: "Detection".to_string(),
            status,
            score,
            threshold,
            message,
            details: HashMap::from([
                ("signals_emitted".to_string(), serde_json::json!(signals)),
                ("playbooks_loaded".to_string(), serde_json::json!(playbooks_loaded)),
                ("playbooks_matched".to_string(), serde_json::json!(playbooks_matched)),
            ]),
        }
    }

    fn evaluate_explainability_gate(&self, summary: &RunSummary) -> GateResult {
        let explain = &summary.explain;
        
        let deref_rate = explain.deref_success_rate();
        let slot_fill_rate = explain.slot_fill_rate();
        let entity_coverage = explain.entity_coverage();

        let mut score = 100u32;

        // Deref success is critical
        if deref_rate < self.expectations.min_deref_success_rate {
            let penalty = ((self.expectations.min_deref_success_rate - deref_rate) * 50.0) as u32;
            score = score.saturating_sub(penalty);
        }

        // Slot fill rate
        if slot_fill_rate < self.expectations.min_slot_fill_rate {
            let penalty = ((self.expectations.min_slot_fill_rate - slot_fill_rate) * 30.0) as u32;
            score = score.saturating_sub(penalty);
        }

        // Entity coverage
        if entity_coverage < 0.8 {
            score = score.saturating_sub(10);
        }

        // Excerpt failures
        if explain.excerpt_failures > 0 {
            score = score.saturating_sub(std::cmp::min(explain.excerpt_failures, 10) as u32);
        }

        // Skip if no signals
        if summary.compiler.signals_emitted == 0 {
            return GateResult {
                name: "Explainability".to_string(),
                status: GateStatus::Skip,
                score: 100,
                threshold: 70,
                message: "No signals to explain".to_string(),
                details: HashMap::new(),
            };
        }

        let threshold = 70;
        let status = if score >= 90 {
            GateStatus::Pass
        } else if score >= threshold {
            GateStatus::Warn
        } else {
            GateStatus::Fail
        };

        let message = format!(
            "Deref: {:.0}%, Slots: {:.0}%, Entities: {:.0}%",
            deref_rate * 100.0, slot_fill_rate * 100.0, entity_coverage * 100.0
        );

        GateResult {
            name: "Explainability".to_string(),
            status,
            score,
            threshold,
            message,
            details: HashMap::from([
                ("deref_success_rate".to_string(), serde_json::json!(deref_rate)),
                ("slot_fill_rate".to_string(), serde_json::json!(slot_fill_rate)),
                ("entity_coverage".to_string(), serde_json::json!(entity_coverage)),
                ("excerpt_failures".to_string(), serde_json::json!(explain.excerpt_failures)),
            ]),
        }
    }

    fn evaluate_performance_gate(&self, summary: &RunSummary) -> GateResult {
        let perf = &summary.perf;
        
        let mut score = 100u32;
        let mut issues = vec![];

        // Check peak RSS
        if let Some(max_rss) = self.expectations.max_peak_rss_mb {
            if perf.peak_rss_mb > max_rss {
                let excess = (perf.peak_rss_mb - max_rss) / max_rss;
                score = score.saturating_sub((excess * 30.0) as u32);
                issues.push(format!("Peak RSS {:.0}MB exceeds {:.0}MB limit", perf.peak_rss_mb, max_rss));
            }
        }

        // Check events/second (warn if very slow)
        if perf.events_per_second < 10.0 && summary.capture.events_read > 100 {
            score = score.saturating_sub(10);
            issues.push("Slow event processing".to_string());
        }

        let threshold = 60;
        let status = if score >= 90 {
            GateStatus::Pass
        } else if score >= threshold {
            GateStatus::Warn
        } else {
            GateStatus::Fail
        };

        let message = if issues.is_empty() {
            format!(
                "Peak RSS: {:.0}MB, Throughput: {:.1} events/sec",
                perf.peak_rss_mb, perf.events_per_second
            )
        } else {
            issues.join("; ")
        };

        GateResult {
            name: "Performance".to_string(),
            status,
            score,
            threshold,
            message,
            details: HashMap::from([
                ("peak_rss_mb".to_string(), serde_json::json!(perf.peak_rss_mb)),
                ("avg_rss_mb".to_string(), serde_json::json!(perf.avg_rss_mb)),
                ("events_per_second".to_string(), serde_json::json!(perf.events_per_second)),
            ]),
        }
    }

    fn evaluate_mission_specific_gate(&self, summary: &RunSummary) -> Option<GateResult> {
        match self.mission_type {
            MissionType::Discovery => Some(self.evaluate_noise_gate(summary)),
            MissionType::AdversarySimulation => Some(self.evaluate_required_detections_gate(summary)),
            MissionType::ForensicImport => Some(self.evaluate_determinism_gate(summary)),
        }
    }

    fn evaluate_noise_gate(&self, summary: &RunSummary) -> GateResult {
        let signals = summary.compiler.signals_emitted;
        let max_noise = self.expectations.max_noise_signals.unwrap_or(5);

        let score = if signals <= max_noise as u64 {
            100
        } else {
            let excess = signals - max_noise as u64;
            100u32.saturating_sub((excess * 10) as u32)
        };

        let threshold = 70;
        let status = if signals <= max_noise as u64 {
            GateStatus::Pass
        } else if score >= threshold {
            GateStatus::Warn
        } else {
            GateStatus::Fail
        };

        let message = format!(
            "{} signals emitted (max allowed: {})",
            signals, max_noise
        );

        GateResult {
            name: "Benign Noise".to_string(),
            status,
            score,
            threshold,
            message,
            details: HashMap::from([
                ("signals".to_string(), serde_json::json!(signals)),
                ("max_allowed".to_string(), serde_json::json!(max_noise)),
            ]),
        }
    }

    fn evaluate_required_detections_gate(&self, summary: &RunSummary) -> GateResult {
        let signals = summary.compiler.signals_emitted;
        let min_detections = self.expectations.min_detections.unwrap_or(1);

        let playbooks_matched = &summary.compiler.playbooks_matched;
        let required = &self.expectations.required_playbooks;
        let matched_required = required.iter().filter(|p| playbooks_matched.contains(p)).count();

        let detection_score = if signals >= min_detections as u64 { 50 } else {
            ((signals as f64 / min_detections as f64) * 50.0) as u32
        };

        let playbook_score = if required.is_empty() {
            50
        } else {
            ((matched_required as f64 / required.len() as f64) * 50.0) as u32
        };

        let score = detection_score + playbook_score;
        let threshold = 70;

        let status = if score >= 90 {
            GateStatus::Pass
        } else if score >= threshold {
            GateStatus::Warn
        } else {
            GateStatus::Fail
        };

        let message = format!(
            "{} signals (min: {}), {}/{} required playbooks matched",
            signals, min_detections, matched_required, required.len()
        );

        GateResult {
            name: "Required Detections".to_string(),
            status,
            score,
            threshold,
            message,
            details: HashMap::from([
                ("signals".to_string(), serde_json::json!(signals)),
                ("min_required".to_string(), serde_json::json!(min_detections)),
                ("required_playbooks".to_string(), serde_json::json!(required)),
                ("matched_playbooks".to_string(), serde_json::json!(playbooks_matched)),
            ]),
        }
    }

    fn evaluate_determinism_gate(&self, summary: &RunSummary) -> GateResult {
        // For forensic import, results should be deterministic
        // This requires comparing against a golden baseline
        
        let parse_errors = summary.compiler.events_parse_errors;
        let deref_rate = summary.explain.deref_success_rate();

        let mut score = 100u32;

        // Zero tolerance for parse errors in golden replay
        if parse_errors > 0 {
            score = score.saturating_sub(parse_errors as u32 * 10);
        }

        // Must have perfect deref
        if deref_rate < 1.0 {
            score = score.saturating_sub(((1.0 - deref_rate) * 50.0) as u32);
        }

        let threshold = 90; // Higher bar for determinism
        let status = if score >= 95 {
            GateStatus::Pass
        } else if score >= threshold {
            GateStatus::Warn
        } else {
            GateStatus::Fail
        };

        let message = format!(
            "Parse errors: {}, Deref rate: {:.0}%",
            parse_errors, deref_rate * 100.0
        );

        GateResult {
            name: "Determinism".to_string(),
            status,
            score,
            threshold,
            message,
            details: HashMap::from([
                ("parse_errors".to_string(), serde_json::json!(parse_errors)),
                ("deref_success_rate".to_string(), serde_json::json!(deref_rate)),
            ]),
        }
    }

    fn evaluate_mission_expectations(&self, summary: &RunSummary) -> ExpectationResult {
        let playbooks_matched = &summary.compiler.playbooks_matched;
        
        let required_playbooks = self.expectations.required_playbooks.iter()
            .map(|p| PlaybookExpectation {
                playbook_id: p.clone(),
                expected: true,
                matched: playbooks_matched.contains(p),
            })
            .collect();

        let max_noise_signals = self.expectations.max_noise_signals.map(|threshold| {
            let actual = summary.compiler.signals_emitted as u32;
            ThresholdResult {
                threshold,
                actual,
                passed: actual <= threshold,
            }
        });

        let min_detections = self.expectations.min_detections.map(|threshold| {
            let actual = summary.compiler.signals_emitted as u32;
            ThresholdResult {
                threshold,
                actual,
                passed: actual >= threshold,
            }
        });

        ExpectationResult {
            required_playbooks,
            max_noise_signals,
            min_detections,
        }
    }

    fn compute_overall_verdict(&self, gates: &GatesResult) -> String {
        let gate_results = [
            &gates.readiness,
            &gates.telemetry,
            &gates.extraction,
            &gates.detection,
            &gates.explainability,
            &gates.performance,
        ];

        let any_fail = gate_results.iter().any(|g| g.status == GateStatus::Fail);
        let any_warn = gate_results.iter().any(|g| g.status == GateStatus::Warn);

        // Also check mission-specific gate
        if let Some(ref mission_gate) = gates.mission_specific {
            if mission_gate.status == GateStatus::Fail {
                return "fail".to_string();
            }
        }

        if any_fail {
            "fail".to_string()
        } else if any_warn {
            "warn".to_string()
        } else {
            "pass".to_string()
        }
    }

    fn generate_verdict_summary(&self, gates: &GatesResult, verdict: &str) -> String {
        let failed: Vec<&str> = [
            (&gates.readiness, "Readiness"),
            (&gates.telemetry, "Telemetry"),
            (&gates.extraction, "Extraction"),
            (&gates.detection, "Detection"),
            (&gates.explainability, "Explainability"),
            (&gates.performance, "Performance"),
        ]
        .iter()
        .filter(|(g, _)| g.status == GateStatus::Fail)
        .map(|(_, name)| *name)
        .collect();

        match verdict {
            "pass" => "All quality gates passed".to_string(),
            "warn" => "Quality gates passed with warnings".to_string(),
            "fail" => format!("Failed gates: {}", failed.join(", ")),
            _ => "Unknown verdict".to_string(),
        }
    }

    fn generate_recommendations(&self, gates: &GatesResult, summary: &RunSummary) -> Vec<Recommendation> {
        let mut recommendations = vec![];

        // Readiness recommendations
        if gates.readiness.status != GateStatus::Pass {
            if !summary.environment.is_admin {
                recommendations.push(Recommendation {
                    id: "run_as_admin".to_string(),
                    priority: "high".to_string(),
                    title: "Run as Administrator".to_string(),
                    description: "Limited telemetry available without admin rights".to_string(),
                    action: "Right-click the app and select 'Run as administrator'".to_string(),
                });
            }
            if !summary.environment.sysmon_installed {
                recommendations.push(Recommendation {
                    id: "install_sysmon".to_string(),
                    priority: "medium".to_string(),
                    title: "Install Sysmon".to_string(),
                    description: "Sysmon provides rich process, network, and file telemetry".to_string(),
                    action: "Download and install Sysmon from Microsoft Sysinternals".to_string(),
                });
            }
        }

        // Detection recommendations
        if gates.detection.status == GateStatus::Fail {
            recommendations.push(Recommendation {
                id: "check_playbooks".to_string(),
                priority: "high".to_string(),
                title: "Verify Playbooks".to_string(),
                description: "No signals detected - check playbook configuration".to_string(),
                action: "Ensure playbooks are loaded and match expected activity patterns".to_string(),
            });
        }

        // Explainability recommendations
        if gates.explainability.status != GateStatus::Pass && gates.explainability.status != GateStatus::Skip {
            if summary.explain.deref_success_rate() < 0.9 {
                recommendations.push(Recommendation {
                    id: "fix_evidence_deref".to_string(),
                    priority: "medium".to_string(),
                    title: "Fix Evidence Dereferencing".to_string(),
                    description: "Some evidence pointers could not be resolved".to_string(),
                    action: "Check segment integrity and evidence pointer formats".to_string(),
                });
            }
        }

        recommendations
    }

    /// Compare current run against a baseline and compute deltas
    pub fn compare_runs(&self, current: &RunSummary, baseline: &RunSummary) -> RegressionResult {
        let mut deltas = vec![];
        let mut improved = vec![];
        let mut regressed = vec![];
        let mut stable = vec![];

        // Compare key metrics
        let metric_pairs = [
            ("events_read", current.capture.events_read as f64, baseline.capture.events_read as f64, true),
            ("facts_extracted", current.compiler.facts_extracted as f64, baseline.compiler.facts_extracted as f64, true),
            ("signals_emitted", current.compiler.signals_emitted as f64, baseline.compiler.signals_emitted as f64, true),
            ("deref_success_rate", current.explain.deref_success_rate(), baseline.explain.deref_success_rate(), true),
            ("slot_fill_rate", current.explain.slot_fill_rate(), baseline.explain.slot_fill_rate(), true),
            ("peak_rss_mb", current.perf.peak_rss_mb, baseline.perf.peak_rss_mb, false), // Lower is better
            ("events_per_second", current.perf.events_per_second, baseline.perf.events_per_second, true),
        ];

        for (metric, current_val, baseline_val, higher_is_better) in metric_pairs {
            let delta_absolute = current_val - baseline_val;
            let delta_percent = if baseline_val != 0.0 {
                (delta_absolute / baseline_val) * 100.0
            } else {
                0.0
            };

            let direction = if delta_absolute.abs() < 0.001 {
                DeltaDirection::Stable
            } else if (delta_absolute > 0.0) == higher_is_better {
                DeltaDirection::Improved
            } else {
                DeltaDirection::Regressed
            };

            let significance = if delta_percent.abs() >= 20.0 {
                Significance::High
            } else if delta_percent.abs() >= 10.0 {
                Significance::Medium
            } else if delta_percent.abs() >= 5.0 {
                Significance::Low
            } else {
                Significance::None
            };

            match direction {
                DeltaDirection::Improved => improved.push(metric.to_string()),
                DeltaDirection::Regressed => regressed.push(metric.to_string()),
                DeltaDirection::Stable => stable.push(metric.to_string()),
            }

            deltas.push(MetricDelta {
                metric: metric.to_string(),
                baseline_value: baseline_val,
                current_value: current_val,
                delta_absolute,
                delta_percent,
                direction,
                significance,
            });
        }

        RegressionResult {
            baseline_run_id: baseline.run_id.clone(),
            baseline_timestamp: baseline.timing.started_at.clone(),
            deltas,
            improved,
            regressed,
            stable,
        }
    }
}

/// Write quality report to run directory
pub fn write_quality_report(report: &QualityReport, run_dir: &Path) -> Result<PathBuf, String> {
    let path = run_dir.join("quality_report.json");
    let json = serde_json::to_string_pretty(report)
        .map_err(|e| format!("Failed to serialize quality report: {}", e))?;
    std::fs::write(&path, json)
        .map_err(|e| format!("Failed to write quality report: {}", e))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_metrics::*;

    fn make_test_summary() -> RunSummary {
        let mut summary = RunSummary::default();
        summary.run_id = "20260107_120000".to_string();
        summary.environment.is_admin = true;
        summary.environment.sysmon_installed = true;
        summary.environment.audit_policy.process_creation = true;
        summary.environment.audit_policy.command_line_logging = true;
        summary.environment.powershell_logging = true;
        summary.capture.events_read = 1000;
        summary.capture.segments_written = 5;
        summary.compiler.events_ingested = 1000;
        summary.compiler.facts_extracted = 500;
        summary.compiler.playbooks_loaded = 10;
        summary.compiler.signals_emitted = 5;
        summary.explain.signals_with_explain = 5;
        summary.explain.deref_attempts = 10;
        summary.explain.deref_successes = 9;
        summary.explain.slots_required = 20;
        summary.explain.slots_filled = 18;
        summary
    }

    #[test]
    fn test_quality_gates_pass() {
        let summary = make_test_summary();
        let expectations = MissionExpectations {
            min_events: 100,
            min_detections: Some(3),
            min_deref_success_rate: 0.85,
            min_slot_fill_rate: 0.80,
            ..Default::default()
        };
        
        let engine = QualityGatesEngine::new(MissionType::AdversarySimulation, expectations);
        let report = engine.evaluate(&summary);

        assert_eq!(report.overall_verdict, "pass");
    }

    #[test]
    fn test_regression_comparison() {
        let mut current = make_test_summary();
        let mut baseline = make_test_summary();
        
        // Simulate improvement
        current.capture.events_read = 1200;
        current.compiler.signals_emitted = 7;
        
        let engine = QualityGatesEngine::new(MissionType::Discovery, MissionExpectations::default());
        let regression = engine.compare_runs(&current, &baseline);

        assert!(!regression.improved.is_empty());
        assert!(regression.improved.contains(&"events_read".to_string()));
    }
}

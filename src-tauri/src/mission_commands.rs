//! Mission Workflow Commands for Tauri
//!
//! Tauri commands for the Mission Workflow Harness.
//! Provides UI-facing APIs for missions, scenario packs, quality gates, and regression.
//!
//! Real Pipeline Integration:
//! - Mission start/stop orchestrates capture + locald + server
//! - Counters come from real artifacts (index.json, workbench.db, API)
//! - Baseline mechanism for regression detection

use crate::baseline::{
    BaselineManager, BaselineMetadata, BaselineComparison, ComparisonVerdict,
};
use crate::missions::{MissionProfile, MissionType, MissionExpectations, get_builtin_profiles};
use crate::pipeline_counters::{
    PipelineCounterFetcher, PipelineCounters, SignalProvenanceProof,
    prove_signal_provenance,
};
use crate::quality_gates::{QualityGatesEngine, QualityReport, GateResult, GateStatus};
use crate::run_metrics::RunSummary;
use crate::scenario_packs::{
    self, ScenarioPack, ScenarioCategory, PackExecutionResult, 
    get_all_packs, get_pack_by_id, get_packs_by_category,
};
use crate::supervisor::SupervisorState;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::State;
use tokio::sync::RwLock;

// ============================================================================
// Mission State Management
// ============================================================================

/// Active mission state - tracks metrics during a run
#[derive(Default)]
pub struct MissionState {
    pub active_profile: Option<MissionProfile>,
    pub baseline_runs: Vec<RunSummary>,
}

pub struct MissionStateHandle {
    pub inner: RwLock<MissionState>,
}

impl MissionStateHandle {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(MissionState::default()),
        }
    }
}

// ============================================================================
// Mission Profile Commands
// ============================================================================

/// Get all built-in mission profiles
#[tauri::command]
pub async fn get_mission_profiles() -> Result<Vec<MissionProfile>, String> {
    Ok(get_builtin_profiles())
}

/// Get mission profiles by type
#[tauri::command]
pub async fn get_mission_profiles_by_type(mission_type: String) -> Result<Vec<MissionProfile>, String> {
    let mt = parse_mission_type(&mission_type)?;
    let profiles = get_builtin_profiles()
        .into_iter()
        .filter(|p| p.config.mission_type == mt)
        .collect();
    Ok(profiles)
}

/// Get a specific mission profile by ID
#[tauri::command]
pub async fn get_mission_profile(profile_id: String) -> Result<MissionProfile, String> {
    get_builtin_profiles()
        .into_iter()
        .find(|p| p.id == profile_id)
        .ok_or_else(|| format!("Mission profile not found: {}", profile_id))
}

// ============================================================================
// Scenario Pack Commands
// ============================================================================

/// Get all scenario packs
#[tauri::command]
pub async fn get_scenario_packs() -> Result<Vec<ScenarioPack>, String> {
    Ok(get_all_packs())
}

/// Get scenario packs by category
#[tauri::command]
pub async fn get_scenario_packs_by_category(category: String) -> Result<Vec<ScenarioPack>, String> {
    let cat = match category.to_lowercase().as_str() {
        "discovery" => ScenarioCategory::Discovery,
        "adversary" | "adversarysimulation" | "adversary_simulation" => ScenarioCategory::AdversarySimulation,
        _ => return Err(format!("Unknown category: {}. Use 'discovery' or 'adversary'.", category)),
    };
    Ok(get_packs_by_category(cat))
}

/// Get a specific scenario pack
#[tauri::command]
pub async fn get_scenario_pack(pack_id: String) -> Result<ScenarioPack, String> {
    get_pack_by_id(&pack_id)
        .ok_or_else(|| format!("Scenario pack not found: {}", pack_id))
}

/// Execute a scenario pack
#[tauri::command]
pub async fn execute_scenario_pack(
    pack_id: String,
) -> Result<PackExecutionResult, String> {
    let pack = get_pack_by_id(&pack_id)
        .ok_or_else(|| format!("Scenario pack not found: {}", pack_id))?;
    
    scenario_packs::execute_pack(&pack).await
}

// ============================================================================
// Mission Lifecycle Commands
// ============================================================================

/// Start a mission with a specific profile
#[tauri::command]
pub async fn start_mission(
    supervisor_state: State<'_, SupervisorState>,
    mission_state: State<'_, MissionStateHandle>,
    profile_id: String,
    duration_override_minutes: Option<u32>,
) -> Result<MissionStartResult, String> {
    // Get the profile
    let mut profile = get_builtin_profiles()
        .into_iter()
        .find(|p| p.id == profile_id)
        .ok_or_else(|| format!("Mission profile not found: {}", profile_id))?;
    
    // Apply duration override (convert minutes to seconds)
    let duration_minutes = if let Some(duration) = duration_override_minutes {
        profile.config.duration_seconds = duration * 60;
        duration
    } else {
        profile.config.duration_seconds / 60
    };
    
    // Check readiness
    let readiness = {
        let supervisor = supervisor_state.inner.read().await;
        supervisor.get_readiness()
    };
    
    // Store mission state
    {
        let mut state = mission_state.inner.write().await;
        state.active_profile = Some(profile.clone());
    }
    
    // Start the supervisor run
    let run_config = crate::supervisor::RunConfig {
        duration_minutes,
        selected_playbooks: profile.config.playbooks.clone(),
    };
    
    {
        let mut supervisor = supervisor_state.inner.write().await;
        supervisor.start_run(run_config).await?;
    }
    
    Ok(MissionStartResult {
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        mission_type: format!("{:?}", profile.config.mission_type),
        duration_minutes,
        started_at: chrono::Utc::now().to_rfc3339(),
        is_admin: readiness.is_admin,
    })
}

/// Get mission readiness check
#[tauri::command]
pub async fn get_mission_readiness(
    supervisor_state: State<'_, SupervisorState>,
    mission_state: State<'_, MissionStateHandle>,
) -> Result<MissionReadiness, String> {
    let readiness = {
        let supervisor = supervisor_state.inner.read().await;
        supervisor.get_readiness()
    };
    
    let has_active_mission = {
        let state = mission_state.inner.read().await;
        state.active_profile.is_some()
    };
    
    // Calculate overall readiness score (0-100)
    let mut score = 0;
    if readiness.is_admin { score += 25; }
    if readiness.can_read_security_log { score += 25; }
    if readiness.sysmon_installed { score += 25; }
    if readiness.audit_policy_state.process_creation { score += 15; }
    if readiness.powershell_logging_enabled { score += 10; }
    
    // Determine readiness level
    let level = if score >= 90 {
        "excellent"
    } else if score >= 70 {
        "good"
    } else if score >= 50 {
        "limited"
    } else {
        "minimal"
    };
    
    // Build recommendations
    let mut recommendations = vec![];
    if !readiness.is_admin {
        recommendations.push("Run as Administrator for full telemetry access".to_string());
    }
    if !readiness.can_read_security_log {
        recommendations.push("Enable Security log read access".to_string());
    }
    if !readiness.sysmon_installed {
        recommendations.push("Install Sysmon for enhanced process/network visibility".to_string());
    }
    if !readiness.audit_policy_state.process_creation {
        recommendations.push("Enable Process Creation auditing".to_string());
    }
    if !readiness.powershell_logging_enabled {
        recommendations.push("Enable PowerShell Script Block Logging".to_string());
    }
    
    Ok(MissionReadiness {
        score,
        level: level.to_string(),
        is_admin: readiness.is_admin,
        security_log_readable: readiness.can_read_security_log,
        sysmon_installed: readiness.sysmon_installed,
        process_creation_auditing: readiness.audit_policy_state.process_creation,
        powershell_logging: readiness.powershell_logging_enabled,
        has_active_mission,
        recommendations,
    })
}

/// Get live metrics during a mission - REAL PIPELINE COUNTERS
/// 
/// Fetches actual counters from:
/// - index.json (events captured, segments written)
/// - workbench.db (facts, signals)
/// - Server API (health, explanations)
#[tauri::command]
pub async fn get_mission_metrics(
    supervisor_state: State<'_, SupervisorState>,
    mission_state: State<'_, MissionStateHandle>,
) -> Result<Option<LiveMissionMetrics>, String> {
    let state = mission_state.inner.read().await;
    
    let Some(ref profile) = state.active_profile else {
        return Ok(None);
    };
    
    // Get status from supervisor
    let (run_dir, api_base_url, run_started) = {
        let mut supervisor = supervisor_state.inner.write().await;
        let status = supervisor.status().await;
        (
            status.run_dir.map(PathBuf::from),
            status.api_base_url,
            status.run_started,
        )
    };
    
    // Calculate elapsed time
    let elapsed_seconds = run_started
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|started: chrono::DateTime<chrono::FixedOffset>| {
            let now = chrono::Utc::now();
            let started_utc = started.with_timezone(&chrono::Utc);
            let duration = now.signed_duration_since(started_utc);
            duration.num_seconds().max(0) as u64
        })
        .unwrap_or(0);
    
    // Fetch REAL counters from the pipeline
    let (events_captured, facts_generated, signals_fired, incidents_formed) = 
        if let Some(ref run_dir) = run_dir {
            let fetcher = PipelineCounterFetcher::new(run_dir.clone(), api_base_url);
            let counters = fetcher.fetch_all().await;
            (
                counters.capture.events_total,
                counters.locald.facts_count,
                counters.locald.signals_count,
                counters.locald.incidents_count,
            )
        } else {
            (0, 0, 0, 0)
        };
    
    Ok(Some(LiveMissionMetrics {
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        events_captured,
        facts_generated,
        signals_fired,
        incidents_formed,
        elapsed_seconds,
        expected_events_min: profile.expectations.min_events,
        expected_facts_min: 0, // Not directly available
        expected_signals_min: profile.expectations.min_detections.unwrap_or(0),
    }))
}

/// Stop and finalize the current mission
#[tauri::command]
pub async fn stop_mission(
    supervisor_state: State<'_, SupervisorState>,
    mission_state: State<'_, MissionStateHandle>,
) -> Result<MissionStopResult, String> {
    // Stop the supervisor
    {
        let mut supervisor = supervisor_state.inner.write().await;
        supervisor.stop_all().await?;
    }
    
    // Clear mission state
    let profile = {
        let mut state = mission_state.inner.write().await;
        state.active_profile.take()
    };
    
    match profile {
        Some(profile) => {
            Ok(MissionStopResult {
                profile_id: profile.id,
                profile_name: profile.name,
                run_summary: None, // Summary would be written to disk
            })
        }
        None => Ok(MissionStopResult {
            profile_id: "unknown".to_string(),
            profile_name: "Unknown".to_string(),
            run_summary: None,
        })
    }
}

// ============================================================================
// Quality Gates Commands
// ============================================================================

/// Evaluate quality gates for the current/last run
#[tauri::command]
pub async fn evaluate_quality_gates(
    supervisor_state: State<'_, SupervisorState>,
    mission_state: State<'_, MissionStateHandle>,
) -> Result<QualityReport, String> {
    // Get GROUNDED gates from supervisor
    let grounded_gates = {
        let supervisor = supervisor_state.inner.read().await;
        supervisor.get_grounded_health_gates().await?
    };
    
    // Get mission profile if available
    let (mission_type, expectations) = {
        let state = mission_state.inner.read().await;
        match &state.active_profile {
            Some(p) => (p.config.mission_type, p.expectations.clone()),
            None => (MissionType::Discovery, MissionExpectations::default()),
        }
    };
    
    // Create quality gates engine
    let engine = QualityGatesEngine::new(mission_type, expectations);
    
    // Build RunSummary from GROUNDED gates
    let summary = grounded_gates_to_run_summary(&grounded_gates);
    
    // Evaluate all gates
    let report = engine.evaluate(&summary);
    
    Ok(report)
}

/// Convert GROUNDED gates to RunSummary for quality evaluation
fn grounded_gates_to_run_summary(gates: &crate::grounded_gates::GroundedHealthGates) -> RunSummary {
    use crate::run_metrics::*;
    
    let mut summary = RunSummary::default();
    summary.run_id = "current".to_string();
    
    // Map GROUNDED metrics to RunSummary
    summary.capture.events_read = gates.telemetry.events_count as u64;
    summary.capture.segments_written = gates.telemetry.segments_count;
    
    // Compiler metrics from extraction gate
    summary.compiler.facts_extracted = gates.extraction.facts_count as u64;
    
    // Signals from detection gate
    summary.compiler.signals_emitted = gates.detection.signals_count as u64;
    summary.compiler.playbooks_matched = gates.detection.signals_by_playbook.keys().cloned().collect();
    
    // Environment info - set from readiness (we don't have direct access here)
    summary.environment.is_admin = true; // Default assumption
    
    summary
}

/// Get quality gates scoreboard (simplified view for UI)
#[tauri::command]
pub async fn get_quality_scoreboard(
    supervisor_state: State<'_, SupervisorState>,
    mission_state: State<'_, MissionStateHandle>,
) -> Result<QualityScoreboard, String> {
    let report = evaluate_quality_gates(supervisor_state, mission_state).await?;
    
    // Convert GatesResult to scoreboard format
    let gates = vec![
        gate_to_scoreboard(&report.gates.readiness),
        gate_to_scoreboard(&report.gates.telemetry),
        gate_to_scoreboard(&report.gates.extraction),
        gate_to_scoreboard(&report.gates.detection),
        gate_to_scoreboard(&report.gates.explainability),
        gate_to_scoreboard(&report.gates.performance),
    ];
    
    let overall_emoji = match report.overall_verdict.as_str() {
        "pass" => "🎉",
        "warn" => "⚠️",
        "fail" => "❌",
        _ => "❓",
    };
    
    // Calculate total score
    let total_score = gates.iter().map(|g| g.score).sum::<u32>() / gates.len().max(1) as u32;
    
    Ok(QualityScoreboard {
        gates,
        overall_verdict: report.overall_verdict,
        overall_emoji: overall_emoji.to_string(),
        total_score,
    })
}

fn gate_to_scoreboard(gate: &GateResult) -> ScoreboardGate {
    ScoreboardGate {
        name: gate.name.clone(),
        status: format!("{:?}", gate.status),
        score: gate.score,
        emoji: match gate.status {
            GateStatus::Pass => "✅".to_string(),
            GateStatus::Warn => "⚠️".to_string(),
            GateStatus::Fail => "❌".to_string(),
            GateStatus::Skip => "⏭️".to_string(),
        },
    }
}

/// Compare current run against a baseline for regression
#[tauri::command]
pub async fn compare_runs(
    current_run_path: String,
    baseline_run_path: String,
) -> Result<RegressionComparison, String> {
    // Load run summaries
    let current_path = PathBuf::from(&current_run_path).join("run_summary.json");
    let baseline_path = PathBuf::from(&baseline_run_path).join("run_summary.json");
    
    let current_json: serde_json::Value = if current_path.exists() {
        let content = std::fs::read_to_string(&current_path)
            .map_err(|e| format!("Failed to read current run: {}", e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse current run: {}", e))?
    } else {
        return Err("Current run summary not found".to_string());
    };
    
    let baseline_json: serde_json::Value = if baseline_path.exists() {
        let content = std::fs::read_to_string(&baseline_path)
            .map_err(|e| format!("Failed to read baseline run: {}", e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse baseline run: {}", e))?
    } else {
        return Err("Baseline run summary not found".to_string());
    };
    
    // Extract metrics for comparison
    let current_events = current_json["capture"]["events_captured"].as_u64().unwrap_or(0);
    let baseline_events = baseline_json["capture"]["events_captured"].as_u64().unwrap_or(0);
    
    let current_facts = current_json["compiler"]["facts_generated"].as_u64().unwrap_or(0);
    let baseline_facts = baseline_json["compiler"]["facts_generated"].as_u64().unwrap_or(0);
    
    let current_signals = current_json["compiler"]["signals_fired"].as_u64().unwrap_or(0);
    let baseline_signals = baseline_json["compiler"]["signals_fired"].as_u64().unwrap_or(0);
    
    let current_incidents = current_json["compiler"]["incidents_formed"].as_u64().unwrap_or(0);
    let baseline_incidents = baseline_json["compiler"]["incidents_formed"].as_u64().unwrap_or(0);
    
    // Calculate deltas
    let events_delta = current_events as i64 - baseline_events as i64;
    let facts_delta = current_facts as i64 - baseline_facts as i64;
    let signals_delta = current_signals as i64 - baseline_signals as i64;
    let incidents_delta = current_incidents as i64 - baseline_incidents as i64;
    
    // Determine regression status
    let has_regression = events_delta < -(baseline_events as i64 / 10) as i64 // >10% drop
        || facts_delta < -(baseline_facts as i64 / 10) as i64
        || signals_delta < 0  // Any signal loss is concerning
        || incidents_delta < 0;
    
    Ok(RegressionComparison {
        current_run: current_run_path,
        baseline_run: baseline_run_path,
        events_delta,
        facts_delta,
        signals_delta,
        incidents_delta,
        has_regression,
        verdict: if has_regression { "regression" } else { "stable" }.to_string(),
    })
}

/// List available baseline runs for comparison
#[tauri::command]
pub async fn list_baseline_runs(
    supervisor_state: State<'_, SupervisorState>,
) -> Result<Vec<BaselineRunInfo>, String> {
    let runs = {
        let supervisor = supervisor_state.inner.read().await;
        supervisor.list_runs()?
    };
    
    // Convert runs to baseline info
    let baselines: Vec<BaselineRunInfo> = runs
        .into_iter()
        .map(|run| {
            BaselineRunInfo {
                run_id: run.run_id,
                started_at: run.started,
                duration_minutes: run.duration_minutes,
                has_summary: true, // Assume all runs have summary
            }
        })
        .collect();
    
    Ok(baselines)
}

// ============================================================================
// Helper Types
// ============================================================================

fn parse_mission_type(s: &str) -> Result<MissionType, String> {
    match s.to_lowercase().as_str() {
        "discovery" => Ok(MissionType::Discovery),
        "adversary" | "adversarysimulation" | "adversary_simulation" => Ok(MissionType::AdversarySimulation),
        "forensic" | "forensicimport" | "forensic_import" => Ok(MissionType::ForensicImport),
        _ => Err(format!("Unknown mission type: {}. Use 'discovery', 'adversary', or 'forensic'.", s)),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionStartResult {
    pub profile_id: String,
    pub profile_name: String,
    pub mission_type: String,
    pub duration_minutes: u32,
    pub started_at: String,
    pub is_admin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionReadiness {
    pub score: u32,
    pub level: String,
    pub is_admin: bool,
    pub security_log_readable: bool,
    pub sysmon_installed: bool,
    pub process_creation_auditing: bool,
    pub powershell_logging: bool,
    pub has_active_mission: bool,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveMissionMetrics {
    pub profile_id: String,
    pub profile_name: String,
    pub events_captured: u64,
    pub facts_generated: u64,
    pub signals_fired: u64,
    pub incidents_formed: u64,
    pub elapsed_seconds: u64,
    pub expected_events_min: u32,
    pub expected_facts_min: u32,
    pub expected_signals_min: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionStopResult {
    pub profile_id: String,
    pub profile_name: String,
    pub run_summary: Option<RunSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityScoreboard {
    pub gates: Vec<ScoreboardGate>,
    pub overall_verdict: String,
    pub overall_emoji: String,
    pub total_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreboardGate {
    pub name: String,
    pub status: String,
    pub score: u32,
    pub emoji: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionComparison {
    pub current_run: String,
    pub baseline_run: String,
    pub events_delta: i64,
    pub facts_delta: i64,
    pub signals_delta: i64,
    pub incidents_delta: i64,
    pub has_regression: bool,
    pub verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineRunInfo {
    pub run_id: String,
    pub started_at: String,
    pub duration_minutes: u32,
    pub has_summary: bool,
}

// ============================================================================
// Baseline Management Commands
// ============================================================================

/// Mark a run as a baseline for regression comparison
#[tauri::command]
pub async fn mark_run_as_baseline(
    supervisor_state: State<'_, SupervisorState>,
    run_id: String,
    description: String,
    mission_profile: Option<String>,
) -> Result<BaselineMetadata, String> {
    let telemetry_root = {
        let supervisor = supervisor_state.inner.read().await;
        PathBuf::from(supervisor.get_telemetry_root())
    };
    
    let manager = BaselineManager::new(telemetry_root);
    manager.mark_as_baseline(&run_id, &description, mission_profile)
}

/// Set the default baseline for comparisons
#[tauri::command]
pub async fn set_default_baseline(
    supervisor_state: State<'_, SupervisorState>,
    run_id: String,
) -> Result<(), String> {
    let telemetry_root = {
        let supervisor = supervisor_state.inner.read().await;
        PathBuf::from(supervisor.get_telemetry_root())
    };
    
    let manager = BaselineManager::new(telemetry_root);
    manager.set_default_baseline(&run_id)
}

/// Get all marked baselines
#[tauri::command]
pub async fn get_baselines(
    supervisor_state: State<'_, SupervisorState>,
) -> Result<Vec<BaselineMetadata>, String> {
    let telemetry_root = {
        let supervisor = supervisor_state.inner.read().await;
        PathBuf::from(supervisor.get_telemetry_root())
    };
    
    let manager = BaselineManager::new(telemetry_root);
    manager.list_baselines()
}

/// Compare current/specified run against baseline with full delta report
#[tauri::command]
pub async fn compare_against_baseline(
    supervisor_state: State<'_, SupervisorState>,
    current_run_id: String,
    baseline_run_id: Option<String>,
) -> Result<BaselineComparison, String> {
    let telemetry_root = {
        let supervisor = supervisor_state.inner.read().await;
        PathBuf::from(supervisor.get_telemetry_root())
    };
    
    let manager = BaselineManager::new(telemetry_root);
    manager.compare_against_baseline(&current_run_id, baseline_run_id.as_deref())
}

// ============================================================================
// Real Pipeline Counters Commands
// ============================================================================

/// Get real-time pipeline counters from capture/locald/server
#[tauri::command]
pub async fn get_pipeline_counters(
    supervisor_state: State<'_, SupervisorState>,
) -> Result<Option<PipelineCounters>, String> {
    let (run_dir, api_base_url) = {
        let mut supervisor = supervisor_state.inner.write().await;
        let status = supervisor.status().await;
        (
            status.run_dir.map(PathBuf::from),
            status.api_base_url,
        )
    };
    
    match run_dir {
        Some(run_dir) => {
            let fetcher = PipelineCounterFetcher::new(run_dir, api_base_url);
            Ok(Some(fetcher.fetch_all().await))
        }
        None => Ok(None),
    }
}

/// Prove that signals originated from captured segments (evidence chain)
#[tauri::command]
pub async fn prove_signal_origins(
    supervisor_state: State<'_, SupervisorState>,
) -> Result<Vec<SignalProvenanceProof>, String> {
    let (run_dir, api_base_url) = {
        let mut supervisor = supervisor_state.inner.write().await;
        let status = supervisor.status().await;
        (
            status.run_dir.map(PathBuf::from),
            status.api_base_url,
        )
    };
    
    match run_dir {
        Some(run_dir) => {
            prove_signal_provenance(&run_dir, &api_base_url).await
        }
        None => Err("No active run".to_string()),
    }
}

/// Register all mission commands with Tauri
/// Call this in main.rs setup
pub fn mission_commands() -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        // Mission profiles
        get_mission_profiles,
        get_mission_profiles_by_type,
        get_mission_profile,
        // Scenario packs
        get_scenario_packs,
        get_scenario_packs_by_category,
        get_scenario_pack,
        execute_scenario_pack,
        // Mission lifecycle
        start_mission,
        get_mission_readiness,
        get_mission_metrics,
        stop_mission,
        // Quality gates
        evaluate_quality_gates,
        get_quality_scoreboard,
        compare_runs,
        list_baseline_runs,
        // Baseline management
        mark_run_as_baseline,
        set_default_baseline,
        get_baselines,
        compare_against_baseline,
        // Real pipeline counters
        get_pipeline_counters,
        prove_signal_origins,
    ]
}

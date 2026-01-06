//! EDR Desktop Application - Tauri supervisor for Windows EDR stack
//!
//! This app:
//! - Launches and supervises capture, locald, and server processes
//! - Provides mission-first UI with time window controls
//! - Auto-stops after configured duration
//! - Handles admin/non-admin gracefully (limited telemetry mode)
//! - Writes Metrics v3.1 GROUNDED artifacts with health gates on completion
//! - Per-run telemetry structure: runs/<run_id>/{segments,logs,metrics}
//! - Readiness checks: admin, security log, sysmon, audit policy
//! - Scenario profiles with expected outcomes for validation testing
//! - 4-gate GROUNDED health validation: Telemetry, Extraction, Detection, Explainability

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod grounded_gates;
mod health_gates;
mod logging;
mod port;
mod scenario_profiles;
mod supervisor;

use grounded_gates::E2EVerificationResult;
use supervisor::{ProcessKind, RunConfig, StackStatus, SupervisorState, ReadinessCheck, RunHistoryEntry};
use scenario_profiles::{ScenarioProfile, ScenarioTier, get_all_scenarios, get_scenarios_by_tier, get_scenario_by_id};
use std::path::PathBuf;
use tauri::{Emitter, Manager, State};

// ============================================================================
// Tauri Commands
// ============================================================================

/// Start a mission run with the given configuration
#[tauri::command]
async fn start_run(
    state: State<'_, SupervisorState>,
    duration_minutes: u32,
    selected_playbooks: Option<Vec<String>>,
) -> Result<StackStatus, String> {
    let config = RunConfig {
        duration_minutes: if duration_minutes == 0 { 10 } else { duration_minutes },
        selected_playbooks,
    };

    let mut supervisor = state.inner.write().await;
    supervisor.start_run(config).await?;
    Ok(supervisor.status().await)
}

/// Stop all running processes
#[tauri::command]
async fn stop_all(state: State<'_, SupervisorState>) -> Result<StackStatus, String> {
    let mut supervisor = state.inner.write().await;
    supervisor.stop_all().await?;
    Ok(supervisor.status().await)
}

/// Get current stack status
#[tauri::command]
async fn get_status(state: State<'_, SupervisorState>) -> Result<StackStatus, String> {
    let mut supervisor = state.inner.write().await;
    Ok(supervisor.status().await)
}

/// Get the API base URL
#[tauri::command]
async fn get_api_base_url(state: State<'_, SupervisorState>) -> Result<String, String> {
    let supervisor = state.inner.read().await;
    Ok(supervisor.api_base_url())
}

/// Check if running as administrator
#[tauri::command]
async fn is_admin(state: State<'_, SupervisorState>) -> Result<bool, String> {
    let supervisor = state.inner.read().await;
    Ok(supervisor.is_admin())
}

/// Open the telemetry folder in system file browser
#[tauri::command]
async fn open_telemetry_folder(state: State<'_, SupervisorState>) -> Result<(), String> {
    let supervisor = state.inner.read().await;
    let path = supervisor.telemetry_root();

    std::process::Command::new("explorer")
        .arg(&path)
        .spawn()
        .map_err(|e| format!("Failed to open folder: {}", e))?;

    Ok(())
}

/// Open the logs folder
#[tauri::command]
async fn open_logs_folder(state: State<'_, SupervisorState>) -> Result<(), String> {
    let supervisor = state.inner.read().await;
    let path = supervisor.logs_folder();

    std::process::Command::new("explorer")
        .arg(&path)
        .spawn()
        .map_err(|e| format!("Failed to open folder: {}", e))?;

    Ok(())
}

/// Open the metrics folder
#[tauri::command]
async fn open_metrics_folder(state: State<'_, SupervisorState>) -> Result<(), String> {
    let supervisor = state.inner.read().await;
    let path = supervisor.metrics_folder();

    std::process::Command::new("explorer")
        .arg(&path)
        .spawn()
        .map_err(|e| format!("Failed to open folder: {}", e))?;

    Ok(())
}

/// Export current run metrics
#[tauri::command]
async fn export_metrics(
    state: State<'_, SupervisorState>,
    path: Option<String>,
) -> Result<String, String> {
    let supervisor = state.inner.read().await;

    let metrics_path = if let Some(p) = path {
        supervisor.export_metrics(PathBuf::from(p)).await?;
        PathBuf::from("exported")
    } else {
        supervisor.write_metrics().await?
    };

    Ok(metrics_path.display().to_string())
}

/// Read tail of a process log
#[tauri::command]
async fn read_log_tail(
    state: State<'_, SupervisorState>,
    process: String,
    lines: Option<usize>,
) -> Result<Vec<String>, String> {
    let supervisor = state.inner.read().await;

    let kind = match process.as_str() {
        "capture" => ProcessKind::Capture,
        "locald" => ProcessKind::Locald,
        "server" => ProcessKind::Server,
        _ => return Err(format!("Unknown process: {}", process)),
    };

    supervisor.read_log_tail(kind, lines.unwrap_or(100))
}

/// Get list of available playbooks
#[tauri::command]
async fn get_available_playbooks(state: State<'_, SupervisorState>) -> Result<Vec<String>, String> {
    let supervisor = state.inner.read().await;
    let playbooks_dir = supervisor
        .telemetry_root()
        .join("playbooks")
        .join("windows");

    if !playbooks_dir.exists() {
        return Ok(vec![]);
    }

    let playbooks: Vec<String> = std::fs::read_dir(playbooks_dir)
        .map_err(|e| format!("Failed to read playbooks: {}", e))?
        .filter_map(Result::ok)
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        })
        .filter_map(|e| {
            e.path()
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
        })
        .collect();

    Ok(playbooks)
}

/// Run a safe activity command for test detection generation
/// Only allows whitelisted executables for safety
#[tauri::command]
async fn run_activity_command(exe: String, args: Vec<String>) -> Result<String, String> {
    // Whitelist of allowed executables for activity generation
    let allowed_exes = [
        "powershell.exe",
        "schtasks.exe",
        "wmic.exe",
        "sc.exe",
        "certutil.exe",
        "reg.exe",
        "net.exe",
        "nltest.exe",
        "whoami.exe",
        "hostname.exe",
    ];

    let exe_lower = exe.to_lowercase();
    let exe_name = std::path::Path::new(&exe_lower)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&exe_lower);

    if !allowed_exes.contains(&exe_name) {
        return Err(format!("Executable '{}' not in whitelist for activity generation", exe));
    }

    tracing::info!("Running activity command: {} {:?}", exe, args);

    let output = std::process::Command::new(&exe)
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", exe, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        Ok(stdout.to_string())
    } else {
        // Still return success for activity generation purposes - the command ran
        // and generated telemetry even if it returned non-zero
        Ok(format!("Command completed (exit {}): {} {}", 
            output.status.code().unwrap_or(-1),
            stdout, stderr))
    }
}

// ============================================================================
// Readiness & Run History Commands (Agent-READINESS / Agent-METRICS)
// ============================================================================

/// Get system readiness check results
#[tauri::command]
async fn get_readiness(state: State<'_, SupervisorState>) -> Result<ReadinessCheck, String> {
    let supervisor = state.inner.read().await;
    Ok(supervisor.get_readiness())
}

/// List all previous runs with their metrics
#[tauri::command]
async fn list_runs(state: State<'_, SupervisorState>) -> Result<Vec<RunHistoryEntry>, String> {
    let supervisor = state.inner.read().await;
    supervisor.list_runs()
}

/// Get detailed metrics for a specific run
#[tauri::command]
async fn get_run_metrics(
    state: State<'_, SupervisorState>,
    run_id: String,
) -> Result<serde_json::Value, String> {
    let supervisor = state.inner.read().await;
    supervisor.get_run_metrics(&run_id)
}

/// Open a specific run folder in explorer
#[tauri::command]
async fn open_run_folder(
    state: State<'_, SupervisorState>,
    run_id: String,
) -> Result<(), String> {
    let supervisor = state.inner.read().await;
    supervisor.open_run_folder(&run_id)
}

/// Get the current run directory (if a run is active)
#[tauri::command]
async fn get_current_run_dir(state: State<'_, SupervisorState>) -> Result<Option<String>, String> {
    let supervisor = state.inner.read().await;
    Ok(supervisor.current_run_dir().map(|p| p.display().to_string()))
}

/// Apply an advanced telemetry fix (requires admin)
#[tauri::command]
async fn apply_telemetry_fix(fix_id: String) -> Result<String, String> {
    tracing::info!("Applying telemetry fix: {}", fix_id);
    
    let (cmd, args): (&str, Vec<&str>) = match fix_id.as_str() {
        "enable_cmdline" => (
            "reg",
            vec!["add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit", 
                 "/v", "ProcessCreationIncludeCmdLine_Enabled", "/t", "REG_DWORD", "/d", "1", "/f"]
        ),
        "enable_ps_logging" => (
            "reg",
            vec!["add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
                 "/v", "EnableScriptBlockLogging", "/t", "REG_DWORD", "/d", "1", "/f"]
        ),
        "enable_process_audit" => (
            "auditpol",
            vec!["/set", "/subcategory:Process Creation", "/success:enable", "/failure:enable"]
        ),
        "enable_logon_audit" => (
            "auditpol",
            vec!["/set", "/subcategory:Logon", "/success:enable", "/failure:enable"]
        ),
        _ => return Err(format!("Unknown fix ID: {}", fix_id)),
    };
    
    let output = std::process::Command::new(cmd)
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;
    
    if output.status.success() {
        Ok(format!("Successfully applied fix: {}", fix_id))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to apply fix: {}", stderr))
    }
}

// ============================================================================
// GROUNDED Health Gates Commands (Agent-ORCH)
// ============================================================================

/// Get grounded health gates (computed from disk artifacts + API, NOT memory)
#[tauri::command]
async fn get_grounded_health_gates(
    state: State<'_, SupervisorState>,
) -> Result<serde_json::Value, String> {
    let supervisor = state.inner.read().await;
    let gates = supervisor.get_grounded_health_gates().await?;
    Ok(gates.to_metrics_json())
}

/// Run E2E verification of grounded gates
#[tauri::command]
async fn verify_grounded_gates(
    state: State<'_, SupervisorState>,
) -> Result<E2EVerificationResult, String> {
    let supervisor = state.inner.read().await;
    supervisor.verify_grounded_gates().await
}

/// Get grounded gates summary (one-liner for status bar)
#[tauri::command]
async fn get_grounded_gates_summary(
    state: State<'_, SupervisorState>,
) -> Result<String, String> {
    let supervisor = state.inner.read().await;
    let gates = supervisor.get_grounded_health_gates().await?;
    Ok(gates.summary())
}

// ============================================================================
// Scenario Profile Commands (Agent-SCENARIOS)
// ============================================================================

/// Get all available scenario profiles
#[tauri::command]
async fn get_scenarios() -> Result<Vec<ScenarioProfile>, String> {
    Ok(get_all_scenarios())
}

/// Get scenarios by tier (A, B, or C)
#[tauri::command]
async fn get_scenarios_for_tier(tier: String) -> Result<Vec<ScenarioProfile>, String> {
    let scenario_tier = match tier.to_uppercase().as_str() {
        "A" => ScenarioTier::A,
        "B" => ScenarioTier::B,
        "C" => ScenarioTier::C,
        _ => return Err(format!("Invalid tier: {}. Use A, B, or C.", tier)),
    };
    Ok(get_scenarios_by_tier(scenario_tier))
}

/// Get a specific scenario by ID
#[tauri::command]
async fn get_scenario(scenario_id: String) -> Result<ScenarioProfile, String> {
    get_scenario_by_id(&scenario_id)
        .ok_or_else(|| format!("Scenario not found: {}", scenario_id))
}

/// Run a scenario's commands (for activity generation)
#[tauri::command]
async fn run_scenario(
    state: State<'_, SupervisorState>,
    scenario_id: String,
) -> Result<Vec<scenario_profiles::StepResult>, String> {
    let scenario = get_scenario_by_id(&scenario_id)
        .ok_or_else(|| format!("Scenario not found: {}", scenario_id))?;
    
    // Check capabilities
    let readiness = {
        let supervisor = state.inner.read().await;
        supervisor.get_readiness()
    };
    
    let missing = scenario_profiles::check_scenario_capabilities(
        &scenario,
        readiness.is_admin,
        readiness.sysmon_installed,
        readiness.audit_policy_state.process_creation,
        readiness.powershell_logging_enabled,
    );
    
    if !missing.is_empty() {
        tracing::warn!("Scenario {} has missing capabilities: {:?}", scenario_id, missing);
    }
    
    // Execute scenario steps
    let mut results = Vec::new();
    
    for step in &scenario.steps {
        let start = std::time::Instant::now();
        
        tracing::info!("Executing scenario step: {} - {} {:?}", step.name, step.exe, step.args);
        
        let output = std::process::Command::new(&step.exe)
            .args(&step.args)
            .output();
        
        let duration_ms = start.elapsed().as_millis() as u64;
        
        let result = match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                
                scenario_profiles::StepResult {
                    step_name: step.name.clone(),
                    success: out.status.success(),
                    output: if stdout.is_empty() { None } else { Some(stdout) },
                    error: if stderr.is_empty() || out.status.success() { None } else { Some(stderr) },
                    duration_ms,
                }
            }
            Err(e) => scenario_profiles::StepResult {
                step_name: step.name.clone(),
                success: false,
                output: None,
                error: Some(format!("Failed to execute: {}", e)),
                duration_ms,
            },
        };
        
        results.push(result);
        
        // Small delay between steps for telemetry capture
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    
    Ok(results)
}

/// Check which capabilities are available for a scenario
#[tauri::command]
async fn check_scenario_capabilities(
    state: State<'_, SupervisorState>,
    scenario_id: String,
) -> Result<Vec<String>, String> {
    let scenario = get_scenario_by_id(&scenario_id)
        .ok_or_else(|| format!("Scenario not found: {}", scenario_id))?;
    
    let readiness = {
        let supervisor = state.inner.read().await;
        supervisor.get_readiness()
    };
    
    Ok(scenario_profiles::check_scenario_capabilities(
        &scenario,
        readiness.is_admin,
        readiness.sysmon_installed,
        readiness.audit_policy_state.process_creation,
        readiness.powershell_logging_enabled,
    ))
}

// ============================================================================
// Main Entry Point
// ============================================================================

fn main() {
    // Initialize logging
    let _guard = logging::init_logging();

    tracing::info!("EDR Desktop starting...");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            let app_handle = app.handle().clone();

            // Initialize supervisor state
            tauri::async_runtime::spawn(async move {
                match SupervisorState::new().await {
                    Ok(state) => {
                        // Initialize directories
                        {
                            let supervisor = state.inner.read().await;
                            if let Err(e) = supervisor.init_directories() {
                                tracing::warn!("Failed to initialize directories: {}", e);
                            }
                        }

                        let is_admin = {
                            let supervisor = state.inner.read().await;
                            supervisor.is_admin()
                        };

                        tracing::info!(
                            "Supervisor initialized (admin: {})",
                            is_admin
                        );

                        // Store state
                        app_handle.manage(state);

                        // UI is loaded directly from index.html via tauri.conf.json
                        tracing::info!("Supervisor state registered, UI ready");
                    }
                    Err(e) => {
                        tracing::error!("Failed to initialize supervisor: {}", e);
                        show_error_dialog(
                            &app_handle,
                            &format!(
                                "Failed to initialize EDR Desktop:\n\n{}\n\n\
                                Please ensure the application has proper permissions.",
                                e
                            ),
                        );
                    }
                }
            });

            // Spawn auto-stop checker (checks every 5 seconds)
            let app_handle_checker = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                    if let Some(state) = app_handle_checker.try_state::<SupervisorState>() {
                        let mut supervisor = state.inner.write().await;
                        if supervisor.check_auto_stop().await {
                            tracing::info!("Auto-stop triggered, run complete");
                            // Emit event to UI
                            let _ = app_handle_checker.emit("run-complete", ());
                        }
                    }
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                tracing::info!("Window close requested, shutting down...");

                // Shutdown supervisor on window close
                if let Some(state) = window.try_state::<SupervisorState>() {
                    let supervisor = state.inner.clone();
                    tauri::async_runtime::block_on(async {
                        let mut sup = supervisor.write().await;
                        if let Err(e) = sup.stop_all().await {
                            tracing::error!("Error during shutdown: {}", e);
                        }
                    });
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            start_run,
            stop_all,
            get_status,
            get_api_base_url,
            is_admin,
            open_telemetry_folder,
            open_logs_folder,
            open_metrics_folder,
            export_metrics,
            read_log_tail,
            get_available_playbooks,
            run_activity_command,
            // Agent-READINESS commands
            get_readiness,
            apply_telemetry_fix,
            // Agent-METRICS / Run History commands
            list_runs,
            get_run_metrics,
            open_run_folder,
            get_current_run_dir,
            // Agent-ORCH: GROUNDED Health Gates commands
            get_grounded_health_gates,
            verify_grounded_gates,
            get_grounded_gates_summary,
            // Agent-SCENARIOS commands  
            get_scenarios,
            get_scenarios_for_tier,
            get_scenario,
            run_scenario,
            check_scenario_capabilities,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn show_error_dialog(app: &tauri::AppHandle, message: &str) {
    use tauri_plugin_dialog::DialogExt;
    app.dialog()
        .message(message)
        .title("EDR Desktop Error")
        .blocking_show();
}

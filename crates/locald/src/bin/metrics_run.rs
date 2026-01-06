//! metrics_run - Generate run metrics artifact for E2E verification
//!
//! Produces a JSON artifact with telemetry, process, API, and database metrics
//! used for repeatable verification of the EDR pipeline on Windows.

use chrono::Utc;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

/// Host information
#[derive(Debug, Serialize, Deserialize)]
pub struct HostInfo {
    pub computername: String,
    pub os: String,
    pub arch: String,
}

/// Process status
#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessStatus {
    pub pid: Option<u32>,
    pub start_time: Option<String>,
    pub exit_code: Option<i32>,
    pub running: bool,
}

/// All process statuses
#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessStatuses {
    pub capture: ProcessStatus,
    pub locald: ProcessStatus,
    pub server: ProcessStatus,
}

/// Telemetry file statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct TelemetryFiles {
    pub segments_count: usize,
    pub segments_bytes_total: u64,
    pub index_exists: bool,
    pub index_bytes: u64,
    pub newest_segment_mtime: Option<String>,
}

/// Database statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct DbStats {
    pub db_path_found: Option<String>,
    pub db_bytes: u64,
    pub signals_row_count: Option<i64>,
    pub signals_count_note: Option<String>,
}

/// API endpoint check result
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiCheck {
    pub endpoint: String,
    pub status: Option<u16>,
    pub latency_ms: u64,
    pub ok: bool,
    pub error: Option<String>,
}

/// Run summary
#[derive(Debug, Serialize, Deserialize)]
pub struct Summary {
    pub passed: bool,
    pub failures: Vec<String>,
    pub warnings: Vec<String>,
}

/// Complete metrics artifact
#[derive(Debug, Serialize, Deserialize)]
pub struct RunMetrics {
    pub run_id: String,
    pub collected_at: String,
    pub host: HostInfo,
    pub telemetry_root: String,
    pub processes: ProcessStatuses,
    pub telemetry_files: TelemetryFiles,
    pub db: DbStats,
    pub api: Vec<ApiCheck>,
    pub summary: Summary,
}

fn main() {
    let run_id = format!("run_{}", Utc::now().format("%Y%m%d_%H%M%S"));
    let collected_at = Utc::now().to_rfc3339();

    // Determine telemetry root
    let telemetry_root = env::var("EDR_TELEMETRY_ROOT").unwrap_or_else(|_| {
        if cfg!(target_os = "windows") {
            r"C:\ProgramData\edr".to_string()
        } else {
            "/var/lib/edr".to_string()
        }
    });

    // Ensure metrics directory exists
    let metrics_dir = Path::new(&telemetry_root).join("metrics");
    let _ = fs::create_dir_all(&metrics_dir);

    // Collect all metrics
    let host = collect_host_info();
    let processes = collect_process_statuses();
    let telemetry_files = collect_telemetry_files(&telemetry_root);
    let db = collect_db_stats(&telemetry_root);
    let api = check_all_endpoints();
    let summary = compute_summary(&telemetry_files, &db, &api);

    let metrics = RunMetrics {
        run_id: run_id.clone(),
        collected_at,
        host,
        telemetry_root: telemetry_root.clone(),
        processes,
        telemetry_files,
        db,
        api,
        summary,
    };

    // Write metrics artifact
    let metrics_path = metrics_dir.join(format!("{}.json", run_id));
    let json = serde_json::to_string_pretty(&metrics).expect("Failed to serialize metrics");
    fs::write(&metrics_path, &json).expect("Failed to write metrics artifact");

    // Print summary to stdout
    print_summary(&metrics, &metrics_path);
}

fn collect_host_info() -> HostInfo {
    let computername = env::var("COMPUTERNAME")
        .or_else(|_| hostname::get().map(|h| h.to_string_lossy().to_string()))
        .unwrap_or_else(|_| "unknown".to_string());

    HostInfo {
        computername,
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
    }
}

fn collect_process_statuses() -> ProcessStatuses {
    // We check if processes are running by name
    // This is a best-effort check since we don't have direct PIDs

    fn check_process(name: &str) -> ProcessStatus {
        #[cfg(target_os = "windows")]
        {
            // Use tasklist to check if process is running
            let output = Command::new("tasklist")
                .args(["/FI", &format!("IMAGENAME eq {}", name), "/NH"])
                .output();

            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let running = stdout.contains(name);

                    // Try to get PID from tasklist output
                    let pid = if running {
                        // Parse "capture_windows_ro... 1234 Console ..."
                        stdout.lines().find(|l| l.contains(name)).and_then(|line| {
                            line.split_whitespace()
                                .nth(1)
                                .and_then(|s| s.parse::<u32>().ok())
                        })
                    } else {
                        None
                    };

                    ProcessStatus {
                        pid,
                        start_time: None, // Would need WMI for accurate start time
                        exit_code: if running { None } else { Some(-1) },
                        running,
                    }
                }
                Err(_) => ProcessStatus {
                    pid: None,
                    start_time: None,
                    exit_code: None,
                    running: false,
                },
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Use pgrep on Unix
            let output = Command::new("pgrep").arg("-x").arg(name).output();

            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let pid = stdout.lines().next().and_then(|s| s.parse::<u32>().ok());
                    ProcessStatus {
                        pid,
                        start_time: None,
                        exit_code: if pid.is_some() { None } else { Some(-1) },
                        running: pid.is_some(),
                    }
                }
                Err(_) => ProcessStatus {
                    pid: None,
                    start_time: None,
                    exit_code: None,
                    running: false,
                },
            }
        }
    }

    ProcessStatuses {
        capture: check_process(if cfg!(target_os = "windows") {
            "capture_windows_rotating.exe"
        } else {
            "capture_windows_rotating"
        }),
        locald: check_process(if cfg!(target_os = "windows") {
            "edr-locald.exe"
        } else {
            "edr-locald"
        }),
        server: check_process(if cfg!(target_os = "windows") {
            "edr-server.exe"
        } else {
            "edr-server"
        }),
    }
}

fn collect_telemetry_files(telemetry_root: &str) -> TelemetryFiles {
    let segments_dir = Path::new(telemetry_root).join("segments");
    let index_path = Path::new(telemetry_root).join("index.json");

    // Count segments
    let mut segments_count = 0;
    let mut segments_bytes_total = 0u64;
    let mut newest_mtime: Option<std::time::SystemTime> = None;

    if segments_dir.exists() {
        if let Ok(entries) = fs::read_dir(&segments_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
                    segments_count += 1;
                    if let Ok(meta) = fs::metadata(&path) {
                        segments_bytes_total += meta.len();
                        if let Ok(mtime) = meta.modified() {
                            if newest_mtime.map(|n| mtime > n).unwrap_or(true) {
                                newest_mtime = Some(mtime);
                            }
                        }
                    }
                }
            }
        }
    }

    // Index stats
    let index_exists = index_path.exists();
    let index_bytes = if index_exists {
        fs::metadata(&index_path).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };

    // Format newest mtime
    let newest_segment_mtime = newest_mtime.map(|t| {
        chrono::DateTime::<Utc>::from(t)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    });

    TelemetryFiles {
        segments_count,
        segments_bytes_total,
        index_exists,
        index_bytes,
        newest_segment_mtime,
    }
}

fn collect_db_stats(telemetry_root: &str) -> DbStats {
    // Try workbench.db first (used by edr-server), fall back to analysis.db
    let workbench_path = Path::new(telemetry_root).join("workbench.db");
    let analysis_path = Path::new(telemetry_root).join("analysis.db");

    let db_path = if workbench_path.exists() {
        workbench_path
    } else if analysis_path.exists() {
        analysis_path
    } else {
        return DbStats {
            db_path_found: None,
            db_bytes: 0,
            signals_row_count: None,
            signals_count_note: Some(
                "Database file not found (checked workbench.db and analysis.db)".to_string(),
            ),
        };
    };

    let db_bytes = fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);

    // Try to count signals using rusqlite
    let signals_row_count = match Connection::open(&db_path) {
        Ok(conn) => conn
            .query_row("SELECT COUNT(*) FROM signals", [], |row| {
                row.get::<_, i64>(0)
            })
            .ok(),
        Err(_) => None,
    };

    let signals_count_note = if signals_row_count.is_none() {
        Some("Could not query signals table".to_string())
    } else {
        None
    };

    DbStats {
        db_path_found: Some(db_path.to_string_lossy().to_string()),
        db_bytes,
        signals_row_count,
        signals_count_note,
    }
}

fn check_all_endpoints() -> Vec<ApiCheck> {
    let base_url = env::var("EDR_API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    let endpoints = vec![
        ("/api/health", "GET /api/health"),
        ("/api/signals", "GET /api/signals"),
        ("/api/capabilities", "GET /api/capabilities"),
        ("/api/app/state", "GET /api/app/state"),
        ("/", "GET / (HTML)"),
    ];

    endpoints
        .into_iter()
        .map(|(path, name)| check_endpoint(&base_url, path, name))
        .collect()
}

fn check_endpoint(base_url: &str, path: &str, name: &str) -> ApiCheck {
    let url = format!("{}{}", base_url, path);
    let start = Instant::now();

    #[cfg(target_os = "windows")]
    let result = {
        // Use curl if available, fallback to PowerShell
        let curl_result = Command::new("curl")
            .args([
                "-s",
                "--max-time",
                "5",
                "-o",
                "NUL",
                "-w",
                "%{http_code}",
                &url,
            ])
            .output();

        match curl_result {
            Ok(output) if !output.stdout.is_empty() => {
                let status_str = String::from_utf8_lossy(&output.stdout);
                if let Ok(code) = status_str.trim().parse::<u16>() {
                    Ok(code)
                } else {
                    Err("Failed to parse curl status".to_string())
                }
            }
            _ => {
                // Fallback to PowerShell
                let ps_script = format!(
                    "try {{ $r = Invoke-WebRequest -Uri '{}' -TimeoutSec 5 -UseBasicParsing; $r.StatusCode }} catch {{ if ($_.Exception.Response) {{ [int]$_.Exception.Response.StatusCode }} else {{ 0 }} }}",
                    url
                );

                let ps_result = Command::new("powershell.exe")
                    .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
                    .output();

                match ps_result {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if let Ok(code) = stdout.parse::<u16>() {
                            if code > 0 {
                                Ok(code)
                            } else {
                                Err("Connection failed".to_string())
                            }
                        } else {
                            Err(format!("Unexpected response: {}", stdout))
                        }
                    }
                    Err(e) => Err(format!("PowerShell failed: {}", e)),
                }
            }
        }
    };

    #[cfg(not(target_os = "windows"))]
    let result = {
        let curl_result = Command::new("curl")
            .args([
                "-s",
                "--max-time",
                "5",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                &url,
            ])
            .output();

        match curl_result {
            Ok(output) => {
                let status_str = String::from_utf8_lossy(&output.stdout);
                if let Ok(code) = status_str.trim().parse::<u16>() {
                    Ok(code)
                } else {
                    Err("Failed to parse curl status".to_string())
                }
            }
            Err(e) => Err(format!("curl failed: {}", e)),
        }
    };

    let latency_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(status) => ApiCheck {
            endpoint: name.to_string(),
            status: Some(status),
            latency_ms,
            ok: (200..400).contains(&status),
            error: None,
        },
        Err(e) => ApiCheck {
            endpoint: name.to_string(),
            status: None,
            latency_ms,
            ok: false,
            error: Some(e),
        },
    }
}

fn compute_summary(telemetry: &TelemetryFiles, db: &DbStats, api: &[ApiCheck]) -> Summary {
    let mut failures = Vec::new();
    let mut warnings = Vec::new();

    // Check telemetry
    if telemetry.segments_count == 0 {
        failures.push("No telemetry segments found".to_string());
    }
    if !telemetry.index_exists {
        failures.push("index.json missing".to_string());
    }

    // Check DB
    if db.db_path_found.is_none() {
        warnings.push("Database not found (checked workbench.db and analysis.db)".to_string());
    }

    // Check API
    for check in api {
        if !check.ok {
            if check.endpoint.contains("health") || check.endpoint.contains("signals") {
                failures.push(format!("{}: failed", check.endpoint));
            } else {
                warnings.push(format!("{}: failed", check.endpoint));
            }
        }
    }

    Summary {
        passed: failures.is_empty(),
        failures,
        warnings,
    }
}

fn print_summary(metrics: &RunMetrics, artifact_path: &Path) {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                    EDR Run Metrics                           ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    println!("Run ID:        {}", metrics.run_id);
    println!("Collected:     {}", metrics.collected_at);
    println!(
        "Host:          {} ({}/{})",
        metrics.host.computername, metrics.host.os, metrics.host.arch
    );
    println!("Telemetry:     {}\n", metrics.telemetry_root);

    println!("─── Telemetry Files ─────────────────────────────────────────────");
    println!(
        "  Segments:       {} ({} bytes)",
        metrics.telemetry_files.segments_count, metrics.telemetry_files.segments_bytes_total
    );
    println!(
        "  Index exists:   {}",
        if metrics.telemetry_files.index_exists {
            "✓"
        } else {
            "✗"
        }
    );
    if let Some(mtime) = &metrics.telemetry_files.newest_segment_mtime {
        println!("  Newest mtime:   {}", mtime);
    }

    println!("\n─── Database ────────────────────────────────────────────────────");
    if let Some(path) = &metrics.db.db_path_found {
        println!("  Path:           {}", path);
        println!("  Size:           {} bytes", metrics.db.db_bytes);
        if let Some(count) = metrics.db.signals_row_count {
            println!("  Signals:        {}", count);
        } else if let Some(note) = &metrics.db.signals_count_note {
            println!("  Signals:        ({})", note);
        }
    } else {
        println!("  Path:           (not found)");
    }

    println!("\n─── API Endpoints ───────────────────────────────────────────────");
    for check in &metrics.api {
        let status_str = check
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "---".to_string());
        let icon = if check.ok { "✓" } else { "✗" };
        println!(
            "  {} {} [{}] {}ms",
            icon, check.endpoint, status_str, check.latency_ms
        );
    }

    println!("\n─── Summary ─────────────────────────────────────────────────────");
    if metrics.summary.passed {
        println!("  Result: PASS ✓");
    } else {
        println!("  Result: FAIL ✗");
        for f in &metrics.summary.failures {
            println!("    - {}", f);
        }
    }
    if !metrics.summary.warnings.is_empty() {
        println!("  Warnings:");
        for w in &metrics.summary.warnings {
            println!("    - {}", w);
        }
    }

    println!("\n─── Artifact ────────────────────────────────────────────────────");
    println!("  {}\n", artifact_path.display());
}

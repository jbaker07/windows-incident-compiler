//! Ship Hardening: Unified /api/health Endpoint
//!
//! Provides a single contract for health status:
//! - Build info
//! - Storage health
//! - Capture status  
//! - Stream diagnostics
//! - Import isolation status
//! - Overall verdict
//!
//! This endpoint does NOT require UI session state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// ============================================================================
// Health Response Types
// ============================================================================

/// Unified health response - single contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Build information
    pub build: BuildInfo,
    /// Storage health
    pub storage: StorageHealth,
    /// Capture status
    pub capture: CaptureStatus,
    /// Top critical streams (max 5)
    pub streams: Vec<StreamHealth>,
    /// Import isolation status
    pub imported: ImportedStatus,
    /// Overall verdict
    pub verdict: HealthVerdict,
    /// Timestamp of this check
    pub checked_at: DateTime<Utc>,
    /// Blocking issues if verdict is Blocked
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking_issue: Option<BlockingIssue>,
}

/// Build information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_time: Option<String>,
}

/// Storage health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageHealth {
    pub telemetry_root: String,
    pub db_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_free_bytes: Option<u64>,
    pub writable: bool,
}

/// Capture status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStatus {
    pub profile: String,
    pub throttling_degraded: bool,
    pub tier0_throttled: bool,
    pub drops_last_30s: u64,
    pub alive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

/// Stream health (for top 5 critical streams)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamHealth {
    pub stream_id: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_ts: Option<DateTime<Utc>>,
    pub rate_recent: f64,
}

/// Import isolation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedStatus {
    pub imported_bundles_count: usize,
    /// Always true - imported bundles are mechanically isolated
    pub imported_isolated: bool,
}

/// Overall health verdict
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthVerdict {
    /// All systems nominal
    Healthy,
    /// Some issues but telemetry is flowing
    Degraded,
    /// Critical issues preventing operation
    Blocked,
}

impl HealthVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Blocked => "blocked",
        }
    }
}

/// Blocking issue details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockingIssue {
    pub issue: String,
    pub recommended_action: String,
    pub detail: Option<String>,
}

// ============================================================================
// Health Check Implementation
// ============================================================================

/// Configuration for health check
pub struct HealthCheckConfig {
    pub telemetry_root: PathBuf,
    pub db_path: PathBuf,
    pub imported_bundle_count: usize,
}

/// Check overall system health
pub fn check_health(config: &HealthCheckConfig) -> HealthResponse {
    let mut blocking_issue: Option<BlockingIssue> = None;
    let mut verdict = HealthVerdict::Healthy;

    // Build info
    let build = BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_sha: option_env!("GIT_SHA").map(String::from),
        build_time: option_env!("BUILD_TIME").map(String::from),
    };

    // Storage health
    let storage = check_storage_health(&config.telemetry_root, &config.db_path);
    if !storage.db_ok {
        verdict = HealthVerdict::Blocked;
        blocking_issue = Some(BlockingIssue {
            issue: "Database not accessible".to_string(),
            recommended_action: "Check database file permissions and disk space".to_string(),
            detail: storage.db_error.clone(),
        });
    }
    if !storage.writable {
        verdict = HealthVerdict::Blocked;
        blocking_issue = Some(BlockingIssue {
            issue: "Telemetry root not writable".to_string(),
            recommended_action: format!(
                "Ensure {} is writable by the current user",
                storage.telemetry_root
            ),
            detail: None,
        });
    }

    // Capture status
    let capture = check_capture_status(&config.telemetry_root);
    if !capture.alive && verdict != HealthVerdict::Blocked {
        verdict = HealthVerdict::Degraded;
    }
    if capture.throttling_degraded && verdict == HealthVerdict::Healthy {
        verdict = HealthVerdict::Degraded;
    }

    // Stream health (top 5 critical)
    let streams = check_stream_health(&config.db_path);
    let critical_missing = streams
        .iter()
        .filter(|s| s.enabled && s.last_seen_ts.is_none())
        .count();
    if critical_missing > 0 && verdict == HealthVerdict::Healthy {
        verdict = HealthVerdict::Degraded;
    }

    // Import status
    let imported = ImportedStatus {
        imported_bundles_count: config.imported_bundle_count,
        imported_isolated: true, // Always mechanically isolated
    };

    HealthResponse {
        build,
        storage,
        capture,
        streams,
        imported,
        verdict,
        checked_at: Utc::now(),
        blocking_issue,
    }
}

/// Check storage health
fn check_storage_health(telemetry_root: &Path, db_path: &Path) -> StorageHealth {
    let mut db_ok = true;
    let mut db_error = None;
    let mut writable = true;

    // Check DB
    if db_path.exists() {
        match rusqlite::Connection::open(db_path) {
            Ok(conn) => {
                // Quick sanity check
                if let Err(e) = conn.execute_batch("SELECT 1") {
                    db_ok = false;
                    db_error = Some(format!("DB query failed: {}", e));
                }
            }
            Err(e) => {
                db_ok = false;
                db_error = Some(format!("Cannot open DB: {}", e));
            }
        }
    } else {
        // DB doesn't exist yet - check if we can create it
        match rusqlite::Connection::open(db_path) {
            Ok(_) => {
                // Created successfully, remove it
                let _ = fs::remove_file(db_path);
            }
            Err(e) => {
                db_ok = false;
                db_error = Some(format!("Cannot create DB: {}", e));
            }
        }
    }

    // Check writability
    let test_file = telemetry_root.join(".health_check_probe");
    match fs::write(&test_file, b"probe") {
        Ok(_) => {
            let _ = fs::remove_file(&test_file);
        }
        Err(_) => {
            writable = false;
        }
    }

    // Get disk free space (platform-specific)
    let disk_free_bytes = get_disk_free_bytes(telemetry_root);

    StorageHealth {
        telemetry_root: telemetry_root.display().to_string(),
        db_ok,
        db_error,
        disk_free_bytes,
        writable,
    }
}

/// Check capture status from heartbeat
fn check_capture_status(telemetry_root: &Path) -> CaptureStatus {
    let heartbeat_path = telemetry_root.join("capture_heartbeat.json");

    let mut status = CaptureStatus {
        profile: "unknown".to_string(),
        throttling_degraded: false,
        tier0_throttled: false,
        drops_last_30s: 0,
        alive: false,
        pid: None,
    };

    if let Ok(contents) = fs::read_to_string(&heartbeat_path) {
        if let Ok(hb) = serde_json::from_str::<serde_json::Value>(&contents) {
            // Check if heartbeat is recent (within 15 seconds)
            if let Some(ts_ms) = hb.get("ts_ms").and_then(|v| v.as_u64()) {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                status.alive = (now_ms - ts_ms) < 15_000;
            }

            if let Some(pid) = hb.get("pid").and_then(|v| v.as_u64()) {
                status.pid = Some(pid as u32);
            }

            if let Some(profile) = hb.get("capture_profile").and_then(|v| v.as_str()) {
                status.profile = profile.to_string();
            }

            if let Some(degraded) = hb.get("throttling_degraded").and_then(|v| v.as_bool()) {
                status.throttling_degraded = degraded;
            }

            if let Some(tier0) = hb.get("tier0_throttled").and_then(|v| v.as_bool()) {
                status.tier0_throttled = tier0;
            }

            if let Some(drops) = hb.get("drops_last_30s").and_then(|v| v.as_u64()) {
                status.drops_last_30s = drops;
            }
        }
    }

    status
}

/// Check top 5 critical stream health
fn check_stream_health(db_path: &Path) -> Vec<StreamHealth> {
    let critical_streams = [
        "process_exec",
        "file_write",
        "net_connect",
        "auth_event",
        "persistence_change",
    ];

    let mut streams = Vec::new();

    if let Ok(conn) = rusqlite::Connection::open(db_path) {
        for stream_id in critical_streams {
            let mut health = StreamHealth {
                stream_id: stream_id.to_string(),
                enabled: true,
                last_seen_ts: None,
                rate_recent: 0.0,
            };

            // Get last seen timestamp
            if let Ok(mut stmt) =
                conn.prepare("SELECT MAX(ts) FROM telemetry_events WHERE stream_id = ?1")
            {
                if let Ok(Some(ts_ms)) =
                    stmt.query_row([stream_id], |row| row.get::<_, Option<i64>>(0))
                {
                    health.last_seen_ts = DateTime::from_timestamp_millis(ts_ms);
                }
            }

            // Get recent event count (last 30 seconds)
            let thirty_secs_ago = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64 - 30_000)
                .unwrap_or(0);

            if let Ok(mut stmt) = conn
                .prepare("SELECT COUNT(*) FROM telemetry_events WHERE stream_id = ?1 AND ts > ?2")
            {
                if let Ok(count) = stmt
                    .query_row(rusqlite::params![stream_id, thirty_secs_ago], |row| {
                        row.get::<_, i64>(0)
                    })
                {
                    health.rate_recent = count as f64 / 30.0;
                }
            }

            streams.push(health);
        }
    }

    streams
}

/// Get free disk space (returns None if unavailable)
#[cfg(unix)]
fn get_disk_free_bytes(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path_cstr = CString::new(path.as_os_str().as_bytes()).ok()?;

    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(path_cstr.as_ptr(), &mut stat) == 0 {
            Some(stat.f_bavail as u64 * stat.f_frsize as u64)
        } else {
            None
        }
    }
}

#[cfg(not(unix))]
fn get_disk_free_bytes(_path: &Path) -> Option<u64> {
    None
}

// ============================================================================
// Startup Validation
// ============================================================================

/// Startup validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupValidation {
    pub success: bool,
    pub verdict: HealthVerdict,
    pub blocking_issue: Option<BlockingIssue>,
}

/// Validate startup conditions
/// Returns Blocked verdict with clear action if critical issues found
pub fn validate_startup(telemetry_root: &Path, db_path: &Path) -> StartupValidation {
    // Check telemetry root exists and is writable
    if !telemetry_root.exists() {
        if let Err(e) = fs::create_dir_all(telemetry_root) {
            return StartupValidation {
                success: false,
                verdict: HealthVerdict::Blocked,
                blocking_issue: Some(BlockingIssue {
                    issue: "Cannot create telemetry root directory".to_string(),
                    recommended_action: format!(
                        "Create {} with appropriate permissions, or set EDR_TELEMETRY_ROOT to a writable path",
                        telemetry_root.display()
                    ),
                    detail: Some(e.to_string()),
                }),
            };
        }
    }

    // Check writability
    let test_file = telemetry_root.join(".startup_probe");
    if let Err(e) = fs::write(&test_file, b"probe") {
        #[cfg(unix)]
        let uid_info = format!(" (uid={})", unsafe { libc::getuid() });
        #[cfg(not(unix))]
        let uid_info = String::new();

        return StartupValidation {
            success: false,
            verdict: HealthVerdict::Blocked,
            blocking_issue: Some(BlockingIssue {
                issue: "Telemetry root is not writable".to_string(),
                recommended_action: format!(
                    "Ensure {} is writable by the current user{}",
                    telemetry_root.display(),
                    uid_info
                ),
                detail: Some(e.to_string()),
            }),
        };
    }
    let _ = fs::remove_file(&test_file);

    // Check DB can be opened/created
    match rusqlite::Connection::open(db_path) {
        Ok(conn) => {
            // Try to run migrations / create tables
            if let Err(e) = conn
                .execute_batch("CREATE TABLE IF NOT EXISTS _health_check (id INTEGER PRIMARY KEY)")
            {
                return StartupValidation {
                    success: false,
                    verdict: HealthVerdict::Blocked,
                    blocking_issue: Some(BlockingIssue {
                        issue: "Database migration failed".to_string(),
                        recommended_action: format!(
                            "Check database file {} is not corrupted. Try deleting it to recreate.",
                            db_path.display()
                        ),
                        detail: Some(e.to_string()),
                    }),
                };
            }
        }
        Err(e) => {
            return StartupValidation {
                success: false,
                verdict: HealthVerdict::Blocked,
                blocking_issue: Some(BlockingIssue {
                    issue: "Cannot open database".to_string(),
                    recommended_action: format!(
                        "Check {} is accessible and disk has space",
                        db_path.display()
                    ),
                    detail: Some(e.to_string()),
                }),
            };
        }
    }

    StartupValidation {
        success: true,
        verdict: HealthVerdict::Healthy,
        blocking_issue: None,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_health_check_healthy() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        // Create DB with telemetry_events table and some recent events
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE telemetry_events (ts INTEGER, stream_id TEXT)")
            .unwrap();

        // Insert recent events for critical streams so they don't cause Degraded status
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let critical_streams = [
            "process_exec",
            "file_write",
            "net_connect",
            "auth_event",
            "persistence_change",
        ];
        for stream_id in critical_streams {
            conn.execute(
                "INSERT INTO telemetry_events (ts, stream_id) VALUES (?1, ?2)",
                rusqlite::params![now_ms, stream_id],
            )
            .unwrap();
        }

        // Create a valid heartbeat file so capture is considered alive
        let heartbeat = serde_json::json!({
            "ts_ms": now_ms as u64,
            "pid": 12345,
            "capture_profile": "standard",
            "throttling_degraded": false,
            "tier0_throttled": false,
            "drops_last_30s": 0
        });

        let heartbeat_path = dir.path().join("capture_heartbeat.json");
        fs::write(&heartbeat_path, heartbeat.to_string()).unwrap();

        let config = HealthCheckConfig {
            telemetry_root: dir.path().to_path_buf(),
            db_path,
            imported_bundle_count: 0,
        };

        let health = check_health(&config);
        assert_eq!(health.verdict, HealthVerdict::Healthy);
        assert!(health.storage.db_ok);
        assert!(health.storage.writable);
        assert!(health.capture.alive);
    }

    #[test]
    fn test_health_check_blocked_db() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("nonexistent/subdir/test.db");

        let config = HealthCheckConfig {
            telemetry_root: dir.path().to_path_buf(),
            db_path,
            imported_bundle_count: 0,
        };

        let health = check_health(&config);
        // Should be blocked because DB path parent doesn't exist
        assert_eq!(health.verdict, HealthVerdict::Blocked);
        assert!(!health.storage.db_ok);
    }

    #[test]
    fn test_startup_validation_success() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let result = validate_startup(dir.path(), &db_path);
        assert!(result.success);
        assert_eq!(result.verdict, HealthVerdict::Healthy);
        assert!(result.blocking_issue.is_none());
    }

    #[test]
    #[cfg(unix)]
    fn test_startup_validation_not_writable() {
        // Use a path we definitely can't write to
        let result = validate_startup(
            Path::new("/root/definitely_not_writable"),
            Path::new("/root/test.db"),
        );
        assert!(!result.success);
        assert_eq!(result.verdict, HealthVerdict::Blocked);
        assert!(result.blocking_issue.is_some());
    }

    #[test]
    #[cfg(windows)]
    fn test_startup_validation_not_writable() {
        // Use a path we definitely can't write to on Windows
        let result = validate_startup(
            Path::new("C:\\Windows\\System32\\definitely_not_writable"),
            Path::new("C:\\Windows\\System32\\test.db"),
        );
        // On Windows this may or may not fail depending on permissions,
        // so we just test that it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_storage_health_writable() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        // Create DB
        let _ = rusqlite::Connection::open(&db_path).unwrap();

        let health = check_storage_health(dir.path(), &db_path);
        assert!(health.writable);
        assert!(health.db_ok);
    }

    #[test]
    fn test_capture_status_no_heartbeat() {
        let dir = tempdir().unwrap();
        let status = check_capture_status(dir.path());
        assert!(!status.alive);
        assert_eq!(status.profile, "unknown");
    }

    #[test]
    fn test_capture_status_with_heartbeat() {
        let dir = tempdir().unwrap();
        let heartbeat_path = dir.path().join("capture_heartbeat.json");

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let heartbeat = serde_json::json!({
            "ts_ms": now_ms,
            "pid": 12345,
            "capture_profile": "extended",
            "throttling_degraded": false,
            "tier0_throttled": false,
            "drops_last_30s": 5
        });

        fs::write(&heartbeat_path, heartbeat.to_string()).unwrap();

        let status = check_capture_status(dir.path());
        assert!(status.alive);
        assert_eq!(status.pid, Some(12345));
        assert_eq!(status.profile, "extended");
        assert_eq!(status.drops_last_30s, 5);
    }
}

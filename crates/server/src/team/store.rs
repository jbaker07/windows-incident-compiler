//! Team Store Service
//!
//! Handles case store configuration, status, and locking.

use crate::services::types::LockOwnerInfo;
use std::path::{Path, PathBuf};

// ============================================================================
// Constants
// ============================================================================

/// Store schema version for forward compatibility
pub const CASE_STORE_SCHEMA_VERSION: &str = "1.1.0";

/// Lock heartbeat interval in seconds
pub const CASE_LOCK_HEARTBEAT_INTERVAL_SECS: u64 = 30;

// ============================================================================
// Store Resolution
// ============================================================================

/// Resolve case store directory from env or local config
pub fn resolve_case_store_dir() -> Option<PathBuf> {
    // Priority 1: Environment variable
    if let Ok(path) = std::env::var("LOCINT_CASE_STORE_DIR") {
        let p = PathBuf::from(path);
        if !p.as_os_str().is_empty() {
            return Some(p);
        }
    }
    None
}

/// Get store directory, checking both env and local config
pub fn get_store_dir(data_dir: &Path) -> Option<PathBuf> {
    // Check env first
    if let Some(p) = resolve_case_store_dir() {
        return Some(p);
    }

    // Check local config file
    let config_path = data_dir.join("team_config.json");
    if config_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&config_path) {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&contents) {
                if let Some(path) = config.get("store_path").and_then(|v| v.as_str()) {
                    return Some(PathBuf::from(path));
                }
            }
        }
    }

    None
}

/// Get store status
pub fn get_store_status(data_dir: &Path) -> serde_json::Value {
    let store_dir = get_store_dir(data_dir);

    match store_dir {
        Some(ref dir) if dir.exists() => {
            // Check if writable
            let writable = check_store_writable(dir);

            // Get store.json metadata
            let store_meta = read_store_meta(dir);

            // Count cases
            let cases_count = count_cases(dir);

            serde_json::json!({
                "configured": true,
                "available": true,
                "writable": writable,
                "store_path": dir.display().to_string(),
                "schema_version": store_meta.get("schema_version").and_then(|v| v.as_str()),
                "cases_count": cases_count,
                "source": if std::env::var("LOCINT_CASE_STORE_DIR").is_ok() { "env" } else { "config" }
            })
        }
        Some(ref dir) => {
            serde_json::json!({
                "configured": true,
                "available": false,
                "writable": false,
                "store_path": dir.display().to_string(),
                "reason": "Store directory does not exist or is unreachable",
                "source": if std::env::var("LOCINT_CASE_STORE_DIR").is_ok() { "env" } else { "config" }
            })
        }
        None => {
            serde_json::json!({
                "configured": false,
                "available": false,
                "writable": false,
                "reason": "No case store configured. Set LOCINT_CASE_STORE_DIR or use /api/team/store/configure"
            })
        }
    }
}

/// Check if store is writable
fn check_store_writable(store_dir: &Path) -> bool {
    let test_path = store_dir.join(".write_test");
    match std::fs::write(&test_path, b"test") {
        Ok(_) => {
            let _ = std::fs::remove_file(&test_path);
            true
        }
        Err(_) => false,
    }
}

/// Read store.json metadata
fn read_store_meta(store_dir: &Path) -> serde_json::Value {
    let meta_path = store_dir.join("store.json");
    if meta_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&meta_path) {
            if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&contents) {
                return meta;
            }
        }
    }
    serde_json::json!({})
}

/// Count cases in store
fn count_cases(store_dir: &Path) -> usize {
    let cases_dir = store_dir.join("cases");
    if !cases_dir.exists() {
        return 0;
    }

    std::fs::read_dir(&cases_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .count()
        })
        .unwrap_or(0)
}

// ============================================================================
// Store Configuration
// ============================================================================

/// Configure case store path
pub fn configure_store(data_dir: &Path, store_path: &str) -> Result<serde_json::Value, String> {
    let path = PathBuf::from(store_path);

    // Validate path exists or can be created
    if !path.exists() {
        std::fs::create_dir_all(&path).map_err(|e| format!("Failed to create store directory: {}", e))?;
    }

    // Initialize store structure if needed
    initialize_store(&path)?;

    // Save to local config
    let config_path = data_dir.join("team_config.json");
    let config = serde_json::json!({
        "store_path": store_path,
        "configured_at": chrono::Utc::now().to_rfc3339()
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap())
        .map_err(|e| format!("Failed to save config: {}", e))?;

    Ok(serde_json::json!({
        "configured": true,
        "store_path": store_path,
        "message": "Case store configured successfully"
    }))
}

/// Initialize store directory structure
fn initialize_store(store_dir: &Path) -> Result<(), String> {
    // Create subdirectories
    std::fs::create_dir_all(store_dir.join("cases"))
        .map_err(|e| format!("Failed to create cases dir: {}", e))?;
    std::fs::create_dir_all(store_dir.join("locks"))
        .map_err(|e| format!("Failed to create locks dir: {}", e))?;
    std::fs::create_dir_all(store_dir.join("audit"))
        .map_err(|e| format!("Failed to create audit dir: {}", e))?;

    // Create store.json if it doesn't exist
    let meta_path = store_dir.join("store.json");
    if !meta_path.exists() {
        let meta = serde_json::json!({
            "schema_version": CASE_STORE_SCHEMA_VERSION,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "created_by": get_install_id_internal()
        });
        std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap())
            .map_err(|e| format!("Failed to create store.json: {}", e))?;
    }

    Ok(())
}

fn get_install_id_internal() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

// ============================================================================
// Path Safety
// ============================================================================

/// Safe path join for case store that prevents path traversal
pub fn safe_case_path_join(base: &Path, component: &str) -> Option<PathBuf> {
    // Reject obviously dangerous patterns
    if component.contains("..")
        || component.contains('/')
        || component.contains('\\')
        || component.contains('\0')
        || component.starts_with('.')
    {
        return None;
    }

    // Basic alphanumeric + underscore + hyphen only
    let is_safe = component
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.');

    if !is_safe || component.is_empty() {
        return None;
    }

    let joined = base.join(component);

    // Double-check canonical path is under base (only if base exists)
    if base.exists() {
        if let (Ok(canon_base), Ok(canon_joined)) = (base.canonicalize(), joined.canonicalize()) {
            if !canon_joined.starts_with(&canon_base) {
                return None;
            }
        }
    }

    Some(joined)
}

// ============================================================================
// Locking
// ============================================================================

/// Lock timeout in seconds
pub fn case_lock_timeout_secs() -> u64 {
    std::env::var("LOCINT_CASE_LOCK_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300) // 5 minutes default
}

/// Case store lock for atomic updates
#[derive(Debug)]
pub struct CaseStoreLock {
    pub lock_path: PathBuf,
    pub owner_info: LockOwnerInfo,
}

impl CaseStoreLock {
    /// Try to acquire lock with timeout for stale lock recovery
    pub fn try_acquire(
        store_dir: &Path,
        case_id: &str,
    ) -> Result<Self, (String, &'static str, Option<LockOwnerInfo>)> {
        let locks_dir = store_dir.join("locks");
        std::fs::create_dir_all(&locks_dir)
            .map_err(|e| (format!("Failed to create locks dir: {}", e), "LOCK_DIR_FAILED", None))?;

        let lock_file = format!("{}.lock", case_id);
        let lock_path = match safe_case_path_join(&locks_dir, &lock_file) {
            Some(p) => p,
            None => return Err(("Invalid case ID for lock".to_string(), "INVALID_CASE_ID", None)),
        };

        let timeout_secs = case_lock_timeout_secs();

        // Check for existing lock
        if lock_path.exists() {
            match std::fs::read_to_string(&lock_path) {
                Ok(content) => {
                    if let Ok(lock_info) = serde_json::from_str::<LockOwnerInfo>(&content) {
                        if let Ok(heartbeat_time) =
                            chrono::DateTime::parse_from_rfc3339(&lock_info.last_heartbeat_at)
                        {
                            let heartbeat_utc = heartbeat_time.with_timezone(&chrono::Utc);
                            let age = chrono::Utc::now().signed_duration_since(heartbeat_utc);

                            if age.num_seconds() > timeout_secs as i64 {
                                // Stale lock - safe to remove
                                let _ = std::fs::remove_file(&lock_path);
                            } else {
                                // Active lock
                                return Err((
                                    format!(
                                        "Case locked by {} (PID: {}) since {}",
                                        lock_info.host_name, lock_info.pid, lock_info.acquired_at
                                    ),
                                    "CASE_LOCKED",
                                    Some(lock_info),
                                ));
                            }
                        }
                    }
                }
                Err(_) => {
                    // Check file mtime for stale detection
                    if let Ok(meta) = std::fs::metadata(&lock_path) {
                        if let Ok(modified) = meta.modified() {
                            let age = std::time::SystemTime::now()
                                .duration_since(modified)
                                .unwrap_or_default();

                            if age.as_secs() > timeout_secs {
                                let _ = std::fs::remove_file(&lock_path);
                            } else {
                                return Err((
                                    "Case is locked by another process".to_string(),
                                    "CASE_LOCKED",
                                    None,
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Create new lock
        let now = chrono::Utc::now().to_rfc3339();
        let owner_info = LockOwnerInfo {
            install_id: get_install_id_internal(),
            host_name: std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "unknown".to_string()),
            pid: std::process::id(),
            acquired_at: now.clone(),
            last_heartbeat_at: now,
        };

        let lock_content = serde_json::to_string_pretty(&owner_info)
            .map_err(|e| (format!("Failed to serialize lock: {}", e), "LOCK_SERIALIZE_FAILED", None))?;

        // Use OpenOptions for exclusive creation
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    ("Case is locked by another process (race)".to_string(), "CASE_LOCKED", None)
                } else {
                    (format!("Failed to acquire lock: {}", e), "LOCK_ACQUIRE_FAILED", None)
                }
            })?;

        file.write_all(lock_content.as_bytes())
            .map_err(|e| (format!("Failed to write lock: {}", e), "LOCK_WRITE_FAILED", None))?;

        Ok(Self { lock_path, owner_info })
    }

    /// Update heartbeat timestamp
    pub fn heartbeat(&mut self) -> Result<(), String> {
        let now = chrono::Utc::now().to_rfc3339();
        self.owner_info.last_heartbeat_at = now;

        let lock_content = serde_json::to_string_pretty(&self.owner_info)
            .map_err(|e| format!("Failed to serialize lock: {}", e))?;

        std::fs::write(&self.lock_path, &lock_content)
            .map_err(|e| format!("Failed to update heartbeat: {}", e))?;

        Ok(())
    }
}

impl Drop for CaseStoreLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

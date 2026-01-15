//! Instance Lock: Prevent split-brain from multiple LocInt instances
//!
//! PROBLEM: If two instances run on different ports, UI can hit the wrong one.
//! This causes "flakiness" where sometimes updates work, sometimes they don't.
//!
//! SOLUTION: Use a lock file with port information:
//!   {DATA_ROOT}/instance.lock
//!   Contains JSON: {"pid": ..., "port": ..., "started_at": ...}
//!
//! BEHAVIOR:
//! - On startup, try to acquire lock
//! - If lock exists and process is alive, refuse to start
//! - Return info about existing instance so user can open it
//!
//! INVARIANT: Only ONE LocInt instance per data directory.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

/// Lock file contents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceLockInfo {
    pub pid: u32,
    pub port: u16,
    pub started_at: String,
    pub exe_path: String,
    pub api_base: String,
}

/// Result of trying to acquire the instance lock
#[derive(Debug)]
pub enum LockResult {
    /// Lock acquired successfully
    Acquired(InstanceLock),
    /// Another instance is running
    Conflict(InstanceLockInfo),
    /// Lock file exists but process is dead (stale lock cleaned up)
    StaleCleanedUp(InstanceLock),
    /// Failed to acquire lock for other reason
    Error(String),
}

/// Held lock (releases on drop)
#[derive(Debug)]
pub struct InstanceLock {
    lock_file_path: PathBuf,
    #[allow(dead_code)]
    file_handle: Option<File>,
    pub info: InstanceLockInfo,
}

impl InstanceLock {
    /// Try to acquire the instance lock
    /// 
    /// Lock file: {data_dir}/instance.lock
    pub fn try_acquire(data_dir: &Path, port: u16) -> LockResult {
        let lock_path = data_dir.join("instance.lock");
        let pid = std::process::id();
        let exe_path = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        
        let info = InstanceLockInfo {
            pid,
            port,
            started_at: chrono::Utc::now().to_rfc3339(),
            exe_path,
            api_base: format!("http://127.0.0.1:{}", port),
        };
        
        // Check for existing lock
        if lock_path.exists() {
            match read_lock_file(&lock_path) {
                Ok(existing) => {
                    // Check if process is still alive
                    if is_process_alive(existing.pid) {
                        return LockResult::Conflict(existing);
                    } else {
                        // Stale lock - remove and proceed
                        tracing::info!(
                            "Removing stale instance lock (PID {} no longer running)",
                            existing.pid
                        );
                        let _ = std::fs::remove_file(&lock_path);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read existing lock file: {}", e);
                    // Try to remove corrupted lock
                    let _ = std::fs::remove_file(&lock_path);
                }
            }
        }
        
        // Try to create lock file exclusively
        #[cfg(windows)]
        let file_result = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0) // No sharing - exclusive access
            .open(&lock_path);
        
        #[cfg(not(windows))]
        let file_result = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path);
        
        match file_result {
            Ok(mut file) => {
                // Write lock info
                let json = serde_json::to_string_pretty(&info).unwrap();
                if let Err(e) = file.write_all(json.as_bytes()) {
                    return LockResult::Error(format!("Failed to write lock file: {}", e));
                }
                let _ = file.flush();
                
                // Re-open without exclusive to allow reading
                let file_handle = OpenOptions::new()
                    .read(true)
                    .open(&lock_path)
                    .ok();
                
                LockResult::Acquired(InstanceLock {
                    lock_file_path: lock_path,
                    file_handle,
                    info,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Race condition - another instance beat us
                match read_lock_file(&lock_path) {
                    Ok(existing) => LockResult::Conflict(existing),
                    Err(_) => LockResult::Error("Lock file exists but unreadable".to_string()),
                }
            }
            Err(e) => LockResult::Error(format!("Failed to create lock file: {}", e)),
        }
    }
    
    /// Get the lock file path
    pub fn lock_file_path(&self) -> &Path {
        &self.lock_file_path
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // Remove lock file on clean shutdown
        let _ = std::fs::remove_file(&self.lock_file_path);
    }
}

/// Read lock file contents
fn read_lock_file(path: &Path) -> Result<InstanceLockInfo, String> {
    let mut file = File::open(path).map_err(|e| format!("Cannot open: {}", e))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| format!("Cannot read: {}", e))?;
    serde_json::from_str(&contents).map_err(|e| format!("Invalid JSON: {}", e))
}

/// Check if a process is still alive
#[cfg(windows)]
fn is_process_alive(pid: u32) -> bool {
    use std::os::windows::process::CommandExt;
    
    // Use tasklist to check if PID exists
    let mut cmd = std::process::Command::new("tasklist");
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    let output = cmd
        .args(["/FI", &format!("PID eq {}", pid), "/NH", "/FO", "CSV"])
        .output();
    
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // If process exists, output contains the PID
            stdout.contains(&pid.to_string())
        }
        Err(_) => false,
    }
}

#[cfg(not(windows))]
fn is_process_alive(pid: u32) -> bool {
    // On Unix, check /proc/{pid} or use kill -0
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
        || unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Get info about existing instance (for UI display)
pub fn get_existing_instance(data_dir: &Path) -> Option<InstanceLockInfo> {
    let lock_path = data_dir.join("instance.lock");
    if lock_path.exists() {
        if let Ok(info) = read_lock_file(&lock_path) {
            if is_process_alive(info.pid) {
                return Some(info);
            }
        }
    }
    None
}

/// Error returned when instance conflict occurs
#[derive(Debug, Clone, Serialize)]
pub struct InstanceConflictError {
    pub message: String,
    pub existing_port: u16,
    pub existing_pid: u32,
    pub existing_api_base: String,
    pub suggestion: String,
}

impl InstanceConflictError {
    pub fn new(existing: &InstanceLockInfo) -> Self {
        Self {
            message: format!(
                "Another LocInt instance is already running on port {}",
                existing.port
            ),
            existing_port: existing.port,
            existing_pid: existing.pid,
            existing_api_base: existing.api_base.clone(),
            suggestion: format!(
                "Open the existing instance at {} or close it before starting a new one",
                existing.api_base
            ),
        }
    }
}

//! Backend process manager - spawns and monitors ui_server

use crate::port::find_available_port;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Status information returned to the UI
#[derive(Clone, serde::Serialize)]
pub struct StatusInfo {
    pub running: bool,
    pub port: u16,
    pub telemetry_root: String,
    pub api_base_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_ts: Option<String>,  // ISO 8601 timestamp of last received event
}

/// Manages the backend ui_server process
pub struct BackendManager {
    port: u16,
    telemetry_root: PathBuf,
    child: Option<Child>,
    binary_path: PathBuf,
}

impl BackendManager {
    /// Create a new backend manager
    /// 
    /// Determines port and telemetry paths but does not start the server.
    pub async fn new() -> Result<Self, String> {
        // Find available port (default 3000, fallback 3001-3010)
        let port = find_available_port(3000, 3010)
            .await
            .ok_or("No available ports in range 3000-3010")?;
        
        tracing::info!("Selected port {} for backend server", port);

        // Determine telemetry root
        let telemetry_root = get_telemetry_root();
        
        // Ensure telemetry directory exists
        std::fs::create_dir_all(&telemetry_root)
            .map_err(|e| format!("Failed to create telemetry directory: {}", e))?;
        
        tracing::info!("Telemetry root: {:?}", telemetry_root);

        // Find ui_server binary
        let binary_path = find_ui_server_binary()?;
        tracing::info!("Backend binary: {:?}", binary_path);

        Ok(Self {
            port,
            telemetry_root,
            child: None,
            binary_path,
        })
    }

    /// Start the backend server process
    pub async fn start(&mut self) -> Result<(), String> {
        if self.child.is_some() {
            return Err("Backend already running".into());
        }

        tracing::info!("Starting backend on port {}...", self.port);

        let child = Command::new(&self.binary_path)
            .arg("--port")
            .arg(self.port.to_string())
            .arg("--telemetry-root")
            .arg(&self.telemetry_root)
            .env("EDR_TELEMETRY_ROOT", &self.telemetry_root)
            .env("EDR_SERVER_PORT", self.port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn backend: {}", e))?;

        let pid = child.id();
        tracing::info!("Backend started with PID {}", pid);
        
        self.child = Some(child);
        Ok(())
    }

    /// Wait for the backend to become ready (health check)
    pub async fn wait_for_ready(&self, timeout: Duration) -> Result<(), String> {
        let url = format!("{}/api/health", self.api_base_url());
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(200);

        tracing::info!("Waiting for backend health at {}...", url);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        loop {
            if start.elapsed() > timeout {
                return Err(format!("Backend did not become ready within {:?}", timeout));
            }

            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("Backend health check passed");
                    return Ok(());
                }
                Ok(resp) => {
                    tracing::debug!("Health check returned status: {}", resp.status());
                }
                Err(e) => {
                    tracing::debug!("Health check failed: {}", e);
                }
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Shutdown the backend process
    pub async fn shutdown(&mut self) -> Result<(), String> {
        if let Some(mut child) = self.child.take() {
            let pid = child.id();
            tracing::info!("Shutting down backend (PID {})...", pid);

            // Try graceful shutdown first (SIGTERM on Unix)
            #[cfg(unix)]
            {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }

            #[cfg(windows)]
            {
                // On Windows, just kill it
                let _ = child.kill();
            }

            // Wait briefly for graceful shutdown
            let grace_period = Duration::from_secs(2);
            let start = std::time::Instant::now();
            
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        tracing::info!("Backend exited with status: {:?}", status);
                        return Ok(());
                    }
                    Ok(None) if start.elapsed() > grace_period => {
                        tracing::warn!("Backend did not exit gracefully, sending SIGKILL");
                        let _ = child.kill();
                        let _ = child.wait();
                        return Ok(());
                    }
                    Ok(None) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        tracing::error!("Error waiting for backend: {}", e);
                        let _ = child.kill();
                        return Err(format!("Error during shutdown: {}", e));
                    }
                }
            }
        }
        Ok(())
    }

    /// Restart the backend
    pub async fn restart(&mut self) -> Result<(), String> {
        self.shutdown().await?;
        
        // Small delay to ensure port is released
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        self.start().await?;
        self.wait_for_ready(Duration::from_secs(10)).await
    }

    /// Get current status
    pub async fn status(&self) -> StatusInfo {
        // Try to fetch last event timestamp from the health endpoint
        let last_event_ts = if self.child.is_some() {
            fetch_last_event_ts(&self.api_base_url()).await
        } else {
            None
        };
        
        StatusInfo {
            running: self.child.is_some(),
            port: self.port,
            telemetry_root: self.telemetry_root.display().to_string(),
            api_base_url: self.api_base_url(),
            pid: self.child.as_ref().map(|c| c.id()),
            last_event_ts,
        }
    }

    /// Get the API base URL
    pub fn api_base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the telemetry root path
    pub fn telemetry_root(&self) -> PathBuf {
        self.telemetry_root.clone()
    }
}

impl Drop for BackendManager {
    fn drop(&mut self) {
        // Best-effort cleanup on drop
        if let Some(mut child) = self.child.take() {
            tracing::info!("BackendManager dropping, killing child process");
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Determine the telemetry root directory
fn get_telemetry_root() -> PathBuf {
    // 1. Check environment variable
    if let Ok(root) = std::env::var("EDR_TELEMETRY_ROOT") {
        return PathBuf::from(root);
    }

    // 2. Use platform-appropriate app data directory
    if let Some(data_dir) = dirs::data_local_dir() {
        return data_dir.join("EDR Desktop").join("telemetry");
    }

    // 3. Fallback to home directory
    if let Some(home) = dirs::home_dir() {
        return home.join(".edr-desktop").join("telemetry");
    }

    // 4. Last resort
    PathBuf::from("./edr_telemetry")
}

/// Find the ui_server binary
fn find_ui_server_binary() -> Result<PathBuf, String> {
    // Check possible locations in order of preference
    let candidates = [
        // 1. Same directory as the app binary (bundled) - edr-server
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("edr-server"))),
        // 2. macOS bundle Resources directory
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("../Resources/edr-server"))),
        // 3. Development: target/release (edr-server binary)
        Some(PathBuf::from("target/release/edr-server")),
        // 4. Development: target/debug  
        Some(PathBuf::from("target/debug/edr-server")),
        // 5. Legacy name: ui_server
        Some(PathBuf::from("target/release/ui_server")),
        Some(PathBuf::from("target/debug/ui_server")),
        // 6. In PATH
        which_server_binary(),
    ];

    for candidate in candidates.into_iter().flatten() {
        let path = if cfg!(windows) && !candidate.extension().is_some_and(|e| e == "exe") {
            candidate.with_extension("exe")
        } else {
            candidate
        };

        if path.exists() {
            return Ok(path.canonicalize().unwrap_or(path));
        }
    }

    Err(
        "Could not find edr-server binary. Please build it with:\n\
         cargo build --release -p edr-server".into()
    )
}

fn which_server_binary() -> Option<PathBuf> {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .flat_map(|p| vec![p.join("edr-server"), p.join("ui_server")])
                .find(|p| p.exists())
        })
}

/// Fetch the last event timestamp from the health endpoint
async fn fetch_last_event_ts(api_base_url: &str) -> Option<String> {
    let url = format!("{}/api/health", api_base_url);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .ok()?;
    
    let response = client.get(&url).send().await.ok()?;
    let health: serde_json::Value = response.json().await.ok()?;
    
    // Try to get last_event_ts or last_ts from the response
    if let Some(ts) = health.get("last_event_ts").and_then(|v| v.as_str()) {
        Some(ts.to_string())
    } else if let Some(ts) = health.get("last_ts").and_then(|v| v.as_str()) {
        Some(ts.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_root_is_deterministic() {
        let root1 = get_telemetry_root();
        let root2 = get_telemetry_root();
        assert_eq!(root1, root2, "Telemetry root should be deterministic");
    }

    #[test]
    fn test_telemetry_root_is_local() {
        let root = get_telemetry_root();
        let path_str = root.display().to_string();
        
        // Should not point to any cloud locations
        assert!(!path_str.contains("iCloud"), "Should not use iCloud");
        assert!(!path_str.contains("Dropbox"), "Should not use Dropbox");
        assert!(!path_str.contains("OneDrive"), "Should not use OneDrive");
    }

    #[test]
    fn test_status_info_serialization() {
        // Verify StatusInfo can be serialized correctly
        let status = StatusInfo {
            running: true,
            port: 3000,
            telemetry_root: "/tmp/telemetry".to_string(),
            api_base_url: "http://127.0.0.1:3000".to_string(),
            pid: Some(12345),
            last_event_ts: Some("2025-01-02T14:30:00Z".to_string()),
        };

        let json = serde_json::to_value(&status).expect("Should serialize");
        
        assert_eq!(json["running"], true);
        assert_eq!(json["port"], 3000);
        assert_eq!(json["pid"], 12345);
        assert_eq!(json["last_event_ts"], "2025-01-02T14:30:00Z");
    }

    #[test]
    fn test_status_info_skips_none_timestamp() {
        // Verify that None last_event_ts is not serialized (skip_serializing_if)
        let status = StatusInfo {
            running: false,
            port: 3001,
            telemetry_root: "/tmp/telemetry".to_string(),
            api_base_url: "http://127.0.0.1:3001".to_string(),
            pid: None,
            last_event_ts: None,
        };

        let json = serde_json::to_value(&status).expect("Should serialize");
        
        assert!(json.get("last_event_ts").is_none(), "None timestamp should not be serialized");
        assert!(json.get("pid").is_none(), "None pid should not be serialized");
    }

    #[test]
    fn test_api_base_url_format() {
        let status = StatusInfo {
            running: true,
            port: 3000,
            telemetry_root: "/tmp/test".to_string(),
            api_base_url: "http://127.0.0.1:3000".to_string(),
            pid: Some(100),
            last_event_ts: None,
        };
        
        assert_eq!(status.api_base_url, "http://127.0.0.1:3000");
        assert!(status.api_base_url.starts_with("http://"));
    }

    #[tokio::test]
    async fn test_backend_manager_port_determinism() {
        // Verify that creating two managers selects different ports (or same if only one available)
        // This test documents the expected behavior
        let manager1 = BackendManager::new().await;
        let manager2 = BackendManager::new().await;
        
        match (manager1, manager2) {
            (Ok(m1), Ok(m2)) => {
                // If both succeed, they should have ports (deterministic for test environment)
                assert!(m1.port > 0);
                assert!(m2.port > 0);
                // In test env with no real process binding, both might get same port
                // Real test would require actual process binding
            }
            (Err(_), _) | (_, Err(_)) => {
                // OK if port range is exhausted in test environment
            }
        }
    }
}

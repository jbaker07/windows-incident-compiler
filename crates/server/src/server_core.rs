//! Server Core: Shared infrastructure between edr-server and locint
//!
//! This module provides the common server setup used by both binaries,
//! ensuring identical routing and behavior. Only the entrypoint differs:
//! - edr-server: CLI with console output
//! - locint: Windows GUI with MessageBox errors
//!
//! INVARIANT: Both binaries use `build_app_router()` to construct routes.

use std::path::PathBuf;

/// Server startup configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Directory for data storage (workbench.db, runs/, etc.)
    pub data_dir: PathBuf,
    
    /// Directory containing UI files (index.html, app.js)
    pub ui_dir: PathBuf,
    
    /// Directory containing the executable (for diagnostics)
    pub exe_dir: PathBuf,
    
    /// HTTP port to listen on
    pub port: u16,
    
    /// Whether to auto-open browser on startup
    pub open_browser: bool,
}

impl ServerConfig {
    /// Create config for development (paths relative to CARGO_MANIFEST_DIR)
    pub fn for_development(port: u16, open_browser: bool) -> Self {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let project_root = manifest_dir
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        
        let ui_dir = project_root.join("ui");
        let exe_dir = project_root.join("target").join("debug"); // approximate for dev
        
        let data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("attack-workbench");
        
        Self {
            data_dir,
            ui_dir,
            exe_dir,
            port,
            open_browser,
        }
    }
    
    /// Create config with explicit paths (for locint exe-relative mode)
    pub fn with_paths(data_dir: PathBuf, ui_dir: PathBuf, exe_dir: PathBuf, port: u16, open_browser: bool) -> Self {
        Self {
            data_dir,
            ui_dir,
            exe_dir,
            port,
            open_browser,
        }
    }
}

/// Resource paths for shipped binaries (locint)
#[derive(Debug, Clone)]
pub struct ShippedResources {
    /// Directory containing the executable
    pub exe_dir: PathBuf,
    /// Path to UI directory
    pub ui_dir: PathBuf,
    /// Path to playbooks directory (may not exist - playbooks are optional)
    pub playbooks_dir: PathBuf,
    /// Path to capture binary
    pub capture_binary: PathBuf,
    /// Path to locald binary
    pub locald_binary: PathBuf,
}

impl ShippedResources {
    /// Resolve all paths relative to the current executable
    pub fn resolve() -> Result<Self, String> {
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Failed to get executable path: {}", e))?;
        
        let exe_dir = exe_path.parent()
            .ok_or("Failed to get executable directory")?
            .to_path_buf();
        
        #[cfg(target_os = "windows")]
        let (capture_name, locald_name) = ("capture_windows_rotating.exe", "edr-locald.exe");
        
        #[cfg(not(target_os = "windows"))]
        let (capture_name, locald_name) = ("capture_linux_rotating", "edr-locald");
        
        Ok(Self {
            ui_dir: exe_dir.join("ui"),
            playbooks_dir: exe_dir.join("playbooks").join("windows"),
            capture_binary: exe_dir.join(capture_name),
            locald_binary: exe_dir.join(locald_name),
            exe_dir,
        })
    }
    
    /// Validate that all required resources exist
    /// Returns list of missing resources (empty = all present)
    /// Note: Playbooks directory is NOT required - playbooks are optional
    pub fn validate(&self) -> Vec<String> {
        let mut missing = Vec::new();
        
        if !self.ui_dir.exists() {
            missing.push(format!("UI directory: {}", self.ui_dir.display()));
        } else if !self.ui_dir.join("index.html").exists() {
            missing.push(format!("UI index.html in: {}", self.ui_dir.display()));
        }
        
        // Playbooks are OPTIONAL - don't fail startup if missing
        // The /api/runs/:run_id/playbooks endpoint will report searched_paths
        // and not_found_reason if no playbooks are available
        
        if !self.capture_binary.exists() {
            missing.push(format!("Capture binary: {}", self.capture_binary.display()));
        }
        
        if !self.locald_binary.exists() {
            missing.push(format!("Locald binary: {}", self.locald_binary.display()));
        }
        
        missing
    }
    
    /// Check if playbooks are available
    pub fn has_playbooks(&self) -> bool {
        self.playbooks_dir.exists() && self.playbooks_dir.is_dir()
    }
    
    /// Build ServerConfig from shipped resources
    pub fn to_server_config(&self, port: u16) -> ServerConfig {
        let data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| self.exe_dir.clone())
            .join("attack-workbench");
        
        ServerConfig {
            data_dir,
            ui_dir: self.ui_dir.clone(),
            exe_dir: self.exe_dir.clone(),
            port,
            open_browser: true, // locint always opens browser
        }
    }
}

/// Errors that can occur during server startup
#[derive(Debug)]
pub enum StartupError {
    /// Required resources are missing
    MissingResources(Vec<String>),
    /// Port is already in use
    PortInUse { port: u16, error: String },
    /// Failed to create data directory
    DataDirCreation { path: PathBuf, error: String },
    /// Failed to open database
    DatabaseOpen { path: PathBuf, error: String },
    /// Failed to spawn child process
    ChildProcessSpawn { binary: PathBuf, error: String },
    /// Other startup failure
    Other(String),
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartupError::MissingResources(missing) => {
                writeln!(f, "Missing required files:")?;
                for item in missing {
                    writeln!(f, "  • {}", item)?;
                }
                writeln!(f)?;
                writeln!(f, "Expected shipped layout:")?;
                writeln!(f, "  LocInt/")?;
                writeln!(f, "    locint.exe")?;
                writeln!(f, "    edr-locald.exe")?;
                writeln!(f, "    capture_windows_rotating.exe")?;
                writeln!(f, "    ui/")?;
                writeln!(f, "    playbooks/windows/")
            }
            StartupError::PortInUse { port, error } => {
                writeln!(f, "Port {} is already in use.", port)?;
                writeln!(f)?;
                writeln!(f, "Another instance may be running.")?;
                writeln!(f, "Close it or use EDR_SERVER_PORT environment variable.")?;
                writeln!(f)?;
                writeln!(f, "Details: {}", error)
            }
            StartupError::DataDirCreation { path, error } => {
                writeln!(f, "Failed to create data directory:")?;
                writeln!(f, "  {}", path.display())?;
                writeln!(f)?;
                writeln!(f, "Error: {}", error)
            }
            StartupError::DatabaseOpen { path, error } => {
                writeln!(f, "Failed to open database:")?;
                writeln!(f, "  {}", path.display())?;
                writeln!(f)?;
                writeln!(f, "Error: {}", error)
            }
            StartupError::ChildProcessSpawn { binary, error } => {
                writeln!(f, "Failed to start process:")?;
                writeln!(f, "  {}", binary.display())?;
                writeln!(f)?;
                writeln!(f, "Error: {}", error)?;
                writeln!(f)?;
                writeln!(f, "Check that the file exists and is executable.")
            }
            StartupError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for StartupError {}

#[cfg(test)]
mod tests {
    use super::*;
    
    /// Compile-time verification that ServerConfig can be constructed
    #[test]
    fn server_config_construction() {
        let config = ServerConfig::for_development(3000, true);
        assert_eq!(config.port, 3000);
        assert!(config.open_browser);
    }
    
    /// Verify ShippedResources::resolve doesn't panic
    #[test]
    fn shipped_resources_resolve() {
        // This will work in test context (finds cargo test binary)
        let result = ShippedResources::resolve();
        assert!(result.is_ok());
    }
}

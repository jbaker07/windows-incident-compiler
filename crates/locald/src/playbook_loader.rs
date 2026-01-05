// locald/playbook_loader.rs
// Platform-scoped playbook loading for locald ingest daemon

use anyhow::Result;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Macos,
    Linux,
}

impl Platform {
    /// Detect current platform
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::Macos
        } else {
            Platform::Linux
        }
    }

    /// Playbook directory for this platform
    pub fn playbook_dir(&self) -> &'static str {
        match self {
            Platform::Windows => "playbooks/windows",
            Platform::Macos => "playbooks/macos",
            Platform::Linux => "playbooks/linux",
        }
    }
}

/// Load playbooks with platform awareness
pub fn load_playbook_paths(root: &Path) -> Result<Vec<PathBuf>> {
    // Check for override env var first
    if let Ok(override_dir) = env::var("EDR_PLAYBOOK_DIR") {
        let path = PathBuf::from(override_dir);
        if path.exists() && path.is_dir() {
            return Ok(vec![path]);
        }
    }

    // Default to platform-scoped directory
    let platform = Platform::current();
    let playbook_dir = root.join(platform.playbook_dir());

    if !playbook_dir.exists() {
        anyhow::bail!("Playbook directory not found: {:?}", playbook_dir);
    }

    // Collect all .yaml/.yml files in platform directory
    let mut playbooks = Vec::new();
    for entry in std::fs::read_dir(&playbook_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "yaml" || ext == "yml" {
                    playbooks.push(path);
                }
            }
        }
    }

    // Also load common playbooks
    let common_dir = root.join("playbooks/common");
    if common_dir.exists() {
        for entry in std::fs::read_dir(&common_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yaml" || ext == "yml" {
                        playbooks.push(path);
                    }
                }
            }
        }
    }

    playbooks.sort();
    Ok(playbooks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_playbook_dirs() {
        assert_eq!(Platform::Windows.playbook_dir(), "playbooks/windows");
        assert_eq!(Platform::Macos.playbook_dir(), "playbooks/macos");
        assert_eq!(Platform::Linux.playbook_dir(), "playbooks/linux");
    }

    #[test]
    fn test_current_platform() {
        let p = Platform::current();
        assert!(
            p == Platform::Windows || p == Platform::Macos || p == Platform::Linux,
            "Platform should be detected"
        );
    }
}

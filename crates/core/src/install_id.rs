//! Installation Identity Management
//!
//! Generates and persists a unique installation ID for license binding.
//! The install_id is a UUID v4 that anchors license verification to this specific installation.

use std::fs;
use std::path::PathBuf;

/// Get the EDR data directory path.
/// Windows: %PROGRAMDATA%\edr
/// Linux/macOS: /var/lib/edr (or ~/.local/share/edr for non-root)
pub fn get_edr_data_dir() -> PathBuf {
    if cfg!(windows) {
        std::env::var("PROGRAMDATA")
            .map(|p| PathBuf::from(p).join("edr"))
            .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\edr"))
    } else {
        // Check if running as root
        if std::env::var("USER").map(|u| u == "root").unwrap_or(false) {
            PathBuf::from("/var/lib/edr")
        } else {
            dirs::data_local_dir()
                .map(|p| p.join("edr"))
                .unwrap_or_else(|| PathBuf::from("/var/lib/edr"))
        }
    }
}

/// Get the path to the install_id file.
pub fn get_install_id_path() -> PathBuf {
    get_edr_data_dir().join("install_id")
}

/// Get the path to the license file.
pub fn get_license_path() -> PathBuf {
    get_edr_data_dir().join("license.json")
}

/// Get or create the installation ID.
///
/// On first run, generates a new UUID v4 and persists it.
/// On subsequent runs, reads the existing ID from disk.
///
/// Returns the installation ID as a string.
pub fn get_or_create_install_id() -> Result<String, String> {
    let path = get_install_id_path();

    // Try to read existing install_id
    if path.exists() {
        match fs::read_to_string(&path) {
            Ok(id) => {
                let id = id.trim().to_string();
                if !id.is_empty() && uuid::Uuid::parse_str(&id).is_ok() {
                    return Ok(id);
                }
                // Invalid format, regenerate
            }
            Err(_) => {
                // Read error, try to regenerate
            }
        }
    }

    // Generate new install_id
    let new_id = uuid::Uuid::new_v4().to_string();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create EDR data directory: {}", e))?;
    }

    // Write the new ID
    fs::write(&path, &new_id).map_err(|e| format!("Failed to write install_id: {}", e))?;

    Ok(new_id)
}

/// Read the installation ID without creating one.
/// Returns None if no install_id exists.
pub fn read_install_id() -> Option<String> {
    let path = get_install_id_path();
    fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && uuid::Uuid::parse_str(s).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_edr_data_dir() {
        let dir = get_edr_data_dir();
        assert!(dir.to_string_lossy().contains("edr"));
    }

    #[test]
    fn test_install_id_path() {
        let path = get_install_id_path();
        assert!(path.to_string_lossy().ends_with("install_id"));
    }

    #[test]
    fn test_license_path() {
        let path = get_license_path();
        assert!(path.to_string_lossy().ends_with("license.json"));
    }
}

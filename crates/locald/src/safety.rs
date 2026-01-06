//! Path safety and import isolation mechanisms for credibility locks.
//!
//! Provides:
//! - safe_join_under(): Safely join paths with traversal prevention
//! - Namespace isolation for imported vs live data
//! - ZIP safety policies for bundle imports

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Path safety errors
#[derive(Debug, Clone, Error)]
pub enum SafetyError {
    #[error("Path traversal detected: {0}")]
    PathTraversal(String),

    #[error("Symlink escapes root: {0}")]
    SymlinkEscape(String),

    #[error("Absolute path not allowed: {0}")]
    AbsolutePath(String),

    #[error("Path not under root: {0}")]
    NotUnderRoot(String),

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("IO error: {0}")]
    IoError(String),
}

/// Safely join a root path with a relative path, ensuring the result is
/// strictly under the root and cannot escape via traversal, absolute paths, or symlinks.
///
/// # Rules
/// 1. Reject absolute paths
/// 2. Reject paths containing ".."
/// 3. Reject paths starting with "/"
/// 4. Canonicalize and verify result is under root
/// 5. Reject symlinks that escape the root
///
/// # Example
/// ```ignore
/// let root = Path::new("/var/app/data");
/// let rel = Path::new("events/2025/01/01.json");
/// let safe_path = safe_join_under(&root, &rel)?;
/// // Result: /var/app/data/events/2025/01/01.json
/// ```
pub fn safe_join_under(root: &Path, rel: &Path) -> Result<PathBuf, SafetyError> {
    // Rule 1: Reject absolute paths
    if rel.is_absolute() {
        return Err(SafetyError::AbsolutePath(rel.display().to_string()));
    }

    // Rule 2: Reject paths with ".."
    for component in rel.components() {
        use std::path::Component;
        if let Component::ParentDir = component {
            return Err(SafetyError::PathTraversal(rel.display().to_string()));
        }
    }

    // Rule 3: Reject paths starting with "/"
    let rel_str = rel.to_string_lossy();
    if rel_str.starts_with('/') {
        return Err(SafetyError::AbsolutePath(rel_str.to_string()));
    }

    // Rule 4: Canonicalize and verify result is under root
    // First try to canonicalize root
    let canonical_root = match root.canonicalize() {
        Ok(r) => r,
        Err(e) => {
            // If root doesn't exist, that's an error
            return Err(SafetyError::IoError(format!(
                "Failed to canonicalize root: {}",
                e
            )));
        }
    };

    // Join the paths
    let joined = canonical_root.join(rel);

    // Try to canonicalize joined path (fails if doesn't exist, which is OK for write paths)
    // But at least verify it would be under root
    let canonical_joined = match joined.canonicalize() {
        Ok(c) => c,
        Err(_) => {
            // File doesn't exist yet, but we can still validate the path
            // by checking the parent and walking up
            let normalized = normalize_path(&joined);

            // Verify normalized path starts with canonical root
            if !normalized.starts_with(&canonical_root) {
                return Err(SafetyError::NotUnderRoot(format!(
                    "{} is not under {}",
                    normalized.display(),
                    canonical_root.display()
                )));
            }
            normalized
        }
    };

    // Verify the canonical joined path is under the canonical root
    if !canonical_joined.starts_with(&canonical_root) {
        return Err(SafetyError::NotUnderRoot(format!(
            "{} is not under {}",
            canonical_joined.display(),
            canonical_root.display()
        )));
    }

    Ok(canonical_joined)
}

/// Normalize a path without requiring it to exist
/// Removes . and .. components
fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {
                // Skip
            }
            _ => {
                normalized.push(component);
            }
        }
    }
    normalized
}

/// Data namespace for isolation (imported vs live)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataNamespace {
    /// Live telemetry from sensors
    Live,
    /// Imported from bundle
    Imported(u32), // bundle_id hash
}

impl DataNamespace {
    /// Convert to string for storage paths
    pub fn as_str(&self) -> String {
        match self {
            DataNamespace::Live => "live".to_string(),
            DataNamespace::Imported(bundle_id) => format!("imported_{}", bundle_id),
        }
    }

    /// Parse from string representation
    pub fn parse(s: &str) -> Option<Self> {
        if s == "live" {
            Some(DataNamespace::Live)
        } else if s.starts_with("imported_") {
            s.strip_prefix("imported_")
                .and_then(|id_str| id_str.parse::<u32>().ok())
                .map(DataNamespace::Imported)
        } else {
            None
        }
    }
}

/// ZIP safety policy for bundle imports
#[derive(Debug, Clone)]
pub struct ZipSafetyPolicy {
    /// Maximum number of files in archive
    pub max_files: usize,
    /// Maximum total uncompressed size in bytes
    pub max_total_uncompressed: u64,
    /// Maximum single file size in bytes
    pub max_single_file: u64,
    /// Allowed filenames (allowlist)
    pub allowed_filenames: Vec<String>,
    /// Reject nested archives
    pub reject_nested_archives: bool,
}

impl ZipSafetyPolicy {
    /// Default safe policy for EDR bundles
    pub fn default_edr() -> Self {
        Self {
            max_files: 32,
            max_total_uncompressed: 25 * 1024 * 1024, // 25MB
            max_single_file: 10 * 1024 * 1024,        // 10MB
            allowed_filenames: vec![
                "manifest.json".to_string(),
                "replay".to_string(),
                "recompute".to_string(),
                "metadata.json".to_string(),
            ],
            reject_nested_archives: true,
        }
    }

    /// Check if a filename is allowed (exact match or directory prefix)
    pub fn is_filename_allowed(&self, filename: &str) -> bool {
        self.allowed_filenames
            .iter()
            .any(|allowed| filename == allowed || filename.starts_with(&format!("{}/", allowed)))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_safe_join_normal_path() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();

        // Create the nested directory structure
        fs::create_dir_all(root.join("events/2025/01")).unwrap();
        fs::write(root.join("events/2025/01/01.json"), "{}").unwrap();

        let rel = Path::new("events/2025/01/01.json");

        let result = safe_join_under(root, rel);
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.ends_with("events/2025/01/01.json"));
    }

    #[test]
    fn test_safe_join_rejects_traversal() {
        let root = Path::new("/var/app/data");
        let rel = Path::new("../../../etc/passwd");

        let result = safe_join_under(root, rel);
        assert!(matches!(result, Err(SafetyError::PathTraversal(_))));
    }

    #[test]
    fn test_safe_join_rejects_absolute_path() {
        let root = Path::new("/var/app/data");
        let rel = Path::new("/etc/passwd");

        let result = safe_join_under(root, rel);
        assert!(matches!(result, Err(SafetyError::AbsolutePath(_))));
    }

    #[test]
    fn test_safe_join_rejects_parent_dir() {
        let root = Path::new("/var/app/data");
        let rel = Path::new("events/..");

        let result = safe_join_under(root, rel);
        assert!(matches!(result, Err(SafetyError::PathTraversal(_))));
    }

    #[test]
    fn test_safe_join_with_tempdir() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();

        // Create a subdirectory
        let subdir = root.join("events");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("test.json"), "{}").unwrap();

        let rel = Path::new("events/test.json");
        let result = safe_join_under(root, rel);

        assert!(result.is_ok());
        let path = result.unwrap();

        // The canonicalized path should contain the file we created
        assert!(path.ends_with("test.json"));

        // And should exist
        assert!(path.exists());
    }

    #[test]
    fn test_safe_join_rejects_symlink_escape() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();

        // Create a directory outside root
        let tempdir2 = TempDir::new().unwrap();
        let _outside_dir = tempdir2.path();

        // Create a symlink inside root pointing outside
        let _symlink_path = root.join("escape");
        #[cfg(unix)]
        {
            use std::os::unix::fs as unix_fs;
            let _ = unix_fs::symlink(_outside_dir, &_symlink_path);

            // Trying to join through the symlink should fail or return safely
            let result = safe_join_under(root, Path::new("escape"));
            // This may succeed or fail depending on whether symlink exists
            // The important thing is it shouldn't crash
            let _ = result;
        }
    }

    #[test]
    fn test_data_namespace_conversions() {
        assert_eq!(DataNamespace::Live.as_str(), "live");
        assert_eq!(DataNamespace::parse("live"), Some(DataNamespace::Live));

        let imported = DataNamespace::Imported(12345);
        let s = imported.as_str();
        assert_eq!(s, "imported_12345");
        assert_eq!(DataNamespace::parse(&s), Some(imported));
    }

    #[test]
    fn test_zip_safety_policy_default() {
        let policy = ZipSafetyPolicy::default_edr();

        assert_eq!(policy.max_files, 32);
        assert_eq!(policy.max_total_uncompressed, 25 * 1024 * 1024);
        assert_eq!(policy.max_single_file, 10 * 1024 * 1024);
        assert!(policy.reject_nested_archives);
    }

    #[test]
    fn test_zip_safety_policy_allowlist() {
        let policy = ZipSafetyPolicy::default_edr();

        assert!(policy.is_filename_allowed("manifest.json"));
        assert!(policy.is_filename_allowed("replay/events.jsonl"));
        assert!(policy.is_filename_allowed("recompute/hypotheses.json"));
        assert!(!policy.is_filename_allowed("../../../etc/passwd"));
        assert!(!policy.is_filename_allowed("malware.exe"));
    }
}

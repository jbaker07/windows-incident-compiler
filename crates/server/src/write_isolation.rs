//! Bundle Write Isolation: Ship Hardening for Imported Bundles
//!
//! Enforces write isolation for imported bundles:
//! - ALL writes must go under telemetry_root/imported/IMPORTED_<bundle_id>/
//! - Rejects any attempt to write outside the allowlisted path
//! - Validates paths before any file operation
//!
//! This module prevents imported bundles from polluting live data.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

// ============================================================================
// Constants
// ============================================================================

/// Directory name for imported bundles
const IMPORTED_DIR: &str = "imported";

/// Prefix for imported bundle directories
const BUNDLE_DIR_PREFIX: &str = "IMPORTED_";

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Error)]
pub enum WriteIsolationError {
    #[error("Write denied: path {path} is outside import sandbox (root: {sandbox_root})")]
    OutsideSandbox { path: String, sandbox_root: String },

    #[error("Invalid bundle_id format: {bundle_id}")]
    InvalidBundleId { bundle_id: String },

    #[error("Path traversal detected: {path}")]
    PathTraversal { path: String },

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Cannot create imported directory: {reason}")]
    DirectoryCreationFailed { reason: String },
}

// ============================================================================
// Write Isolation Context
// ============================================================================

/// Write isolation context for a specific imported bundle
pub struct WriteIsolationContext {
    /// Root telemetry directory
    #[allow(dead_code)]
    telemetry_root: PathBuf,
    /// Bundle ID
    bundle_id: String,
    /// Computed sandbox root: telemetry_root/imported/IMPORTED_<bundle_id>/
    sandbox_root: PathBuf,
}

impl WriteIsolationContext {
    /// Create a write isolation context for an imported bundle
    ///
    /// Returns error if bundle_id is invalid
    pub fn new(
        telemetry_root: impl AsRef<Path>,
        bundle_id: &str,
    ) -> Result<Self, WriteIsolationError> {
        let telemetry_root = telemetry_root.as_ref().to_path_buf();

        // Validate bundle_id format
        Self::validate_bundle_id(bundle_id)?;

        // Build sandbox path
        let sandbox_root = telemetry_root
            .join(IMPORTED_DIR)
            .join(format!("{}{}", BUNDLE_DIR_PREFIX, bundle_id));

        Ok(Self {
            telemetry_root,
            bundle_id: bundle_id.to_string(),
            sandbox_root,
        })
    }

    /// Validate bundle_id format (alphanumeric, dash, underscore only)
    fn validate_bundle_id(bundle_id: &str) -> Result<(), WriteIsolationError> {
        if bundle_id.is_empty() {
            return Err(WriteIsolationError::InvalidBundleId {
                bundle_id: bundle_id.to_string(),
            });
        }

        // Check for path traversal attempts
        if bundle_id.contains("..") || bundle_id.contains('/') || bundle_id.contains('\\') {
            return Err(WriteIsolationError::PathTraversal {
                path: bundle_id.to_string(),
            });
        }

        // Allow only safe characters
        for c in bundle_id.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                return Err(WriteIsolationError::InvalidBundleId {
                    bundle_id: bundle_id.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Get the sandbox root path
    pub fn sandbox_root(&self) -> &Path {
        &self.sandbox_root
    }

    /// Get the bundle ID
    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    /// Ensure the sandbox directory exists
    pub fn ensure_sandbox_dir(&self) -> Result<(), WriteIsolationError> {
        if !self.sandbox_root.exists() {
            fs::create_dir_all(&self.sandbox_root).map_err(|e| {
                WriteIsolationError::DirectoryCreationFailed {
                    reason: format!("Cannot create {}: {}", self.sandbox_root.display(), e),
                }
            })?;
        }
        Ok(())
    }

    /// Validate that a path is within the sandbox
    ///
    /// Returns the canonicalized path if valid, error otherwise
    pub fn validate_path(&self, relative_path: &str) -> Result<PathBuf, WriteIsolationError> {
        // Check for obvious traversal in the relative path
        if relative_path.contains("..") {
            return Err(WriteIsolationError::PathTraversal {
                path: relative_path.to_string(),
            });
        }

        // Check for absolute path
        let rel_path = Path::new(relative_path);
        if rel_path.is_absolute() {
            return Err(WriteIsolationError::OutsideSandbox {
                path: relative_path.to_string(),
                sandbox_root: self.sandbox_root.display().to_string(),
            });
        }

        // Build full path
        let full_path = self.sandbox_root.join(relative_path);

        // Canonicalize if possible (for existing paths)
        let canonical = if full_path.exists() {
            full_path.canonicalize()?
        } else {
            // For new files, canonicalize parent and join filename
            if let Some(parent) = full_path.parent() {
                if parent.exists() {
                    let canonical_parent = parent.canonicalize()?;
                    if let Some(filename) = full_path.file_name() {
                        canonical_parent.join(filename)
                    } else {
                        canonical_parent
                    }
                } else {
                    // Parent doesn't exist yet, ensure sandbox exists and try again
                    self.ensure_sandbox_dir()?;
                    fs::create_dir_all(parent)?;
                    let canonical_parent = parent.canonicalize()?;
                    if let Some(filename) = full_path.file_name() {
                        canonical_parent.join(filename)
                    } else {
                        canonical_parent
                    }
                }
            } else {
                full_path
            }
        };

        // Ensure sandbox_root exists for comparison
        self.ensure_sandbox_dir()?;
        let canonical_sandbox = self.sandbox_root.canonicalize()?;

        // Verify path is within sandbox
        if !canonical.starts_with(&canonical_sandbox) {
            return Err(WriteIsolationError::OutsideSandbox {
                path: canonical.display().to_string(),
                sandbox_root: canonical_sandbox.display().to_string(),
            });
        }

        Ok(canonical)
    }

    /// Write data to a file within the sandbox
    ///
    /// Returns error if path escapes sandbox
    pub fn write_file(
        &self,
        relative_path: &str,
        data: &[u8],
    ) -> Result<PathBuf, WriteIsolationError> {
        let path = self.validate_path(relative_path)?;

        // Ensure parent exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = fs::File::create(&path)?;
        file.write_all(data)?;

        Ok(path)
    }

    /// Create a directory within the sandbox
    pub fn create_dir(&self, relative_path: &str) -> Result<PathBuf, WriteIsolationError> {
        let path = self.validate_path(relative_path)?;
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// List files in the sandbox
    pub fn list_files(&self) -> Result<Vec<PathBuf>, WriteIsolationError> {
        self.ensure_sandbox_dir()?;

        let mut files = Vec::new();
        self.collect_files_recursive(&self.sandbox_root, &mut files)?;
        Ok(files)
    }

    fn collect_files_recursive(&self, dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    self.collect_files_recursive(&path, files)?;
                } else {
                    files.push(path);
                }
            }
        }
        Ok(())
    }

    /// Remove the entire sandbox directory (cleanup)
    pub fn remove_sandbox(&self) -> Result<(), WriteIsolationError> {
        if self.sandbox_root.exists() {
            fs::remove_dir_all(&self.sandbox_root)?;
        }
        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if a namespace/path looks like an imported bundle path
pub fn is_imported_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.contains("/imported/IMPORTED_") || path_str.contains("\\imported\\IMPORTED_")
}

/// Extract bundle_id from an imported path, if present
pub fn extract_bundle_id_from_path(path: &Path) -> Option<String> {
    let _path_str = path.to_string_lossy();

    // Look for IMPORTED_ prefix in path components
    for component in path.components() {
        if let std::path::Component::Normal(s) = component {
            let s_str = s.to_string_lossy();
            if let Some(bundle_id) = s_str.strip_prefix(BUNDLE_DIR_PREFIX) {
                return Some(bundle_id.to_string());
            }
        }
    }

    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_write_isolation_valid_bundle_id() {
        let dir = tempdir().unwrap();
        let ctx = WriteIsolationContext::new(dir.path(), "test-bundle-123").unwrap();

        assert_eq!(ctx.bundle_id(), "test-bundle-123");
        assert!(ctx
            .sandbox_root()
            .to_string_lossy()
            .contains("IMPORTED_test-bundle-123"));
    }

    #[test]
    fn test_write_isolation_invalid_bundle_id() {
        let dir = tempdir().unwrap();

        // Path traversal
        assert!(WriteIsolationContext::new(dir.path(), "../escape").is_err());
        assert!(WriteIsolationContext::new(dir.path(), "foo/../bar").is_err());

        // Invalid characters
        assert!(WriteIsolationContext::new(dir.path(), "foo<bar").is_err());
        assert!(WriteIsolationContext::new(dir.path(), "foo bar").is_err());

        // Empty
        assert!(WriteIsolationContext::new(dir.path(), "").is_err());
    }

    #[test]
    fn test_write_within_sandbox() {
        let dir = tempdir().unwrap();
        let ctx = WriteIsolationContext::new(dir.path(), "bundle-001").unwrap();

        // Write file
        let path = ctx.write_file("events.jsonl", b"test data").unwrap();
        assert!(path.exists());
        assert!(is_imported_path(&path));

        // Read back
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "test data");
    }

    #[test]
    fn test_write_in_subdir() {
        let dir = tempdir().unwrap();
        let ctx = WriteIsolationContext::new(dir.path(), "bundle-002").unwrap();

        // Write file in subdirectory
        let path = ctx.write_file("replay/report.json", b"{}").unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_path_escape_rejected() {
        let dir = tempdir().unwrap();
        let ctx = WriteIsolationContext::new(dir.path(), "bundle-003").unwrap();
        ctx.ensure_sandbox_dir().unwrap();

        // Attempt to escape
        assert!(ctx.validate_path("../escape.txt").is_err());
        assert!(ctx.validate_path("subdir/../../escape.txt").is_err());
    }

    #[test]
    fn test_absolute_path_rejected() {
        let dir = tempdir().unwrap();
        let ctx = WriteIsolationContext::new(dir.path(), "bundle-004").unwrap();

        assert!(ctx.validate_path("/etc/passwd").is_err());
    }

    #[test]
    fn test_list_files() {
        let dir = tempdir().unwrap();
        let ctx = WriteIsolationContext::new(dir.path(), "bundle-005").unwrap();

        // Write some files
        ctx.write_file("file1.txt", b"data1").unwrap();
        ctx.write_file("subdir/file2.txt", b"data2").unwrap();

        let files = ctx.list_files().unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_remove_sandbox() {
        let dir = tempdir().unwrap();
        let ctx = WriteIsolationContext::new(dir.path(), "bundle-006").unwrap();

        ctx.write_file("file.txt", b"data").unwrap();
        assert!(ctx.sandbox_root().exists());

        ctx.remove_sandbox().unwrap();
        assert!(!ctx.sandbox_root().exists());
    }

    #[test]
    fn test_extract_bundle_id() {
        let path = Path::new("/telemetry/imported/IMPORTED_bundle-123/events.jsonl");
        assert_eq!(
            extract_bundle_id_from_path(path),
            Some("bundle-123".to_string())
        );

        let path = Path::new("/telemetry/live/events.jsonl");
        assert_eq!(extract_bundle_id_from_path(path), None);
    }
}

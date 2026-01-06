//! Path Safety: Ship Hardening for Evidence Deref
//!
//! Prevents directory traversal attacks by validating that all file paths:
//! 1. Are relative (no absolute paths)
//! 2. Do not contain ".." components
//! 3. Stay within the telemetry_root boundary
//!
//! Returns ValidationError for any attempt to escape the sandbox.

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Path validation errors
#[derive(Debug, Clone, Error)]
pub enum PathValidationError {
    #[error("Absolute path not allowed: {path}")]
    AbsolutePathNotAllowed { path: String },

    #[error("Path traversal detected (..) in: {path}")]
    PathTraversalDetected { path: String },

    #[error("Path escapes telemetry root: {path} (root: {root})")]
    EscapesTelemetryRoot { path: String, root: String },

    #[error("Cannot canonicalize path: {path} ({reason})")]
    CanonicalizeError { path: String, reason: String },

    #[error("Invalid path component: {component}")]
    InvalidComponent { component: String },
}

/// Validate that a path component (segment_id, etc.) is safe
///
/// Returns ValidationError if:
/// - Component is empty
/// - Component contains path separator
/// - Component is "." or ".."
/// - Component contains null bytes
pub fn validate_path_component(component: &str) -> Result<(), PathValidationError> {
    if component.is_empty() {
        return Err(PathValidationError::InvalidComponent {
            component: "<empty>".to_string(),
        });
    }

    // Reject null bytes
    if component.contains('\0') {
        return Err(PathValidationError::InvalidComponent {
            component: component.to_string(),
        });
    }

    // Reject path separators
    if component.contains('/') || component.contains('\\') {
        return Err(PathValidationError::PathTraversalDetected {
            path: component.to_string(),
        });
    }

    // Reject . and ..
    if component == "." || component == ".." {
        return Err(PathValidationError::PathTraversalDetected {
            path: component.to_string(),
        });
    }

    // Reject if it looks like an absolute path on any OS
    if component.starts_with('/') || (component.len() >= 2 && component.chars().nth(1) == Some(':'))
    {
        return Err(PathValidationError::AbsolutePathNotAllowed {
            path: component.to_string(),
        });
    }

    Ok(())
}

/// Validate that a relative path is safe and stays within the telemetry root
///
/// Returns ValidationError if:
/// - Path is absolute
/// - Path contains ".." components
/// - Path escapes telemetry_root after canonicalization
pub fn validate_relative_path(relative_path: &str) -> Result<(), PathValidationError> {
    let path = Path::new(relative_path);

    // Check for absolute path
    if path.is_absolute() {
        return Err(PathValidationError::AbsolutePathNotAllowed {
            path: relative_path.to_string(),
        });
    }

    // Check each component for ".."
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(PathValidationError::PathTraversalDetected {
                    path: relative_path.to_string(),
                });
            }
            std::path::Component::Normal(s) => {
                if let Some(s_str) = s.to_str() {
                    validate_path_component(s_str)?;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

/// Validate that a full path stays within the telemetry root boundary
///
/// This is the main validation function that should be called before any file read.
/// It canonicalizes both paths and ensures the target path starts with the root.
pub fn validate_path_within_root(
    telemetry_root: &Path,
    target_path: &Path,
) -> Result<PathBuf, PathValidationError> {
    // Canonicalize the root (it must exist)
    let canonical_root =
        telemetry_root
            .canonicalize()
            .map_err(|e| PathValidationError::CanonicalizeError {
                path: telemetry_root.display().to_string(),
                reason: e.to_string(),
            })?;

    // For target, we need to handle the case where it doesn't exist yet
    // Use the parent directory + filename approach
    let canonical_target = if target_path.exists() {
        target_path
            .canonicalize()
            .map_err(|e| PathValidationError::CanonicalizeError {
                path: target_path.display().to_string(),
                reason: e.to_string(),
            })?
    } else {
        // File doesn't exist, canonicalize parent and join filename
        if let Some(parent) = target_path.parent() {
            let canonical_parent = if parent.as_os_str().is_empty() {
                // Empty parent means current directory
                std::env::current_dir().map_err(|e| PathValidationError::CanonicalizeError {
                    path: ".".to_string(),
                    reason: e.to_string(),
                })?
            } else if parent.exists() {
                parent
                    .canonicalize()
                    .map_err(|e| PathValidationError::CanonicalizeError {
                        path: parent.display().to_string(),
                        reason: e.to_string(),
                    })?
            } else {
                return Err(PathValidationError::CanonicalizeError {
                    path: parent.display().to_string(),
                    reason: "Parent directory does not exist".to_string(),
                });
            };

            if let Some(filename) = target_path.file_name() {
                canonical_parent.join(filename)
            } else {
                canonical_parent
            }
        } else {
            return Err(PathValidationError::CanonicalizeError {
                path: target_path.display().to_string(),
                reason: "No parent directory".to_string(),
            });
        }
    };

    // Check that target starts with root
    if !canonical_target.starts_with(&canonical_root) {
        return Err(PathValidationError::EscapesTelemetryRoot {
            path: canonical_target.display().to_string(),
            root: canonical_root.display().to_string(),
        });
    }

    Ok(canonical_target)
}

/// Safe path joiner that validates the component before joining
///
/// Use this instead of PathBuf::join when adding user-controlled segments
pub fn safe_join(base: &Path, component: &str) -> Result<PathBuf, PathValidationError> {
    validate_path_component(component)?;
    Ok(base.join(component))
}

/// Validate a segment_id for use in file paths
///
/// Segment IDs must be safe path components (no traversal, no absolute paths)
pub fn validate_segment_id(segment_id: &str) -> Result<(), PathValidationError> {
    validate_path_component(segment_id)?;

    // Additional check: segment_id should look like a reasonable ID
    // Allow alphanumeric, dash, underscore, dot (but not starting with dot)
    if segment_id.starts_with('.') {
        return Err(PathValidationError::InvalidComponent {
            component: segment_id.to_string(),
        });
    }

    // Check for suspicious patterns
    for c in segment_id.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.' {
            return Err(PathValidationError::InvalidComponent {
                component: segment_id.to_string(),
            });
        }
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_validate_path_component_valid() {
        assert!(validate_path_component("seg-001").is_ok());
        assert!(validate_path_component("stream_a").is_ok());
        assert!(validate_path_component("file.json").is_ok());
        assert!(validate_path_component("2024-01-15").is_ok());
    }

    #[test]
    fn test_validate_path_component_empty() {
        assert!(matches!(
            validate_path_component(""),
            Err(PathValidationError::InvalidComponent { .. })
        ));
    }

    #[test]
    fn test_validate_path_component_traversal() {
        assert!(matches!(
            validate_path_component(".."),
            Err(PathValidationError::PathTraversalDetected { .. })
        ));
        assert!(matches!(
            validate_path_component("."),
            Err(PathValidationError::PathTraversalDetected { .. })
        ));
    }

    #[test]
    fn test_validate_path_component_with_separator() {
        assert!(matches!(
            validate_path_component("foo/bar"),
            Err(PathValidationError::PathTraversalDetected { .. })
        ));
        assert!(matches!(
            validate_path_component("foo\\bar"),
            Err(PathValidationError::PathTraversalDetected { .. })
        ));
    }

    #[test]
    fn test_validate_path_component_absolute() {
        assert!(matches!(
            validate_path_component("/etc/passwd"),
            Err(PathValidationError::PathTraversalDetected { .. })
        ));
    }

    #[test]
    fn test_validate_relative_path_valid() {
        assert!(validate_relative_path("segments/seg-001").is_ok());
        assert!(validate_relative_path("seg-001").is_ok());
    }

    #[test]
    fn test_validate_relative_path_absolute() {
        // Use platform-appropriate absolute path
        #[cfg(unix)]
        assert!(matches!(
            validate_relative_path("/etc/passwd"),
            Err(PathValidationError::AbsolutePathNotAllowed { .. })
        ));
        #[cfg(windows)]
        assert!(matches!(
            validate_relative_path("C:\\Windows\\System32\\config"),
            Err(PathValidationError::AbsolutePathNotAllowed { .. })
        ));
    }

    #[test]
    fn test_validate_relative_path_traversal() {
        assert!(matches!(
            validate_relative_path("../etc/passwd"),
            Err(PathValidationError::PathTraversalDetected { .. })
        ));
        assert!(matches!(
            validate_relative_path("segments/../../../etc/passwd"),
            Err(PathValidationError::PathTraversalDetected { .. })
        ));
    }

    #[test]
    fn test_validate_path_within_root_valid() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Create a segment file
        let segment_dir = root.join("segments");
        fs::create_dir_all(&segment_dir).unwrap();
        let segment_file = segment_dir.join("seg-001");
        fs::write(&segment_file, "test").unwrap();

        let result = validate_path_within_root(root, &segment_file);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_within_root_escape() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("subdir");
        fs::create_dir_all(&root).unwrap();

        // Try to escape to parent
        let escape_path = dir.path().join("other_file");
        fs::write(&escape_path, "test").unwrap();

        let result = validate_path_within_root(&root, &escape_path);
        assert!(matches!(
            result,
            Err(PathValidationError::EscapesTelemetryRoot { .. })
        ));
    }

    #[test]
    fn test_safe_join_valid() {
        let base = Path::new("/tmp/telemetry");
        let result = safe_join(base, "seg-001").unwrap();
        assert_eq!(result, PathBuf::from("/tmp/telemetry/seg-001"));
    }

    #[test]
    fn test_safe_join_traversal() {
        let base = Path::new("/tmp/telemetry");
        assert!(safe_join(base, "..").is_err());
        assert!(safe_join(base, "../etc").is_err());
    }

    #[test]
    fn test_validate_segment_id_valid() {
        assert!(validate_segment_id("seg-001").is_ok());
        assert!(validate_segment_id("process_exec_2024-01-15").is_ok());
        assert!(validate_segment_id("segment.json").is_ok());
    }

    #[test]
    fn test_validate_segment_id_invalid() {
        // Hidden file
        assert!(validate_segment_id(".hidden").is_err());

        // Path traversal
        assert!(validate_segment_id("..").is_err());

        // Contains separator
        assert!(validate_segment_id("seg/001").is_err());

        // Contains invalid chars
        assert!(validate_segment_id("seg<>001").is_err());
    }
}

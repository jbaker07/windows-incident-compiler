//! Packs Service
//!
//! Handles content pack discovery and validation.
//! All business logic for playbook packs lives here.

use crate::services::types::PackValidation;
use std::io::Read;
use std::path::Path;

// ============================================================================
// Constants
// ============================================================================

/// Supported pack schema versions
pub const PACK_SCHEMA_VERSIONS: &[&str] = &["1.0.0", "1.1.0"];

// ============================================================================
// Pack Discovery
// ============================================================================

/// List available packs in a directory
pub fn list_packs(packs_dir: &Path) -> Vec<serde_json::Value> {
    let mut packs = Vec::new();

    if !packs_dir.exists() || !packs_dir.is_dir() {
        return packs;
    }

    if let Ok(entries) = std::fs::read_dir(packs_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let pack_dir = entry.path();
            if !pack_dir.is_dir() {
                continue;
            }

            let manifest_path = pack_dir.join("pack.json");
            if !manifest_path.exists() {
                continue;
            }

            if let Ok(contents) = std::fs::read_to_string(&manifest_path) {
                if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&contents) {
                    let pack_name = pack_dir
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();

                    let validation = validate_pack(&pack_dir, &manifest);
                    let playbook_count = count_playbooks(&pack_dir);

                    packs.push(serde_json::json!({
                        "name": pack_name,
                        "display_name": manifest.get("name").and_then(|v| v.as_str()).unwrap_or(&pack_name),
                        "description": manifest.get("description").and_then(|v| v.as_str()),
                        "version": manifest.get("version").and_then(|v| v.as_str()),
                        "schema_version": manifest.get("schema_version").and_then(|v| v.as_str()),
                        "author": manifest.get("author").and_then(|v| v.as_str()),
                        "playbook_count": playbook_count,
                        "valid": validation.valid,
                        "validation": {
                            "valid": validation.valid,
                            "reason_code": validation.reason_code,
                            "reason_message": validation.reason_message
                        },
                        "path": pack_dir.display().to_string()
                    }));
                }
            }
        }
    }

    packs
}

/// Get details of a specific pack
pub fn get_pack_details(packs_dir: &Path, pack_name: &str) -> Option<serde_json::Value> {
    // Validate pack name to prevent path traversal
    if pack_name.contains("..") || pack_name.contains('/') || pack_name.contains('\\') {
        return None;
    }

    let pack_dir = packs_dir.join(pack_name);
    if !pack_dir.exists() || !pack_dir.is_dir() {
        return None;
    }

    let manifest_path = pack_dir.join("pack.json");
    if !manifest_path.exists() {
        return None;
    }

    let contents = std::fs::read_to_string(&manifest_path).ok()?;
    let manifest: serde_json::Value = serde_json::from_str(&contents).ok()?;

    let validation = validate_pack(&pack_dir, &manifest);
    let playbooks = list_pack_playbooks(&pack_dir);

    Some(serde_json::json!({
        "name": pack_name,
        "display_name": manifest.get("name").and_then(|v| v.as_str()).unwrap_or(pack_name),
        "description": manifest.get("description").and_then(|v| v.as_str()),
        "version": manifest.get("version").and_then(|v| v.as_str()),
        "schema_version": manifest.get("schema_version").and_then(|v| v.as_str()),
        "author": manifest.get("author").and_then(|v| v.as_str()),
        "tags": manifest.get("tags"),
        "dependencies": manifest.get("dependencies"),
        "validation": {
            "valid": validation.valid,
            "reason_code": validation.reason_code,
            "reason_message": validation.reason_message
        },
        "playbooks": playbooks,
        "playbook_count": playbooks.len(),
        "path": pack_dir.display().to_string()
    }))
}

// ============================================================================
// Pack Validation
// ============================================================================

/// Validate a pack and return validation result
pub fn validate_pack(pack_dir: &Path, manifest: &serde_json::Value) -> PackValidation {
    // Check schema version
    let schema_version = manifest
        .get("schema_version")
        .and_then(|v| v.as_str())
        .unwrap_or("1.0.0");

    if !PACK_SCHEMA_VERSIONS.contains(&schema_version) {
        return PackValidation {
            valid: false,
            reason_code: Some("SCHEMA_UNSUPPORTED".to_string()),
            reason_message: Some(format!(
                "Pack schema version '{}' not supported. Supported: {:?}",
                schema_version, PACK_SCHEMA_VERSIONS
            )),
        };
    }

    // Check required fields
    if manifest.get("name").and_then(|v| v.as_str()).is_none() {
        return PackValidation {
            valid: false,
            reason_code: Some("MISSING_NAME".to_string()),
            reason_message: Some("Pack must have a 'name' field".to_string()),
        };
    }

    // Check playbooks directory exists
    let playbooks_dir = pack_dir.join("playbooks").join("windows");
    if !playbooks_dir.exists() {
        return PackValidation {
            valid: false,
            reason_code: Some("MISSING_PLAYBOOKS_DIR".to_string()),
            reason_message: Some("Pack must contain playbooks/windows/ directory".to_string()),
        };
    }

    // Count playbooks
    let playbook_count = count_playbooks(pack_dir);

    if playbook_count == 0 {
        return PackValidation {
            valid: false,
            reason_code: Some("NO_PLAYBOOKS".to_string()),
            reason_message: Some("Pack contains no playbook files (*.yaml/*.yml)".to_string()),
        };
    }

    // If pack has integrity field, verify it
    if let Some(integrity) = manifest.get("integrity") {
        if let Some(expected_hash) = integrity.get("playbooks_sha256").and_then(|v| v.as_str()) {
            let computed_hash = compute_playbooks_hash(&playbooks_dir);
            if computed_hash != expected_hash {
                return PackValidation {
                    valid: false,
                    reason_code: Some("INTEGRITY_MISMATCH".to_string()),
                    reason_message: Some(format!(
                        "Playbooks hash mismatch. Expected: {}, Got: {}",
                        expected_hash, computed_hash
                    )),
                };
            }
        }
    }

    PackValidation {
        valid: true,
        reason_code: None,
        reason_message: None,
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Count playbooks in a pack directory
fn count_playbooks(pack_dir: &Path) -> usize {
    let playbooks_dir = pack_dir.join("playbooks").join("windows");
    if !playbooks_dir.exists() {
        return 0;
    }

    std::fs::read_dir(&playbooks_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "yaml" || ext == "yml")
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

/// List playbooks in a pack
fn list_pack_playbooks(pack_dir: &Path) -> Vec<serde_json::Value> {
    let playbooks_dir = pack_dir.join("playbooks").join("windows");
    let mut playbooks = Vec::new();

    if !playbooks_dir.exists() {
        return playbooks;
    }

    if let Ok(entries) = std::fs::read_dir(&playbooks_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path
                .extension()
                .map(|ext| ext == "yaml" || ext == "yml")
                .unwrap_or(false)
            {
                continue;
            }

            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            // Try to read playbook metadata
            let metadata = read_playbook_metadata(&path);

            playbooks.push(serde_json::json!({
                "filename": filename,
                "name": metadata.get("name").and_then(|v| v.as_str()).unwrap_or(&filename),
                "description": metadata.get("description").and_then(|v| v.as_str()),
                "severity": metadata.get("severity").and_then(|v| v.as_str()),
                "mitre": metadata.get("mitre"),
                "tags": metadata.get("tags")
            }));
        }
    }

    playbooks
}

/// Read playbook metadata from YAML file
fn read_playbook_metadata(path: &Path) -> serde_json::Value {
    if let Ok(contents) = std::fs::read_to_string(path) {
        // Simple YAML front-matter extraction
        // Look for fields like: name:, description:, severity:, mitre:, tags:
        let mut metadata = serde_json::Map::new();

        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with("name:") {
                if let Some(value) = line.strip_prefix("name:") {
                    metadata.insert(
                        "name".to_string(),
                        serde_json::Value::String(value.trim().trim_matches('"').to_string()),
                    );
                }
            } else if line.starts_with("description:") {
                if let Some(value) = line.strip_prefix("description:") {
                    metadata.insert(
                        "description".to_string(),
                        serde_json::Value::String(value.trim().trim_matches('"').to_string()),
                    );
                }
            } else if line.starts_with("severity:") {
                if let Some(value) = line.strip_prefix("severity:") {
                    metadata.insert(
                        "severity".to_string(),
                        serde_json::Value::String(value.trim().trim_matches('"').to_string()),
                    );
                }
            }
        }

        return serde_json::Value::Object(metadata);
    }

    serde_json::json!({})
}

/// Compute SHA256 hash of all playbook files in a directory
pub fn compute_playbooks_hash(playbooks_dir: &Path) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    let mut files: Vec<_> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(playbooks_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .map(|ext| ext == "yaml" || ext == "yml")
                .unwrap_or(false)
            {
                files.push(path);
            }
        }
    }

    // Sort for deterministic hash
    files.sort();

    for file_path in files {
        // Include filename in hash
        if let Some(name) = file_path.file_name() {
            hasher.update(name.to_string_lossy().as_bytes());
        }
        // Include file contents
        if let Ok(mut file) = std::fs::File::open(&file_path) {
            let mut buffer = Vec::new();
            if file.read_to_end(&mut buffer).is_ok() {
                hasher.update(&buffer);
            }
        }
    }

    format!("{:x}", hasher.finalize())
}

/// Check if tier allows custom packs (Pro/Team only)
pub fn tier_allows_custom_packs() -> bool {
    std::env::var("LOCINT_TIER")
        .map(|t| t == "pro" || t == "team" || t == "enterprise")
        .unwrap_or(false)
}

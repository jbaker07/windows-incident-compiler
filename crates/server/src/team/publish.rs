//! Team Publish Service
//!
//! Handles run publishing to case store with SHA256 verification.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::services::types::PublishManifest;

use super::cases::{add_source_run, get_case_dir, read_case_meta, update_signals_count, write_case_meta};
use super::store::{safe_case_path_join, CaseStoreLock};

// ============================================================================
// SHA256 Computation
// ============================================================================

/// Compute SHA256 hash of a file
pub fn compute_file_sha256(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};

    let mut file = std::fs::File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer).map_err(|e| format!("Failed to read file: {}", e))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Compute SHA256 of data in memory
pub fn compute_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}

// ============================================================================
// Run Publishing
// ============================================================================

/// Publish a run to a case in the store
pub fn publish_run_to_case(
    store_dir: &Path,
    case_id: &str,
    run_id: &str,
    run_source_path: &Path,
    publish_signals: bool,
    publish_segments: bool,
    publish_meta: bool,
) -> Result<PublishManifest, String> {
    // Validate case exists
    let case_dir = get_case_dir(store_dir, case_id).ok_or_else(|| "Invalid case ID".to_string())?;

    if !case_dir.exists() {
        return Err("Case not found".to_string());
    }

    // Acquire lock
    let _lock = CaseStoreLock::try_acquire(store_dir, case_id).map_err(|(msg, _code, _owner)| msg)?;

    // Create run directory in case
    let runs_dir = case_dir.join("runs");
    let run_dest_dir =
        safe_case_path_join(&runs_dir, run_id).ok_or_else(|| "Invalid run ID".to_string())?;

    if run_dest_dir.exists() {
        return Err(format!("Run {} already published to this case", run_id));
    }

    std::fs::create_dir_all(&run_dest_dir).map_err(|e| format!("Failed to create run dir: {}", e))?;

    let mut manifest = PublishManifest {
        run_id: run_id.to_string(),
        case_id: case_id.to_string(),
        published_at: chrono::Utc::now().to_rfc3339(),
        files: vec![],
        signals_count: 0,
        segments_count: 0,
        total_bytes: 0,
    };

    // Copy signals database
    if publish_signals {
        let signals_source = run_source_path.join("signals.db");
        if signals_source.exists() {
            let signals_dest = run_dest_dir.join("signals.db");
            copy_file_with_hash(&signals_source, &signals_dest, &mut manifest)?;

            // Count signals
            if let Ok(conn) = rusqlite::Connection::open(&signals_dest) {
                if let Ok(count) =
                    conn.query_row("SELECT COUNT(*) FROM signals", [], |row| row.get::<_, i64>(0))
                {
                    manifest.signals_count = count as usize;
                }
            }
        }
    }

    // Copy segments
    if publish_segments {
        let segments_source = run_source_path.join("segments");
        if segments_source.exists() {
            let segments_dest = run_dest_dir.join("segments");
            std::fs::create_dir_all(&segments_dest)
                .map_err(|e| format!("Failed to create segments dir: {}", e))?;

            let count = copy_directory_with_hashes(&segments_source, &segments_dest, &mut manifest)?;
            manifest.segments_count = count;
        }
    }

    // Copy metadata
    if publish_meta {
        for meta_file in &["index.json", "run_meta.json", "run_stats.json", "playbook_coverage.json"] {
            let source = run_source_path.join(meta_file);
            if source.exists() {
                let dest = run_dest_dir.join(meta_file);
                copy_file_with_hash(&source, &dest, &mut manifest)?;
            }
        }
    }

    // Write publish manifest
    let manifest_path = run_dest_dir.join("publish_manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
    std::fs::write(&manifest_path, &manifest_json)
        .map_err(|e| format!("Failed to write manifest: {}", e))?;

    // Update case metadata
    add_source_run(&case_dir, run_id)?;
    let _ = update_signals_count(&case_dir);

    Ok(manifest)
}

fn copy_file_with_hash(source: &Path, dest: &Path, manifest: &mut PublishManifest) -> Result<(), String> {
    let data = std::fs::read(source).map_err(|e| format!("Failed to read {}: {}", source.display(), e))?;

    let hash = compute_sha256(&data);
    let size = data.len() as u64;

    std::fs::write(dest, &data).map_err(|e| format!("Failed to write {}: {}", dest.display(), e))?;

    manifest.files.push(crate::services::types::PublishedFile {
        relative_path: dest
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string(),
        sha256: hash,
        size_bytes: size,
    });

    manifest.total_bytes += size;

    Ok(())
}

fn copy_directory_with_hashes(
    source_dir: &Path,
    dest_dir: &Path,
    manifest: &mut PublishManifest,
) -> Result<usize, String> {
    let mut count = 0;

    for entry in
        std::fs::read_dir(source_dir).map_err(|e| format!("Failed to read dir {}: {}", source_dir.display(), e))?
    {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let source_path = entry.path();

        if source_path.is_file() {
            if let Some(name) = source_path.file_name().and_then(|n| n.to_str()) {
                let dest_path = dest_dir.join(name);
                copy_file_with_hash(&source_path, &dest_path, manifest)?;
                count += 1;
            }
        } else if source_path.is_dir() {
            if let Some(name) = source_path.file_name().and_then(|n| n.to_str()) {
                let dest_subdir = dest_dir.join(name);
                std::fs::create_dir_all(&dest_subdir)
                    .map_err(|e| format!("Failed to create dir: {}", e))?;
                count += copy_directory_with_hashes(&source_path, &dest_subdir, manifest)?;
            }
        }
    }

    Ok(count)
}

// ============================================================================
// Verification
// ============================================================================

/// Verify a published run's integrity
pub fn verify_published_run(store_dir: &Path, case_id: &str, run_id: &str) -> Result<VerifyResult, String> {
    let case_dir = get_case_dir(store_dir, case_id).ok_or_else(|| "Invalid case ID".to_string())?;

    if !case_dir.exists() {
        return Err("Case not found".to_string());
    }

    let runs_dir = case_dir.join("runs");
    let run_dir = safe_case_path_join(&runs_dir, run_id).ok_or_else(|| "Invalid run ID".to_string())?;

    if !run_dir.exists() {
        return Err("Run not found in case".to_string());
    }

    // Read manifest
    let manifest_path = run_dir.join("publish_manifest.json");
    if !manifest_path.exists() {
        return Err("No publish manifest found".to_string());
    }

    let manifest_content =
        std::fs::read_to_string(&manifest_path).map_err(|e| format!("Failed to read manifest: {}", e))?;

    let manifest: PublishManifest =
        serde_json::from_str(&manifest_content).map_err(|e| format!("Failed to parse manifest: {}", e))?;

    let mut verified = 0;
    let mut failed = 0;
    let mut missing = 0;
    let mut failures = Vec::new();

    for file_info in &manifest.files {
        let file_path = run_dir.join(&file_info.relative_path);

        if !file_path.exists() {
            missing += 1;
            failures.push(format!("Missing: {}", file_info.relative_path));
            continue;
        }

        match compute_file_sha256(&file_path) {
            Ok(hash) => {
                if hash == file_info.sha256 {
                    verified += 1;
                } else {
                    failed += 1;
                    failures.push(format!(
                        "Hash mismatch: {} (expected: {}, got: {})",
                        file_info.relative_path, file_info.sha256, hash
                    ));
                }
            }
            Err(e) => {
                failed += 1;
                failures.push(format!("Error reading {}: {}", file_info.relative_path, e));
            }
        }
    }

    Ok(VerifyResult {
        run_id: run_id.to_string(),
        case_id: case_id.to_string(),
        verified_at: chrono::Utc::now().to_rfc3339(),
        total_files: manifest.files.len(),
        verified,
        failed,
        missing,
        failures,
        integrity_ok: failed == 0 && missing == 0,
    })
}

/// Result of integrity verification
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyResult {
    pub run_id: String,
    pub case_id: String,
    pub verified_at: String,
    pub total_files: usize,
    pub verified: usize,
    pub failed: usize,
    pub missing: usize,
    pub failures: Vec<String>,
    pub integrity_ok: bool,
}

// ============================================================================
// Unpublish
// ============================================================================

/// Remove a run from a case
pub fn unpublish_run(store_dir: &Path, case_id: &str, run_id: &str) -> Result<(), String> {
    let case_dir = get_case_dir(store_dir, case_id).ok_or_else(|| "Invalid case ID".to_string())?;

    if !case_dir.exists() {
        return Err("Case not found".to_string());
    }

    // Acquire lock
    let _lock = CaseStoreLock::try_acquire(store_dir, case_id).map_err(|(msg, _code, _owner)| msg)?;

    let runs_dir = case_dir.join("runs");
    let run_dir = safe_case_path_join(&runs_dir, run_id).ok_or_else(|| "Invalid run ID".to_string())?;

    if !run_dir.exists() {
        return Err("Run not found in case".to_string());
    }

    // Remove run directory
    std::fs::remove_dir_all(&run_dir).map_err(|e| format!("Failed to remove run: {}", e))?;

    // Update case metadata
    let mut meta = read_case_meta(&case_dir)?;
    meta.source_runs.retain(|r| r != run_id);
    meta.modified_at = chrono::Utc::now().to_rfc3339();
    write_case_meta(&case_dir, &meta)?;

    let _ = update_signals_count(&case_dir);

    Ok(())
}

// ============================================================================
// Export Published Run
// ============================================================================

/// Export a published run as a zip bundle
pub fn export_published_run(store_dir: &Path, case_id: &str, run_id: &str) -> Result<Vec<u8>, String> {
    let case_dir = get_case_dir(store_dir, case_id).ok_or_else(|| "Invalid case ID".to_string())?;

    if !case_dir.exists() {
        return Err("Case not found".to_string());
    }

    let runs_dir = case_dir.join("runs");
    let run_dir = safe_case_path_join(&runs_dir, run_id).ok_or_else(|| "Invalid run ID".to_string())?;

    if !run_dir.exists() {
        return Err("Run not found in case".to_string());
    }

    let mut buffer = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buffer);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        add_directory_to_zip(&mut zip, &run_dir, "", options)?;

        zip.finish().map_err(|e| format!("Failed to finish zip: {}", e))?;
    }

    Ok(buffer)
}

fn add_directory_to_zip<W: Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    dir: &Path,
    prefix: &str,
    options: zip::write::FileOptions,
) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("Failed to read dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        let zip_path = if prefix.is_empty() {
            name_str.to_string()
        } else {
            format!("{}/{}", prefix, name_str)
        };

        if path.is_file() {
            let data = std::fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;

            zip.start_file(&zip_path, options)
                .map_err(|e| format!("Failed to start zip file: {}", e))?;
            zip.write_all(&data)
                .map_err(|e| format!("Failed to write to zip: {}", e))?;
        } else if path.is_dir() {
            zip.add_directory(&zip_path, options)
                .map_err(|e| format!("Failed to add directory to zip: {}", e))?;
            add_directory_to_zip(zip, &path, &zip_path, options)?;
        }
    }

    Ok(())
}

//! Export/Import Service
//!
//! Handles bundle export, import, validation, and case pack generation.
//! All business logic for data exchange lives here.

use std::io::{Read, Write};
use std::path::Path;

// ============================================================================
// Bundle Export
// ============================================================================

/// Create a complete ZIP bundle for a run
pub fn create_run_bundle(run_dir: &Path, run_id: &str, include_segments: bool) -> Result<Vec<u8>, String> {
    use zip::write::FileOptions;
    use zip::ZipWriter;

    let buffer = Vec::new();
    let mut cursor = std::io::Cursor::new(buffer);

    {
        let mut zip = ZipWriter::new(&mut cursor);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        // Add run_meta.json
        let meta_path = run_dir.join("run_meta.json");
        if meta_path.exists() {
            let content = std::fs::read_to_string(&meta_path)
                .map_err(|e| format!("Failed to read run_meta.json: {}", e))?;
            zip.start_file("run_meta.json", options)
                .map_err(|e| format!("ZIP error: {}", e))?;
            zip.write_all(content.as_bytes())
                .map_err(|e| format!("ZIP write error: {}", e))?;
        }

        // Add workbench.db
        let db_path = run_dir.join("workbench.db");
        if db_path.exists() {
            let mut content = Vec::new();
            std::fs::File::open(&db_path)
                .map_err(|e| format!("Failed to open workbench.db: {}", e))?
                .read_to_end(&mut content)
                .map_err(|e| format!("Failed to read workbench.db: {}", e))?;
            zip.start_file("workbench.db", options)
                .map_err(|e| format!("ZIP error: {}", e))?;
            zip.write_all(&content)
                .map_err(|e| format!("ZIP write error: {}", e))?;
        }

        // Add segments directory if requested
        if include_segments {
            let segments_dir = run_dir.join("segments");
            if segments_dir.exists() && segments_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&segments_dir) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        if path.is_file() {
                            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                let zip_path = format!("segments/{}", name);
                                let mut content = Vec::new();
                                if let Ok(mut f) = std::fs::File::open(&path) {
                                    if f.read_to_end(&mut content).is_ok() {
                                        let _ = zip.start_file(&zip_path, options);
                                        let _ = zip.write_all(&content);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Add bundle manifest
        let manifest = serde_json::json!({
            "run_id": run_id,
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "schema_version": "1.0.0",
            "contract_hash": "v1-bundle-202601",
            "includes_segments": include_segments
        });
        zip.start_file("bundle_manifest.json", options)
            .map_err(|e| format!("ZIP error: {}", e))?;
        zip.write_all(serde_json::to_string_pretty(&manifest).unwrap().as_bytes())
            .map_err(|e| format!("ZIP write error: {}", e))?;

        zip.finish().map_err(|e| format!("ZIP finish error: {}", e))?;
    }

    Ok(cursor.into_inner())
}

// ============================================================================
// Bundle Validation
// ============================================================================

/// Validation result for imported bundle
pub struct BundleValidation {
    pub available: bool,
    pub reason_code: Option<String>,
    pub missing_artifacts: Vec<String>,
    pub found_artifacts: Vec<String>,
    pub schema_version: Option<String>,
    pub suggested_fix: Option<String>,
    pub can_compile: bool,
    pub can_diff: bool,
    pub can_case_summary: bool,
    pub evidence_deref_available: bool,
    pub segment_count: usize,
    pub has_workbench_db: bool,
}

/// Validate a ZIP bundle before import
pub fn validate_bundle(zip_data: &[u8]) -> BundleValidation {
    let cursor = std::io::Cursor::new(zip_data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(e) => {
            return BundleValidation {
                available: false,
                reason_code: Some("INVALID_ZIP".to_string()),
                missing_artifacts: vec![],
                found_artifacts: vec![],
                schema_version: None,
                suggested_fix: Some(format!("ZIP file is invalid: {}", e)),
                can_compile: false,
                can_diff: false,
                can_case_summary: false,
                evidence_deref_available: false,
                segment_count: 0,
                has_workbench_db: false,
            };
        }
    };

    let mut found_artifacts: Vec<String> = Vec::new();
    let mut schema_version: Option<String> = None;
    let mut run_meta_idx: Option<usize> = None;
    let mut has_workbench_db = false;
    let mut has_run_meta = false;
    let mut has_segments = false;
    let mut segment_count = 0;

    // First pass: collect filenames and categorize
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            let name = file.name().to_string();

            if name.ends_with("run_meta.json") {
                run_meta_idx = Some(i);
                has_run_meta = true;
            }
            if name.ends_with("workbench.db") {
                has_workbench_db = true;
            }
            if name.contains("segments/") && name.ends_with(".jsonl") {
                has_segments = true;
                segment_count += 1;
            }

            found_artifacts.push(name);
        }
    }

    // Second pass: read run_meta.json if found
    if let Some(idx) = run_meta_idx {
        if let Ok(mut file) = archive.by_index(idx) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&contents) {
                    schema_version = meta["schema_version"].as_str().map(|s| s.to_string());
                }
            }
        }
    }

    // Validate schema version
    let supported_schemas = vec!["1.0.0", "1.1.0"];
    let schema_supported = schema_version
        .as_ref()
        .map(|v| supported_schemas.contains(&v.as_str()))
        .unwrap_or(true);

    // Determine capabilities
    let can_compile = has_segments;
    let can_diff = has_workbench_db || has_segments;
    let can_case_summary = has_workbench_db;
    let evidence_deref_available = has_segments;

    // Determine result
    let (available, reason_code, suggested_fix): (bool, Option<String>, Option<String>) = if !has_run_meta {
        (
            false,
            Some("MISSING_RUN_META".to_string()),
            Some("Bundle must contain run_meta.json".to_string()),
        )
    } else if !schema_supported {
        (
            false,
            Some("SCHEMA_UNSUPPORTED".to_string()),
            Some(format!(
                "Schema version '{}' is not supported. Supported: {:?}",
                schema_version.as_deref().unwrap_or("unknown"),
                supported_schemas
            )),
        )
    } else if !has_workbench_db && !has_segments {
        (
            false,
            Some("MISSING_DB_AND_SEGMENTS".to_string()),
            Some("Bundle must contain either workbench.db or segments/ directory".to_string()),
        )
    } else {
        (true, None, None)
    };

    // Build missing artifacts list
    let mut missing_artifacts = Vec::new();
    if !has_run_meta {
        missing_artifacts.push("run_meta.json".to_string());
    }
    if !has_workbench_db && !has_segments {
        missing_artifacts.push("workbench.db OR segments/".to_string());
    }

    BundleValidation {
        available,
        reason_code,
        missing_artifacts,
        found_artifacts,
        schema_version,
        suggested_fix,
        can_compile,
        can_diff,
        can_case_summary,
        evidence_deref_available,
        segment_count,
        has_workbench_db,
    }
}

// ============================================================================
// Bundle Import
// ============================================================================

/// Import a bundle ZIP to a run directory
pub fn import_bundle(
    zip_data: &[u8],
    data_dir: &Path,
    run_id: Option<&str>,
) -> Result<ImportResult, String> {
    let cursor = std::io::Cursor::new(zip_data);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| format!("Invalid ZIP: {}", e))?;

    // Determine run_id from bundle or generate one
    let run_id = run_id
        .map(|s| s.to_string())
        .or_else(|| {
            // Try to get from bundle manifest
            for i in 0..archive.len() {
                if let Ok(mut file) = archive.by_index(i) {
                    if file.name().ends_with("bundle_manifest.json") || file.name().ends_with("run_meta.json") {
                        let mut contents = String::new();
                        if file.read_to_string(&mut contents).is_ok() {
                            if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&contents) {
                                if let Some(id) = meta["run_id"].as_str() {
                                    return Some(id.to_string());
                                }
                            }
                        }
                    }
                }
            }
            None
        })
        .unwrap_or_else(|| format!("imported_{}", chrono::Utc::now().timestamp()));

    let run_dir = data_dir.join("runs").join(&run_id);
    std::fs::create_dir_all(&run_dir).map_err(|e| format!("Failed to create run dir: {}", e))?;

    let mut files_extracted = 0;
    let mut bytes_written = 0u64;

    // Extract files
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| format!("Archive error: {}", e))?;
        let name = file.name().to_string();

        // Skip directories
        if name.ends_with('/') {
            continue;
        }

        // Determine output path
        let output_path = if name.starts_with("segments/") {
            let segments_dir = run_dir.join("segments");
            std::fs::create_dir_all(&segments_dir).ok();
            segments_dir.join(name.strip_prefix("segments/").unwrap_or(&name))
        } else {
            run_dir.join(&name)
        };

        // Extract file
        let mut content = Vec::new();
        file.read_to_end(&mut content).map_err(|e| format!("Read error: {}", e))?;

        std::fs::write(&output_path, &content).map_err(|e| format!("Write error: {}", e))?;

        files_extracted += 1;
        bytes_written += content.len() as u64;
    }

    Ok(ImportResult {
        run_id,
        run_dir: run_dir.display().to_string(),
        files_extracted,
        bytes_written,
    })
}

/// Result of bundle import
pub struct ImportResult {
    pub run_id: String,
    pub run_dir: String,
    pub files_extracted: usize,
    pub bytes_written: u64,
}

// ============================================================================
// Case Pack Generation (Pro)
// ============================================================================

/// Build case pack summary from run database
pub fn build_case_pack_summary(
    db_path: &Path,
    run_id: &str,
    data_dir: &Path,
) -> serde_json::Value {
    use crate::services::run_control::{open_db_with_wal, read_run_meta, read_run_stats};

    let run_dir = data_dir.join("runs").join(run_id);
    let meta_path = run_dir.join("run_meta.json");

    let (started_at, stopped_at, status) = read_run_meta(&meta_path, run_id);
    let (events, segments, facts, signals, earliest_ts, latest_ts, _) = read_run_stats(db_path);

    serde_json::json!({
        "run_id": run_id,
        "started_at": started_at.map(|t| t.to_rfc3339()),
        "stopped_at": stopped_at.map(|t| t.to_rfc3339()),
        "status": status,
        "events_total": events,
        "segments_count": segments,
        "facts_extracted": facts,
        "signals_count": signals,
        "earliest_ts": earliest_ts,
        "latest_ts": latest_ts
    })
}

/// Build findings section for case pack
pub fn build_case_pack_findings(db_path: &Path) -> serde_json::Value {
    use crate::services::run_control::open_db_with_wal;

    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return serde_json::json!({"findings": [], "error": "DB unavailable"}),
    };

    let mut findings = Vec::new();

    let query = r#"
        SELECT signal_id, signal_type, severity, ts, host, proc_key, evidence_ptrs
        FROM signals
        ORDER BY 
            CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
            ts DESC
        LIMIT 50
    "#;

    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "signal_id": row.get::<_, String>(0)?,
                "signal_type": row.get::<_, String>(1)?,
                "severity": row.get::<_, String>(2)?,
                "ts": row.get::<_, i64>(3)?,
                "host": row.get::<_, Option<String>>(4)?,
                "proc_key": row.get::<_, Option<String>>(5)?,
                "evidence_preview": row.get::<_, Option<String>>(6)?
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            }))
        }) {
            for row in rows.flatten() {
                findings.push(row);
            }
        }
    }

    serde_json::json!({
        "findings": findings,
        "count": findings.len()
    })
}

/// Build changes section for case pack (with novelty)
pub fn build_case_pack_changes(db_path: &Path, run_id: &str) -> serde_json::Value {
    use crate::services::run_control::open_db_with_wal;
    use crate::services::diff::categorize_fact_type;

    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return serde_json::json!({"changes": [], "error": "DB unavailable"}),
    };

    let mut changes = Vec::new();
    let mut categories: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    let query = r#"
        SELECT fact_key, fact_type, value_json, ts
        FROM facts
        WHERE run_id = ?
        ORDER BY ts DESC
        LIMIT 100
    "#;

    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        }) {
            for row in rows.flatten() {
                let (fact_key, fact_type, value_json, ts) = row;
                let category = categorize_fact_type(&fact_type);
                *categories.entry(category.to_string()).or_insert(0) += 1;

                changes.push(serde_json::json!({
                    "fact_key": fact_key,
                    "fact_type": fact_type,
                    "category": category,
                    "ts": ts,
                    "value": value_json.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                }));
            }
        }
    }

    serde_json::json!({
        "changes": changes,
        "count": changes.len(),
        "categories": categories
    })
}

// ============================================================================
// SHA256 Computation
// ============================================================================

/// Compute SHA256 hash of data
pub fn compute_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

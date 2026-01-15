//! Baseline Service
//!
//! Handles baseline management for Pro tier.
//! All business logic for baseline operations lives here.

use crate::services::types::BaselineMetricsSnapshot;
use crate::services::run_control::read_run_stats;
use std::path::Path;

// ============================================================================
// Baseline Operations
// ============================================================================

/// Get metrics snapshot for a run (used when setting baseline)
pub fn get_run_metrics_snapshot(run_dir: &Path) -> Option<BaselineMetricsSnapshot> {
    let db_path = run_dir.join("workbench.db");
    if !db_path.exists() {
        return None;
    }

    let (events, segments, facts, signals, _, _, _) = read_run_stats(&db_path);
    Some(BaselineMetricsSnapshot {
        events_count: events,
        segments_count: segments,
        facts_count: facts,
        signals_count: signals as u64,
    })
}

/// Write baseline.json to run directory (atomic write)
pub fn write_baseline_json(
    run_dir: &Path,
    run_id: &str,
    scope: &str,
    description: &str,
    is_default: bool,
    metrics: Option<&BaselineMetricsSnapshot>,
) -> Result<(), String> {
    let now = chrono::Utc::now().to_rfc3339();

    let baseline_data = serde_json::json!({
        "schema_version": "1.1.0",
        "run_id": run_id,
        "scope": scope,
        "marked_at": now,
        "description": description,
        "is_default": is_default,
        "metrics_snapshot": metrics,
    });

    let baseline_path = run_dir.join("baseline.json");
    let temp_path = run_dir.join(".baseline.json.tmp");

    let json_str = serde_json::to_string_pretty(&baseline_data)
        .map_err(|e| format!("Failed to serialize baseline: {}", e))?;

    std::fs::write(&temp_path, &json_str)
        .map_err(|e| format!("Failed to write temp baseline file: {}", e))?;

    std::fs::rename(&temp_path, &baseline_path)
        .or_else(|_| std::fs::write(&baseline_path, &json_str))
        .map_err(|e| format!("Failed to finalize baseline file: {}", e))?;

    Ok(())
}

/// Update baselines.json registry (atomic write)
pub fn update_baselines_registry(
    data_dir: &Path,
    run_id: &str,
    scope: &str,
    baseline_data: serde_json::Value,
    set_as_default: bool,
) -> Result<(), String> {
    let registry_path = data_dir.join("baselines.json");
    let temp_registry_path = data_dir.join(".baselines.json.tmp");

    let mut registry: serde_json::Value = if registry_path.exists() {
        std::fs::read_to_string(&registry_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(serde_json::json!({
                "schema_version": "1.1.0",
                "baselines": {},
                "defaults": {}
            }))
    } else {
        serde_json::json!({
            "schema_version": "1.1.0",
            "baselines": {},
            "defaults": {}
        })
    };

    registry["schema_version"] = serde_json::json!("1.1.0");
    registry["baselines"][run_id] = baseline_data.clone();

    if set_as_default {
        // Clear existing default for this scope
        if let Some(baselines) = registry["baselines"].as_object_mut() {
            for (_, bl) in baselines.iter_mut() {
                if bl["scope"] == scope && bl["is_default"] == true {
                    bl["is_default"] = serde_json::json!(false);
                }
            }
        }
        registry["baselines"][run_id]["is_default"] = serde_json::json!(true);
        registry["defaults"][scope] = serde_json::json!(run_id);
    }

    let json_str = serde_json::to_string_pretty(&registry)
        .map_err(|e| format!("Failed to serialize registry: {}", e))?;

    std::fs::write(&temp_registry_path, &json_str)
        .map_err(|e| format!("Failed to write temp registry: {}", e))?;

    std::fs::rename(&temp_registry_path, &registry_path)
        .or_else(|_| std::fs::write(&registry_path, &json_str))
        .map_err(|e| format!("Failed to finalize registry: {}", e))?;

    Ok(())
}

/// Get baseline stable keys for novelty classification
pub fn get_baseline_stable_keys(
    data_dir: &Path,
    baseline_run_id: &str,
) -> std::collections::HashSet<String> {
    use crate::services::run_control::open_db_with_wal;
    
    let mut keys = std::collections::HashSet::new();
    let db_path = data_dir.join("runs").join(baseline_run_id).join("workbench.db");

    if !db_path.exists() {
        return keys;
    }

    let conn = match open_db_with_wal(&db_path) {
        Ok(c) => c,
        Err(_) => return keys,
    };

    // Query all stable keys from facts
    let query = "SELECT DISTINCT fact_key FROM facts";
    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
            for row in rows.flatten() {
                keys.insert(row);
            }
        }
    }

    keys
}

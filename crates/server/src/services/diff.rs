//! Diff Service
//!
//! Handles Diff v2 with phase/baseline/marker modes.
//! All business logic for change detection lives here.

use crate::services::types::{DiffCategory, DiffChange, DiffDirection, DiffEntities, DiffMode};
use crate::services::run_control::open_db_with_wal;
use std::collections::{HashMap, HashSet};
use std::path::Path;

// ============================================================================
// Stable Key Generation
// ============================================================================

/// Build stable key from fact data for consistent diffing
pub fn build_stable_key(category: DiffCategory, fact_json: &serde_json::Value, host: &str) -> String {
    match category {
        DiffCategory::Persistence => {
            if let Some(svc) = fact_json.get("service_name").and_then(|v| v.as_str()) {
                return format!("persistence:service:{}:{}", host, svc);
            }
            if let Some(task) = fact_json.get("task_name").and_then(|v| v.as_str()) {
                return format!("persistence:task:{}:{}", host, task);
            }
            if let Some(reg) = fact_json.get("registry_path").and_then(|v| v.as_str()) {
                return format!("persistence:reg:{}:{}", host, reg);
            }
            format!("persistence:unknown:{}", host)
        }
        DiffCategory::Process => {
            if let Some(pk) = fact_json.get("proc_key").and_then(|v| v.as_str()) {
                let parent = fact_json.get("parent_proc_key").and_then(|v| v.as_str()).unwrap_or("_");
                return format!("process:{}:{}:{}", host, pk, parent);
            }
            if let Some(exe) = fact_json.get("exe_path").and_then(|v| v.as_str()) {
                let cmd_hash = fact_json.get("cmdline")
                    .and_then(|v| v.as_str())
                    .map(|c| format!("{:x}", c.len() as u32))
                    .unwrap_or_default();
                return format!("process:{}:{}:{}", host, exe, cmd_hash);
            }
            format!("process:unknown:{}", host)
        }
        DiffCategory::Network => {
            let proc = fact_json.get("proc_key").and_then(|v| v.as_str()).unwrap_or("_");
            let ip = fact_json.get("remote_ip").or(fact_json.get("dest_ip")).and_then(|v| v.as_str()).unwrap_or("_");
            let port = fact_json.get("remote_port").or(fact_json.get("dest_port")).and_then(|v| v.as_u64()).unwrap_or(0);
            format!("network:{}:{}:{}:{}", host, proc, ip, port)
        }
        DiffCategory::Auth => {
            let user = fact_json.get("user").or(fact_json.get("username")).and_then(|v| v.as_str()).unwrap_or("_");
            let logon = fact_json.get("logon_type").and_then(|v| v.as_str()).unwrap_or("_");
            format!("auth:{}:{}:{}", host, user, logon)
        }
        DiffCategory::File => {
            let path = fact_json.get("file_path").or(fact_json.get("target_path")).and_then(|v| v.as_str()).unwrap_or("_");
            let op = fact_json.get("operation").and_then(|v| v.as_str()).unwrap_or("_");
            format!("file:{}:{}:{}", host, path, op)
        }
        DiffCategory::Evasion => {
            let tech = fact_json.get("technique").and_then(|v| v.as_str()).unwrap_or("_");
            let target = fact_json.get("target").and_then(|v| v.as_str()).unwrap_or("_");
            format!("evasion:{}:{}:{}", host, tech, target)
        }
        DiffCategory::Other => {
            let ft = fact_json.get("fact_type").and_then(|v| v.as_str()).unwrap_or("unknown");
            format!("other:{}:{}", host, ft)
        }
    }
}

/// Extract entities from fact JSON
pub fn extract_entities(fact_json: &serde_json::Value, host: &str) -> DiffEntities {
    DiffEntities {
        host: Some(host.to_string()),
        proc_key: fact_json.get("proc_key").and_then(|v| v.as_str()).map(String::from),
        parent_proc_key: fact_json.get("parent_proc_key").and_then(|v| v.as_str()).map(String::from),
        file_key: fact_json.get("file_key").or(fact_json.get("file_path")).and_then(|v| v.as_str()).map(String::from),
        user: fact_json.get("user").or(fact_json.get("username")).and_then(|v| v.as_str()).map(String::from),
        ip: fact_json.get("remote_ip").or(fact_json.get("dest_ip")).and_then(|v| v.as_str()).map(String::from),
        port: fact_json.get("remote_port").or(fact_json.get("dest_port")).and_then(|v| v.as_u64()).map(|p| p as u16),
        service_name: fact_json.get("service_name").and_then(|v| v.as_str()).map(String::from),
        task_name: fact_json.get("task_name").and_then(|v| v.as_str()).map(String::from),
        registry_path: fact_json.get("registry_path").and_then(|v| v.as_str()).map(String::from),
        logon_type: fact_json.get("logon_type").and_then(|v| v.as_str()).map(String::from),
    }
}

// ============================================================================
// Severity Computation
// ============================================================================

/// Compute deterministic severity for diff changes
pub fn compute_diff_severity(
    category: DiffCategory,
    direction: DiffDirection,
    count_delta: i64,
) -> (&'static str, String) {
    let base_weight = match category {
        DiffCategory::Persistence => 4,
        DiffCategory::Evasion => 4,
        DiffCategory::Auth => 3,
        DiffCategory::Network => 2,
        DiffCategory::Process => 2,
        DiffCategory::File => 1,
        DiffCategory::Other => 1,
    };

    let direction_multiplier = match direction {
        DiffDirection::Added => 1.5,
        DiffDirection::Increased => 1.2,
        DiffDirection::Modified => 1.0,
        DiffDirection::Decreased => 0.5,
        DiffDirection::Removed => 0.3,
    };

    let count_factor = (count_delta.abs() as f64).log10().max(1.0);
    let score = (base_weight as f64) * direction_multiplier * count_factor;

    let severity = if score >= 5.0 {
        "critical"
    } else if score >= 3.5 {
        "high"
    } else if score >= 2.0 {
        "medium"
    } else {
        "low"
    };

    let basis = format!(
        "category={} ({}) × direction={} ({:.1}) × count_factor={:.1} = {:.1}",
        category.as_str(),
        base_weight,
        direction.as_str(),
        direction_multiplier,
        count_factor,
        score
    );

    (severity, basis)
}

// ============================================================================
// Novelty Classification
// ============================================================================

/// Classify novelty of a change relative to baseline
pub fn classify_novelty(
    stable_key: &str,
    baseline_keys: &HashSet<String>,
    direction: DiffDirection,
) -> (String, String) {
    if baseline_keys.is_empty() {
        return ("unknown".to_string(), "No baseline for comparison".to_string());
    }

    let in_baseline = baseline_keys.contains(stable_key);

    match (in_baseline, direction) {
        (false, DiffDirection::Added) => ("new".to_string(), "Key not present in baseline".to_string()),
        (true, DiffDirection::Added) => ("reappeared".to_string(), "Key exists in baseline, appeared again".to_string()),
        (true, DiffDirection::Removed) => ("removed".to_string(), "Key was in baseline, now removed".to_string()),
        (true, DiffDirection::Modified) => ("changed".to_string(), "Key exists in baseline with different value".to_string()),
        (true, DiffDirection::Increased) => ("changed".to_string(), "Key exists in baseline, count increased".to_string()),
        (true, DiffDirection::Decreased) => ("changed".to_string(), "Key exists in baseline, count decreased".to_string()),
        (false, _) => ("new".to_string(), "Key not present in baseline".to_string()),
    }
}

// ============================================================================
// Diff Execution
// ============================================================================

/// Execute phase-mode diff (first N minutes vs rest)
pub fn diff_phase(
    db_path: &Path,
    run_id: &str,
    phase_minutes: i64,
    baseline_keys: Option<&HashSet<String>>,
) -> Result<Vec<DiffChange>, String> {
    let conn = open_db_with_wal(db_path).map_err(|e| format!("DB error: {}", e))?;

    // Get time range
    let (min_ts, max_ts): (i64, i64) = conn
        .query_row(
            "SELECT COALESCE(MIN(ts), 0), COALESCE(MAX(ts), 0) FROM facts WHERE run_id = ?",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or((0, 0));

    if min_ts == 0 || max_ts == 0 {
        return Ok(vec![]);
    }

    let phase_boundary = min_ts + (phase_minutes * 60 * 1000);

    // Get facts from initial phase
    let initial_keys = get_phase_keys(&conn, run_id, min_ts, phase_boundary)?;

    // Get facts from main phase
    let main_keys = get_phase_keys(&conn, run_id, phase_boundary, max_ts)?;

    // Compute diff
    let changes = compute_key_diff(&initial_keys, &main_keys, baseline_keys);

    Ok(changes)
}

/// Get unique keys from a time range
fn get_phase_keys(
    conn: &rusqlite::Connection,
    run_id: &str,
    start_ts: i64,
    end_ts: i64,
) -> Result<HashMap<String, (serde_json::Value, i64, String)>, String> {
    let mut keys = HashMap::new();

    let query = r#"
        SELECT fact_key, fact_type, value_json, ts
        FROM facts
        WHERE run_id = ? AND ts >= ? AND ts < ?
    "#;

    let mut stmt = conn.prepare(query).map_err(|e| format!("Query error: {}", e))?;
    let rows = stmt
        .query_map(rusqlite::params![run_id, start_ts, end_ts], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|e| format!("Query error: {}", e))?;

    for row in rows.flatten() {
        let (fact_key, fact_type, value_json, ts) = row;
        let value: serde_json::Value = value_json
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(serde_json::json!({}));

        let host = value
            .get("host")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let category = DiffCategory::from_fact_type(&fact_type);
        let stable_key = build_stable_key(category, &value, &host);

        keys.insert(stable_key, (value, ts, host));
    }

    Ok(keys)
}

/// Compute diff between two key sets
fn compute_key_diff(
    before: &HashMap<String, (serde_json::Value, i64, String)>,
    after: &HashMap<String, (serde_json::Value, i64, String)>,
    baseline_keys: Option<&HashSet<String>>,
) -> Vec<DiffChange> {
    let mut changes = Vec::new();
    let empty_baseline = HashSet::new();
    let baseline = baseline_keys.unwrap_or(&empty_baseline);

    // Find added keys (in after but not in before)
    for (key, (value, ts, host)) in after.iter() {
        if !before.contains_key(key) {
            let fact_type = value
                .get("fact_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let category = DiffCategory::from_fact_type(fact_type);
            let (severity, severity_basis) = compute_diff_severity(category, DiffDirection::Added, 1);
            let (novelty, novelty_basis) = classify_novelty(key, baseline, DiffDirection::Added);

            changes.push(DiffChange {
                change_id: format!("{}_{}_added", category.as_str().to_lowercase(), hash_str(key)),
                ts_ms: *ts,
                ts_end_ms: None,
                category,
                direction: DiffDirection::Added,
                title: format!("New {} activity", category.as_str()),
                summary: format!("New {} detected: {}", category.as_str().to_lowercase(), key),
                entities: extract_entities(value, host),
                severity: severity.to_string(),
                severity_basis,
                evidence_ptrs: vec![],
                evidence_unavailable_reason: Some("Phase diff mode - no direct evidence".to_string()),
                supporting_facts_count: 1,
                stable_key: key.clone(),
                novelty: Some(novelty),
                novelty_basis: Some(novelty_basis),
            });
        }
    }

    // Find removed keys (in before but not in after)
    for (key, (value, ts, host)) in before.iter() {
        if !after.contains_key(key) {
            let fact_type = value
                .get("fact_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let category = DiffCategory::from_fact_type(fact_type);
            let (severity, severity_basis) = compute_diff_severity(category, DiffDirection::Removed, 1);
            let (novelty, novelty_basis) = classify_novelty(key, baseline, DiffDirection::Removed);

            changes.push(DiffChange {
                change_id: format!("{}_{}_removed", category.as_str().to_lowercase(), hash_str(key)),
                ts_ms: *ts,
                ts_end_ms: None,
                category,
                direction: DiffDirection::Removed,
                title: format!("Removed {} activity", category.as_str()),
                summary: format!("Removed {} detected: {}", category.as_str().to_lowercase(), key),
                entities: extract_entities(value, host),
                severity: severity.to_string(),
                severity_basis,
                evidence_ptrs: vec![],
                evidence_unavailable_reason: Some("Phase diff mode - no direct evidence".to_string()),
                supporting_facts_count: 1,
                stable_key: key.clone(),
                novelty: Some(novelty),
                novelty_basis: Some(novelty_basis),
            });
        }
    }

    // Sort by severity then timestamp
    changes.sort_by(|a, b| {
        let sev_order = |s: &str| match s {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        };
        sev_order(&a.severity)
            .cmp(&sev_order(&b.severity))
            .then(b.ts_ms.cmp(&a.ts_ms))
    });

    changes
}

/// Simple string hash for stable IDs
fn hash_str(s: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

// ============================================================================
// Category Helpers
// ============================================================================

/// Categorize a fact type into a high-level category
pub fn categorize_fact_type(fact_type: &str) -> &'static str {
    match fact_type.to_lowercase().as_str() {
        "exec" | "processexec" | "processcreate" | "processexit" | "moduleload" | "memread" => "Process",
        "fileop" | "filecreate" | "filedelete" | "filemodify" | "fileaccess" => "File",
        "netconn" | "networkconnection" | "dnsquery" | "dns" => "Network",
        "persistartifact" | "servicecreate" | "schedtask" | "regop" | "registryop" | "wmiop" => "Persistence",
        "authevent" | "authlogon" | "logon" | "logoff" | "authfailure" => "Auth",
        "logtamper" | "defenseevasion" | "securityevasion" => "Evasion",
        _ => "Other",
    }
}

/// Get severity hint from signal severity string
pub fn severity_hint_from_signal(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    }
}

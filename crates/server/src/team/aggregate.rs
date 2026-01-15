//! Team Aggregate Service
//!
//! Handles aggregate views across runs: timeline, signals, entities.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::cases::get_case_dir;
use super::store::safe_case_path_join;

// ============================================================================
// Aggregate Signal Stats
// ============================================================================

/// Get aggregated signal statistics across all runs in a case
pub fn get_case_signal_stats(store_dir: &Path, case_id: &str) -> Result<CaseSignalStats, String> {
    let case_dir = get_case_dir(store_dir, case_id).ok_or_else(|| "Invalid case ID".to_string())?;

    if !case_dir.exists() {
        return Err("Case not found".to_string());
    }

    let runs_dir = case_dir.join("runs");
    if !runs_dir.exists() {
        return Ok(CaseSignalStats::default());
    }

    let mut total_signals = 0;
    let mut severity_counts: HashMap<String, usize> = HashMap::new();
    let mut playbook_counts: HashMap<String, usize> = HashMap::new();
    let mut run_counts: Vec<RunSignalCount> = Vec::new();

    for entry in std::fs::read_dir(&runs_dir).map_err(|e| format!("Failed to read runs dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let run_dir = entry.path();

        if !run_dir.is_dir() {
            continue;
        }

        let run_id = run_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let db_path = run_dir.join("signals.db");
        if !db_path.exists() {
            continue;
        }

        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            // Count signals in this run
            let run_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM signals", [], |row| row.get(0))
                .unwrap_or(0);

            total_signals += run_count as usize;

            run_counts.push(RunSignalCount {
                run_id: run_id.clone(),
                count: run_count as usize,
            });

            // Count by severity
            if let Ok(mut stmt) = conn.prepare("SELECT severity, COUNT(*) FROM signals GROUP BY severity") {
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                });

                if let Ok(rows) = rows {
                    for row in rows.flatten() {
                        *severity_counts.entry(row.0).or_insert(0) += row.1 as usize;
                    }
                }
            }

            // Count by playbook
            if let Ok(mut stmt) = conn.prepare("SELECT playbook_id, COUNT(*) FROM signals GROUP BY playbook_id")
            {
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                });

                if let Ok(rows) = rows {
                    for row in rows.flatten() {
                        *playbook_counts.entry(row.0).or_insert(0) += row.1 as usize;
                    }
                }
            }
        }
    }

    Ok(CaseSignalStats {
        total_signals,
        runs_count: run_counts.len(),
        by_severity: severity_counts,
        by_playbook: playbook_counts,
        per_run: run_counts,
    })
}

/// Signal statistics for a case
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CaseSignalStats {
    pub total_signals: usize,
    pub runs_count: usize,
    pub by_severity: HashMap<String, usize>,
    pub by_playbook: HashMap<String, usize>,
    pub per_run: Vec<RunSignalCount>,
}

/// Signal count per run
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RunSignalCount {
    pub run_id: String,
    pub count: usize,
}

// ============================================================================
// Aggregate Timeline
// ============================================================================

/// Get aggregated timeline events across all runs
pub fn get_case_timeline(
    store_dir: &Path,
    case_id: &str,
    start_time: Option<&str>,
    end_time: Option<&str>,
    limit: Option<usize>,
) -> Result<CaseTimeline, String> {
    let case_dir = get_case_dir(store_dir, case_id).ok_or_else(|| "Invalid case ID".to_string())?;

    if !case_dir.exists() {
        return Err("Case not found".to_string());
    }

    let runs_dir = case_dir.join("runs");
    if !runs_dir.exists() {
        return Ok(CaseTimeline::default());
    }

    let mut events: Vec<TimelineEvent> = Vec::new();
    let limit = limit.unwrap_or(1000);

    for entry in std::fs::read_dir(&runs_dir).map_err(|e| format!("Failed to read runs dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let run_dir = entry.path();

        if !run_dir.is_dir() {
            continue;
        }

        let run_id = run_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let db_path = run_dir.join("signals.db");
        if !db_path.exists() {
            continue;
        }

        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            // Build query with optional time filters
            let mut sql = String::from(
                "SELECT signal_id, timestamp, severity, playbook_id, title FROM signals WHERE 1=1",
            );

            if start_time.is_some() {
                sql.push_str(" AND timestamp >= ?1");
            }
            if end_time.is_some() {
                let param_num = if start_time.is_some() { "?2" } else { "?1" };
                sql.push_str(&format!(" AND timestamp <= {}", param_num));
            }

            sql.push_str(" ORDER BY timestamp DESC");

            if let Ok(mut stmt) = conn.prepare(&sql) {
                // Collect results manually to avoid closure type issues
                let query_result: Result<Vec<TimelineEvent>, _> = match (start_time, end_time) {
                    (Some(st), Some(et)) => {
                        stmt.query([st, et]).and_then(|mut rows| {
                            let mut results = Vec::new();
                            while let Some(row) = rows.next()? {
                                results.push(TimelineEvent {
                                    run_id: run_id.clone(),
                                    signal_id: row.get(0)?,
                                    timestamp: row.get(1)?,
                                    severity: row.get(2)?,
                                    playbook_id: row.get(3)?,
                                    title: row.get(4)?,
                                });
                            }
                            Ok(results)
                        })
                    }
                    (Some(st), None) => {
                        stmt.query([st]).and_then(|mut rows| {
                            let mut results = Vec::new();
                            while let Some(row) = rows.next()? {
                                results.push(TimelineEvent {
                                    run_id: run_id.clone(),
                                    signal_id: row.get(0)?,
                                    timestamp: row.get(1)?,
                                    severity: row.get(2)?,
                                    playbook_id: row.get(3)?,
                                    title: row.get(4)?,
                                });
                            }
                            Ok(results)
                        })
                    }
                    (None, Some(et)) => {
                        stmt.query([et]).and_then(|mut rows| {
                            let mut results = Vec::new();
                            while let Some(row) = rows.next()? {
                                results.push(TimelineEvent {
                                    run_id: run_id.clone(),
                                    signal_id: row.get(0)?,
                                    timestamp: row.get(1)?,
                                    severity: row.get(2)?,
                                    playbook_id: row.get(3)?,
                                    title: row.get(4)?,
                                });
                            }
                            Ok(results)
                        })
                    }
                    (None, None) => {
                        stmt.query([]).and_then(|mut rows| {
                            let mut results = Vec::new();
                            while let Some(row) = rows.next()? {
                                results.push(TimelineEvent {
                                    run_id: run_id.clone(),
                                    signal_id: row.get(0)?,
                                    timestamp: row.get(1)?,
                                    severity: row.get(2)?,
                                    playbook_id: row.get(3)?,
                                    title: row.get(4)?,
                                });
                            }
                            Ok(results)
                        })
                    }
                };

                if let Ok(run_events) = query_result {
                    events.extend(run_events);
                }
            }
        }
    }

    // Sort all events by timestamp
    events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    // Apply limit
    events.truncate(limit);

    Ok(CaseTimeline {
        events,
        start_time: start_time.map(|s| s.to_string()),
        end_time: end_time.map(|s| s.to_string()),
    })
}

/// Aggregated timeline for a case
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CaseTimeline {
    pub events: Vec<TimelineEvent>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
}

/// Timeline event
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimelineEvent {
    pub run_id: String,
    pub signal_id: String,
    pub timestamp: String,
    pub severity: String,
    pub playbook_id: String,
    pub title: String,
}

// ============================================================================
// Entity Aggregation
// ============================================================================

/// Get unique entities across all runs in a case
pub fn get_case_entities(store_dir: &Path, case_id: &str) -> Result<CaseEntities, String> {
    let case_dir = get_case_dir(store_dir, case_id).ok_or_else(|| "Invalid case ID".to_string())?;

    if !case_dir.exists() {
        return Err("Case not found".to_string());
    }

    let runs_dir = case_dir.join("runs");
    if !runs_dir.exists() {
        return Ok(CaseEntities::default());
    }

    let mut processes: HashMap<String, EntityInfo> = HashMap::new();
    let mut files: HashMap<String, EntityInfo> = HashMap::new();
    let mut users: HashMap<String, EntityInfo> = HashMap::new();
    let mut network: HashMap<String, EntityInfo> = HashMap::new();

    for entry in std::fs::read_dir(&runs_dir).map_err(|e| format!("Failed to read runs dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let run_dir = entry.path();

        if !run_dir.is_dir() {
            continue;
        }

        let run_id = run_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let db_path = run_dir.join("signals.db");
        if !db_path.exists() {
            continue;
        }

        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            // Extract entities from signals JSON
            if let Ok(mut stmt) = conn.prepare("SELECT signal_id, signal_json FROM signals") {
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                });

                if let Ok(rows) = rows {
                    for row in rows.flatten() {
                        let (signal_id, json_str) = row;
                        if let Ok(signal) = serde_json::from_str::<serde_json::Value>(&json_str) {
                            extract_entities_from_signal(&signal, &run_id, &signal_id, &mut processes, &mut files, &mut users, &mut network);
                        }
                    }
                }
            }
        }
    }

    Ok(CaseEntities {
        processes: processes.into_values().collect(),
        files: files.into_values().collect(),
        users: users.into_values().collect(),
        network: network.into_values().collect(),
    })
}

fn extract_entities_from_signal(
    signal: &serde_json::Value,
    run_id: &str,
    signal_id: &str,
    processes: &mut HashMap<String, EntityInfo>,
    files: &mut HashMap<String, EntityInfo>,
    users: &mut HashMap<String, EntityInfo>,
    network: &mut HashMap<String, EntityInfo>,
) {
    // Extract process entities
    if let Some(proc_name) = signal.pointer("/process/name").and_then(|v| v.as_str()) {
        let key = proc_name.to_lowercase();
        let entry = processes.entry(key).or_insert_with(|| EntityInfo {
            entity_type: "process".to_string(),
            value: proc_name.to_string(),
            first_seen: run_id.to_string(),
            run_ids: vec![],
            signal_count: 0,
        });
        if !entry.run_ids.contains(&run_id.to_string()) {
            entry.run_ids.push(run_id.to_string());
        }
        entry.signal_count += 1;
    }

    // Extract file entities
    if let Some(file_path) = signal.pointer("/file/path").and_then(|v| v.as_str()) {
        let key = file_path.to_lowercase();
        let entry = files.entry(key).or_insert_with(|| EntityInfo {
            entity_type: "file".to_string(),
            value: file_path.to_string(),
            first_seen: run_id.to_string(),
            run_ids: vec![],
            signal_count: 0,
        });
        if !entry.run_ids.contains(&run_id.to_string()) {
            entry.run_ids.push(run_id.to_string());
        }
        entry.signal_count += 1;
    }

    // Extract user entities
    if let Some(user) = signal.pointer("/user/name").and_then(|v| v.as_str()) {
        let key = user.to_lowercase();
        let entry = users.entry(key).or_insert_with(|| EntityInfo {
            entity_type: "user".to_string(),
            value: user.to_string(),
            first_seen: run_id.to_string(),
            run_ids: vec![],
            signal_count: 0,
        });
        if !entry.run_ids.contains(&run_id.to_string()) {
            entry.run_ids.push(run_id.to_string());
        }
        entry.signal_count += 1;
    }

    // Extract network entities
    if let Some(dest_ip) = signal.pointer("/network/destination/ip").and_then(|v| v.as_str()) {
        let key = dest_ip.to_string();
        let entry = network.entry(key.clone()).or_insert_with(|| EntityInfo {
            entity_type: "network".to_string(),
            value: dest_ip.to_string(),
            first_seen: run_id.to_string(),
            run_ids: vec![],
            signal_count: 0,
        });
        if !entry.run_ids.contains(&run_id.to_string()) {
            entry.run_ids.push(run_id.to_string());
        }
        entry.signal_count += 1;
    }
}

/// Aggregated entities for a case
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CaseEntities {
    pub processes: Vec<EntityInfo>,
    pub files: Vec<EntityInfo>,
    pub users: Vec<EntityInfo>,
    pub network: Vec<EntityInfo>,
}

/// Entity information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntityInfo {
    pub entity_type: String,
    pub value: String,
    pub first_seen: String,
    pub run_ids: Vec<String>,
    pub signal_count: usize,
}

// ============================================================================
// Cross-Run Search
// ============================================================================

/// Search signals across all runs in a case
pub fn search_case_signals(
    store_dir: &Path,
    case_id: &str,
    query: &str,
    limit: Option<usize>,
) -> Result<Vec<SearchResult>, String> {
    let case_dir = get_case_dir(store_dir, case_id).ok_or_else(|| "Invalid case ID".to_string())?;

    if !case_dir.exists() {
        return Err("Case not found".to_string());
    }

    let runs_dir = case_dir.join("runs");
    if !runs_dir.exists() {
        return Ok(vec![]);
    }

    let query_lower = query.to_lowercase();
    let limit = limit.unwrap_or(100);
    let mut results: Vec<SearchResult> = Vec::new();

    for entry in std::fs::read_dir(&runs_dir).map_err(|e| format!("Failed to read runs dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let run_dir = entry.path();

        if !run_dir.is_dir() {
            continue;
        }

        let run_id = run_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let db_path = run_dir.join("signals.db");
        if !db_path.exists() {
            continue;
        }

        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            // Simple text search in title and signal_json
            let sql = "SELECT signal_id, timestamp, severity, title, signal_json 
                       FROM signals 
                       WHERE LOWER(title) LIKE ? OR LOWER(signal_json) LIKE ?
                       LIMIT ?";

            let pattern = format!("%{}%", query_lower);

            if let Ok(mut stmt) = conn.prepare(sql) {
                let rows = stmt.query_map(rusqlite::params![&pattern, &pattern, limit], |row| {
                    Ok(SearchResult {
                        run_id: run_id.clone(),
                        signal_id: row.get(0)?,
                        timestamp: row.get(1)?,
                        severity: row.get(2)?,
                        title: row.get(3)?,
                        snippet: create_snippet(row.get::<_, String>(4).ok().as_deref(), &query_lower),
                    })
                });

                if let Ok(rows) = rows {
                    for result in rows.flatten() {
                        results.push(result);
                        if results.len() >= limit {
                            break;
                        }
                    }
                }
            }
        }

        if results.len() >= limit {
            break;
        }
    }

    // Sort by timestamp descending
    results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    results.truncate(limit);

    Ok(results)
}

fn create_snippet(json_str: Option<&str>, query: &str) -> Option<String> {
    let json_str = json_str?;
    let lower = json_str.to_lowercase();
    let pos = lower.find(query)?;

    let start = pos.saturating_sub(50);
    let end = (pos + query.len() + 50).min(json_str.len());

    let snippet = &json_str[start..end];
    Some(format!("...{}...", snippet.trim()))
}

/// Search result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SearchResult {
    pub run_id: String,
    pub signal_id: String,
    pub timestamp: String,
    pub severity: String,
    pub title: String,
    pub snippet: Option<String>,
}

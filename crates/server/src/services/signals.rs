//! Signals Service
//!
//! Handles signal queries, explainability, and statistics.
//! All business logic for signal management lives here.

use crate::services::run_control::open_db_with_wal;
use std::path::Path;

// ============================================================================
// Signal Queries
// ============================================================================

/// Query signals for a run with optional cursor-based pagination
pub fn query_signals(
    db_path: &Path,
    since_ts_ms: Option<i64>,
    limit: usize,
) -> Result<(Vec<serde_json::Value>, i64), String> {
    let conn = open_db_with_wal(db_path).map_err(|e| format!("DB error: {}", e))?;

    let (query_str, query_params): (String, Vec<i64>) = match since_ts_ms {
        Some(since_ts) => (
            format!(
                "SELECT signal_id, signal_type, severity, ts, host 
                 FROM signals 
                 WHERE ts > ? 
                 ORDER BY ts DESC 
                 LIMIT {}",
                limit
            ),
            vec![since_ts],
        ),
        None => (
            format!(
                "SELECT signal_id, signal_type, severity, ts, host 
                 FROM signals 
                 ORDER BY ts DESC 
                 LIMIT {}",
                limit
            ),
            vec![],
        ),
    };

    let mut stmt = conn.prepare(&query_str).map_err(|e| format!("Query error: {}", e))?;

    let signals: Vec<serde_json::Value> = if query_params.is_empty() {
        stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "signal_id": row.get::<_, String>(0)?,
                "signal_type": row.get::<_, String>(1)?,
                "severity": row.get::<_, String>(2)?,
                "ts": row.get::<_, i64>(3)?,
                "host": row.get::<_, Option<String>>(4)?,
            }))
        })
        .map_err(|e| format!("Query error: {}", e))?
        .filter_map(|r| r.ok())
        .collect()
    } else {
        stmt.query_map([query_params[0]], |row| {
            Ok(serde_json::json!({
                "signal_id": row.get::<_, String>(0)?,
                "signal_type": row.get::<_, String>(1)?,
                "severity": row.get::<_, String>(2)?,
                "ts": row.get::<_, i64>(3)?,
                "host": row.get::<_, Option<String>>(4)?,
            }))
        })
        .map_err(|e| format!("Query error: {}", e))?
        .filter_map(|r| r.ok())
        .collect()
    };

    // Compute next cursor
    let max_ts: Option<i64> = signals
        .iter()
        .filter_map(|s| s.get("ts").and_then(|t| t.as_i64()))
        .max();

    let next_since_ts_ms = match (max_ts, since_ts_ms) {
        (Some(max), _) => max,
        (None, Some(prev)) => prev,
        (None, None) => 0,
    };

    Ok((signals, next_since_ts_ms))
}

/// Get a single signal by ID
pub fn get_signal(db_path: &Path, signal_id: &str) -> Result<Option<serde_json::Value>, String> {
    let conn = open_db_with_wal(db_path).map_err(|e| format!("DB error: {}", e))?;

    let result = conn.query_row(
        "SELECT signal_id, signal_type, severity, ts, host, proc_key, evidence_ptrs, metadata
         FROM signals 
         WHERE signal_id = ?",
        [signal_id],
        |row| {
            let evidence_ptrs_str: Option<String> = row.get(6)?;
            let evidence_ptrs: Vec<serde_json::Value> = evidence_ptrs_str
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            Ok(serde_json::json!({
                "signal_id": row.get::<_, String>(0)?,
                "signal_type": row.get::<_, String>(1)?,
                "severity": row.get::<_, String>(2)?,
                "ts": row.get::<_, i64>(3)?,
                "host": row.get::<_, Option<String>>(4)?,
                "proc_key": row.get::<_, Option<String>>(5)?,
                "evidence_ptrs": evidence_ptrs,
                "evidence_ptrs_count": evidence_ptrs.len(),
                "metadata": row.get::<_, Option<String>>(7)?,
            }))
        },
    );

    match result {
        Ok(signal) => Ok(Some(signal)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Query error: {}", e)),
    }
}

// ============================================================================
// Signal Explanation
// ============================================================================

/// Get explanation for a signal - ALWAYS returns a complete explanation bundle
/// Per requirement: never return empty/useless explanations
pub fn get_signal_explanation(
    db_path: &Path,
    signal_id: &str,
) -> Result<serde_json::Value, String> {
    let conn = open_db_with_wal(db_path).map_err(|e| format!("DB error: {}", e))?;

    // First get the signal (including dropped_evidence_count for diagnostics)
    let signal_result = conn.query_row(
        "SELECT signal_id, signal_type, severity, ts, evidence_ptrs, proc_key, host, metadata, 
                COALESCE(dropped_evidence_count, 0) as dropped_evidence_count
         FROM signals 
         WHERE signal_id = ?",
        [signal_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, i64>(8)?,
            ))
        },
    );

    let (signal_id, signal_type, severity, ts, evidence_ptrs_str, proc_key, host, metadata_str, dropped_evidence_count) = match signal_result {
        Ok(s) => s,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Ok(serde_json::json!({
                "available": false,
                "signal": null,
                "source": null,
                "narrative": "Signal not found in database.",
                "evidence_ptrs": [],
                "evidence_ptrs_count": 0,
                "evidence_unavailable_reason": {
                    "code": "SIGNAL_NOT_FOUND",
                    "message": "The requested signal ID does not exist in this run's database."
                },
                "scoring": {
                    "severity": "unknown",
                    "confidence": "low",
                    "basis": ["Signal not found - cannot compute score"]
                },
                "matched_facts": [],
                "matched_slots": null,
                "reason_code": "SIGNAL_NOT_FOUND",
                "message": "Signal not found in database"
            }));
        }
        Err(e) => return Err(format!("Query error: {}", e)),
    };

    // Parse evidence pointers
    let evidence_ptrs: Vec<serde_json::Value> = evidence_ptrs_str
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let evidence_ptrs_count = evidence_ptrs.len();
    
    // Parse metadata if present
    let metadata: Option<serde_json::Value> = metadata_str
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok());
    
    // Build evidence diagnostics
    let evidence_diagnostics = build_evidence_diagnostics(
        &evidence_ptrs, 
        dropped_evidence_count as usize,
        &metadata
    );

    // Try to get explanation from signal_explanations table
    let explanation_result = conn.query_row(
        "SELECT explanation_json FROM signal_explanations WHERE signal_id = ?",
        [&signal_id],
        |row| row.get::<_, String>(0),
    );
    
    // Query matched facts for this signal (from facts table via entity keys)
    let matched_facts = get_matched_facts_for_signal(&conn, &proc_key, &host);
    
    // Build entities from signal data
    let mut entities = serde_json::json!({});
    if let Some(ref pk) = proc_key {
        entities["process"] = serde_json::json!(pk);
    }
    if let Some(ref h) = host {
        entities["host"] = serde_json::json!(h);
    }

    match explanation_result {
        Ok(explanation_json) => {
            let explanation: serde_json::Value =
                serde_json::from_str(&explanation_json).unwrap_or(serde_json::json!({}));
            
            // Extract or build narrative
            let narrative = build_narrative(&signal_type, &severity, &explanation, &matched_facts, evidence_ptrs_count, &proc_key);
            
            // Build scoring object (always present)
            let scoring = build_scoring(&severity, &explanation, &matched_facts, evidence_ptrs_count);

            // Build evidence_unavailable_reason if no pointers but some were dropped
            let evidence_reason = if evidence_ptrs_count == 0 && dropped_evidence_count > 0 {
                Some(serde_json::json!({
                    "code": "EVIDENCE_DROPPED",
                    "message": format!("{} evidence pointers were dropped during analysis (storage limit or segment unavailable)", dropped_evidence_count)
                }))
            } else if evidence_ptrs_count == 0 {
                Some(serde_json::json!({
                    "code": "NO_EVIDENCE_GENERATED",
                    "message": "No evidence pointers were generated for this signal. The detector may not support evidence linking."
                }))
            } else {
                None
            };

            Ok(serde_json::json!({
                "available": true,
                "signal": {
                    "signal_id": signal_id,
                    "signal_type": signal_type,
                    "severity": severity,
                    "ts": ts,
                    "proc_key": proc_key,
                    "host": host
                },
                "source": "signal_explanations",
                "narrative": narrative,
                "evidence_ptrs": evidence_ptrs,
                "evidence_ptrs_count": evidence_ptrs_count,
                "dropped_evidence_count": dropped_evidence_count,
                "evidence_unavailable_reason": evidence_reason,
                "evidence_diagnostics": evidence_diagnostics,
                "scoring": scoring,
                "matched_facts": matched_facts,
                "matched_slots": explanation.get("slots"),
                "entities": entities,
                "explanation": explanation
            }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            // No stored explanation - build deterministic fallback
            let narrative = build_narrative(&signal_type, &severity, &serde_json::json!({}), &matched_facts, evidence_ptrs_count, &proc_key);
            let scoring = build_scoring(&severity, &serde_json::json!({}), &matched_facts, evidence_ptrs_count);
            
            // Determine evidence unavailable reason with detailed diagnostics
            let evidence_reason = if evidence_ptrs_count == 0 && dropped_evidence_count > 0 {
                Some(serde_json::json!({
                    "code": "EVIDENCE_DROPPED",
                    "message": format!("{} evidence pointers were dropped during analysis (storage limit or segment unavailable)", dropped_evidence_count)
                }))
            } else if evidence_ptrs_count == 0 {
                Some(serde_json::json!({
                    "code": "LINKAGE_MISSING",
                    "message": "Signal exists but evidence pointers were not linked during analysis. This may be a pipeline issue."
                }))
            } else {
                None
            };

            Ok(serde_json::json!({
                "available": true,
                "reason_code": "EXPLANATION_NOT_STORED",
                "message": "Signal exists but detailed explanation was not stored. Showing computed explanation.",
                "signal": {
                    "signal_id": signal_id,
                    "signal_type": signal_type,
                    "severity": severity,
                    "ts": ts,
                    "proc_key": proc_key,
                    "host": host
                },
                "source": "computed",
                "narrative": narrative,
                "evidence_ptrs": evidence_ptrs,
                "evidence_ptrs_count": evidence_ptrs_count,
                "dropped_evidence_count": dropped_evidence_count,
                "evidence_unavailable_reason": evidence_reason,
                "evidence_diagnostics": evidence_diagnostics,
                "scoring": scoring,
                "matched_facts": matched_facts,
                "matched_slots": null,
                "entities": entities
            }))
        }
        Err(e) => Err(format!("Query error: {}", e)),
    }
}

/// Build a deterministic narrative from structured evidence
fn build_narrative(
    signal_type: &str,
    severity: &str,
    explanation: &serde_json::Value,
    matched_facts: &[serde_json::Value],
    evidence_count: usize,
    proc_key: &Option<String>,
) -> String {
    // Check if explanation has a stored narrative/summary
    if let Some(summary) = explanation.get("summary").and_then(|s| s.as_str()) {
        if !summary.is_empty() {
            return summary.to_string();
        }
    }
    if let Some(why) = explanation.get("why_fired").and_then(|s| s.as_str()) {
        if !why.is_empty() {
            return why.to_string();
        }
    }
    
    // Build deterministic narrative from available data
    let mut parts = Vec::new();
    
    // Opening statement
    let signal_name = signal_type.replace('_', " ");
    parts.push(format!(
        "This {} severity finding was triggered by the {} detector.",
        severity, signal_name
    ));
    
    // Process context if available
    if let Some(pk) = proc_key {
        parts.push(format!("The activity was associated with process: {}.", pk));
    }
    
    // Matched facts summary
    if !matched_facts.is_empty() {
        let fact_types: Vec<&str> = matched_facts.iter()
            .filter_map(|f| f.get("fact_type").and_then(|t| t.as_str()))
            .collect();
        if !fact_types.is_empty() {
            let unique_types: std::collections::HashSet<&str> = fact_types.into_iter().collect();
            parts.push(format!(
                "{} supporting facts were observed, including: {}.",
                matched_facts.len(),
                unique_types.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    
    // Evidence summary
    if evidence_count > 0 {
        parts.push(format!(
            "{} evidence pointer{} linked to this finding.",
            evidence_count,
            if evidence_count == 1 { " is" } else { "s are" }
        ));
    } else {
        parts.push("No evidence pointers are currently linked to this finding.".to_string());
    }
    
    parts.join(" ")
}

/// Build scoring object (always returns valid object)
fn build_scoring(
    severity: &str,
    explanation: &serde_json::Value,
    matched_facts: &[serde_json::Value],
    evidence_count: usize,
) -> serde_json::Value {
    // Check if explanation has stored scoring
    if let Some(scoring) = explanation.get("scoring") {
        if scoring.get("risk_score").is_some() || scoring.get("severity").is_some() {
            return scoring.clone();
        }
    }
    
    // Build minimal scoring from available data
    let mut basis = Vec::new();
    
    // Severity-based confidence
    let confidence = match severity {
        "critical" | "high" => "high",
        "medium" => "medium",
        _ => "low",
    };
    basis.push(format!("Base severity: {}", severity));
    
    // Facts-based scoring
    if !matched_facts.is_empty() {
        basis.push(format!("{} supporting facts observed", matched_facts.len()));
    } else {
        basis.push("No linked facts (reduces confidence)".to_string());
    }
    
    // Evidence-based scoring
    if evidence_count > 0 {
        basis.push(format!("{} evidence pointers linked", evidence_count));
    } else {
        basis.push("No evidence pointers (linkage may be incomplete)".to_string());
    }
    
    serde_json::json!({
        "severity": severity,
        "confidence": confidence,
        "basis": basis
    })
}

/// Build evidence diagnostics object for pipeline transparency
fn build_evidence_diagnostics(
    evidence_ptrs: &[serde_json::Value],
    dropped_count: usize,
    metadata: &Option<serde_json::Value>,
) -> serde_json::Value {
    let total_count = evidence_ptrs.len();
    
    // Analyze evidence pointer types and validity
    let mut dereferenceable = 0;
    let mut segment_missing = 0;
    let mut malformed = 0;
    let mut by_kind: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    
    for ptr in evidence_ptrs {
        let kind = ptr.get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or("segment_record");
        *by_kind.entry(kind.to_string()).or_insert(0) += 1;
        
        // Check if dereferenceable
        if kind == "segment_record" {
            if ptr.get("segment_id").is_some() && ptr.get("record_index").is_some() {
                dereferenceable += 1;
            } else if ptr.get("segment_id").is_none() {
                segment_missing += 1;
            } else {
                malformed += 1;
            }
        }
    }
    
    // Determine overall health
    let health = if total_count == 0 && dropped_count == 0 {
        "none"
    } else if total_count == 0 && dropped_count > 0 {
        "dropped"
    } else if dereferenceable == total_count && dropped_count == 0 {
        "full"
    } else if dereferenceable > 0 {
        "partial"
    } else {
        "degraded"
    };
    
    // Build issues list
    let mut issues = Vec::new();
    if dropped_count > 0 {
        issues.push(format!("{} pointers dropped (storage limit)", dropped_count));
    }
    if segment_missing > 0 {
        issues.push(format!("{} pointers missing segment reference", segment_missing));
    }
    if malformed > 0 {
        issues.push(format!("{} malformed pointers", malformed));
    }
    
    // Check metadata for pipeline hints
    let pipeline_version = metadata
        .as_ref()
        .and_then(|m| m.get("pipeline_version"))
        .and_then(|v| v.as_str());
    let source_sensor = metadata
        .as_ref()
        .and_then(|m| m.get("source_sensor"))
        .and_then(|v| v.as_str());
    
    serde_json::json!({
        "total_count": total_count,
        "dereferenceable_count": dereferenceable,
        "dropped_count": dropped_count,
        "health": health,
        "by_kind": by_kind,
        "issues": issues,
        "pipeline_version": pipeline_version,
        "source_sensor": source_sensor
    })
}

/// Get matched facts for a signal based on entity keys
fn get_matched_facts_for_signal(
    conn: &rusqlite::Connection,
    proc_key: &Option<String>,
    host: &Option<String>,
) -> Vec<serde_json::Value> {
    let mut facts = Vec::new();
    
    // Query facts matching the process key
    if let Some(pk) = proc_key {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT fact_type, entity_keys, ts FROM facts 
             WHERE json_extract(entity_keys, '$.proc_key') = ?
             ORDER BY ts DESC
             LIMIT 10"
        ) {
            if let Ok(rows) = stmt.query_map([pk], |row| {
                let fact_type: String = row.get(0)?;
                let entity_keys_str: Option<String> = row.get(1)?;
                let ts: i64 = row.get(2)?;
                let entity_keys: serde_json::Value = entity_keys_str
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(serde_json::json!({}));
                Ok(serde_json::json!({
                    "fact_type": fact_type,
                    "entity_keys": entity_keys,
                    "ts": ts
                }))
            }) {
                for row in rows.flatten() {
                    facts.push(row);
                }
            }
        }
    }
    
    // If no facts from proc_key, try host-based query
    if facts.is_empty() {
        if let Some(h) = host {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT fact_type, entity_keys, ts FROM facts 
                 WHERE json_extract(entity_keys, '$.host_key') = ?
                 ORDER BY ts DESC
                 LIMIT 5"
            ) {
                if let Ok(rows) = stmt.query_map([h], |row| {
                    let fact_type: String = row.get(0)?;
                    let entity_keys_str: Option<String> = row.get(1)?;
                    let ts: i64 = row.get(2)?;
                    let entity_keys: serde_json::Value = entity_keys_str
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or(serde_json::json!({}));
                    Ok(serde_json::json!({
                        "fact_type": fact_type,
                        "entity_keys": entity_keys,
                        "ts": ts
                    }))
                }) {
                    for row in rows.flatten() {
                        facts.push(row);
                    }
                }
            }
        }
    }
    
    facts
}

// ============================================================================
// Signal Statistics
// ============================================================================

/// Get signal statistics for a run
pub fn get_signal_stats(db_path: &Path) -> Result<serde_json::Value, String> {
    let conn = open_db_with_wal(db_path).map_err(|e| format!("DB error: {}", e))?;

    // Total count
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM signals", [], |row| row.get(0))
        .unwrap_or(0);

    // By severity
    let mut by_severity: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    if let Ok(mut stmt) = conn.prepare("SELECT severity, COUNT(*) FROM signals GROUP BY severity") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        }) {
            for row in rows.flatten() {
                by_severity.insert(row.0, row.1);
            }
        }
    }

    // By type
    let mut by_type: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    if let Ok(mut stmt) = conn.prepare("SELECT signal_type, COUNT(*) FROM signals GROUP BY signal_type")
    {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        }) {
            for row in rows.flatten() {
                by_type.insert(row.0, row.1);
            }
        }
    }

    // Time range
    let (earliest_ts, latest_ts): (i64, i64) = conn
        .query_row(
            "SELECT COALESCE(MIN(ts), 0), COALESCE(MAX(ts), 0) FROM signals",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or((0, 0));

    Ok(serde_json::json!({
        "total": total,
        "by_severity": by_severity,
        "by_type": by_type,
        "earliest_ts": earliest_ts,
        "latest_ts": latest_ts
    }))
}

/// Get explainability statistics for a run
pub fn get_explainability_stats(db_path: &Path) -> Result<serde_json::Value, String> {
    let conn = open_db_with_wal(db_path).map_err(|e| format!("DB error: {}", e))?;

    // Total signals
    let total_signals: i64 = conn
        .query_row("SELECT COUNT(*) FROM signals", [], |row| row.get(0))
        .unwrap_or(0);

    // Signals with explanations
    let with_explanations: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signal_explanations",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // Signals with evidence
    let with_evidence: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signals WHERE evidence_ptrs IS NOT NULL AND evidence_ptrs != '[]'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let coverage_pct = if total_signals > 0 {
        (with_explanations as f64 / total_signals as f64) * 100.0
    } else {
        0.0
    };

    let evidence_pct = if total_signals > 0 {
        (with_evidence as f64 / total_signals as f64) * 100.0
    } else {
        0.0
    };

    Ok(serde_json::json!({
        "total_signals": total_signals,
        "with_explanations": with_explanations,
        "with_evidence": with_evidence,
        "explanation_coverage_pct": coverage_pct,
        "evidence_coverage_pct": evidence_pct
    }))
}

// ============================================================================
// Top Signals Helper
// ============================================================================

/// Get top signals for a run (sorted by severity)
pub fn get_top_signals(db_path: &Path, limit: usize) -> Vec<serde_json::Value> {
    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut signals = Vec::new();
    let query = r#"
        SELECT signal_id, signal_type, severity, ts, host, proc_key, evidence_ptrs
        FROM signals
        ORDER BY 
            CASE severity 
                WHEN 'critical' THEN 0 
                WHEN 'high' THEN 1 
                WHEN 'medium' THEN 2 
                WHEN 'low' THEN 3 
                ELSE 4 
            END,
            ts DESC
        LIMIT ?
    "#;

    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([limit as i64], |row| {
            let signal_id: String = row.get(0)?;
            let signal_type: String = row.get(1)?;
            let severity: String = row.get(2)?;
            let ts: i64 = row.get(3)?;
            let host: Option<String> = row.get(4)?;
            let proc_key: Option<String> = row.get(5)?;
            let evidence_ptrs: Option<String> = row.get(6)?;

            Ok(serde_json::json!({
                "signal_id": signal_id,
                "signal_type": signal_type,
                "severity": severity,
                "ts": ts,
                "host": host,
                "proc_key": proc_key,
                "evidence_preview": evidence_ptrs.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            }))
        }) {
            for row in rows.flatten() {
                signals.push(row);
            }
        }
    }

    signals
}

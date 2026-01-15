//! EDR Locald entry point - Windows signal detection daemon
//!
//! Pipeline: segments/*.jsonl -> extract_facts -> HypothesisController -> Incidents -> signals table -> edr-server
//!
//! This is the FULL detection pipeline that uses:
//! - PlaybookDef: Windows playbook definitions with slot predicates
//! - extract_facts: Convert Windows events to canonical Facts
//! - HypothesisController: Slot matching, TTL, cooldowns, incident promotion
//! - Signal persistence: Store fired incidents as signals for API
//! - ExplanationBundle: Full explainability for each signal

use chrono::Utc;
use edr_core::{Event, EvidencePtr};
use edr_locald::explanation_builder::build_explanation_from_hypothesis;
use edr_locald::explanation_reason::{ExplanationReasonCode, SignalContext, UnavailableExplanation};
use edr_locald::hypothesis::{Fact, FactType};
use edr_locald::hypothesis_controller::HypothesisController;
use edr_locald::os::windows::{extract_facts, WindowsSignalEngine};
use edr_locald::playbook_manager::PlaybookManager;
use edr_locald::scoring::ScoringEngine;
use edr_locald::signal_result::SignalResult;
use edr_locald::slot_matcher::PlaybookDef;
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Get telemetry root from env or default
fn get_telemetry_root() -> PathBuf {
    std::env::var("EDR_TELEMETRY_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                PathBuf::from(r"C:\ProgramData\edr")
            } else {
                PathBuf::from("/var/lib/edr")
            }
        })
}

/// Index file structure
#[derive(Debug, Deserialize)]
struct SegmentIndex {
    #[allow(dead_code)]
    schema_version: u32,
    segments: Vec<SegmentEntry>,
}

#[derive(Debug, Deserialize)]
struct SegmentEntry {
    #[serde(alias = "path", alias = "rel_path")]
    path: Option<String>,
    #[allow(dead_code)]
    stream_id: Option<String>,
}

impl SegmentEntry {
    fn get_path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

/// Parse a segment JSONL record into edr_core::Event
fn parse_segment_record(line: &str, segment_id: u64, record_index: u32) -> Option<Event> {
    let parsed: serde_json::Value = serde_json::from_str(line).ok()?;

    let ts_ms = parsed.get("ts_ms")?.as_i64()?;
    let host = parsed.get("host")?.as_str()?.to_string();

    let tags: Vec<String> = parsed
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    // Extract fields from the "fields" object
    let fields: BTreeMap<String, serde_json::Value> = parsed
        .get("fields")
        .and_then(|v| v.as_object())
        .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    // Build evidence pointer from segment record
    let evidence_ptr = parsed.get("evidence_ptr").and_then(|ep| {
        let stream_id = ep.get("stream_id")?.as_str()?.to_string();
        Some(EvidencePtr {
            stream_id,
            segment_id,
            record_index,
        })
    });

    Some(Event {
        ts_ms,
        host,
        tags,
        proc_key: parsed
            .get("proc_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        file_key: parsed
            .get("file_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        identity_key: parsed
            .get("identity_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        evidence_ptr,
        fields,
    })
}

/// Convert an incident to a SignalResult for database persistence
fn incident_to_signal(incident: &edr_locald::hypothesis::Incident, hostname: &str) -> SignalResult {
    use edr_locald::signal_result::EvidenceRef;

    let evidence_refs: Vec<EvidenceRef> = incident
        .evidence_ptrs_summary
        .iter()
        .map(|ep| EvidenceRef {
            stream_id: ep.stream_id.clone(),
            segment_id: ep.segment_id.clone(),
            record_index: ep.record_index,
        })
        .collect();

    // Build metadata JSON
    let metadata = serde_json::json!({
        "family": incident.family,
        "primary_scope_key": format!("{:?}", incident.primary_scope_key),
        "confidence": incident.confidence,
        "mitre_techniques": incident.mitre_techniques,
        "tags": incident.tags.iter().collect::<Vec<_>>(),
        "promoted_from": incident.promoted_from_hypothesis_ids,
    });

    SignalResult {
        signal_id: incident.incident_id.clone(),
        signal_type: format!("playbook:{}", incident.family),
        severity: format!("{:?}", incident.severity),
        host: hostname.to_string(),
        ts: incident.first_ts.timestamp_millis(),
        ts_start: incident.first_ts.timestamp_millis(),
        ts_end: incident.last_ts.timestamp_millis(),
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptrs: evidence_refs,
        dropped_evidence_count: 0,
        metadata,
    }
}

/// Get fact type discriminant string for coverage tracking
fn fact_type_name(fact: &Fact) -> &'static str {
    match &fact.fact_type {
        FactType::ProcSpawn { .. } => "ProcSpawn",
        FactType::Exec { .. } => "Exec",
        FactType::OutboundConnect { .. } => "OutboundConnect",
        FactType::InboundConnect { .. } => "InboundConnect",
        FactType::DnsResolve { .. } => "DnsResolve",
        FactType::WritePath { .. } => "WritePath",
        FactType::ReadPath { .. } => "ReadPath",
        FactType::CreatePath { .. } => "CreatePath",
        FactType::DeletePath { .. } => "DeletePath",
        FactType::RenamePath { .. } => "RenamePath",
        FactType::PersistArtifact { .. } => "PersistArtifact",
        FactType::PrivilegeBoundary { .. } => "PrivilegeBoundary",
        FactType::MemWX { .. } => "MemWX",
        FactType::MemAlloc { .. } => "MemAlloc",
        FactType::ModuleLoad { .. } => "ModuleLoad",
        FactType::Injection { .. } => "Injection",
        FactType::RegistryMod { .. } => "RegistryMod",
        FactType::AuthEvent { .. } => "AuthEvent",
        FactType::LogTamper { .. } => "LogTamper",
        FactType::SecurityToolDisable { .. } => "SecurityToolDisable",
        FactType::ShellCommand { .. } => "ShellCommand",
        FactType::ScriptExec { .. } => "ScriptExec",
        FactType::ProcessAccess { .. } => "ProcessAccess",
        FactType::Unknown { .. } => "Unknown",
    }
}

/// Extract entity key from fact for entity rollup (Part C)
fn extract_entity_key(fact: &Fact, entity_type: &str) -> Option<String> {
    match entity_type {
        "process" => {
            // Extract process key from scope_key or fact_type
            match &fact.scope_key {
                edr_locald::hypothesis::ScopeKey::Process { key } => Some(key.clone()),
                _ => match &fact.fact_type {
                    FactType::Exec { path, .. } => Some(path.clone()),
                    FactType::ProcSpawn { child_proc_key, .. } => Some(child_proc_key.clone()),
                    FactType::ShellCommand { shell, .. } => Some(shell.clone()),
                    FactType::ScriptExec { interpreter, .. } => Some(interpreter.clone()),
                    _ => None,
                },
            }
        }
        "user" => {
            // Extract user/identity key
            match &fact.scope_key {
                edr_locald::hypothesis::ScopeKey::User { key } => Some(key.clone()),
                _ => match &fact.fact_type {
                    FactType::AuthEvent { user, .. } => Some(user.clone()),
                    _ => None,
                },
            }
        }
        "network" => {
            // Extract network destination
            match &fact.fact_type {
                FactType::OutboundConnect { dst_ip, dst_port, .. } => {
                    Some(format!("{}:{}", dst_ip, dst_port))
                }
                FactType::InboundConnect { src_ip, src_port, .. } => {
                    Some(format!("{}:{}", src_ip, src_port))
                }
                FactType::DnsResolve { query, .. } => Some(query.clone()),
                _ => None,
            }
        }
        "file" => {
            // Extract file path
            match &fact.fact_type {
                FactType::WritePath { path, .. } => Some(path.clone()),
                FactType::ReadPath { path, .. } => Some(path.clone()),
                FactType::CreatePath { path, .. } => Some(path.clone()),
                FactType::DeletePath { path, .. } => Some(path.clone()),
                FactType::RenamePath { old_path, .. } => Some(old_path.clone()),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Record coverage rollup data (fact types and signal types seen per minute)
fn record_coverage_rollup(
    db: &Connection,
    host: &str,
    sensor_mode: &str,
    fact_type: Option<&str>,
    signal_type: Option<&str>,
    enabled_caps: &str,
) {
    let ts_minute = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0)) as i64;
    
    // Fix: Correct parameter binding for coverage_rollup
    // Schema: ts_minute, host, sensor_mode, fact_type, fact_count, signal_type, signal_count, enabled_capabilities
    let signal_count_val = if signal_type.is_some() { 1 } else { 0 };
    let _ = db.execute(
        "INSERT INTO coverage_rollup (ts_minute, host, sensor_mode, fact_type, fact_count, signal_type, signal_count, enabled_capabilities) 
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)
         ON CONFLICT(ts_minute, host, sensor_mode, fact_type, signal_type) DO UPDATE SET 
         fact_count = fact_count + CASE WHEN excluded.fact_type IS NOT NULL THEN 1 ELSE 0 END,
         signal_count = signal_count + CASE WHEN excluded.signal_type IS NOT NULL THEN 1 ELSE 0 END",
        params![ts_minute, host, sensor_mode, fact_type, signal_type, signal_count_val, enabled_caps],
    );
}

/// Record entity rollup for top-N tracking (Part C)
fn record_entity_rollup(
    db: &Connection,
    run_id: &str,
    entity_type: &str,
    entity_key: &str,
    ts: i64,
) {
    let _ = db.execute(
        "INSERT INTO entity_rollup (run_id, entity_type, entity_key, fact_count, first_ts, last_ts)
         VALUES (?1, ?2, ?3, 1, ?4, ?4)
         ON CONFLICT(run_id, entity_type, entity_key) DO UPDATE SET
         fact_count = fact_count + 1,
         last_ts = MAX(last_ts, excluded.last_ts)",
        params![run_id, entity_type, entity_key, ts],
    );
}

// =============================================================================
// FACTS SAMPLE PERSISTENCE (Discovery Mode V1 - Hybrid Persistence)
// =============================================================================

/// Discovery categories - ALWAYS persist all facts in these categories
const DISCOVERY_CATEGORIES: &[&str] = &["services", "tasks", "log_tamper", "registry_persistence", "persistence"];

/// Max exemplars per fact_type for non-discovery categories
const MAX_EXEMPLARS_PER_TYPE: usize = 200;

/// Determine the category for a fact (used for pivoting and selective persistence)
fn fact_category(fact_type_name: &str) -> &'static str {
    match fact_type_name {
        "PersistArtifact" => "persistence",
        "RegistryMod" => "registry_persistence",
        "LogTamper" => "log_tamper",
        "AuthEvent" => "auth",
        "PrivilegeBoundary" => "auth",
        "Exec" | "ProcSpawn" | "ShellCommand" | "ScriptExec" => "process",
        "OutboundConnect" | "InboundConnect" | "DnsResolve" => "network",
        "WritePath" | "ReadPath" | "CreatePath" | "DeletePath" | "RenamePath" => "file",
        "ModuleLoad" => "modules",
        "MemWX" | "MemAlloc" | "Injection" | "ProcessAccess" => "memory",
        "SecurityToolDisable" => "evasion",
        _ => "other",
    }
}

/// Check if a category is a discovery category (always persist)
fn is_discovery_category(category: &str) -> bool {
    DISCOVERY_CATEGORIES.contains(&category)
}

/// Extract entity key for facts_sample (for pivot filtering)
fn fact_entity_key(fact: &Fact) -> Option<String> {
    match &fact.fact_type {
        FactType::PersistArtifact { artifact_type, path_or_key, .. } => {
            // Map artifact type to entity key prefix
            use edr_locald::hypothesis::canonical_fact::PersistenceType;
            let prefix = match artifact_type {
                PersistenceType::Service => "service",
                PersistenceType::ScheduledTask => "task",
                PersistenceType::RegistryRunKey => "reg",
                PersistenceType::LaunchAgent | PersistenceType::LaunchDaemon => "launchd",
                PersistenceType::CronJob => "cron",
                PersistenceType::SystemdService => "systemd",
                PersistenceType::SshAuthorizedKey => "ssh",
                PersistenceType::ShellProfile => "profile",
                PersistenceType::Other(_) => "persist",
            };
            Some(format!("{}:{}", prefix, path_or_key))
        }
        FactType::RegistryMod { key, .. } => Some(format!("reg:{}", key)),
        FactType::LogTamper { log_type, .. } => Some(format!("log:{}", log_type)),
        FactType::AuthEvent { user, auth_type, .. } => {
            Some(format!("user:{}:{:?}", user, auth_type))
        }
        FactType::Exec { path, .. } => Some(format!("exe:{}", path)),
        FactType::ProcSpawn { child_proc_key, .. } => Some(format!("proc:{}", child_proc_key)),
        FactType::ShellCommand { command, .. } => {
            let truncated = if command.len() > 50 { &command[..50] } else { command };
            Some(format!("cmd:{}", truncated))
        }
        FactType::ScriptExec { interpreter, .. } => Some(format!("script:{}", interpreter)),
        FactType::OutboundConnect { dst_ip, dst_port, .. } => Some(format!("net:{}:{}", dst_ip, dst_port)),
        FactType::DnsResolve { query, .. } => Some(format!("dns:{}", query)),
        FactType::WritePath { path, .. } | FactType::CreatePath { path, .. } => {
            Some(format!("file:{}", path))
        }
        _ => None,
    }
}

/// Serialize fact details to JSON for storage
fn fact_to_details_json(fact: &Fact) -> String {
    // Serialize the fact_type variant with its fields
    match serde_json::to_string(&fact.fact_type) {
        Ok(json) => json,
        Err(_) => "{}".to_string(),
    }
}

/// Persist a fact sample to the database (hybrid persistence strategy)
/// Returns true if persisted, false if skipped (exemplar cap reached)
fn persist_fact_sample(
    db: &Connection,
    fact: &Fact,
    fact_type_name: &str,
    exemplar_counts: &mut std::collections::HashMap<String, usize>,
) -> bool {
    let category = fact_category(fact_type_name);
    let is_discovery = is_discovery_category(category);
    
    // Check exemplar cap for non-discovery categories
    if !is_discovery {
        let count = exemplar_counts.entry(fact_type_name.to_string()).or_insert(0);
        if *count >= MAX_EXEMPLARS_PER_TYPE {
            return false; // Skip - cap reached
        }
        *count += 1;
    }
    
    let fact_id = format!("fact_{}_{}", fact.ts.timestamp_millis(), uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0"));
    let ts = fact.ts.timestamp_millis();
    let entity_key = fact_entity_key(fact);
    let details_json = fact_to_details_json(fact);
    
    // Serialize full fact struct for Fact Inspector (TWEAK B)
    let fact_json = serde_json::to_string(fact).unwrap_or_else(|_| "{}".to_string());
    
    // Serialize evidence pointers (use first if available)
    let evidence_ptrs_str = if !fact.evidence_ptrs.is_empty() {
        serde_json::to_string(&fact.evidence_ptrs).ok()
    } else {
        None
    };
    
    let result = db.execute(
        "INSERT OR IGNORE INTO facts_sample (fact_id, ts, fact_type, category, host, entity_key, details_json, fact_json, evidence_ptrs)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            fact_id,
            ts,
            fact_type_name,
            category,
            fact.host_id,
            entity_key,
            details_json,
            fact_json,
            evidence_ptrs_str
        ],
    );
    
    result.is_ok()
}

/// Initialize playbook evaluation rollup (Part B)
/// Call once at start to seed all loaded playbooks with no_match status
/// Non-selected playbooks are marked as "not_selected" and won't be evaluated
fn init_playbook_eval_rollup(
    db: &Connection,
    run_id: &str,
    playbooks: &HashMap<String, PlaybookDef>,
    readiness: &serde_json::Value,
    selected_playbooks: &Option<HashSet<String>>,
) {
    let is_admin = readiness.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
    let sysmon_installed = readiness.get("sysmon_installed").and_then(|v| v.as_bool()).unwrap_or(false);
    let security_log_accessible = readiness.get("security_log_accessible").and_then(|v| v.as_bool()).unwrap_or(is_admin);
    
    for (playbook_id, playbook) in playbooks {
        let total_slots = playbook.slots.len() as i32;
        let missing_slot_names: Vec<String> = playbook.slots.iter().map(|s| s.name.clone()).collect();
        let missing_json = serde_json::to_string(&missing_slot_names).unwrap_or_default();
        
        // Check if this playbook is selected (None means all selected)
        let is_selected = selected_playbooks.as_ref()
            .map(|sel| sel.contains(playbook_id))
            .unwrap_or(true);
        
        // Determine if this playbook requires specific telemetry
        let requires_sysmon = playbook.slots.iter().any(|s| {
            let ft = s.predicate.fact_type.to_lowercase();
            ft.contains("exec") || ft.contains("proc") || ft.contains("module") || ft.contains("inject")
        });
        let requires_security_log = playbook.slots.iter().any(|s| {
            let ft = s.predicate.fact_type.to_lowercase();
            ft.contains("auth") || ft.contains("logon") || ft.contains("privilege")
        });
        
        // Determine if telemetry is blocked
        let telemetry_blocked = (requires_sysmon && !sysmon_installed) || 
                                 (requires_security_log && !security_log_accessible);
        
        // Determine status: not_selected > telemetry_missing > no_match
        let status = if !is_selected {
            "not_selected"
        } else if telemetry_blocked {
            "telemetry_missing"
        } else {
            "no_match"
        };
        
        let why_not = if !is_selected {
            serde_json::to_string(&vec!["Not selected for this run"]).unwrap_or_default()
        } else if telemetry_blocked {
            let mut reasons: Vec<&str> = Vec::new();
            if requires_sysmon && !sysmon_installed { reasons.push("Sysmon not installed"); }
            if requires_security_log && !security_log_accessible { reasons.push("Security log not accessible"); }
            serde_json::to_string(&reasons).unwrap_or_default()
        } else {
            "[]".to_string()
        };
        
        let _ = db.execute(
            "INSERT OR REPLACE INTO playbook_eval_rollup 
             (run_id, playbook_id, playbook_name, category, status, total_slots, matched_slots, 
              completion_ratio, matched_slot_names, missing_slot_names, why_not_fired,
              requires_sysmon, requires_security_log, telemetry_blocked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0.0, '[]', ?7, ?8, ?9, ?10, ?11)",
            params![
                run_id,
                playbook_id,
                playbook.title,
                playbook.family,
                status,
                total_slots,
                missing_json,
                why_not,
                requires_sysmon as i32,
                requires_security_log as i32,
                telemetry_blocked as i32,
            ],
        );
    }
}

/// Update playbook evaluation state when slots are filled
fn update_playbook_eval_progress(
    db: &Connection,
    run_id: &str,
    playbook_id: &str,
    matched_slot_names: &[String],
    missing_slot_names: &[String],
    status: &str,
    ts: i64,
    evidence_ptrs: Option<&[serde_json::Value]>,
) {
    let total = (matched_slot_names.len() + missing_slot_names.len()) as i32;
    let matched = matched_slot_names.len() as i32;
    let ratio = if total > 0 { matched as f64 / total as f64 } else { 0.0 };
    
    let matched_json = serde_json::to_string(matched_slot_names).unwrap_or_default();
    let missing_json = serde_json::to_string(missing_slot_names).unwrap_or_default();
    
    let why_not = if !missing_slot_names.is_empty() {
        let reasons: Vec<String> = missing_slot_names.iter().map(|s| format!("Missing slot: {}", s)).collect();
        serde_json::to_string(&reasons).unwrap_or_default()
    } else {
        "[]".to_string()
    };
    
    // Evidence pointers sample (up to 3 for fired playbooks)
    let evidence_sample = evidence_ptrs
        .map(|ptrs| {
            let sample: Vec<&serde_json::Value> = ptrs.iter().take(3).collect();
            serde_json::to_string(&sample).unwrap_or_default()
        })
        .unwrap_or_else(|| "[]".to_string());
    
    let _ = db.execute(
        "UPDATE playbook_eval_rollup SET
         status = ?3, matched_slots = ?4, completion_ratio = ?5,
         matched_slot_names = ?6, missing_slot_names = ?7, why_not_fired = ?8,
         evidence_ptrs_sample = ?9, last_progress_ts = ?10, updated_at = CURRENT_TIMESTAMP
         WHERE run_id = ?1 AND playbook_id = ?2",
        params![run_id, playbook_id, status, matched, ratio, matched_json, missing_json, why_not, evidence_sample, ts],
    );
}

fn main() {
    let telemetry_root = get_telemetry_root();

    eprintln!("edr-locald starting (FULL PIPELINE MODE)");
    eprintln!("TELEMETRY_ROOT: {}", telemetry_root.display());

    // TASK B: Read run_id from env var (passed by edr-server)
    let run_id = std::env::var("EDR_RUN_ID").unwrap_or_else(|_| {
        // Fallback: derive from telemetry_root path (e.g., runs/run_20260110_123456)
        telemetry_root
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("run_{}", chrono::Local::now().format("%Y%m%d_%H%M%S")))
    });
    eprintln!("RUN_ID: {}", run_id);

    // Check workflow seed env var (for backward compatibility)
    let workflow_seed = std::env::var("EDR_WORKFLOW_SEED")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);
    if workflow_seed {
        eprintln!("EDR_WORKFLOW_SEED: enabled (will also emit synthetic WorkflowSeed signal)");
    }

    // Ensure directories exist
    let segments_dir = telemetry_root.join("segments");
    if let Err(e) = fs::create_dir_all(&segments_dir) {
        eprintln!("ERROR: Failed to create segments dir: {}", e);
        return;
    }

    // Initialize SQLite database (use same db as edr-server for API compatibility)
    let db_path = telemetry_root.join("workbench.db");
    let db = match Connection::open(&db_path) {
        Ok(conn) => {
            // CRITICAL: Enable WAL mode for concurrent read/write access
            // This allows the server process to read while locald writes
            if let Err(e) = conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA busy_timeout=5000;
                 PRAGMA temp_store=MEMORY;"
            ) {
                eprintln!("WARNING: Failed to set WAL pragmas: {}", e);
            }
            
            // Create signals table (same schema as edr-server for /api/signals)
            // TASK B: Added run_id column for consistent signal filtering
            let _ = conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS signals (
                    signal_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL DEFAULT 'unknown',
                    signal_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    host TEXT NOT NULL,
                    ts INTEGER NOT NULL,
                    ts_start INTEGER NOT NULL,
                    ts_end INTEGER NOT NULL,
                    proc_key TEXT,
                    file_key TEXT,
                    identity_key TEXT,
                    metadata TEXT NOT NULL,
                    evidence_ptrs TEXT NOT NULL,
                    dropped_evidence_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_signals_ts ON signals(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_signals_type ON signals(signal_type);
                CREATE INDEX IF NOT EXISTS idx_signals_host ON signals(host);
                CREATE INDEX IF NOT EXISTS idx_signals_severity ON signals(severity);
                CREATE INDEX IF NOT EXISTS idx_signals_run_id ON signals(run_id);

                CREATE TABLE IF NOT EXISTS signal_explanations (
                    signal_id TEXT PRIMARY KEY,
                    explanation_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (signal_id) REFERENCES signals(signal_id)
                );
                CREATE INDEX IF NOT EXISTS idx_explanations_signal ON signal_explanations(signal_id);

                CREATE TABLE IF NOT EXISTS locald_checkpoint (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS coverage_rollup (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts_minute INTEGER NOT NULL,
                    host TEXT NOT NULL,
                    sensor_mode TEXT,
                    fact_type TEXT,
                    fact_count INTEGER DEFAULT 0,
                    event_count INTEGER DEFAULT 0,
                    signal_type TEXT,
                    signal_count INTEGER DEFAULT 0,
                    enabled_capabilities TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ts_minute, host, sensor_mode, fact_type, signal_type)
                );
                CREATE INDEX IF NOT EXISTS idx_coverage_ts ON coverage_rollup(ts_minute DESC);
                
                -- Segments table for tracking processed segments
                CREATE TABLE IF NOT EXISTS segments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    segment_id TEXT NOT NULL UNIQUE,
                    segment_path TEXT NOT NULL,
                    records INTEGER NOT NULL DEFAULT 0,
                    facts INTEGER NOT NULL DEFAULT 0,
                    signals INTEGER NOT NULL DEFAULT 0,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_segments_id ON segments(segment_id);
                
                -- Entity rollup for top-N tracking (Part C)
                CREATE TABLE IF NOT EXISTS entity_rollup (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_key TEXT NOT NULL,
                    fact_count INTEGER DEFAULT 1,
                    first_ts INTEGER,
                    last_ts INTEGER,
                    UNIQUE(run_id, entity_type, entity_key)
                );
                CREATE INDEX IF NOT EXISTS idx_entity_run ON entity_rollup(run_id);
                CREATE INDEX IF NOT EXISTS idx_entity_type ON entity_rollup(entity_type, fact_count DESC);
                
                -- Playbook evaluation rollup for slot progress tracking (Part B)
                CREATE TABLE IF NOT EXISTS playbook_eval_rollup (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    playbook_id TEXT NOT NULL,
                    playbook_name TEXT,
                    category TEXT,
                    status TEXT NOT NULL DEFAULT 'no_match',
                    total_slots INTEGER NOT NULL DEFAULT 0,
                    matched_slots INTEGER NOT NULL DEFAULT 0,
                    completion_ratio REAL DEFAULT 0.0,
                    matched_slot_names TEXT,
                    missing_slot_names TEXT,
                    why_not_fired TEXT,
                    evidence_ptrs_sample TEXT,
                    last_progress_ts INTEGER,
                    requires_sysmon INTEGER DEFAULT 0,
                    requires_security_log INTEGER DEFAULT 0,
                    telemetry_blocked INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(run_id, playbook_id)
                );
                CREATE INDEX IF NOT EXISTS idx_playbook_eval_run ON playbook_eval_rollup(run_id);
                CREATE INDEX IF NOT EXISTS idx_playbook_eval_status ON playbook_eval_rollup(status);
                
                -- Facts sample table for Discovery Mode V1 (hybrid persistence)
                -- Always persist: discovery categories (services, tasks, log_clear, registry persistence)
                -- Cap others: N exemplars per fact_type (default N=200)
                CREATE TABLE IF NOT EXISTS facts_sample (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fact_id TEXT NOT NULL UNIQUE,
                    ts INTEGER NOT NULL,
                    fact_type TEXT NOT NULL,
                    category TEXT NOT NULL,
                    host TEXT NOT NULL,
                    entity_key TEXT,
                    details_json TEXT NOT NULL,
                    fact_json TEXT,
                    evidence_ptrs TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_facts_sample_type ON facts_sample(fact_type);
                CREATE INDEX IF NOT EXISTS idx_facts_sample_category ON facts_sample(category);
                CREATE INDEX IF NOT EXISTS idx_facts_sample_ts ON facts_sample(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_facts_sample_entity ON facts_sample(entity_key);",
            );
            
            // Auto-migration: Add fact_json column to existing DBs (safe to call multiple times)
            // SQLite will error if column exists, which we silently ignore
            let _ = conn.execute("ALTER TABLE facts_sample ADD COLUMN fact_json TEXT", []);
            
            eprintln!("Database: {}", db_path.display());
            conn
        }
        Err(e) => {
            eprintln!("FATAL: Failed to open database: {}", e);
            return;
        }
    };

    // Initialize hostname
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    eprintln!("Host: {}", hostname);

    // Initialize HypothesisController (the core of playbook-based detection)
    let mut hypothesis_controller = HypothesisController::new(&hostname);

    // Load playbooks via PlaybookManager (deterministic path, fail-loud)
    let mut playbook_manager = PlaybookManager::new();
    if !playbook_manager.load_default() {
        eprintln!("ERROR: No playbooks loaded! Detection will not work.");
        eprintln!("       Check playbook configuration and ensure playbooks are available.");
    }
    playbook_manager.log_summary();
    
    // Check for playbook selection filter (passed from supervisor)
    let selected_playbooks: Option<HashSet<String>> = std::env::var("EDR_SELECTED_PLAYBOOKS")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.split(',').map(|p| p.trim().to_string()).collect());
    
    let selection_mode = std::env::var("EDR_SELECTION_MODE").unwrap_or_else(|_| "preset".to_string());
    let selection_preset = std::env::var("EDR_SELECTION_PRESET").ok();
    
    if let Some(ref selected) = selected_playbooks {
        eprintln!("Playbook selection: {} playbooks selected (mode={}, preset={:?})", 
            selected.len(), selection_mode, selection_preset);
    } else {
        eprintln!("Playbook selection: ALL playbooks (mode={}, preset={:?})", 
            selection_mode, selection_preset);
    }
    
    // Register playbooks with hypothesis controller
    // Only register selected playbooks if selection is active
    let playbook_count = playbook_manager.loaded_count();
    let mut playbook_map: HashMap<String, PlaybookDef> = HashMap::new();
    let mut registered_count = 0usize;
    
    for playbook in playbook_manager.playbooks_owned() {
        let is_selected = selected_playbooks.as_ref()
            .map(|sel| sel.contains(&playbook.playbook_id))
            .unwrap_or(true); // If no selection, all are selected
        
        playbook_map.insert(playbook.playbook_id.clone(), playbook.clone());
        
        if is_selected {
            eprintln!(
                "  [playbook] Registered: {} (family={}, slots={})",
                playbook.playbook_id,
                playbook.family,
                playbook.slots.len()
            );
            hypothesis_controller.register_playbook(playbook);
            registered_count += 1;
        } else {
            eprintln!(
                "  [playbook] Skipped (not selected): {}",
                playbook.playbook_id
            );
        }
    }
    eprintln!("Registered {}/{} playbooks with HypothesisController", registered_count, playbook_count);

    // Track facts for explanation building
    let mut facts_store: Vec<Fact> = Vec::new();

    // Initialize legacy WindowsSignalEngine (for WorkflowSeed only if enabled)
    let mut signal_engine = WindowsSignalEngine::new(hostname.clone());

    // Initialize scoring engine
    let scoring_engine = ScoringEngine::new(false);

    // Track processed segments
    let mut seen_segments: HashSet<String> = HashSet::new();

    // Load checkpoint
    if let Ok(checkpoint) = db.query_row::<String, _, _>(
        "SELECT value FROM locald_checkpoint WHERE key = 'seen_segments'",
        [],
        |row| row.get(0),
    ) {
        for seg in checkpoint.split(',') {
            if !seg.is_empty() {
                seen_segments.insert(seg.to_string());
            }
        }
        eprintln!(
            "Resumed from checkpoint with {} segments",
            seen_segments.len()
        );
    }

    // Load readiness snapshot from run_meta.json (for playbook telemetry checks)
    let readiness_snapshot: serde_json::Value = {
        let meta_path = telemetry_root.join("run_meta.json");
        std::fs::read_to_string(&meta_path)
            .ok()
            .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
            .and_then(|v| v.get("readiness_snapshot").cloned())
            .unwrap_or(serde_json::json!({}))
    };
    eprintln!("Readiness snapshot loaded: {}", readiness_snapshot);
    
    // Initialize playbook evaluation rollup with all playbooks
    // Pass selection to mark non-selected playbooks appropriately
    init_playbook_eval_rollup(&db, &run_id, &playbook_map, &readiness_snapshot, &selected_playbooks);
    eprintln!("Initialized playbook eval rollup for {} playbooks ({} selected)", 
        playbook_map.len(), 
        selected_playbooks.as_ref().map(|s| s.len()).unwrap_or(playbook_map.len()));

    // Setup graceful shutdown
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        eprintln!("\n[locald] Shutting down...");
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .ok();

    let index_path = telemetry_root.join("index.json");
    eprintln!("Watching: {}", index_path.display());
    eprintln!("(Press Ctrl+C to stop)");

    let mut total_events = 0u64;
    let mut total_facts = 0u64;
    let mut total_signals = 0u64;
    let mut incidents_fired: HashSet<String> = HashSet::new();
    
    // Exemplar counts for hybrid persistence (cap non-discovery categories)
    let mut exemplar_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    // Main loop
    while !shutdown.load(Ordering::Relaxed) {
        // Read index.json
        if let Ok(index_content) = fs::read_to_string(&index_path) {
            if let Ok(index) = serde_json::from_str::<SegmentIndex>(&index_content) {
                for entry in &index.segments {
                    let entry_path = match entry.get_path() {
                        Some(p) => p.to_string(),
                        None => continue,
                    };

                    if seen_segments.contains(&entry_path) {
                        continue;
                    }

                    let segment_path = telemetry_root.join(&entry_path);
                    if !segment_path.exists() {
                        continue;
                    }

                    // Extract segment_id from filename (e.g., "segments/1234.jsonl" -> 1234)
                    let segment_id: u64 = segment_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);

                    eprintln!("[ingest] Processing: {}", entry_path);

                    if let Ok(content) = fs::read_to_string(&segment_path) {
                        let mut segment_events = 0u32;
                        let mut segment_facts = 0u32;
                        let mut segment_signals = 0u32;

                        for (record_index, line) in content.lines().enumerate() {
                            if line.trim().is_empty() {
                                continue;
                            }

                            if let Some(event) =
                                parse_segment_record(line, segment_id, record_index as u32)
                            {
                                segment_events += 1;

                                // === FULL PIPELINE: Extract Facts ===
                                let facts = extract_facts(&event);
                                segment_facts += facts.len() as u32;

                                // === FULL PIPELINE: Feed Facts to HypothesisController ===
                                for fact in &facts {
                                    // Record coverage for this fact type
                                    let ft_name = fact_type_name(fact);
                                    record_coverage_rollup(&db, &hostname, "ETW", Some(ft_name), None, "proc_exec,file_ops,netconnect,registry");
                                    
                                    // Persist fact sample (hybrid persistence - discovery always, capped for others)
                                    persist_fact_sample(&db, fact, ft_name, &mut exemplar_counts);
                                    
                                    // Extract and record entity rollup (Part C)
                                    let ts_ms = fact.ts.timestamp_millis();
                                    if let Some(entity_key) = extract_entity_key(fact, "process") {
                                        record_entity_rollup(&db, &run_id, "process", &entity_key, ts_ms);
                                    }
                                    if let Some(entity_key) = extract_entity_key(fact, "user") {
                                        record_entity_rollup(&db, &run_id, "user", &entity_key, ts_ms);
                                    }
                                    if let Some(entity_key) = extract_entity_key(fact, "network") {
                                        record_entity_rollup(&db, &run_id, "network", &entity_key, ts_ms);
                                    }
                                    if let Some(entity_key) = extract_entity_key(fact, "file") {
                                        record_entity_rollup(&db, &run_id, "file", &entity_key, ts_ms);
                                    }
                                    // Always record host
                                    record_entity_rollup(&db, &run_id, "host", &fact.host_id, ts_ms);
                                    
                                    // Store fact for explanation building
                                    facts_store.push(fact.clone());

                                    match hypothesis_controller.ingest_fact(fact.clone()) {
                                        Ok(affected_hypotheses) => {
                                            if !affected_hypotheses.is_empty() {
                                                eprintln!(
                                                    "    [fact] Affected {} hypotheses",
                                                    affected_hypotheses.len()
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("    [fact] Error: {}", e);
                                        }
                                    }
                                }

                                // === LEGACY: WorkflowSeed signal if enabled ===
                                if workflow_seed {
                                    let legacy_signals = signal_engine.process_event(&event);
                                    for signal in legacy_signals {
                                        segment_signals += 1;
                                        let scored = scoring_engine.score(signal.clone());
                                        persist_signal(&db, &signal, &scored.risk_score, &run_id);
                                        eprintln!(
                                            "  [signal] {} severity={} risk={:.2}",
                                            scored.signal.signal_type,
                                            scored.signal.severity,
                                            scored.risk_score
                                        );
                                    }
                                }
                            }
                        }

                        // === FULL PIPELINE: Check for fired incidents ===
                        // HypothesisController promotes hypotheses to incidents automatically
                        hypothesis_controller.expire_hypotheses();

                        // Persist any new incidents as signals with explanations
                        let all_incidents = hypothesis_controller.all_incidents();
                        for incident in all_incidents {
                            if !incidents_fired.contains(&incident.incident_id) {
                                // Convert incident to signal and persist
                                let signal = incident_to_signal(incident, &hostname);
                                segment_signals += 1;
                                
                                // Record coverage for signal
                                record_coverage_rollup(&db, &hostname, "ETW", None, Some(&signal.signal_type), "proc_exec,file_ops,netconnect,registry");

                                let evidence_json = serde_json::to_string(&signal.evidence_ptrs)
                                    .unwrap_or_else(|_| "[]".to_string());
                                let metadata_json = signal.metadata.to_string();
                                let created_at = Utc::now().to_rfc3339();

                                // === TRANSACTIONAL SIGNAL + EXPLANATION WRITE ===
                                // INVARIANT: Every signal MUST have an explanation row.
                                // Write both in same transaction for atomicity.
                                let tx_result = db.execute("BEGIN TRANSACTION", []);
                                
                                if tx_result.is_err() {
                                    eprintln!("  [error] Failed to begin transaction for {}", signal.signal_id);
                                    continue;
                                }

                                // Write signal row
                                let signal_result = db.execute(
                                    "INSERT OR REPLACE INTO signals
                                     (signal_id, run_id, signal_type, severity, host, ts, ts_start, ts_end, proc_key, file_key, identity_key, metadata, evidence_ptrs, dropped_evidence_count, created_at)
                                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                                    params![
                                        signal.signal_id,
                                        &run_id,
                                        signal.signal_type,
                                        signal.severity,
                                        signal.host,
                                        signal.ts,
                                        signal.ts_start,
                                        signal.ts_end,
                                        signal.proc_key,
                                        signal.file_key,
                                        signal.identity_key,
                                        metadata_json,
                                        evidence_json,
                                        signal.dropped_evidence_count,
                                        &created_at
                                    ],
                                );

                                if signal_result.is_err() {
                                    let _ = db.execute("ROLLBACK", []);
                                    eprintln!("  [error] Failed to write signal {}", signal.signal_id);
                                    continue;
                                }

                                // === BUILD EXPLANATION WITH PRECISE REASON CODES ===
                                let (explanation_json, explanation_status) = build_explanation_with_reason(
                                    incident,
                                    &hypothesis_controller,
                                    &playbook_map,
                                    &telemetry_root,
                                    &facts_store,
                                    &signal,
                                );
                                
                                // Write explanation row (ALWAYS - either full or unavailable stub)
                                let explain_result = db.execute(
                                    "INSERT OR REPLACE INTO signal_explanations
                                     (signal_id, explanation_json, created_at)
                                     VALUES (?1, ?2, ?3)",
                                    params![signal.signal_id, explanation_json, &created_at],
                                );

                                if explain_result.is_err() {
                                    let _ = db.execute("ROLLBACK", []);
                                    eprintln!("  [error] Failed to write explanation for {}", signal.signal_id);
                                    continue;
                                }

                                // Commit transaction
                                let commit_result = db.execute("COMMIT", []);
                                if commit_result.is_err() {
                                    eprintln!("  [error] Failed to commit transaction for {}", signal.signal_id);
                                    continue;
                                }
                                
                                // Log outcome
                                match &explanation_status {
                                    ExplanationStatus::Available { slots, evidence } => {
                                        eprintln!(
                                            "  [explanation:available] {} → {} slots, {} evidence",
                                            signal.signal_id, slots, evidence
                                        );
                                    }
                                    ExplanationStatus::Unavailable { reason } => {
                                        eprintln!(
                                            "  [explanation:unavailable] {} → reason={}",
                                            signal.signal_id, reason.as_str()
                                        );
                                    }
                                }
                                
                                // Update playbook_eval_rollup if we have playbook info
                                if let Some(hyp_id) = incident.promoted_from_hypothesis_ids.first() {
                                    if let Some(hypothesis) = hypothesis_controller.get_hypothesis(hyp_id) {
                                        if let Some(playbook) = playbook_map.get(&hypothesis.template_id) {
                                            let matched_slots: Vec<String> = playbook.slots.iter().map(|s| s.name.clone()).collect();
                                            // Convert EvidenceRef to JSON values for the progress update
                                            let evidence_json: Vec<serde_json::Value> = signal.evidence_ptrs.iter()
                                                .map(|e| serde_json::to_value(e).unwrap_or(serde_json::json!({})))
                                                .collect();
                                            update_playbook_eval_progress(
                                                &db,
                                                &run_id,
                                                &playbook.playbook_id,
                                                &matched_slots,
                                                &[], // No missing slots when fired
                                                "fired",
                                                signal.ts,
                                                Some(&evidence_json),
                                            );
                                        }
                                    }
                                }

                                eprintln!(
                                    "  [persisted] {} → {} severity={:?}",
                                    signal.signal_id, signal.signal_type, incident.severity
                                );

                                incidents_fired.insert(incident.incident_id.clone());
                            }
                        }

                        // Check active hypotheses for debugging
                        let active = hypothesis_controller.active_hypotheses();
                        if !active.is_empty() {
                            eprintln!("  [hypothesis] {} active hypotheses", active.len());
                        }

                        total_events += segment_events as u64;
                        total_facts += segment_facts as u64;
                        total_signals += segment_signals as u64;

                        // Record segment in segments table for run stats
                        let segment_size = fs::metadata(&segment_path).map(|m| m.len()).unwrap_or(0);
                        let segment_id_str = format!("evtx_{:06}", segment_id);
                        let _ = db.execute(
                            "INSERT OR REPLACE INTO segments (segment_id, segment_path, records, facts, signals, size_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            params![segment_id_str, entry_path, segment_events, segment_facts, segment_signals, segment_size as i64],
                        );

                        eprintln!(
                            "  [done] {} events, {} facts, {} signals (total: {} events, {} facts, {} signals)",
                            segment_events, segment_facts, segment_signals, total_events, total_facts, total_signals
                        );
                    }

                    seen_segments.insert(entry_path.clone());

                    // Save checkpoint
                    let checkpoint = seen_segments.iter().cloned().collect::<Vec<_>>().join(",");
                    let _ = db.execute(
                        "INSERT OR REPLACE INTO locald_checkpoint (key, value) VALUES ('seen_segments', ?1)",
                        params![checkpoint],
                    );
                }
            }
        }

        // Poll every 2 seconds
        std::thread::sleep(Duration::from_secs(2));
    }

    eprintln!(
        "edr-locald stopped. Total: {} events, {} facts, {} signals",
        total_events, total_facts, total_signals
    );
}

/// Status of explanation building
enum ExplanationStatus {
    Available { slots: usize, evidence: usize },
    Unavailable { reason: ExplanationReasonCode },
}

/// Build explanation with precise reason codes
///
/// Returns (explanation_json, status) where:
/// - explanation_json is ALWAYS valid JSON (either full ExplanationBundle or UnavailableExplanation)
/// - status indicates availability and reason
fn build_explanation_with_reason(
    incident: &edr_locald::hypothesis::Incident,
    hypothesis_controller: &HypothesisController,
    playbook_map: &HashMap<String, PlaybookDef>,
    telemetry_root: &std::path::Path,
    facts_store: &[Fact],
    signal: &SignalResult,
) -> (String, ExplanationStatus) {
    // Build strict signal context (ONLY verbatim signal row fields - no inference)
    let signal_ctx = SignalContext::new(&signal.signal_id)
        .with_type(&signal.signal_type)
        .with_severity(&signal.severity)
        .with_host(&signal.host)
        .with_ts(signal.ts);
    
    // Check for hypothesis
    let hyp_id = match incident.promoted_from_hypothesis_ids.first() {
        Some(id) => id,
        None => {
            let unavail = UnavailableExplanation::new(ExplanationReasonCode::MissingHypothesis)
                .with_signal_context(signal_ctx);
            return (
                serde_json::to_string(&unavail).unwrap_or_else(|_| r#"{"available":false,"reason_code":"JSON_SERIALIZE_FAILED"}"#.to_string()),
                ExplanationStatus::Unavailable { reason: ExplanationReasonCode::MissingHypothesis },
            );
        }
    };

    // Get hypothesis
    let hypothesis = match hypothesis_controller.get_hypothesis(hyp_id) {
        Some(h) => h,
        None => {
            let unavail = UnavailableExplanation::new(ExplanationReasonCode::MissingHypothesis)
                .with_signal_context(signal_ctx);
            return (
                serde_json::to_string(&unavail).unwrap_or_else(|_| r#"{"available":false,"reason_code":"JSON_SERIALIZE_FAILED"}"#.to_string()),
                ExplanationStatus::Unavailable { reason: ExplanationReasonCode::MissingHypothesis },
            );
        }
    };

    // Get playbook
    let playbook = match playbook_map.get(&hypothesis.template_id) {
        Some(p) => p,
        None => {
            let unavail = UnavailableExplanation::new(ExplanationReasonCode::MissingPlaybook)
                .with_signal_context(signal_ctx);
            return (
                serde_json::to_string(&unavail).unwrap_or_else(|_| r#"{"available":false,"reason_code":"JSON_SERIALIZE_FAILED"}"#.to_string()),
                ExplanationStatus::Unavailable { reason: ExplanationReasonCode::MissingPlaybook },
            );
        }
    };

    // Check facts store
    if facts_store.is_empty() {
        let unavail = UnavailableExplanation::new(ExplanationReasonCode::MissingFactsStore)
            .with_signal_context(signal_ctx);
        return (
            serde_json::to_string(&unavail).unwrap_or_else(|_| r#"{"available":false,"reason_code":"JSON_SERIALIZE_FAILED"}"#.to_string()),
            ExplanationStatus::Unavailable { reason: ExplanationReasonCode::MissingFactsStore },
        );
    }

    // Build full explanation
    let explanation = build_explanation_from_hypothesis(
        hypothesis,
        incident,
        playbook,
        telemetry_root,
        facts_store,
    );

    // Serialize
    match serde_json::to_string(&explanation) {
        Ok(json) => (
            json,
            ExplanationStatus::Available {
                slots: explanation.slots.len(),
                evidence: explanation.evidence.len(),
            },
        ),
        Err(_) => {
            let unavail = UnavailableExplanation::new(ExplanationReasonCode::JsonSerializeFailed)
                .with_signal_context(signal_ctx);
            (
                serde_json::to_string(&unavail).unwrap_or_else(|_| r#"{"available":false,"reason_code":"JSON_SERIALIZE_FAILED"}"#.to_string()),
                ExplanationStatus::Unavailable { reason: ExplanationReasonCode::JsonSerializeFailed },
            )
        }
    }
}

/// Persist a signal to the database
/// TASK B: Added run_id parameter for consistent signal stamping
fn persist_signal(db: &Connection, signal: &SignalResult, _risk_score: &f64, run_id: &str) {
    let evidence_json =
        serde_json::to_string(&signal.evidence_ptrs).unwrap_or_else(|_| "[]".to_string());
    let metadata_json = signal.metadata.to_string();
    let created_at = Utc::now().to_rfc3339();

    let _ = db.execute(
        "INSERT OR REPLACE INTO signals
         (signal_id, run_id, signal_type, severity, host, ts, ts_start, ts_end, proc_key, file_key, identity_key, metadata, evidence_ptrs, dropped_evidence_count, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            signal.signal_id,
            run_id,
            signal.ts_end,
            signal.proc_key,
            signal.file_key,
            Option::<String>::None, // identity_key
            metadata_json,
            evidence_json,
            signal.dropped_evidence_count,
            created_at
        ],
    );
}

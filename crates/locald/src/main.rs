//! EDR Locald entry point - Windows signal detection daemon
//!
//! Pipeline: segments/*.jsonl -> flatten_event_xml -> extract_facts -> YAML playbook engine
//! -> signals table + signal_explanations table -> edr-server
//!
//! Detection logic lives in the YAML files under playbooks/windows. At startup
//! edr-locald loads them (see edr_locald::playbook::loader for the directory
//! order and EDR_SELECTED_PLAYBOOKS), writes playbooks_loaded.json into the
//! telemetry root, and then runs every fact through the engine.
//!
//! Flags:
//! - `--once`: process the segments listed in index.json one time and exit
//!   instead of polling. Used for replaying a capture and by the end to end test.

use chrono::Utc;
use edr_core::{Event, EvidencePtr};
use edr_locald::explanation_builder::build_explanation_from_match;
use edr_locald::os::windows::{extract_facts, flatten_event_xml, WindowsSignalEngine};
use edr_locald::playbook::{self, PlaybookEngine, PlaybookMatch};
use edr_locald::scoring::ScoringEngine;
use edr_locald::signal_result::{EvidenceRef, SignalResult};
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
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

    // Build evidence pointer from segment record. The capture agent writes the
    // segment sequence and record index it assigned, so prefer those and fall
    // back to the file name and line position.
    let evidence_ptr = parsed.get("evidence_ptr").and_then(|ep| {
        let stream_id = ep.get("stream_id")?.as_str()?.to_string();
        Some(EvidencePtr {
            stream_id,
            segment_id: ep
                .get("segment_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(segment_id),
            record_index: ep
                .get("record_index")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
                .unwrap_or(record_index),
        })
    });

    let mut event = Event {
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
    };
    flatten_event_xml(&mut event);
    Some(event)
}

/// Convert a playbook match to a SignalResult for database persistence
fn match_to_signal(m: &PlaybookMatch) -> SignalResult {
    let evidence_ptrs: Vec<EvidenceRef> = m
        .facts
        .iter()
        .flat_map(|f| f.fact.evidence_ptrs.iter())
        .map(|ep| EvidenceRef {
            stream_id: ep.stream_id.clone(),
            segment_id: ep.segment_id.clone(),
            record_index: ep.record_index,
        })
        .collect();

    let metadata = serde_json::json!({
        "playbook_id": m.playbook_id,
        "playbook_title": m.playbook_title,
        "rule": m.rule_name,
        "family": m.family,
        "attack_version": m.attack_version,
        "mitre_techniques": m.techniques,
        "mitre_tactics": m.tactics,
        "group_by": m.group_by,
        "group_key": m.group_key,
        "tags": m.tags,
        "fact_count": m.facts.len(),
    });

    SignalResult {
        signal_id: m.signal_id.clone(),
        signal_type: format!("playbook:{}", m.playbook_id),
        severity: m.severity.clone(),
        host: m.host.clone(),
        ts: m.first_ts_ms,
        ts_start: m.first_ts_ms,
        ts_end: m.last_ts_ms,
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptrs,
        dropped_evidence_count: 0,
        metadata,
    }
}

/// Load playbooks, log the result, and write the status file the desktop app reads.
fn load_playbooks(telemetry_root: &Path) -> PlaybookEngine {
    let report = playbook::load_from_env(telemetry_root);

    match &report.dir {
        Some(dir) => eprintln!("Playbook dir: {} (from {})", dir.path.display(), dir.source),
        None => eprintln!("Playbook dir: none found"),
    }
    if let Some(sel) = &report.selected {
        eprintln!("Selected playbooks ({}): {}", sel.len(), sel.join(", "));
    }
    for pb in &report.playbooks {
        eprintln!(
            "  [playbook] Loaded: {} ({} rules, ATT&CK {})",
            pb.id,
            pb.rules.len(),
            pb.technique_ids().join(" ")
        );
    }
    for id in &report.disabled {
        eprintln!("  [playbook] Disabled in file: {}", id);
    }
    for id in &report.unknown_selected {
        eprintln!("  [playbook] WARNING: selected but not found: {}", id);
    }
    for err in &report.errors {
        eprintln!("  [playbook] ERROR: {} {}", err.file, err.error);
    }
    eprintln!(
        "Loaded {} Windows playbooks ({} rules) from {} files",
        report.playbooks.len(),
        report.rule_count(),
        report.files_found
    );

    let status_path = telemetry_root.join(playbook::STATUS_FILE_NAME);
    match serde_json::to_string_pretty(&report.status_json()) {
        Ok(json) => {
            if let Err(e) = fs::write(&status_path, json) {
                eprintln!("WARNING: could not write {}: {}", status_path.display(), e);
            }
        }
        Err(e) => eprintln!("WARNING: could not serialize playbook status: {}", e),
    }

    PlaybookEngine::new(report.playbooks)
}

/// Write one playbook match and its explanation to the database.
fn persist_match(
    db: &Connection,
    engine: &PlaybookEngine,
    m: &PlaybookMatch,
    telemetry_root: &Path,
) {
    let signal = match_to_signal(m);
    let evidence_json =
        serde_json::to_string(&signal.evidence_ptrs).unwrap_or_else(|_| "[]".to_string());
    let metadata_json = signal.metadata.to_string();
    let created_at = Utc::now().to_rfc3339();

    if let Err(e) = db.execute(
        "INSERT OR REPLACE INTO signals
         (signal_id, signal_type, severity, host, ts, ts_start, ts_end, proc_key, file_key, identity_key, metadata, evidence_ptrs, dropped_evidence_count, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            signal.signal_id,
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
    ) {
        eprintln!("  [signal] ERROR writing {}: {}", signal.signal_id, e);
        return;
    }

    if let Some(pb) = engine.playbook(&m.playbook_id) {
        let explanation = build_explanation_from_match(m, pb, telemetry_root);
        if let Ok(explanation_json) = serde_json::to_string(&explanation) {
            let _ = db.execute(
                "INSERT OR REPLACE INTO signal_explanations
                 (signal_id, explanation_json, created_at)
                 VALUES (?1, ?2, ?3)",
                params![signal.signal_id, explanation_json, &created_at],
            );
        }
    }

    eprintln!(
        "  [signal] {} {} rule=\"{}\" severity={} techniques={}",
        signal.signal_id,
        signal.signal_type,
        m.rule_name,
        m.severity,
        m.techniques.join(",")
    );
}

fn main() {
    let telemetry_root = get_telemetry_root();
    let run_once = std::env::args().any(|a| a == "--once");

    eprintln!("edr-locald starting (YAML playbook engine)");
    eprintln!("TELEMETRY_ROOT: {}", telemetry_root.display());

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
            // Create signals table (same schema as edr-server for /api/signals)
            let _ = conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS signals (
                    signal_id TEXT PRIMARY KEY,
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
                );",
            );
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

    // Load YAML playbooks (the single source of detection logic)
    let mut engine = load_playbooks(&telemetry_root);

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
    if run_once {
        eprintln!("(--once: processing the current index and exiting)");
    } else {
        eprintln!("(Press Ctrl+C to stop)");
    }

    let mut total_events = 0u64;
    let mut total_facts = 0u64;
    let mut total_signals = 0u64;

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

                    // Segment number from the file name: "segments/1234.jsonl" -> 1234,
                    // "segments/evtx_000012.jsonl" -> 12
                    let segment_id: u64 = segment_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .and_then(|s| s.rsplit('_').next())
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

                                // Extract facts, then run them through the playbooks
                                let facts = extract_facts(&event);
                                segment_facts += facts.len() as u32;

                                for m in engine.process(&event, &facts) {
                                    persist_match(&db, &engine, &m, &telemetry_root);
                                    segment_signals += 1;
                                }

                                // === LEGACY: WorkflowSeed signal if enabled ===
                                if workflow_seed {
                                    let legacy_signals = signal_engine.process_event(&event);
                                    for signal in legacy_signals {
                                        segment_signals += 1;
                                        let scored = scoring_engine.score(signal.clone());
                                        persist_signal(&db, &signal, &scored.risk_score);
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

                        total_events += segment_events as u64;
                        total_facts += segment_facts as u64;
                        total_signals += segment_signals as u64;

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

        if run_once {
            break;
        }

        // Poll every 2 seconds
        std::thread::sleep(Duration::from_secs(2));
    }

    eprintln!(
        "edr-locald stopped. Total: {} events, {} facts, {} signals",
        total_events, total_facts, total_signals
    );
}

/// Persist a signal to the database
fn persist_signal(db: &Connection, signal: &SignalResult, _risk_score: &f64) {
    let evidence_json =
        serde_json::to_string(&signal.evidence_ptrs).unwrap_or_else(|_| "[]".to_string());
    let metadata_json = signal.metadata.to_string();
    let created_at = Utc::now().to_rfc3339();

    let _ = db.execute(
        "INSERT OR REPLACE INTO signals
         (signal_id, signal_type, severity, host, ts, ts_start, ts_end, proc_key, file_key, identity_key, metadata, evidence_ptrs, dropped_evidence_count, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            signal.signal_id,
            signal.signal_type,
            signal.severity,
            signal.host,
            signal.ts,
            signal.ts_start,
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

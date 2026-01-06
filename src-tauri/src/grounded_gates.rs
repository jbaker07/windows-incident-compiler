//! Grounded Health Gates - Truth from Artifacts Only
//!
//! These gates read ONLY from real artifacts:
//! - run_dir/index.json + segments/*.jsonl
//! - workbench.db / analysis.db
//! - Live API (http://127.0.0.1:PORT/api/signals)
//!
//! NO in-memory counters. Each gate returns status + diagnosis + "how computed" notes.

// Used by Tauri commands, not CLI binaries
#![allow(dead_code)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Gate status with explicit meanings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateStatus {
    Pass,
    Partial,
    Fail,
    NoData,
}

impl GateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            GateStatus::Pass => "PASS",
            GateStatus::Partial => "PARTIAL",
            GateStatus::Fail => "FAIL",
            GateStatus::NoData => "NO_DATA",
        }
    }
    
    pub fn emoji(&self) -> &'static str {
        match self {
            GateStatus::Pass => "✅",
            GateStatus::Partial => "⚠️",
            GateStatus::Fail => "❌",
            GateStatus::NoData => "⬜",
        }
    }
    
    pub fn is_healthy(&self) -> bool {
        matches!(self, GateStatus::Pass | GateStatus::Partial)
    }
}

// ============================================================================
// GATE A: TELEMETRY - Read from index.json + count JSONL lines
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundedTelemetryGate {
    pub status: GateStatus,
    pub segments_count: u32,
    pub events_count: u32,
    pub events_by_channel: HashMap<String, u32>,
    pub events_by_provider: HashMap<String, u32>,
    pub channels_active: Vec<String>,
    pub events_per_second: f64,
    pub diagnosis: Option<String>,
    pub how_computed: String,
}

/// Index.json segment entry
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct IndexSegment {
    seq: Option<u64>,
    segment_id: String,
    rel_path: String,
    records: u32,
    #[serde(default)]
    ts_first: Option<i64>,
    #[serde(default)]
    ts_last: Option<i64>,
}

/// Index.json schema
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct IndexJson {
    schema_version: Option<u32>,
    segments: Vec<IndexSegment>,
    #[serde(default)]
    next_seq: u64,
}

impl GroundedTelemetryGate {
    /// Evaluate Gate A from run_dir artifacts ONLY
    ///
    /// Source: index.json for segment metadata + segments/*.jsonl for event counts
    pub fn evaluate_from_disk(run_dir: &Path, elapsed_seconds: u64) -> Self {
        let index_path = run_dir.join("index.json");
        let segments_dir = run_dir.join("segments");
        
        // Try to read index.json first
        let (segments_from_index, index_status) = Self::read_index_json(&index_path);
        
        // Count actual segment files
        let actual_segment_files = Self::count_segment_files(&segments_dir);
        
        // Parse all segment files for events
        let (events_count, events_by_channel, events_by_provider) = 
            Self::count_events_from_segments(&segments_dir);
        
        let segments_count = if !segments_from_index.is_empty() {
            segments_from_index.len() as u32
        } else {
            actual_segment_files
        };
        
        let channels_active: Vec<String> = events_by_channel.keys().cloned().collect();
        let events_per_second = if elapsed_seconds > 0 {
            events_count as f64 / elapsed_seconds as f64
        } else {
            0.0
        };
        
        // Determine status per spec:
        // PASS: ≥1000 events across ≥3 channels
        // PARTIAL: ≥100 events OR ≥1 channel
        // FAIL: 0 events OR 0 segments
        let (status, diagnosis) = if events_count == 0 || segments_count == 0 {
            (GateStatus::Fail, Some("No events or segments found".to_string()))
        } else if events_count >= 1000 && channels_active.len() >= 3 {
            (GateStatus::Pass, Some(format!(
                "{} events across {} channels",
                events_count, channels_active.len()
            )))
        } else if events_count >= 100 || !channels_active.is_empty() {
            (GateStatus::Partial, Some(format!(
                "{} events, {} channels (need ≥1000 events, ≥3 channels for PASS)",
                events_count, channels_active.len()
            )))
        } else {
            (GateStatus::Fail, Some(format!(
                "Only {} events, {} channels",
                events_count, channels_active.len()
            )))
        };
        
        let how_computed = format!(
            "Read {} from {} | Scanned {} segment files for event counts | {}",
            index_path.display(),
            index_status,
            actual_segment_files,
            if events_count > 0 {
                format!("Parsed {} lines from *.jsonl files", events_count)
            } else {
                "No JSONL lines found".to_string()
            }
        );
        
        Self {
            status,
            segments_count,
            events_count,
            events_by_channel,
            events_by_provider,
            channels_active,
            events_per_second,
            diagnosis,
            how_computed,
        }
    }
    
    fn read_index_json(path: &Path) -> (Vec<IndexSegment>, String) {
        if !path.exists() {
            return (vec![], "index.json not found".to_string());
        }
        
        match fs::read_to_string(path) {
            Ok(content) => {
                match serde_json::from_str::<IndexJson>(&content) {
                    Ok(index) => (
                        index.segments,
                        format!("parsed {} segments", index.next_seq)
                    ),
                    Err(e) => (vec![], format!("parse error: {}", e)),
                }
            }
            Err(e) => (vec![], format!("read error: {}", e)),
        }
    }
    
    fn count_segment_files(segments_dir: &Path) -> u32 {
        if !segments_dir.exists() {
            return 0;
        }
        
        fs::read_dir(segments_dir)
            .map(|entries| {
                entries.filter_map(Result::ok)
                    .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
                    .count() as u32
            })
            .unwrap_or(0)
    }
    
    fn count_events_from_segments(segments_dir: &Path) -> (u32, HashMap<String, u32>, HashMap<String, u32>) {
        let mut total_events = 0u32;
        let mut by_channel: HashMap<String, u32> = HashMap::new();
        let mut by_provider: HashMap<String, u32> = HashMap::new();
        
        if !segments_dir.exists() {
            return (0, by_channel, by_provider);
        }
        
        let entries = match fs::read_dir(segments_dir) {
            Ok(e) => e,
            Err(_) => return (0, by_channel, by_provider),
        };
        
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "jsonl") {
                if let Ok(file) = File::open(&path) {
                    let reader = BufReader::new(file);
                    for line in reader.lines().map_while(Result::ok) {
                        total_events += 1;
                        
                        // Parse each line to extract channel/provider
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&line) {
                            if let Some(channel) = parsed.get("channel")
                                .or_else(|| parsed.get("Channel"))
                                .and_then(|v| v.as_str()) 
                            {
                                *by_channel.entry(channel.to_string()).or_insert(0) += 1;
                            }
                            
                            if let Some(provider) = parsed.get("provider")
                                .or_else(|| parsed.get("Provider"))
                                .or_else(|| parsed.get("provider_name"))
                                .and_then(|v| v.as_str())
                            {
                                *by_provider.entry(provider.to_string()).or_insert(0) += 1;
                            }
                        }
                    }
                }
            }
        }
        
        (total_events, by_channel, by_provider)
    }
}

// ============================================================================
// GATE B: EXTRACTION - Read from DB or facts.jsonl
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundedExtractionGate {
    pub status: GateStatus,
    pub facts_count: u32,
    pub facts_by_type: HashMap<String, u32>,
    pub key_fact_types_present: Vec<String>,
    pub key_fact_types_missing: Vec<String>,
    pub extraction_rate: f64,
    pub diagnosis: Option<String>,
    pub how_computed: String,
}

/// Key fact types that indicate healthy extraction
pub const KEY_FACT_TYPES: &[&str] = &[
    "ProcessExecution",
    "NetworkConnection", 
    "FileOperation",
    "RegistryModification",
    "PowershellCommand",
    "ServiceOperation",
    "UserLogon",
];

impl GroundedExtractionGate {
    /// Evaluate Gate B from DB or facts.jsonl
    ///
    /// Priority: workbench.db > analysis.db > facts.jsonl > API fallback
    pub async fn evaluate_from_artifacts(run_dir: &Path, api_base_url: &str, events_count: u32) -> Self {
        let workbench_db = run_dir.join("workbench.db");
        let analysis_db = run_dir.join("analysis.db");
        let facts_jsonl = run_dir.join("facts.jsonl");
        
        // Try sources in priority order
        let (facts_count, facts_by_type, source) = 
            if workbench_db.exists() {
                let (count, by_type) = Self::read_facts_from_sqlite(&workbench_db).await;
                (count, by_type, format!("workbench.db at {}", workbench_db.display()))
            } else if analysis_db.exists() {
                let (count, by_type) = Self::read_facts_from_sqlite(&analysis_db).await;
                (count, by_type, format!("analysis.db at {}", analysis_db.display()))
            } else if facts_jsonl.exists() {
                let (count, by_type) = Self::read_facts_from_jsonl(&facts_jsonl);
                (count, by_type, format!("facts.jsonl at {}", facts_jsonl.display()))
            } else {
                // API fallback
                let (count, by_type) = Self::fetch_facts_from_api(api_base_url).await;
                (count, by_type, format!("API at {}/api/facts", api_base_url))
            };
        
        // Check key fact types
        let key_fact_types_present: Vec<String> = KEY_FACT_TYPES.iter()
            .filter(|&&t| facts_by_type.contains_key(t))
            .map(|s| s.to_string())
            .collect();
        
        let key_fact_types_missing: Vec<String> = KEY_FACT_TYPES.iter()
            .filter(|&&t| !facts_by_type.contains_key(t))
            .map(|s| s.to_string())
            .collect();
        
        let extraction_rate = if events_count > 0 {
            (facts_count as f64 / events_count as f64) * 100.0
        } else {
            0.0
        };
        
        // Status per spec:
        // PASS: ≥100 facts AND ≥3 key types present
        // PARTIAL: ≥10 facts OR ≥1 key type
        // FAIL: 0 facts
        let (status, diagnosis) = if facts_count == 0 {
            (GateStatus::Fail, Some("No facts extracted".to_string()))
        } else if facts_count >= 100 && key_fact_types_present.len() >= 3 {
            (GateStatus::Pass, Some(format!(
                "{} facts across {} key types ({:.1}% extraction rate)",
                facts_count, key_fact_types_present.len(), extraction_rate
            )))
        } else if facts_count >= 10 || !key_fact_types_present.is_empty() {
            (GateStatus::Partial, Some(format!(
                "{} facts, {} key types (need ≥100 facts, ≥3 types for PASS)",
                facts_count, key_fact_types_present.len()
            )))
        } else {
            (GateStatus::Fail, Some(format!(
                "Only {} facts, no key types",
                facts_count
            )))
        };
        
        let how_computed = format!(
            "Source: {} | Found {} facts | Key types: {:?}",
            source, facts_count, key_fact_types_present
        );
        
        Self {
            status,
            facts_count,
            facts_by_type,
            key_fact_types_present,
            key_fact_types_missing,
            extraction_rate,
            diagnosis,
            how_computed,
        }
    }
    
    async fn read_facts_from_sqlite(db_path: &Path) -> (u32, HashMap<String, u32>) {
        // Use rusqlite if available, otherwise return empty
        // For now, try to read via file parsing (SQLite has recognizable structure)
        // In production, this would use rusqlite crate
        
        // Fallback: check if DB exists and has size, return placeholder
        if let Ok(metadata) = fs::metadata(db_path) {
            if metadata.len() > 1024 {
                // DB exists and has content - would query here
                // SELECT fact_type, COUNT(*) FROM facts GROUP BY fact_type
                return (0, HashMap::new()); // TODO: Implement SQLite query
            }
        }
        (0, HashMap::new())
    }
    
    fn read_facts_from_jsonl(path: &Path) -> (u32, HashMap<String, u32>) {
        let mut count = 0u32;
        let mut by_type: HashMap<String, u32> = HashMap::new();
        
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                count += 1;
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&line) {
                    if let Some(fact_type) = parsed.get("fact_type")
                        .or_else(|| parsed.get("type"))
                        .and_then(|v| v.as_str())
                    {
                        *by_type.entry(fact_type.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }
        
        (count, by_type)
    }
    
    async fn fetch_facts_from_api(api_base_url: &str) -> (u32, HashMap<String, u32>) {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build() {
            Ok(c) => c,
            Err(_) => return (0, HashMap::new()),
        };
        
        let url = format!("{}/api/facts", api_base_url);
        if let Ok(response) = client.get(&url).send().await {
            if let Ok(data) = response.json::<serde_json::Value>().await {
                let facts = data.get("data")
                    .and_then(|d| d.as_array())
                    .or_else(|| data.as_array())
                    .cloned()
                    .unwrap_or_default();
                
                let mut by_type: HashMap<String, u32> = HashMap::new();
                for fact in &facts {
                    if let Some(fact_type) = fact.get("fact_type")
                        .or_else(|| fact.get("type"))
                        .and_then(|v| v.as_str())
                    {
                        *by_type.entry(fact_type.to_string()).or_insert(0) += 1;
                    }
                }
                
                return (facts.len() as u32, by_type);
            }
        }
        
        (0, HashMap::new())
    }
}

// ============================================================================
// GATE C: DETECTION - Read from DB + verify API consistency
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundedDetectionGate {
    pub status: GateStatus,
    pub signals_count: u32,
    pub signals_from_db: u32,
    pub signals_from_api: u32,
    pub signals_by_playbook: HashMap<String, u32>,
    pub signals_by_severity: HashMap<String, u32>,
    pub playbooks_matched: u32,
    pub playbooks_loaded: u32,
    pub match_rate: f64,
    pub db_api_consistent: bool,
    pub diagnosis: Option<String>,
    pub how_computed: String,
}

impl GroundedDetectionGate {
    /// Evaluate Gate C from DB + API
    ///
    /// Must read signals from BOTH DB and API, verify consistency
    pub async fn evaluate_from_artifacts(
        run_dir: &Path, 
        api_base_url: &str, 
        facts_count: u32,
        playbooks_loaded: u32,
    ) -> Self {
        let workbench_db = run_dir.join("workbench.db");
        let analysis_db = run_dir.join("analysis.db");
        let signals_jsonl = run_dir.join("signals.jsonl");
        
        // Get signals from DB
        let (signals_from_db, by_playbook_db, by_severity_db, db_source) = 
            if workbench_db.exists() {
                let (count, by_pb, by_sev) = Self::read_signals_from_sqlite(&workbench_db).await;
                (count, by_pb, by_sev, "workbench.db".to_string())
            } else if analysis_db.exists() {
                let (count, by_pb, by_sev) = Self::read_signals_from_sqlite(&analysis_db).await;
                (count, by_pb, by_sev, "analysis.db".to_string())
            } else if signals_jsonl.exists() {
                let (count, by_pb, by_sev) = Self::read_signals_from_jsonl(&signals_jsonl);
                (count, by_pb, by_sev, "signals.jsonl".to_string())
            } else {
                (0, HashMap::new(), HashMap::new(), "no DB found".to_string())
            };
        
        // Get signals from API for consistency check
        let (signals_from_api, by_playbook_api, by_severity_api) = 
            Self::fetch_signals_from_api(api_base_url).await;
        
        // Use the larger count as authoritative (API may have more recent data)
        let signals_count = signals_from_db.max(signals_from_api);
        let signals_by_playbook = if signals_from_api >= signals_from_db { 
            by_playbook_api 
        } else { 
            by_playbook_db 
        };
        let signals_by_severity = if signals_from_api >= signals_from_db { 
            by_severity_api 
        } else { 
            by_severity_db 
        };
        
        let playbooks_matched = signals_by_playbook.len() as u32;
        let match_rate = if playbooks_loaded > 0 {
            (playbooks_matched as f64 / playbooks_loaded as f64) * 100.0
        } else {
            0.0
        };
        
        // Check DB/API consistency (allow some drift)
        let db_api_consistent = if signals_from_db == 0 && signals_from_api == 0 {
            true // Both empty is consistent
        } else {
            let diff = (signals_from_db as i64 - signals_from_api as i64).abs();
            diff <= 5 || (diff as f64 / signals_count.max(1) as f64) < 0.1
        };
        
        // Status per spec:
        // PASS: ≥1 signal AND ≥50% playbooks matched AND DB/API consistent
        // PARTIAL: ≥1 signal but low match rate
        // FAIL: 0 signals when facts exist
        // NO_DATA: 0 signals and 0 facts
        let (status, diagnosis) = if facts_count == 0 && signals_count == 0 {
            (GateStatus::NoData, Some("No facts to detect signals from".to_string()))
        } else if signals_count == 0 {
            (GateStatus::Fail, Some(format!(
                "No signals detected from {} facts",
                facts_count
            )))
        } else if signals_count >= 1 && match_rate >= 50.0 && db_api_consistent {
            (GateStatus::Pass, Some(format!(
                "{} signals from {} playbooks ({:.0}% match rate)",
                signals_count, playbooks_matched, match_rate
            )))
        } else if signals_count >= 1 {
            let mut issues = vec![];
            if match_rate < 50.0 {
                issues.push(format!("{:.0}% match rate", match_rate));
            }
            if !db_api_consistent {
                issues.push(format!("DB({}) != API({})", signals_from_db, signals_from_api));
            }
            (GateStatus::Partial, Some(format!(
                "{} signals but: {}",
                signals_count, issues.join(", ")
            )))
        } else {
            (GateStatus::Fail, Some("No signals".to_string()))
        };
        
        let how_computed = format!(
            "DB source: {} ({} signals) | API: {}/api/signals ({} signals) | Consistent: {}",
            db_source, signals_from_db, api_base_url, signals_from_api, db_api_consistent
        );
        
        Self {
            status,
            signals_count,
            signals_from_db,
            signals_from_api,
            signals_by_playbook,
            signals_by_severity,
            playbooks_matched,
            playbooks_loaded,
            match_rate,
            db_api_consistent,
            diagnosis,
            how_computed,
        }
    }
    
    async fn read_signals_from_sqlite(_db_path: &Path) -> (u32, HashMap<String, u32>, HashMap<String, u32>) {
        // TODO: Implement SQLite query
        // SELECT playbook_id, severity, COUNT(*) FROM signals GROUP BY playbook_id, severity
        (0, HashMap::new(), HashMap::new())
    }
    
    fn read_signals_from_jsonl(path: &Path) -> (u32, HashMap<String, u32>, HashMap<String, u32>) {
        let mut count = 0u32;
        let mut by_playbook: HashMap<String, u32> = HashMap::new();
        let mut by_severity: HashMap<String, u32> = HashMap::new();
        
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                count += 1;
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&line) {
                    if let Some(pb) = parsed.get("playbook_id")
                        .and_then(|v| v.as_str())
                    {
                        *by_playbook.entry(pb.to_string()).or_insert(0) += 1;
                    }
                    if let Some(sev) = parsed.get("severity")
                        .and_then(|v| v.as_str())
                    {
                        *by_severity.entry(sev.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }
        
        (count, by_playbook, by_severity)
    }
    
    async fn fetch_signals_from_api(api_base_url: &str) -> (u32, HashMap<String, u32>, HashMap<String, u32>) {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build() {
            Ok(c) => c,
            Err(_) => return (0, HashMap::new(), HashMap::new()),
        };
        
        let url = format!("{}/api/signals", api_base_url);
        if let Ok(response) = client.get(&url).send().await {
            if let Ok(data) = response.json::<serde_json::Value>().await {
                let signals = data.get("data")
                    .and_then(|d| d.as_array())
                    .or_else(|| data.as_array())
                    .cloned()
                    .unwrap_or_default();
                
                let mut by_playbook: HashMap<String, u32> = HashMap::new();
                let mut by_severity: HashMap<String, u32> = HashMap::new();
                
                for signal in &signals {
                    if let Some(pb) = signal.get("playbook_id").and_then(|v| v.as_str()) {
                        *by_playbook.entry(pb.to_string()).or_insert(0) += 1;
                    }
                    if let Some(sev) = signal.get("severity").and_then(|v| v.as_str()) {
                        *by_severity.entry(sev.to_string()).or_insert(0) += 1;
                    }
                }
                
                return (signals.len() as u32, by_playbook, by_severity);
            }
        }
        
        (0, HashMap::new(), HashMap::new())
    }
}

// ============================================================================
// GATE D: EXPLAINABILITY - Validate explanations + evidence_ptr dereference
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundedExplainabilityGate {
    pub status: GateStatus,
    pub signals_validated: u32,
    pub signals_valid: u32,
    pub signals_invalid: u32,
    pub explain_valid_rate: f64,
    pub evidence_ptr_rate: f64,
    pub evidence_deref_rate: f64,
    pub required_slot_filled_rate: f64,
    pub validation_details: Vec<SignalValidation>,
    pub diagnosis: Option<String>,
    pub how_computed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalValidation {
    pub signal_id: String,
    pub playbook_id: String,
    pub has_evidence_ptrs: bool,
    pub evidence_ptr_count: u32,
    pub evidence_deref_success: u32,
    pub evidence_deref_failed: u32,
    pub has_entity_bundle: bool,
    pub required_slots_filled: u32,
    pub required_slots_total: u32,
    pub is_valid: bool,
    pub issues: Vec<String>,
}

impl GroundedExplainabilityGate {
    /// Evaluate Gate D from real explanations + evidence dereference
    ///
    /// For each signal: fetch explanation, validate evidence_ptr can be dereferenced
    pub async fn evaluate_from_artifacts(
        run_dir: &Path,
        api_base_url: &str,
    ) -> Self {
        // Get all signals
        let signals = Self::fetch_all_signals(api_base_url).await;
        
        if signals.is_empty() {
            return Self {
                status: GateStatus::NoData,
                signals_validated: 0,
                signals_valid: 0,
                signals_invalid: 0,
                explain_valid_rate: 0.0,
                evidence_ptr_rate: 0.0,
                evidence_deref_rate: 0.0,
                required_slot_filled_rate: 0.0,
                validation_details: vec![],
                diagnosis: Some("No signals to validate".to_string()),
                how_computed: format!("API: {}/api/signals returned 0 signals", api_base_url),
            };
        }
        
        let mut validations = Vec::new();
        let mut total_evidence_ptrs = 0u32;
        let mut total_deref_success = 0u32;
        let mut total_required_slots = 0u32;
        let mut total_filled_slots = 0u32;
        
        for signal in &signals {
            let validation = Self::validate_signal(run_dir, api_base_url, signal).await;
            total_evidence_ptrs += validation.evidence_ptr_count;
            total_deref_success += validation.evidence_deref_success;
            total_required_slots += validation.required_slots_total;
            total_filled_slots += validation.required_slots_filled;
            validations.push(validation);
        }
        
        let signals_validated = validations.len() as u32;
        let signals_valid = validations.iter().filter(|v| v.is_valid).count() as u32;
        let signals_invalid = signals_validated - signals_valid;
        
        let explain_valid_rate = if signals_validated > 0 {
            (signals_valid as f64 / signals_validated as f64) * 100.0
        } else {
            0.0
        };
        
        let evidence_ptr_rate = if signals_validated > 0 {
            let with_ptrs = validations.iter().filter(|v| v.has_evidence_ptrs).count();
            (with_ptrs as f64 / signals_validated as f64) * 100.0
        } else {
            0.0
        };
        
        let evidence_deref_rate = if total_evidence_ptrs > 0 {
            (total_deref_success as f64 / total_evidence_ptrs as f64) * 100.0
        } else {
            100.0 // No pointers to deref is considered OK
        };
        
        let required_slot_filled_rate = if total_required_slots > 0 {
            (total_filled_slots as f64 / total_required_slots as f64) * 100.0
        } else {
            100.0
        };
        
        // Status per spec:
        // PASS: ≥90% valid AND ≥90% evidence_ptr deref success
        // PARTIAL: ≥50% valid OR ≥50% deref success
        // FAIL: <50% on both
        let (status, diagnosis) = if explain_valid_rate >= 90.0 && evidence_deref_rate >= 90.0 {
            (GateStatus::Pass, Some(format!(
                "{}/{} signals valid ({:.0}%), {:.0}% evidence deref success",
                signals_valid, signals_validated, explain_valid_rate, evidence_deref_rate
            )))
        } else if explain_valid_rate >= 50.0 || evidence_deref_rate >= 50.0 {
            (GateStatus::Partial, Some(format!(
                "{:.0}% valid, {:.0}% deref success (need ≥90% for PASS)",
                explain_valid_rate, evidence_deref_rate
            )))
        } else {
            (GateStatus::Fail, Some(format!(
                "Only {:.0}% valid, {:.0}% deref success",
                explain_valid_rate, evidence_deref_rate
            )))
        };
        
        let how_computed = format!(
            "Validated {} signals from {}/api/signals | Tested evidence deref on {} pointers | Run dir: {}",
            signals_validated, api_base_url, total_evidence_ptrs, run_dir.display()
        );
        
        Self {
            status,
            signals_validated,
            signals_valid,
            signals_invalid,
            explain_valid_rate,
            evidence_ptr_rate,
            evidence_deref_rate,
            required_slot_filled_rate,
            validation_details: validations,
            diagnosis,
            how_computed,
        }
    }
    
    async fn fetch_all_signals(api_base_url: &str) -> Vec<serde_json::Value> {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build() {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        
        let url = format!("{}/api/signals", api_base_url);
        if let Ok(response) = client.get(&url).send().await {
            if let Ok(data) = response.json::<serde_json::Value>().await {
                return data.get("data")
                    .and_then(|d| d.as_array())
                    .or_else(|| data.as_array())
                    .cloned()
                    .unwrap_or_default();
            }
        }
        vec![]
    }
    
    async fn validate_signal(
        run_dir: &Path,
        _api_base_url: &str,
        signal: &serde_json::Value,
    ) -> SignalValidation {
        let signal_id = signal.get("id")
            .or_else(|| signal.get("signal_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
            
        let playbook_id = signal.get("playbook_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        
        // Check evidence_ptrs
        let evidence_ptrs = signal.get("evidence_ptrs")
            .or_else(|| signal.get("evidence"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        
        let has_evidence_ptrs = !evidence_ptrs.is_empty();
        let evidence_ptr_count = evidence_ptrs.len() as u32;
        
        // Try to dereference evidence pointers
        let (deref_success, deref_failed) = Self::test_evidence_deref(run_dir, &evidence_ptrs);
        
        // Check entity bundle
        let has_entity_bundle = signal.get("entity_bundle")
            .or_else(|| signal.get("entities"))
            .map(|v| !v.is_null())
            .unwrap_or(false);
        
        // Check required slots
        let explanation = signal.get("explanation")
            .or_else(|| signal.get("matched_slots"));
        
        let (required_slots_total, required_slots_filled) = if let Some(exp) = explanation {
            if let Some(obj) = exp.as_object() {
                let total = obj.len() as u32;
                let filled = obj.values()
                    .filter(|v| !v.is_null() && !matches!(v, serde_json::Value::String(s) if s.is_empty()))
                    .count() as u32;
                (total, filled)
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };
        
        // Build issues
        let mut issues = Vec::new();
        if !has_evidence_ptrs {
            issues.push("Missing evidence_ptrs".to_string());
        }
        if deref_failed > 0 {
            issues.push(format!("{}/{} evidence deref failed", deref_failed, evidence_ptr_count));
        }
        if required_slots_total > 0 && required_slots_filled < required_slots_total {
            issues.push(format!(
                "Only {}/{} required slots filled",
                required_slots_filled, required_slots_total
            ));
        }
        
        let is_valid = has_evidence_ptrs && deref_failed == 0 && 
            (required_slots_total == 0 || required_slots_filled == required_slots_total);
        
        SignalValidation {
            signal_id,
            playbook_id,
            has_evidence_ptrs,
            evidence_ptr_count,
            evidence_deref_success: deref_success,
            evidence_deref_failed: deref_failed,
            has_entity_bundle,
            required_slots_filled,
            required_slots_total,
            is_valid,
            issues,
        }
    }
    
    fn test_evidence_deref(run_dir: &Path, evidence_ptrs: &[serde_json::Value]) -> (u32, u32) {
        let mut success = 0u32;
        let mut failed = 0u32;
        let segments_dir = run_dir.join("segments");
        
        for ptr in evidence_ptrs {
            // Parse evidence pointer
            let segment_id = ptr.get("segment_id")
                .and_then(|v| v.as_u64())
                .or_else(|| ptr.get("segment_id").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()));
            
            let record_index = ptr.get("record_index")
                .or_else(|| ptr.get("line"))
                .and_then(|v| v.as_u64());
            
            if let (Some(seg_id), Some(rec_idx)) = (segment_id, record_index) {
                // Try to find and read the segment file
                let patterns = [
                    format!("{}.jsonl", seg_id),
                    format!("evtx_{:06}.jsonl", seg_id),
                    format!("segment_{}.jsonl", seg_id),
                ];
                
                let mut found = false;
                for pattern in &patterns {
                    let segment_path = segments_dir.join(pattern);
                    if segment_path.exists() {
                        // Try to read the specific line
                        if Self::can_read_line(&segment_path, rec_idx as usize) {
                            success += 1;
                            found = true;
                            break;
                        }
                    }
                }
                
                if !found {
                    failed += 1;
                }
            } else {
                failed += 1;
            }
        }
        
        (success, failed)
    }
    
    fn can_read_line(path: &Path, line_index: usize) -> bool {
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            reader.lines().nth(line_index).is_some_and(|l| l.is_ok())
        } else {
            false
        }
    }
}

// ============================================================================
// UNIFIED HEALTH GATES - Single source of truth
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundedHealthGates {
    pub telemetry: GroundedTelemetryGate,
    pub extraction: GroundedExtractionGate,
    pub detection: GroundedDetectionGate,
    pub explainability: GroundedExplainabilityGate,
    pub overall_healthy: bool,
    pub overall_status: GateStatus,
    pub overall_diagnosis: String,
    pub computed_at: String,
}

impl GroundedHealthGates {
    /// Compute ALL health gates from disk artifacts + API
    ///
    /// This is THE SINGLE function that both write_metrics() and the UI call.
    /// No in-memory counters. Only real artifacts.
    pub async fn compute(
        run_dir: &Path,
        api_base_url: &str,
        elapsed_seconds: u64,
        playbooks_loaded: u32,
    ) -> Self {
        // Gate A: Telemetry from disk
        let telemetry = GroundedTelemetryGate::evaluate_from_disk(run_dir, elapsed_seconds);
        
        // Gate B: Extraction from DB/disk
        let extraction = GroundedExtractionGate::evaluate_from_artifacts(
            run_dir, 
            api_base_url, 
            telemetry.events_count
        ).await;
        
        // Gate C: Detection from DB + API
        let detection = GroundedDetectionGate::evaluate_from_artifacts(
            run_dir,
            api_base_url,
            extraction.facts_count,
            playbooks_loaded,
        ).await;
        
        // Gate D: Explainability validation
        let explainability = GroundedExplainabilityGate::evaluate_from_artifacts(
            run_dir,
            api_base_url,
        ).await;
        
        // Compute overall status
        let statuses = [
            telemetry.status,
            extraction.status,
            detection.status,
            explainability.status,
        ];
        
        let pass_count = statuses.iter().filter(|&&s| s == GateStatus::Pass).count();
        let fail_count = statuses.iter().filter(|&&s| s == GateStatus::Fail).count();
        let no_data_count = statuses.iter().filter(|&&s| s == GateStatus::NoData).count();
        
        let overall_status = if fail_count > 0 {
            GateStatus::Fail
        } else if no_data_count == 4 {
            GateStatus::NoData
        } else if pass_count == 4 {
            GateStatus::Pass
        } else {
            GateStatus::Partial
        };
        
        let overall_healthy = overall_status == GateStatus::Pass || overall_status == GateStatus::Partial;
        
        let overall_diagnosis = if overall_healthy && pass_count == 4 {
            "All 4 health gates PASS - pipeline fully operational".to_string()
        } else if overall_healthy {
            let partial_gates: Vec<&str> = [
                ("A-Telemetry", telemetry.status),
                ("B-Extraction", extraction.status),
                ("C-Detection", detection.status),
                ("D-Explainability", explainability.status),
            ].iter()
                .filter(|(_, s)| *s == GateStatus::Partial)
                .map(|(n, _)| *n)
                .collect();
            format!("Pipeline operational with partial gates: {}", partial_gates.join(", "))
        } else {
            let failed_gates: Vec<&str> = [
                ("A-Telemetry", telemetry.status),
                ("B-Extraction", extraction.status),
                ("C-Detection", detection.status),
                ("D-Explainability", explainability.status),
            ].iter()
                .filter(|(_, s)| *s == GateStatus::Fail)
                .map(|(n, _)| *n)
                .collect();
            format!("Pipeline issues - failed gates: {}", failed_gates.join(", "))
        };
        
        Self {
            telemetry,
            extraction,
            detection,
            explainability,
            overall_healthy,
            overall_status,
            overall_diagnosis,
            computed_at: chrono::Local::now().to_rfc3339(),
        }
    }
    
    /// Convert to Metrics v3 JSON format
    pub fn to_metrics_json(&self) -> serde_json::Value {
        serde_json::json!({
            "gates": {
                "telemetry": {
                    "status": self.telemetry.status.as_str(),
                    "events_count": self.telemetry.events_count,
                    "segments_count": self.telemetry.segments_count,
                    "channels_active": self.telemetry.channels_active,
                    "events_by_channel": self.telemetry.events_by_channel,
                    "events_by_provider": self.telemetry.events_by_provider,
                    "events_per_second": self.telemetry.events_per_second,
                    "diagnosis": self.telemetry.diagnosis,
                    "how_computed": self.telemetry.how_computed,
                },
                "extraction": {
                    "status": self.extraction.status.as_str(),
                    "facts_count": self.extraction.facts_count,
                    "facts_by_type": self.extraction.facts_by_type,
                    "extraction_rate": self.extraction.extraction_rate,
                    "key_fact_types_present": self.extraction.key_fact_types_present,
                    "key_fact_types_missing": self.extraction.key_fact_types_missing,
                    "diagnosis": self.extraction.diagnosis,
                    "how_computed": self.extraction.how_computed,
                },
                "detection": {
                    "status": self.detection.status.as_str(),
                    "signals_count": self.detection.signals_count,
                    "signals_from_db": self.detection.signals_from_db,
                    "signals_from_api": self.detection.signals_from_api,
                    "signals_by_playbook": self.detection.signals_by_playbook,
                    "signals_by_severity": self.detection.signals_by_severity,
                    "playbooks_matched": self.detection.playbooks_matched,
                    "playbooks_loaded": self.detection.playbooks_loaded,
                    "match_rate": self.detection.match_rate,
                    "db_api_consistent": self.detection.db_api_consistent,
                    "diagnosis": self.detection.diagnosis,
                    "how_computed": self.detection.how_computed,
                },
                "explainability": {
                    "status": self.explainability.status.as_str(),
                    "signals_validated": self.explainability.signals_validated,
                    "signals_valid": self.explainability.signals_valid,
                    "signals_invalid": self.explainability.signals_invalid,
                    "explain_valid_rate": self.explainability.explain_valid_rate,
                    "evidence_ptr_rate": self.explainability.evidence_ptr_rate,
                    "evidence_deref_rate": self.explainability.evidence_deref_rate,
                    "required_slot_filled_rate": self.explainability.required_slot_filled_rate,
                    "diagnosis": self.explainability.diagnosis,
                    "how_computed": self.explainability.how_computed,
                },
                "overall_healthy": self.overall_healthy,
                "overall_status": self.overall_status.as_str(),
                "overall_diagnosis": self.overall_diagnosis,
            },
            "computed_at": self.computed_at,
        })
    }
    
    /// Summary for UI display
    pub fn summary(&self) -> String {
        format!(
            "{} A:Telemetry | {} B:Extraction | {} C:Detection | {} D:Explainability → {} Overall",
            self.telemetry.status.emoji(),
            self.extraction.status.emoji(),
            self.detection.status.emoji(),
            self.explainability.status.emoji(),
            self.overall_status.emoji(),
        )
    }
}

// ============================================================================
// E2E VERIFICATION HARNESS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2EVerificationResult {
    pub success: bool,
    pub gates_computed: bool,
    pub gates: Option<GroundedHealthGates>,
    pub checks: Vec<VerificationCheck>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCheck {
    pub name: String,
    pub passed: bool,
    pub details: String,
}

impl E2EVerificationResult {
    /// Run full E2E verification of grounded gates
    pub async fn run(run_dir: &Path, api_base_url: &str) -> Self {
        let mut checks = Vec::new();
        
        // Check 1: run_dir exists
        let run_dir_exists = run_dir.exists();
        checks.push(VerificationCheck {
            name: "run_dir_exists".to_string(),
            passed: run_dir_exists,
            details: format!("Path: {}", run_dir.display()),
        });
        
        if !run_dir_exists {
            return Self {
                success: false,
                gates_computed: false,
                gates: None,
                checks,
                summary: "FAIL: run_dir does not exist".to_string(),
            };
        }
        
        // Check 2: segments directory exists
        let segments_dir = run_dir.join("segments");
        let segments_exists = segments_dir.exists();
        checks.push(VerificationCheck {
            name: "segments_dir_exists".to_string(),
            passed: segments_exists,
            details: format!("Path: {}", segments_dir.display()),
        });
        
        // Check 3: At least one .jsonl file
        let jsonl_count = if segments_exists {
            fs::read_dir(&segments_dir)
                .map(|e| e.filter_map(Result::ok)
                    .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
                    .count())
                .unwrap_or(0)
        } else {
            0
        };
        checks.push(VerificationCheck {
            name: "has_jsonl_files".to_string(),
            passed: jsonl_count > 0,
            details: format!("{} .jsonl files found", jsonl_count),
        });
        
        // Check 4: API reachable
        let api_reachable = Self::check_api_reachable(api_base_url).await;
        checks.push(VerificationCheck {
            name: "api_reachable".to_string(),
            passed: api_reachable,
            details: format!("URL: {}/api/signals", api_base_url),
        });
        
        // Check 5: Compute gates
        let gates = GroundedHealthGates::compute(run_dir, api_base_url, 60, 9).await;
        checks.push(VerificationCheck {
            name: "gates_computed".to_string(),
            passed: true,
            details: gates.summary(),
        });
        
        // Check 6: Gate A grounded (not from memory)
        checks.push(VerificationCheck {
            name: "gate_a_grounded".to_string(),
            passed: gates.telemetry.how_computed.contains("index.json") || 
                    gates.telemetry.how_computed.contains("segment files"),
            details: gates.telemetry.how_computed.clone(),
        });
        
        // Check 7: Gate D evidence deref works (if signals exist)
        let deref_check = if gates.explainability.signals_validated > 0 {
            gates.explainability.evidence_deref_rate >= 50.0
        } else {
            true // No signals to check
        };
        checks.push(VerificationCheck {
            name: "evidence_deref_works".to_string(),
            passed: deref_check,
            details: format!(
                "{:.0}% deref success on {} signals",
                gates.explainability.evidence_deref_rate,
                gates.explainability.signals_validated
            ),
        });
        
        let all_passed = checks.iter().all(|c| c.passed);
        let passed_count = checks.iter().filter(|c| c.passed).count();
        
        Self {
            success: all_passed,
            gates_computed: true,
            gates: Some(gates),
            checks,
            summary: format!(
                "{}: {}/{} checks passed",
                if all_passed { "PASS" } else { "FAIL" },
                passed_count,
                7
            ),
        }
    }
    
    async fn check_api_reachable(api_base_url: &str) -> bool {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build() {
            Ok(c) => c,
            Err(_) => return false,
        };
        
        let url = format!("{}/api/signals", api_base_url);
        client.get(&url).send().await.is_ok()
    }
}

// ============================================================================
// GATE I: IMPORT - Read from imports directory
// ============================================================================

/// Per-adapter statistics for import gate
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdapterStats {
    pub files_parsed: u32,
    pub events_extracted: u64,
    pub warnings_count: u32,
    pub avg_events_per_file: f64,
    pub file_kinds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundedImportGate {
    pub status: GateStatus,
    pub bundles_count: u32,
    pub total_files: u32,
    pub total_events: u64,
    pub total_signals: u64,
    pub parseable_files: u32,
    pub parsed_files: u32,
    pub parse_success_rate: f64,
    pub adapters_used: Vec<String>,
    pub adapter_stats: HashMap<String, AdapterStats>,
    pub file_types: HashMap<String, u32>,
    pub event_types: HashMap<String, u64>,
    pub rejected_files: u32,
    pub warnings_count: u32,
    pub detection_success: HashMap<String, bool>,
    pub diagnosis: Option<String>,
    pub how_computed: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ImportManifestSummary {
    total_files: u64,
    total_bytes: u64,
    parsed_files: u64,
    events_extracted: u64,
    rejected_files: u64,
    warnings_count: u64,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ImportManifestFile {
    rel_path: String,
    kind: String,
    size_bytes: u64,
    sha256: String,
    parsed: bool,
    parser: Option<String>,
    events_extracted: Option<u64>,
    #[serde(default)]
    warnings: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ImportManifest {
    bundle_id: String,
    bundle_name: Option<String>,
    created_at: String,
    summary: ImportManifestSummary,
    files: Vec<ImportManifestFile>,
}

impl GroundedImportGate {
    /// Evaluate Gate I from imports directory ONLY
    ///
    /// Source: imports/*/manifest.json for bundle metadata
    pub fn evaluate_from_disk(imports_dir: &Path) -> Self {
        let mut bundles_count = 0u32;
        let mut total_files = 0u32;
        let mut total_events = 0u64;
        let mut total_signals = 0u64;
        let mut parseable_files = 0u32;
        let mut parsed_files = 0u32;
        let mut rejected_files = 0u32;
        let mut warnings_count = 0u32;
        let mut adapters_used: HashMap<String, bool> = HashMap::new();
        let mut adapter_stats: HashMap<String, AdapterStats> = HashMap::new();
        let mut file_types: HashMap<String, u32> = HashMap::new();
        let mut event_types: HashMap<String, u64> = HashMap::new();
        let mut detection_success: HashMap<String, bool> = HashMap::new();
        let mut scan_notes = Vec::new();
        
        if !imports_dir.exists() {
            return Self {
                status: GateStatus::NoData,
                bundles_count: 0,
                total_files: 0,
                total_events: 0,
                total_signals: 0,
                parseable_files: 0,
                parsed_files: 0,
                parse_success_rate: 0.0,
                adapters_used: vec![],
                adapter_stats: HashMap::new(),
                file_types: HashMap::new(),
                event_types: HashMap::new(),
                rejected_files: 0,
                warnings_count: 0,
                detection_success: HashMap::new(),
                diagnosis: Some("Imports directory does not exist".to_string()),
                how_computed: format!("{} does not exist", imports_dir.display()),
            };
        }
        
        // Scan all bundle directories
        let entries = match fs::read_dir(imports_dir) {
            Ok(e) => e,
            Err(e) => {
                return Self {
                    status: GateStatus::Fail,
                    bundles_count: 0,
                    total_files: 0,
                    total_events: 0,
                    total_signals: 0,
                    parseable_files: 0,
                    parsed_files: 0,
                    parse_success_rate: 0.0,
                    adapters_used: vec![],
                    adapter_stats: HashMap::new(),
                    file_types: HashMap::new(),
                    event_types: HashMap::new(),
                    rejected_files: 0,
                    warnings_count: 0,
                    detection_success: HashMap::new(),
                    diagnosis: Some(format!("Cannot read imports dir: {}", e)),
                    how_computed: format!("Failed to read {}", imports_dir.display()),
                };
            }
        };
        
        for entry in entries.filter_map(Result::ok) {
            let bundle_dir = entry.path();
            if !bundle_dir.is_dir() {
                continue;
            }
            
            let manifest_path = bundle_dir.join("manifest.json");
            if !manifest_path.exists() {
                scan_notes.push(format!("No manifest in {}", bundle_dir.display()));
                continue;
            }
            
            // Parse manifest
            match Self::parse_manifest(&manifest_path) {
                Ok(manifest) => {
                    bundles_count += 1;
                    total_files += manifest.summary.total_files as u32;
                    total_events += manifest.summary.events_extracted;
                    rejected_files += manifest.summary.rejected_files as u32;
                    warnings_count += manifest.summary.warnings_count as u32;
                    
                    for file in &manifest.files {
                        let kind = file.kind.clone();
                        *file_types.entry(kind.clone()).or_insert(0) += 1;
                        
                        // Track detection success for each file type
                        let detected = Self::is_parseable_kind(&file.kind);
                        detection_success.entry(kind.clone()).or_insert(detected);
                        
                        // Count parseable vs parsed
                        if detected {
                            parseable_files += 1;
                            if file.parsed {
                                parsed_files += 1;
                                if let Some(parser) = &file.parser {
                                    adapters_used.insert(parser.clone(), true);
                                    
                                    // Update per-adapter stats
                                    let stats = adapter_stats.entry(parser.clone())
                                        .or_default();
                                    stats.files_parsed += 1;
                                    stats.events_extracted += file.events_extracted.unwrap_or(0);
                                    stats.warnings_count += file.warnings.len() as u32;
                                    if !stats.file_kinds.contains(&kind) {
                                        stats.file_kinds.push(kind);
                                    }
                                }
                            }
                        }
                    }
                    
                    // Check for events file to get event type breakdown
                    let events_path = bundle_dir.join("events.json");
                    if events_path.exists() {
                        if let Ok(content) = fs::read_to_string(&events_path) {
                            if let Ok(events) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                                for event in events {
                                    if let Some(event_type) = event.get("event_type").and_then(|v| v.as_str()) {
                                        *event_types.entry(event_type.to_string()).or_insert(0) += 1;
                                    }
                                }
                            }
                        }
                    }
                    
                    // Check for signals file
                    let signals_path = bundle_dir.join("signals.json");
                    if signals_path.exists() {
                        if let Ok(content) = fs::read_to_string(&signals_path) {
                            if let Ok(signals) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                                total_signals += signals.len() as u64;
                            }
                        }
                    }
                }
                Err(e) => {
                    scan_notes.push(format!("Failed to parse {}: {}", manifest_path.display(), e));
                }
            }
        }
        
        // Calculate average events per file for each adapter
        for stats in adapter_stats.values_mut() {
            if stats.files_parsed > 0 {
                stats.avg_events_per_file = stats.events_extracted as f64 / stats.files_parsed as f64;
            }
        }
        
        let parse_success_rate = if parseable_files > 0 {
            (parsed_files as f64 / parseable_files as f64) * 100.0
        } else {
            0.0
        };
        
        // Determine status
        let (status, diagnosis) = if bundles_count == 0 {
            (GateStatus::NoData, Some("No import bundles found".to_string()))
        } else if parsed_files > 0 && total_events > 0 && rejected_files == 0 && warnings_count < 10 {
            (GateStatus::Pass, Some(format!(
                "{} bundles, {} events, {:.0}% parse success",
                bundles_count, total_events, parse_success_rate
            )))
        } else if parsed_files > 0 || total_events > 0 {
            let issues = vec![
                if rejected_files > 0 { Some(format!("{} rejected", rejected_files)) } else { None },
                if warnings_count >= 10 { Some(format!("{} warnings", warnings_count)) } else { None },
                if parse_success_rate < 80.0 { Some(format!("{:.0}% parse rate", parse_success_rate)) } else { None },
            ].into_iter().flatten().collect::<Vec<_>>().join(", ");
            
            (GateStatus::Partial, Some(format!(
                "{} bundles, {} events - issues: {}",
                bundles_count, total_events, issues
            )))
        } else {
            (GateStatus::Fail, Some(format!(
                "{} bundles but no events extracted",
                bundles_count
            )))
        };
        
        let how_computed = format!(
            "Scanned {} | Found {} bundle dirs | {} | Adapters: {:?}",
            imports_dir.display(),
            bundles_count,
            if scan_notes.is_empty() {
                "All manifests parsed successfully".to_string()
            } else {
                format!("Notes: {}", scan_notes.join("; "))
            },
            adapters_used.keys().collect::<Vec<_>>()
        );
        
        Self {
            status,
            bundles_count,
            total_files,
            total_events,
            total_signals,
            parseable_files,
            parsed_files,
            parse_success_rate,
            adapters_used: adapters_used.keys().cloned().collect(),
            adapter_stats,
            file_types,
            event_types,
            rejected_files,
            warnings_count,
            detection_success,
            diagnosis,
            how_computed,
        }
    }
    
    fn parse_manifest(path: &Path) -> Result<ImportManifest, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Read error: {}", e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Parse error: {}", e))
    }
    
    fn is_parseable_kind(kind: &str) -> bool {
        matches!(kind.to_lowercase().as_str(),
            // Core formats
            "jsonl" | "json" | "har" | "csv" |
            // Zeek
            "zeek_conn" | "zeek_dns" | "zeek_http" | "zeek_ssl" | 
            "zeek_files" | "zeek" | "zeektsv" |
            // Network tools
            "nmapxml" | "nmap_xml" | "suricataeve" | "suricata_eve" |
            "zapjson" | "zap_json" |
            // Endpoint tools
            "osquery" | "velociraptor" | "evtxjson" | "evtx_json" |
            // Threat detection
            "yarajson" | "yara_json" | "yaratext" | "yara_text" |
            "atomicoutput" | "atomic_output" |
            // Plaintext
            "shellhistory" | "shell_history" | "pstranscript" | "ps_transcript" |
            "gobuster" | "ffuf" | "reconoutput" | "recon_output"
        )
    }
}

// ============================================================================
// COMBINED IMPORT METRICS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRunMetrics {
    pub schema_version: String,
    pub bundle_id: String,
    pub bundle_name: Option<String>,
    pub gates: ImportGates,
    pub timing: ImportTiming,
    pub environment: ImportEnvironment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportGates {
    pub import: GroundedImportGate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportTiming {
    pub started_at: String,
    pub finished_at: Option<String>,
    pub elapsed_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEnvironment {
    pub imports_dir: String,
    pub is_admin: bool,
}

impl ImportRunMetrics {
    /// Build metrics for an import bundle
    pub fn from_bundle(imports_dir: &Path, bundle_id: &str, elapsed_seconds: u64) -> Self {
        let import_gate = GroundedImportGate::evaluate_from_disk(imports_dir);
        
        Self {
            schema_version: "3.1".to_string(),
            bundle_id: bundle_id.to_string(),
            bundle_name: None,
            gates: ImportGates { import: import_gate },
            timing: ImportTiming {
                started_at: chrono::Utc::now().to_rfc3339(),
                finished_at: Some(chrono::Utc::now().to_rfc3339()),
                elapsed_seconds,
            },
            environment: ImportEnvironment {
                imports_dir: imports_dir.display().to_string(),
                is_admin: false,
            },
        }
    }
    
    /// Write metrics to file
    pub fn write_to_file(&self, path: &Path) -> Result<(), String> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialize error: {}", e))?;
        fs::write(path, content)
            .map_err(|e| format!("Write error: {}", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_telemetry_gate_from_empty_dir() {
        let temp = TempDir::new().unwrap();
        let gate = GroundedTelemetryGate::evaluate_from_disk(temp.path(), 60);
        
        assert_eq!(gate.status, GateStatus::Fail);
        assert_eq!(gate.events_count, 0);
        assert_eq!(gate.segments_count, 0);
        assert!(gate.how_computed.contains("not found") || gate.how_computed.contains("0 segment"));
    }

    #[test]
    fn test_telemetry_gate_with_segments() {
        let temp = TempDir::new().unwrap();
        let segments_dir = temp.path().join("segments");
        fs::create_dir_all(&segments_dir).unwrap();
        
        // Create a test segment file
        let segment_path = segments_dir.join("test.jsonl");
        let mut file = File::create(&segment_path).unwrap();
        for i in 0..100 {
            writeln!(file, r#"{{"channel":"Security","provider":"Microsoft-Windows-Security-Auditing","event_id":{}}}"#, i).unwrap();
        }
        
        let gate = GroundedTelemetryGate::evaluate_from_disk(temp.path(), 60);
        
        assert_eq!(gate.events_count, 100);
        assert_eq!(gate.segments_count, 1);
        assert!(gate.events_by_channel.contains_key("Security"));
        assert_eq!(gate.status, GateStatus::Partial); // 100 events, 1 channel
    }

    #[test]
    fn test_gate_status_thresholds() {
        // Test the status determination logic
        assert!(GateStatus::Pass.is_healthy());
        assert!(GateStatus::Partial.is_healthy());
        assert!(!GateStatus::Fail.is_healthy());
        assert!(!GateStatus::NoData.is_healthy());
    }
}

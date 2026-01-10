//! Real Pipeline Counters
//!
//! Fetches live metrics from the actual running telemetry stack:
//! - capture_windows_rotating: segments + events from index.json
//! - edr-locald: facts + signals from workbench.db
//! - edr-server: API health + signal counts
//!
//! This module provides GROUNDED counters - no in-memory estimates.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

// ============================================================================
// Live Counter Types
// ============================================================================

/// Real-time counters from the pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineCounters {
    /// Capture process counters
    pub capture: CaptureCounters,
    /// Locald process counters
    pub locald: LocaldCounters,
    /// Server process counters
    pub server: ServerCounters,
    /// When these counters were fetched
    pub fetched_at: String,
    /// Overall pipeline health
    pub pipeline_healthy: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureCounters {
    /// Total events captured across all segments
    pub events_total: u64,
    /// Number of segment files written
    pub segments_count: u32,
    /// Bytes written to segment files
    pub bytes_written: u64,
    /// Events per second rate (computed)
    pub events_per_second: f64,
    /// Active channels being captured
    pub channels: Vec<String>,
    /// Last segment timestamp
    pub last_segment_ts: Option<String>,
    /// Process is running
    pub is_running: bool,
    /// Error if any
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocaldCounters {
    /// Facts extracted from events
    pub facts_count: u64,
    /// Facts by type
    pub facts_by_type: HashMap<String, u64>,
    /// Signals in database
    pub signals_count: u64,
    /// Signals by playbook
    pub signals_by_playbook: HashMap<String, u64>,
    /// Signals by severity
    pub signals_by_severity: HashMap<String, u64>,
    /// Hypotheses active
    pub hypotheses_active: u64,
    /// Incidents formed
    pub incidents_count: u64,
    /// Playbooks loaded
    pub playbooks_loaded: Vec<String>,
    /// Process is running
    pub is_running: bool,
    /// Error if any
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerCounters {
    /// API health status
    pub api_healthy: bool,
    /// Response time ms
    pub response_time_ms: u64,
    /// Signals served via API
    pub signals_served: u64,
    /// Explanations generated
    pub explanations_count: u64,
    /// Evidence derefs successful
    pub evidence_derefs_success: u64,
    /// Evidence derefs failed
    pub evidence_derefs_failed: u64,
    /// Process is running
    pub is_running: bool,
    /// Error if any
    pub error: Option<String>,
}

// ============================================================================
// Counter Fetcher
// ============================================================================

/// Fetches real counters from the pipeline
pub struct PipelineCounterFetcher {
    run_dir: PathBuf,
    api_base_url: String,
}

impl PipelineCounterFetcher {
    pub fn new(run_dir: PathBuf, api_base_url: String) -> Self {
        Self { run_dir, api_base_url }
    }

    /// Fetch all counters from the pipeline
    pub async fn fetch_all(&self) -> PipelineCounters {
        let capture = self.fetch_capture_counters();
        let locald = self.fetch_locald_counters();
        let server = self.fetch_server_counters().await;

        let pipeline_healthy = capture.is_running 
            && locald.is_running 
            && server.api_healthy
            && capture.error.is_none()
            && locald.error.is_none();

        PipelineCounters {
            capture,
            locald,
            server,
            fetched_at: chrono::Utc::now().to_rfc3339(),
            pipeline_healthy,
        }
    }

    /// Fetch counters from capture (index.json + segments)
    fn fetch_capture_counters(&self) -> CaptureCounters {
        let mut counters = CaptureCounters::default();

        // Read index.json
        let index_path = self.run_dir.join("index.json");
        if !index_path.exists() {
            counters.error = Some("index.json not found".to_string());
            return counters;
        }

        match fs::read_to_string(&index_path) {
            Ok(content) => {
                match serde_json::from_str::<serde_json::Value>(&content) {
                    Ok(json) => {
                        // Parse segments
                        if let Some(segments) = json["segments"].as_array() {
                            counters.segments_count = segments.len() as u32;
                            
                            for seg in segments {
                                counters.events_total += seg["records"].as_u64().unwrap_or(0);
                                counters.bytes_written += seg["size_bytes"].as_u64().unwrap_or(0);
                                
                                // Track last segment timestamp
                                if let Some(ts) = seg["ts_last"].as_u64() {
                                    let ts_str = chrono::DateTime::from_timestamp_millis(ts as i64)
                                        .map(|dt| dt.to_rfc3339())
                                        .unwrap_or_default();
                                    if counters.last_segment_ts.is_none() 
                                        || ts_str > *counters.last_segment_ts.as_ref().unwrap_or(&String::new()) 
                                    {
                                        counters.last_segment_ts = Some(ts_str);
                                    }
                                }
                            }
                        }

                        // Compute events per second
                        if let (Some(first_ts), Some(last_ts)) = (
                            json["segments"].as_array()
                                .and_then(|s| s.first())
                                .and_then(|s| s["ts_first"].as_u64()),
                            json["segments"].as_array()
                                .and_then(|s| s.last())
                                .and_then(|s| s["ts_last"].as_u64()),
                        ) {
                            let duration_ms = last_ts.saturating_sub(first_ts);
                            if duration_ms > 0 {
                                counters.events_per_second = 
                                    (counters.events_total as f64 * 1000.0) / duration_ms as f64;
                            }
                        }

                        counters.is_running = true;
                    }
                    Err(e) => {
                        counters.error = Some(format!("Failed to parse index.json: {}", e));
                    }
                }
            }
            Err(e) => {
                counters.error = Some(format!("Failed to read index.json: {}", e));
            }
        }

        // Try to detect active channels from segment filenames or events
        let segments_dir = self.run_dir.join("segments");
        if segments_dir.exists() {
            if let Ok(entries) = fs::read_dir(&segments_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".jsonl") {
                        // Try to read first line to detect channel
                        if let Ok(content) = fs::read_to_string(entry.path()) {
                            if let Some(first_line) = content.lines().next() {
                                if let Ok(event) = serde_json::from_str::<serde_json::Value>(first_line) {
                                    if let Some(channel) = event["fields"]["windows.channel"].as_str() {
                                        if !counters.channels.contains(&channel.to_string()) {
                                            counters.channels.push(channel.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        counters
    }

    /// Fetch counters from locald (workbench.db)
    fn fetch_locald_counters(&self) -> LocaldCounters {
        let mut counters = LocaldCounters::default();

        let db_path = self.run_dir.join("workbench.db");
        if !db_path.exists() {
            // Also try analysis.db
            let alt_path = self.run_dir.join("analysis.db");
            if !alt_path.exists() {
                counters.error = Some("Database not found (workbench.db / analysis.db)".to_string());
                return counters;
            }
        }

        let db_path = if self.run_dir.join("workbench.db").exists() {
            self.run_dir.join("workbench.db")
        } else {
            self.run_dir.join("analysis.db")
        };

        match rusqlite::Connection::open(&db_path) {
            Ok(conn) => {
                counters.is_running = true;

                // Count signals
                if let Ok(count) = conn.query_row(
                    "SELECT COUNT(*) FROM signals",
                    [],
                    |row| row.get::<_, i64>(0),
                ) {
                    counters.signals_count = count as u64;
                }

                // Signals by severity
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT severity, COUNT(*) FROM signals GROUP BY severity"
                ) {
                    if let Ok(rows) = stmt.query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    }) {
                        for row in rows.flatten() {
                            counters.signals_by_severity.insert(row.0, row.1 as u64);
                        }
                    }
                }

                // Signals by playbook (from signal_type which often matches playbook)
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT signal_type, COUNT(*) FROM signals GROUP BY signal_type"
                ) {
                    if let Ok(rows) = stmt.query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    }) {
                        for row in rows.flatten() {
                            counters.signals_by_playbook.insert(row.0, row.1 as u64);
                        }
                    }
                }

                // Count facts if table exists
                if let Ok(count) = conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='facts'",
                    [],
                    |row| row.get::<_, i64>(0),
                ) {
                    if count > 0 {
                        if let Ok(fact_count) = conn.query_row(
                            "SELECT COUNT(*) FROM facts",
                            [],
                            |row| row.get::<_, i64>(0),
                        ) {
                            counters.facts_count = fact_count as u64;
                        }
                    }
                }

                // Count hypotheses if table exists
                if let Ok(count) = conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='hypotheses'",
                    [],
                    |row| row.get::<_, i64>(0),
                ) {
                    if count > 0 {
                        if let Ok(hyp_count) = conn.query_row(
                            "SELECT COUNT(*) FROM hypotheses WHERE status = 'active'",
                            [],
                            |row| row.get::<_, i64>(0),
                        ) {
                            counters.hypotheses_active = hyp_count as u64;
                        }
                    }
                }

                // Count explanations
                if let Ok(count) = conn.query_row(
                    "SELECT COUNT(*) FROM signal_explanations",
                    [],
                    |row| row.get::<_, i64>(0),
                ) {
                    counters.incidents_count = count as u64; // Using explanations as proxy
                }
            }
            Err(e) => {
                counters.error = Some(format!("Failed to open database: {}", e));
            }
        }

        counters
    }

    /// Fetch counters from server (API)
    async fn fetch_server_counters(&self) -> ServerCounters {
        let mut counters = ServerCounters::default();

        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                counters.error = Some(format!("Failed to create HTTP client: {}", e));
                return counters;
            }
        };

        // Health check
        let health_url = format!("{}/api/health", self.api_base_url);
        let start = std::time::Instant::now();
        
        match client.get(&health_url).send().await {
            Ok(resp) => {
                counters.response_time_ms = start.elapsed().as_millis() as u64;
                counters.api_healthy = resp.status().is_success();
                counters.is_running = true;
            }
            Err(e) => {
                counters.error = Some(format!("Health check failed: {}", e));
                return counters;
            }
        }

        // Fetch signals count
        let signals_url = format!("{}/api/signals", self.api_base_url);
        if let Ok(resp) = client.get(&signals_url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(signals) = json.as_array() {
                    counters.signals_served = signals.len() as u64;
                }
            }
        }

        // Fetch stats if available
        let stats_url = format!("{}/api/stats", self.api_base_url);
        if let Ok(resp) = client.get(&stats_url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                counters.explanations_count = json["explanations_generated"].as_u64().unwrap_or(0);
                counters.evidence_derefs_success = json["evidence_derefs_success"].as_u64().unwrap_or(0);
                counters.evidence_derefs_failed = json["evidence_derefs_failed"].as_u64().unwrap_or(0);
            }
        }

        counters
    }
}

// ============================================================================
// Evidence Proof Types
// ============================================================================

/// Proof that a signal came from a captured segment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalProvenanceProof {
    /// The signal being proven
    pub signal_id: String,
    /// Signal type/playbook
    pub signal_type: String,
    /// Evidence pointers in the signal
    pub evidence_pointers: Vec<EvidencePointer>,
    /// Segment files that contain the evidence
    pub source_segments: Vec<SegmentReference>,
    /// Dereferenced evidence excerpts
    pub evidence_excerpts: Vec<EvidenceExcerpt>,
    /// Whether all evidence was successfully dereferenced
    pub fully_proven: bool,
    /// Proof summary
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePointer {
    pub stream_id: String,
    pub segment_id: u64,
    pub record_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentReference {
    pub segment_id: String,
    pub rel_path: String,
    pub sha256: String,
    pub records: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceExcerpt {
    pub from_segment: String,
    pub record_index: u64,
    /// First 500 chars of the raw event
    pub event_excerpt: String,
    /// Key fields extracted
    pub key_fields: HashMap<String, String>,
}

/// Prove that signals originated from captured segments
pub async fn prove_signal_provenance(
    run_dir: &Path,
    api_base_url: &str,
) -> Result<Vec<SignalProvenanceProof>, String> {
    let mut proofs = Vec::new();

    // Load segment index
    let index_path = run_dir.join("index.json");
    let segments: Vec<SegmentReference> = if index_path.exists() {
        let content = fs::read_to_string(&index_path)
            .map_err(|e| format!("Failed to read index: {}", e))?;
        let json: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse index: {}", e))?;
        
        json["segments"].as_array()
            .map(|segs| segs.iter().filter_map(|s| {
                Some(SegmentReference {
                    segment_id: s["segment_id"].as_str()?.to_string(),
                    rel_path: s["rel_path"].as_str()?.to_string(),
                    sha256: s["sha256_segment"].as_str().unwrap_or("").to_string(),
                    records: s["records"].as_u64().unwrap_or(0) as u32,
                })
            }).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Load signals from database
    let db_path = if run_dir.join("workbench.db").exists() {
        run_dir.join("workbench.db")
    } else {
        run_dir.join("analysis.db")
    };

    if !db_path.exists() {
        return Err("Database not found".to_string());
    }

    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    // Get signals with evidence pointers
    let mut stmt = conn.prepare(
        "SELECT signal_id, signal_type, evidence_ptrs FROM signals LIMIT 10"
    ).map_err(|e| format!("Failed to prepare query: {}", e))?;

    let signal_rows: Vec<(String, String, String)> = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })
    .map_err(|e| format!("Failed to query signals: {}", e))?
    .filter_map(|r| r.ok())
    .collect();

    for (signal_id, signal_type, evidence_ptrs_json) in signal_rows {
        let mut proof = SignalProvenanceProof {
            signal_id: signal_id.clone(),
            signal_type: signal_type.clone(),
            evidence_pointers: Vec::new(),
            source_segments: Vec::new(),
            evidence_excerpts: Vec::new(),
            fully_proven: false,
            summary: String::new(),
        };

        // Parse evidence pointers
        if let Ok(ptrs) = serde_json::from_str::<Vec<serde_json::Value>>(&evidence_ptrs_json) {
            for ptr in ptrs {
                if let (Some(stream_id), Some(segment_id), Some(record_index)) = (
                    ptr["stream_id"].as_str(),
                    ptr["segment_id"].as_u64(),
                    ptr["record_index"].as_u64(),
                ) {
                    proof.evidence_pointers.push(EvidencePointer {
                        stream_id: stream_id.to_string(),
                        segment_id,
                        record_index,
                    });

                    // Find matching segment
                    if let Some(seg) = segments.iter().find(|s| {
                        s.segment_id.contains(&segment_id.to_string())
                    }) {
                        if !proof.source_segments.iter().any(|s| s.segment_id == seg.segment_id) {
                            proof.source_segments.push(seg.clone());
                        }

                        // Try to dereference the evidence
                        let segment_path = run_dir.join(&seg.rel_path);
                        if segment_path.exists() {
                            if let Ok(content) = fs::read_to_string(&segment_path) {
                                if let Some(line) = content.lines().nth(record_index as usize) {
                                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(line) {
                                        let mut key_fields = HashMap::new();
                                        
                                        // Extract key fields
                                        for key in ["exe", "cmdline", "pid", "host", "event_kind"] {
                                            if let Some(val) = event["fields"][key].as_str() {
                                                key_fields.insert(key.to_string(), val.to_string());
                                            } else if let Some(val) = event["fields"][key].as_i64() {
                                                key_fields.insert(key.to_string(), val.to_string());
                                            }
                                        }

                                        proof.evidence_excerpts.push(EvidenceExcerpt {
                                            from_segment: seg.segment_id.clone(),
                                            record_index,
                                            event_excerpt: line.chars().take(500).collect(),
                                            key_fields,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Determine if fully proven
        proof.fully_proven = !proof.evidence_pointers.is_empty()
            && proof.evidence_excerpts.len() == proof.evidence_pointers.len();

        proof.summary = if proof.fully_proven {
            format!(
                "Signal {} ({}) proven from {} evidence records in {} segments",
                proof.signal_id,
                proof.signal_type,
                proof.evidence_excerpts.len(),
                proof.source_segments.len()
            )
        } else if proof.evidence_excerpts.is_empty() {
            format!("Signal {} has no dereferenced evidence", proof.signal_id)
        } else {
            format!(
                "Signal {} partially proven: {}/{} evidence records dereferenced",
                proof.signal_id,
                proof.evidence_excerpts.len(),
                proof.evidence_pointers.len()
            )
        };

        proofs.push(proof);
    }

    Ok(proofs)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counters_default() {
        let capture = CaptureCounters::default();
        assert_eq!(capture.events_total, 0);
        assert!(!capture.is_running);
    }
}

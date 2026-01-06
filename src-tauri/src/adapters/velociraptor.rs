//! Velociraptor Adapter - Parse Velociraptor hunt/collection exports
//!
//! Parses Velociraptor JSON and CSV exports from:
//! - Hunt results
//! - Collection artifacts
//! - Timeline exports

use crate::adapters::{Adapter, ParseResult, generate_event_id};
use crate::import_types::*;
use std::collections::HashMap;
use std::path::Path;
use std::io::{BufRead, BufReader};
use std::fs::File;
use chrono::{DateTime, Utc, TimeZone};

pub struct VelociraptorAdapter;

impl VelociraptorAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for VelociraptorAdapter {
    fn name(&self) -> &'static str {
        "velociraptor"
    }
    
    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::Velociraptor)
    }
    
    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read Velociraptor file: {}", e))?;
        
        // Detect format
        if content.trim().starts_with('[') || content.trim().starts_with('{') {
            self.parse_json(file, &content, bundle_id, limits)
        } else {
            self.parse_csv(file, file_path, bundle_id, limits)
        }
    }
}

impl VelociraptorAdapter {
    fn parse_json(
        &self,
        file: &ManifestFile,
        content: &str,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        
        let records: Vec<serde_json::Value> = if content.trim().starts_with('[') {
            serde_json::from_str(content)
                .map_err(|e| format!("Failed to parse JSON array: {}", e))?
        } else {
            // Line-delimited JSON
            let reader = BufReader::new(content.as_bytes());
            let mut results = Vec::new();
            for line in reader.lines().flatten() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                    results.push(val);
                }
            }
            results
        };
        
        for (idx, record) in records.iter().enumerate() {
            if entries_processed >= limits.max_events as u64 {
                warnings.push("Event limit reached".to_string());
                break;
            }
            
            let obj = match record.as_object() {
                Some(o) => o,
                None => continue,
            };
            
            // Extract common Velociraptor fields
            let artifact = obj.get("_Source")
                .or_else(|| obj.get("Artifact"))
                .or_else(|| obj.get("artifact"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            
            let client_id = obj.get("ClientId")
                .or_else(|| obj.get("client_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            
            let hostname = obj.get("Fqdn")
                .or_else(|| obj.get("Hostname"))
                .or_else(|| obj.get("hostname"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            
            // Extract timestamp
            let timestamp = extract_vr_timestamp(obj);
            
            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            fields.insert("artifact".to_string(), serde_json::json!(artifact));
            if !client_id.is_empty() {
                fields.insert("client_id".to_string(), serde_json::json!(client_id));
            }
            if !hostname.is_empty() {
                fields.insert("hostname".to_string(), serde_json::json!(hostname));
            }
            
            // Add all other fields
            for (k, v) in obj {
                if !k.starts_with('_') && k != "ClientId" && k != "Fqdn" {
                    fields.insert(k.clone(), v.clone());
                }
            }
            
            // Determine event type and tags based on artifact
            let (event_type, mut tags) = categorize_vr_artifact(artifact, obj);
            tags.push("velociraptor".to_string());
            
            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp,
                timestamp_quality: TimestampQuality::Precise,
                event_type,
                source_file: file.rel_path.clone(),
                source_line: None,
                fields,
                evidence_ptr: ImportEvidencePtr {
                    bundle_id: bundle_id.to_string(),
                    rel_path: file.rel_path.clone(),
                    line_no: None,
                    json_path: Some(format!("[{}]", idx)),
                    byte_offset: None,
                },
                tags,
            });
            
            entries_processed += 1;
        }
        
        Ok(ParseResult {
            events,
            warnings,
            entries_processed,
            entries_skipped: 0,
        })
    }
    
    fn parse_csv(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path)
            .map_err(|e| format!("Failed to open CSV: {}", e))?;
        let mut rdr = csv::Reader::from_reader(f);
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        
        let headers: Vec<String> = rdr.headers()
            .map_err(|e| format!("Failed to read CSV headers: {}", e))?
            .iter()
            .map(|s| s.to_string())
            .collect();
        
        for (idx, result) in rdr.records().enumerate() {
            if entries_processed >= limits.max_events as u64 {
                warnings.push(format!("Event limit reached at row {}", idx));
                break;
            }
            
            let record = match result {
                Ok(r) => r,
                Err(e) => {
                    warnings.push(format!("Row {} error: {}", idx, e));
                    continue;
                }
            };
            
            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            let mut artifact = "unknown".to_string();
            let mut timestamp = Utc::now();
            
            for (i, value) in record.iter().enumerate() {
                if let Some(header) = headers.get(i) {
                    let header_lower = header.to_lowercase();
                    
                    // Handle special fields
                    if header_lower == "_source" || header_lower == "artifact" {
                        artifact = value.to_string();
                    }
                    
                    // Try to parse timestamp fields
                    if header_lower.contains("time") || header_lower.contains("date") {
                        if let Some(ts) = parse_vr_timestamp_str(value) {
                            timestamp = ts;
                        }
                    }
                    
                    if !value.is_empty() {
                        // Try to parse as number or bool
                        let json_value = if let Ok(n) = value.parse::<i64>() {
                            serde_json::json!(n)
                        } else if let Ok(f) = value.parse::<f64>() {
                            serde_json::json!(f)
                        } else if value == "true" || value == "false" {
                            serde_json::json!(value == "true")
                        } else {
                            serde_json::json!(value)
                        };
                        fields.insert(header.clone(), json_value);
                    }
                }
            }
            
            fields.insert("artifact".to_string(), serde_json::json!(artifact));
            
            let (event_type, mut tags) = categorize_vr_artifact_simple(&artifact);
            tags.push("velociraptor".to_string());
            tags.push("csv".to_string());
            
            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp,
                timestamp_quality: TimestampQuality::Precise,
                event_type,
                source_file: file.rel_path.clone(),
                source_line: Some(idx + 2), // +2 for header + 1-based
                fields,
                evidence_ptr: ImportEvidencePtr {
                    bundle_id: bundle_id.to_string(),
                    rel_path: file.rel_path.clone(),
                    line_no: Some(idx + 2),
                    json_path: None,
                    byte_offset: None,
                },
                tags,
            });
            
            entries_processed += 1;
        }
        
        Ok(ParseResult {
            events,
            warnings,
            entries_processed,
            entries_skipped: 0,
        })
    }
}

fn extract_vr_timestamp(obj: &serde_json::Map<String, serde_json::Value>) -> DateTime<Utc> {
    // Common VR timestamp fields
    let ts_fields = [
        "Time", "Timestamp", "CreateTime", "ModTime", "AccessTime",
        "EventTime", "_time", "timestamp", "time"
    ];
    
    for field in &ts_fields {
        if let Some(val) = obj.get(*field) {
            if let Some(ts) = parse_vr_timestamp_value(val) {
                return ts;
            }
        }
    }
    
    Utc::now()
}

fn parse_vr_timestamp_value(val: &serde_json::Value) -> Option<DateTime<Utc>> {
    match val {
        serde_json::Value::Number(n) => {
            // Unix timestamp (seconds or nanoseconds)
            if let Some(ts) = n.as_i64() {
                if ts > 1_000_000_000_000_000 {
                    // Nanoseconds
                    return Utc.timestamp_opt(ts / 1_000_000_000, (ts % 1_000_000_000) as u32).single();
                } else if ts > 1_000_000_000_000 {
                    // Milliseconds
                    return Utc.timestamp_opt(ts / 1000, ((ts % 1000) * 1_000_000) as u32).single();
                } else {
                    // Seconds
                    return Utc.timestamp_opt(ts, 0).single();
                }
            }
            None
        }
        serde_json::Value::String(s) => parse_vr_timestamp_str(s),
        _ => None,
    }
}

fn parse_vr_timestamp_str(s: &str) -> Option<DateTime<Utc>> {
    // Try RFC3339
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    
    // Try common formats
    let formats = [
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ];
    
    for fmt in &formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
        }
    }
    
    // Try parsing as unix timestamp
    if let Ok(ts) = s.parse::<i64>() {
        return Utc.timestamp_opt(ts, 0).single();
    }
    
    None
}

fn categorize_vr_artifact(artifact: &str, obj: &serde_json::Map<String, serde_json::Value>) -> (String, Vec<String>) {
    let artifact_lower = artifact.to_lowercase();
    let mut tags = Vec::new();
    
    // Process artifacts
    if artifact_lower.contains("pslist") || artifact_lower.contains("process") {
        tags.push("process".to_string());
        return ("process_info".to_string(), tags);
    }
    
    // Network artifacts
    if artifact_lower.contains("netstat") || artifact_lower.contains("network") || artifact_lower.contains("connection") {
        tags.push("network".to_string());
        return ("network_connection".to_string(), tags);
    }
    
    // File artifacts
    if artifact_lower.contains("mft") || artifact_lower.contains("ntfs") {
        tags.push("filesystem".to_string());
        tags.push("mft".to_string());
        return ("mft_entry".to_string(), tags);
    }
    
    if artifact_lower.contains("file") {
        tags.push("file".to_string());
        return ("file_info".to_string(), tags);
    }
    
    // Registry artifacts
    if artifact_lower.contains("registry") || artifact_lower.contains("reg") {
        tags.push("registry".to_string());
        return ("registry_entry".to_string(), tags);
    }
    
    // Prefetch
    if artifact_lower.contains("prefetch") {
        tags.push("prefetch".to_string());
        tags.push("execution".to_string());
        return ("prefetch_entry".to_string(), tags);
    }
    
    // Event logs
    if artifact_lower.contains("eventlog") || artifact_lower.contains("evtx") {
        tags.push("eventlog".to_string());
        return ("windows_event".to_string(), tags);
    }
    
    // Scheduled tasks
    if artifact_lower.contains("scheduled") || artifact_lower.contains("task") {
        tags.push("scheduled_task".to_string());
        tags.push("persistence".to_string());
        return ("scheduled_task".to_string(), tags);
    }
    
    // Services
    if artifact_lower.contains("service") {
        tags.push("service".to_string());
        return ("service_info".to_string(), tags);
    }
    
    // Users
    if artifact_lower.contains("user") || artifact_lower.contains("account") {
        tags.push("user".to_string());
        return ("user_info".to_string(), tags);
    }
    
    // Default
    tags.push(artifact.replace('.', "_").to_lowercase());
    ("vr_artifact".to_string(), tags)
}

fn categorize_vr_artifact_simple(artifact: &str) -> (String, Vec<String>) {
    let mut dummy_map = serde_json::Map::new();
    categorize_vr_artifact(artifact, &dummy_map)
}

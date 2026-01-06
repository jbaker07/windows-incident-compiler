//! osquery JSON Adapter - Parse osquery query results
//!
//! Parses osquery JSON output including:
//! - processes: Running process information
//! - users: User account information
//! - listening_ports: Open network ports
//! - logged_in_users: Active sessions
//! - file_events: File system activity
//! - Generic table queries (table_row events)

use crate::adapters::{Adapter, ParseResult, generate_event_id};
use crate::import_types::*;
use std::collections::HashMap;
use std::path::Path;
use std::io::BufReader;
use std::fs::File;
use chrono::{DateTime, Utc, TimeZone};

pub struct OsqueryAdapter;

impl OsqueryAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for OsqueryAdapter {
    fn name(&self) -> &'static str {
        "osquery"
    }
    
    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::Osquery)
    }
    
    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path)
            .map_err(|e| format!("Failed to open osquery JSON: {}", e))?;
        let reader = BufReader::new(f);
        
        let json: serde_json::Value = serde_json::from_reader(reader)
            .map_err(|e| format!("Failed to parse osquery JSON: {}", e))?;
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let mut entries_skipped = 0u64;
        
        // Determine the format - could be array of results or wrapped format
        let rows = if json.is_array() {
            json.as_array().unwrap()
        } else if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
            data
        } else if let Some(results) = json.get("results").and_then(|r| r.as_array()) {
            results
        } else {
            warnings.push("Unknown osquery format - expected array or {data:[]} or {results:[]}".to_string());
            return Ok(ParseResult {
                events,
                warnings,
                entries_processed: 0,
                entries_skipped: 1,
            });
        };
        
        // Try to detect table type from content
        let table_type = detect_osquery_table(&rows);
        
        for (idx, row) in rows.iter().enumerate() {
            if entries_processed >= limits.max_events as u64 {
                warnings.push(format!("Event limit reached at row {}", idx));
                break;
            }
            
            let obj = match row.as_object() {
                Some(o) => o,
                None => {
                    entries_skipped += 1;
                    continue;
                }
            };
            
            // Extract timestamp if present
            let timestamp = extract_osquery_timestamp(obj)
                .unwrap_or_else(Utc::now);
            
            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            for (k, v) in obj {
                fields.insert(k.clone(), v.clone());
            }
            
            let (event_type, tags) = match table_type.as_str() {
                "processes" => {
                    let pid = obj.get("pid").and_then(|v| v.as_str()).unwrap_or("");
                    let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let cmdline = obj.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
                    let uid = obj.get("uid").and_then(|v| v.as_str()).unwrap_or("");
                    let ppid = obj.get("parent").and_then(|v| v.as_str()).unwrap_or("");
                    
                    fields.insert("process_name".to_string(), serde_json::json!(name));
                    fields.insert("process_id".to_string(), serde_json::json!(pid));
                    fields.insert("command_line".to_string(), serde_json::json!(cmdline));
                    fields.insert("user_id".to_string(), serde_json::json!(uid));
                    fields.insert("parent_pid".to_string(), serde_json::json!(ppid));
                    
                    ("process_info", vec!["osquery".to_string(), "process".to_string()])
                }
                "users" => {
                    let username = obj.get("username").and_then(|v| v.as_str()).unwrap_or("");
                    let uid = obj.get("uid").and_then(|v| v.as_str()).unwrap_or("");
                    let gid = obj.get("gid").and_then(|v| v.as_str()).unwrap_or("");
                    let shell = obj.get("shell").and_then(|v| v.as_str()).unwrap_or("");
                    let directory = obj.get("directory").and_then(|v| v.as_str()).unwrap_or("");
                    
                    fields.insert("username".to_string(), serde_json::json!(username));
                    fields.insert("uid".to_string(), serde_json::json!(uid));
                    fields.insert("gid".to_string(), serde_json::json!(gid));
                    fields.insert("shell".to_string(), serde_json::json!(shell));
                    fields.insert("home_directory".to_string(), serde_json::json!(directory));
                    
                    ("user_info", vec!["osquery".to_string(), "user".to_string(), "identity".to_string()])
                }
                "listening_ports" => {
                    let port = obj.get("port").and_then(|v| v.as_str()).unwrap_or("");
                    let address = obj.get("address").and_then(|v| v.as_str()).unwrap_or("");
                    let protocol = obj.get("protocol").and_then(|v| v.as_u64()).unwrap_or(0);
                    let pid = obj.get("pid").and_then(|v| v.as_str()).unwrap_or("");
                    
                    let proto_str = match protocol {
                        6 => "tcp",
                        17 => "udp",
                        _ => "unknown",
                    };
                    
                    fields.insert("port".to_string(), serde_json::json!(port));
                    fields.insert("address".to_string(), serde_json::json!(address));
                    fields.insert("protocol".to_string(), serde_json::json!(proto_str));
                    fields.insert("pid".to_string(), serde_json::json!(pid));
                    
                    ("listening_port", vec!["osquery".to_string(), "network".to_string(), "listener".to_string()])
                }
                "logged_in_users" => {
                    let user = obj.get("user").and_then(|v| v.as_str()).unwrap_or("");
                    let tty = obj.get("tty").and_then(|v| v.as_str()).unwrap_or("");
                    let host = obj.get("host").and_then(|v| v.as_str()).unwrap_or("");
                    let login_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    
                    fields.insert("username".to_string(), serde_json::json!(user));
                    fields.insert("tty".to_string(), serde_json::json!(tty));
                    fields.insert("remote_host".to_string(), serde_json::json!(host));
                    fields.insert("session_type".to_string(), serde_json::json!(login_type));
                    
                    ("active_session", vec!["osquery".to_string(), "session".to_string(), "login".to_string()])
                }
                "file_events" => {
                    let target_path = obj.get("target_path").and_then(|v| v.as_str()).unwrap_or("");
                    let action = obj.get("action").and_then(|v| v.as_str()).unwrap_or("");
                    let md5 = obj.get("md5").and_then(|v| v.as_str()).unwrap_or("");
                    let sha256 = obj.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
                    
                    fields.insert("file_path".to_string(), serde_json::json!(target_path));
                    fields.insert("action".to_string(), serde_json::json!(action));
                    if !md5.is_empty() {
                        fields.insert("md5".to_string(), serde_json::json!(md5));
                    }
                    if !sha256.is_empty() {
                        fields.insert("sha256".to_string(), serde_json::json!(sha256));
                    }
                    
                    ("file_event", vec!["osquery".to_string(), "file".to_string(), "fim".to_string()])
                }
                "process_events" => {
                    let path = obj.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    let cmdline = obj.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
                    let pid = obj.get("pid").and_then(|v| v.as_str()).unwrap_or("");
                    let uid = obj.get("uid").and_then(|v| v.as_str()).unwrap_or("");
                    
                    fields.insert("process_path".to_string(), serde_json::json!(path));
                    fields.insert("command_line".to_string(), serde_json::json!(cmdline));
                    fields.insert("pid".to_string(), serde_json::json!(pid));
                    fields.insert("uid".to_string(), serde_json::json!(uid));
                    
                    ("process_exec", vec!["osquery".to_string(), "process".to_string(), "execution".to_string()])
                }
                "socket_events" => {
                    let action = obj.get("action").and_then(|v| v.as_str()).unwrap_or("");
                    let local_address = obj.get("local_address").and_then(|v| v.as_str()).unwrap_or("");
                    let local_port = obj.get("local_port").and_then(|v| v.as_str()).unwrap_or("");
                    let remote_address = obj.get("remote_address").and_then(|v| v.as_str()).unwrap_or("");
                    let remote_port = obj.get("remote_port").and_then(|v| v.as_str()).unwrap_or("");
                    
                    fields.insert("action".to_string(), serde_json::json!(action));
                    fields.insert("local_address".to_string(), serde_json::json!(local_address));
                    fields.insert("local_port".to_string(), serde_json::json!(local_port));
                    fields.insert("remote_address".to_string(), serde_json::json!(remote_address));
                    fields.insert("remote_port".to_string(), serde_json::json!(remote_port));
                    
                    ("socket_event", vec!["osquery".to_string(), "network".to_string(), "socket".to_string()])
                }
                _ => {
                    // Generic table row
                    fields.insert("_osquery_table".to_string(), serde_json::json!(table_type));
                    ("table_row", vec!["osquery".to_string(), table_type.clone()])
                }
            };
            
            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp,
                timestamp_quality: if extract_osquery_timestamp(obj).is_some() {
                    TimestampQuality::Precise
                } else {
                    TimestampQuality::Unknown
                },
                event_type: event_type.to_string(),
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
            entries_skipped,
        })
    }
}

/// Detect the osquery table type from the content
fn detect_osquery_table(rows: &[serde_json::Value]) -> String {
    if rows.is_empty() {
        return "unknown".to_string();
    }
    
    let first = match rows[0].as_object() {
        Some(o) => o,
        None => return "unknown".to_string(),
    };
    
    let keys: Vec<&String> = first.keys().collect();
    
    // Process tables
    if keys.contains(&&"cmdline".to_string()) && keys.contains(&&"pid".to_string()) {
        if keys.contains(&&"parent".to_string()) || keys.contains(&&"ppid".to_string()) {
            return "processes".to_string();
        }
    }
    
    // Process events
    if keys.contains(&&"path".to_string()) && keys.contains(&&"cmdline".to_string()) 
       && keys.contains(&&"time".to_string()) {
        return "process_events".to_string();
    }
    
    // Users table
    if keys.contains(&&"username".to_string()) && keys.contains(&&"uid".to_string()) 
       && keys.contains(&&"shell".to_string()) {
        return "users".to_string();
    }
    
    // Listening ports
    if keys.contains(&&"port".to_string()) && keys.contains(&&"address".to_string()) 
       && keys.contains(&&"protocol".to_string()) {
        return "listening_ports".to_string();
    }
    
    // Logged in users
    if keys.contains(&&"user".to_string()) && keys.contains(&&"tty".to_string()) {
        return "logged_in_users".to_string();
    }
    
    // File events
    if keys.contains(&&"target_path".to_string()) && keys.contains(&&"action".to_string()) {
        return "file_events".to_string();
    }
    
    // Socket events
    if keys.contains(&&"local_address".to_string()) && keys.contains(&&"remote_address".to_string()) 
       && keys.contains(&&"action".to_string()) {
        return "socket_events".to_string();
    }
    
    "generic".to_string()
}

/// Extract timestamp from osquery record
fn extract_osquery_timestamp(obj: &serde_json::Map<String, serde_json::Value>) -> Option<DateTime<Utc>> {
    // Try various timestamp fields
    let timestamp_fields = ["time", "timestamp", "created_at", "epoch", "unixtime"];
    
    for field in &timestamp_fields {
        if let Some(val) = obj.get(*field) {
            // Try as unix timestamp (string or number)
            if let Some(n) = val.as_i64() {
                if let Some(dt) = Utc.timestamp_opt(n, 0).single() {
                    return Some(dt);
                }
            }
            if let Some(s) = val.as_str() {
                if let Ok(n) = s.parse::<i64>() {
                    if let Some(dt) = Utc.timestamp_opt(n, 0).single() {
                        return Some(dt);
                    }
                }
                // Try ISO format
                if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                    return Some(dt.with_timezone(&Utc));
                }
            }
        }
    }
    
    None
}

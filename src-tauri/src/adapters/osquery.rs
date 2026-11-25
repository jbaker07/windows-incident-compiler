//! osquery JSON Adapter - Parse osquery query results
//!
//! Parses osquery JSON output including:
//! - processes: Running process information
//! - users: User account information
//! - listening_ports: Open network ports
//! - logged_in_users: Active sessions
//! - file_events: File system activity
//! - Generic table queries (table_row events)

use crate::adapters::{generate_event_id, Adapter, ParseResult};
use crate::import_types::*;
use chrono::{DateTime, TimeZone, Utc};
use std::collections::HashMap;
use std::path::Path;

#[derive(Default)]
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
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to open osquery JSON: {}", e))?;

        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let mut entries_skipped = 0u64;

        let rows = collect_osquery_rows(&content, &mut warnings, &mut entries_skipped);

        for (idx, row) in rows.iter().enumerate() {
            if entries_processed >= limits.max_lines_per_file {
                warnings.push(format!("Event limit reached at row {}", idx));
                break;
            }

            let obj = &row.columns;
            let table_type = detect_osquery_table(obj, row.query_name.as_deref());

            // The daemon log carries the time of the query run, an osqueryi
            // row may carry its own time column.
            let row_time = row
                .unix_time
                .and_then(|n| Utc.timestamp_opt(n, 0).single())
                .or_else(|| extract_osquery_timestamp(obj));
            let timestamp = row_time.unwrap_or_else(Utc::now);

            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            for (k, v) in obj {
                fields.insert(k.clone(), v.clone());
            }
            if let Some(name) = &row.query_name {
                fields.insert("query_name".to_string(), serde_json::json!(name));
            }
            if let Some(host) = &row.host {
                fields.insert("host".to_string(), serde_json::json!(host));
            }
            if let Some(action) = &row.action {
                fields.insert("osquery_action".to_string(), serde_json::json!(action));
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

                    (
                        "process_info",
                        vec!["osquery".to_string(), "process".to_string()],
                    )
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

                    (
                        "user_info",
                        vec![
                            "osquery".to_string(),
                            "user".to_string(),
                            "identity".to_string(),
                        ],
                    )
                }
                "listening_ports" => {
                    let port = obj.get("port").and_then(|v| v.as_str()).unwrap_or("");
                    let address = obj.get("address").and_then(|v| v.as_str()).unwrap_or("");
                    // osquery writes columns as strings ("6"), osqueryi --json as numbers
                    let protocol = obj
                        .get("protocol")
                        .and_then(|v| {
                            v.as_u64()
                                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                        })
                        .unwrap_or(0);
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

                    (
                        "listening_port",
                        vec![
                            "osquery".to_string(),
                            "network".to_string(),
                            "listener".to_string(),
                        ],
                    )
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

                    (
                        "active_session",
                        vec![
                            "osquery".to_string(),
                            "session".to_string(),
                            "login".to_string(),
                        ],
                    )
                }
                "file_events" => {
                    let target_path = obj
                        .get("target_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
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

                    (
                        "file_event",
                        vec!["osquery".to_string(), "file".to_string(), "fim".to_string()],
                    )
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

                    (
                        "process_exec",
                        vec![
                            "osquery".to_string(),
                            "process".to_string(),
                            "execution".to_string(),
                        ],
                    )
                }
                "socket_events" => {
                    let action = obj.get("action").and_then(|v| v.as_str()).unwrap_or("");
                    let local_address = obj
                        .get("local_address")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let local_port = obj.get("local_port").and_then(|v| v.as_str()).unwrap_or("");
                    let remote_address = obj
                        .get("remote_address")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let remote_port = obj
                        .get("remote_port")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    fields.insert("action".to_string(), serde_json::json!(action));
                    fields.insert(
                        "local_address".to_string(),
                        serde_json::json!(local_address),
                    );
                    fields.insert("local_port".to_string(), serde_json::json!(local_port));
                    fields.insert(
                        "remote_address".to_string(),
                        serde_json::json!(remote_address),
                    );
                    fields.insert("remote_port".to_string(), serde_json::json!(remote_port));

                    (
                        "socket_event",
                        vec![
                            "osquery".to_string(),
                            "network".to_string(),
                            "socket".to_string(),
                        ],
                    )
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
                timestamp_quality: if row_time.is_some() {
                    TimestampQuality::Precise
                } else {
                    TimestampQuality::Unknown
                },
                event_type: event_type.to_string(),
                source_file: file.rel_path.clone(),
                source_line: row.line_no,
                fields,
                evidence_ptr: ImportEvidencePtr {
                    bundle_id: bundle_id.to_string(),
                    rel_path: file.rel_path.clone(),
                    line_no: row.line_no,
                    json_path: Some(row.json_path.clone()),
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

/// One result row with what the daemon log wraps around it
struct OsqueryRow {
    columns: serde_json::Map<String, serde_json::Value>,
    query_name: Option<String>,
    unix_time: Option<i64>,
    host: Option<String>,
    action: Option<String>,
    line_no: Option<u64>,
    json_path: String,
}

/// Rows from the three shapes osquery writes: an osqueryi `--json` array of
/// flat rows, the daemon results log (one JSON object per line, rows under
/// `columns`, or a `snapshot` array for snapshot queries), and a wrapping
/// object with `data` or `results`.
fn collect_osquery_rows(
    content: &str,
    warnings: &mut Vec<String>,
    skipped: &mut u64,
) -> Vec<OsqueryRow> {
    let mut out = Vec::new();
    let trimmed = content.trim_start();
    let whole: Option<serde_json::Value> = if trimmed.starts_with('[') || trimmed.starts_with('{') {
        serde_json::from_str(trimmed).ok()
    } else {
        None
    };

    fn push_record(
        value: &serde_json::Value,
        line_no: Option<u64>,
        path: String,
        out: &mut Vec<OsqueryRow>,
        skipped: &mut u64,
    ) {
        let Some(obj) = value.as_object() else {
            *skipped += 1;
            return;
        };
        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let unix_time = obj.get("unixTime").and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });
        let host = obj
            .get("hostIdentifier")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if let Some(cols) = obj.get("columns").and_then(|v| v.as_object()) {
            out.push(OsqueryRow {
                columns: cols.clone(),
                query_name: name,
                unix_time,
                host,
                action: obj
                    .get("action")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                line_no,
                json_path: format!("{}.columns", path),
            });
        } else if let Some(snapshot) = obj.get("snapshot").and_then(|v| v.as_array()) {
            for (i, row) in snapshot.iter().enumerate() {
                if let Some(cols) = row.as_object() {
                    out.push(OsqueryRow {
                        columns: cols.clone(),
                        query_name: name.clone(),
                        unix_time,
                        host: host.clone(),
                        action: Some("snapshot".to_string()),
                        line_no,
                        json_path: format!("{}.snapshot[{}]", path, i),
                    });
                } else {
                    *skipped += 1;
                }
            }
        } else {
            out.push(OsqueryRow {
                columns: obj.clone(),
                query_name: None,
                unix_time: None,
                host: None,
                action: None,
                line_no,
                json_path: path,
            });
        }
    }

    match whole {
        Some(serde_json::Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                push_record(item, None, format!("[{}]", i), &mut out, skipped);
            }
        }
        Some(serde_json::Value::Object(obj))
            if obj
                .get("data")
                .or_else(|| obj.get("results"))
                .is_some_and(|v| v.is_array()) =>
        {
            let items = obj
                .get("data")
                .or_else(|| obj.get("results"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for (i, item) in items.iter().enumerate() {
                push_record(item, None, format!("data[{}]", i), &mut out, skipped);
            }
        }
        Some(value @ serde_json::Value::Object(_)) => {
            push_record(&value, Some(1), "$".to_string(), &mut out, skipped)
        }
        _ => {
            // Daemon results log: one JSON object per line
            for (i, line) in content.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<serde_json::Value>(line) {
                    Ok(value) => push_record(
                        &value,
                        Some(i as u64 + 1),
                        "$".to_string(),
                        &mut out,
                        skipped,
                    ),
                    Err(e) => {
                        warnings.push(format!("Line {}: not JSON: {}", i + 1, e));
                        *skipped += 1;
                    }
                }
            }
        }
    }
    out
}

/// Detect the osquery table of one row, from the query name when it names a
/// table, otherwise from the columns.
fn detect_osquery_table(
    first: &serde_json::Map<String, serde_json::Value>,
    query_name: Option<&str>,
) -> String {
    if let Some(name) = query_name {
        let name = name.to_lowercase();
        for table in [
            "listening_ports",
            "logged_in_users",
            "process_events",
            "socket_events",
            "file_events",
            "processes",
            "users",
        ] {
            if name.contains(table) {
                return table.to_string();
            }
        }
    }

    let keys: Vec<&String> = first.keys().collect();

    // Process tables
    if keys.contains(&&"cmdline".to_string())
        && keys.contains(&&"pid".to_string())
        && (keys.contains(&&"parent".to_string()) || keys.contains(&&"ppid".to_string()))
    {
        return "processes".to_string();
    }

    // Process events
    if keys.contains(&&"path".to_string())
        && keys.contains(&&"cmdline".to_string())
        && keys.contains(&&"time".to_string())
    {
        return "process_events".to_string();
    }

    // Users table
    if keys.contains(&&"username".to_string())
        && keys.contains(&&"uid".to_string())
        && keys.contains(&&"shell".to_string())
    {
        return "users".to_string();
    }

    // Listening ports
    if keys.contains(&&"port".to_string())
        && keys.contains(&&"address".to_string())
        && keys.contains(&&"protocol".to_string())
    {
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
    if keys.contains(&&"local_address".to_string())
        && keys.contains(&&"remote_address".to_string())
        && keys.contains(&&"action".to_string())
    {
        return "socket_events".to_string();
    }

    "generic".to_string()
}

/// Extract timestamp from osquery record
fn extract_osquery_timestamp(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Option<DateTime<Utc>> {
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

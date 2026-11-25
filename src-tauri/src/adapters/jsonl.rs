//! JSONL Adapter - Parse JSON Lines files into events
//!
//! Handles .jsonl and .ndjson files with one JSON object per line.

use crate::adapters::{extract_timestamp, generate_event_id, Adapter, ParseResult};
use crate::import_types::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// JSONL adapter
#[derive(Default)]
pub struct JsonlAdapter;

impl JsonlAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for JsonlAdapter {
    fn name(&self) -> &'static str {
        "jsonl"
    }

    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::Jsonl | FileKind::Json)
    }

    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path).map_err(|e| format!("Failed to open file: {}", e))?;
        let reader = BufReader::new(f);

        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let mut entries_skipped = 0u64;

        // For JSON files, try to parse as array or single object
        if matches!(file.kind, FileKind::Json) {
            return self.parse_json(file, file_path, bundle_id, limits);
        }

        // Parse JSONL line by line
        for (line_no, line) in reader.lines().enumerate() {
            let line_no = line_no as u64 + 1; // 1-indexed

            // Check line limit
            if entries_processed >= limits.max_lines_per_file {
                warnings.push(format!("Stopped at line {} (limit reached)", line_no));
                break;
            }

            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    warnings.push(format!("Line {}: read error: {}", line_no, e));
                    entries_skipped += 1;
                    continue;
                }
            };

            // Skip empty lines
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Check line length
            if line.len() > limits.max_line_bytes as usize {
                warnings.push(format!("Line {}: exceeds max length", line_no));
                entries_skipped += 1;
                continue;
            }

            // Parse JSON
            let value: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    warnings.push(format!("Line {}: JSON parse error: {}", line_no, e));
                    entries_skipped += 1;
                    continue;
                }
            };

            // Convert to event
            if let Some(event) = self.value_to_event(&value, file, bundle_id, line_no) {
                events.push(event);
            }

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

impl JsonlAdapter {
    /// Parse a single JSON file (may be object or array)
    fn parse_json(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        let value: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| format!("JSON parse error: {}", e))?;

        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;

        match &value {
            serde_json::Value::Array(arr) => {
                for (idx, item) in arr.iter().enumerate() {
                    if entries_processed >= limits.max_lines_per_file {
                        warnings.push(format!("Stopped at entry {} (limit reached)", idx));
                        break;
                    }

                    if let Some(event) = self.value_to_event(item, file, bundle_id, idx as u64) {
                        events.push(event);
                    }
                    entries_processed += 1;
                }
            }
            serde_json::Value::Object(_) => {
                if let Some(event) = self.value_to_event(&value, file, bundle_id, 0) {
                    events.push(event);
                }
                entries_processed = 1;
            }
            _ => {
                warnings.push("JSON root is not object or array".to_string());
            }
        }

        Ok(ParseResult {
            events,
            warnings,
            entries_processed,
            entries_skipped: 0,
        })
    }

    /// Convert a JSON value to an ImportEvent
    fn value_to_event(
        &self,
        value: &serde_json::Value,
        file: &ManifestFile,
        bundle_id: &str,
        index: u64,
    ) -> Option<ImportEvent> {
        self.record_to_event(value, file, bundle_id, index, Some(index + 1), None)
    }

    /// One structured record (a JSON object, a YAML mapping or a CSV row) as
    /// an event: nested fields flattened, the type and tags detected, and the
    /// common entities named once. `line_no` and `json_path` locate it.
    pub(crate) fn record_to_event(
        &self,
        value: &serde_json::Value,
        file: &ManifestFile,
        bundle_id: &str,
        index: u64,
        line_no: Option<u64>,
        json_path: Option<String>,
    ) -> Option<ImportEvent> {
        let nested = value.as_object()?;
        // Nested records (Elastic Common Schema and most SIEM exports) are
        // flattened to dotted keys, such as process.command_line.
        let obj = &flatten_object(nested);

        // Extract timestamp
        let (timestamp, ts_quality) = extract_timestamp(
            value,
            &[
                "timestamp",
                "ts",
                "time",
                "@timestamp",
                "datetime",
                "date",
                "ts_ms",
                "Timestamp",
                "Time",
                "Date",
                "DateTime",
                "EventTime",
                "event_time",
                "created_at",
            ],
        );

        // Determine event type
        let event_type = self.detect_event_type(obj);

        // Build tags based on content
        let tags = self.detect_tags(obj, &event_type);

        // Convert all fields to our format, plus the common entities under
        // one name each so imports from different tools line up.
        let mut fields: HashMap<String, serde_json::Value> = obj.clone().into_iter().collect();
        for (entity, candidates) in ENTITY_FIELDS {
            if fields.contains_key(*entity) {
                continue;
            }
            if let Some(v) = candidates
                .iter()
                .find_map(|k| obj.get(*k).filter(|v| v.is_string() || v.is_number()))
            {
                fields.insert(entity.to_string(), v.clone());
            }
        }

        let evidence_ptr = ImportEvidencePtr {
            bundle_id: bundle_id.to_string(),
            rel_path: file.rel_path.clone(),
            line_no,
            json_path,
            byte_offset: None,
        };

        Some(ImportEvent {
            event_id: generate_event_id(bundle_id, &file.rel_path, index),
            timestamp,
            timestamp_quality: ts_quality,
            event_type,
            source_file: file.rel_path.clone(),
            source_line: line_no,
            fields,
            evidence_ptr,
            tags,
        })
    }

    /// Detect event type from JSON fields
    fn detect_event_type(&self, obj: &serde_json::Map<String, serde_json::Value>) -> String {
        // Check for explicit event type fields (ECS writes event.type and
        // event.category as arrays)
        for field in [
            "event_type",
            "eventType",
            "event.action",
            "type",
            "event.type",
            "event.category",
            "EventID",
            "event_id",
            "action",
        ] {
            if let Some(v) = obj.get(field) {
                let v = v.as_array().and_then(|a| a.first()).unwrap_or(v);
                if let Some(s) = v.as_str() {
                    return s.to_string();
                }
                if let Some(n) = v.as_i64() {
                    return n.to_string();
                }
            }
        }

        // Infer from content
        if obj.contains_key("ProcessId")
            || obj.contains_key("process_id")
            || obj.contains_key("pid")
            || obj.contains_key("process.pid")
        {
            if obj.contains_key("CommandLine")
                || obj.contains_key("cmdline")
                || obj.contains_key("process.command_line")
            {
                return "process_creation".to_string();
            }
            return "process".to_string();
        }

        if obj.contains_key("DestinationIp")
            || obj.contains_key("dst_ip")
            || obj.contains_key("dest_ip")
            || obj.contains_key("destination.ip")
        {
            return "network_connection".to_string();
        }

        if obj.contains_key("url")
            || obj.contains_key("URL")
            || obj.contains_key("url.full")
            || obj.contains_key("url.original")
        {
            return "http_request".to_string();
        }

        if obj.contains_key("dns")
            || obj.contains_key("query")
            || obj.contains_key("dns.question.name")
        {
            return "dns_query".to_string();
        }

        // A user name alone does not make an authentication event, a logon
        // type or an authentication outcome does.
        if obj.contains_key("LogonType")
            || obj.contains_key("logon_type")
            || obj.contains_key("authentication")
            || obj.contains_key("auth_result")
        {
            return "auth_event".to_string();
        }

        "generic".to_string()
    }

    /// Detect tags for playbook routing
    fn detect_tags(
        &self,
        obj: &serde_json::Map<String, serde_json::Value>,
        event_type: &str,
    ) -> Vec<String> {
        let mut tags = vec![event_type.to_string()];

        // Add category tags based on content
        if obj.contains_key("ProcessId") || obj.contains_key("process_id") {
            tags.push("process".to_string());
        }

        if obj.contains_key("CommandLine")
            || obj.contains_key("cmdline")
            || obj.contains_key("command_line")
            || obj.contains_key("process.command_line")
        {
            tags.push("process_creation".to_string());
        }

        if obj.contains_key("DestinationIp")
            || obj.contains_key("dst_ip")
            || obj.contains_key("remote_ip")
            || obj.contains_key("destination.ip")
        {
            tags.push("network".to_string());
        }

        if obj.contains_key("ParentProcessId") || obj.contains_key("parent_pid") {
            tags.push("process_tree".to_string());
        }

        // Check for PowerShell indicators
        if let Some(cmd) = obj
            .get("CommandLine")
            .or(obj.get("cmdline"))
            .or(obj.get("command_line"))
            .or(obj.get("process.command_line"))
        {
            if let Some(s) = cmd.as_str() {
                let lower = s.to_lowercase();
                if lower.contains("powershell") || lower.contains("pwsh") {
                    tags.push("powershell".to_string());
                }
                if lower.contains("-enc") || lower.contains("-encoded") {
                    tags.push("encoded_command".to_string());
                }
            }
        }

        // Check for suspicious file types
        if let Some(path) = obj
            .get("TargetFilename")
            .or(obj.get("path"))
            .or(obj.get("file_path"))
        {
            if let Some(s) = path.as_str() {
                let lower = s.to_lowercase();
                if lower.ends_with(".exe")
                    || lower.ends_with(".dll")
                    || lower.ends_with(".ps1")
                    || lower.ends_with(".bat")
                    || lower.ends_with(".cmd")
                {
                    tags.push("executable".to_string());
                }
            }
        }

        tags.dedup();
        tags
    }
}

/// Entity fields added to every JSON event, with the source keys tried in order
const ENTITY_FIELDS: &[(&str, &[&str])] = &[
    (
        "process_name",
        &["process.name", "process_name", "ProcessName", "Image"],
    ),
    (
        "command_line",
        &[
            "process.command_line",
            "CommandLine",
            "cmdline",
            "command_line",
        ],
    ),
    ("user_name", &["user.name", "User", "username", "user"]),
    (
        "hostname",
        &["host.name", "host.hostname", "hostname", "Computer", "host"],
    ),
    ("src_ip", &["source.ip", "src_ip", "SourceIp", "client.ip"]),
    (
        "dest_ip",
        &[
            "destination.ip",
            "dest_ip",
            "dst_ip",
            "DestinationIp",
            "server.ip",
        ],
    ),
    (
        "dest_port",
        &[
            "destination.port",
            "dest_port",
            "dst_port",
            "DestinationPort",
        ],
    ),
];

/// Copy nested objects into dotted keys: {"process": {"pid": 1}} becomes
/// {"process.pid": 1}. Arrays and plain values stay as they are.
fn flatten_object(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    fn walk(
        prefix: &str,
        obj: &serde_json::Map<String, serde_json::Value>,
        out: &mut serde_json::Map<String, serde_json::Value>,
        depth: usize,
    ) {
        for (k, v) in obj {
            let key = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{}.{}", prefix, k)
            };
            match v {
                serde_json::Value::Object(inner) if depth < 8 => walk(&key, inner, out, depth + 1),
                _ => {
                    out.insert(key, v.clone());
                }
            }
        }
    }
    let mut out = serde_json::Map::new();
    walk("", obj, &mut out, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_detection() {
        let adapter = JsonlAdapter::new();

        let obj: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
            r#"{
            "ProcessId": 1234,
            "CommandLine": "cmd.exe"
        }"#,
        )
        .unwrap();

        assert_eq!(adapter.detect_event_type(&obj), "process_creation");
    }

    #[test]
    fn test_tag_detection() {
        let adapter = JsonlAdapter::new();

        let obj: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
            r#"{
            "ProcessId": 1234,
            "CommandLine": "powershell.exe -EncodedCommand ABC123"
        }"#,
        )
        .unwrap();

        let tags = adapter.detect_tags(&obj, "process_creation");
        assert!(tags.contains(&"powershell".to_string()));
        assert!(tags.contains(&"encoded_command".to_string()));
    }

    #[test]
    fn test_ecs_record_is_flattened_and_typed() {
        let adapter = JsonlAdapter::new();
        let nested: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
            r#"{
            "@timestamp": "2024-01-01T00:02:00Z",
            "event": {"action": "process_start", "category": ["process"]},
            "process": {"name": "rundll32.exe", "pid": 5555},
            "user": {"name": "alice"}
        }"#,
        )
        .unwrap();
        let flat = flatten_object(&nested);
        assert_eq!(flat["process.name"], "rundll32.exe");
        assert_eq!(adapter.detect_event_type(&flat), "process_start");

        // A user name alone is not an authentication event
        let only_user: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"user": "alice", "message": "hello"}"#).unwrap();
        assert_eq!(adapter.detect_event_type(&only_user), "generic");
    }
}

//! Zeek Adapter - Parse Zeek/Bro log files into events
//!
//! Zeek produces TSV-format logs with a specific header structure.
//! This adapter handles conn.log, dns.log, http.log, ssl.log, files.log etc.

use crate::adapters::{Adapter, ParseResult, generate_event_id, parse_timestamp};
use crate::import_types::*;
use std::collections::HashMap;
use std::path::Path;
use std::io::{BufRead, BufReader};
use std::fs::File;
use chrono::{DateTime, Utc, TimeZone};

/// Zeek adapter for TSV-format logs
pub struct ZeekAdapter;

impl ZeekAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for ZeekAdapter {
    fn name(&self) -> &'static str {
        "zeek"
    }
    
    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, 
            FileKind::ZeekConn | FileKind::ZeekDns | FileKind::ZeekHttp | 
            FileKind::ZeekSsl | FileKind::ZeekFiles | FileKind::Zeek
        )
    }
    
    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path)
            .map_err(|e| format!("Failed to open Zeek file: {}", e))?;
        let reader = BufReader::new(f);
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let mut entries_skipped = 0u64;
        
        // Parse Zeek header to get field names
        let mut separator = "\t".to_string();
        let mut fields: Vec<String> = Vec::new();
        let mut types: Vec<String> = Vec::new();
        let mut line_no = 0u64;
        
        for line_result in reader.lines() {
            line_no += 1;
            
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    warnings.push(format!("Line {}: read error: {}", line_no, e));
                    entries_skipped += 1;
                    continue;
                }
            };
            
            // Parse header lines
            if line.starts_with("#separator") {
                // #separator \x09
                if let Some(sep) = line.strip_prefix("#separator ") {
                    separator = parse_separator(sep);
                }
                continue;
            }
            if line.starts_with("#set_separator") || line.starts_with("#empty_field") ||
               line.starts_with("#unset_field") || line.starts_with("#path") ||
               line.starts_with("#open") || line.starts_with("#close") {
                continue;
            }
            if line.starts_with("#fields") {
                fields = line.strip_prefix("#fields")
                    .unwrap_or("")
                    .split(&separator)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                continue;
            }
            if line.starts_with("#types") {
                types = line.strip_prefix("#types")
                    .unwrap_or("")
                    .split(&separator)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                continue;
            }
            if line.starts_with('#') {
                // Unknown header, skip
                continue;
            }
            
            // Data line - ensure we have fields
            if fields.is_empty() {
                warnings.push(format!("Line {}: no #fields header found", line_no));
                entries_skipped += 1;
                continue;
            }
            
            if entries_processed >= limits.max_lines_per_file {
                warnings.push(format!("Stopped at line {} (limit reached)", line_no));
                break;
            }
            
            // Parse data row
            let values: Vec<&str> = line.split(&separator).collect();
            if values.len() != fields.len() {
                warnings.push(format!("Line {}: field count mismatch ({} vs {})", 
                    line_no, values.len(), fields.len()));
                entries_skipped += 1;
                continue;
            }
            
            // Build field map
            let mut field_map: HashMap<String, serde_json::Value> = HashMap::new();
            for (i, field_name) in fields.iter().enumerate() {
                let value = values[i];
                if value == "-" || value == "(empty)" {
                    continue; // Skip unset fields
                }
                
                // Try to parse based on field type if available
                let parsed = if i < types.len() {
                    parse_zeek_value(value, &types[i])
                } else {
                    serde_json::Value::String(value.to_string())
                };
                
                field_map.insert(field_name.clone(), parsed);
            }
            
            // Create event
            if let Some(event) = self.row_to_event(
                &field_map, &file.kind, file, bundle_id, line_no
            ) {
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

impl ZeekAdapter {
    /// Convert a parsed row to an ImportEvent
    fn row_to_event(
        &self,
        field_map: &HashMap<String, serde_json::Value>,
        kind: &FileKind,
        file: &ManifestFile,
        bundle_id: &str,
        line_no: u64,
    ) -> Option<ImportEvent> {
        // Extract timestamp (Zeek uses 'ts' field as Unix epoch float)
        let timestamp = field_map.get("ts")
            .and_then(|v| v.as_f64())
            .map(|ts| {
                let secs = ts as i64;
                let nanos = ((ts - secs as f64) * 1_000_000_000.0) as u32;
                Utc.timestamp_opt(secs, nanos).single()
            })
            .flatten()
            .unwrap_or_else(Utc::now);
        
        let ts_quality = if field_map.contains_key("ts") {
            TimestampQuality::Precise
        } else {
            TimestampQuality::Unknown
        };
        
        // Determine event type based on file kind
        let event_type = match kind {
            FileKind::ZeekConn => "zeek_conn",
            FileKind::ZeekDns => "zeek_dns",
            FileKind::ZeekHttp => "zeek_http",
            FileKind::ZeekSsl => "zeek_ssl",
            FileKind::ZeekFiles => "zeek_files",
            _ => "zeek_log",
        }.to_string();
        
        // Build tags based on content
        let mut tags = vec!["zeek".to_string(), "network".to_string()];
        
        match kind {
            FileKind::ZeekConn => {
                tags.push("connection".to_string());
                // Check for interesting connection patterns
                if let Some(service) = field_map.get("service").and_then(|v| v.as_str()) {
                    if !service.is_empty() && service != "-" {
                        tags.push(format!("service_{}", service.to_lowercase()));
                    }
                }
                // Check for large data transfers
                if let Some(bytes) = field_map.get("orig_bytes").and_then(|v| v.as_i64()) {
                    if bytes > 10_000_000 {
                        tags.push("large_transfer".to_string());
                    }
                }
                // Check for long duration (potential C2 beacon)
                if let Some(duration) = field_map.get("duration").and_then(|v| v.as_f64()) {
                    if duration > 3600.0 {
                        tags.push("long_connection".to_string());
                    }
                }
            }
            FileKind::ZeekDns => {
                tags.push("dns".to_string());
                // Check for interesting query types
                if let Some(qtype) = field_map.get("qtype_name").and_then(|v| v.as_str()) {
                    match qtype.to_uppercase().as_str() {
                        "TXT" => tags.push("dns_txt".to_string()),
                        "MX" => tags.push("dns_mx".to_string()),
                        "AAAA" | "A" => {}
                        _ => tags.push(format!("dns_{}", qtype.to_lowercase())),
                    }
                }
                // Check for NXDOMAIN (potential DGA)
                if let Some(rcode) = field_map.get("rcode_name").and_then(|v| v.as_str()) {
                    if rcode == "NXDOMAIN" {
                        tags.push("nxdomain".to_string());
                    }
                }
                // Check query length (potential DNS tunneling)
                if let Some(query) = field_map.get("query").and_then(|v| v.as_str()) {
                    if query.len() > 50 {
                        tags.push("long_query".to_string());
                    }
                    // Check for suspicious TLDs
                    let query_lower = query.to_lowercase();
                    if query_lower.ends_with(".xyz") || query_lower.ends_with(".top") ||
                       query_lower.ends_with(".tk") || query_lower.ends_with(".ml") {
                        tags.push("suspicious_tld".to_string());
                    }
                }
            }
            FileKind::ZeekHttp => {
                tags.push("http".to_string());
                // Check method
                if let Some(method) = field_map.get("method").and_then(|v| v.as_str()) {
                    if method == "POST" {
                        tags.push("http_post".to_string());
                    }
                }
                // Check for suspicious URIs
                if let Some(uri) = field_map.get("uri").and_then(|v| v.as_str()) {
                    let uri_lower = uri.to_lowercase();
                    if uri_lower.contains(".exe") || uri_lower.contains(".dll") ||
                       uri_lower.contains(".ps1") || uri_lower.contains(".bat") {
                        tags.push("suspicious_download".to_string());
                    }
                }
                // Check user agent
                if let Some(ua) = field_map.get("user_agent").and_then(|v| v.as_str()) {
                    let ua_lower = ua.to_lowercase();
                    if ua_lower.contains("powershell") || ua_lower.contains("wget") ||
                       ua_lower.contains("curl") {
                        tags.push("script_ua".to_string());
                    }
                }
                // Check status code
                if let Some(status) = field_map.get("status_code").and_then(|v| v.as_i64()) {
                    if status == 401 || status == 403 {
                        tags.push("auth_failure".to_string());
                    }
                }
            }
            FileKind::ZeekSsl => {
                tags.push("ssl".to_string());
                // Check for self-signed or expired certs
                if let Some(validation) = field_map.get("validation_status").and_then(|v| v.as_str()) {
                    if validation.contains("self signed") || validation.contains("expired") {
                        tags.push("cert_issue".to_string());
                    }
                }
                // Check for unusual TLS versions
                if let Some(version) = field_map.get("version").and_then(|v| v.as_str()) {
                    if version.contains("SSLv") || version == "TLSv10" || version == "TLSv11" {
                        tags.push("old_tls".to_string());
                    }
                }
            }
            FileKind::ZeekFiles => {
                tags.push("file_transfer".to_string());
                // Check mime type
                if let Some(mime) = field_map.get("mime_type").and_then(|v| v.as_str()) {
                    let mime_lower = mime.to_lowercase();
                    if mime_lower.contains("executable") || mime_lower.contains("x-msdownload") ||
                       mime_lower.contains("x-msdos") {
                        tags.push("executable".to_string());
                    }
                    if mime_lower.contains("javascript") {
                        tags.push("javascript".to_string());
                    }
                }
                // Check for extracted files
                if field_map.contains_key("extracted") {
                    tags.push("extracted_file".to_string());
                }
            }
            _ => {}
        }
        
        let evidence_ptr = ImportEvidencePtr {
            bundle_id: bundle_id.to_string(),
            rel_path: file.rel_path.clone(),
            line_no: Some(line_no),
            json_path: None,
            byte_offset: None,
        };
        
        Some(ImportEvent {
            event_id: generate_event_id(bundle_id, &file.rel_path, line_no),
            timestamp,
            timestamp_quality: ts_quality,
            event_type,
            source_file: file.rel_path.clone(),
            source_line: Some(line_no),
            fields: field_map.clone(),
            evidence_ptr,
            tags,
        })
    }
}

/// Parse Zeek's separator encoding (e.g., \x09 -> tab)
fn parse_separator(sep: &str) -> String {
    if sep.starts_with("\\x") && sep.len() >= 4 {
        if let Ok(byte) = u8::from_str_radix(&sep[2..4], 16) {
            return String::from(byte as char);
        }
    }
    sep.to_string()
}

/// Parse a Zeek value based on its type
fn parse_zeek_value(value: &str, type_str: &str) -> serde_json::Value {
    match type_str {
        "time" => {
            // Unix timestamp as float
            value.parse::<f64>()
                .map(serde_json::Value::from)
                .unwrap_or_else(|_| serde_json::Value::String(value.to_string()))
        }
        "interval" | "double" => {
            value.parse::<f64>()
                .map(serde_json::Value::from)
                .unwrap_or_else(|_| serde_json::Value::String(value.to_string()))
        }
        "count" | "int" | "port" => {
            value.parse::<i64>()
                .map(serde_json::Value::from)
                .unwrap_or_else(|_| serde_json::Value::String(value.to_string()))
        }
        "bool" => {
            serde_json::Value::Bool(value == "T" || value == "true")
        }
        "set[string]" | "vector[string]" => {
            // Comma-separated values
            let items: Vec<serde_json::Value> = value
                .split(',')
                .map(|s| serde_json::Value::String(s.to_string()))
                .collect();
            serde_json::Value::Array(items)
        }
        "addr" | "string" | _ => {
            serde_json::Value::String(value.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_separator() {
        assert_eq!(parse_separator("\\x09"), "\t");
        assert_eq!(parse_separator("\\x2c"), ",");
        assert_eq!(parse_separator(","), ",");
    }
    
    #[test]
    fn test_parse_zeek_value() {
        assert_eq!(
            parse_zeek_value("1234567890.123456", "time"),
            serde_json::json!(1234567890.123456)
        );
        assert_eq!(
            parse_zeek_value("443", "port"),
            serde_json::json!(443)
        );
        assert_eq!(
            parse_zeek_value("T", "bool"),
            serde_json::json!(true)
        );
        assert_eq!(
            parse_zeek_value("F", "bool"),
            serde_json::json!(false)
        );
    }
}

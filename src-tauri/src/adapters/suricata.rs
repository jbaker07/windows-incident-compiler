//! Suricata EVE JSON Adapter - Parse Suricata eve.json alerts
//!
//! Parses Suricata EVE JSON output for network security events:
//! - alert: IDS/IPS alerts with signatures
//! - dns: DNS query/response logs
//! - http: HTTP transaction logs
//! - tls: TLS handshake metadata
//! - flow: Network flow records

use crate::adapters::{Adapter, ParseResult, generate_event_id};
use crate::import_types::*;
use std::collections::HashMap;
use std::path::Path;
use std::io::{BufRead, BufReader};
use std::fs::File;
use chrono::{DateTime, Utc};

pub struct SuricataAdapter;

impl SuricataAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for SuricataAdapter {
    fn name(&self) -> &'static str {
        "suricata"
    }
    
    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::SuricataEve)
    }
    
    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path)
            .map_err(|e| format!("Failed to open EVE JSON: {}", e))?;
        let reader = BufReader::new(f);
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let mut entries_skipped = 0u64;
        
        for (line_no, line_result) in reader.lines().enumerate() {
            if entries_processed >= limits.max_events as u64 {
                warnings.push(format!("Event limit reached at line {}", line_no + 1));
                break;
            }
            
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    warnings.push(format!("Line {} read error: {}", line_no + 1, e));
                    entries_skipped += 1;
                    continue;
                }
            };
            
            if line.trim().is_empty() {
                continue;
            }
            
            let json: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    warnings.push(format!("Line {} JSON parse error: {}", line_no + 1, e));
                    entries_skipped += 1;
                    continue;
                }
            };
            
            let event_type = json.get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            
            let timestamp = json.get("timestamp")
                .and_then(|v| v.as_str())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);
            
            let src_ip = json.get("src_ip").and_then(|v| v.as_str()).unwrap_or("");
            let dest_ip = json.get("dest_ip").and_then(|v| v.as_str()).unwrap_or("");
            let src_port = json.get("src_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let dest_port = json.get("dest_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let proto = json.get("proto").and_then(|v| v.as_str()).unwrap_or("");
            
            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            fields.insert("src_ip".to_string(), serde_json::json!(src_ip));
            fields.insert("dest_ip".to_string(), serde_json::json!(dest_ip));
            fields.insert("src_port".to_string(), serde_json::json!(src_port));
            fields.insert("dest_port".to_string(), serde_json::json!(dest_port));
            fields.insert("protocol".to_string(), serde_json::json!(proto));
            
            let mut tags = vec!["suricata".to_string()];
            
            let canonical_event_type = match event_type {
                "alert" => {
                    tags.push("alert".to_string());
                    tags.push("ids".to_string());
                    
                    if let Some(alert) = json.get("alert") {
                        let signature = alert.get("signature")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let signature_id = alert.get("signature_id")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let category = alert.get("category")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let severity = alert.get("severity")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(3);
                        
                        fields.insert("signature".to_string(), serde_json::json!(signature));
                        fields.insert("signature_id".to_string(), serde_json::json!(signature_id));
                        fields.insert("category".to_string(), serde_json::json!(category));
                        fields.insert("severity".to_string(), serde_json::json!(severity));
                        
                        // Add category-specific tags
                        let category_lower = category.to_lowercase();
                        if category_lower.contains("malware") {
                            tags.push("malware".to_string());
                        }
                        if category_lower.contains("exploit") {
                            tags.push("exploit".to_string());
                        }
                        if category_lower.contains("trojan") {
                            tags.push("trojan".to_string());
                        }
                        if category_lower.contains("c2") || category_lower.contains("command") {
                            tags.push("c2".to_string());
                        }
                    }
                    
                    "net_alert"
                }
                "dns" => {
                    tags.push("dns".to_string());
                    
                    if let Some(dns) = json.get("dns") {
                        let query_type = dns.get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("query");
                        let rrname = dns.get("rrname")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let rrtype = dns.get("rrtype")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let rcode = dns.get("rcode")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        
                        fields.insert("dns_type".to_string(), serde_json::json!(query_type));
                        fields.insert("query".to_string(), serde_json::json!(rrname));
                        fields.insert("rrtype".to_string(), serde_json::json!(rrtype));
                        fields.insert("rcode".to_string(), serde_json::json!(rcode));
                        
                        // Extract answers
                        if let Some(answers) = dns.get("answers") {
                            fields.insert("answers".to_string(), answers.clone());
                        }
                    }
                    
                    "dns_query"
                }
                "http" => {
                    tags.push("http".to_string());
                    tags.push("web".to_string());
                    
                    if let Some(http) = json.get("http") {
                        let hostname = http.get("hostname")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let url = http.get("url")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let method = http.get("http_method")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let status = http.get("status")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let user_agent = http.get("http_user_agent")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        
                        fields.insert("hostname".to_string(), serde_json::json!(hostname));
                        fields.insert("url".to_string(), serde_json::json!(url));
                        fields.insert("method".to_string(), serde_json::json!(method));
                        fields.insert("status".to_string(), serde_json::json!(status));
                        fields.insert("user_agent".to_string(), serde_json::json!(user_agent));
                    }
                    
                    "http_txn"
                }
                "tls" => {
                    tags.push("tls".to_string());
                    tags.push("encrypted".to_string());
                    
                    if let Some(tls) = json.get("tls") {
                        let sni = tls.get("sni")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let version = tls.get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let subject = tls.get("subject")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let issuerdn = tls.get("issuerdn")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let ja3 = tls.get("ja3")
                            .and_then(|v| v.as_object())
                            .and_then(|o| o.get("hash"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        
                        fields.insert("sni".to_string(), serde_json::json!(sni));
                        fields.insert("tls_version".to_string(), serde_json::json!(version));
                        fields.insert("subject".to_string(), serde_json::json!(subject));
                        fields.insert("issuer".to_string(), serde_json::json!(issuerdn));
                        if !ja3.is_empty() {
                            fields.insert("ja3".to_string(), serde_json::json!(ja3));
                        }
                    }
                    
                    "tls_handshake"
                }
                "flow" => {
                    tags.push("netflow".to_string());
                    
                    if let Some(flow) = json.get("flow") {
                        let pkts_toserver = flow.get("pkts_toserver")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let pkts_toclient = flow.get("pkts_toclient")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let bytes_toserver = flow.get("bytes_toserver")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let bytes_toclient = flow.get("bytes_toclient")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let state = flow.get("state")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        
                        fields.insert("pkts_toserver".to_string(), serde_json::json!(pkts_toserver));
                        fields.insert("pkts_toclient".to_string(), serde_json::json!(pkts_toclient));
                        fields.insert("bytes_toserver".to_string(), serde_json::json!(bytes_toserver));
                        fields.insert("bytes_toclient".to_string(), serde_json::json!(bytes_toclient));
                        fields.insert("flow_state".to_string(), serde_json::json!(state));
                    }
                    
                    "netflow"
                }
                "fileinfo" => {
                    tags.push("fileinfo".to_string());
                    
                    if let Some(fileinfo) = json.get("fileinfo") {
                        let filename = fileinfo.get("filename")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let size = fileinfo.get("size")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let md5 = fileinfo.get("md5")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let sha256 = fileinfo.get("sha256")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        
                        fields.insert("filename".to_string(), serde_json::json!(filename));
                        fields.insert("size".to_string(), serde_json::json!(size));
                        if !md5.is_empty() {
                            fields.insert("md5".to_string(), serde_json::json!(md5));
                        }
                        if !sha256.is_empty() {
                            fields.insert("sha256".to_string(), serde_json::json!(sha256));
                        }
                    }
                    
                    "file_observed"
                }
                other => {
                    tags.push(other.to_string());
                    other
                }
            };
            
            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp,
                timestamp_quality: TimestampQuality::Precise,
                event_type: canonical_event_type.to_string(),
                source_file: file.rel_path.clone(),
                source_line: Some(line_no + 1),
                fields,
                evidence_ptr: ImportEvidencePtr {
                    bundle_id: bundle_id.to_string(),
                    rel_path: file.rel_path.clone(),
                    line_no: Some(line_no + 1),
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
            entries_skipped,
        })
    }
}

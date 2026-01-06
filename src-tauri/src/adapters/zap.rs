//! OWASP ZAP JSON Adapter - Parse ZAP scan results
//!
//! Parses OWASP ZAP JSON export including:
//! - site: Target site information
//! - alerts: Security findings with risk levels
//! - instances: Specific occurrences of vulnerabilities

use crate::adapters::{Adapter, ParseResult, generate_event_id};
use crate::import_types::*;
use std::collections::HashMap;
use std::path::Path;
use std::io::BufReader;
use std::fs::File;
use chrono::Utc;

pub struct ZapAdapter;

impl ZapAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for ZapAdapter {
    fn name(&self) -> &'static str {
        "zap"
    }
    
    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::ZapJson)
    }
    
    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path)
            .map_err(|e| format!("Failed to open ZAP JSON: {}", e))?;
        let reader = BufReader::new(f);
        
        let json: serde_json::Value = serde_json::from_reader(reader)
            .map_err(|e| format!("Failed to parse ZAP JSON: {}", e))?;
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let timestamp = Utc::now();
        
        // ZAP JSON structure can vary - handle multiple formats
        let sites = if let Some(arr) = json.get("site").and_then(|v| v.as_array()) {
            arr.clone()
        } else if let Some(obj) = json.get("site").and_then(|v| v.as_object()) {
            vec![serde_json::json!(obj)]
        } else if let Some(arr) = json.as_array() {
            arr.clone()
        } else {
            warnings.push("Unknown ZAP format - expected {site:[]} or [{...}]".to_string());
            Vec::new()
        };
        
        for site in &sites {
            let site_name = site.get("@name")
                .or_else(|| site.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let site_host = site.get("@host")
                .or_else(|| site.get("host"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let site_port = site.get("@port")
                .or_else(|| site.get("port"))
                .and_then(|v| v.as_str())
                .or_else(|| site.get("@port").and_then(|v| v.as_u64()).map(|n| n.to_string()).as_deref().map(|s| s.to_string()).as_deref())
                .unwrap_or("80");
            let site_ssl = site.get("@ssl")
                .or_else(|| site.get("ssl"))
                .and_then(|v| v.as_str())
                .unwrap_or("false");
            
            // Extract alerts
            let alerts = if let Some(arr) = site.get("alerts").and_then(|v| v.as_array()) {
                arr.clone()
            } else if let Some(arr) = site.get("alert").and_then(|v| v.as_array()) {
                arr.clone()
            } else {
                Vec::new()
            };
            
            for alert in &alerts {
                if entries_processed >= limits.max_events as u64 {
                    warnings.push("Event limit reached".to_string());
                    break;
                }
                
                let alert_name = alert.get("name")
                    .or_else(|| alert.get("alert"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown Alert");
                let risk = alert.get("riskcode")
                    .or_else(|| alert.get("risk"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0");
                let confidence = alert.get("confidence")
                    .or_else(|| alert.get("reliability"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0");
                let description = alert.get("desc")
                    .or_else(|| alert.get("description"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let solution = alert.get("solution")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let reference = alert.get("reference")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let cwe_id = alert.get("cweid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let wasc_id = alert.get("wascid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let plugin_id = alert.get("pluginid")
                    .or_else(|| alert.get("pluginId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                
                let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
                fields.insert("alert_name".to_string(), serde_json::json!(alert_name));
                fields.insert("site".to_string(), serde_json::json!(site_name));
                fields.insert("host".to_string(), serde_json::json!(site_host));
                fields.insert("port".to_string(), serde_json::json!(site_port));
                fields.insert("ssl".to_string(), serde_json::json!(site_ssl == "true"));
                fields.insert("risk_code".to_string(), serde_json::json!(risk));
                fields.insert("confidence".to_string(), serde_json::json!(confidence));
                fields.insert("plugin_id".to_string(), serde_json::json!(plugin_id));
                
                // Risk level mapping
                let risk_level = match risk {
                    "3" => "High",
                    "2" => "Medium",
                    "1" => "Low",
                    "0" => "Informational",
                    _ => "Unknown",
                };
                fields.insert("risk_level".to_string(), serde_json::json!(risk_level));
                
                if !description.is_empty() {
                    // Strip HTML tags from description
                    let clean_desc = strip_html_tags(description);
                    fields.insert("description".to_string(), serde_json::json!(clean_desc));
                }
                if !solution.is_empty() {
                    let clean_solution = strip_html_tags(solution);
                    fields.insert("solution".to_string(), serde_json::json!(clean_solution));
                }
                if !reference.is_empty() {
                    fields.insert("reference".to_string(), serde_json::json!(reference));
                }
                if !cwe_id.is_empty() && cwe_id != "0" {
                    fields.insert("cwe_id".to_string(), serde_json::json!(format!("CWE-{}", cwe_id)));
                }
                if !wasc_id.is_empty() && wasc_id != "0" {
                    fields.insert("wasc_id".to_string(), serde_json::json!(format!("WASC-{}", wasc_id)));
                }
                
                // Extract instances (specific URLs where vulnerability was found)
                let instances = alert.get("instances")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .take(10) // Limit instances
                            .filter_map(|i| {
                                let uri = i.get("uri").and_then(|v| v.as_str())?;
                                let method = i.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
                                let param = i.get("param").and_then(|v| v.as_str()).unwrap_or("");
                                Some(serde_json::json!({
                                    "uri": uri,
                                    "method": method,
                                    "param": param
                                }))
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                
                if !instances.is_empty() {
                    fields.insert("instances".to_string(), serde_json::json!(instances));
                    fields.insert("instance_count".to_string(), serde_json::json!(instances.len()));
                }
                
                let mut tags = vec![
                    "zap".to_string(),
                    "web_scan".to_string(),
                    "vulnerability".to_string(),
                ];
                
                // Add risk-level tag
                match risk_level {
                    "High" => tags.push("high_risk".to_string()),
                    "Medium" => tags.push("medium_risk".to_string()),
                    "Low" => tags.push("low_risk".to_string()),
                    _ => tags.push("info".to_string()),
                }
                
                // Add vulnerability category tags based on alert name
                let alert_lower = alert_name.to_lowercase();
                if alert_lower.contains("xss") || alert_lower.contains("cross-site scripting") {
                    tags.push("xss".to_string());
                }
                if alert_lower.contains("sql") || alert_lower.contains("injection") {
                    tags.push("injection".to_string());
                }
                if alert_lower.contains("csrf") {
                    tags.push("csrf".to_string());
                }
                if alert_lower.contains("ssl") || alert_lower.contains("tls") || alert_lower.contains("certificate") {
                    tags.push("tls".to_string());
                }
                if alert_lower.contains("header") {
                    tags.push("security_headers".to_string());
                }
                if alert_lower.contains("disclosure") || alert_lower.contains("information") {
                    tags.push("information_disclosure".to_string());
                }
                
                events.push(ImportEvent {
                    event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                    timestamp,
                    timestamp_quality: TimestampQuality::ImportTime,
                    event_type: "web_vulnerability".to_string(),
                    source_file: file.rel_path.clone(),
                    source_line: None,
                    fields,
                    evidence_ptr: ImportEvidencePtr {
                        bundle_id: bundle_id.to_string(),
                        rel_path: file.rel_path.clone(),
                        line_no: None,
                        json_path: Some(format!("site[{}].alerts[{}]", 
                            sites.iter().position(|s| s == site).unwrap_or(0),
                            alerts.iter().position(|a| a == alert).unwrap_or(0)
                        )),
                        byte_offset: None,
                    },
                    tags,
                });
                
                entries_processed += 1;
            }
        }
        
        Ok(ParseResult {
            events,
            warnings,
            entries_processed,
            entries_skipped: 0,
        })
    }
}

/// Strip HTML tags from a string (basic implementation)
fn strip_html_tags(input: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    
    for c in input.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(c),
            _ => {}
        }
    }
    
    // Clean up HTML entities
    result
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&nbsp;", " ")
        .replace("\r\n", " ")
        .replace('\n', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

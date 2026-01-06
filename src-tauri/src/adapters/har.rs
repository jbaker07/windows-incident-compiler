//! HAR Adapter - Parse HTTP Archive files into events
//!
//! HAR (HTTP Archive) is a JSON format for recording HTTP requests/responses.
//! This adapter extracts security-relevant events from HAR files.

use crate::adapters::{Adapter, ParseResult, generate_event_id, parse_timestamp};
use crate::import_types::*;
use std::collections::HashMap;
use std::path::Path;
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// HAR adapter
pub struct HarAdapter;

impl HarAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for HarAdapter {
    fn name(&self) -> &'static str {
        "har"
    }
    
    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::Har)
    }
    
    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read HAR file: {}", e))?;
        
        let har: HarFile = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse HAR JSON: {}", e))?;
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        
        for (idx, entry) in har.log.entries.iter().enumerate() {
            if entries_processed >= limits.max_lines_per_file {
                warnings.push(format!("Stopped at entry {} (limit reached)", idx));
                break;
            }
            
            // Parse request event
            if let Some(event) = self.entry_to_event(entry, file, bundle_id, idx as u64) {
                events.push(event);
            }
            
            entries_processed += 1;
        }
        
        // Add summary events for patterns
        let summary_events = self.detect_patterns(&har.log.entries, file, bundle_id);
        events.extend(summary_events);
        
        Ok(ParseResult {
            events,
            warnings,
            entries_processed,
            entries_skipped: 0,
        })
    }
}

impl HarAdapter {
    /// Convert a HAR entry to an ImportEvent
    fn entry_to_event(
        &self,
        entry: &HarEntry,
        file: &ManifestFile,
        bundle_id: &str,
        index: u64,
    ) -> Option<ImportEvent> {
        let timestamp = parse_timestamp(&entry.started_date_time)
            .unwrap_or_else(Utc::now);
        let ts_quality = if parse_timestamp(&entry.started_date_time).is_some() {
            TimestampQuality::Precise
        } else {
            TimestampQuality::Unknown
        };
        
        // Extract URL parts
        let url = &entry.request.url;
        let method = &entry.request.method;
        let status = entry.response.status;
        
        // Parse URL for domain
        let domain = url.split("://")
            .nth(1)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.split(':').next())
            .unwrap_or("unknown")
            .to_string();
        
        // Build tags
        let mut tags = vec!["http_request".to_string(), "network".to_string()];
        
        // Add method-based tags
        if method.eq_ignore_ascii_case("POST") {
            tags.push("http_post".to_string());
        }
        
        // Check for suspicious patterns
        let url_lower = url.to_lowercase();
        if url_lower.contains(".exe") || url_lower.contains(".dll") || 
           url_lower.contains(".ps1") || url_lower.contains(".bat") {
            tags.push("suspicious_download".to_string());
        }
        
        // Check response for auth endpoints
        if url_lower.contains("login") || url_lower.contains("auth") || 
           url_lower.contains("signin") || url_lower.contains("token") {
            tags.push("auth_endpoint".to_string());
        }
        
        // Check for error statuses
        if status == 401 || status == 403 {
            tags.push("auth_failure".to_string());
        }
        if status >= 500 {
            tags.push("server_error".to_string());
        }
        
        // Check headers for auth tokens (redact in display but flag)
        let has_auth_header = entry.request.headers.iter()
            .any(|h| {
                let name_lower = h.name.to_lowercase();
                name_lower == "authorization" || name_lower == "cookie" || 
                name_lower == "x-auth-token" || name_lower == "x-api-key"
            });
        if has_auth_header {
            tags.push("has_auth_token".to_string());
        }
        
        // Check content type
        let content_type = entry.response.content.mime_type.as_deref().unwrap_or("");
        if content_type.contains("javascript") {
            tags.push("javascript".to_string());
        }
        if content_type.contains("octet-stream") || content_type.contains("application/x-") {
            tags.push("binary_content".to_string());
        }
        
        // Build fields
        let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
        fields.insert("url".to_string(), serde_json::json!(url));
        fields.insert("method".to_string(), serde_json::json!(method));
        fields.insert("status".to_string(), serde_json::json!(status));
        fields.insert("domain".to_string(), serde_json::json!(domain));
        fields.insert("content_type".to_string(), serde_json::json!(content_type));
        
        // Add timing if available
        if entry.time > 0.0 {
            fields.insert("duration_ms".to_string(), serde_json::json!(entry.time));
        }
        
        // Add response size
        let response_size = entry.response.content.size.unwrap_or(0);
        fields.insert("response_size".to_string(), serde_json::json!(response_size));
        
        // Add header count (not the actual headers for privacy)
        fields.insert("request_header_count".to_string(), 
            serde_json::json!(entry.request.headers.len()));
        fields.insert("response_header_count".to_string(), 
            serde_json::json!(entry.response.headers.len()));
        
        // Redacted headers (for display - mark that auth is present but don't show value)
        let redacted_headers: Vec<String> = entry.request.headers.iter()
            .map(|h| {
                let name_lower = h.name.to_lowercase();
                if name_lower == "authorization" || name_lower == "cookie" || 
                   name_lower.contains("token") || name_lower.contains("key") || 
                   name_lower.contains("secret") {
                    format!("{}: [REDACTED]", h.name)
                } else {
                    format!("{}: {}", h.name, h.value)
                }
            })
            .collect();
        fields.insert("headers_redacted".to_string(), serde_json::json!(redacted_headers));
        
        let evidence_ptr = ImportEvidencePtr {
            bundle_id: bundle_id.to_string(),
            rel_path: file.rel_path.clone(),
            line_no: None,
            json_path: Some(format!("$.log.entries[{}]", index)),
            byte_offset: None,
        };
        
        Some(ImportEvent {
            event_id: generate_event_id(bundle_id, &file.rel_path, index),
            timestamp,
            timestamp_quality: ts_quality,
            event_type: format!("http_{}", method.to_lowercase()),
            source_file: file.rel_path.clone(),
            source_line: None,
            fields,
            evidence_ptr,
            tags,
        })
    }
    
    /// Detect patterns across all entries (brute force, scanning, etc.)
    fn detect_patterns(
        &self,
        entries: &[HarEntry],
        file: &ManifestFile,
        bundle_id: &str,
    ) -> Vec<ImportEvent> {
        let mut pattern_events = Vec::new();
        
        // Count auth failures by domain
        let mut auth_failures: HashMap<String, u32> = HashMap::new();
        // Count status codes by domain
        let mut status_by_domain: HashMap<String, HashMap<u16, u32>> = HashMap::new();
        // Track domains
        let mut domains: HashMap<String, u32> = HashMap::new();
        
        for entry in entries {
            let url = &entry.request.url;
            let domain = url.split("://")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .and_then(|s| s.split(':').next())
                .unwrap_or("unknown")
                .to_string();
            
            *domains.entry(domain.clone()).or_insert(0) += 1;
            
            let status = entry.response.status;
            
            // Track auth failures
            if status == 401 || status == 403 {
                let url_lower = url.to_lowercase();
                if url_lower.contains("login") || url_lower.contains("auth") || 
                   url_lower.contains("signin") {
                    *auth_failures.entry(domain.clone()).or_insert(0) += 1;
                }
            }
            
            // Track status codes
            *status_by_domain.entry(domain).or_default()
                .entry(status).or_insert(0) += 1;
        }
        
        // Generate brute force indicator if many auth failures
        for (domain, count) in &auth_failures {
            if *count >= 5 {
                let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
                fields.insert("domain".to_string(), serde_json::json!(domain));
                fields.insert("auth_failure_count".to_string(), serde_json::json!(count));
                fields.insert("pattern".to_string(), serde_json::json!("brute_force_indicator"));
                
                let evidence_ptr = ImportEvidencePtr {
                    bundle_id: bundle_id.to_string(),
                    rel_path: file.rel_path.clone(),
                    line_no: None,
                    json_path: Some("$.log.entries[*]".to_string()),
                    byte_offset: None,
                };
                
                pattern_events.push(ImportEvent {
                    event_id: generate_event_id(bundle_id, &file.rel_path, 100000 + pattern_events.len() as u64),
                    timestamp: Utc::now(),
                    timestamp_quality: TimestampQuality::Estimated,
                    event_type: "security_pattern".to_string(),
                    source_file: file.rel_path.clone(),
                    source_line: None,
                    fields,
                    evidence_ptr,
                    tags: vec![
                        "pattern".to_string(),
                        "brute_force".to_string(),
                        "auth_failure".to_string(),
                    ],
                });
            }
        }
        
        // Generate scanning indicator if many 404s
        for (domain, statuses) in &status_by_domain {
            let not_found = statuses.get(&404).unwrap_or(&0);
            if *not_found >= 10 {
                let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
                fields.insert("domain".to_string(), serde_json::json!(domain));
                fields.insert("404_count".to_string(), serde_json::json!(not_found));
                fields.insert("pattern".to_string(), serde_json::json!("directory_scanning"));
                
                let evidence_ptr = ImportEvidencePtr {
                    bundle_id: bundle_id.to_string(),
                    rel_path: file.rel_path.clone(),
                    line_no: None,
                    json_path: Some("$.log.entries[*]".to_string()),
                    byte_offset: None,
                };
                
                pattern_events.push(ImportEvent {
                    event_id: generate_event_id(bundle_id, &file.rel_path, 200000 + pattern_events.len() as u64),
                    timestamp: Utc::now(),
                    timestamp_quality: TimestampQuality::Estimated,
                    event_type: "security_pattern".to_string(),
                    source_file: file.rel_path.clone(),
                    source_line: None,
                    fields,
                    evidence_ptr,
                    tags: vec![
                        "pattern".to_string(),
                        "scanning".to_string(),
                        "directory_enumeration".to_string(),
                    ],
                });
            }
        }
        
        pattern_events
    }
}

// ============================================================================
// HAR SCHEMA (subset)
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarFile {
    pub log: HarLog,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarLog {
    pub version: String,
    #[serde(default)]
    pub creator: Option<HarCreator>,
    #[serde(default)]
    pub browser: Option<HarBrowser>,
    #[serde(default)]
    pub pages: Vec<HarPage>,
    pub entries: Vec<HarEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarCreator {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarBrowser {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarPage {
    #[serde(rename = "startedDateTime")]
    pub started_date_time: String,
    pub id: String,
    pub title: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarEntry {
    #[serde(rename = "startedDateTime")]
    pub started_date_time: String,
    #[serde(default)]
    pub time: f64,
    pub request: HarRequest,
    pub response: HarResponse,
    #[serde(default)]
    pub cache: serde_json::Value,
    #[serde(default)]
    pub timings: serde_json::Value,
    #[serde(default)]
    pub serverIPAddress: Option<String>,
    #[serde(default)]
    pub connection: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    #[serde(default)]
    pub cookies: Vec<HarCookie>,
    pub headers: Vec<HarHeader>,
    #[serde(default)]
    pub queryString: Vec<HarQueryString>,
    #[serde(default)]
    pub postData: Option<HarPostData>,
    #[serde(rename = "headersSize")]
    pub headers_size: i64,
    #[serde(rename = "bodySize")]
    pub body_size: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarResponse {
    pub status: u16,
    #[serde(rename = "statusText")]
    pub status_text: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    #[serde(default)]
    pub cookies: Vec<HarCookie>,
    pub headers: Vec<HarHeader>,
    pub content: HarContent,
    #[serde(rename = "redirectURL")]
    pub redirect_url: String,
    #[serde(rename = "headersSize")]
    pub headers_size: i64,
    #[serde(rename = "bodySize")]
    pub body_size: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarCookie {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub expires: Option<String>,
    #[serde(default)]
    pub httpOnly: Option<bool>,
    #[serde(default)]
    pub secure: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarQueryString {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarPostData {
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub params: Vec<HarParam>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarParam {
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub fileName: Option<String>,
    #[serde(default)]
    pub contentType: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HarContent {
    pub size: Option<i64>,
    #[serde(default)]
    pub compression: Option<i64>,
    #[serde(rename = "mimeType")]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub encoding: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_har_parsing() {
        let har_json = r#"{
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "startedDateTime": "2024-01-01T12:00:00.000Z",
                        "time": 100,
                        "request": {
                            "method": "GET",
                            "url": "https://example.com/api/login",
                            "httpVersion": "HTTP/1.1",
                            "headers": [{"name": "Authorization", "value": "Bearer xxx"}],
                            "headersSize": 100,
                            "bodySize": 0
                        },
                        "response": {
                            "status": 401,
                            "statusText": "Unauthorized",
                            "httpVersion": "HTTP/1.1",
                            "headers": [],
                            "content": {"size": 0},
                            "redirectURL": "",
                            "headersSize": 50,
                            "bodySize": 0
                        }
                    }
                ]
            }
        }"#;
        
        let har: HarFile = serde_json::from_str(har_json).unwrap();
        assert_eq!(har.log.entries.len(), 1);
        assert_eq!(har.log.entries[0].response.status, 401);
    }
}

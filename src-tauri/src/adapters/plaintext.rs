//! Plaintext Log Adapter - Parse generic text log files
//!
//! Parses various plaintext log formats:
//! - Shell/bash history
//! - PowerShell transcripts
//! - Generic logs with timestamp patterns
//! - Gobuster/ffuf/recon tool output

use crate::adapters::{Adapter, ParseResult, generate_event_id};
use crate::import_types::*;
use std::collections::HashMap;
use std::path::Path;
use std::io::{BufRead, BufReader};
use std::fs::File;
use chrono::{DateTime, Utc, TimeZone, NaiveDateTime};
use regex::Regex;

pub struct PlaintextAdapter;

impl PlaintextAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for PlaintextAdapter {
    fn name(&self) -> &'static str {
        "plaintext"
    }
    
    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, 
            FileKind::ShellHistory | 
            FileKind::PsTranscript | 
            FileKind::Gobuster | 
            FileKind::Ffuf |
            FileKind::ReconOutput
        )
    }
    
    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        match file.kind {
            FileKind::ShellHistory => self.parse_shell_history(file, file_path, bundle_id, limits),
            FileKind::PsTranscript => self.parse_ps_transcript(file, file_path, bundle_id, limits),
            FileKind::Gobuster => self.parse_gobuster(file, file_path, bundle_id, limits),
            FileKind::Ffuf => self.parse_ffuf(file, file_path, bundle_id, limits),
            FileKind::ReconOutput => self.parse_generic_recon(file, file_path, bundle_id, limits),
            _ => self.parse_generic_log(file, file_path, bundle_id, limits),
        }
    }
}

impl PlaintextAdapter {
    /// Parse shell history files (.bash_history, .zsh_history, etc.)
    fn parse_shell_history(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path)
            .map_err(|e| format!("Failed to open shell history: {}", e))?;
        let reader = BufReader::new(f);
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let timestamp = Utc::now();
        
        // Zsh extended history format: : timestamp:0;command
        let zsh_re = Regex::new(r"^: (\d+):\d+;(.+)$").unwrap();
        
        for (line_no, line_result) in reader.lines().enumerate() {
            if entries_processed >= limits.max_events as u64 {
                warnings.push(format!("Event limit reached at line {}", line_no + 1));
                break;
            }
            
            let line = match line_result {
                Ok(l) => l,
                Err(_) => continue,
            };
            
            if line.trim().is_empty() {
                continue;
            }
            
            let (cmd_timestamp, command) = if let Some(cap) = zsh_re.captures(&line) {
                // Zsh extended history format
                let ts = cap.get(1).unwrap().as_str().parse::<i64>()
                    .ok()
                    .and_then(|t| Utc.timestamp_opt(t, 0).single())
                    .unwrap_or(timestamp);
                let cmd = cap.get(2).unwrap().as_str().to_string();
                (ts, cmd)
            } else {
                // Plain command
                (timestamp, line.clone())
            };
            
            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            fields.insert("command".to_string(), serde_json::json!(command));
            fields.insert("line_number".to_string(), serde_json::json!(line_no + 1));
            
            // Extract entities from command
            let entities = extract_command_entities(&command);
            if !entities.ips.is_empty() {
                fields.insert("ips".to_string(), serde_json::json!(entities.ips));
            }
            if !entities.urls.is_empty() {
                fields.insert("urls".to_string(), serde_json::json!(entities.urls));
            }
            if !entities.paths.is_empty() {
                fields.insert("paths".to_string(), serde_json::json!(entities.paths));
            }
            
            let mut tags = vec![
                "shell_history".to_string(),
                "command".to_string(),
            ];
            
            // Add tool-specific tags
            let cmd_lower = command.to_lowercase();
            if cmd_lower.contains("nmap") { tags.push("nmap".to_string()); }
            if cmd_lower.contains("curl") || cmd_lower.contains("wget") { tags.push("http_client".to_string()); }
            if cmd_lower.contains("ssh") { tags.push("ssh".to_string()); }
            if cmd_lower.contains("sudo") { tags.push("privilege_escalation".to_string()); }
            if cmd_lower.contains("hydra") || cmd_lower.contains("medusa") { tags.push("brute_force".to_string()); }
            if cmd_lower.contains("metasploit") || cmd_lower.contains("msfconsole") { tags.push("metasploit".to_string()); }
            if cmd_lower.contains("gobuster") || cmd_lower.contains("dirb") { tags.push("directory_enum".to_string()); }
            
            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp: cmd_timestamp,
                timestamp_quality: if cmd_timestamp != timestamp {
                    TimestampQuality::Precise
                } else {
                    TimestampQuality::Unknown
                },
                event_type: "shell_command".to_string(),
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
            entries_skipped: 0,
        })
    }
    
    /// Parse PowerShell transcript files
    fn parse_ps_transcript(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read PS transcript: {}", e))?;
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        
        // Extract transcript metadata
        let start_time_re = Regex::new(r"Start time: (\d{14})").unwrap();
        let username_re = Regex::new(r"Username: (.+)").unwrap();
        let hostname_re = Regex::new(r"Machine: (.+)").unwrap();
        let command_re = Regex::new(r"(?m)^PS[^>]*>\s*(.+)$").unwrap();
        
        let transcript_time = start_time_re.captures(&content)
            .and_then(|c| c.get(1))
            .and_then(|m| NaiveDateTime::parse_from_str(m.as_str(), "%Y%m%d%H%M%S").ok())
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
            .unwrap_or_else(Utc::now);
        
        let username = username_re.captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        
        let hostname = hostname_re.captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        
        // Extract commands
        for cap in command_re.captures_iter(&content) {
            if entries_processed >= limits.max_events as u64 {
                warnings.push("Event limit reached".to_string());
                break;
            }
            
            let command = cap.get(1).unwrap().as_str().trim();
            if command.is_empty() {
                continue;
            }
            
            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            fields.insert("command".to_string(), serde_json::json!(command));
            if !username.is_empty() {
                fields.insert("username".to_string(), serde_json::json!(username));
            }
            if !hostname.is_empty() {
                fields.insert("hostname".to_string(), serde_json::json!(hostname));
            }
            
            let entities = extract_command_entities(command);
            if !entities.ips.is_empty() {
                fields.insert("ips".to_string(), serde_json::json!(entities.ips));
            }
            
            let mut tags = vec![
                "powershell".to_string(),
                "transcript".to_string(),
                "command".to_string(),
            ];
            
            // Detect interesting PowerShell patterns
            let cmd_lower = command.to_lowercase();
            if cmd_lower.contains("invoke-") { tags.push("invoke_cmdlet".to_string()); }
            if cmd_lower.contains("downloadstring") || cmd_lower.contains("downloadfile") {
                tags.push("download".to_string());
            }
            if cmd_lower.contains("encodedcommand") || cmd_lower.contains("-enc") {
                tags.push("encoded".to_string());
            }
            if cmd_lower.contains("bypass") { tags.push("bypass".to_string()); }
            
            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp: transcript_time,
                timestamp_quality: TimestampQuality::Precise,
                event_type: "powershell_command".to_string(),
                source_file: file.rel_path.clone(),
                source_line: None,
                fields,
                evidence_ptr: ImportEvidencePtr {
                    bundle_id: bundle_id.to_string(),
                    rel_path: file.rel_path.clone(),
                    line_no: None,
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
    
    /// Parse gobuster output
    fn parse_gobuster(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path)
            .map_err(|e| format!("Failed to open gobuster output: {}", e))?;
        let reader = BufReader::new(f);
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let timestamp = Utc::now();
        
        // Gobuster output format: /path (Status: 200) [Size: 1234]
        let gobuster_re = Regex::new(r"^(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?").unwrap();
        
        for (line_no, line_result) in reader.lines().enumerate() {
            if entries_processed >= limits.max_events as u64 {
                warnings.push(format!("Event limit reached at line {}", line_no + 1));
                break;
            }
            
            let line = match line_result {
                Ok(l) => l,
                Err(_) => continue,
            };
            
            if let Some(cap) = gobuster_re.captures(&line) {
                let path = cap.get(1).unwrap().as_str();
                let status = cap.get(2).unwrap().as_str().parse::<u16>().unwrap_or(0);
                let size = cap.get(3).and_then(|m| m.as_str().parse::<u64>().ok());
                
                let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
                fields.insert("path".to_string(), serde_json::json!(path));
                fields.insert("status_code".to_string(), serde_json::json!(status));
                if let Some(s) = size {
                    fields.insert("size".to_string(), serde_json::json!(s));
                }
                
                let mut tags = vec![
                    "gobuster".to_string(),
                    "directory_enum".to_string(),
                    "recon".to_string(),
                ];
                
                // Tag interesting findings
                if status == 200 { tags.push("found".to_string()); }
                if status == 301 || status == 302 { tags.push("redirect".to_string()); }
                if status == 403 { tags.push("forbidden".to_string()); }
                
                let path_lower = path.to_lowercase();
                if path_lower.contains("admin") { tags.push("admin".to_string()); }
                if path_lower.contains("api") { tags.push("api".to_string()); }
                if path_lower.contains("login") { tags.push("login".to_string()); }
                if path_lower.contains("upload") { tags.push("upload".to_string()); }
                if path_lower.contains("backup") { tags.push("backup".to_string()); }
                
                events.push(ImportEvent {
                    event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                    timestamp,
                    timestamp_quality: TimestampQuality::ImportTime,
                    event_type: "directory_found".to_string(),
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
        }
        
        Ok(ParseResult {
            events,
            warnings,
            entries_processed,
            entries_skipped: 0,
        })
    }
    
    /// Parse ffuf output (JSON preferred, but handle text too)
    fn parse_ffuf(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read ffuf output: {}", e))?;
        
        // Try JSON first
        if content.trim().starts_with('{') {
            return self.parse_ffuf_json(file, &content, bundle_id, limits);
        }
        
        // Fall back to text
        self.parse_ffuf_text(file, &content, bundle_id, limits)
    }
    
    fn parse_ffuf_json(
        &self,
        file: &ManifestFile,
        content: &str,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let json: serde_json::Value = serde_json::from_str(content)
            .map_err(|e| format!("Failed to parse ffuf JSON: {}", e))?;
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let timestamp = Utc::now();
        
        let results = json.get("results")
            .and_then(|v| v.as_array())
            .ok_or("Missing 'results' array in ffuf JSON")?;
        
        for (idx, result) in results.iter().enumerate() {
            if entries_processed >= limits.max_events as u64 {
                warnings.push("Event limit reached".to_string());
                break;
            }
            
            let url = result.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let status = result.get("status").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let length = result.get("length").and_then(|v| v.as_u64()).unwrap_or(0);
            let words = result.get("words").and_then(|v| v.as_u64()).unwrap_or(0);
            let lines = result.get("lines").and_then(|v| v.as_u64()).unwrap_or(0);
            let input = result.get("input").cloned();
            
            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            fields.insert("url".to_string(), serde_json::json!(url));
            fields.insert("status_code".to_string(), serde_json::json!(status));
            fields.insert("content_length".to_string(), serde_json::json!(length));
            fields.insert("word_count".to_string(), serde_json::json!(words));
            fields.insert("line_count".to_string(), serde_json::json!(lines));
            if let Some(inp) = input {
                fields.insert("input".to_string(), inp);
            }
            
            let mut tags = vec![
                "ffuf".to_string(),
                "fuzzing".to_string(),
                "recon".to_string(),
            ];
            
            if status == 200 { tags.push("found".to_string()); }
            
            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp,
                timestamp_quality: TimestampQuality::ImportTime,
                event_type: "fuzz_result".to_string(),
                source_file: file.rel_path.clone(),
                source_line: None,
                fields,
                evidence_ptr: ImportEvidencePtr {
                    bundle_id: bundle_id.to_string(),
                    rel_path: file.rel_path.clone(),
                    line_no: None,
                    json_path: Some(format!("results[{}]", idx)),
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
    
    fn parse_ffuf_text(
        &self,
        file: &ManifestFile,
        content: &str,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let timestamp = Utc::now();
        
        // ffuf text output: [Status: 200, Size: 1234, Words: 56, Lines: 12] url
        let ffuf_re = Regex::new(r"\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)[^\]]*\]\s+(.+)").unwrap();
        
        for (line_no, line) in content.lines().enumerate() {
            if entries_processed >= limits.max_events as u64 {
                warnings.push(format!("Event limit reached at line {}", line_no + 1));
                break;
            }
            
            if let Some(cap) = ffuf_re.captures(line) {
                let status = cap.get(1).unwrap().as_str().parse::<u16>().unwrap_or(0);
                let size = cap.get(2).unwrap().as_str().parse::<u64>().unwrap_or(0);
                let words = cap.get(3).unwrap().as_str().parse::<u64>().unwrap_or(0);
                let lines = cap.get(4).unwrap().as_str().parse::<u64>().unwrap_or(0);
                let url = cap.get(5).unwrap().as_str().trim();
                
                let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
                fields.insert("url".to_string(), serde_json::json!(url));
                fields.insert("status_code".to_string(), serde_json::json!(status));
                fields.insert("content_length".to_string(), serde_json::json!(size));
                fields.insert("word_count".to_string(), serde_json::json!(words));
                fields.insert("line_count".to_string(), serde_json::json!(lines));
                
                events.push(ImportEvent {
                    event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                    timestamp,
                    timestamp_quality: TimestampQuality::ImportTime,
                    event_type: "fuzz_result".to_string(),
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
                    tags: vec!["ffuf".to_string(), "fuzzing".to_string(), "recon".to_string()],
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
    
    /// Parse generic recon tool output
    fn parse_generic_recon(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        self.parse_generic_log(file, file_path, bundle_id, limits)
    }
    
    /// Parse generic log files with timestamp extraction
    fn parse_generic_log(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path)
            .map_err(|e| format!("Failed to open log file: {}", e))?;
        let reader = BufReader::new(f);
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let default_timestamp = Utc::now();
        
        // Common timestamp patterns
        let timestamp_patterns = vec![
            // ISO 8601
            Regex::new(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)").unwrap(),
            // Common log format
            Regex::new(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]").unwrap(),
            // Syslog style
            Regex::new(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})").unwrap(),
        ];
        
        for (line_no, line_result) in reader.lines().enumerate() {
            if entries_processed >= limits.max_events as u64 {
                warnings.push(format!("Event limit reached at line {}", line_no + 1));
                break;
            }
            
            let line = match line_result {
                Ok(l) => l,
                Err(_) => continue,
            };
            
            if line.trim().is_empty() {
                continue;
            }
            
            // Try to extract timestamp
            let (timestamp, ts_quality) = timestamp_patterns.iter()
                .find_map(|re| re.captures(&line).and_then(|c| c.get(1)))
                .and_then(|m| parse_flexible_timestamp(m.as_str()))
                .map(|ts| (ts, TimestampQuality::Precise))
                .unwrap_or((default_timestamp, TimestampQuality::Unknown));
            
            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            fields.insert("raw_line".to_string(), serde_json::json!(line));
            fields.insert("line_number".to_string(), serde_json::json!(line_no + 1));
            
            // Extract entities
            let entities = extract_command_entities(&line);
            if !entities.ips.is_empty() {
                fields.insert("ips".to_string(), serde_json::json!(entities.ips));
            }
            if !entities.urls.is_empty() {
                fields.insert("urls".to_string(), serde_json::json!(entities.urls));
            }
            
            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp,
                timestamp_quality: ts_quality,
                event_type: "log_line".to_string(),
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
                tags: vec!["log".to_string(), "plaintext".to_string()],
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

struct ExtractedEntities {
    ips: Vec<String>,
    urls: Vec<String>,
    paths: Vec<String>,
}

fn extract_command_entities(text: &str) -> ExtractedEntities {
    let ip_re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
    let url_re = Regex::new(r"(https?://[^\s\"'<>]+)").unwrap();
    let path_re = Regex::new(r"(/[\w./\-]+)").unwrap();
    
    let ips: Vec<String> = ip_re.captures_iter(text)
        .filter_map(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .collect();
    
    let urls: Vec<String> = url_re.captures_iter(text)
        .filter_map(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .take(10)
        .collect();
    
    let paths: Vec<String> = path_re.captures_iter(text)
        .filter_map(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .filter(|p| p.len() > 2)
        .take(10)
        .collect();
    
    ExtractedEntities { ips, urls, paths }
}

fn parse_flexible_timestamp(s: &str) -> Option<DateTime<Utc>> {
    // Try RFC3339 first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    
    // Try ISO 8601 without timezone
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
    }
    
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
    }
    
    None
}

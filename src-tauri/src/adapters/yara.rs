//! YARA Scan Results Adapter - Parse YARA scan output
//!
//! Parses YARA output in both JSON and text formats:
//! - JSON: yara -j output or yara-python JSON results
//! - Text: standard yara CLI output (rule_name file_path)

use crate::adapters::{Adapter, ParseResult, generate_event_id};
use crate::import_types::*;
use std::collections::HashMap;
use std::path::Path;
use std::io::{BufRead, BufReader};
use std::fs::File;
use chrono::Utc;

pub struct YaraAdapter;

impl YaraAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for YaraAdapter {
    fn name(&self) -> &'static str {
        "yara"
    }
    
    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::YaraJson | FileKind::YaraText)
    }
    
    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        match file.kind {
            FileKind::YaraJson => self.parse_json(file, file_path, bundle_id, limits),
            FileKind::YaraText => self.parse_text(file, file_path, bundle_id, limits),
            _ => Err("Unsupported YARA format".to_string()),
        }
    }
}

impl YaraAdapter {
    fn parse_json(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path)
            .map_err(|e| format!("Failed to open YARA JSON: {}", e))?;
        let reader = BufReader::new(f);
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let mut entries_skipped = 0u64;
        
        // Try to parse as array or line-delimited JSON
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read YARA JSON: {}", e))?;
        
        let matches: Vec<serde_json::Value> = if content.trim().starts_with('[') {
            // Array format
            serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse YARA JSON array: {}", e))?
        } else {
            // Line-delimited format
            let reader = BufReader::new(content.as_bytes());
            let mut results = Vec::new();
            for line in reader.lines() {
                if let Ok(line) = line {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                        results.push(val);
                    }
                }
            }
            results
        };
        
        let timestamp = Utc::now();
        
        for (idx, match_obj) in matches.iter().enumerate() {
            if entries_processed >= limits.max_events as u64 {
                warnings.push("Event limit reached".to_string());
                break;
            }
            
            let rule = match_obj.get("rule")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let target = match_obj.get("file")
                .or_else(|| match_obj.get("target"))
                .or_else(|| match_obj.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let namespace = match_obj.get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("default");
            
            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            fields.insert("rule".to_string(), serde_json::json!(rule));
            fields.insert("target_file".to_string(), serde_json::json!(target));
            fields.insert("namespace".to_string(), serde_json::json!(namespace));
            
            // Extract tags if present
            if let Some(tags) = match_obj.get("tags").and_then(|v| v.as_array()) {
                let tag_strs: Vec<String> = tags.iter()
                    .filter_map(|t| t.as_str())
                    .map(|s| s.to_string())
                    .collect();
                if !tag_strs.is_empty() {
                    fields.insert("rule_tags".to_string(), serde_json::json!(tag_strs));
                }
            }
            
            // Extract metadata if present
            if let Some(meta) = match_obj.get("meta").or_else(|| match_obj.get("metadata")) {
                fields.insert("metadata".to_string(), meta.clone());
            }
            
            // Extract string matches if present
            if let Some(strings) = match_obj.get("strings").and_then(|v| v.as_array()) {
                let string_matches: Vec<serde_json::Value> = strings.iter()
                    .take(20) // Limit string matches to prevent huge events
                    .cloned()
                    .collect();
                if !string_matches.is_empty() {
                    fields.insert("string_matches".to_string(), serde_json::json!(string_matches));
                    fields.insert("string_match_count".to_string(), serde_json::json!(strings.len()));
                }
            }
            
            let mut tags = vec![
                "yara".to_string(),
                "malware".to_string(),
                "detection".to_string(),
                rule.to_string(),
            ];
            
            // Add severity hints based on rule name patterns
            let rule_lower = rule.to_lowercase();
            if rule_lower.contains("apt") || rule_lower.contains("cve") {
                tags.push("high_severity".to_string());
            }
            if rule_lower.contains("miner") || rule_lower.contains("cryptominer") {
                tags.push("cryptominer".to_string());
            }
            if rule_lower.contains("ransomware") {
                tags.push("ransomware".to_string());
            }
            if rule_lower.contains("webshell") {
                tags.push("webshell".to_string());
            }
            if rule_lower.contains("cobalt") || rule_lower.contains("beacon") {
                tags.push("c2".to_string());
            }
            
            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp,
                timestamp_quality: TimestampQuality::ImportTime,
                event_type: "yara_match".to_string(),
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
    
    fn parse_text(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path)
            .map_err(|e| format!("Failed to open YARA text: {}", e))?;
        let reader = BufReader::new(f);
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let mut entries_skipped = 0u64;
        let timestamp = Utc::now();
        
        // YARA text output formats:
        // rule_name file_path
        // rule_name [tag1,tag2] file_path
        // rule_name namespace file_path (with -n)
        
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
            
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            
            // Parse the line
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() < 2 {
                warnings.push(format!("Line {} invalid format: {}", line_no + 1, line));
                entries_skipped += 1;
                continue;
            }
            
            let rule = parts[0];
            let target = parts[1];
            
            // Check for tags in brackets
            let (rule, rule_tags): (&str, Vec<String>) = if rule.contains('[') {
                let rule_parts: Vec<&str> = rule.splitn(2, '[').collect();
                let base_rule = rule_parts[0];
                let tags_str = rule_parts.get(1)
                    .map(|s| s.trim_end_matches(']'))
                    .unwrap_or("");
                let tags: Vec<String> = tags_str.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                (base_rule, tags)
            } else {
                (rule, Vec::new())
            };
            
            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            fields.insert("rule".to_string(), serde_json::json!(rule));
            fields.insert("target_file".to_string(), serde_json::json!(target));
            if !rule_tags.is_empty() {
                fields.insert("rule_tags".to_string(), serde_json::json!(rule_tags));
            }
            
            let mut tags = vec![
                "yara".to_string(),
                "malware".to_string(),
                "detection".to_string(),
                rule.to_string(),
            ];
            tags.extend(rule_tags);
            
            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp,
                timestamp_quality: TimestampQuality::ImportTime,
                event_type: "yara_match".to_string(),
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

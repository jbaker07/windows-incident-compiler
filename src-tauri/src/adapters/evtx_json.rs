//! EVTX JSON Adapter - Parse Windows Event Logs exported as JSON
//!
//! Parses EVTX files that have been converted to JSON using tools like:
//! - evtx_dump (omerbenamram/evtx)
//! - python-evtx
//! - Get-WinEvent | ConvertTo-Json
//!
//! Provides rich Windows event interpretation and categorization.

use crate::adapters::{Adapter, ParseResult, generate_event_id};
use crate::import_types::*;
use std::collections::HashMap;
use std::path::Path;
use std::io::{BufRead, BufReader};
use std::fs::File;
use chrono::{DateTime, Utc};

pub struct EvtxJsonAdapter;

impl EvtxJsonAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for EvtxJsonAdapter {
    fn name(&self) -> &'static str {
        "evtx_json"
    }
    
    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::EvtxJson)
    }
    
    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path)
            .map_err(|e| format!("Failed to open EVTX JSON: {}", e))?;
        let reader = BufReader::new(f);
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let mut entries_skipped = 0u64;
        
        // EVTX JSON can be line-delimited (evtx_dump) or array format
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        let records: Vec<serde_json::Value> = if content.trim().starts_with('[') {
            serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse JSON array: {}", e))?
        } else {
            // Line-delimited JSON
            let reader = BufReader::new(content.as_bytes());
            let mut results = Vec::new();
            for (line_no, line) in reader.lines().enumerate() {
                if let Ok(line) = line {
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<serde_json::Value>(&line) {
                        Ok(val) => results.push(val),
                        Err(e) => {
                            warnings.push(format!("Line {} parse error: {}", line_no + 1, e));
                        }
                    }
                }
            }
            results
        };
        
        for (idx, record) in records.iter().enumerate() {
            if entries_processed >= limits.max_events as u64 {
                warnings.push(format!("Event limit reached at record {}", idx));
                break;
            }
            
            // Extract event data - handle different JSON structures
            let (event_id, provider, channel, timestamp, event_data) = 
                extract_event_info(record);
            
            let timestamp = timestamp.unwrap_or_else(Utc::now);
            
            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            fields.insert("event_id".to_string(), serde_json::json!(event_id));
            fields.insert("provider".to_string(), serde_json::json!(provider));
            fields.insert("channel".to_string(), serde_json::json!(channel));
            
            // Add all event data fields
            if let Some(data) = event_data {
                if let Some(obj) = data.as_object() {
                    for (k, v) in obj {
                        fields.insert(k.clone(), v.clone());
                    }
                }
            }
            
            // Determine canonical event type and tags based on event ID
            let (canonical_type, mut tags) = categorize_windows_event(event_id, &provider, &fields);
            
            tags.push("evtx".to_string());
            tags.push("windows".to_string());
            
            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp,
                timestamp_quality: TimestampQuality::Precise,
                event_type: canonical_type.to_string(),
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

/// Extract event information from different JSON structures
fn extract_event_info(record: &serde_json::Value) -> (u32, String, String, Option<DateTime<Utc>>, Option<serde_json::Value>) {
    // evtx_dump format
    if let Some(event) = record.get("Event") {
        let system = event.get("System");
        
        let event_id = system
            .and_then(|s| s.get("EventID"))
            .and_then(|e| {
                // EventID can be a number or {"#text": number}
                if let Some(n) = e.as_u64() {
                    Some(n as u32)
                } else {
                    e.get("#text").and_then(|t| t.as_u64()).map(|n| n as u32)
                }
            })
            .unwrap_or(0);
        
        let provider = system
            .and_then(|s| s.get("Provider"))
            .and_then(|p| p.get("@Name").or_else(|| p.get("Name")))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        
        let channel = system
            .and_then(|s| s.get("Channel"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        
        let timestamp = system
            .and_then(|s| s.get("TimeCreated"))
            .and_then(|t| t.get("@SystemTime").or_else(|| t.get("SystemTime")))
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        
        let event_data = event.get("EventData").cloned();
        
        return (event_id, provider, channel, timestamp, event_data);
    }
    
    // PowerShell Get-WinEvent format
    if record.get("Id").is_some() || record.get("EventId").is_some() {
        let event_id = record.get("Id")
            .or_else(|| record.get("EventId"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        
        let provider = record.get("ProviderName")
            .or_else(|| record.get("Provider"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        
        let channel = record.get("LogName")
            .or_else(|| record.get("Channel"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        
        let timestamp = record.get("TimeCreated")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        
        let event_data = record.get("Properties")
            .or_else(|| record.get("Message"))
            .cloned();
        
        return (event_id, provider, channel, timestamp, event_data);
    }
    
    // Fallback - try to extract what we can
    let event_id = record.get("EventID")
        .or_else(|| record.get("event_id"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    
    let provider = record.get("Provider")
        .or_else(|| record.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    
    let channel = record.get("Channel")
        .or_else(|| record.get("channel"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    
    let timestamp = record.get("TimeCreated")
        .or_else(|| record.get("timestamp"))
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    
    (event_id, provider, channel, timestamp, Some(record.clone()))
}

/// Categorize Windows events by Event ID and provider
fn categorize_windows_event(event_id: u32, provider: &str, fields: &HashMap<String, serde_json::Value>) -> (&'static str, Vec<String>) {
    let provider_lower = provider.to_lowercase();
    let mut tags = Vec::new();
    
    // Security log events
    if provider_lower.contains("security") || provider_lower.contains("microsoft-windows-security-auditing") {
        tags.push("security".to_string());
        
        return match event_id {
            // Logon events
            4624 => {
                tags.push("logon".to_string());
                tags.push("authentication".to_string());
                ("logon_success", tags)
            }
            4625 => {
                tags.push("logon".to_string());
                tags.push("authentication".to_string());
                tags.push("failure".to_string());
                ("logon_failure", tags)
            }
            4634 | 4647 => {
                tags.push("logoff".to_string());
                ("logoff", tags)
            }
            4648 => {
                tags.push("logon".to_string());
                tags.push("explicit_credentials".to_string());
                ("explicit_credential_logon", tags)
            }
            
            // Process events
            4688 => {
                tags.push("process".to_string());
                tags.push("execution".to_string());
                ("process_create", tags)
            }
            4689 => {
                tags.push("process".to_string());
                ("process_terminate", tags)
            }
            
            // Account management
            4720 => {
                tags.push("account".to_string());
                tags.push("user_created".to_string());
                ("user_created", tags)
            }
            4722 => {
                tags.push("account".to_string());
                ("user_enabled", tags)
            }
            4725 => {
                tags.push("account".to_string());
                ("user_disabled", tags)
            }
            4726 => {
                tags.push("account".to_string());
                ("user_deleted", tags)
            }
            4728 | 4732 | 4756 => {
                tags.push("account".to_string());
                tags.push("group_membership".to_string());
                ("member_added_to_group", tags)
            }
            4729 | 4733 | 4757 => {
                tags.push("account".to_string());
                tags.push("group_membership".to_string());
                ("member_removed_from_group", tags)
            }
            
            // Privilege use
            4672 => {
                tags.push("privilege".to_string());
                tags.push("special_logon".to_string());
                ("special_privileges_assigned", tags)
            }
            4673 => {
                tags.push("privilege".to_string());
                ("privileged_service_called", tags)
            }
            
            // Object access
            4663 => {
                tags.push("file".to_string());
                tags.push("object_access".to_string());
                ("file_accessed", tags)
            }
            
            // Policy changes
            4719 => {
                tags.push("policy".to_string());
                tags.push("audit_policy".to_string());
                ("audit_policy_changed", tags)
            }
            
            // Scheduled tasks
            4698 => {
                tags.push("scheduled_task".to_string());
                tags.push("persistence".to_string());
                ("scheduled_task_created", tags)
            }
            4699 => {
                tags.push("scheduled_task".to_string());
                ("scheduled_task_deleted", tags)
            }
            
            // Services
            4697 => {
                tags.push("service".to_string());
                tags.push("persistence".to_string());
                ("service_installed", tags)
            }
            
            // Kerberos
            4768 => {
                tags.push("kerberos".to_string());
                tags.push("authentication".to_string());
                ("tgt_requested", tags)
            }
            4769 => {
                tags.push("kerberos".to_string());
                tags.push("authentication".to_string());
                ("service_ticket_requested", tags)
            }
            4771 => {
                tags.push("kerberos".to_string());
                tags.push("authentication".to_string());
                tags.push("failure".to_string());
                ("kerberos_preauth_failed", tags)
            }
            
            _ => {
                tags.push(format!("eid_{}", event_id));
                ("security_event", tags)
            }
        };
    }
    
    // Sysmon events
    if provider_lower.contains("sysmon") || provider_lower.contains("microsoft-windows-sysmon") {
        tags.push("sysmon".to_string());
        
        return match event_id {
            1 => {
                tags.push("process".to_string());
                tags.push("execution".to_string());
                ("process_create", tags)
            }
            2 => {
                tags.push("file".to_string());
                tags.push("timestomp".to_string());
                ("file_time_changed", tags)
            }
            3 => {
                tags.push("network".to_string());
                ("network_connection", tags)
            }
            5 => {
                tags.push("process".to_string());
                ("process_terminate", tags)
            }
            6 => {
                tags.push("driver".to_string());
                ("driver_loaded", tags)
            }
            7 => {
                tags.push("image".to_string());
                tags.push("dll".to_string());
                ("image_loaded", tags)
            }
            8 => {
                tags.push("process".to_string());
                tags.push("injection".to_string());
                ("create_remote_thread", tags)
            }
            9 => {
                tags.push("file".to_string());
                ("raw_access_read", tags)
            }
            10 => {
                tags.push("process".to_string());
                tags.push("memory".to_string());
                ("process_access", tags)
            }
            11 => {
                tags.push("file".to_string());
                ("file_create", tags)
            }
            12 | 13 | 14 => {
                tags.push("registry".to_string());
                ("registry_event", tags)
            }
            15 => {
                tags.push("file".to_string());
                tags.push("ads".to_string());
                ("file_stream_create", tags)
            }
            17 | 18 => {
                tags.push("pipe".to_string());
                ("pipe_event", tags)
            }
            19 | 20 | 21 => {
                tags.push("wmi".to_string());
                tags.push("persistence".to_string());
                ("wmi_event", tags)
            }
            22 => {
                tags.push("dns".to_string());
                ("dns_query", tags)
            }
            23 => {
                tags.push("file".to_string());
                ("file_delete", tags)
            }
            24 => {
                tags.push("clipboard".to_string());
                ("clipboard_change", tags)
            }
            25 => {
                tags.push("process".to_string());
                tags.push("tampering".to_string());
                ("process_tampering", tags)
            }
            26 => {
                tags.push("file".to_string());
                ("file_delete_logged", tags)
            }
            _ => {
                tags.push(format!("sysmon_{}", event_id));
                ("sysmon_event", tags)
            }
        };
    }
    
    // PowerShell events
    if provider_lower.contains("powershell") {
        tags.push("powershell".to_string());
        
        return match event_id {
            4103 => {
                tags.push("module_logging".to_string());
                ("powershell_module", tags)
            }
            4104 => {
                tags.push("script_block".to_string());
                ("powershell_script_block", tags)
            }
            4105 | 4106 => {
                tags.push("script_block".to_string());
                ("powershell_script_start_stop", tags)
            }
            _ => {
                tags.push(format!("ps_{}", event_id));
                ("powershell_event", tags)
            }
        };
    }
    
    // Default categorization
    tags.push(format!("eid_{}", event_id));
    ("windows_event", tags)
}

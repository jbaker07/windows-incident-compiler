// windows/sensors/sysmon_adapter.rs
// Sysmon event adaptation - convert Sysmon events to canonical Event format

use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

/// Sysmon Event IDs:
/// 1: Process Create
/// 2: File creation time changed
/// 3: Network connection
/// 4: Sysmon service state changed
/// 5: Process terminated
/// 6: Driver loaded
/// 7: Image loaded
/// 8: CreateRemoteThread
/// 10: ProcessAccess
/// 11: FileCreate
/// 12: RegistryObject Create/Delete
/// 13: RegistryValueSet
/// 14: RegistryObject Rename
/// 15: FileCreateStreamHash
/// 17: PipeCreated
/// 18: PipeConnected
/// 22: DNSQuery
/// 23: FileDelete (archived)
/// 24: ClipboardChange
/// 25: ProcessTampering
/// 26: FileDeleteDetected

#[derive(Debug)]
pub struct SysmonAdapter;

impl SysmonAdapter {
    /// Convert Sysmon event record to canonical Event
    pub fn adapt(record: &super::evtx_collector::EvtxRecord) -> Option<edr_core::Event> {
        // Sysmon events have provider "Microsoft-Windows-Sysmon"
        if !record.provider.contains("Sysmon") {
            return None;
        }

        let event_tag = Self::event_id_to_tag(record.event_id);
        let mut tags = vec!["windows".to_string(), "sysmon".to_string()];
        tags.push(event_tag.to_string());

        // Parse fields from message - in real impl would parse XML
        let mut fields: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        fields.insert("event_id".to_string(), serde_json::json!(record.event_id));
        fields.insert("level".to_string(), serde_json::json!(record.level));
        fields.insert("provider".to_string(), serde_json::json!(record.provider));

        // Extract key fields from message (simplified parsing)
        if !record.message.is_empty() {
            fields.insert("raw_message".to_string(), serde_json::json!(record.message));

            // Parse common Sysmon fields from message
            Self::parse_sysmon_fields(&record.message, &mut fields);
        }

        Some(edr_core::Event {
            ts_ms: Utc::now().timestamp_millis(),
            host: "localhost".to_string(),
            tags,
            proc_key: fields
                .get("proc_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            file_key: fields
                .get("file_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            identity_key: fields
                .get("identity_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            evidence_ptr: None,
            fields,
        })
    }

    fn event_id_to_tag(event_id: u32) -> &'static str {
        match event_id {
            1 => "process_create",
            2 => "file_time_change",
            3 => "network_connect",
            4 => "sysmon_state",
            5 => "process_terminate",
            6 => "driver_load",
            7 => "image_load",
            8 => "create_remote_thread",
            10 => "process_access",
            11 => "file_create",
            12 => "registry_create_delete",
            13 => "registry_value_set",
            14 => "registry_rename",
            15 => "file_stream_hash",
            17 => "pipe_create",
            18 => "pipe_connect",
            22 => "dns_query",
            23 => "file_delete_archived",
            24 => "clipboard_change",
            25 => "process_tampering",
            26 => "file_delete_detected",
            _ => "sysmon_unknown",
        }
    }

    fn parse_sysmon_fields(message: &str, fields: &mut BTreeMap<String, serde_json::Value>) {
        // Parse key=value pairs from Sysmon message
        // Format typically: "Key: Value\r\n"
        for line in message.lines() {
            if let Some(idx) = line.find(':') {
                let key = line[..idx].trim().to_lowercase().replace(' ', "_");
                let value = line[idx + 1..].trim();

                // Map to canonical field names
                match key.as_str() {
                    "image" | "targetfilename" => {
                        fields.insert("exe".to_string(), serde_json::json!(value));
                    }
                    "processid" | "process_id" => {
                        if let Ok(pid) = value.parse::<u32>() {
                            fields.insert("pid".to_string(), serde_json::json!(pid));
                            fields.insert(
                                "proc_key".to_string(),
                                serde_json::json!(format!("pid:{}", pid)),
                            );
                        }
                    }
                    "user" => {
                        fields.insert("user".to_string(), serde_json::json!(value));
                        fields.insert("identity_key".to_string(), serde_json::json!(value));
                    }
                    "commandline" => {
                        fields.insert("cmdline".to_string(), serde_json::json!(value));
                    }
                    "parentimage" => {
                        fields.insert("parent_exe".to_string(), serde_json::json!(value));
                    }
                    "parentprocessid" => {
                        if let Ok(ppid) = value.parse::<u32>() {
                            fields.insert("ppid".to_string(), serde_json::json!(ppid));
                        }
                    }
                    "destinationip" => {
                        fields.insert("remote_ip".to_string(), serde_json::json!(value));
                    }
                    "destinationport" => {
                        if let Ok(port) = value.parse::<u16>() {
                            fields.insert("remote_port".to_string(), serde_json::json!(port));
                        }
                    }
                    "targetobject" => {
                        fields.insert("registry_key".to_string(), serde_json::json!(value));
                        fields.insert("file_key".to_string(), serde_json::json!(value));
                    }
                    "queryname" => {
                        fields.insert("dns_query".to_string(), serde_json::json!(value));
                    }
                    "hashes" => {
                        fields.insert("hashes".to_string(), serde_json::json!(value));
                    }
                    _ => {
                        // Store other fields as-is
                        fields.insert(key, serde_json::json!(value));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysmon_adapter_non_sysmon() {
        let record = super::super::evtx_collector::EvtxRecord {
            event_id: 4688,
            level: "Information".to_string(),
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            message: "A new process has been created.".to_string(),
        };
        assert!(SysmonAdapter::adapt(&record).is_none());
    }

    #[test]
    fn test_sysmon_adapter_process_create() {
        let record = super::super::evtx_collector::EvtxRecord {
            event_id: 1,
            level: "Information".to_string(),
            provider: "Microsoft-Windows-Sysmon".to_string(),
            message: "Process Create:\r\nImage: C:\\Windows\\System32\\cmd.exe\r\nProcessId: 1234\r\nUser: DOMAIN\\user\r\nCommandLine: cmd.exe /c whoami".to_string(),
        };
        let event = SysmonAdapter::adapt(&record).unwrap();
        assert!(event.tags.contains(&"process_create".to_string()));
        assert!(event.tags.contains(&"sysmon".to_string()));
        assert_eq!(event.fields.get("pid"), Some(&serde_json::json!(1234)));
    }
}

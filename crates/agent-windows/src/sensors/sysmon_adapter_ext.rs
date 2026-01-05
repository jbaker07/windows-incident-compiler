// windows/sensors/sysmon_adapter_ext.rs
// Extended Sysmon event adaptation for advanced event types
// Handles: CreateRemoteThread, ProcessAccess, FileCreateStreamHash, Pipes, etc.

use chrono::Utc;
use std::collections::BTreeMap;

/// Extended Sysmon Event IDs (high-value for threat detection):
/// 8: CreateRemoteThread (injection)
/// 10: ProcessAccess (credential dumping, injection)
/// 15: FileCreateStreamHash (ADS creation)
/// 17: PipeCreated (named pipe)
/// 18: PipeConnected
/// 19: WmiEventFilter
/// 20: WmiEventConsumer
/// 21: WmiEventConsumerToFilter
/// 25: ProcessTampering
/// 26: FileDeleteDetected

#[derive(Debug)]
pub struct SysmonAdapterExt;

impl SysmonAdapterExt {
    /// Convert extended Sysmon event to canonical Event
    pub fn adapt(record: &super::evtx_collector::EvtxRecord) -> Option<edr_core::Event> {
        // Only handle Sysmon events
        if !record.provider.contains("Sysmon") {
            return None;
        }

        // Only handle extended event IDs
        if !Self::is_extended_event(record.event_id) {
            return None;
        }

        let (event_tag, mitre_technique) = Self::event_id_to_tag_and_mitre(record.event_id);

        let mut tags = vec![
            "windows".to_string(),
            "sysmon".to_string(),
            "sysmon_ext".to_string(),
        ];
        tags.push(event_tag.to_string());
        if let Some(mitre) = mitre_technique {
            tags.push(format!("mitre:{}", mitre));
        }

        let mut fields: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        fields.insert("event_id".to_string(), serde_json::json!(record.event_id));
        fields.insert("level".to_string(), serde_json::json!(record.level));
        fields.insert("provider".to_string(), serde_json::json!(record.provider));

        if !record.message.is_empty() {
            fields.insert("raw_message".to_string(), serde_json::json!(record.message));
            Self::parse_ext_fields(&record.message, record.event_id, &mut fields);
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

    fn is_extended_event(event_id: u32) -> bool {
        matches!(event_id, 8 | 10 | 15 | 17 | 18 | 19 | 20 | 21 | 25 | 26)
    }

    fn event_id_to_tag_and_mitre(event_id: u32) -> (&'static str, Option<&'static str>) {
        match event_id {
            8 => ("create_remote_thread", Some("T1055")), // Process Injection
            10 => ("process_access", Some("T1003")),      // Credential Dumping
            15 => ("file_stream_hash", Some("T1564.004")), // ADS hiding
            17 => ("pipe_create", Some("T1570")),         // Lateral Tool Transfer
            18 => ("pipe_connect", None),
            19 => ("wmi_filter_create", Some("T1546.003")), // WMI Event Subscription
            20 => ("wmi_consumer_create", Some("T1546.003")),
            21 => ("wmi_binding", Some("T1546.003")),
            25 => ("process_tampering", Some("T1055")), // Process Injection
            26 => ("file_delete", Some("T1070.004")),   // Indicator Removal
            _ => ("sysmon_ext_unknown", None),
        }
    }

    fn parse_ext_fields(
        message: &str,
        event_id: u32,
        fields: &mut BTreeMap<String, serde_json::Value>,
    ) {
        for line in message.lines() {
            if let Some(idx) = line.find(':') {
                let key = line[..idx].trim().to_lowercase().replace(' ', "_");
                let value = line[idx + 1..].trim();

                match key.as_str() {
                    "sourceimage" | "source_image" => {
                        fields.insert("source_exe".to_string(), serde_json::json!(value));
                    }
                    "targetimage" | "target_image" => {
                        fields.insert("target_exe".to_string(), serde_json::json!(value));
                    }
                    "sourceprocessid" => {
                        if let Ok(pid) = value.parse::<u32>() {
                            fields.insert("source_pid".to_string(), serde_json::json!(pid));
                            fields.insert(
                                "proc_key".to_string(),
                                serde_json::json!(format!("pid:{}", pid)),
                            );
                        }
                    }
                    "targetprocessid" => {
                        if let Ok(pid) = value.parse::<u32>() {
                            fields.insert("target_pid".to_string(), serde_json::json!(pid));
                        }
                    }
                    "grantedaccess" => {
                        fields.insert("granted_access".to_string(), serde_json::json!(value));
                        // Flag suspicious access masks
                        if value.contains("0x1010") || value.contains("0x1FFFFF") {
                            fields.insert("suspicious_access".to_string(), serde_json::json!(true));
                        }
                    }
                    "callTrace" | "calltrace" => {
                        fields.insert("call_trace".to_string(), serde_json::json!(value));
                    }
                    "pipename" => {
                        fields.insert("pipe_name".to_string(), serde_json::json!(value));
                        fields.insert(
                            "file_key".to_string(),
                            serde_json::json!(format!("pipe:{}", value)),
                        );
                    }
                    "targetfilename" => {
                        fields.insert("target_file".to_string(), serde_json::json!(value));
                        fields.insert("file_key".to_string(), serde_json::json!(value));
                    }
                    "type" => {
                        fields.insert("tampering_type".to_string(), serde_json::json!(value));
                    }
                    "operation" | "eventtype" => {
                        fields.insert("operation".to_string(), serde_json::json!(value));
                    }
                    "consumer" | "filter" | "destination" => {
                        fields.insert(key, serde_json::json!(value));
                    }
                    "user" => {
                        fields.insert("user".to_string(), serde_json::json!(value));
                        fields.insert("identity_key".to_string(), serde_json::json!(value));
                    }
                    _ => {
                        fields.insert(key, serde_json::json!(value));
                    }
                }
            }
        }

        // Add event-specific context
        match event_id {
            8 => {
                fields.insert(
                    "attack_technique".to_string(),
                    serde_json::json!("Process Injection via CreateRemoteThread"),
                );
            }
            10 => {
                fields.insert(
                    "attack_technique".to_string(),
                    serde_json::json!("Process Access (potential credential dumping)"),
                );
            }
            25 => {
                fields.insert(
                    "attack_technique".to_string(),
                    serde_json::json!("Process Tampering detected"),
                );
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ext_adapter_create_remote_thread() {
        let record = super::super::evtx_collector::EvtxRecord {
            event_id: 8,
            level: "Information".to_string(),
            provider: "Microsoft-Windows-Sysmon".to_string(),
            message: "CreateRemoteThread:\r\nSourceImage: C:\\malware.exe\r\nTargetImage: C:\\Windows\\explorer.exe\r\nSourceProcessId: 1234\r\nTargetProcessId: 5678".to_string(),
        };
        let event = SysmonAdapterExt::adapt(&record).unwrap();
        assert!(event.tags.contains(&"create_remote_thread".to_string()));
        assert!(event.tags.contains(&"mitre:T1055".to_string()));
    }

    #[test]
    fn test_ext_adapter_process_access() {
        let record = super::super::evtx_collector::EvtxRecord {
            event_id: 10,
            level: "Information".to_string(),
            provider: "Microsoft-Windows-Sysmon".to_string(),
            message: "ProcessAccess:\r\nSourceImage: C:\\mimikatz.exe\r\nTargetImage: C:\\Windows\\System32\\lsass.exe\r\nGrantedAccess: 0x1010".to_string(),
        };
        let event = SysmonAdapterExt::adapt(&record).unwrap();
        assert!(event.tags.contains(&"process_access".to_string()));
        assert!(event.fields.get("suspicious_access") == Some(&serde_json::json!(true)));
    }

    #[test]
    fn test_ext_adapter_non_extended() {
        let record = super::super::evtx_collector::EvtxRecord {
            event_id: 1, // Process Create - not an extended event
            level: "Information".to_string(),
            provider: "Microsoft-Windows-Sysmon".to_string(),
            message: "Process Create".to_string(),
        };
        assert!(SysmonAdapterExt::adapt(&record).is_none());
    }
}

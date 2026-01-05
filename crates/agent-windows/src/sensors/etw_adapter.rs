// windows/sensors/etw_adapter.rs
// ETW (Event Tracing for Windows) event adaptation
// Handles: WMI activity, WinRM, PowerShell, process creation, etc.

use chrono::Utc;
use std::collections::BTreeMap;

/// ETW Provider GUIDs we care about:
/// - Microsoft-Windows-WMI-Activity
/// - Microsoft-Windows-PowerShell
/// - Microsoft-Windows-WinRM
/// - Microsoft-Windows-Security-Auditing

#[derive(Debug)]
pub struct EtwAdapter;

impl EtwAdapter {
    /// Convert ETW event record to canonical Event
    pub fn adapt(record: &super::evtx_collector::EvtxRecord) -> Option<edr_core::Event> {
        // ETW events can come from various providers
        let (category, event_tag) = Self::categorize_event(record);

        let mut tags = vec!["windows".to_string(), "etw".to_string()];
        tags.push(category.to_string());
        tags.push(event_tag.to_string());

        let mut fields: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        fields.insert("event_id".to_string(), serde_json::json!(record.event_id));
        fields.insert("level".to_string(), serde_json::json!(record.level));
        fields.insert("provider".to_string(), serde_json::json!(record.provider));

        if !record.message.is_empty() {
            fields.insert("raw_message".to_string(), serde_json::json!(record.message));
            Self::parse_etw_fields(&record.message, &mut fields);
        }

        Some(edr_core::Event {
            ts_ms: Utc::now().timestamp_millis(),
            host: "localhost".to_string(),
            tags,
            proc_key: fields
                .get("proc_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            file_key: None,
            identity_key: fields
                .get("identity_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            evidence_ptr: None,
            fields,
        })
    }

    fn categorize_event(
        record: &super::evtx_collector::EvtxRecord,
    ) -> (&'static str, &'static str) {
        let provider = record.provider.to_lowercase();

        if provider.contains("wmi") {
            let tag = match record.event_id {
                5857 => "wmi_consumer_failure",
                5858 => "wmi_query_exec",
                5859 => "wmi_operation",
                _ => "wmi_unknown",
            };
            ("wmi", tag)
        } else if provider.contains("powershell") {
            let tag = match record.event_id {
                4100 => "ps_engine_state",
                4103 => "ps_module_logging",
                4104 => "ps_script_block",
                _ => "ps_unknown",
            };
            ("powershell", tag)
        } else if provider.contains("winrm") {
            let tag = match record.event_id {
                6 => "winrm_session_created",
                15 => "winrm_session_closed",
                91 => "winrm_shell_created",
                _ => "winrm_unknown",
            };
            ("winrm", tag)
        } else if provider.contains("security") {
            let tag = match record.event_id {
                4624 => "logon_success",
                4625 => "logon_failure",
                4688 => "process_create",
                4689 => "process_exit",
                4697 => "service_installed",
                4698 => "scheduled_task_created",
                4769 => "kerberos_tgs_request",
                _ => "security_unknown",
            };
            ("security", tag)
        } else {
            ("etw", "generic")
        }
    }

    fn parse_etw_fields(message: &str, fields: &mut BTreeMap<String, serde_json::Value>) {
        // Parse key-value pairs from ETW message
        for line in message.lines() {
            if let Some(idx) = line.find(':') {
                let key = line[..idx].trim().to_lowercase().replace(' ', "_");
                let value = line[idx + 1..].trim();

                match key.as_str() {
                    "process_id" | "processid" => {
                        if let Ok(pid) = value.parse::<u32>() {
                            fields.insert("pid".to_string(), serde_json::json!(pid));
                            fields.insert(
                                "proc_key".to_string(),
                                serde_json::json!(format!("pid:{}", pid)),
                            );
                        }
                    }
                    "user" | "account_name" | "targetusername" => {
                        fields.insert("user".to_string(), serde_json::json!(value));
                        fields.insert("identity_key".to_string(), serde_json::json!(value));
                    }
                    "script_block_text" | "scriptblocktext" => {
                        fields.insert("script_block".to_string(), serde_json::json!(value));
                    }
                    "namespace" => {
                        fields.insert("wmi_namespace".to_string(), serde_json::json!(value));
                    }
                    "operation" => {
                        fields.insert("wmi_operation".to_string(), serde_json::json!(value));
                    }
                    "logon_type" | "logontype" => {
                        if let Ok(logon_type) = value.parse::<u32>() {
                            fields.insert("logon_type".to_string(), serde_json::json!(logon_type));
                        }
                    }
                    "source_network_address" | "ipaddress" => {
                        fields.insert("source_ip".to_string(), serde_json::json!(value));
                    }
                    _ => {
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
    fn test_etw_adapter_wmi() {
        let record = super::super::evtx_collector::EvtxRecord {
            event_id: 5858,
            level: "Information".to_string(),
            provider: "Microsoft-Windows-WMI-Activity".to_string(),
            message: "Operation: ExecQuery\r\nNamespace: root\\cimv2".to_string(),
        };
        let event = EtwAdapter::adapt(&record).unwrap();
        assert!(event.tags.contains(&"wmi".to_string()));
        assert!(event.tags.contains(&"wmi_query_exec".to_string()));
    }

    #[test]
    fn test_etw_adapter_powershell() {
        let record = super::super::evtx_collector::EvtxRecord {
            event_id: 4104,
            level: "Information".to_string(),
            provider: "Microsoft-Windows-PowerShell".to_string(),
            message: "ScriptBlockText: Get-Process\r\nPath: ".to_string(),
        };
        let event = EtwAdapter::adapt(&record).unwrap();
        assert!(event.tags.contains(&"powershell".to_string()));
        assert!(event.tags.contains(&"ps_script_block".to_string()));
    }
}

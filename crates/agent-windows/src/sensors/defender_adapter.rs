// windows/sensors/defender_adapter.rs
// Windows Defender and AMSI event adaptation
// Handles: Defender detections, AMSI scans, real-time protection events

use chrono::Utc;
use std::collections::BTreeMap;

/// Defender Event IDs:
/// 1006: Malware or potentially unwanted software detected
/// 1007: Action taken (quarantine, remove, allow)
/// 1116: Malware detected
/// 1117: Protection took action
/// 1118: Protection failed
/// 5001: Real-time protection disabled
/// 5004: Real-time protection configuration changed

#[derive(Debug)]
pub struct DefenderAdapter;

impl DefenderAdapter {
    /// Convert Defender/AMSI event record to canonical Event
    pub fn adapt(record: &super::evtx_collector::EvtxRecord) -> Option<edr_core::Event> {
        // Check if this is a Defender event
        let provider = record.provider.to_lowercase();
        if !provider.contains("defender") && !provider.contains("antimalware") {
            return None;
        }

        let event_tag = Self::event_id_to_tag(record.event_id);
        let severity = Self::event_severity(record.event_id);

        let mut tags = vec!["windows".to_string(), "defender".to_string()];
        tags.push(event_tag.to_string());
        if severity == "high" {
            tags.push("high_severity".to_string());
        }

        let mut fields: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        fields.insert("event_id".to_string(), serde_json::json!(record.event_id));
        fields.insert("level".to_string(), serde_json::json!(record.level));
        fields.insert("provider".to_string(), serde_json::json!(record.provider));
        fields.insert("severity".to_string(), serde_json::json!(severity));

        if !record.message.is_empty() {
            fields.insert("raw_message".to_string(), serde_json::json!(record.message));
            Self::parse_defender_fields(&record.message, &mut fields);
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
            1006 => "malware_detected",
            1007 => "action_taken",
            1116 => "detection",
            1117 => "protection_action",
            1118 => "protection_failed",
            5001 => "realtime_disabled",
            5004 => "config_changed",
            1121 => "asr_block", // Attack Surface Reduction
            1122 => "asr_audit",
            5007 => "platform_updated",
            _ => "defender_unknown",
        }
    }

    fn event_severity(event_id: u32) -> &'static str {
        match event_id {
            1006 | 1116 | 1117 | 1118 | 1121 => "high",
            5001 | 5004 => "medium",
            _ => "low",
        }
    }

    fn parse_defender_fields(message: &str, fields: &mut BTreeMap<String, serde_json::Value>) {
        for line in message.lines() {
            if let Some(idx) = line.find(':') {
                let key = line[..idx].trim().to_lowercase().replace(' ', "_");
                let value = line[idx + 1..].trim();

                match key.as_str() {
                    "threat_name" | "name" => {
                        fields.insert("threat_name".to_string(), serde_json::json!(value));
                    }
                    "path" | "file" | "resource" => {
                        fields.insert("file_path".to_string(), serde_json::json!(value));
                        fields.insert("file_key".to_string(), serde_json::json!(value));
                    }
                    "process_name" => {
                        fields.insert("process_name".to_string(), serde_json::json!(value));
                    }
                    "process_id" => {
                        if let Ok(pid) = value.parse::<u32>() {
                            fields.insert("pid".to_string(), serde_json::json!(pid));
                            fields.insert(
                                "proc_key".to_string(),
                                serde_json::json!(format!("pid:{}", pid)),
                            );
                        }
                    }
                    "user" | "domain\\user" => {
                        fields.insert("user".to_string(), serde_json::json!(value));
                        fields.insert("identity_key".to_string(), serde_json::json!(value));
                    }
                    "action" => {
                        fields.insert("action_taken".to_string(), serde_json::json!(value));
                    }
                    "severity" => {
                        fields.insert("threat_severity".to_string(), serde_json::json!(value));
                    }
                    "category" => {
                        fields.insert("threat_category".to_string(), serde_json::json!(value));
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
    fn test_defender_adapter_non_defender() {
        let record = super::super::evtx_collector::EvtxRecord {
            event_id: 4688,
            level: "Information".to_string(),
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            message: "Process created".to_string(),
        };
        assert!(DefenderAdapter::adapt(&record).is_none());
    }

    #[test]
    fn test_defender_adapter_detection() {
        let record = super::super::evtx_collector::EvtxRecord {
            event_id: 1116,
            level: "Warning".to_string(),
            provider: "Microsoft-Windows-Windows Defender".to_string(),
            message: "Threat Name: Trojan:Win32/Test\r\nPath: C:\\temp\\malware.exe\r\nAction: Quarantine".to_string(),
        };
        let event = DefenderAdapter::adapt(&record).unwrap();
        assert!(event.tags.contains(&"detection".to_string()));
        assert!(event.tags.contains(&"high_severity".to_string()));
    }
}

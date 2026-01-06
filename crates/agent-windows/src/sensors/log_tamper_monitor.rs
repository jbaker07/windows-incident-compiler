// windows/sensors/log_tamper_monitor.rs
// Event log tampering detection: clearing, modification, truncation attempts
// Sources: Security log (4688=process created with suspicious names), System log

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogTamperEvent {
    pub event_id: u32,
    pub log_name: String,
    pub ts: DateTime<Utc>,
    pub computer: String,
    pub fields: BTreeMap<String, String>,
    pub stream_id: Option<String>,
    pub segment_id: Option<String>,
    pub record_index: Option<u64>,
}

#[derive(Debug)]
pub struct LogTamperMonitor;

impl LogTamperMonitor {
    pub fn collect(_host: &crate::host::HostCtx) -> Vec<edr_core::Event> {
        // On Windows: would query Security 4688 (process name = wevtutil/Clear-EventLog/LogParser) and 1102 (audit log cleared)
        // For now: Log tamper events are detected by wevt_reader via Security 1102 events
        // This module is a STUB - all tamper detection flows through main event log reader
        vec![]
    }

    pub fn to_canonical_event(event: &LogTamperEvent) -> Option<edr_core::Event> {
        // Convert LogTamperEvent to canonical Event
        // Security 1102: Audit log cleared
        // Security 4688: Process created (check for wevtutil, Clear-EventLog, LogParser)

        let event_tag = match event.event_id {
            1102 => "log_cleared",
            4688 => "suspicious_process", // Process name checked in collect phase
            _ => "log_tamper_unknown",
        };

        let fields = event.fields.clone();
        // Convert string values to JSON for consistency
        let fields_json: BTreeMap<String, serde_json::Value> = fields
            .into_iter()
            .map(|(k, v)| (k, serde_json::json!(v)))
            .collect();

        let mut tags = vec!["windows".to_string(), "log_tamper".to_string()];
        tags.push(event_tag.to_string());

        Some(edr_core::Event {
            ts_ms: event.ts.timestamp_millis(),
            host: event.computer.clone(),
            proc_key: None,
            file_key: None,
            identity_key: None,
            fields: fields_json,
            tags,
            evidence_ptr: None,
        })
    }
}

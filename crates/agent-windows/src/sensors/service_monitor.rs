// windows/sensors/service_monitor.rs
// Service lifecycle monitoring: install, start, configuration changes
// Sources: System event log (7045=service installed), Security (4697=service registry modified)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEvent {
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
pub struct ServiceMonitor;

impl ServiceMonitor {
    pub fn collect(_host: &crate::host::HostCtx) -> Vec<edr_core::Event> {
        // On Windows: would query System 7045 (ServiceName, ImagePath, StartType) and Security 4697
        // For now: Service events are included in wevt_reader polling
        // This module is a STUB - all service events flow through main event log reader
        vec![]
    }

    pub fn to_canonical_event(event: &ServiceEvent) -> Option<edr_core::Event> {
        // Convert ServiceEvent (System 7045 or Security 4697) to canonical Event
        // System 7045: Service installed
        // Security 4697: Service registry key modified

        let event_tag = match event.event_id {
            7045 => "service_install",
            4697 => "service_registry_modify",
            _ => "service_unknown",
        };

        let fields = event.fields.clone();
        // Convert string values to JSON for consistency
        let fields_json: BTreeMap<String, serde_json::Value> = fields
            .into_iter()
            .map(|(k, v)| (k, serde_json::json!(v)))
            .collect();

        let mut tags = vec!["windows".to_string(), "service".to_string()];
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

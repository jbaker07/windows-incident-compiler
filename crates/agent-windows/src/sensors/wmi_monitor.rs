// windows/sensors/wmi_monitor.rs
//! WMI activity monitoring: process execution, object modification
//!
//! # Architecture Note
//! This module is intentionally a STUB. WMI persistence events are captured via the
//! unified WEVTAPI polling path (`wevt_reader.rs`), then normalized in
//! `attack_surface.rs::parse_wmi_persistence()`.
//!
//! The sources handled by the main pipeline are:
//! - Sysmon EventID 19: WMI filter created
//! - Sysmon EventID 20: WMI consumer created
//! - Sysmon EventID 21: WMI filter/consumer binding
//!
//! Note: WMI-Activity/Operational events (5857-5861) are also polled for additional
//! context but the primary detection path is through Sysmon WMI events.
//!
//! This module remains for reference and to document the expected event schema.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiEvent {
    pub event_id: u32,
    pub ts: DateTime<Utc>,
    pub computer: String,
    pub fields: BTreeMap<String, String>,
    pub stream_id: Option<String>,
    pub segment_id: Option<String>,
    pub record_index: Option<u64>,
}

#[derive(Debug)]
pub struct WmiMonitor;

impl WmiMonitor {
    pub fn collect(_host: &crate::host::HostCtx) -> Vec<edr_core::Event> {
        // On Windows: would query Microsoft-Windows-WMI-Activity/Operational
        // Event 5857: WMI event consumer delivery failure (suspicious activity)
        // Event 5858: WMI query creation (process execution via WMI)
        // For now: WMI events are included in wevt_reader polling
        // This module is a STUB - all WMI events flow through main event log reader
        vec![]
    }

    pub fn to_canonical_event(event: &WmiEvent) -> Option<edr_core::Event> {
        // Convert WmiEvent to canonical Event
        // WMI-Activity/Operational 5857: Event consumer delivery failed
        // WMI-Activity/Operational 5858: WMI query created (method execution)

        let event_tag = match event.event_id {
            5857 => "wmi_consumer_delivery",
            5858 => "wmi_query_execution",
            _ => "wmi_unknown",
        };

        let fields = event.fields.clone();
        // Convert string values to JSON for consistency
        let fields_json: BTreeMap<String, serde_json::Value> = fields
            .into_iter()
            .map(|(k, v)| (k, serde_json::json!(v)))
            .collect();

        let mut tags = vec!["windows".to_string(), "wmi".to_string()];
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

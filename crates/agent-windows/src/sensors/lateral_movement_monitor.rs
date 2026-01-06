// windows/sensors/lateral_movement_monitor.rs
// Lateral movement detection: RDP, PSExec, WinRM, pass-the-hash, etc.
// Sources: Security event logs, Sysmon

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementEvent {
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
pub struct LateralMovementMonitor;

impl LateralMovementMonitor {
    pub fn collect(_host: &crate::host::HostCtx) -> Vec<edr_core::Event> {
        // On Windows: would query Security 4624 (LogonType, SourceNetworkAddress), 4769 (Kerberos), 4688 (CommandLine)
        // Pattern: type 3/10 logons (network/RDP), failed logons, suspicious Kerberos requests
        // For now: Logon events are included in wevt_reader polling
        // This module is a STUB - all lateral movement detection flows through main event log reader
        vec![]
    }

    pub fn to_canonical_event(event: &LateralMovementEvent) -> Option<edr_core::Event> {
        // Convert LateralMovementEvent to canonical Event
        // Security 4624: Account logon (type 3=network, 10=RDP)
        // Security 4769: Kerberos service ticket requested
        // Security 4688: Process created (check CommandLine for suspicious tools)

        let event_tag = match event.event_id {
            4624 => "network_logon",
            4769 => "kerberos_request",
            4688 => "process_create",
            _ => "lateral_movement_unknown",
        };

        let fields = event.fields.clone();
        // Convert string values to JSON for consistency
        let fields_json: BTreeMap<String, serde_json::Value> = fields
            .into_iter()
            .map(|(k, v)| (k, serde_json::json!(v)))
            .collect();

        let mut tags = vec!["windows".to_string(), "lateral_movement".to_string()];
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

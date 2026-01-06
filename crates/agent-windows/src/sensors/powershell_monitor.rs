// windows/sensors/powershell_monitor.rs
// PowerShell command execution monitoring: scripts, cmdlets, execution policy bypass
// Sources: Microsoft-Windows-PowerShell/Operational (Event IDs 4100, 4104=ScriptBlock execution)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShellEvent {
    pub event_id: u32,
    pub ts: DateTime<Utc>,
    pub computer: String,
    pub fields: BTreeMap<String, String>,
    pub stream_id: Option<String>,
    pub segment_id: Option<String>,
    pub record_index: Option<u64>,
}

#[derive(Debug)]
pub struct PowerShellMonitor;

impl PowerShellMonitor {
    pub fn collect(_host: &crate::host::HostCtx) -> Vec<edr_core::Event> {
        // On Windows: would query Microsoft-Windows-PowerShell/Operational
        // Event 4100: Engine state changed
        // Event 4104: Script block execution (high-value, captures actual command)
        // For now: PowerShell events are included in wevt_reader polling
        // This module is a STUB - all PowerShell events flow through main event log reader
        vec![]
    }

    pub fn to_canonical_event(event: &PowerShellEvent) -> Option<edr_core::Event> {
        // Convert PowerShellEvent to canonical Event
        // PowerShell/Operational 4100: Engine state changed (startup)
        // PowerShell/Operational 4104: Script block execution (captured cmdline)

        let event_tag = match event.event_id {
            4100 => "ps_engine_state",
            4104 => "ps_script_block",
            _ => "ps_unknown",
        };

        let fields = event.fields.clone();
        // Convert string values to JSON for consistency
        let fields_json: BTreeMap<String, serde_json::Value> = fields
            .into_iter()
            .map(|(k, v)| (k, serde_json::json!(v)))
            .collect();

        let mut tags = vec!["windows".to_string(), "powershell".to_string()];
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

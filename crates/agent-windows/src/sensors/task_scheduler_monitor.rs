// windows/sensors/task_scheduler_monitor.rs
// Scheduled task lifecycle monitoring: create, update, run
// Sources: TaskScheduler/Operational (Event IDs 106=create, 140=update, 200=execute)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSchedulerEvent {
    pub event_id: u32,
    pub ts: DateTime<Utc>,
    pub computer: String,
    pub fields: BTreeMap<String, String>,
    pub stream_id: Option<String>,
    pub segment_id: Option<String>,
    pub record_index: Option<u64>,
}

#[derive(Debug)]
pub struct TaskSchedulerMonitor;

impl TaskSchedulerMonitor {
    pub fn collect(_host: &crate::host::HostCtx) -> Vec<edr_core::Event> {
        // On Windows: would query TaskScheduler/Operational 106/140/200 (TaskName, Actions, Triggers)
        // For now: Task events are included in wevt_reader polling
        // This module is a STUB - all task events flow through main event log reader
        vec![]
    }

    pub fn to_canonical_event(event: &TaskSchedulerEvent) -> Option<edr_core::Event> {
        // Convert TaskSchedulerEvent to canonical Event
        // TaskScheduler/Operational 106: Task registered (created)
        // TaskScheduler/Operational 140: Task updated
        // TaskScheduler/Operational 200: Task executed

        let event_tag = match event.event_id {
            106 => "task_register",
            140 => "task_update",
            200 => "task_execute",
            _ => "task_unknown",
        };

        let fields = event.fields.clone();
        // Convert string values to JSON for consistency
        let fields_json: BTreeMap<String, serde_json::Value> = fields
            .into_iter()
            .map(|(k, v)| (k, serde_json::json!(v)))
            .collect();

        let mut tags = vec!["windows".to_string(), "task_scheduler".to_string()];
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

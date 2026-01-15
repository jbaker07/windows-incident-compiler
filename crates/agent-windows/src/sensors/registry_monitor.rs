// windows/sensors/registry_monitor.rs
//! Registry key/value monitoring: persistence through registry modifications
//!
//! # Architecture Note
//! This module is intentionally a STUB. Registry events are captured via the
//! unified WEVTAPI polling path (`wevt_reader.rs`), then normalized in
//! `attack_surface.rs::parse_registry_mod()`.
//!
//! The sources handled by the main pipeline are:
//! - Sysmon EventID 12: RegistryObject created
//! - Sysmon EventID 13: RegistryObject value set
//! - Sysmon EventID 14: RegistryObject renamed
//! - Security EventID 4657: Registry value modified
//!
//! This module remains for reference and to document the expected event schema.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
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
pub struct RegistryMonitor;

impl RegistryMonitor {
    pub fn collect(_host: &crate::host::HostCtx) -> Vec<edr_core::Event> {
        // On Windows: would query Sysmon events 12-14 (TargetObject, Image, ProcessId, User fields)
        // For now: Sysmon events are included in wevt_reader polling
        // This module is a STUB - all registry events flow through main event log reader
        vec![]
    }

    pub fn to_canonical_event(event: &RegistryEvent) -> Option<edr_core::Event> {
        // Convert RegistryEvent (Sysmon 12-14 or Security 4657) to canonical Event
        // Sysmon 12: RegistryObject created
        // Sysmon 13: RegistryObject value set
        // Sysmon 14: RegistryObject renamed
        // Security 4657: Registry value modified

        let event_tag = match event.event_id {
            12 => "registry_create",
            13 => "registry_set_value",
            14 => "registry_rename",
            4657 => "registry_modify",
            _ => "registry_unknown",
        };

        let fields = event.fields.clone();
        // Convert string values to JSON for consistency
        let fields_json: BTreeMap<String, serde_json::Value> = fields
            .into_iter()
            .map(|(k, v)| (k, serde_json::json!(v)))
            .collect();

        let mut tags = vec!["windows".to_string(), "registry".to_string()];
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

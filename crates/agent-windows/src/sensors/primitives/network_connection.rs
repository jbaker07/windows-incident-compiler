// windows/sensors/primitives/network_connection.rs
// Detects network connections on Windows (Sysmon EventID 3, Security 5156)

use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Detect network connections from Windows network events
pub fn detect_network_connection(base_event: &Event) -> Option<Event> {
    // Extract required fields from base network event
    let remote_ip = base_event
        .fields
        .get(event_keys::NET_REMOTE_IP)
        .or_else(|| base_event.fields.get("DestinationIp"))
        .and_then(|v| v.as_str())?;

    let remote_port = base_event
        .fields
        .get(event_keys::NET_REMOTE_PORT)
        .or_else(|| base_event.fields.get("DestinationPort"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u16)?;

    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .or_else(|| base_event.fields.get("ProcessId"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)?;

    let uid = base_event
        .fields
        .get(event_keys::PROC_UID)
        .or_else(|| base_event.fields.get("User"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let euid_str = uid.clone();

    // Check for suspicious ports
    let suspicious_port = is_suspicious_port(remote_port);

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid_str));
    fields.insert(event_keys::NET_REMOTE_IP.to_string(), json!(remote_ip));
    fields.insert(event_keys::NET_REMOTE_PORT.to_string(), json!(remote_port));

    if suspicious_port {
        fields.insert(event_keys::NET_SUSPICIOUS_PORT.to_string(), json!(true));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "network_connection".to_string(),
            "sysmon".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None, // Capture will assign this
        fields,
    })
}

/// Check if port is commonly used for C&C or remote management
fn is_suspicious_port(port: u16) -> bool {
    matches!(
        port,
        4444 | 5555 | 6666 | 7777 | 8080 | 8443 | 9999 |  // Common C&C
        22 | 3389 | 5985 | 5986 |  // Remote management (SSH, RDP, WinRM)
        53 | 5353 |  // DNS (tunneling)
        123 |  // NTP (timing channels)
        25 | 587 | 465 // SMTP (exfiltration)
    )
}

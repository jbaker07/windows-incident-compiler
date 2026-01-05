// windows/sensors/primitives/staging_write.rs
// Detects file writes to staging directories (%TEMP%, %APPDATA%\Local\Temp, user\Downloads, etc.)

use edr_core::Event;
use edr_core::event_keys;
use std::collections::BTreeMap;
use serde_json::json;

/// Detect writes to staging directories on Windows
/// Triggers on paths matching:
/// - C:\Windows\Temp\, %TEMP%
/// - %APPDATA%\Local\Temp
/// - C:\Users\<user>\AppData\Local\Temp
/// - C:\Users\<user>\Downloads
/// - C:\Users\<user>\Desktop (sometimes used for staging)
pub fn detect_staging_write(base_event: &Event) -> Option<Event> {
    // Case-insensitive staging path prefixes (Windows paths use backslash)
    let staging_patterns = [
        r"\\Windows\Temp\\",
        r"\\Temp\\",
        r"\AppData\Local\Temp\\",
        r"\Downloads\\",
        r"\Desktop\\",  // Sometimes used for staging (lower priority)
    ];

    // Extract path from base file event
    let path = base_event.fields
        .get(event_keys::FILE_PATH)
        .or_else(|| base_event.fields.get("TargetFilename"))
        .and_then(|v| v.as_str())?;

    let path_lower = path.to_lowercase();

    // Check if path matches staging directories (case-insensitive)
    let mut is_staging = false;
    for pattern in &staging_patterns {
        // Use case-insensitive contains check
        let pattern_lower = pattern.to_lowercase();
        if path_lower.contains(&pattern_lower) {
            is_staging = true;
            break;
        }
    }

    if !is_staging {
        return None;
    }

    // Extract required fields
    let pid = base_event.fields
        .get(event_keys::PROC_PID)
        .or_else(|| base_event.fields.get("ProcessId"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)?;
    
    let uid = base_event.fields
        .get(event_keys::PROC_UID)
        .or_else(|| base_event.fields.get("User"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    
    let euid_str = uid.clone();

    let exe = base_event.fields
        .get(event_keys::PROC_EXE)
        .or_else(|| base_event.fields.get("Image"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Determine operation type (create, write, modify, etc.)
    let op = base_event.fields
        .get(event_keys::FILE_OP)
        .or_else(|| base_event.fields.get("EventType"))
        .and_then(|v| v.as_str())
        .unwrap_or("write")
        .to_string();

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid_str));
    if !exe.is_empty() {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    }
    fields.insert(event_keys::FILE_PATH.to_string(), json!(path));
    fields.insert(event_keys::FILE_OP.to_string(), json!(op));
    fields.insert(event_keys::PRIMITIVE_SUBTYPE.to_string(), json!("staging_write"));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec!["windows".to_string(), "exfiltration".to_string(), "sysmon".to_string()],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,  // Capture will assign this
        fields,
    })
}

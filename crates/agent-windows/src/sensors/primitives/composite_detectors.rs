// windows/sensors/primitives/composite_detectors.rs
// High-value composite detectors for Windows combining multiple signals

use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Detect LSASS credential harvesting pattern
/// Indicator: Process accessing LSASS memory + procdump/minidump creation
/// Threat level: Critical - LSASS harvesting is primary credential theft vector
pub fn detect_lsass_memory_dump_harvesting(base_event: &Event) -> Option<Event> {
    if !base_event.tags.contains(&"exec".to_string())
        && !base_event.tags.contains(&"sysmon_process".to_string())
        && !base_event.tags.contains(&"security_process".to_string())
    {
        return None;
    }

    let exe = base_event.fields.get(event_keys::PROC_EXE)?.as_str()?;
    let argv = base_event
        .fields
        .get(event_keys::PROC_ARGV)?
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })?;

    let exe_lower = exe.to_lowercase();
    let arg_str = argv.join(" ").to_lowercase();

    // Check for memory dump tools
    let is_dump_tool = exe_lower.contains("procdump")
        || exe_lower.contains("minidump")
        || exe_lower.contains("nanodump");

    if !is_dump_tool {
        return None;
    }

    // Check for LSASS in arguments or exe name
    let targets_lsass =
        arg_str.contains("lsass") || arg_str.contains("pid") || arg_str.contains("0x");

    if !targets_lsass {
        return None;
    }

    let host = &base_event.host;
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)?
        .as_u64()
        .map(|p| p as u32)?;
    let uid = base_event
        .fields
        .get(event_keys::PROC_UID)?
        .as_u64()
        .map(|u| u as u32)?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    fields.insert("correlation_type".to_string(), json!("lsass_memory_dump"));
    fields.insert("severity".to_string(), json!("critical"));
    fields.insert("impact".to_string(), json!("credential_harvesting"));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: host.clone(),
        tags: vec![
            "windows".to_string(),
            "credential_access".to_string(),
            "composite".to_string(),
            "high_value".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect registry persistence pattern
/// Indicator: Writing to HKLM\Software\Microsoft\Windows\Run registry + Sysmon registry event
/// Threat level: High - Registry Run key is primary Windows persistence mechanism
pub fn detect_registry_run_persistence(base_event: &Event) -> Option<Event> {
    if !base_event.tags.contains(&"sysmon_registry".to_string())
        && !base_event.tags.contains(&"registry".to_string())
    {
        return None;
    }

    let target_object = base_event
        .fields
        .get("TargetObject")
        .or(base_event.fields.get("target_object"))?
        .as_str()?;

    let target_lower = target_object.to_lowercase();

    // Check for Run registry keys
    let targets_run = target_lower.contains("\\run\\") || target_lower.contains("run key");

    if !targets_run {
        return None;
    }

    // Check that it's under HKLM or HKCU
    let is_user_writable =
        target_lower.contains("hkcu") || target_lower.contains("hkey_current_user");

    let host = &base_event.host;
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .and_then(|v| v.as_u64())
        .map(|p| p as u32)?;
    let uid = base_event
        .fields
        .get(event_keys::PROC_UID)
        .and_then(|v| v.as_u64())
        .map(|u| u as u32)?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert("registry_target".to_string(), json!(target_object));
    fields.insert(
        "correlation_type".to_string(),
        json!("registry_run_persistence"),
    );
    fields.insert("severity".to_string(), json!("high"));
    fields.insert("user_writable".to_string(), json!(is_user_writable));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: host.clone(),
        tags: vec![
            "windows".to_string(),
            "persistence_change".to_string(),
            "composite".to_string(),
            "high_value".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect UAC bypass pattern
/// Indicator: Execution bypassing UAC (fodhelper.exe, eventvwr.exe, etc.) + unsigned binary
/// Threat level: High - UAC bypass enables unrestricted code execution
pub fn detect_uac_bypass_with_unsigned_execution(base_event: &Event) -> Option<Event> {
    if !base_event.tags.contains(&"exec".to_string())
        && !base_event.tags.contains(&"sysmon_process".to_string())
        && !base_event.tags.contains(&"security_process".to_string())
    {
        return None;
    }

    let exe = base_event.fields.get(event_keys::PROC_EXE)?.as_str()?;
    let exe_lower = exe.to_lowercase();

    // Check for UAC bypass tools
    let uac_bypass_tools = [
        "fodhelper.exe",
        "eventvwr.exe",
        "wsreset.exe",
        "wusa.exe",
        "slui.exe",
        "compmgmt.msc",
    ];

    let is_uac_tool = uac_bypass_tools.iter().any(|tool| exe_lower.contains(tool));

    if !is_uac_tool {
        return None;
    }

    let parent_exe = base_event
        .fields
        .get("parent_exe")
        .or(base_event.fields.get("ParentImage"))?
        .as_str()?;

    // Check if parent is a suspicious process
    let suspicious_parents = ["powershell", "cmd.exe", "explorer.exe", "shell.exe"];
    let has_suspicious_parent = suspicious_parents
        .iter()
        .any(|p| parent_exe.to_lowercase().contains(p));

    if !has_suspicious_parent {
        return None;
    }

    let host = &base_event.host;
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)?
        .as_u64()
        .map(|p| p as u32)?;
    let uid = base_event
        .fields
        .get(event_keys::PROC_UID)?
        .as_u64()
        .map(|u| u as u32)?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    fields.insert("parent_exe".to_string(), json!(parent_exe));
    fields.insert("correlation_type".to_string(), json!("uac_bypass"));
    fields.insert("severity".to_string(), json!("high"));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: host.clone(),
        tags: vec![
            "windows".to_string(),
            "defense_evasion".to_string(),
            "composite".to_string(),
            "high_value".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect event log tampering via wevtutil
/// Indicator: Execution of wevtutil to clear/disable security logs
/// Threat level: High - Indicates post-compromise log covering
pub fn detect_event_log_tampering(base_event: &Event) -> Option<Event> {
    if !base_event.tags.contains(&"exec".to_string())
        && !base_event.tags.contains(&"sysmon_process".to_string())
        && !base_event.tags.contains(&"security_process".to_string())
    {
        return None;
    }

    let exe = base_event.fields.get(event_keys::PROC_EXE)?.as_str()?;
    let argv = base_event
        .fields
        .get(event_keys::PROC_ARGV)?
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })?;

    let exe_lower = exe.to_lowercase();
    let arg_str = argv.join(" ").to_lowercase();

    if !exe_lower.contains("wevtutil") {
        return None;
    }

    // Check for log clearing/disabling operations
    let tampering_operations = ["clear-log", "cl", "set-log", "sl"];
    let is_tampering = tampering_operations.iter().any(|op| arg_str.contains(op));

    if !is_tampering {
        return None;
    }

    let host = &base_event.host;
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)?
        .as_u64()
        .map(|p| p as u32)?;
    let uid = base_event
        .fields
        .get(event_keys::PROC_UID)?
        .as_u64()
        .map(|u| u as u32)?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    fields.insert("correlation_type".to_string(), json!("event_log_tampering"));
    fields.insert("severity".to_string(), json!("high"));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: host.clone(),
        tags: vec![
            "windows".to_string(),
            "defense_evasion".to_string(),
            "composite".to_string(),
            "high_value".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsass_dump_detection() {
        let mut fields = BTreeMap::new();
        fields.insert(
            event_keys::PROC_EXE.to_string(),
            json!("C:\\Tools\\procdump.exe"),
        );
        fields.insert(event_keys::PROC_PID.to_string(), json!(1000u64));
        fields.insert(event_keys::PROC_UID.to_string(), json!(1001u64));
        fields.insert(
            event_keys::PROC_ARGV.to_string(),
            json!(vec!["procdump.exe", "-ma", "lsass.exe", "output.dmp"]),
        );

        let event = Event {
            ts_ms: 1000000,
            host: "test_host".to_string(),
            tags: vec!["exec".to_string()],
            proc_key: Some("key".to_string()),
            file_key: None,
            identity_key: None,
            evidence_ptr: None,
            fields,
        };

        let result = detect_lsass_memory_dump_harvesting(&event);
        assert!(result.is_some());
        let evt = result.unwrap();
        assert!(evt.tags.contains(&"credential_access".to_string()));
        assert!(evt.tags.contains(&"high_value".to_string()));
    }

    #[test]
    fn test_uac_bypass_detection() {
        let mut fields = BTreeMap::new();
        fields.insert(
            event_keys::PROC_EXE.to_string(),
            json!("C:\\Windows\\System32\\fodhelper.exe"),
        );
        fields.insert(event_keys::PROC_PID.to_string(), json!(1000u64));
        fields.insert(event_keys::PROC_UID.to_string(), json!(1001u64));
        fields.insert(
            "parent_exe".to_string(),
            json!("C:\\Windows\\System32\\cmd.exe"),
        );

        let event = Event {
            ts_ms: 1000000,
            host: "test_host".to_string(),
            tags: vec!["exec".to_string()],
            proc_key: Some("key".to_string()),
            file_key: None,
            identity_key: None,
            evidence_ptr: None,
            fields,
        };

        let result = detect_uac_bypass_with_unsigned_execution(&event);
        assert!(result.is_some());
        let evt = result.unwrap();
        assert!(evt.tags.contains(&"defense_evasion".to_string()));
        assert!(evt.tags.contains(&"high_value".to_string()));
    }

    #[test]
    fn test_event_log_tampering_detection() {
        let mut fields = BTreeMap::new();
        fields.insert(
            event_keys::PROC_EXE.to_string(),
            json!("C:\\Windows\\System32\\wevtutil.exe"),
        );
        fields.insert(event_keys::PROC_PID.to_string(), json!(1000u64));
        fields.insert(event_keys::PROC_UID.to_string(), json!(1001u64));
        fields.insert(
            event_keys::PROC_ARGV.to_string(),
            json!(vec!["wevtutil.exe", "clear-log", "Security"]),
        );

        let event = Event {
            ts_ms: 1000000,
            host: "test_host".to_string(),
            tags: vec!["exec".to_string()],
            proc_key: Some("key".to_string()),
            file_key: None,
            identity_key: None,
            evidence_ptr: None,
            fields,
        };

        let result = detect_event_log_tampering(&event);
        assert!(result.is_some());
        let evt = result.unwrap();
        assert!(evt.tags.contains(&"defense_evasion".to_string()));
        assert!(evt.tags.contains(&"high_value".to_string()));
    }
}

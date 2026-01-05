// windows/sensors/primitives/process_injection.rs
// Detects process injection on Windows
// Triggers on: CreateRemoteThread, process hollowing, APC injection, DLL injection patterns

use edr_core::Event;
use edr_core::event_keys;
use std::collections::BTreeMap;
use serde_json::json;

/// Sysmon Event IDs for injection detection
/// EventID 8 = CreateRemoteThread
/// EventID 10 = ProcessAccess (with suspicious access rights)
const SYSMON_CREATE_REMOTE_THREAD: &str = "8";
const SYSMON_PROCESS_ACCESS: &str = "10";

/// Suspicious access rights for process injection
/// PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
const SUSPICIOUS_ACCESS_RIGHTS: &[u32] = &[
    0x0002,  // PROCESS_CREATE_THREAD
    0x0020,  // PROCESS_VM_WRITE
    0x0008,  // PROCESS_VM_OPERATION
    0x001F0FFF,  // PROCESS_ALL_ACCESS
    0x1FFFFF,    // All rights
];

/// Injection tool patterns
const INJECTION_TOOLS: &[&str] = &[
    "mimikatz",
    "cobalt",
    "beacon",
    "empire",
    "metasploit",
    "msfvenom",
    "shellcode",
    "inject",
    "reflective",
    "donut",
    "sharpshooter",
];

/// Detect process injection from Sysmon CreateRemoteThread (Event ID 8)
pub fn detect_process_injection(base_event: &Event) -> Option<Event> {
    // Check for Sysmon Event ID 8 (CreateRemoteThread)
    let event_id = base_event.fields
        .get("EventID")
        .or_else(|| base_event.fields.get("event_id"))
        .and_then(|v| v.as_str())
        .or_else(|| base_event.fields.get("EventID").and_then(|v| v.as_u64()).map(|_| "8"))?;

    let is_injection_event = event_id == SYSMON_CREATE_REMOTE_THREAD 
        || base_event.tags.contains(&"sysmon_create_remote_thread".to_string())
        || base_event.tags.contains(&"create_remote_thread".to_string());

    // Also check ProcessAccess with suspicious rights
    let is_suspicious_access = if event_id == SYSMON_PROCESS_ACCESS 
        || base_event.tags.contains(&"process_access".to_string()) {
        check_suspicious_access_rights(base_event)
    } else {
        false
    };

    if !is_injection_event && !is_suspicious_access {
        return None;
    }

    // Extract source process info
    let source_pid = base_event.fields
        .get(event_keys::PROC_PID)
        .or_else(|| base_event.fields.get("SourceProcessId"))
        .or_else(|| base_event.fields.get("ProcessId"))
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .map(|v| v as u32)?;

    let source_image = base_event.fields
        .get(event_keys::PROC_EXE)
        .or_else(|| base_event.fields.get("SourceImage"))
        .or_else(|| base_event.fields.get("Image"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Extract target process info
    let target_pid = base_event.fields
        .get("TargetProcessId")
        .or_else(|| base_event.fields.get("target_pid"))
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .map(|v| v as u32)?;

    let target_image = base_event.fields
        .get("TargetImage")
        .or_else(|| base_event.fields.get("target_image"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Skip self-injection
    if source_pid == target_pid {
        return None;
    }

    // Determine injection method
    let inject_method = determine_injection_method(base_event, event_id);

    // Get user info
    let uid = base_event.fields
        .get(event_keys::PROC_UID)
        .or_else(|| base_event.fields.get("User"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(source_pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid.clone()));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(source_image));
    fields.insert(event_keys::INJECT_METHOD.to_string(), json!(inject_method));
    fields.insert(event_keys::INJECT_TARGET_PID.to_string(), json!(target_pid));
    fields.insert(event_keys::INJECT_TARGET_EXE.to_string(), json!(target_image));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "process_injection".to_string(),
            "sysmon".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None, // Capture will assign this
        fields,
    })
}

/// Detect process injection from exec (looking for injection tool signatures)
pub fn detect_process_injection_from_exec(base_event: &Event) -> Option<Event> {
    let image = base_event.fields
        .get(event_keys::PROC_EXE)
        .or_else(|| base_event.fields.get("Image"))
        .and_then(|v| v.as_str())?;

    let image_lower = image.to_lowercase();

    let cmd_line = base_event.fields
        .get(event_keys::PROC_ARGV)
        .or_else(|| base_event.fields.get("CommandLine"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    // Check for injection tool patterns
    let mut matched_tool = None;
    for tool in INJECTION_TOOLS {
        if image_lower.contains(tool) || cmd_line.contains(tool) {
            matched_tool = Some(*tool);
            break;
        }
    }

    // Check for specific injection patterns in command line
    if matched_tool.is_none() {
        let injection_cmdline_patterns = [
            "createremotethread",
            "ntcreatethreadex",
            "queueuserapc",
            "setthreadcontext",
            "writeprocessmemory",
            "virtualalloc",
            "rtlcreateuserthread",
            "ntunmapviewofsection",  // Process hollowing
            "-inject",
            "/inject",
            "reflectiveloader",
        ];

        for pattern in &injection_cmdline_patterns {
            if cmd_line.contains(pattern) {
                matched_tool = Some(*pattern);
                break;
            }
        }
    }

    // Check for PowerShell reflection/injection
    if matched_tool.is_none() && image_lower.contains("powershell") {
        let ps_injection_patterns = [
            "[System.Runtime.InteropServices.Marshal]",
            "GetDelegateForFunctionPointer",
            "VirtualProtect",
            "CreateThread",
            "[DllImport",
            "Add-Type -TypeDefinition",
            "Invoke-ReflectivePEInjection",
            "Invoke-Shellcode",
        ];

        for pattern in &ps_injection_patterns {
            if cmd_line.contains(&pattern.to_lowercase()) {
                matched_tool = Some("powershell_reflection");
                break;
            }
        }
    }

    let inject_tool = matched_tool?;

    // Extract PIDs
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

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid.clone()));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(image));
    fields.insert(event_keys::INJECT_METHOD.to_string(), json!(inject_tool));
    fields.insert(event_keys::INJECT_TARGET_PID.to_string(), json!(0u32)); // Unknown target
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(cmd_line));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "process_injection".to_string(),
            "sysmon".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Check if ProcessAccess event has suspicious access rights
fn check_suspicious_access_rights(base_event: &Event) -> bool {
    let granted_access = base_event.fields
        .get("GrantedAccess")
        .or_else(|| base_event.fields.get("granted_access"))
        .and_then(|v| {
            // Could be hex string or number
            if let Some(s) = v.as_str() {
                if s.starts_with("0x") {
                    u32::from_str_radix(&s[2..], 16).ok()
                } else {
                    s.parse().ok()
                }
            } else {
                v.as_u64().map(|n| n as u32)
            }
        });

    if let Some(access) = granted_access {
        // Check if any suspicious rights are set
        for &suspicious in SUSPICIOUS_ACCESS_RIGHTS {
            if access & suspicious == suspicious {
                return true;
            }
        }
    }

    false
}

/// Determine injection method from event data
fn determine_injection_method(base_event: &Event, event_id: &str) -> &'static str {
    if event_id == SYSMON_CREATE_REMOTE_THREAD {
        // Check for specific signatures
        let start_address = base_event.fields
            .get("StartAddress")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let start_function = base_event.fields
            .get("StartFunction")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if start_function.contains("LoadLibrary") {
            return "dll_injection";
        }
        if start_address.starts_with("0x") {
            // Non-module address suggests shellcode
            return "create_remote_thread";
        }
        return "create_remote_thread";
    }

    if event_id == SYSMON_PROCESS_ACCESS {
        return "process_access";
    }

    "unknown"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_base_event(tags: Vec<&str>, fields: Vec<(&str, serde_json::Value)>) -> Event {
        let mut f = BTreeMap::new();
        for (k, v) in fields {
            f.insert(k.to_string(), v);
        }
        Event {
            ts_ms: 1000000,
            host: "testhost".to_string(),
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            proc_key: Some("proc_test".to_string()),
            file_key: None,
            identity_key: Some("id_test".to_string()),
            evidence_ptr: None,
            fields: f,
        }
    }

    #[test]
    fn test_detect_create_remote_thread() {
        let event = make_base_event(
            vec!["sysmon", "create_remote_thread"],
            vec![
                ("EventID", json!("8")),
                ("SourceProcessId", json!(1234)),
                ("SourceImage", json!("C:\\evil\\injector.exe")),
                ("TargetProcessId", json!(5678)),
                ("TargetImage", json!("C:\\Windows\\explorer.exe")),
                ("User", json!("DOMAIN\\user")),
            ],
        );

        let result = detect_process_injection(&event);
        assert!(result.is_some());
        let e = result.unwrap();
        assert!(e.tags.contains(&"process_injection".to_string()));
        assert_eq!(e.fields.get("inject_method").unwrap(), "create_remote_thread");
        assert_eq!(e.fields.get("inject_target_pid").unwrap(), 5678);
    }

    #[test]
    fn test_detect_mimikatz_injection() {
        let event = make_base_event(
            vec!["sysmon_process", "exec"],
            vec![
                (event_keys::PROC_PID, json!(1234)),
                (event_keys::PROC_EXE, json!("C:\\temp\\mimikatz.exe")),
                (event_keys::PROC_ARGV, json!("mimikatz.exe sekurlsa::logonpasswords")),
                (event_keys::PROC_UID, json!("admin")),
            ],
        );

        let result = detect_process_injection_from_exec(&event);
        assert!(result.is_some());
        let e = result.unwrap();
        assert_eq!(e.fields.get("inject_method").unwrap(), "mimikatz");
    }

    #[test]
    fn test_detect_powershell_reflection() {
        let event = make_base_event(
            vec!["sysmon_process", "exec"],
            vec![
                (event_keys::PROC_PID, json!(1234)),
                (event_keys::PROC_EXE, json!("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")),
                (event_keys::PROC_ARGV, json!("[DllImport(\"kernel32\")] static extern IntPtr VirtualAlloc")),
                (event_keys::PROC_UID, json!("user")),
            ],
        );

        let result = detect_process_injection_from_exec(&event);
        assert!(result.is_some());
        let e = result.unwrap();
        assert_eq!(e.fields.get("inject_method").unwrap(), "powershell_reflection");
    }

    #[test]
    fn test_skip_self_injection() {
        let event = make_base_event(
            vec!["sysmon", "create_remote_thread"],
            vec![
                ("EventID", json!("8")),
                ("SourceProcessId", json!(1234)),
                ("SourceImage", json!("C:\\app\\app.exe")),
                ("TargetProcessId", json!(1234)), // Same PID
                ("TargetImage", json!("C:\\app\\app.exe")),
                ("User", json!("user")),
            ],
        );

        let result = detect_process_injection(&event);
        assert!(result.is_none());
    }

    #[test]
    fn test_no_detection_normal_process() {
        let event = make_base_event(
            vec!["sysmon_process", "exec"],
            vec![
                (event_keys::PROC_PID, json!(1234)),
                (event_keys::PROC_EXE, json!("C:\\Windows\\notepad.exe")),
                (event_keys::PROC_ARGV, json!("notepad.exe document.txt")),
                (event_keys::PROC_UID, json!("user")),
            ],
        );

        let result = detect_process_injection_from_exec(&event);
        assert!(result.is_none());
    }
}

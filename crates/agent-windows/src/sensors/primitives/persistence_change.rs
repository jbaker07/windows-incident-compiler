// windows/sensors/primitives/persistence_change.rs
// Detects persistence mechanism changes on Windows
// Registry Run keys, Services, Tasks, WMI subscriptions, Startup folders

use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Registry persistence locations
const REGISTRY_PERSISTENCE: &[(&str, &str)] = &[
    // Run keys
    (
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "registry_run",
    ),
    (
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "registry_run",
    ),
    (
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "registry_run",
    ),
    (
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        "registry_run",
    ),
    (
        "\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "registry_run",
    ),
    // AppInit_DLLs
    (
        "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
        "appinit_dlls",
    ),
    // Winlogon
    (
        "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
        "winlogon",
    ),
    (
        "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
        "winlogon",
    ),
    (
        "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify",
        "winlogon",
    ),
    // Active Setup
    (
        "\\Software\\Microsoft\\Active Setup\\Installed Components",
        "active_setup",
    ),
    // Image File Execution Options (debugger hijacking)
    (
        "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "ifeo",
    ),
    // Services
    ("\\System\\CurrentControlSet\\Services", "service"),
    ("\\ControlSet001\\Services", "service"),
    // COM objects
    ("\\Software\\Classes\\CLSID", "com_hijack"),
    // Explorer shell extensions
    (
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
        "shell_extension",
    ),
    (
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
        "shell_extension",
    ),
    // Browser extensions
    (
        "\\Software\\Microsoft\\Internet Explorer\\Extensions",
        "browser_extension",
    ),
];

/// File-based persistence locations (Startup folders)
const FILE_PERSISTENCE: &[(&str, &str)] = &[
    ("\\Start Menu\\Programs\\Startup\\", "startup_folder"),
    (
        "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
        "startup_folder",
    ),
    (
        "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        "startup_folder",
    ),
];

/// Detect persistence change from registry events (Sysmon 12, 13, 14)
pub fn detect_persistence_change(base_event: &Event) -> Option<Event> {
    // Check for registry events
    let event_id = base_event
        .fields
        .get("EventID")
        .or_else(|| base_event.fields.get("windows.event_id"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32)?;

    // Sysmon 12 = RegistryEvent (Object create/delete)
    // Sysmon 13 = RegistryEvent (Value Set)
    // Sysmon 14 = RegistryEvent (Key and Value Rename)
    if !matches!(event_id, 12..=14) && !base_event.tags.iter().any(|t| t.contains("registry")) {
        return None;
    }

    // Get registry path
    let target_object = base_event
        .fields
        .get("TargetObject")
        .or_else(|| base_event.fields.get("target_object"))
        .and_then(|v| v.as_str())?;

    // Check if path matches persistence location
    let (persist_type, action) = match_registry_persistence(target_object, event_id)?;

    // Extract process info
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .or_else(|| base_event.fields.get("ProcessId"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32)?;

    let image = base_event
        .fields
        .get(event_keys::PROC_EXE)
        .or_else(|| base_event.fields.get("Image"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let user = base_event
        .fields
        .get(event_keys::PROC_UID)
        .or_else(|| base_event.fields.get("User"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(user.clone()));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(user));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(image));
    fields.insert(
        event_keys::PERSIST_LOCATION.to_string(),
        json!(target_object),
    );
    fields.insert(event_keys::PERSIST_TYPE.to_string(), json!(persist_type));
    fields.insert(event_keys::PERSIST_ACTION.to_string(), json!(action));

    // Include Details field if present (contains the actual value)
    if let Some(details) = base_event.fields.get("Details").and_then(|v| v.as_str()) {
        fields.insert("persist_value".to_string(), json!(details));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "persistence_change".to_string(),
            "sysmon".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect persistence from file creation in Startup folders (Sysmon 11)
pub fn detect_persistence_from_file(base_event: &Event) -> Option<Event> {
    let event_id = base_event
        .fields
        .get("EventID")
        .or_else(|| base_event.fields.get("windows.event_id"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32)?;

    // Sysmon 11 = FileCreate
    if event_id != 11 && !base_event.tags.iter().any(|t| t.contains("file_create")) {
        return None;
    }

    let target_filename = base_event
        .fields
        .get("TargetFilename")
        .or_else(|| base_event.fields.get(event_keys::FILE_PATH))
        .and_then(|v| v.as_str())?;

    // Check if file is in startup folder
    let (persist_type, _) = FILE_PERSISTENCE
        .iter()
        .find(|(pattern, _)| target_filename.contains(pattern))
        .map(|(_, t)| (*t, "create"))?;

    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .or_else(|| base_event.fields.get("ProcessId"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32)?;

    let image = base_event
        .fields
        .get(event_keys::PROC_EXE)
        .or_else(|| base_event.fields.get("Image"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let user = base_event
        .fields
        .get(event_keys::PROC_UID)
        .or_else(|| base_event.fields.get("User"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(user.clone()));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(user));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(image));
    fields.insert(
        event_keys::PERSIST_LOCATION.to_string(),
        json!(target_filename),
    );
    fields.insert(event_keys::PERSIST_TYPE.to_string(), json!(persist_type));
    fields.insert(event_keys::PERSIST_ACTION.to_string(), json!("create"));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "persistence_change".to_string(),
            "sysmon".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: base_event.file_key.clone(),
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect persistence from scheduled task creation (Security 4698, 4702)
pub fn detect_persistence_from_task(base_event: &Event) -> Option<Event> {
    let event_id = base_event
        .fields
        .get("EventID")
        .or_else(|| base_event.fields.get("windows.event_id"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32)?;

    // 4698 = Task created, 4702 = Task updated
    let action = match event_id {
        4698 => "create",
        4702 => "modify",
        _ if base_event.tags.iter().any(|t| t.contains("task")) => "modify",
        _ => return None,
    };

    let task_name = base_event.fields.get("TaskName").and_then(|v| v.as_str())?;

    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .or_else(|| base_event.fields.get("ProcessId"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0);

    let user = base_event
        .fields
        .get("SubjectUserName")
        .or_else(|| base_event.fields.get(event_keys::PROC_UID))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(user.clone()));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(user));
    fields.insert(event_keys::PROC_EXE.to_string(), json!("taskschd.dll"));
    fields.insert(event_keys::PERSIST_LOCATION.to_string(), json!(task_name));
    fields.insert(
        event_keys::PERSIST_TYPE.to_string(),
        json!("scheduled_task"),
    );
    fields.insert(event_keys::PERSIST_ACTION.to_string(), json!(action));

    // Include task content if available
    if let Some(content) = base_event
        .fields
        .get("TaskContent")
        .and_then(|v| v.as_str())
    {
        // Truncate to first 2KB
        let content_limited = if content.len() > 2048 {
            &content[..2048]
        } else {
            content
        };
        fields.insert("task_content".to_string(), json!(content_limited));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "persistence_change".to_string(),
            "security".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect persistence from service installation (Security 4697, System 7045)
pub fn detect_persistence_from_service(base_event: &Event) -> Option<Event> {
    let event_id = base_event
        .fields
        .get("EventID")
        .or_else(|| base_event.fields.get("windows.event_id"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32)?;

    // 4697 (Security) = Service installed, 7045 (System) = Service installed
    if !matches!(event_id, 4697 | 7045) && !base_event.tags.iter().any(|t| t.contains("service")) {
        return None;
    }

    let service_name = base_event
        .fields
        .get("ServiceName")
        .or_else(|| base_event.fields.get("TargetServiceName"))
        .and_then(|v| v.as_str())?;

    let service_file = base_event
        .fields
        .get("ServiceFileName")
        .or_else(|| base_event.fields.get("FileName"))
        .and_then(|v| v.as_str());

    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0);

    let user = base_event
        .fields
        .get("SubjectUserName")
        .or_else(|| base_event.fields.get(event_keys::PROC_UID))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(user.clone()));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(user));
    fields.insert(
        event_keys::PROC_EXE.to_string(),
        json!(service_file.unwrap_or("unknown")),
    );
    fields.insert(
        event_keys::PERSIST_LOCATION.to_string(),
        json!(service_name),
    );
    fields.insert(event_keys::PERSIST_TYPE.to_string(), json!("service"));
    fields.insert(event_keys::PERSIST_ACTION.to_string(), json!("create"));

    if let Some(sf) = service_file {
        fields.insert("service_file".to_string(), json!(sf));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "persistence_change".to_string(),
            "security".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

fn match_registry_persistence(path: &str, event_id: u32) -> Option<(&'static str, &'static str)> {
    let path_lower = path.to_lowercase();

    for (pattern, persist_type) in REGISTRY_PERSISTENCE {
        if path_lower.contains(&pattern.to_lowercase()) {
            let action = match event_id {
                12 => "create", // Object create/delete
                13 => "modify", // Value set
                14 => "modify", // Rename
                _ => "modify",
            };
            return Some((persist_type, action));
        }
    }
    None
}

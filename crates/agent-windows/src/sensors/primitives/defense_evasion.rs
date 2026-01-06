// windows/sensors/primitives/defense_evasion.rs
// Detects defense evasion activities on Windows
// Log clearing, audit tampering, security tool disabling

// Evasion tool lists and event constants used by conditional detection
#![allow(dead_code)]

use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Security Event IDs for defense evasion
const EVENT_LOG_CLEARED: u32 = 1102; // Security log was cleared
const EVENT_AUDIT_POLICY_CHANGE: u32 = 4719; // System audit policy changed
const EVENT_AUDIT_DISABLED: u32 = 4713; // Kerberos policy changed (can indicate evasion)

/// System Event IDs
const SYSTEM_LOG_CLEARED: u32 = 104; // System log was cleared

/// Sysmon Event IDs
const SYSMON_FILE_DELETE: u32 = 23; // FileDelete (archived)
const SYSMON_FILE_DELETE_LOGGED: u32 = 26; // FileDeleteDetected

/// Log files to watch for deletion
const LOG_TARGETS: &[&str] = &[
    "\\Windows\\System32\\winevt\\Logs\\",
    "\\Windows\\System32\\config\\",
    ".evtx",
    "Security.evtx",
    "System.evtx",
    "Application.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
];

/// Tools associated with evasion
const EVASION_TOOLS: &[&str] = &[
    "wevtutil", "fsutil", "bcdedit", "auditpol", "reg", "sc", "net", "attrib", "icacls",
];

/// Detect defense evasion from Security log clearing (Event 1102)
pub fn detect_defense_evasion_log_clear(base_event: &Event) -> Option<Event> {
    let event_id = base_event
        .fields
        .get("EventID")
        .or_else(|| base_event.fields.get("windows.event_id"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32)?;

    // Check for log clear events
    let (evasion_target, channel) = match event_id {
        EVENT_LOG_CLEARED => ("log", "Security"),
        SYSTEM_LOG_CLEARED => ("log", "System"),
        _ if base_event.tags.iter().any(|t| t.contains("log_clear")) => ("log", "unknown"),
        _ => return None,
    };

    let user = base_event
        .fields
        .get("SubjectUserName")
        .or_else(|| base_event.fields.get("User"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let domain = base_event
        .fields
        .get("SubjectDomainName")
        .and_then(|v| v.as_str());

    let full_user = if let Some(d) = domain {
        format!("{}\\{}", d, user)
    } else {
        user.clone()
    };

    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .or_else(|| base_event.fields.get("ProcessId"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0);

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(full_user.clone()));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(full_user));
    fields.insert(event_keys::PROC_EXE.to_string(), json!("wevtutil.exe"));
    fields.insert(
        event_keys::EVASION_TARGET.to_string(),
        json!(evasion_target),
    );
    fields.insert(event_keys::EVASION_ACTION.to_string(), json!("clear"));
    fields.insert("cleared_log".to_string(), json!(channel));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "defense_evasion".to_string(),
            "security".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect defense evasion from audit policy change (Event 4719)
pub fn detect_defense_evasion_audit_change(base_event: &Event) -> Option<Event> {
    let event_id = base_event
        .fields
        .get("EventID")
        .or_else(|| base_event.fields.get("windows.event_id"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32)?;

    if event_id != EVENT_AUDIT_POLICY_CHANGE {
        return None;
    }

    let user = base_event
        .fields
        .get("SubjectUserName")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0);

    // Check if audit was disabled
    let audit_category = base_event
        .fields
        .get("CategoryId")
        .or_else(|| base_event.fields.get("AuditCategory"))
        .and_then(|v| v.as_str());

    let subcategory = base_event
        .fields
        .get("SubcategoryId")
        .or_else(|| base_event.fields.get("SubcategoryGuid"))
        .and_then(|v| v.as_str());

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(user.clone()));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(user));
    fields.insert(event_keys::PROC_EXE.to_string(), json!("auditpol.exe"));
    fields.insert(event_keys::EVASION_TARGET.to_string(), json!("audit"));
    fields.insert(event_keys::EVASION_ACTION.to_string(), json!("disable"));

    if let Some(cat) = audit_category {
        fields.insert("audit_category".to_string(), json!(cat));
    }
    if let Some(sub) = subcategory {
        fields.insert("audit_subcategory".to_string(), json!(sub));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "defense_evasion".to_string(),
            "security".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect defense evasion from exec (wevtutil clear, auditpol /set, etc.)
pub fn detect_defense_evasion_from_exec(base_event: &Event) -> Option<Event> {
    let image = base_event
        .fields
        .get(event_keys::PROC_EXE)
        .or_else(|| base_event.fields.get("Image"))
        .and_then(|v| v.as_str())?;

    let image_lower = image.to_lowercase();
    let image_base = std::path::Path::new(&image_lower)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let cmd_line = base_event
        .fields
        .get(event_keys::PROC_ARGV)
        .or_else(|| base_event.fields.get("CommandLine"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    // Detect evasion command
    let (evasion_target, evasion_action) = detect_evasion_command(image_base, &cmd_line)?;

    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .or_else(|| base_event.fields.get("ProcessId"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32)?;

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
        event_keys::EVASION_TARGET.to_string(),
        json!(evasion_target),
    );
    fields.insert(
        event_keys::EVASION_ACTION.to_string(),
        json!(evasion_action),
    );

    if !cmd_line.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(cmd_line));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "defense_evasion".to_string(),
            "sysmon".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect defense evasion from log file deletion (Sysmon 23, 26)
pub fn detect_defense_evasion_file_delete(base_event: &Event) -> Option<Event> {
    let event_id = base_event
        .fields
        .get("EventID")
        .or_else(|| base_event.fields.get("windows.event_id"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32)?;

    // Sysmon file delete events
    if !matches!(event_id, SYSMON_FILE_DELETE | SYSMON_FILE_DELETE_LOGGED) {
        return None;
    }

    let target_filename = base_event
        .fields
        .get("TargetFilename")
        .or_else(|| base_event.fields.get(event_keys::FILE_PATH))
        .and_then(|v| v.as_str())?;

    // Check if deleted file is a log target
    let is_log_target = LOG_TARGETS.iter().any(|pattern| {
        target_filename
            .to_lowercase()
            .contains(&pattern.to_lowercase())
    });

    if !is_log_target {
        return None;
    }

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
    fields.insert(event_keys::EVASION_TARGET.to_string(), json!("log"));
    fields.insert(event_keys::EVASION_ACTION.to_string(), json!("delete"));
    fields.insert(event_keys::FILE_PATH.to_string(), json!(target_filename));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "defense_evasion".to_string(),
            "sysmon".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: base_event.file_key.clone(),
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

fn detect_evasion_command(exe: &str, cmd_line: &str) -> Option<(&'static str, &'static str)> {
    match exe {
        "wevtutil.exe" | "wevtutil" => {
            if cmd_line.contains("cl ") || cmd_line.contains("clear-log") {
                return Some(("log", "clear"));
            }
            None
        }
        "auditpol.exe" | "auditpol" => {
            if cmd_line.contains("/set")
                && (cmd_line.contains("/success:disable") || cmd_line.contains("/failure:disable"))
            {
                return Some(("audit", "disable"));
            }
            if cmd_line.contains("clear") || cmd_line.contains("/remove") {
                return Some(("audit", "clear"));
            }
            None
        }
        "bcdedit.exe" | "bcdedit" => {
            if cmd_line.contains("recoveryenabled") && cmd_line.contains("no") {
                return Some(("security_tool", "disable"));
            }
            if cmd_line.contains("bootstatuspolicy") && cmd_line.contains("ignoreallfailures") {
                return Some(("security_tool", "disable"));
            }
            None
        }
        "fsutil.exe" | "fsutil" => {
            if cmd_line.contains("usn") && cmd_line.contains("deletejournal") {
                return Some(("log", "delete"));
            }
            None
        }
        "reg.exe" | "reg" => {
            // Disable Windows Defender, Firewall, etc.
            let cmd_lower = cmd_line.to_lowercase();
            if cmd_lower.contains("windows defender") && cmd_lower.contains("disableantispyware") {
                return Some(("security_tool", "disable"));
            }
            if cmd_lower.contains("securityhealth") && cmd_lower.contains("disablenotifications") {
                return Some(("security_tool", "disable"));
            }
            None
        }
        "sc.exe" | "sc" => {
            // Disable security services
            if cmd_line.contains("config") && cmd_line.contains("start= disabled") {
                let cmd_lower = cmd_line.to_lowercase();
                if cmd_lower.contains("windefend")
                    || cmd_lower.contains("mpssvc")
                    || cmd_lower.contains("seclogon")
                    || cmd_lower.contains("wscsvc")
                {
                    return Some(("security_tool", "disable"));
                }
            }
            if cmd_line.contains("stop") {
                let cmd_lower = cmd_line.to_lowercase();
                if cmd_lower.contains("windefend") || cmd_lower.contains("mpssvc") {
                    return Some(("security_tool", "disable"));
                }
            }
            None
        }
        "netsh.exe" | "netsh" => {
            if cmd_line.contains("firewall") && cmd_line.contains("disable") {
                return Some(("security_tool", "disable"));
            }
            if cmd_line.contains("advfirewall") && cmd_line.contains("off") {
                return Some(("security_tool", "disable"));
            }
            None
        }
        "powershell.exe" | "pwsh.exe" | "powershell" | "pwsh" => {
            let cmd_lower = cmd_line.to_lowercase();
            if cmd_lower.contains("clear-eventlog") {
                return Some(("log", "clear"));
            }
            if cmd_lower.contains("set-mppreference")
                && cmd_lower.contains("disablerealtimemonitoring")
            {
                return Some(("security_tool", "disable"));
            }
            if cmd_lower.contains("remove-item") && cmd_lower.contains("evtx") {
                return Some(("log", "delete"));
            }
            None
        }
        "attrib.exe" | "attrib" => {
            // Hiding files
            if cmd_line.contains("+h") && cmd_line.contains("+s") {
                return Some(("file", "hide"));
            }
            None
        }
        _ => None,
    }
}

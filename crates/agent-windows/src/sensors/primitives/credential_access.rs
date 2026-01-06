// windows/sensors/primitives/credential_access.rs
// Detects credential access via bounded tool execution (lsass.exe, procdump.exe, mimikatz, Get-Credential, etc.)

use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Detect credential access from Windows process creation events (Sysmon 1, Security 4688)
/// Triggers on: lsass.exe, procdump.exe, mimikatz, Get-Credential, Invoke-Mimikatz, etc.
pub fn detect_cred_access(base_event: &Event) -> Option<Event> {
    let cred_tools = [
        "lsass.exe",
        "procdump.exe",
        "procdump",
        "minidump.exe",
        "mimikatz",
        "mimikatz.exe",
        "Invoke-Mimikatz",
        "powershell.exe",
        "powershell", // With credential patterns (filtered below)
        "wmic.exe",
        "wmic",
        "tasklist.exe",
        "tasklist", // Used in credential enumeration chains
    ];

    // Extract image (executable name) from base event
    let image = base_event
        .fields
        .get(event_keys::PROC_EXE)
        .or_else(|| base_event.fields.get("image")) // Sysmon field name
        .and_then(|v| v.as_str())?;

    let image_lower = image.to_lowercase();
    let image_base = std::path::Path::new(&image_lower).file_name()?.to_str()?;

    // Check if image matches any cred tool
    let matched_tool = cred_tools
        .iter()
        .find(|tool| image_base.contains(&tool.to_lowercase()))?;

    // For PowerShell/WMIC, require additional context (command line patterns)
    if image_base.contains("powershell") || image_base.contains("wmic") {
        let cmd = base_event
            .fields
            .get(event_keys::PROC_ARGV)
            .or_else(|| base_event.fields.get("CommandLine"))
            .and_then(|v| v.as_str())?;

        let cred_patterns = [
            "Get-Credential",
            "credential",
            "Invoke-Mimikatz",
            "Invoke-WMIMethod",
            "Get-WmiObject",
            "process.*call.*create",
            "lsass",
            "procdump",
        ];

        let has_cred_context = cred_patterns.iter().any(|pat| cmd.contains(pat));
        if !has_cred_context {
            return None; // Filter out generic PowerShell/WMIC; need credential pattern
        }
    }

    // Extract required fields
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

    // For Windows, euid is typically same as uid (no setuid concept)
    let euid_str = uid.clone();

    let argv = base_event
        .fields
        .get(event_keys::PROC_ARGV)
        .or_else(|| base_event.fields.get("CommandLine"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid_str));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(image));
    fields.insert(
        event_keys::CRED_TOOL.to_string(),
        json!(matched_tool.to_string()),
    );

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "credential_access".to_string(),
            "sysmon".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None, // Capture will assign this
        fields,
    })
}

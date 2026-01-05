// windows/sensors/primitives/archive_tool_exec.rs
// Detects archive/compression tool execution (7z, tar via Git, PowerShell compression)

use edr_core::Event;
use edr_core::event_keys;
use std::collections::BTreeMap;
use serde_json::json;

/// Detect archive tool execution from Windows process creation events
/// Triggers on: 7z.exe, tar (via Git\usr\bin\tar), PowerShell with compression (Compress-Archive, etc.)
pub fn detect_archive_tool_exec(base_event: &Event) -> Option<Event> {
    let archive_tools = [
        "7z.exe", "7z",
        "tar.exe", "tar",  // Git ships tar
        "powershell.exe", "powershell",  // If using Compress-Archive
    ];

    // Extract image from base event
    let image = base_event.fields
        .get(event_keys::PROC_EXE)
        .or_else(|| base_event.fields.get("image"))
        .and_then(|v| v.as_str())?;
    
    let image_lower = image.to_lowercase();
    let image_base = std::path::Path::new(&image_lower)
        .file_name()?
        .to_str()?;

    // Check if image matches any archive tool
    let matched_tool = archive_tools.iter().find(|tool| {
        image_base.contains(&tool.to_lowercase())
    })?;

    // For PowerShell, require compression pattern in command line
    if image_base.contains("powershell") {
        let cmd = base_event.fields
            .get(event_keys::PROC_ARGV)
            .or_else(|| base_event.fields.get("CommandLine"))
            .and_then(|v| v.as_str())?;
        
        let compression_patterns = [
            "Compress-Archive",
            "expand-archive",
            "-CompressionLevel",
            "System.IO.Compression",
        ];
        
        let has_compression = compression_patterns.iter().any(|pat| cmd.contains(pat));
        if !has_compression {
            return None;  // Filter out generic PowerShell; need compression pattern
        }
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

    let argv = base_event.fields
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
    fields.insert(event_keys::ARCHIVE_TOOL.to_string(), json!(matched_tool.to_string()));
    fields.insert(event_keys::PRIMITIVE_SUBTYPE.to_string(), json!("archive_tool_exec"));
    
    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

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

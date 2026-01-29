//! Windows Fact Extractor
//!
//! Converts Windows telemetry events to canonical Facts for playbook matching.
//! Maps Windows Event IDs and fields to the FactType enum variants.

use crate::hypothesis::canonical_fact::{
    AuthType, Fact, FactType, InjectionType, PersistenceType, RegistryOp, TamperAction,
};
use crate::hypothesis::{EvidencePtr, ScopeKey};
use chrono::{DateTime, TimeZone, Utc};
use edr_core::Event;

// ============================================================================
// XML FIELD EXTRACTION HELPERS (W1/W2/W4 Fix + Hardening)
// Windows Event Log XML format: <Data Name='FieldName'>value</Data>
// Handles: empty nodes, XML entities, multiple matches, whitespace
// ============================================================================

/// Unescape common XML entities in a value
/// Converts: &lt; -> <, &gt; -> >, &amp; -> &, &quot; -> ", &apos; -> '
/// Safe and deterministic - no external crates needed
fn unescape_xml_entities(s: &str) -> String {
    // Quick check: if no ampersand, nothing to unescape
    if !s.contains('&') {
        return s.to_string();
    }
    
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    
    while let Some(c) = chars.next() {
        if c == '&' {
            // Collect entity name until ';' or max 10 chars (avoid runaway)
            let mut entity = String::with_capacity(10);
            let mut found_semicolon = false;
            for _ in 0..10 {
                match chars.peek() {
                    Some(';') => {
                        chars.next();
                        found_semicolon = true;
                        break;
                    }
                    Some(&ch) if ch.is_ascii_alphanumeric() || ch == '#' => {
                        entity.push(ch);
                        chars.next();
                    }
                    _ => break,
                }
            }
            
            if found_semicolon {
                // Decode known entities
                match entity.as_str() {
                    "lt" => result.push('<'),
                    "gt" => result.push('>'),
                    "amp" => result.push('&'),
                    "quot" => result.push('"'),
                    "apos" => result.push('\''),
                    // Numeric entities: &#60; or &#x3c;
                    s if s.starts_with('#') => {
                        let num_str = &s[1..];
                        let code_point = if num_str.starts_with('x') || num_str.starts_with('X') {
                            u32::from_str_radix(&num_str[1..], 16).ok()
                        } else {
                            num_str.parse::<u32>().ok()
                        };
                        if let Some(cp) = code_point.and_then(char::from_u32) {
                            result.push(cp);
                        } else {
                            // Unknown numeric entity, preserve as-is
                            result.push('&');
                            result.push_str(&entity);
                            result.push(';');
                        }
                    }
                    _ => {
                        // Unknown entity, preserve as-is
                        result.push('&');
                        result.push_str(&entity);
                        result.push(';');
                    }
                }
            } else {
                // No semicolon found, not a valid entity - preserve ampersand and collected chars
                result.push('&');
                result.push_str(&entity);
            }
        } else {
            result.push(c);
        }
    }
    
    result
}

/// Extract a string field from Windows Event XML
/// Handles both formats:
/// - Direct field in event.fields (e.g., "NewProcessName")
/// - Embedded in windows.xml as <Data Name='NewProcessName'>value</Data>
fn extract_xml_string(event: &Event, field_name: &str) -> Option<String> {
    // First try direct field lookup (works if capture agent extracts fields)
    if let Some(val) = event.fields.get(field_name).and_then(|v| v.as_str()) {
        let trimmed = val.trim();
        if !trimmed.is_empty() && trimmed != "unknown" {
            return Some(unescape_xml_entities(trimmed));
        }
    }
    
    // Also try common variations
    let variations = [
        field_name.to_string(),
        field_name.to_lowercase(),
        format!("windows.{}", field_name),
    ];
    
    for var in &variations {
        if let Some(val) = event.fields.get(var).and_then(|v| v.as_str()) {
            let trimmed = val.trim();
            if !trimmed.is_empty() && trimmed != "unknown" {
                return Some(unescape_xml_entities(trimmed));
            }
        }
    }
    
    // Fallback: parse from windows.xml
    let xml = event.fields.get("windows.xml")?.as_str()?;
    parse_xml_data_field(xml, field_name)
}

/// Extract a u32 field from Windows Event XML
fn extract_xml_u32(event: &Event, field_name: &str) -> Option<u32> {
    // First try direct field lookup
    if let Some(val) = event.fields.get(field_name).and_then(|v| v.as_u64()) {
        return Some(val as u32);
    }
    
    // Try as string
    if let Some(val) = event.fields.get(field_name).and_then(|v| v.as_str()) {
        if let Ok(n) = val.trim().parse::<u32>() {
            return Some(n);
        }
    }
    
    // Fallback: parse from windows.xml
    let xml = event.fields.get("windows.xml")?.as_str()?;
    parse_xml_data_field(xml, field_name)?.parse().ok()
}

/// Parse a <Data Name='field_name'>value</Data> from Windows Event XML
/// Handles: empty nodes, self-closing tags, multiple matches (returns first non-empty)
/// Applies XML entity unescaping to the result
fn parse_xml_data_field(xml: &str, field_name: &str) -> Option<String> {
    let field_lower = field_name.to_lowercase();
    let xml_lower = xml.to_lowercase();
    
    // Build patterns for case-insensitive matching
    // Pattern variants: single quotes, double quotes
    let patterns = [
        format!("<data name='{}'>", field_lower),
        format!("<data name=\"{}\">", field_lower),
    ];
    
    // Also check for self-closing empty tags: <Data Name="X" /> or <Data Name="X"/>
    let empty_patterns = [
        format!("<data name='{}' />", field_lower),
        format!("<data name='{}'/>" , field_lower),
        format!("<data name=\"{}\" />", field_lower),
        format!("<data name=\"{}\"/>", field_lower),
    ];
    
    // Check if any self-closing empty pattern exists (return None early)
    for empty_pat in &empty_patterns {
        if xml_lower.contains(empty_pat) {
            // Found empty self-closing tag - this field is explicitly empty
            // Continue searching for non-empty matches
        }
    }
    
    // Track all matches, return first non-empty
    let mut first_value: Option<String> = None;
    
    for pattern in &patterns {
        let mut search_start = 0;
        while let Some(rel_idx) = xml_lower[search_start..].find(pattern) {
            let start_idx = search_start + rel_idx;
            let value_start = start_idx + pattern.len();
            
            // Find closing </Data> tag (case insensitive)
            if let Some(end_offset) = xml_lower[value_start..].find("</data>") {
                // Extract value from original XML to preserve case
                let raw_value = &xml[value_start..value_start + end_offset];
                let trimmed = raw_value.trim();
                
                if !trimmed.is_empty() {
                    // Found non-empty value - unescape and return
                    let unescaped = unescape_xml_entities(trimmed);
                    if !unescaped.is_empty() {
                        return Some(unescaped);
                    }
                }
                
                // Continue searching after this match
                search_start = value_start + end_offset + 7; // len("</data>")
            } else {
                break; // No closing tag found, malformed XML
            }
        }
    }
    
    // No non-empty value found
    first_value
}

/// Parse Windows Security Event XML to extract the Message element (for PowerShell 4104)
/// Applies XML entity unescaping to the result
fn parse_xml_message(xml: &str) -> Option<String> {
    let xml_lower = xml.to_lowercase();
    
    // Try <Message>...</Message> tag (case insensitive)
    if let Some(start) = xml_lower.find("<message>") {
        let value_start = start + "<message>".len();
        if let Some(end) = xml_lower[value_start..].find("</message>") {
            let raw_value = &xml[value_start..value_start + end];
            let trimmed = raw_value.trim();
            if !trimmed.is_empty() {
                return Some(unescape_xml_entities(trimmed));
            }
        }
    }
    None
}

/// Extract EventID from Windows Event XML System section
/// Parses <EventID>N</EventID> from the <System> block
fn extract_event_id_from_xml(event: &Event) -> Option<u32> {
    // First try direct field lookup
    if let Some(val) = event.fields.get("windows.event_id") {
        if let Some(n) = val.as_u64() {
            return Some(n as u32);
        }
        if let Some(s) = val.as_str() {
            if let Ok(n) = s.parse::<u32>() {
                return Some(n);
            }
        }
    }
    
    // Fallback: parse from windows.xml System section
    let xml = event.fields.get("windows.xml")?.as_str()?;
    let xml_lower = xml.to_lowercase();
    
    // Find <eventid>N</eventid> in the System section
    if let Some(start) = xml_lower.find("<eventid>") {
        let value_start = start + "<eventid>".len();
        if let Some(end) = xml_lower[value_start..].find("</eventid>") {
            let raw_value = &xml[value_start..value_start + end];
            return raw_value.trim().parse().ok();
        }
    }
    
    None
}

/// Extract Channel from Windows Event XML System section
/// Parses <Channel>...</Channel> from the <System> block
fn extract_channel_from_xml(event: &Event) -> Option<String> {
    // First try direct field lookup
    if let Some(val) = event.fields.get("windows.channel").and_then(|v| v.as_str()) {
        if !val.trim().is_empty() {
            return Some(val.to_string());
        }
    }
    
    // Also check evidence_ptr.stream_id which often contains channel name
    if let Some(ptr) = &event.evidence_ptr {
        if !ptr.stream_id.is_empty() && ptr.stream_id != "unknown" {
            return Some(ptr.stream_id.clone());
        }
    }
    
    // Fallback: parse from windows.xml System section
    let xml = event.fields.get("windows.xml")?.as_str()?;
    let xml_lower = xml.to_lowercase();
    
    // Find <channel>...</channel> in the System section  
    if let Some(start) = xml_lower.find("<channel>") {
        let value_start = start + "<channel>".len();
        if let Some(end) = xml_lower[value_start..].find("</channel>") {
            let raw_value = &xml[value_start..value_start + end];
            let trimmed = raw_value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    
    None
}

/// RD-4 FIX: Self-process allowlist to prevent LocInt from flagging itself
/// Returns true if the process path/name belongs to LocInt's own processes
fn is_self_process(proc_path: &str) -> bool {
    let path_lower = proc_path.to_lowercase();
    let self_processes = [
        "locint.exe",
        "edr-server.exe",
        "edr-locald.exe",
        "capture_windows_rotating.exe",
        // Also match without extension (for path components)
        "locint",
        "edr-server",
        "edr-locald", 
        "capture_windows_rotating",
    ];
    self_processes.iter().any(|p| path_lower.ends_with(p) || path_lower.contains(&format!("\\{}", p)))
}

/// Extract canonical facts from a Windows event
///
/// This is the primary entry point for the fact extraction pipeline.
/// Maps Windows event tags/fields to canonical FactType variants.
pub fn extract_facts(event: &Event) -> Vec<Fact> {
    // RD-4 FIX: Skip events from our own processes to prevent self-flagging
    // Check common process path fields
    let exe_path = event.fields.get("exe")
        .or(event.fields.get("exe_path"))
        .or(event.fields.get("image"))
        .or(event.fields.get("Image"))
        .or(event.fields.get("process_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    
    if is_self_process(exe_path) {
        // This event is from one of our own processes - skip fact extraction
        // This prevents export operations, DB queries, etc. from generating signals
        return Vec::new();
    }
    
    // Also check parent process (for child process creation events)
    let parent_path = event.fields.get("parent_exe")
        .or(event.fields.get("ParentImage"))
        .or(event.fields.get("parent_image"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    
    if is_self_process(parent_path) {
        // Parent is one of our processes - skip (e.g., locint spawning child)
        return Vec::new();
    }

    let mut facts = Vec::new();
    let ts = timestamp_from_ms(event.ts_ms);
    let host_id = event.host.clone();

    // Build evidence pointer with timestamp
    let evidence = match &event.evidence_ptr {
        Some(ptr) => EvidencePtr::new(
            ptr.stream_id.clone(),
            format!("{}", ptr.segment_id),
            ptr.record_index as u64,
        )
        .with_timestamp(ts),
        None => EvidencePtr::new("unknown", "0", 0).with_timestamp(ts),
    };

    // === EVENT ID BASED ENRICHMENT ===
    // Raw events from capture agent have minimal tags. Enrich based on windows.event_id.
    let enriched_tags = enrich_tags_from_event_id(event);
    let all_tags: Vec<&str> = event
        .tags
        .iter()
        .map(|s| s.as_str())
        .chain(enriched_tags.iter().map(|s| s.as_str()))
        .collect();

    // Route by tags to appropriate extractors
    for tag in all_tags {
        match tag {
            // Process events
            "process" | "process_creation" => {
                if let Some(fact) = extract_process_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Network events
            "network" | "network_connection" => {
                if let Some(fact) = extract_network_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Logon events (4624, 4625)
            "logon" | "remote_logon" | "lateral_movement" => {
                if let Some(fact) = extract_auth_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Share access (5140)
            "network_access" | "share_access" => {
                if let Some(fact) = extract_share_access_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Log tampering (1102, 104)
            "log_cleared" | "log_tamper" => {
                if let Some(fact) = extract_log_tamper_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Audit policy changes (4719)
            "audit_policy" | "policy_change" => {
                if let Some(fact) = extract_audit_change_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Service installation (7045)
            "service_installed" | "service" => {
                if let Some(fact) = extract_service_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Scheduled task (4698, 4699)
            "task" | "scheduled_task" => {
                if let Some(fact) = extract_task_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Registry modification (4657, Sysmon 13)
            "registry" | "registry_mod" => {
                if let Some(fact) = extract_registry_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // WMI events (Sysmon 19, 20, 21)
            "wmi" | "wmi_persistence" => {
                if let Some(fact) = extract_wmi_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // LSASS access (Sysmon 10)
            "credential_access" | "lsass_access" => {
                if let Some(fact) = extract_lsass_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // === NEW: PowerShell Script Block (4103, 4104) ===
            "script_block" => {
                if let Some(fact) = extract_powershell_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // === NEW: File creation (Sysmon 11) ===
            "file_create" => {
                if let Some(fact) = extract_file_create_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // === NEW: File deletion (Sysmon 23, 26) ===
            "file_delete" => {
                if let Some(fact) = extract_file_delete_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // === NEW: DNS query (Sysmon 22) ===
            "dns_query" => {
                if let Some(fact) = extract_dns_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // === NEW: Image/Module load (Sysmon 6, 7) ===
            "image_load" | "driver_load" => {
                if let Some(fact) = extract_module_load_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // === NEW: Remote thread creation (Sysmon 8) ===
            "remote_thread" => {
                if let Some(fact) = extract_injection_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // === NEW: RDP sessions ===
            "rdp_session" | "rdp_connection" => {
                if let Some(fact) = extract_rdp_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // === NEW: Account management ===
            "account_created" | "account_enabled" | "group_member_added" => {
                if let Some(fact) = extract_account_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // === Enhanced: Shell commands for LOLBin detection ===
            "shell_command" => {
                if let Some(fact) = extract_shell_command_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // === Enhanced: Named pipe events (Sysmon 17/18) ===
            "pipe_event" => {
                if let Some(fact) = extract_pipe_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            _ => {}
        }
    }

    // === Process-based secondary enrichment ===
    // If we have an Exec fact with certain command patterns, also emit ShellCommand
    if let Some(exe) = event
        .fields
        .get("exe")
        .or_else(|| event.fields.get("NewProcessName"))
        .or_else(|| event.fields.get("Image"))
        .and_then(|v| v.as_str())
    {
        if is_lolbin(exe) {
            if let Some(cmdline) = event
                .fields
                .get("cmdline")
                .or_else(|| event.fields.get("CommandLine"))
                .and_then(|v| v.as_str())
            {
                if let Some(fact) = extract_lolbin_fact(event, &host_id, &evidence, exe, cmdline) {
                    facts.push(fact);
                }
            }
        }
    }

    facts
}

/// Convert millisecond timestamp to DateTime<Utc>
fn timestamp_from_ms(ts_ms: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(ts_ms)
        .single()
        .unwrap_or_else(Utc::now)
}

/// Enrich event tags based on Windows Event ID
/// This bridges the gap between raw capture (generic tags) and detection (specific tags)
/// W1-FIX: Now extracts event_id from XML when not available in fields
fn enrich_tags_from_event_id(event: &Event) -> Vec<String> {
    let mut tags = Vec::new();

    // Get event ID - use helper that parses from XML if needed
    let Some(eid) = extract_event_id_from_xml(event) else {
        return tags;
    };

    // Map Windows Security Event IDs to detection tags
    match eid {
        // === LOG TAMPERING / CLEARING ===
        1102 => tags.push("log_cleared".to_string()),
        104 => tags.push("log_cleared".to_string()),

        // === AUTHENTICATION EVENTS ===
        4624 => tags.push("logon".to_string()),
        4625 => {
            tags.push("logon".to_string());
            tags.push("logon_failed".to_string());
        }
        4648 => tags.push("logon".to_string()), // Explicit credentials
        4769 => tags.push("kerberos_ticket".to_string()), // Kerberos TGS request
        4771 => tags.push("kerberos_preauth_failed".to_string()), // Kerberos pre-auth failed

        // === SHARE ACCESS (LATERAL MOVEMENT) ===
        5140 => tags.push("share_access".to_string()),
        5145 => tags.push("share_access".to_string()),

        // === SERVICE EVENTS (PERSISTENCE) ===
        7045 => tags.push("service_installed".to_string()),
        4697 => tags.push("service_installed".to_string()), // Security log service install
        7036 => tags.push("service_state".to_string()),

        // === SCHEDULED TASK (PERSISTENCE) ===
        4698 => tags.push("scheduled_task".to_string()),
        4699 => tags.push("scheduled_task".to_string()),
        4700 => tags.push("scheduled_task".to_string()),
        4701 => tags.push("scheduled_task".to_string()),
        4702 => tags.push("scheduled_task".to_string()),

        // === PROCESS CREATION ===
        4688 => tags.push("process_creation".to_string()),

        // === REGISTRY MODIFICATION ===
        4657 => tags.push("registry_mod".to_string()),

        // === AUDIT POLICY CHANGE (DEFENSE EVASION) ===
        4719 => tags.push("audit_policy".to_string()),
        4713 => tags.push("policy_change".to_string()),

        // === ACCOUNT MANAGEMENT ===
        4720 => tags.push("account_created".to_string()),
        4722 => tags.push("account_enabled".to_string()),
        4724 => tags.push("password_reset".to_string()),
        4728 | 4732 | 4756 => tags.push("group_member_added".to_string()),

        // === SYSMON EVENTS ===
        1 if is_sysmon_channel(event) => tags.push("process_creation".to_string()),
        2 if is_sysmon_channel(event) => tags.push("file_time_changed".to_string()),
        3 if is_sysmon_channel(event) => tags.push("network_connection".to_string()),
        6 if is_sysmon_channel(event) => tags.push("driver_load".to_string()),
        7 if is_sysmon_channel(event) => tags.push("image_load".to_string()),
        8 if is_sysmon_channel(event) => tags.push("remote_thread".to_string()),
        10 if is_sysmon_channel(event) => tags.push("credential_access".to_string()),
        11 if is_sysmon_channel(event) => tags.push("file_create".to_string()),
        12 | 14 if is_sysmon_channel(event) => tags.push("registry_mod".to_string()),
        13 if is_sysmon_channel(event) => tags.push("registry_mod".to_string()),
        15 if is_sysmon_channel(event) => tags.push("file_stream".to_string()), // ADS
        17 | 18 if is_sysmon_channel(event) => tags.push("pipe_event".to_string()),
        19..=21 if is_sysmon_channel(event) => tags.push("wmi_persistence".to_string()),
        22 if is_sysmon_channel(event) => tags.push("dns_query".to_string()),
        23 | 26 if is_sysmon_channel(event) => tags.push("file_delete".to_string()),
        25 if is_sysmon_channel(event) => tags.push("process_tamper".to_string()),

        // === POWERSHELL OPERATIONAL ===
        4103 | 4104 if is_powershell_channel(event) => tags.push("script_block".to_string()),

        // === RDP / TERMINAL SERVICES ===
        21 | 22 | 25 if is_rdp_channel(event) => tags.push("rdp_session".to_string()),
        1149 if is_rdp_channel(event) => tags.push("rdp_connection".to_string()),

        _ => {}
    }

    tags
}

/// Check if event is from PowerShell Operational channel
/// W1-FIX: Now uses extract_channel_from_xml to parse from XML
fn is_powershell_channel(event: &Event) -> bool {
    extract_channel_from_xml(event)
        .map(|s| s.contains("PowerShell") && s.contains("Operational"))
        .unwrap_or(false)
}

/// Check if event is from RDP/Terminal Services channel
/// W1-FIX: Now uses extract_channel_from_xml to parse from XML
fn is_rdp_channel(event: &Event) -> bool {
    extract_channel_from_xml(event)
        .map(|s| s.contains("TerminalServices") || s.contains("RemoteDesktop"))
        .unwrap_or(false)
}

/// Check if event is from Sysmon channel
/// W1-FIX: Now uses extract_channel_from_xml to parse from XML or evidence_ptr.stream_id
fn is_sysmon_channel(event: &Event) -> bool {
    extract_channel_from_xml(event)
        .map(|s| s.contains("Sysmon"))
        .unwrap_or(false)
}

/// Build scope key from event
fn build_scope_key(event: &Event) -> ScopeKey {
    if let Some(proc_key) = &event.proc_key {
        ScopeKey::Process {
            key: proc_key.clone(),
        }
    } else if let Some(identity_key) = &event.identity_key {
        ScopeKey::User {
            key: identity_key.clone(),
        }
    } else {
        // Fall back to a pseudo-process key based on host
        ScopeKey::Process {
            key: format!("host:{}", event.host),
        }
    }
}

/// Extract process creation fact (4688, Sysmon 1)
/// W1 FIX: Now extracts fields from windows.xml when not available directly
fn extract_process_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    // Try multiple field names for exe path (Sysmon uses Image, Security 4688 uses NewProcessName)
    let exe_path = extract_xml_string(event, "Image")
        .or_else(|| extract_xml_string(event, "NewProcessName"))
        .or_else(|| extract_xml_string(event, "exe"))
        .unwrap_or_else(|| "unknown".to_string());

    // CommandLine extraction
    let cmdline = extract_xml_string(event, "CommandLine")
        .or_else(|| extract_xml_string(event, "cmdline"));

    // Hash extraction (Sysmon provides hashes)
    let hash = extract_xml_string(event, "Hashes")
        .or_else(|| extract_xml_string(event, "hash"));
    
    // User extraction for better scope key
    let user = extract_xml_string(event, "User")
        .or_else(|| extract_xml_string(event, "SubjectUserName"))
        .or_else(|| extract_xml_string(event, "TargetUserName"));
    
    // Build scope key - prefer process key if available, else use user
    let scope_key = if let Some(proc_key) = &event.proc_key {
        ScopeKey::Process { key: proc_key.clone() }
    } else if let Some(u) = &user {
        ScopeKey::User { key: u.clone() }
    } else {
        ScopeKey::Process { key: format!("host:{}", host_id) }
    };

    let fact = Fact::new(
        host_id,
        scope_key,
        FactType::Exec {
            exe_hash: hash,
            path: exe_path,
            signer: None,
            cmdline,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract network connection fact (Sysmon 3, 5156)
fn extract_network_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let dst_ip = extract_xml_string(event, "DestinationIp")
        .unwrap_or_else(|| "0.0.0.0".to_string());

    let dst_port = extract_xml_u32(event, "DestinationPort")
        .unwrap_or(0) as u16;

    let proto = extract_xml_string(event, "Protocol")
        .unwrap_or_else(|| "tcp".to_string());

    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::OutboundConnect {
            dst_ip,
            dst_port,
            proto,
            sock_id: event.file_key.clone(),
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract authentication fact (4624, 4625)
/// W4 FIX: Now extracts TargetUserName, LogonType, IpAddress from windows.xml
fn extract_auth_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    // Extract user - Security 4624 uses TargetUserName
    let user = extract_xml_string(event, "TargetUserName")
        .or_else(|| extract_xml_string(event, "user"))
        .or_else(|| extract_xml_string(event, "SubjectUserName"))
        .unwrap_or_else(|| "unknown".to_string());
    
    // Extract domain for full user identity
    let domain = extract_xml_string(event, "TargetDomainName")
        .or_else(|| extract_xml_string(event, "SubjectDomainName"));
    
    // Build qualified user name (DOMAIN\user)
    let qualified_user = if let Some(d) = &domain {
        if !d.is_empty() && d != "-" {
            format!("{}\\{}", d, user)
        } else {
            user.clone()
        }
    } else {
        user.clone()
    };

    // Extract LogonType - critical for distinguishing local vs remote
    let logon_type_str = extract_xml_string(event, "LogonType")
        .or_else(|| extract_xml_u32(event, "LogonType").map(|n| n.to_string()))
        .unwrap_or_else(|| "0".to_string());

    let auth_type = match logon_type_str.as_str() {
        "2" => AuthType::Interactive,
        "3" => AuthType::Network,
        "5" => AuthType::Service,
        "7" => AuthType::Unlock,
        "10" => AuthType::RemoteInteractive,
        "11" => AuthType::CachedInteractive,
        _ => AuthType::Other(logon_type_str.clone()),
    };

    // Source IP - important for remote logon detection
    let source_ip = extract_xml_string(event, "IpAddress")
        .or_else(|| extract_xml_string(event, "SourceNetworkAddress"))
        .or_else(|| extract_xml_string(event, "source_ip"))
        // Filter out local/empty IPs
        .filter(|ip| !ip.is_empty() && ip != "-" && ip != "127.0.0.1" && ip != "::1");

    // Check if success (4624) or failure (4625)
    let event_id = event.fields.get("windows.event_id")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    let success = event_id != Some(4625) 
        && !event.tags.contains(&"failed".to_string()) 
        && !event.tags.contains(&"4625".to_string());
    
    // Build scope key using qualified user
    let scope_key = ScopeKey::User { key: qualified_user.clone() };

    let mut fact = Fact::new(
        host_id,
        scope_key,
        FactType::AuthEvent {
            auth_type,
            user: qualified_user,
            source: source_ip,
            success,
        },
        vec![evidence.clone()],
    );
    
    // Add logon type description to extra fields for UI
    let logon_desc = match logon_type_str.as_str() {
        "2" => "Interactive (local)",
        "3" => "Network",
        "5" => "Service",
        "7" => "Unlock",
        "10" => "RemoteInteractive (RDP)",
        "11" => "CachedInteractive",
        _ => "Other",
    };
    fact.extra_fields.insert("logon_type_description".to_string(), serde_json::json!(logon_desc));

    Some(fact)
}

/// Extract share access fact (5140)
fn extract_share_access_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let share_name = event
        .fields
        .get("ShareName")
        .or_else(|| event.fields.get("share"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // If it's an admin share (C$, ADMIN$, IPC$), treat as AuthEvent for lateral movement
    let is_admin_share = share_name.ends_with("$");

    if is_admin_share {
        let user = event
            .fields
            .get("SubjectUserName")
            .or_else(|| event.fields.get("user"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let source_ip = event
            .fields
            .get("IpAddress")
            .or_else(|| event.fields.get("source_ip"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let fact = Fact::new(
            host_id,
            ScopeKey::User { key: user.clone() },
            FactType::AuthEvent {
                auth_type: AuthType::Network,
                user,
                source: source_ip,
                success: true,
            },
            vec![evidence.clone()],
        );

        return Some(fact);
    }

    None
}

/// Extract log tampering fact (1102, 104)
fn extract_log_tamper_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let log_type = event
        .fields
        .get("Channel")
        .or_else(|| event.fields.get("log_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("Security")
        .to_string();

    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::LogTamper {
            log_type,
            action: TamperAction::Clear,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract audit policy change fact (4719)
fn extract_audit_change_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let method = event
        .fields
        .get("SubcategoryGuid")
        .or_else(|| event.fields.get("change_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("policy_change")
        .to_string();

    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::SecurityToolDisable {
            tool_name: "Windows Audit Policy".to_string(),
            method,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract service installation fact (7045)
fn extract_service_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let service_name = event
        .fields
        .get("ServiceName")
        .or_else(|| event.fields.get("service_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let image_path = event
        .fields
        .get("ImagePath")
        .or_else(|| event.fields.get("image_path"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let fact = Fact::new(
        host_id,
        ScopeKey::Process {
            key: format!("host:{}", host_id),
        },
        FactType::PersistArtifact {
            artifact_type: PersistenceType::Service,
            path_or_key: format!("{}:{}", service_name, image_path),
            enable_action: true,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract scheduled task fact (4698)
fn extract_task_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let task_name = event
        .fields
        .get("TaskName")
        .or_else(|| event.fields.get("task_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::PersistArtifact {
            artifact_type: PersistenceType::ScheduledTask,
            path_or_key: task_name,
            enable_action: true,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract registry modification fact (4657, Sysmon 13)
fn extract_registry_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let key = extract_xml_string(event, "TargetObject")
        .or_else(|| extract_xml_string(event, "ObjectName"))
        .unwrap_or_else(|| "unknown".to_string());

    let value_name = extract_xml_string(event, "Details");

    let operation = if event.tags.contains(&"deleted".to_string()) {
        RegistryOp::DeleteValue
    } else if event.tags.contains(&"created".to_string()) {
        RegistryOp::Create
    } else {
        RegistryOp::SetValue
    };

    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::RegistryMod {
            key,
            value_name,
            operation,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract WMI persistence fact (Sysmon 19, 20, 21)
fn extract_wmi_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    // WMI persistence creates filter+consumer+binding
    let wmi_type = if event.tags.contains(&"filter".to_string()) {
        "WmiEventFilter"
    } else if event.tags.contains(&"consumer".to_string()) {
        "WmiEventConsumer"
    } else {
        "WmiFilterToConsumerBinding"
    };

    let name = event
        .fields
        .get("Name")
        .or_else(|| event.fields.get("wmi_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let fact = Fact::new(
        host_id,
        ScopeKey::Process {
            key: format!("host:{}", host_id),
        },
        FactType::PersistArtifact {
            artifact_type: PersistenceType::Other(wmi_type.to_string()),
            path_or_key: name,
            enable_action: true,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract LSASS access fact (Sysmon 10)
/// Sysmon Event ID 10 is ProcessAccess - semantic fact type: ProcessAccess
fn extract_lsass_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    // Sysmon 10 TargetImage contains "lsass.exe"
    let target_image = event
        .fields
        .get("TargetImage")
        .or_else(|| event.fields.get("target"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if !target_image.to_lowercase().contains("lsass") {
        return None;
    }

    // Extract source process info
    let source_proc_key = event
        .fields
        .get("SourceProcessGuid")
        .or_else(|| event.fields.get("SourceProcessId"))
        .and_then(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        })
        .unwrap_or_else(|| "unknown".to_string());

    let target_proc_key = event
        .fields
        .get("TargetProcessGuid")
        .or_else(|| event.fields.get("TargetProcessId"))
        .and_then(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        })
        .unwrap_or_else(|| "lsass".to_string());

    // GrantedAccess is typically a hex value like "0x1410"
    let granted_access = event
        .fields
        .get("GrantedAccess")
        .or_else(|| event.fields.get("granted_access"))
        .and_then(|v| v.as_str())
        .unwrap_or("0x0")
        .to_string();

    // CallTrace helps identify the source of the access
    let call_trace = event
        .fields
        .get("CallTrace")
        .or_else(|| event.fields.get("call_trace"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Use ProcessAccess fact type - semantically correct for Sysmon Event 10
    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::ProcessAccess {
            source_proc_key,
            target_proc_key,
            target_image: target_image.to_string(),
            granted_access,
            call_trace,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

// ============================================================================
// NEW EXTRACTION FUNCTIONS (Agent C additions)
// ============================================================================

/// Extract PowerShell script block fact (4103, 4104)
/// W2 FIX: Now extracts ScriptBlockText from windows.xml when not available directly
fn extract_powershell_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    // 4104 has ScriptBlockText in EventData, sometimes in Message element
    let script_content = extract_xml_string(event, "ScriptBlockText")
        .or_else(|| extract_xml_string(event, "Payload"))
        .or_else(|| {
            // PowerShell 4104 sometimes embeds script in Message
            event.fields.get("windows.xml")
                .and_then(|v| v.as_str())
                .and_then(|xml| parse_xml_message(xml))
                .and_then(|msg| {
                    // Extract script content after "ScriptBlockText:" prefix if present
                    if let Some(idx) = msg.find("ScriptBlockText:") {
                        let start = idx + "ScriptBlockText:".len();
                        let content = msg[start..].trim();
                        if !content.is_empty() {
                            return Some(content.to_string());
                        }
                    }
                    // Otherwise use full message as script content
                    if !msg.is_empty() {
                        Some(msg)
                    } else {
                        None
                    }
                })
        });

    // Script path - where the script file is located (if from file)
    let script_path = extract_xml_string(event, "Path")
        .or_else(|| extract_xml_string(event, "ScriptName"));

    // Compute simple hash of script content for tracking
    let content_hash = script_content.as_ref().map(|c| {
        format!("{:016x}", {
            let mut hash: u64 = 0;
            for byte in c.bytes() {
                hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
            }
            hash
        })
    });
    
    // Store script preview (first 400 chars) in the fact for UI display
    let script_preview = script_content.as_ref().map(|c| {
        if c.len() > 400 {
            format!("{}...", &c[..400])
        } else {
            c.clone()
        }
    });

    let mut fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::ScriptExec {
            interpreter: "powershell".to_string(),
            script_path,
            script_content_hash: content_hash,
        },
        vec![evidence.clone()],
    );
    
    // Store script preview in extra_fields for UI
    if let Some(preview) = script_preview {
        fact.extra_fields.insert("script_preview".to_string(), serde_json::json!(preview));
    }

    Some(fact)
}

/// Extract file creation fact (Sysmon 11)
fn extract_file_create_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let path = extract_xml_string(event, "TargetFilename")
        .unwrap_or_else(|| "unknown".to_string());

    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::CreatePath { path, inode: None },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract file deletion fact (Sysmon 23, 26)
fn extract_file_delete_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let path = extract_xml_string(event, "TargetFilename")
        .unwrap_or_else(|| "unknown".to_string());

    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::DeletePath { path, inode: None },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract DNS query fact (Sysmon 22)
fn extract_dns_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let query = extract_xml_string(event, "QueryName")
        .unwrap_or_else(|| "unknown".to_string());

    let responses = extract_xml_string(event, "QueryResults")
        .map(|s| {
            s.split(';')
                .map(|r| r.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::DnsResolve { query, responses },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract module/DLL load fact (Sysmon 6, 7)
fn extract_module_load_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let path = extract_xml_string(event, "ImageLoaded")
        .unwrap_or_else(|| "unknown".to_string());

    let hash = extract_xml_string(event, "Hashes");

    let signer = extract_xml_string(event, "Signature");

    // Event ID 6 = driver (kernel), Event ID 7 = image (user)
    let is_kernel = event
        .fields
        .get("windows.event_id")
        .and_then(|v| v.as_u64())
        .map(|eid| eid == 6)
        .unwrap_or(false);

    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::ModuleLoad {
            path,
            hash,
            signer,
            is_kernel,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract injection fact (Sysmon 8 - CreateRemoteThread)
fn extract_injection_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let source_proc = event
        .fields
        .get("SourceImage")
        .or_else(|| event.fields.get("source_image"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let target_proc = event
        .fields
        .get("TargetImage")
        .or_else(|| event.fields.get("target_image"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let source_key = event
        .fields
        .get("SourceProcessGuid")
        .or_else(|| event.fields.get("SourceProcessId"))
        .and_then(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        })
        .unwrap_or_else(|| source_proc.clone());

    let target_key = event
        .fields
        .get("TargetProcessGuid")
        .or_else(|| event.fields.get("TargetProcessId"))
        .and_then(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        })
        .unwrap_or_else(|| target_proc.clone());

    // Create Injection fact
    let fact = Fact::new(
        host_id,
        ScopeKey::Process {
            key: source_key.clone(),
        },
        FactType::Injection {
            source_proc_key: source_key,
            target_proc_key: target_key,
            injection_type: InjectionType::RemoteThread,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract RDP session fact (Terminal Services events)
fn extract_rdp_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let user = event
        .fields
        .get("User")
        .or_else(|| event.fields.get("TargetUserName"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let source_ip = event
        .fields
        .get("Address")
        .or_else(|| event.fields.get("SourceAddress"))
        .or_else(|| event.fields.get("IpAddress"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let fact = Fact::new(
        host_id,
        ScopeKey::User { key: user.clone() },
        FactType::AuthEvent {
            auth_type: AuthType::RemoteInteractive,
            user,
            source: source_ip,
            success: true,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract account management fact (4720, 4722, 4728, etc.)
fn extract_account_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let target_user = event
        .fields
        .get("TargetUserName")
        .or_else(|| event.fields.get("MemberName"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let subject_user = event
        .fields
        .get("SubjectUserName")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Account creation is tracked as a special auth event
    let fact = Fact::new(
        host_id,
        ScopeKey::User {
            key: target_user.clone(),
        },
        FactType::AuthEvent {
            auth_type: AuthType::Other("account_management".to_string()),
            user: target_user,
            source: subject_user,
            success: true,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

// ============================================================================
// ADDITIONAL EXTRACTION FUNCTIONS FOR DETECTION ENGINEER PACK
// ============================================================================

/// Check if executable is a LOLBin (Living off the Land Binary)
fn is_lolbin(exe_path: &str) -> bool {
    let lower = exe_path.to_lowercase();
    let lolbins = [
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "certutil.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "wmic.exe",
        "wscript.exe",
        "cscript.exe",
        "bitsadmin.exe",
        "schtasks.exe",
        "sc.exe",
        "net.exe",
        "net1.exe",
        "nltest.exe",
        "reg.exe",
        "whoami.exe",
        "hostname.exe",
        "systeminfo.exe",
        "ipconfig.exe",
        "netstat.exe",
        "tasklist.exe",
    ];
    lolbins.iter().any(|l| lower.ends_with(l))
}

/// Extract shell command fact for LOLBin detection
fn extract_shell_command_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
) -> Option<Fact> {
    let shell = event
        .fields
        .get("exe")
        .or_else(|| event.fields.get("NewProcessName"))
        .and_then(|v| v.as_str())
        .unwrap_or("cmd.exe")
        .to_string();

    let command = event
        .fields
        .get("cmdline")
        .or_else(|| event.fields.get("CommandLine"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Detect encoded commands (PowerShell -enc, etc.)
    let is_encoded = command.to_lowercase().contains("-enc")
        || command.to_lowercase().contains("-encodedcommand")
        || command.contains("base64");

    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::ShellCommand {
            shell,
            command,
            is_encoded,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract named pipe fact (Sysmon 17/18 - pipe created/connected)
fn extract_pipe_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let pipe_name = event
        .fields
        .get("PipeName")
        .or_else(|| event.fields.get("pipe_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // Named pipes are used for IPC - suspicious ones indicate lateral movement or C2
    // Track as outbound connect to capture the communication pattern
    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::OutboundConnect {
            dst_ip: "pipe".to_string(),
            dst_port: 0,
            proto: pipe_name,
            sock_id: None,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract LOLBin-specific fact with suspicious patterns
fn extract_lolbin_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
    exe_path: &str,
    cmdline: &str,
) -> Option<Fact> {
    let lower_exe = exe_path.to_lowercase();
    let lower_cmd = cmdline.to_lowercase();

    // Only generate additional fact for suspicious patterns
    let is_suspicious = match lower_exe.as_str() {
        e if e.contains("powershell") || e.contains("pwsh") => {
            lower_cmd.contains("-enc")
                || lower_cmd.contains("downloadstring")
                || lower_cmd.contains("iex")
                || lower_cmd.contains("-ep bypass")
                || lower_cmd.contains("-w hidden")
        }
        e if e.contains("certutil") => {
            lower_cmd.contains("-urlcache")
                || lower_cmd.contains("-decode")
                || lower_cmd.contains("-encode")
        }
        e if e.contains("mshta") => {
            lower_cmd.contains("vbscript:")
                || lower_cmd.contains("javascript:")
                || lower_cmd.contains("http")
        }
        e if e.contains("rundll32") => {
            lower_cmd.contains("javascript:")
                || lower_cmd.contains("comsvcs")
                || lower_cmd.contains("url.dll")
        }
        e if e.contains("regsvr32") => {
            lower_cmd.contains("/i:http") || lower_cmd.contains("scrobj")
        }
        e if e.contains("wmic") => {
            lower_cmd.contains("process call create")
                || lower_cmd.contains("/format:")
                || lower_cmd.contains("shadowcopy delete")
        }
        e if e.contains("schtasks") => {
            lower_cmd.contains("/create")
                && (lower_cmd.contains("/ru system") || lower_cmd.contains("powershell"))
        }
        e if e.contains("sc.exe") || (e.ends_with("\\sc.exe")) => {
            (lower_cmd.contains("create") && lower_cmd.contains("binpath"))
                || (lower_cmd.contains("stop")
                    && (lower_cmd.contains("windefend")
                        || lower_cmd.contains("eventlog")
                        || lower_cmd.contains("sense")))
        }
        _ => false,
    };

    if !is_suspicious {
        return None;
    }

    // Create ShellCommand fact for suspicious LOLBin usage
    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::ShellCommand {
            shell: exe_path.to_string(),
            command: cmdline.to_string(),
            is_encoded: lower_cmd.contains("-enc") || lower_cmd.contains("base64"),
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

// =========================================================================
// REGRESSION GUARD: Sysmon XML field extraction tests
// Ensures extract_*_fact functions use extract_xml_string (not event.fields.get)
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_test_event(tags: Vec<&str>, fields: Vec<(&str, &str)>) -> Event {
        let mut field_map = BTreeMap::new();
        for (k, v) in fields {
            field_map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }

        Event {
            ts_ms: 1700000000000,
            host: "test-host".to_string(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            proc_key: Some("test_proc".to_string()),
            file_key: None,
            identity_key: Some("testuser".to_string()),
            evidence_ptr: None,
            fields: field_map,
        }
    }

    #[test]
    fn test_extract_process_fact() {
        let event = make_test_event(
            vec!["process"],
            vec![
                ("exe", "C:\\Windows\\System32\\cmd.exe"),
                ("cmdline", "cmd /c whoami"),
            ],
        );

        let facts = extract_facts(&event);
        assert_eq!(facts.len(), 1);

        match &facts[0].fact_type {
            FactType::Exec { path, cmdline, .. } => {
                assert!(path.contains("cmd.exe"));
                assert!(cmdline.as_ref().unwrap().contains("whoami"));
            }
            _ => panic!("Expected Exec fact"),
        }
    }

    #[test]
    fn test_extract_auth_fact() {
        let event = make_test_event(
            vec!["logon"],
            vec![
                ("TargetUserName", "admin"),
                ("LogonType", "10"),
                ("SourceNetworkAddress", "192.168.1.100"),
            ],
        );

        let facts = extract_facts(&event);
        assert_eq!(facts.len(), 1);

        match &facts[0].fact_type {
            FactType::AuthEvent {
                auth_type,
                user,
                source,
                success,
            } => {
                assert!(matches!(auth_type, AuthType::RemoteInteractive));
                assert_eq!(user, "admin");
                assert!(source.as_ref().unwrap().contains("192.168.1.100"));
                assert!(*success);
            }
            _ => panic!("Expected AuthEvent fact"),
        }
    }

    #[test]
    fn test_extract_log_tamper_fact() {
        let event = make_test_event(vec!["log_cleared"], vec![("Channel", "Security")]);

        let facts = extract_facts(&event);
        assert_eq!(facts.len(), 1);

        match &facts[0].fact_type {
            FactType::LogTamper { log_type, action } => {
                assert_eq!(log_type, "Security");
                assert!(matches!(action, TamperAction::Clear));
            }
            _ => panic!("Expected LogTamper fact"),
        }
    }

    // =========================================================================
    // XML Parsing Hardening Tests (Caveat 1 Fix)
    // =========================================================================

    #[test]
    fn test_unescape_xml_entities_basic() {
        // Test common entities
        assert_eq!(unescape_xml_entities("hello &lt;world&gt;"), "hello <world>");
        assert_eq!(unescape_xml_entities("a &amp; b"), "a & b");
        assert_eq!(unescape_xml_entities("&quot;quoted&quot;"), "\"quoted\"");
        assert_eq!(unescape_xml_entities("it&apos;s fine"), "it's fine");
    }
    
    #[test]
    fn test_unescape_xml_entities_numeric() {
        // Numeric entities
        assert_eq!(unescape_xml_entities("&#60;tag&#62;"), "<tag>");
        assert_eq!(unescape_xml_entities("&#x3c;hex&#x3e;"), "<hex>");
    }
    
    #[test]
    fn test_unescape_xml_entities_passthrough() {
        // No entities - passthrough unchanged
        assert_eq!(unescape_xml_entities("normal text"), "normal text");
        // Unknown entities preserved
        assert_eq!(unescape_xml_entities("&unknown;"), "&unknown;");
        // Broken ampersand preserved
        assert_eq!(unescape_xml_entities("a & b"), "a & b");
    }
    
    #[test]
    fn test_unescape_xml_entities_cmdline() {
        // Real-world cmdline with entities
        let input = "powershell.exe -Command &quot;if ($x -lt 10) { Write-Host &apos;yes&apos; }&quot;";
        let expected = "powershell.exe -Command \"if ($x -lt 10) { Write-Host 'yes' }\"";
        assert_eq!(unescape_xml_entities(input), expected);
    }
    
    #[test]
    fn test_parse_xml_data_field_basic() {
        let xml = r#"<EventData><Data Name='CommandLine'>cmd.exe /c dir</Data></EventData>"#;
        let result = parse_xml_data_field(xml, "CommandLine");
        assert_eq!(result, Some("cmd.exe /c dir".to_string()));
    }
    
    #[test]
    fn test_parse_xml_data_field_with_entities() {
        let xml = r#"<EventData><Data Name='CommandLine'>powershell -c &quot;Get-Process&quot;</Data></EventData>"#;
        let result = parse_xml_data_field(xml, "CommandLine");
        assert_eq!(result, Some("powershell -c \"Get-Process\"".to_string()));
    }
    
    #[test]
    fn test_parse_xml_data_field_empty_node() {
        // Empty value between tags
        let xml = r#"<EventData><Data Name='ParentImage'></Data></EventData>"#;
        let result = parse_xml_data_field(xml, "ParentImage");
        assert_eq!(result, None);
    }
    
    #[test]
    fn test_parse_xml_data_field_self_closing() {
        // Self-closing tag (no value)
        let xml = r#"<EventData><Data Name='Hashes' /></EventData>"#;
        let result = parse_xml_data_field(xml, "Hashes");
        assert_eq!(result, None);
    }
    
    #[test]
    fn test_parse_xml_data_field_multiple_same_name() {
        // Multiple Data nodes with same name - should return first non-empty
        let xml = r#"<EventData><Data Name='User'></Data><Data Name='User'>SYSTEM</Data></EventData>"#;
        let result = parse_xml_data_field(xml, "User");
        assert_eq!(result, Some("SYSTEM".to_string()));
    }
    
    #[test]
    fn test_parse_xml_data_field_case_insensitive() {
        let xml = r#"<EventData><Data Name='COMMANDLINE'>test</Data></EventData>"#;
        let result = parse_xml_data_field(xml, "CommandLine");
        assert_eq!(result, Some("test".to_string()));
    }
    
    #[test]
    fn test_parse_xml_data_field_whitespace() {
        // Whitespace around value should be trimmed
        let xml = r#"<EventData><Data Name='Image'>  C:\Windows\cmd.exe  </Data></EventData>"#;
        let result = parse_xml_data_field(xml, "Image");
        assert_eq!(result, Some("C:\\Windows\\cmd.exe".to_string()));
    }
    
    #[test]
    fn test_parse_xml_data_field_double_quotes() {
        let xml = r#"<EventData><Data Name="Image">notepad.exe</Data></EventData>"#;
        let result = parse_xml_data_field(xml, "Image");
        assert_eq!(result, Some("notepad.exe".to_string()));
    }

    // =========================================================================
    // REGRESSION GUARD: Sysmon v1 XML extraction (January 2026 fix)
    // These tests ensure Sysmon facts extract fields from windows.xml via
    // extract_xml_string(), NOT from event.fields.get() which is unpopulated.
    // =========================================================================

    fn make_sysmon_event(event_id: u64, xml_content: &str) -> Event {
        let mut fields = BTreeMap::new();
        fields.insert("windows.channel".to_string(), serde_json::json!("Microsoft-Windows-Sysmon/Operational"));
        fields.insert("windows.event_id".to_string(), serde_json::json!(event_id));
        fields.insert("windows.xml".to_string(), serde_json::json!(xml_content));

        Event {
            ts_ms: 1700000000000,
            host: "test-host".to_string(),
            tags: vec!["windows".to_string()],
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptr: None,
            fields,
        }
    }

    /// Create a realistic Sysmon event as it comes from wevt_reader
    /// CRITICAL: wevt_reader only populates windows.xml - NOT windows.event_id or windows.channel!
    /// The event_id and channel must be extracted from the XML System section.
    fn make_realistic_sysmon_event(xml_with_system: &str) -> Event {
        let mut fields = BTreeMap::new();
        // Only windows.xml is populated - NOT windows.event_id or windows.channel!
        fields.insert("windows.xml".to_string(), serde_json::json!(xml_with_system));

        Event {
            ts_ms: 1700000000000,
            host: "test-host".to_string(),
            tags: vec!["windows".to_string()],
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptr: Some(edr_core::EvidencePtr {
                stream_id: "Microsoft-Windows-Sysmon/Operational".to_string(),
                segment_id: 0,
                record_index: 1,
            }),
            fields,
        }
    }

    #[test]
    fn test_sysmon_1_exec_extracts_from_xml_only() {
        // REGRESSION: Sysmon Event ID 1 (ProcessCreate) must work with ONLY windows.xml populated
        // This simulates real wevt_reader output where event_id/channel come from XML System section
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System>
                <EventID>1</EventID>
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            </System>
            <EventData>
                <Data Name='Image'>C:\Windows\System32\cmd.exe</Data>
                <Data Name='CommandLine'>cmd /c whoami</Data>
                <Data Name='User'>DESKTOP\TestUser</Data>
                <Data Name='Hashes'>SHA256=ABC123</Data>
            </EventData>
        </Event>"#;
        
        let event = make_realistic_sysmon_event(xml);
        let facts = extract_facts(&event);
        
        assert!(!facts.is_empty(), "Should extract Exec fact from Sysmon 1 (XML-only)");
        let exec_fact = facts.iter().find(|f| matches!(f.fact_type, FactType::Exec { .. }));
        assert!(exec_fact.is_some(), "Must produce Exec fact for Sysmon Event ID 1");
        
        match &exec_fact.unwrap().fact_type {
            FactType::Exec { path, cmdline, exe_hash, .. } => {
                assert_eq!(path, "C:\\Windows\\System32\\cmd.exe", "Path must be extracted from XML Image");
                assert_eq!(cmdline.as_deref(), Some("cmd /c whoami"), "CommandLine must be extracted from XML");
                assert!(exe_hash.as_ref().map(|h| h.contains("ABC123")).unwrap_or(false), "Hash must be extracted");
            }
            _ => panic!("Expected Exec fact"),
        }
    }

    #[test]
    fn test_sysmon_11_file_create_extracts_from_xml() {
        // Sysmon Event ID 11 (FileCreate) - path must come from windows.xml
        let xml = r#"<Event><EventData>
            <Data Name='TargetFilename'>C:\Temp\malware.exe</Data>
            <Data Name='Image'>C:\Windows\explorer.exe</Data>
        </EventData></Event>"#;
        
        let event = make_sysmon_event(11, xml);
        let facts = extract_facts(&event);
        
        assert!(!facts.is_empty(), "Should extract FileCreate fact");
        match &facts[0].fact_type {
            FactType::CreatePath { path, .. } => {
                assert_eq!(path, "C:\\Temp\\malware.exe", "Path must be extracted from XML TargetFilename");
                assert_ne!(path, "unknown", "Path must NOT be 'unknown' - XML extraction failed");
            }
            _ => panic!("Expected CreatePath fact for Sysmon 11"),
        }
    }

    #[test]
    fn test_sysmon_3_network_extracts_from_xml() {
        // Sysmon Event ID 3 (NetworkConnect) - dst_ip/port must come from windows.xml
        let xml = r#"<Event><EventData>
            <Data Name='DestinationIp'>192.168.1.100</Data>
            <Data Name='DestinationPort'>443</Data>
            <Data Name='Protocol'>tcp</Data>
        </EventData></Event>"#;
        
        let event = make_sysmon_event(3, xml);
        let facts = extract_facts(&event);
        
        assert!(!facts.is_empty(), "Should extract NetworkConnect fact");
        match &facts[0].fact_type {
            FactType::OutboundConnect { dst_ip, dst_port, proto, .. } => {
                assert_eq!(dst_ip, "192.168.1.100", "dst_ip must be extracted from XML");
                assert_eq!(*dst_port, 443, "dst_port must be extracted from XML");
                assert_eq!(proto, "tcp", "proto must be extracted from XML");
            }
            _ => panic!("Expected OutboundConnect fact for Sysmon 3"),
        }
    }

    #[test]
    fn test_sysmon_12_registry_extracts_from_xml() {
        // Sysmon Event ID 12/13/14 (Registry) - key must come from windows.xml
        let xml = r#"<Event><EventData>
            <Data Name='TargetObject'>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Malware</Data>
            <Data Name='Details'>C:\evil.exe</Data>
        </EventData></Event>"#;
        
        let event = make_sysmon_event(12, xml);
        let facts = extract_facts(&event);
        
        assert!(!facts.is_empty(), "Should extract RegistryMod fact");
        match &facts[0].fact_type {
            FactType::RegistryMod { key, .. } => {
                assert!(key.contains("HKLM"), "Key must be extracted from XML TargetObject");
                assert!(key.contains("Run"), "Key must contain full registry path");
                assert_ne!(key, "unknown", "Key must NOT be 'unknown' - XML extraction failed");
            }
            _ => panic!("Expected RegistryMod fact for Sysmon 12"),
        }
    }

    #[test]
    fn test_sysmon_22_dns_extracts_from_xml() {
        // Sysmon Event ID 22 (DnsQuery) - query must come from windows.xml
        let xml = r#"<Event><EventData>
            <Data Name='QueryName'>evil-c2.example.com</Data>
            <Data Name='QueryResults'>192.168.1.1;</Data>
        </EventData></Event>"#;
        
        let event = make_sysmon_event(22, xml);
        let facts = extract_facts(&event);
        
        assert!(!facts.is_empty(), "Should extract DnsResolve fact");
        match &facts[0].fact_type {
            FactType::DnsResolve { query, .. } => {
                assert_eq!(query, "evil-c2.example.com", "Query must be extracted from XML");
                assert_ne!(query, "unknown", "Query must NOT be 'unknown' - XML extraction failed");
            }
            _ => panic!("Expected DnsResolve fact for Sysmon 22"),
        }
    }
}

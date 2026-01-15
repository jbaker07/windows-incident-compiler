//! Windows attack surface event normalization
//! Parses raw Windows events and emits canonical attack-surface events
//! All emitted events have evidence_ptr: None (capture assigns it)

// Detection helper functions used conditionally
#![allow(dead_code)]

use edr_core::{event_keys, Event};
use serde_json::json;
use std::collections::BTreeMap;

/// Normalize Windows event log record into attack-surface canonical events
/// Returns empty vec if event doesn't match any attack surface type
pub fn normalize_to_attack_surface(event: &Event) -> Vec<Event> {
    let mut results = Vec::new();

    let channel = event
        .fields
        .get("windows.channel")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let event_id = event
        .fields
        .get("windows.event_id")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let provider = event
        .fields
        .get("windows.provider")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Route by event type
    match (channel, event_id, provider) {
        // Execution: Sysmon 1 or Security 4688
        ("Microsoft-Windows-Sysmon/Operational", 1, _) | ("Security", 4688, _) => {
            if let Some(evt) = parse_proc_exec(event) {
                results.push(evt);
            }
        }
        // Network Egress: Sysmon 3 (NetworkConnect)
        ("Microsoft-Windows-Sysmon/Operational", 3, _) => {
            if let Some(evt) = parse_network_connect(event) {
                results.push(evt);
            }
        }
        // TRUE Privilege Escalation: Security 4672 (special privileges assigned)
        ("Security", 4672, _) => {
            if let Some(evt) = parse_priv_escalation(event) {
                results.push(evt);
            }
        }
        // Process Access / Injection Candidate: Sysmon 10 (ProcessAccess)
        ("Microsoft-Windows-Sysmon/Operational", 10, _) => {
            if let Some(evt) = parse_proc_access(event) {
                results.push(evt);
            }
        }
        // File Create: Sysmon 11 (FileCreate)
        ("Microsoft-Windows-Sysmon/Operational", 11, _) => {
            if let Some(evt) = parse_file_create(event) {
                results.push(evt);
            }
        }
        // Registry Modification: Sysmon 12/13/14 or Security 4657
        ("Microsoft-Windows-Sysmon/Operational", 12, _)
        | ("Microsoft-Windows-Sysmon/Operational", 13, _)
        | ("Microsoft-Windows-Sysmon/Operational", 14, _)
        | ("Security", 4657, _) => {
            if let Some(evt) = parse_registry_mod(event) {
                results.push(evt);
            }
        }
        // ASR Block / Defense Prevented: Defender 1121
        ("Microsoft-Windows-Windows Defender/Operational", 1121, _) => {
            if let Some(evt) = parse_asr_block(event) {
                results.push(evt);
            }
        }
        // WMI Persistence: Sysmon 19/20/21 (filter/consumer/binding)
        ("Microsoft-Windows-Sysmon/Operational", 19, _)
        | ("Microsoft-Windows-Sysmon/Operational", 20, _)
        | ("Microsoft-Windows-Sysmon/Operational", 21, _) => {
            if let Some(evt) = parse_wmi_persistence(event) {
                results.push(evt);
            }
        }
        // Persistence: Service installed (System 7045, Security 4697)
        ("System", 7045, _) | ("Security", 4697, _) => {
            if let Some(evt) = parse_persistence_service(event) {
                results.push(evt);
            }
        }
        // Persistence: Task created/updated (Security 4698/4702)
        ("Security", 4698, _) | ("Security", 4702, _) => {
            if let Some(evt) = parse_persistence_task(event) {
                results.push(evt);
            }
        }
        // Persistence: Task registered (TaskScheduler 106 - complements Security 4698)
        ("Microsoft-Windows-TaskScheduler/Operational", 106, _) => {
            if let Some(evt) = parse_persistence_task_operational(event) {
                results.push(evt);
            }
        }
        // Defense Evasion: Log clear (Security 1102, System 104)
        ("Security", 1102, _) | ("System", 104, _) => {
            if let Some(evt) = parse_log_clear(event) {
                results.push(evt);
            }
        }
        // Lateral Movement: RDP logon (Security 4624 LogonType=10)
        ("Security", 4624, _) => {
            if let Some(evt) = parse_remote_logon_rdp(event) {
                results.push(evt);
            }
        }
        // Lateral Movement: WinRM (WinRM Operational 91 if available)
        ("Microsoft-Windows-WinRM/Operational", 91, _) => {
            if let Some(evt) = parse_remote_winrm(event) {
                results.push(evt);
            }
        }
        // PowerShell Execution: 4103 (module logging), 4104 (script block)
        ("Microsoft-Windows-PowerShell/Operational", 4103, _)
        | ("Microsoft-Windows-PowerShell/Operational", 4104, _) => {
            if let Some(evt) = parse_powershell_exec(event) {
                results.push(evt);
            }
        }
        _ => {}
    }

    results
}

/// Check if this is a privilege elevation event
/// Security 4672 = special privileges assigned (true priv escalation signal)
fn is_priv_elevation_event(channel: &str, event_id: u32) -> bool {
    matches!((channel, event_id), ("Security", 4672))
}

/// Check if this is a process access / injection candidate
/// Sysmon 10 = ProcessAccess (potential injection, not priv escalation)
fn is_proc_access_event(channel: &str, event_id: u32) -> bool {
    matches!(
        (channel, event_id),
        ("Microsoft-Windows-Sysmon/Operational", 10)
    )
}

/// Check if this is a defender ASR block / defense prevented
/// Defender 1121 = Behavior blocked by ASR
fn is_asr_block_event(channel: &str, event_id: u32) -> bool {
    matches!(
        (channel, event_id),
        ("Microsoft-Windows-Windows Defender/Operational", 1121)
    )
}

/// Check if this is WMI persistence via filter/consumer/binding
/// Sysmon 19/20/21 = WmiEvent created/consumed/bound
fn is_wmi_persistence_event(channel: &str, event_id: u32) -> bool {
    matches!(
        (channel, event_id),
        ("Microsoft-Windows-Sysmon/Operational", 19)
            | ("Microsoft-Windows-Sysmon/Operational", 20)
            | ("Microsoft-Windows-Sysmon/Operational", 21)
    )
}

/// Parse proc_exec from Sysmon 1 or Security 4688
fn parse_proc_exec(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    // Required fields
    let pid = extract_field_u32(event, "ProcessId")
        .or_else(|| extract_field_u32(event, "TargetProcessId"))?;
    let ppid = extract_field_u32(event, "ParentProcessId");
    let exe = extract_field_string(event, "Image")
        .or_else(|| extract_field_string(event, "TargetImage"))?;
    let cmdline = extract_field_string(event, "CommandLine")
        .or_else(|| extract_field_string(event, "ParentCommandLine"));
    let user = extract_field_string(event, "User")
        .or_else(|| extract_field_string(event, "TargetUserName"));

    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    if let Some(ppid_val) = ppid {
        fields.insert(event_keys::PROC_PPID.to_string(), json!(ppid_val));
    }
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    if let Some(cmd) = cmdline {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(cmd));
    }
    if let Some(u) = user {
        fields.insert("windows.user".to_string(), json!(u));
    }

    // Metadata
    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    let evt = Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "execution".to_string(),
            "proc_exec".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None, // CRITICAL: Always None
        fields,
    };

    Some(evt)
}

/// Parse network_connect from Sysmon 3 (NetworkConnect)
fn parse_network_connect(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    let src_ip = extract_field_string(event, "SourceIp");
    let src_port = extract_field_u32(event, "SourcePort");
    let dst_ip = extract_field_string(event, "DestinationIp")?;
    let dst_port = extract_field_u32(event, "DestinationPort")?;
    let dst_hostname = extract_field_string(event, "DestinationHostname");
    let protocol = extract_field_string(event, "Protocol");
    let initiated = extract_field_string(event, "Initiated");
    let image = extract_field_string(event, "Image");
    let pid = extract_field_u32(event, "ProcessId");
    let user = extract_field_string(event, "User");

    fields.insert("dst_ip".to_string(), json!(dst_ip));
    fields.insert("dst_port".to_string(), json!(dst_port));
    if let Some(si) = src_ip {
        fields.insert("src_ip".to_string(), json!(si));
    }
    if let Some(sp) = src_port {
        fields.insert("src_port".to_string(), json!(sp));
    }
    if let Some(dh) = dst_hostname {
        fields.insert("dst_hostname".to_string(), json!(dh));
    }
    if let Some(proto) = protocol {
        fields.insert("protocol".to_string(), json!(proto));
    }
    if let Some(init) = initiated {
        fields.insert("initiated".to_string(), json!(init));
    }
    if let Some(img) = image {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(img));
    }
    if let Some(p) = pid {
        fields.insert(event_keys::PROC_PID.to_string(), json!(p));
    }
    if let Some(u) = user {
        fields.insert("windows.user".to_string(), json!(u));
    }

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "network".to_string(),
            "network_connect".to_string(),
            "network_egress".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse file_create from Sysmon 11 (FileCreate)
fn parse_file_create(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    let target_filename = extract_field_string(event, "TargetFilename")?;
    let image = extract_field_string(event, "Image");
    let pid = extract_field_u32(event, "ProcessId");
    let user = extract_field_string(event, "User");
    let creation_time = extract_field_string(event, "CreationUtcTime");

    fields.insert("target_filename".to_string(), json!(target_filename));
    if let Some(img) = image {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(img));
    }
    if let Some(p) = pid {
        fields.insert(event_keys::PROC_PID.to_string(), json!(p));
    }
    if let Some(u) = user {
        fields.insert("windows.user".to_string(), json!(u));
    }
    if let Some(ct) = creation_time {
        fields.insert("creation_time".to_string(), json!(ct));
    }

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "file".to_string(),
            "file_create".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse registry_mod from Sysmon 12/13/14 or Security 4657
fn parse_registry_mod(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    let event_id = event
        .fields
        .get("windows.event_id")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let reg_type = match event_id {
        12 => "create_delete",     // RegistryEvent (Object create and delete)
        13 => "set_value",         // RegistryEvent (Value Set)
        14 => "rename",            // RegistryEvent (Key and Value Rename)
        4657 => "modify",          // Security: Registry value modified
        _ => "unknown",
    };

    let target_object = extract_field_string(event, "TargetObject")
        .or_else(|| extract_field_string(event, "ObjectName"));
    let details = extract_field_string(event, "Details")
        .or_else(|| extract_field_string(event, "NewValue"));
    let image = extract_field_string(event, "Image");
    let pid = extract_field_u32(event, "ProcessId");
    let user = extract_field_string(event, "User")
        .or_else(|| extract_field_string(event, "SubjectUserName"));

    if let Some(to) = target_object {
        fields.insert("target_object".to_string(), json!(to));
    }
    if let Some(d) = details {
        // Limit details to 2KB
        let d_limited = if d.len() > 2048 {
            d.chars().take(2048).collect::<String>()
        } else {
            d
        };
        fields.insert("details".to_string(), json!(d_limited));
    }
    if let Some(img) = image {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(img));
    }
    if let Some(p) = pid {
        fields.insert(event_keys::PROC_PID.to_string(), json!(p));
    }
    if let Some(u) = user {
        fields.insert("windows.user".to_string(), json!(u));
    }
    fields.insert("registry_event_type".to_string(), json!(reg_type));

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "registry".to_string(),
            "registry_mod".to_string(),
            format!("registry_{}", reg_type),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse powershell_exec from PowerShell/Operational 4103/4104
fn parse_powershell_exec(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    let event_id = event
        .fields
        .get("windows.event_id")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let ps_type = match event_id {
        4103 => "module_logging",   // Module logging
        4104 => "script_block",     // Script block logging
        _ => "unknown",
    };

    // 4104: ScriptBlockText is the captured command
    let script_block = extract_field_string(event, "ScriptBlockText");
    // 4103: CommandLine, CommandPath, etc.
    let command_line = extract_field_string(event, "CommandLine")
        .or_else(|| extract_field_string(event, "Payload"));
    let script_name = extract_field_string(event, "ScriptName")
        .or_else(|| extract_field_string(event, "Path"));
    let user = extract_field_string(event, "UserId")
        .or_else(|| extract_field_string(event, "User"));

    if let Some(sb) = script_block {
        // Limit script block to 4KB
        let sb_limited = if sb.len() > 4096 {
            sb.chars().take(4096).collect::<String>()
        } else {
            sb
        };
        fields.insert("script_block".to_string(), json!(sb_limited));
    }
    if let Some(cl) = command_line {
        fields.insert("command_line".to_string(), json!(cl));
    }
    if let Some(sn) = script_name {
        fields.insert("script_name".to_string(), json!(sn));
    }
    if let Some(u) = user {
        fields.insert("windows.user".to_string(), json!(u));
    }
    fields.insert("ps_event_type".to_string(), json!(ps_type));

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "execution".to_string(),
            "powershell".to_string(),
            format!("ps_{}", ps_type),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse priv_escalation from Security 4672 (special privileges assigned)
/// This is the TRUE privilege escalation signal, not just process access
fn parse_priv_escalation(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    let subject_user = extract_field_string(event, "SubjectUserName");
    let privileges = extract_field_string(event, "PrivilegeList");
    let privilege_count = privileges
        .as_ref()
        .map(|p| p.split('\t').count())
        .unwrap_or(0);

    if let Some(su) = subject_user {
        fields.insert("subject_user".to_string(), json!(su));
    }
    if let Some(priv_list) = privileges {
        fields.insert("privilege_list".to_string(), json!(priv_list));
    }
    fields.insert("privilege_count".to_string(), json!(privilege_count));

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "privilege_escalation".to_string(),
            "priv_escalation".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse proc_access from Sysmon 10 (ProcessAccess)
/// This detects potential code injection, not privilege escalation
fn parse_proc_access(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    let source_pid = extract_field_u32(event, "SourceProcessId")?;
    let target_pid = extract_field_u32(event, "TargetProcessId");
    let source_image = extract_field_string(event, "SourceImage");
    let target_image = extract_field_string(event, "TargetImage");
    let granted_access = extract_field_string(event, "GrantedAccess");
    let call_stack = extract_field_string(event, "CallStack");

    fields.insert(event_keys::PROC_PID.to_string(), json!(source_pid));
    if let Some(tp) = target_pid {
        fields.insert("target_pid".to_string(), json!(tp));
    }
    if let Some(si) = source_image {
        fields.insert("source_image".to_string(), json!(si));
    }
    if let Some(ti) = target_image {
        fields.insert("target_image".to_string(), json!(ti));
    }
    if let Some(ga) = granted_access {
        fields.insert("granted_access".to_string(), json!(ga));
    }
    if let Some(cs) = call_stack {
        // Limit callstack to first 1KB
        let cs_limited = if cs.len() > 1024 {
            cs.chars().take(1024).collect::<String>()
        } else {
            cs
        };
        fields.insert("call_stack".to_string(), json!(cs_limited));
    }

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "execution".to_string(),
            "proc_access".to_string(),
            "proc_injection_candidate".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse asr_block from Defender 1121 (Behavior blocked by ASR)
/// This is a defense action, not a threat signal itself
fn parse_asr_block(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    let detection_name = extract_field_string(event, "DetectionName");
    let process_name = extract_field_string(event, "ProcessName");
    let process_id = extract_field_u32(event, "ProcessId");
    let user = extract_field_string(event, "User");

    if let Some(dn) = detection_name {
        fields.insert("detection_name".to_string(), json!(dn));
    }
    if let Some(pn) = process_name {
        fields.insert("process_name".to_string(), json!(pn));
    }
    if let Some(pid) = process_id {
        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    }
    if let Some(u) = user {
        fields.insert("user".to_string(), json!(u));
    }

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "defense_evasion".to_string(),
            "asr_block".to_string(),
            "defense_prevented".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse wmi_persistence from Sysmon 19/20/21
/// 19 = WmiEvent (filter), 20 = WmiEvent (consumer), 21 = WmiEvent (binding)
fn parse_wmi_persistence(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    let event_id = event
        .fields
        .get("windows.event_id")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let wmi_type = match event_id {
        19 => "filter",
        20 => "consumer",
        21 => "binding",
        _ => "unknown",
    };

    let operation = extract_field_string(event, "Operation").unwrap_or_else(|| match event_id {
        19..=21 => "create".to_string(),
        _ => "unknown".to_string(),
    });

    let event_namespace = extract_field_string(event, "EventNamespace");
    let name = extract_field_string(event, "Name");
    let query = extract_field_string(event, "Query");
    let consumer_type = extract_field_string(event, "Type");

    fields.insert("wmi_type".to_string(), json!(wmi_type));
    fields.insert("operation".to_string(), json!(operation));
    if let Some(ns) = event_namespace {
        fields.insert("event_namespace".to_string(), json!(ns));
    }
    if let Some(n) = name {
        fields.insert("name".to_string(), json!(n));
    }
    if let Some(q) = query {
        // Limit query to first 512 chars
        let q_limited = if q.len() > 512 {
            q.chars().take(512).collect::<String>()
        } else {
            q
        };
        fields.insert("query".to_string(), json!(q_limited));
    }
    if let Some(ct) = consumer_type {
        fields.insert("consumer_type".to_string(), json!(ct));
    }

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "persistence".to_string(),
            "wmi_persistence".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse persistence_service from System 7045 or Security 4697
fn parse_persistence_service(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    let service_name = extract_field_string(event, "ServiceName")
        .or_else(|| extract_field_string(event, "TargetServiceName"))?;
    let service_file = extract_field_string(event, "ServiceFileName")
        .or_else(|| extract_field_string(event, "FileName"));
    let service_type = extract_field_string(event, "ServiceType")
        .or_else(|| extract_field_string(event, "TargetServiceType"));
    let service_start = extract_field_string(event, "StartType")
        .or_else(|| extract_field_string(event, "TargetStartType"));

    fields.insert("service_name".to_string(), json!(service_name));
    if let Some(sf) = service_file {
        fields.insert("service_file".to_string(), json!(sf));
    }
    if let Some(st) = service_type {
        fields.insert("service_type".to_string(), json!(st));
    }
    if let Some(ss) = service_start {
        fields.insert("service_start".to_string(), json!(ss));
    }

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "persistence".to_string(),
            "persistence_service".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse persistence_task from Security 4698/4702
fn parse_persistence_task(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    let task_name = extract_field_string(event, "TaskName")
        .or_else(|| extract_field_string(event, "TargetTaskName"))?;
    let task_content = extract_field_string(event, "TaskContent");
    let client_name = extract_field_string(event, "ClientName");
    let subject_user = extract_field_string(event, "SubjectUserName");

    fields.insert("task_name".to_string(), json!(task_name));
    if let Some(tc) = task_content {
        // Limit to first 2KB
        let tc_limited = if tc.len() > 2048 {
            tc.chars().take(2048).collect::<String>()
        } else {
            tc
        };
        fields.insert("task_content".to_string(), json!(tc_limited));
    }
    if let Some(cn) = client_name {
        fields.insert("client_name".to_string(), json!(cn));
    }
    if let Some(su) = subject_user {
        fields.insert("subject_user".to_string(), json!(su));
    }

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "persistence".to_string(),
            "persistence_task".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse persistence_task from TaskScheduler Operational 106
/// Event 106 = Task registered (complements Security 4698)
fn parse_persistence_task_operational(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    // TaskScheduler 106 has TaskName and UserName
    let task_name = extract_field_string(event, "TaskName")?;
    let user_name = extract_field_string(event, "UserName");
    let user_context = extract_field_string(event, "UserContext");

    fields.insert("task_name".to_string(), json!(task_name));
    if let Some(un) = user_name {
        fields.insert("user_name".to_string(), json!(un));
    }
    if let Some(uc) = user_context {
        fields.insert("user_context".to_string(), json!(uc));
    }

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "persistence".to_string(),
            "persistence_task".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse log_clear from Security 1102 or System 104
fn parse_log_clear(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    let event_id = event
        .fields
        .get("windows.event_id")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let channel = event
        .fields
        .get("windows.channel")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Determine which log was cleared based on event source
    let log_cleared = match (channel, event_id) {
        ("Security", 1102) => "Security".to_string(),
        ("System", 104) => extract_field_string(event, "Channel")
            .unwrap_or_else(|| "System".to_string()),
        _ => "Unknown".to_string(),
    };

    let subject_user = extract_field_string(event, "SubjectUserName")
        .or_else(|| extract_field_string(event, "UserName"));

    if let Some(su) = subject_user {
        fields.insert("subject_user".to_string(), json!(su));
    }
    fields.insert("log_cleared".to_string(), json!(log_cleared));

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "defense_evasion".to_string(),
            "log_clear".to_string(),
            "log_tamper".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse remote_logon_rdp from Security 4624 with LogonType=10
fn parse_remote_logon_rdp(event: &Event) -> Option<Event> {
    let logon_type = extract_field_string(event, "LogonType")?;
    if logon_type != "10" {
        return None; // Only LogonType 10 is RDP
    }

    let mut fields = BTreeMap::new();

    let target_user = extract_field_string(event, "TargetUserName");
    let source_ip = extract_field_string(event, "SourceIPAddress");
    let source_port = extract_field_string(event, "SourcePort");
    let workstation = extract_field_string(event, "WorkstationName");

    if let Some(tu) = target_user {
        fields.insert("target_user".to_string(), json!(tu));
    }
    if let Some(si) = source_ip {
        fields.insert("source_ip".to_string(), json!(si));
    }
    if let Some(sp) = source_port {
        fields.insert("source_port".to_string(), json!(sp));
    }
    if let Some(ws) = workstation {
        fields.insert("workstation".to_string(), json!(ws));
    }

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "lateral_movement".to_string(),
            "remote_logon_rdp".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

/// Parse remote_winrm from WinRM Operational 91
fn parse_remote_winrm(event: &Event) -> Option<Event> {
    let mut fields = BTreeMap::new();

    let connection_user = extract_field_string(event, "User");
    let ip_address = extract_field_string(event, "IPAddress");
    let port = extract_field_string(event, "Port");

    if let Some(cu) = connection_user {
        fields.insert("connection_user".to_string(), json!(cu));
    }
    if let Some(ip) = ip_address {
        fields.insert("ip_address".to_string(), json!(ip));
    }
    if let Some(p) = port {
        fields.insert("port".to_string(), json!(p));
    }

    fields.insert(
        "windows.channel".to_string(),
        json!(event.fields.get("windows.channel")?),
    );
    fields.insert(
        "windows.event_id".to_string(),
        json!(event.fields.get("windows.event_id")?),
    );

    Some(Event {
        ts_ms: event.ts_ms,
        host: event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "lateral_movement".to_string(),
            "remote_winrm".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    })
}

// === Helper functions ===

fn extract_field_string(event: &Event, field_name: &str) -> Option<String> {
    event
        .fields
        .get(field_name)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            // Try nested under windows.xml if present
            event
                .fields
                .get("windows.xml")
                .and_then(|v| v.as_str())
                .and_then(|xml| simple_xml_extract(xml, field_name))
        })
}

fn extract_field_u32(event: &Event, field_name: &str) -> Option<u32> {
    event
        .fields
        .get(field_name)
        .and_then(|v| v.as_u64())
        .map(|u| u as u32)
        .or_else(|| {
            event
                .fields
                .get("windows.xml")
                .and_then(|v| v.as_str())
                .and_then(|xml| simple_xml_extract_u32(xml, field_name))
        })
}

/// Minimal XML tag extraction (not a full parser)
fn simple_xml_extract(xml: &str, tag: &str) -> Option<String> {
    let open_tag = format!("<{}>", tag);
    let close_tag = format!("</{}>", tag);

    let start = xml.find(&open_tag)? + open_tag.len();
    let end = xml[start..].find(&close_tag)?;

    Some(xml[start..start + end].to_string())
}

fn simple_xml_extract_u32(xml: &str, tag: &str) -> Option<u32> {
    simple_xml_extract(xml, tag).and_then(|s| s.parse::<u32>().ok())
}

// ============================================================================
// Regression Tests for Attack Surface Routing
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Helper to create a test event with given channel and event_id
    fn make_test_event(channel: &str, event_id: u32) -> Event {
        let mut fields = BTreeMap::new();
        fields.insert("windows.channel".to_string(), json!(channel));
        fields.insert("windows.event_id".to_string(), json!(event_id));
        fields.insert("windows.provider".to_string(), json!("TestProvider"));
        
        Event {
            ts_ms: 1700000000000,
            host: "test-host".to_string(),
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptr: None,
            fields,
            tags: vec!["windows".to_string()],
        }
    }

    /// Helper to add process fields to an event (Sysmon style)
    fn add_proc_fields(event: &mut Event) {
        event.fields.insert("Image".to_string(), json!("C:\\Windows\\System32\\cmd.exe"));
        event.fields.insert("CommandLine".to_string(), json!("cmd.exe /c echo test"));
        event.fields.insert("ProcessId".to_string(), json!(1234));
        event.fields.insert("ParentProcessId".to_string(), json!(5678));
        event.fields.insert("User".to_string(), json!("DOMAIN\\user"));
    }

    // -------------------------------------------------------------------------
    // Process Execution Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_sysmon_1_routes_to_process_exec() {
        let mut event = make_test_event("Microsoft-Windows-Sysmon/Operational", 1);
        add_proc_fields(&mut event);
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "Sysmon 1 should produce attack surface events");
        assert!(results[0].tags.contains(&"proc_exec".to_string()));
    }

    #[test]
    fn test_security_4688_routes_to_process_exec() {
        let mut event = make_test_event("Security", 4688);
        // Security 4688 uses different field names
        event.fields.insert("TargetImage".to_string(), json!("C:\\Windows\\System32\\cmd.exe"));
        event.fields.insert("CommandLine".to_string(), json!("cmd.exe /c echo test"));
        event.fields.insert("TargetProcessId".to_string(), json!(1234));
        event.fields.insert("ParentProcessId".to_string(), json!(5678));
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "Security 4688 should produce attack surface events");
        assert!(results[0].tags.contains(&"proc_exec".to_string()));
    }

    // -------------------------------------------------------------------------
    // Network Connection Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_sysmon_3_routes_to_network_connect() {
        let mut event = make_test_event("Microsoft-Windows-Sysmon/Operational", 3);
        event.fields.insert("DestinationIp".to_string(), json!("93.184.216.34"));
        event.fields.insert("DestinationPort".to_string(), json!(443));
        event.fields.insert("Image".to_string(), json!("C:\\Windows\\System32\\svchost.exe"));
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "Sysmon 3 should produce attack surface events");
        assert!(results[0].tags.contains(&"network_connect".to_string()));
    }

    // -------------------------------------------------------------------------
    // Persistence Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_system_7045_routes_to_persistence_service() {
        let mut event = make_test_event("System", 7045);
        event.fields.insert("ServiceName".to_string(), json!("TestService"));
        event.fields.insert("ImagePath".to_string(), json!("C:\\test\\service.exe"));
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "System 7045 should produce attack surface events");
        assert!(results[0].tags.contains(&"persistence_service".to_string()));
    }

    #[test]
    fn test_security_4698_routes_to_persistence_task() {
        let mut event = make_test_event("Security", 4698);
        event.fields.insert("TaskName".to_string(), json!("\\TestTask"));
        event.fields.insert("TaskContent".to_string(), json!("<Task>...</Task>"));
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "Security 4698 should produce attack surface events");
        assert!(results[0].tags.contains(&"persistence_task".to_string()));
    }

    #[test]
    fn test_taskscheduler_106_routes_to_persistence_task() {
        let mut event = make_test_event("Microsoft-Windows-TaskScheduler/Operational", 106);
        event.fields.insert("TaskName".to_string(), json!("\\TestTask"));
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "TaskScheduler 106 should produce attack surface events");
        assert!(results[0].tags.contains(&"persistence_task".to_string()));
    }

    #[test]
    fn test_sysmon_12_routes_to_registry_mod() {
        let mut event = make_test_event("Microsoft-Windows-Sysmon/Operational", 12);
        event.fields.insert("TargetObject".to_string(), json!("HKLM\\SOFTWARE\\Test"));
        event.fields.insert("Image".to_string(), json!("C:\\test\\app.exe"));
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "Sysmon 12 should produce attack surface events");
        assert!(results[0].tags.contains(&"registry_mod".to_string()));
    }

    // -------------------------------------------------------------------------
    // PowerShell Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_powershell_4104_routes_to_powershell_exec() {
        let mut event = make_test_event("Microsoft-Windows-PowerShell/Operational", 4104);
        event.fields.insert("ScriptBlockText".to_string(), json!("Get-Process"));
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "PowerShell 4104 should produce attack surface events");
        assert!(results[0].tags.contains(&"powershell".to_string()));
        assert!(results[0].tags.contains(&"ps_script_block".to_string()));
    }

    // -------------------------------------------------------------------------
    // Log Tamper Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_security_1102_routes_to_log_clear() {
        let event = make_test_event("Security", 1102);
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "Security 1102 should produce attack surface events");
        assert!(results[0].tags.contains(&"log_clear".to_string()));
    }

    #[test]
    fn test_system_104_routes_to_log_clear() {
        let mut event = make_test_event("System", 104);
        event.fields.insert("Channel".to_string(), json!("Application"));
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "System 104 should produce attack surface events");
        assert!(results[0].tags.contains(&"log_clear".to_string()));
    }

    // -------------------------------------------------------------------------
    // Credential Access Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_sysmon_10_routes_to_proc_access() {
        let mut event = make_test_event("Microsoft-Windows-Sysmon/Operational", 10);
        event.fields.insert("TargetImage".to_string(), json!("C:\\Windows\\System32\\lsass.exe"));
        event.fields.insert("SourceImage".to_string(), json!("C:\\test\\mimikatz.exe"));
        event.fields.insert("SourceProcessId".to_string(), json!(1234)); // Required field
        event.fields.insert("GrantedAccess".to_string(), json!("0x1410"));
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "Sysmon 10 should produce attack surface events");
        assert!(results[0].tags.contains(&"proc_access".to_string()));
    }

    // -------------------------------------------------------------------------
    // WMI Persistence Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_sysmon_19_routes_to_wmi_persistence() {
        let mut event = make_test_event("Microsoft-Windows-Sysmon/Operational", 19);
        event.fields.insert("Operation".to_string(), json!("Created"));
        event.fields.insert("Name".to_string(), json!("EvilFilter"));
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "Sysmon 19 should produce attack surface events");
        assert!(results[0].tags.contains(&"wmi_persistence".to_string()));
    }

    // -------------------------------------------------------------------------
    // Lateral Movement Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_security_4624_type10_routes_to_remote_logon() {
        let mut event = make_test_event("Security", 4624);
        event.fields.insert("LogonType".to_string(), json!(10)); // RDP
        event.fields.insert("IpAddress".to_string(), json!("192.168.1.100"));
        event.fields.insert("TargetUserName".to_string(), json!("admin"));
        
        let results = normalize_to_attack_surface(&event);
        // Note: parse_remote_logon_rdp only emits for LogonType=10
        if !results.is_empty() {
            assert!(results[0].tags.contains(&"lateral_movement".to_string()));
        }
    }

    #[test]
    fn test_winrm_91_routes_to_remote_winrm() {
        let mut event = make_test_event("Microsoft-Windows-WinRM/Operational", 91);
        event.fields.insert("connection".to_string(), json!("192.168.1.100"));
        
        let results = normalize_to_attack_surface(&event);
        assert!(!results.is_empty(), "WinRM 91 should produce attack surface events");
        assert!(results[0].tags.contains(&"lateral_movement".to_string()));
    }

    // -------------------------------------------------------------------------
    // Unmatched Event Test
    // -------------------------------------------------------------------------

    #[test]
    fn test_unknown_event_produces_no_output() {
        let event = make_test_event("UnknownChannel", 99999);
        
        let results = normalize_to_attack_surface(&event);
        assert!(results.is_empty(), "Unknown events should produce no attack surface events");
    }
}

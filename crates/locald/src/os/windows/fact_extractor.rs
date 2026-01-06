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

/// Extract canonical facts from a Windows event
///
/// This is the primary entry point for the fact extraction pipeline.
/// Maps Windows event tags/fields to canonical FactType variants.
pub fn extract_facts(event: &Event) -> Vec<Fact> {
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
fn enrich_tags_from_event_id(event: &Event) -> Vec<String> {
    let mut tags = Vec::new();

    // Get event ID from fields
    let event_id = event
        .fields
        .get("windows.event_id")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32);

    let Some(eid) = event_id else {
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
fn is_powershell_channel(event: &Event) -> bool {
    event
        .fields
        .get("windows.channel")
        .and_then(|v| v.as_str())
        .map(|s| s.contains("PowerShell") && s.contains("Operational"))
        .unwrap_or(false)
}

/// Check if event is from RDP/Terminal Services channel
fn is_rdp_channel(event: &Event) -> bool {
    event
        .fields
        .get("windows.channel")
        .and_then(|v| v.as_str())
        .map(|s| s.contains("TerminalServices") || s.contains("RemoteDesktop"))
        .unwrap_or(false)
}

/// Check if event is from Sysmon channel
fn is_sysmon_channel(event: &Event) -> bool {
    event
        .fields
        .get("windows.channel")
        .and_then(|v| v.as_str())
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
fn extract_process_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let exe_path = event
        .fields
        .get("exe")
        .or_else(|| event.fields.get("NewProcessName"))
        .or_else(|| event.fields.get("Image"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let cmdline = event
        .fields
        .get("cmdline")
        .or_else(|| event.fields.get("CommandLine"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let hash = event
        .fields
        .get("hash")
        .or_else(|| event.fields.get("Hashes"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let fact = Fact::new(
        host_id,
        build_scope_key(event),
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
    let dst_ip = event
        .fields
        .get("dest_ip")
        .or_else(|| event.fields.get("DestinationIp"))
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0.0")
        .to_string();

    let dst_port = event
        .fields
        .get("dest_port")
        .or_else(|| event.fields.get("DestinationPort"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;

    let proto = event
        .fields
        .get("protocol")
        .or_else(|| event.fields.get("Protocol"))
        .and_then(|v| v.as_str())
        .unwrap_or("tcp")
        .to_string();

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
fn extract_auth_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let user = event
        .fields
        .get("TargetUserName")
        .or_else(|| event.fields.get("user"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let logon_type_str = event
        .fields
        .get("LogonType")
        .or_else(|| event.fields.get("logon_type"))
        .and_then(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        })
        .unwrap_or_else(|| "0".to_string());

    let auth_type = match logon_type_str.as_str() {
        "2" => AuthType::Interactive,
        "3" => AuthType::Network,
        "5" => AuthType::Service,
        "7" => AuthType::Unlock,
        "10" => AuthType::RemoteInteractive,
        "11" => AuthType::CachedInteractive,
        _ => AuthType::Other(logon_type_str),
    };

    let source_ip = event
        .fields
        .get("SourceNetworkAddress")
        .or_else(|| event.fields.get("source_ip"))
        .or_else(|| event.fields.get("IpAddress"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Check if success (4624) or failure (4625)
    let success =
        !event.tags.contains(&"failed".to_string()) && !event.tags.contains(&"4625".to_string());

    let fact = Fact::new(
        host_id,
        ScopeKey::User { key: user.clone() },
        FactType::AuthEvent {
            auth_type,
            user,
            source: source_ip,
            success,
        },
        vec![evidence.clone()],
    );

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
    let key = event
        .fields
        .get("TargetObject")
        .or_else(|| event.fields.get("ObjectName"))
        .or_else(|| event.fields.get("registry_key"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let value_name = event
        .fields
        .get("Details")
        .or_else(|| event.fields.get("value_name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

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
fn extract_lsass_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    // Sysmon 10 TargetImage contains "lsass.exe"
    let target = event
        .fields
        .get("TargetImage")
        .or_else(|| event.fields.get("target"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if !target.to_lowercase().contains("lsass") {
        return None;
    }

    // This is suspicious memory access - use MemAlloc for credential access detection
    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::MemAlloc {
            addr: 0, // Address not typically available
            size: 0,
            protection: 0,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

// ============================================================================
// NEW EXTRACTION FUNCTIONS (Agent C additions)
// ============================================================================

/// Extract PowerShell script block fact (4103, 4104)
fn extract_powershell_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    // 4104 has ScriptBlockText, 4103 has Payload
    let script_content = event
        .fields
        .get("ScriptBlockText")
        .or_else(|| event.fields.get("Payload"))
        .or_else(|| event.fields.get("script_block_text"))
        .and_then(|v| v.as_str());

    let script_path = event
        .fields
        .get("Path")
        .or_else(|| event.fields.get("ScriptName"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Compute simple hash of script content for tracking
    let content_hash = script_content.map(|c| {
        format!("{:016x}", {
            let mut hash: u64 = 0;
            for byte in c.bytes() {
                hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
            }
            hash
        })
    });

    let fact = Fact::new(
        host_id,
        build_scope_key(event),
        FactType::ScriptExec {
            interpreter: "powershell".to_string(),
            script_path,
            script_content_hash: content_hash,
        },
        vec![evidence.clone()],
    );

    Some(fact)
}

/// Extract file creation fact (Sysmon 11)
fn extract_file_create_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let path = event
        .fields
        .get("TargetFilename")
        .or_else(|| event.fields.get("target_filename"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

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
    let path = event
        .fields
        .get("TargetFilename")
        .or_else(|| event.fields.get("target_filename"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

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
    let query = event
        .fields
        .get("QueryName")
        .or_else(|| event.fields.get("query_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let responses = event
        .fields
        .get("QueryResults")
        .or_else(|| event.fields.get("query_results"))
        .and_then(|v| v.as_str())
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
    let path = event
        .fields
        .get("ImageLoaded")
        .or_else(|| event.fields.get("image_loaded"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let hash = event
        .fields
        .get("Hashes")
        .or_else(|| event.fields.get("hash"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let signer = event
        .fields
        .get("Signature")
        .or_else(|| event.fields.get("signer"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

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
}

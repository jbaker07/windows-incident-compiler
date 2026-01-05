// windows/sensors/primitives/mod.rs
// Windows parity primitives: credential_access, discovery, archive_tool_exec, staging_write, network_connection
// + Extended coverage: process_injection, auth_event, persistence_change, defense_evasion, script_exec
// Maps Sysmon + Security Event Log → canonical primitives

pub mod credential_access;
pub mod discovery_exec;
pub mod archive_tool_exec;
pub mod staging_write;
pub mod network_connection;
pub mod process_injection;
pub mod auth_event;
pub mod persistence_change;
pub mod defense_evasion;
pub mod script_exec;
pub mod composite_detectors;

use edr_core::Event;

/// Derive primitive events from Windows base events (Sysmon CreateProcess, Network, File, LogonSuccess)
pub fn derive_primitive_events(base_event: &Event) -> Vec<Event> {
    let mut derived = Vec::new();

    // Map Sysmon EventID 1 (CreateProcess) and Security 4688 (Process Created) to primitives
    if base_event.tags.contains(&"sysmon_process".to_string()) 
        || base_event.tags.contains(&"security_process".to_string())
        || base_event.tags.contains(&"exec".to_string()) {
        
        // Try credential access detection (lsass, procdump, mimikatz patterns)
        if let Some(evt) = credential_access::detect_cred_access(base_event) {
            derived.push(evt);
        }
        
        // Try discovery exec detection (tasklist, wmic, Get-Service, sc, ipconfig, etc.)
        if let Some(evt) = discovery_exec::detect_discovery_exec(base_event) {
            derived.push(evt);
        }
        
        // Try archive tool detection (7z, tar via Git, PowerShell compression)
        if let Some(evt) = archive_tool_exec::detect_archive_tool_exec(base_event) {
            derived.push(evt);
        }
        
        // Try process injection from exec patterns (mimikatz, injection tools)
        if let Some(evt) = process_injection::detect_process_injection_from_exec(base_event) {
            derived.push(evt);
        }
        
        // Try auth event from exec (runas, psexec, etc.)
        if let Some(evt) = auth_event::detect_auth_event_from_exec(base_event) {
            derived.push(evt);
        }
        
        // Try defense evasion from exec (wevtutil, auditpol, etc.)
        if let Some(evt) = defense_evasion::detect_defense_evasion_from_exec(base_event) {
            derived.push(evt);
        }
        
        // Try script exec detection (PowerShell, cmd, wscript, etc.)
        if let Some(evt) = script_exec::detect_script_exec(base_event) {
            derived.push(evt);
        }
        
        // Try LOLBin detection (certutil, mshta, etc.)
        if let Some(evt) = script_exec::detect_lolbin_exec(base_event) {
            derived.push(evt);
        }
    }
    
    // Map file operations (File Create, File Modify) to staging write + persistence
    if base_event.tags.contains(&"sysmon_file".to_string())
        || base_event.tags.contains(&"file".to_string())
        || base_event.tags.contains(&"file_write".to_string())
        || base_event.tags.contains(&"file_create".to_string()) {
        
        if let Some(evt) = staging_write::detect_staging_write(base_event) {
            derived.push(evt);
        }
        
        // Persistence from startup folder file creation
        if let Some(evt) = persistence_change::detect_persistence_from_file(base_event) {
            derived.push(evt);
        }
        
        // Defense evasion from log file deletion
        if let Some(evt) = defense_evasion::detect_defense_evasion_file_delete(base_event) {
            derived.push(evt);
        }
    }
    
    // Map network connections (Sysmon EventID 3, Security 5156)
    if base_event.tags.contains(&"sysmon_network".to_string())
        || base_event.tags.contains(&"security_network".to_string())
        || base_event.tags.contains(&"network".to_string()) {
        if let Some(evt) = network_connection::detect_network_connection(base_event) {
            derived.push(evt);
        }
    }
    
    // Map Sysmon CreateRemoteThread (EventID 8) and ProcessAccess (EventID 10)
    if base_event.tags.contains(&"sysmon_create_remote_thread".to_string())
        || base_event.tags.contains(&"create_remote_thread".to_string())
        || base_event.tags.contains(&"process_access".to_string()) {
        if let Some(evt) = process_injection::detect_process_injection(base_event) {
            derived.push(evt);
        }
    }
    
    // Map Security Event Log auth events (4624, 4625, 4634, etc.)
    if base_event.tags.contains(&"security".to_string())
        || base_event.tags.contains(&"security_auth".to_string())
        || base_event.tags.contains(&"logon".to_string()) {
        if let Some(evt) = auth_event::detect_auth_event(base_event) {
            derived.push(evt);
        }
    }
    
    // Map registry events (Sysmon 12, 13, 14) to persistence change
    if base_event.tags.contains(&"sysmon_registry".to_string())
        || base_event.tags.contains(&"registry".to_string()) {
        if let Some(evt) = persistence_change::detect_persistence_change(base_event) {
            derived.push(evt);
        }
    }
    
    // Map scheduled task events (Security 4698, 4702)
    if base_event.tags.iter().any(|t| t.contains("task")) {
        if let Some(evt) = persistence_change::detect_persistence_from_task(base_event) {
            derived.push(evt);
        }
    }
    
    // Map service installation events (Security 4697, System 7045)
    if base_event.tags.iter().any(|t| t.contains("service")) {
        if let Some(evt) = persistence_change::detect_persistence_from_service(base_event) {
            derived.push(evt);
        }
    }
    
    // Map log clear events (Security 1102, System 104)
    if base_event.tags.iter().any(|t| t.contains("log_clear") || t.contains("audit")) {
        if let Some(evt) = defense_evasion::detect_defense_evasion_log_clear(base_event) {
            derived.push(evt);
        }
        if let Some(evt) = defense_evasion::detect_defense_evasion_audit_change(base_event) {
            derived.push(evt);
        }
    }

    // === HIGH-VALUE COMPOSITE DETECTORS ===
    
    // Process-based composite detectors
    if base_event.tags.contains(&"sysmon_process".to_string()) 
        || base_event.tags.contains(&"security_process".to_string())
        || base_event.tags.contains(&"exec".to_string()) {
        
        // Detect LSASS credential harvesting (procdump + LSASS)
        if let Some(evt) = composite_detectors::detect_lsass_memory_dump_harvesting(base_event) {
            derived.push(evt);
        }
        
        // Detect UAC bypass patterns
        if let Some(evt) = composite_detectors::detect_uac_bypass_with_unsigned_execution(base_event) {
            derived.push(evt);
        }
        
        // Detect event log tampering via wevtutil
        if let Some(evt) = composite_detectors::detect_event_log_tampering(base_event) {
            derived.push(evt);
        }
    }
    
    // Registry-based composite detectors
    if base_event.tags.contains(&"sysmon_registry".to_string())
        || base_event.tags.contains(&"registry".to_string()) {
        
        // Detect registry Run key persistence
        if let Some(evt) = composite_detectors::detect_registry_run_persistence(base_event) {
            derived.push(evt);
        }
    }

    derived
}

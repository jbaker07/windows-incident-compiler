//! Windows Playbook Definitions
//!
//! This module provides programmatic playbook definitions for Windows detection.
//! These are equivalent to the YAML playbooks but expressed as code for type safety.
//!
//! Coverage Map:
//! - Initial Access & Execution: 4 playbooks
//! - Credential Access: 2 playbooks
//! - Persistence: 5 playbooks
//! - Defense Evasion: 4 playbooks
//! - Lateral Movement: 3 playbooks
//! - Discovery: 2 playbooks
//! - Collection: 1 playbook
//!
//! Total: 21 playbooks

use crate::slot_matcher::{PlaybookDef, PlaybookSlot, SlotPredicate};

/// Build all Windows playbook definitions
pub fn windows_playbooks() -> Vec<PlaybookDef> {
    vec![
        // === INITIAL ACCESS & EXECUTION ===
        execution_lolbin_rundll32(),
        execution_lolbin_powershell_download(),
        execution_office_child_process(),
        execution_suspicious_script(),
        // === CREDENTIAL ACCESS ===
        credential_lsass_access(),
        credential_procdump(),
        // === PERSISTENCE ===
        persistence_service_install(),
        persistence_scheduled_task(),
        persistence_registry_run(),
        persistence_wmi_subscription(),
        persistence_startup_folder(),
        // === DEFENSE EVASION ===
        log_tamper_clear(),
        log_tamper_utility(),
        defense_evasion_audit_disable(),
        defense_evasion_defender_disable(),
        // === LATERAL MOVEMENT ===
        lateral_movement_rdp(),
        lateral_movement_admin_share(),
        lateral_movement_winrm(),
        // === DISCOVERY ===
        discovery_network_enum(),
        discovery_domain_enum(),
        // === COLLECTION ===
        collection_archive_staging(),
    ]
}

/// Lateral Movement via RDP (4624 with LogonType 10)
fn lateral_movement_rdp() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_lateral_rdp".to_string(),
        title: "Lateral Movement via RDP".to_string(),
        family: "lateral_movement".to_string(),
        severity: "MEDIUM".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 120,
        tags: vec!["lateral_movement".to_string(), "rdp".to_string()],
        slots: vec![PlaybookSlot::required(
            "remote_logon",
            "Remote RDP Logon Event",
            SlotPredicate::for_fact_type("AuthEvent"),
        )
        .with_ttl(300)],
        narrative: Some("Detected remote RDP logon from non-local source".to_string()),
        playbook_hash: String::new(),
    }
}

/// Lateral Movement via Admin Share Access (5140 with C$/ADMIN$/IPC$)
fn lateral_movement_admin_share() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_lateral_share".to_string(),
        title: "Administrative Share Access".to_string(),
        family: "lateral_movement".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 120,
        tags: vec!["lateral_movement".to_string(), "admin_share".to_string()],
        slots: vec![PlaybookSlot::required(
            "share_access",
            "Admin Share Access Event",
            SlotPredicate::for_fact_type("AuthEvent"),
        )
        .with_ttl(300)],
        narrative: Some("Detected access to administrative share (C$, ADMIN$, IPC$)".to_string()),
        playbook_hash: String::new(),
    }
}

/// Log Tampering - Direct Log Clear (1102, 104)
fn log_tamper_clear() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_log_tamper_clear".to_string(),
        title: "Direct Event Log Clearing".to_string(),
        family: "defense_evasion".to_string(),
        severity: "CRITICAL".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 60,
        cooldown_seconds: 300,
        tags: vec!["log_tampering".to_string(), "defense_evasion".to_string()],
        slots: vec![PlaybookSlot::required(
            "log_clear",
            "Event Log Cleared",
            SlotPredicate::for_fact_type("LogTamper"),
        )
        .with_ttl(60)],
        narrative: Some(
            "Windows event log was cleared - indicator of post-compromise evasion".to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Log Tampering - Utility Execution (wevtutil, Clear-EventLog)
fn log_tamper_utility() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_log_tamper_utility".to_string(),
        title: "Log Clear Utility Execution".to_string(),
        family: "defense_evasion".to_string(),
        severity: "CRITICAL".to_string(),
        entity_scope: "host|user|exe".to_string(),
        ttl_seconds: 60,
        cooldown_seconds: 300,
        tags: vec!["log_tampering".to_string(), "defense_evasion".to_string()],
        slots: vec![PlaybookSlot::required(
            "log_clear_exec",
            "Log Clear Utility Execution",
            SlotPredicate::for_fact_type("Exec").with_exe_filter("wevtutil"),
        )
        .with_ttl(60)],
        narrative: Some("Detected execution of log clearing utility".to_string()),
        playbook_hash: String::new(),
    }
}

/// Persistence - Service Installation (7045)
fn persistence_service_install() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_persist_service".to_string(),
        title: "Suspicious Service Installation".to_string(),
        family: "persistence".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host".to_string(),
        ttl_seconds: 600,
        cooldown_seconds: 300,
        tags: vec!["persistence".to_string(), "service".to_string()],
        slots: vec![PlaybookSlot::required(
            "service_install",
            "New Service Installed",
            SlotPredicate::for_fact_type("PersistArtifact"),
        )
        .with_ttl(600)],
        narrative: Some(
            "New Windows service installed - potential persistence mechanism".to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Persistence - Scheduled Task (4698)
fn persistence_scheduled_task() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_persist_task".to_string(),
        title: "Scheduled Task Creation".to_string(),
        family: "persistence".to_string(),
        severity: "MEDIUM".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 600,
        cooldown_seconds: 300,
        tags: vec!["persistence".to_string(), "scheduled_task".to_string()],
        slots: vec![PlaybookSlot::required(
            "task_create",
            "Scheduled Task Created",
            SlotPredicate::for_fact_type("PersistArtifact"),
        )
        .with_ttl(600)],
        narrative: Some("Scheduled task created - potential persistence mechanism".to_string()),
        playbook_hash: String::new(),
    }
}

/// Persistence - Registry Run Key (4657 or Sysmon 13)
fn persistence_registry_run() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_persist_registry_run".to_string(),
        title: "Registry Run Key Modification".to_string(),
        family: "persistence".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 300,
        tags: vec!["persistence".to_string(), "registry".to_string()],
        slots: vec![PlaybookSlot::required(
            "registry_run_mod",
            "Registry Run Key Modified",
            SlotPredicate::for_fact_type("RegistryMod").with_path_glob("*\\Run*"),
        )
        .with_ttl(300)],
        narrative: Some("Registry Run key modified - persistence mechanism".to_string()),
        playbook_hash: String::new(),
    }
}

/// Credential Access - LSASS Memory Access
fn credential_lsass_access() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_credential_lsass".to_string(),
        title: "LSASS Memory Access".to_string(),
        family: "credential_access".to_string(),
        severity: "CRITICAL".to_string(),
        entity_scope: "host|exe".to_string(),
        ttl_seconds: 60,
        cooldown_seconds: 600,
        tags: vec![
            "credential_access".to_string(),
            "lsass".to_string(),
            "mimikatz".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "lsass_access",
            "LSASS Process Accessed",
            SlotPredicate::for_fact_type("MemAlloc"),
        )
        .with_ttl(60)],
        narrative: Some(
            "Suspicious process accessed LSASS memory - potential credential dumping".to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Defense Evasion - Audit Policy Disabled
fn defense_evasion_audit_disable() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_evasion_audit_disable".to_string(),
        title: "Audit Policy Modification".to_string(),
        family: "defense_evasion".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 600,
        tags: vec!["defense_evasion".to_string(), "audit_policy".to_string()],
        slots: vec![PlaybookSlot::required(
            "audit_change",
            "Audit Policy Changed",
            SlotPredicate::for_fact_type("SecurityToolDisable"),
        )
        .with_ttl(300)],
        narrative: Some("Windows audit policy modified - detection evasion".to_string()),
        playbook_hash: String::new(),
    }
}

// ============================================================================
// NEW PLAYBOOKS (Agent B Additions)
// ============================================================================

/// Execution - LOLBin rundll32 with suspicious arguments
fn execution_lolbin_rundll32() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_exec_lolbin_rundll32".to_string(),
        title: "Suspicious Rundll32 Execution".to_string(),
        family: "execution".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host|user|exe".to_string(),
        ttl_seconds: 60,
        cooldown_seconds: 120,
        tags: vec![
            "execution".to_string(),
            "lolbin".to_string(),
            "rundll32".to_string(),
            "T1218.011".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "rundll32_exec",
            "Rundll32 Execution with Arguments",
            SlotPredicate::for_fact_type("Exec").with_exe_filter("rundll32"),
        )
        .with_ttl(60)],
        narrative: Some(
            "Rundll32 executed with potentially malicious arguments - common LOLBin abuse"
                .to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Execution - PowerShell download cradle
fn execution_lolbin_powershell_download() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_exec_powershell_download".to_string(),
        title: "PowerShell Download Cradle".to_string(),
        family: "execution".to_string(),
        severity: "CRITICAL".to_string(),
        entity_scope: "host|user|exe".to_string(),
        ttl_seconds: 60,
        cooldown_seconds: 120,
        tags: vec![
            "execution".to_string(),
            "powershell".to_string(),
            "download".to_string(),
            "T1059.001".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "ps_download",
            "PowerShell Script Execution",
            SlotPredicate::for_fact_type("ScriptExec"),
        )
        .with_ttl(60)],
        narrative: Some(
            "PowerShell script executed - check for download cradle patterns (IEX, DownloadString)"
                .to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Execution - Office spawning suspicious child
fn execution_office_child_process() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_exec_office_child".to_string(),
        title: "Office Application Spawning Suspicious Process".to_string(),
        family: "execution".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host|user|exe".to_string(),
        ttl_seconds: 120,
        cooldown_seconds: 300,
        tags: vec![
            "execution".to_string(),
            "initial_access".to_string(),
            "office".to_string(),
            "T1566.001".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "suspicious_child",
            "Suspicious Child Process",
            SlotPredicate::for_fact_type("Exec"),
        )
        .with_ttl(120)],
        narrative: Some(
            "Office application spawned suspicious child process - potential macro execution"
                .to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Execution - Suspicious script interpreter
fn execution_suspicious_script() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_exec_script_host".to_string(),
        title: "Suspicious Script Execution".to_string(),
        family: "execution".to_string(),
        severity: "MEDIUM".to_string(),
        entity_scope: "host|user|exe".to_string(),
        ttl_seconds: 60,
        cooldown_seconds: 120,
        tags: vec![
            "execution".to_string(),
            "scripting".to_string(),
            "T1059".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "script_exec",
            "Script Interpreter Execution",
            SlotPredicate::for_fact_type("Exec").with_exe_filter("script"),
        )
        .with_ttl(60)],
        narrative: Some(
            "Script host (wscript/cscript/mshta) executed - review script contents".to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Credential Access - Procdump targeting LSASS
fn credential_procdump() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_credential_procdump".to_string(),
        title: "Procdump LSASS Dump".to_string(),
        family: "credential_access".to_string(),
        severity: "CRITICAL".to_string(),
        entity_scope: "host|exe".to_string(),
        ttl_seconds: 60,
        cooldown_seconds: 600,
        tags: vec![
            "credential_access".to_string(),
            "procdump".to_string(),
            "lsass".to_string(),
            "T1003.001".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "procdump_exec",
            "Procdump Execution",
            SlotPredicate::for_fact_type("Exec").with_exe_filter("procdump"),
        )
        .with_ttl(60)],
        narrative: Some(
            "Procdump executed - commonly used to dump LSASS for credential extraction".to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Persistence - WMI Event Subscription
fn persistence_wmi_subscription() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_persist_wmi".to_string(),
        title: "WMI Persistence Subscription".to_string(),
        family: "persistence".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 600,
        tags: vec![
            "persistence".to_string(),
            "wmi".to_string(),
            "T1546.003".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "wmi_persist",
            "WMI Event Subscription Created",
            SlotPredicate::for_fact_type("PersistArtifact"),
        )
        .with_ttl(300)],
        narrative: Some(
            "WMI event subscription created - stealthy persistence mechanism".to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Persistence - Startup Folder Drop
fn persistence_startup_folder() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_persist_startup".to_string(),
        title: "Startup Folder File Drop".to_string(),
        family: "persistence".to_string(),
        severity: "MEDIUM".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 300,
        tags: vec![
            "persistence".to_string(),
            "startup_folder".to_string(),
            "T1547.001".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "startup_write",
            "File Created in Startup Folder",
            SlotPredicate::for_fact_type("CreatePath").with_path_glob("*\\Startup\\*"),
        )
        .with_ttl(300)],
        narrative: Some(
            "File created in startup folder - persistence via auto-start location".to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Defense Evasion - Windows Defender Disable
fn defense_evasion_defender_disable() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_evasion_defender_disable".to_string(),
        title: "Windows Defender Disabled".to_string(),
        family: "defense_evasion".to_string(),
        severity: "CRITICAL".to_string(),
        entity_scope: "host".to_string(),
        ttl_seconds: 60,
        cooldown_seconds: 600,
        tags: vec![
            "defense_evasion".to_string(),
            "antivirus".to_string(),
            "defender".to_string(),
            "T1562.001".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "defender_disable",
            "Security Tool Disabled",
            SlotPredicate::for_fact_type("SecurityToolDisable"),
        )
        .with_ttl(60)],
        narrative: Some(
            "Windows Defender or other security tool disabled - evasion technique".to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Lateral Movement - WinRM Remote Execution
fn lateral_movement_winrm() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_lateral_winrm".to_string(),
        title: "WinRM Remote Execution".to_string(),
        family: "lateral_movement".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 120,
        tags: vec![
            "lateral_movement".to_string(),
            "winrm".to_string(),
            "T1021.006".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "winrm_connect",
            "WinRM Remote Connection",
            SlotPredicate::for_fact_type("AuthEvent"),
        )
        .with_ttl(300)],
        narrative: Some(
            "WinRM remote connection detected - PowerShell remoting for lateral movement"
                .to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Discovery - Network Enumeration
fn discovery_network_enum() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_discovery_network".to_string(),
        title: "Network Discovery Commands".to_string(),
        family: "discovery".to_string(),
        severity: "LOW".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 60,
        tags: vec![
            "discovery".to_string(),
            "network".to_string(),
            "T1016".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "net_enum",
            "Network Enumeration Command",
            SlotPredicate::for_fact_type("Exec").with_exe_filter("net"),
        )
        .with_ttl(300)],
        narrative: Some(
            "Network enumeration commands executed - reconnaissance activity".to_string(),
        ),
        playbook_hash: String::new(),
    }
}

/// Discovery - Domain Enumeration
fn discovery_domain_enum() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_discovery_domain".to_string(),
        title: "Domain Discovery Commands".to_string(),
        family: "discovery".to_string(),
        severity: "MEDIUM".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 120,
        tags: vec![
            "discovery".to_string(),
            "domain".to_string(),
            "T1087".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "domain_enum",
            "Domain Enumeration Command",
            SlotPredicate::for_fact_type("Exec").with_exe_filter("nltest"),
        )
        .with_ttl(300)],
        narrative: Some("Domain enumeration commands executed (nltest, dsquery) - Active Directory reconnaissance".to_string()),
        playbook_hash: String::new(),
    }
}

/// Collection - Archive Staging
fn collection_archive_staging() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "windows_collection_archive".to_string(),
        title: "Data Archive Staging".to_string(),
        family: "collection".to_string(),
        severity: "MEDIUM".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 600,
        cooldown_seconds: 300,
        tags: vec![
            "collection".to_string(),
            "archive".to_string(),
            "T1560".to_string(),
        ],
        slots: vec![PlaybookSlot::required(
            "archive_create",
            "Archive File Created",
            SlotPredicate::for_fact_type("CreatePath").with_path_glob("*.zip"),
        )
        .with_ttl(600)],
        narrative: Some(
            "Archive file created - potential data staging for exfiltration".to_string(),
        ),
        playbook_hash: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_playbook_loading() {
        let playbooks = windows_playbooks();
        assert!(!playbooks.is_empty());

        // Verify all playbooks have unique IDs
        let mut ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        for pb in &playbooks {
            assert!(
                ids.insert(pb.playbook_id.clone()),
                "Duplicate playbook ID: {}",
                pb.playbook_id
            );
        }
    }

    #[test]
    fn test_playbook_has_slots() {
        let playbooks = windows_playbooks();
        for pb in playbooks {
            assert!(
                !pb.slots.is_empty(),
                "Playbook {} has no slots",
                pb.playbook_id
            );
            assert!(
                !pb.family.is_empty(),
                "Playbook {} has no family",
                pb.playbook_id
            );
        }
    }
}

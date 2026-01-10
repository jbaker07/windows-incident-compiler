//! Windows-specific scenario pack execution
//!
//! This module contains:
//! - All Windows scenario pack definitions
//! - Whitelisted command execution
//! - Audit logging with output hashes

use super::{
    PackExecutionResult, RiskLevel, ScenarioCategory, ScenarioPack, ScenarioStep,
    StepExecutionResult,
};
use sha2::{Digest, Sha256};
use std::process::Command;
use std::time::Instant;

/// Hash output for audit trail (first 16 hex chars of SHA256)
fn hash_output(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    // Convert first 8 bytes to hex manually
    result[..8].iter().map(|b| format!("{:02x}", b)).collect()
}

/// Get all scenario packs (Windows-only)
pub fn get_all_packs() -> Vec<ScenarioPack> {
    vec![
        // === DISCOVERY PACKS (Benign activity) ===
        get_discovery_benign_admin_pack(),
        get_discovery_dev_workflow_pack(),
        // === ADVERSARY SIMULATION PACKS ===
        get_adversary_lolbin_tier_a_pack(),
        get_adversary_lolbin_tier_b_pack(),
        get_adversary_credential_access_pack(),
        get_adversary_defense_evasion_pack(),
        get_adversary_persistence_pack(),
    ]
}

/// Get pack by ID
pub fn get_pack_by_id(id: &str) -> Option<ScenarioPack> {
    get_all_packs().into_iter().find(|p| p.id == id)
}

/// Get packs by category
pub fn get_packs_by_category(category: ScenarioCategory) -> Vec<ScenarioPack> {
    get_all_packs()
        .into_iter()
        .filter(|p| p.category == category)
        .collect()
}

/// Execute a scenario pack with full audit logging
pub async fn execute_pack(pack: &ScenarioPack) -> Result<PackExecutionResult, String> {
    let start = Instant::now();
    let mut step_results = vec![];
    let mut skipped = 0u32;

    for (idx, step) in pack.steps.iter().enumerate() {
        // Whitelist check
        if !is_whitelisted_exe(&step.exe) {
            skipped += 1;
            step_results.push(StepExecutionResult {
                step_id: step.id.clone(),
                step_name: step.name.clone(),
                command: format!("{} {}", step.exe, step.args.join(" ")),
                success: false,
                exit_code: None,
                stdout_hash: String::new(),
                stderr_hash: String::new(),
                stdout_preview: String::new(),
                stderr_preview: format!("SKIPPED: Executable not whitelisted: {}", step.exe),
                duration_ms: 0,
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
            continue;
        }

        let step_start = Instant::now();
        let command_str = format!("{} {}", step.exe, step.args.join(" "));
        let timestamp = chrono::Utc::now().to_rfc3339();

        let result = Command::new(&step.exe).args(&step.args).output();

        let step_result = match result {
            Ok(output) => {
                let stdout_hash = hash_output(&output.stdout);
                let stderr_hash = hash_output(&output.stderr);

                StepExecutionResult {
                    step_id: if step.id.is_empty() {
                        format!("{}_{}", pack.id, idx)
                    } else {
                        step.id.clone()
                    },
                    step_name: step.name.clone(),
                    command: command_str,
                    success: output.status.success(),
                    exit_code: output.status.code(),
                    stdout_hash,
                    stderr_hash,
                    stdout_preview: String::from_utf8_lossy(&output.stdout)
                        .chars()
                        .take(200)
                        .collect(),
                    stderr_preview: String::from_utf8_lossy(&output.stderr)
                        .chars()
                        .take(200)
                        .collect(),
                    duration_ms: step_start.elapsed().as_millis() as u64,
                    timestamp,
                }
            }
            Err(e) => StepExecutionResult {
                step_id: if step.id.is_empty() {
                    format!("{}_{}", pack.id, idx)
                } else {
                    step.id.clone()
                },
                step_name: step.name.clone(),
                command: command_str,
                success: false,
                exit_code: None,
                stdout_hash: String::new(),
                stderr_hash: hash_output(e.to_string().as_bytes()),
                stdout_preview: String::new(),
                stderr_preview: e.to_string(),
                duration_ms: step_start.elapsed().as_millis() as u64,
                timestamp,
            },
        };

        step_results.push(step_result);

        // Delay after step
        if step.delay_after_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(step.delay_after_ms as u64))
                .await;
        }
    }

    let total_duration_ms = start.elapsed().as_millis() as u64;
    let success_count = step_results.iter().filter(|r| r.success).count();

    Ok(PackExecutionResult {
        pack_id: pack.id.clone(),
        pack_name: pack.name.clone(),
        platform: "windows".to_string(),
        total_steps: pack.steps.len() as u32,
        successful_steps: success_count as u32,
        skipped_steps: skipped,
        total_duration_ms,
        step_results,
    })
}

/// Check if executable is in whitelist
fn is_whitelisted_exe(exe: &str) -> bool {
    let exe_lower = exe.to_lowercase();
    let whitelisted = [
        // Basic system utilities
        "hostname.exe",
        "ipconfig.exe",
        "whoami.exe",
        "systeminfo.exe",
        "arp.exe",
        "netstat.exe",
        "nslookup.exe",
        "tracert.exe",
        "ping.exe",
        "where.exe",
        "find.exe",
        "findstr.exe",
        "sort.exe",
        "more.exe",
        // User/group enumeration
        "net.exe",
        "net1.exe",
        // Registry
        "reg.exe",
        "regedit.exe",
        // Services and tasks
        "sc.exe",
        "schtasks.exe",
        "tasklist.exe",
        "taskkill.exe",
        // WMI
        "wmic.exe",
        // Credential stores (read-only)
        "cmdkey.exe",
        "vaultcmd.exe",
        // PowerShell
        "powershell.exe",
        "pwsh.exe",
        // Scripting hosts
        "cmd.exe",
        "cscript.exe",
        "wscript.exe",
        "mshta.exe",
        // Download utilities (read-only usage)
        "certutil.exe",
        "bitsadmin.exe",
        // Dev tools
        "git.exe",
        "node.exe",
        "npm.exe",
        "python.exe",
        "cargo.exe",
        "rustc.exe",
        // Safe utilities
        "explorer.exe",
        "notepad.exe",
        "calc.exe",
    ];

    whitelisted.iter().any(|w| exe_lower.ends_with(w))
}

// === PACK DEFINITIONS ===

fn make_step(
    id: &str,
    name: &str,
    description: &str,
    exe: &str,
    args: Vec<&str>,
    delay_ms: u32,
    event_ids: Vec<u32>,
) -> ScenarioStep {
    ScenarioStep {
        id: id.to_string(),
        name: name.to_string(),
        description: description.to_string(),
        exe: exe.to_string(),
        args: args.into_iter().map(String::from).collect(),
        delay_after_ms: delay_ms,
        expected_event_ids: event_ids,
        expected_fact_types: vec!["Exec".to_string()],
    }
}

fn get_discovery_benign_admin_pack() -> ScenarioPack {
    ScenarioPack {
        id: "discovery_benign_admin".to_string(),
        name: "Benign Admin Activity".to_string(),
        description: "Normal system administration tasks. Should not trigger detection signals."
            .to_string(),
        category: ScenarioCategory::Discovery,
        risk_level: RiskLevel::Safe,
        expected_duration_sec: 30,
        steps: vec![
            make_step(
                "admin_hostname",
                "check_hostname",
                "Get machine hostname",
                "hostname.exe",
                vec![],
                500,
                vec![4688],
            ),
            make_step(
                "admin_ipconfig",
                "check_ipconfig",
                "View network configuration",
                "ipconfig.exe",
                vec!["/all"],
                500,
                vec![4688],
            ),
            make_step(
                "admin_date",
                "check_date",
                "Get current date/time",
                "cmd.exe",
                vec!["/c", "date /t && time /t"],
                500,
                vec![4688],
            ),
            make_step(
                "admin_dir",
                "list_directory",
                "List current directory",
                "cmd.exe",
                vec!["/c", "dir"],
                500,
                vec![4688],
            ),
            make_step(
                "admin_env",
                "check_environment",
                "View environment variables",
                "cmd.exe",
                vec!["/c", "set"],
                500,
                vec![4688],
            ),
        ],
        expected_playbooks: vec![],
        mitre_techniques: vec![],
    }
}

fn get_discovery_dev_workflow_pack() -> ScenarioPack {
    ScenarioPack {
        id: "discovery_dev_workflow".to_string(),
        name: "Developer Workflow".to_string(),
        description: "Common developer commands. Should not trigger alerts.".to_string(),
        category: ScenarioCategory::Discovery,
        risk_level: RiskLevel::Safe,
        expected_duration_sec: 45,
        steps: vec![
            make_step(
                "dev_git",
                "git_version",
                "Check git version",
                "git.exe",
                vec!["--version"],
                500,
                vec![4688],
            ),
            make_step(
                "dev_cargo",
                "cargo_version",
                "Check Cargo version",
                "cargo.exe",
                vec!["--version"],
                500,
                vec![4688],
            ),
            make_step(
                "dev_where",
                "where_code",
                "Find VS Code path",
                "where.exe",
                vec!["code"],
                500,
                vec![4688],
            ),
        ],
        expected_playbooks: vec![],
        mitre_techniques: vec![],
    }
}

fn get_adversary_lolbin_tier_a_pack() -> ScenarioPack {
    ScenarioPack {
        id: "adversary_lolbin_tier_a".to_string(),
        name: "LOLBin Tier A (Safe Discovery)".to_string(),
        description:
            "Safe reconnaissance commands that should trigger discovery playbooks.".to_string(),
        category: ScenarioCategory::AdversarySimulation,
        risk_level: RiskLevel::Safe,
        expected_duration_sec: 60,
        steps: vec![
            make_step(
                "lolbin_whoami",
                "whoami_all",
                "Full user identity enumeration",
                "whoami.exe",
                vec!["/all"],
                1000,
                vec![4688],
            ),
            make_step(
                "lolbin_systeminfo",
                "systeminfo",
                "System information gathering",
                "systeminfo.exe",
                vec![],
                3000,
                vec![4688],
            ),
            make_step(
                "lolbin_net_user",
                "net_user",
                "List local users",
                "net.exe",
                vec!["user"],
                1000,
                vec![4688],
            ),
            make_step(
                "lolbin_net_localgroup",
                "net_localgroup",
                "List local groups",
                "net.exe",
                vec!["localgroup"],
                1000,
                vec![4688],
            ),
            make_step(
                "lolbin_net_admins",
                "net_localgroup_admins",
                "List administrators group",
                "net.exe",
                vec!["localgroup", "Administrators"],
                1000,
                vec![4688],
            ),
            make_step(
                "lolbin_arp",
                "arp_cache",
                "View ARP cache",
                "arp.exe",
                vec!["-a"],
                500,
                vec![4688],
            ),
            make_step(
                "lolbin_netstat",
                "netstat_connections",
                "List network connections",
                "netstat.exe",
                vec!["-ano"],
                1000,
                vec![4688],
            ),
        ],
        expected_playbooks: vec![
            "signal_discovery_burst".to_string(),
            "signal_net_command_abuse".to_string(),
        ],
        mitre_techniques: vec![
            "T1033".to_string(), // System Owner/User Discovery
            "T1082".to_string(), // System Information Discovery
            "T1087".to_string(), // Account Discovery
            "T1049".to_string(), // System Network Connections Discovery
        ],
    }
}

fn get_adversary_lolbin_tier_b_pack() -> ScenarioPack {
    ScenarioPack {
        id: "adversary_lolbin_tier_b".to_string(),
        name: "LOLBin Tier B (Registry/Tasks)".to_string(),
        description: "Registry and scheduled task enumeration. Tests persistence detection."
            .to_string(),
        category: ScenarioCategory::AdversarySimulation,
        risk_level: RiskLevel::Low,
        expected_duration_sec: 60,
        steps: vec![
            make_step(
                "lolbin_reg_run",
                "reg_query_run",
                "Query Run registry key",
                "reg.exe",
                vec![
                    "query",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                ],
                1000,
                vec![4688],
            ),
            make_step(
                "lolbin_reg_runonce",
                "reg_query_runonce",
                "Query RunOnce registry key",
                "reg.exe",
                vec![
                    "query",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                ],
                1000,
                vec![4688],
            ),
            make_step(
                "lolbin_schtasks",
                "schtasks_query",
                "List scheduled tasks",
                "schtasks.exe",
                vec!["/Query", "/FO", "LIST"],
                2000,
                vec![4688],
            ),
            make_step(
                "lolbin_wmic_proc",
                "wmic_process",
                "List processes via WMIC",
                "wmic.exe",
                vec!["process", "list", "brief"],
                2000,
                vec![4688],
            ),
            make_step(
                "lolbin_sc",
                "sc_query",
                "Query services",
                "sc.exe",
                vec!["query"],
                1000,
                vec![4688],
            ),
        ],
        expected_playbooks: vec![
            "signal_registry_persistence".to_string(),
            "signal_schtasks_abuse".to_string(),
            "signal_wmic_abuse".to_string(),
        ],
        mitre_techniques: vec![
            "T1012".to_string(),     // Query Registry
            "T1053.005".to_string(), // Scheduled Task/Job
            "T1047".to_string(),     // Windows Management Instrumentation
        ],
    }
}

fn get_adversary_credential_access_pack() -> ScenarioPack {
    ScenarioPack {
        id: "adversary_credential_access".to_string(),
        name: "Credential Access (Safe)".to_string(),
        description:
            "Safe credential enumeration patterns without actual credential theft.".to_string(),
        category: ScenarioCategory::AdversarySimulation,
        risk_level: RiskLevel::Low,
        expected_duration_sec: 45,
        steps: vec![
            make_step(
                "cred_cmdkey",
                "cmdkey_list",
                "List stored credentials",
                "cmdkey.exe",
                vec!["/list"],
                1000,
                vec![4688],
            ),
            make_step(
                "cred_vault",
                "vaultcmd_list",
                "List credential vault",
                "vaultcmd.exe",
                vec!["/list"],
                1000,
                vec![4688],
            ),
            make_step(
                "cred_sam_reg",
                "reg_sam_query",
                "Query SAM registry (will fail without admin)",
                "reg.exe",
                vec!["query", "HKLM\\SAM"],
                1000,
                vec![4688],
            ),
        ],
        expected_playbooks: vec!["signal_credential_access".to_string()],
        mitre_techniques: vec![
            "T1003".to_string(), // OS Credential Dumping
            "T1555".to_string(), // Credentials from Password Stores
        ],
    }
}

fn get_adversary_defense_evasion_pack() -> ScenarioPack {
    ScenarioPack {
        id: "adversary_defense_evasion".to_string(),
        name: "Defense Evasion (Safe)".to_string(),
        description: "Encoded commands and unusual execution patterns.".to_string(),
        category: ScenarioCategory::AdversarySimulation,
        risk_level: RiskLevel::Low,
        expected_duration_sec: 45,
        steps: vec![
            make_step(
                "evasion_encoded_ps",
                "ps_encoded_whoami",
                "Base64 encoded PowerShell (whoami)",
                "powershell.exe",
                vec!["-EncodedCommand", "dwBoAG8AYQBtAGkA"], // "whoami" base64 UTF-16LE
                1000,
                vec![4688, 4103, 4104],
            ),
            make_step(
                "evasion_bypass",
                "ps_bypass_exec_policy",
                "PowerShell with execution policy bypass",
                "powershell.exe",
                vec!["-ExecutionPolicy", "Bypass", "-Command", "Get-Date"],
                1000,
                vec![4688, 4103],
            ),
            make_step(
                "evasion_hidden",
                "ps_hidden_window",
                "PowerShell with hidden window",
                "powershell.exe",
                vec![
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    "Get-Process | Select-Object -First 1",
                ],
                1000,
                vec![4688],
            ),
        ],
        expected_playbooks: vec![
            "signal_encoded_powershell".to_string(),
            "signal_defense_evasion".to_string(),
        ],
        mitre_techniques: vec![
            "T1027".to_string(),     // Obfuscated Files or Information
            "T1059.001".to_string(), // PowerShell
        ],
    }
}

fn get_adversary_persistence_pack() -> ScenarioPack {
    ScenarioPack {
        id: "adversary_persistence".to_string(),
        name: "Persistence (Query Only)".to_string(),
        description: "Query persistence locations without making changes.".to_string(),
        category: ScenarioCategory::AdversarySimulation,
        risk_level: RiskLevel::Safe,
        expected_duration_sec: 60,
        steps: vec![
            make_step(
                "persist_user_run",
                "reg_user_run",
                "Query user Run key",
                "reg.exe",
                vec![
                    "query",
                    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                ],
                1000,
                vec![4688],
            ),
            make_step(
                "persist_schtasks",
                "schtasks_xml",
                "Export scheduled task as XML",
                "schtasks.exe",
                vec![
                    "/Query",
                    "/TN",
                    "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
                    "/XML",
                ],
                1000,
                vec![4688],
            ),
            make_step(
                "persist_startup",
                "startup_folder",
                "List startup folder",
                "cmd.exe",
                vec![
                    "/c",
                    "dir \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"",
                ],
                1000,
                vec![4688],
            ),
            make_step(
                "persist_wmi",
                "wmi_startup",
                "Query WMI startup programs",
                "wmic.exe",
                vec!["startup", "list", "brief"],
                2000,
                vec![4688],
            ),
        ],
        expected_playbooks: vec![
            "signal_registry_persistence".to_string(),
            "signal_persistence_windows".to_string(),
        ],
        mitre_techniques: vec![
            "T1547.001".to_string(), // Registry Run Keys
            "T1053.005".to_string(), // Scheduled Task
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_all_packs() {
        let packs = get_all_packs();
        assert!(packs.len() >= 5);
    }

    #[test]
    fn test_whitelist() {
        assert!(is_whitelisted_exe("whoami.exe"));
        assert!(is_whitelisted_exe("C:\\Windows\\System32\\whoami.exe"));
        assert!(!is_whitelisted_exe("malware.exe"));
    }

    #[test]
    fn test_pack_has_step_ids() {
        for pack in get_all_packs() {
            for step in &pack.steps {
                assert!(!step.id.is_empty(), "Pack {} has step without ID", pack.id);
            }
        }
    }

    #[test]
    fn test_hash_output() {
        let hash1 = hash_output(b"hello");
        let hash2 = hash_output(b"hello");
        let hash3 = hash_output(b"world");
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 16); // 8 bytes = 16 hex chars
    }
}

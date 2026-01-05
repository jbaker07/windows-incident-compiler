//! Command Alignment: Deterministic categorization of commands for Mission mode.
//!
//! Maps observed command events to MITRE-aligned categories using deterministic
//! regex/tag rules. No AI interpretation - pure pattern matching.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Command Categories (MITRE-aligned)
// ============================================================================

/// MITRE ATT&CK-aligned command category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandCategory {
    /// T1087 - Account Discovery, T1016 - System Network Config, etc.
    Discovery,
    /// T1059 - Command and Scripting Interpreter
    Execution,
    /// T1548 - Abuse Elevation Control, T1068 - Exploitation for PrivEsc
    PrivilegeEscalation,
    /// T1547 - Boot/Logon Autostart, T1053 - Scheduled Task
    Persistence,
    /// T1041 - Exfiltration Over C2, T1048 - Exfiltration Over Alternative Protocol
    Exfiltration,
    /// T1070 - Indicator Removal, T1036 - Masquerading
    DefenseEvasion,
    /// T1110 - Brute Force, T1003 - OS Credential Dumping
    CredentialAccess,
    /// T1021 - Remote Services, T1570 - Lateral Tool Transfer
    LateralMovement,
    /// T1071 - Application Layer Protocol, T1095 - Non-Application Layer Protocol
    CommandAndControl,
    /// T1105 - Ingress Tool Transfer
    ToolTransfer,
    /// Developer/build activity
    Development,
    /// Interactive shell usage
    Interactive,
    /// Unknown/uncategorized
    Unknown,
}

impl CommandCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            CommandCategory::Discovery => "discovery",
            CommandCategory::Execution => "execution",
            CommandCategory::PrivilegeEscalation => "privilege_escalation",
            CommandCategory::Persistence => "persistence",
            CommandCategory::Exfiltration => "exfiltration",
            CommandCategory::DefenseEvasion => "defense_evasion",
            CommandCategory::CredentialAccess => "credential_access",
            CommandCategory::LateralMovement => "lateral_movement",
            CommandCategory::CommandAndControl => "command_and_control",
            CommandCategory::ToolTransfer => "tool_transfer",
            CommandCategory::Development => "development",
            CommandCategory::Interactive => "interactive",
            CommandCategory::Unknown => "unknown",
        }
    }

    pub fn is_suspicious(&self) -> bool {
        matches!(
            self,
            CommandCategory::PrivilegeEscalation
                | CommandCategory::Persistence
                | CommandCategory::Exfiltration
                | CommandCategory::DefenseEvasion
                | CommandCategory::CredentialAccess
                | CommandCategory::LateralMovement
                | CommandCategory::CommandAndControl
        )
    }
}

// ============================================================================
// Command Event
// ============================================================================

/// Observed command execution event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEvent {
    /// Timestamp
    pub ts: chrono::DateTime<chrono::Utc>,
    /// Process scope key
    pub proc_scope_key: String,
    /// Executable path
    pub exe_path: String,
    /// Command line
    pub cmdline: String,
    /// Working directory
    pub cwd: Option<String>,
    /// User context
    pub user: Option<String>,
    /// Parent process
    pub parent_exe: Option<String>,
    /// Evidence pointer
    pub evidence_ptr: Option<super::canonical_event::EvidencePtr>,
}

// ============================================================================
// Command Pattern Rules
// ============================================================================

/// Pattern rule for command categorization
struct PatternRule {
    category: CommandCategory,
    /// Patterns to match against exe name (case-insensitive)
    exe_patterns: Vec<&'static str>,
    /// Patterns to match against cmdline (case-insensitive)
    cmdline_patterns: Vec<&'static str>,
    /// Negative patterns (if present, don't match)
    negative_patterns: Vec<&'static str>,
}

/// Get all pattern rules
fn get_pattern_rules() -> Vec<PatternRule> {
    vec![
        // Discovery
        PatternRule {
            category: CommandCategory::Discovery,
            exe_patterns: vec![
                "whoami",
                "id",
                "hostname",
                "uname",
                "ifconfig",
                "ip",
                "netstat",
                "ss",
                "arp",
                "route",
                "nslookup",
                "dig",
                "host",
                "systeminfo",
                "ipconfig",
                "net.exe",
                "nltest",
                "dsquery",
                "ldapsearch",
                "enum4linux",
                "nmap",
                "masscan",
                "ping",
                "traceroute",
                "tracert",
                "pathping",
            ],
            cmdline_patterns: vec![
                "whoami",
                "/all",
                "net user",
                "net group",
                "net localgroup",
                "get-aduser",
                "get-adcomputer",
                "get-adgroup",
                "klist",
                "systeminfo",
                "cat /etc/passwd",
                "cat /etc/shadow",
                "cat /etc/group",
                "ls /home",
                "dir \\\\users",
                "query user",
                "quser",
            ],
            negative_patterns: vec![],
        },
        // Privilege Escalation
        PatternRule {
            category: CommandCategory::PrivilegeEscalation,
            exe_patterns: vec!["sudo", "su", "doas", "pkexec", "runas", "psexec"],
            cmdline_patterns: vec![
                "sudo ",
                "sudo -",
                "su -",
                "su root",
                "pkexec",
                "runas /user:",
                "setuid",
                "setgid",
                "chmod u+s",
                "chmod g+s",
                "chmod 4",
                "chmod 2",
                "exploit",
                "privesc",
                "potato",
                "juicy",
                "rotten",
                "sweetpotato",
                "printspoofer",
                "godpotato",
                "efspotato",
                "schtasks /create",
                "at \\\\",
                "/grant everyone:f",
            ],
            negative_patterns: vec!["sudo apt", "sudo yum", "sudo dnf", "sudo pacman"],
        },
        // Persistence
        PatternRule {
            category: CommandCategory::Persistence,
            exe_patterns: vec!["crontab", "systemctl", "launchctl", "schtasks", "at.exe"],
            cmdline_patterns: vec![
                "crontab -e",
                "crontab -l",
                "/etc/cron",
                "systemctl enable",
                "launchctl load",
                "launchctl submit",
                "schtasks /create",
                "reg add.*run",
                "reg add.*currentversion\\\\run",
                "startup",
                "autorun",
                "/etc/init.d",
                "/etc/rc",
                "wmic startup",
                "wmic job",
            ],
            negative_patterns: vec![],
        },
        // Credential Access
        PatternRule {
            category: CommandCategory::CredentialAccess,
            exe_patterns: vec![
                "mimikatz",
                "procdump",
                "lazagne",
                "secretsdump",
                "hashdump",
                "lsass",
                "sam",
                "ntds",
                "pypykatz",
                "impacket",
            ],
            cmdline_patterns: vec![
                "mimikatz",
                "sekurlsa",
                "lsadump",
                "kerberos::",
                "privilege::debug",
                "procdump.*lsass",
                "comsvcs.*lsass",
                "rundll32.*comsvcs",
                "reg save.*sam",
                "reg save.*system",
                "reg save.*security",
                "ntdsutil",
                "vssadmin.*shadow",
                "copy.*ntds.dit",
                "/etc/shadow",
                "cat.*shadow",
                "john ",
                "hashcat",
                "hydra",
                "crackmapexec",
                "responder",
                "ntlmrelay",
            ],
            negative_patterns: vec![],
        },
        // Defense Evasion
        PatternRule {
            category: CommandCategory::DefenseEvasion,
            exe_patterns: vec!["shred", "srm", "wipe", "eraser"],
            cmdline_patterns: vec![
                "clear.*log",
                "wevtutil cl",
                "wevtutil clear",
                "del /f.*log",
                "rm -rf.*log",
                "rm -f.*log",
                "history -c",
                "unset histfile",
                "timestomp",
                "touch -t",
                "touch -d",
                "set-itemproperty.*lastwrite",
                "disable-windowsoptionalfeature.*defender",
                "set-mppreference.*disable",
                "stop-service.*defender",
                "netsh advfirewall set.*off",
                "setenforce 0",
                "chmod 000",
                "chattr +i",
            ],
            negative_patterns: vec![],
        },
        // Exfiltration
        PatternRule {
            category: CommandCategory::Exfiltration,
            exe_patterns: vec!["scp", "sftp", "rsync", "rclone", "megacmd"],
            cmdline_patterns: vec![
                "curl.*-d @",
                "curl.*--data-binary",
                "curl.*-F file=",
                "wget.*--post-file",
                "nc -w",
                "ncat.*<",
                "tar.*|.*nc",
                "base64.*|.*curl",
                "xxd.*|.*nc",
                "scp.*@",
                "rsync.*@",
                "rclone copy",
                "rclone sync",
                "aws s3 cp",
                "az storage blob upload",
                "gsutil cp",
                "exfil",
                "upload",
            ],
            negative_patterns: vec!["apt-get", "yum install", "pip install"],
        },
        // Lateral Movement
        PatternRule {
            category: CommandCategory::LateralMovement,
            exe_patterns: vec!["ssh", "plink", "psexec", "wmic", "winrm", "evil-winrm"],
            cmdline_patterns: vec![
                "ssh.*@",
                "plink.*-ssh",
                "psexec.*\\\\\\\\",
                "wmic /node:",
                "winrs -r:",
                "invoke-command -computer",
                "enter-pssession",
                "crackmapexec",
                "smbexec",
                "wmiexec",
                "atexec",
                "dcomexec",
                "net use \\\\\\\\",
                "copy \\\\\\\\",
                "xcopy \\\\\\\\",
            ],
            negative_patterns: vec![],
        },
        // Command and Control
        PatternRule {
            category: CommandCategory::CommandAndControl,
            exe_patterns: vec!["nc", "ncat", "netcat", "socat", "chisel", "plink"],
            cmdline_patterns: vec![
                "nc -e",
                "nc -c",
                "ncat -e",
                "/bin/sh -i",
                "/bin/bash -i",
                "bash -c.*dev/tcp",
                "python.*socket",
                "perl.*socket",
                "powershell.*iex",
                "powershell.*invoke-expression",
                "powershell.*downloadstring",
                "powershell.*downloadfile",
                "certutil.*urlcache",
                "bitsadmin.*transfer",
                "mshta.*http",
                "regsvr32.*http",
                "rundll32.*http",
            ],
            negative_patterns: vec![],
        },
        // Tool Transfer
        PatternRule {
            category: CommandCategory::ToolTransfer,
            exe_patterns: vec!["wget", "curl", "certutil", "bitsadmin"],
            cmdline_patterns: vec![
                "wget http",
                "wget https",
                "curl -o",
                "curl -O",
                "certutil -urlcache",
                "bitsadmin /transfer",
                "invoke-webrequest",
                "iwr ",
                "downloadfile",
                "start-bitstransfer",
            ],
            negative_patterns: vec!["apt-get", "yum", "pip", "npm", "cargo", "go get"],
        },
        // Development (benign)
        PatternRule {
            category: CommandCategory::Development,
            exe_patterns: vec![
                "git",
                "cargo",
                "rustc",
                "gcc",
                "clang",
                "make",
                "cmake",
                "npm",
                "node",
                "python",
                "pip",
                "go",
                "javac",
                "mvn",
                "gradle",
                "docker",
                "kubectl",
                "terraform",
            ],
            cmdline_patterns: vec![
                "git clone",
                "git pull",
                "git push",
                "git commit",
                "cargo build",
                "cargo test",
                "cargo run",
                "npm install",
                "npm run",
                "yarn ",
                "pip install",
                "go build",
                "go test",
                "go run",
                "docker build",
                "docker run",
                "docker-compose",
                "make ",
                "cmake ",
                "mvn ",
                "gradle ",
            ],
            negative_patterns: vec![],
        },
        // Interactive (benign)
        PatternRule {
            category: CommandCategory::Interactive,
            exe_patterns: vec![
                "bash",
                "zsh",
                "fish",
                "sh",
                "cmd",
                "powershell",
                "pwsh",
                "vim",
                "nvim",
                "emacs",
                "nano",
                "code",
                "less",
                "more",
                "cat",
                "head",
                "tail",
                "grep",
                "awk",
                "sed",
                "find",
            ],
            cmdline_patterns: vec![
                "cd ", "ls ", "dir ", "pwd", "echo ", "printf ", "export ", "set ", "alias ",
                "source ", ". ",
            ],
            negative_patterns: vec![],
        },
    ]
}

// ============================================================================
// Command Alignment
// ============================================================================

/// Result of command categorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorizedCommand {
    pub event: CommandEvent,
    pub category: CommandCategory,
    pub confidence: f64,
    pub matched_pattern: Option<String>,
}

/// Categorize a single command
pub fn categorize_command(event: &CommandEvent) -> CategorizedCommand {
    let exe_lower = event.exe_path.to_lowercase();
    let exe_name = std::path::Path::new(&exe_lower)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&exe_lower);
    let cmdline_lower = event.cmdline.to_lowercase();

    let rules = get_pattern_rules();
    let mut best_match: Option<(CommandCategory, f64, String)> = None;

    for rule in &rules {
        // Check negative patterns first
        let has_negative = rule
            .negative_patterns
            .iter()
            .any(|p| cmdline_lower.contains(p));
        if has_negative {
            continue;
        }

        // Check exe patterns
        for pattern in &rule.exe_patterns {
            if exe_name.contains(pattern) {
                let confidence = 0.9;
                if best_match
                    .as_ref()
                    .map(|(_, c, _)| *c < confidence)
                    .unwrap_or(true)
                {
                    best_match = Some((rule.category, confidence, pattern.to_string()));
                }
            }
        }

        // Check cmdline patterns
        for pattern in &rule.cmdline_patterns {
            if cmdline_lower.contains(pattern) {
                // High-severity patterns override exe-based categorization
                let is_high_severity = matches!(
                    rule.category,
                    CommandCategory::CredentialAccess
                        | CommandCategory::Execution
                        | CommandCategory::CommandAndControl
                        | CommandCategory::Discovery // Boost discovery of sensitive files
                );
                let confidence = if is_high_severity { 0.95 } else { 0.85 };
                if best_match
                    .as_ref()
                    .map(|(_, c, _)| *c < confidence)
                    .unwrap_or(true)
                {
                    best_match = Some((rule.category, confidence, pattern.to_string()));
                }
            }
        }
    }

    let (category, confidence, matched_pattern) = best_match
        .map(|(c, conf, p)| (c, conf, Some(p)))
        .unwrap_or((CommandCategory::Unknown, 0.0, None));

    CategorizedCommand {
        event: event.clone(),
        category,
        confidence,
        matched_pattern,
    }
}

/// Categorize multiple commands
pub fn categorize_commands(events: &[CommandEvent]) -> Vec<CategorizedCommand> {
    events.iter().map(categorize_command).collect()
}

// ============================================================================
// Alignment Result
// ============================================================================

/// Overall command alignment result for a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAlignmentResult {
    /// All categorized commands
    pub commands: Vec<CategorizedCommand>,
    /// Category counts
    pub category_counts: HashMap<CommandCategory, usize>,
    /// Primary alignment (most frequent suspicious category)
    pub primary_alignment: Option<CommandCategory>,
    /// Alignment score to primary category
    pub alignment_score: f64,
    /// Mission families this aligns with
    pub aligned_mission_families: Vec<String>,
    /// Summary text for copilot
    pub summary: String,
}

/// Compute alignment result from categorized commands
pub fn compute_alignment(commands: Vec<CategorizedCommand>) -> CommandAlignmentResult {
    // Count categories
    let mut category_counts: HashMap<CommandCategory, usize> = HashMap::new();
    for cmd in &commands {
        *category_counts.entry(cmd.category).or_insert(0) += 1;
    }

    // Find primary suspicious alignment
    let suspicious_categories: Vec<_> = category_counts
        .iter()
        .filter(|(cat, _)| cat.is_suspicious())
        .collect();

    let total_suspicious: usize = suspicious_categories.iter().map(|(_, c)| *c).sum();
    let total_commands = commands.len();

    let (primary_alignment, alignment_score) =
        if let Some((cat, count)) = suspicious_categories.iter().max_by_key(|(_, c)| *c) {
            let score = if total_commands > 0 {
                **count as f64 / total_commands as f64
            } else {
                0.0
            };
            (Some(**cat), score)
        } else {
            (None, 0.0)
        };

    // Map to mission families
    let aligned_mission_families = primary_alignment
        .map(|cat| match cat {
            CommandCategory::PrivilegeEscalation => vec!["privilege_escalation".to_string()],
            CommandCategory::Persistence => vec!["persistence".to_string()],
            CommandCategory::CredentialAccess => vec!["credential_access".to_string()],
            CommandCategory::Exfiltration => {
                vec!["exfiltration".to_string(), "data_theft".to_string()]
            }
            CommandCategory::LateralMovement => vec!["lateral_movement".to_string()],
            CommandCategory::DefenseEvasion => {
                vec!["defense_evasion".to_string(), "tamper".to_string()]
            }
            _ => vec![],
        })
        .unwrap_or_default();

    // Generate summary
    let summary = if let Some(primary) = primary_alignment {
        format!(
            "Activity primarily aligns with {} (score: {:.0}%). \
            {} total commands, {} suspicious.",
            primary.as_str().replace('_', " "),
            alignment_score * 100.0,
            total_commands,
            total_suspicious
        )
    } else if total_commands > 0 {
        let dev_count = category_counts
            .get(&CommandCategory::Development)
            .unwrap_or(&0);
        let interactive_count = category_counts
            .get(&CommandCategory::Interactive)
            .unwrap_or(&0);
        format!(
            "Activity appears benign: {} development commands, {} interactive commands.",
            dev_count, interactive_count
        )
    } else {
        "No command events observed.".to_string()
    };

    CommandAlignmentResult {
        commands,
        category_counts,
        primary_alignment,
        alignment_score,
        aligned_mission_families,
        summary,
    }
}

// ============================================================================
// IDE/Build Context Detection
// ============================================================================

/// Known IDE process names
const IDE_PROCESSES: &[&str] = &[
    "code",
    "code-insiders",
    "cursor",
    "idea",
    "idea64",
    "pycharm",
    "webstorm",
    "goland",
    "clion",
    "rider",
    "sublime_text",
    "atom",
    "brackets",
    "emacs",
    "vim",
    "nvim",
    "neovim",
    "eclipse",
    "netbeans",
    "xcode",
];

/// Check if command is from an IDE context
pub fn is_ide_context(event: &CommandEvent) -> bool {
    if let Some(ref parent) = event.parent_exe {
        let parent_lower = parent.to_lowercase();
        let parent_name = std::path::Path::new(&parent_lower)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&parent_lower);

        for ide in IDE_PROCESSES {
            if parent_name.contains(ide) {
                return true;
            }
        }
    }
    false
}

/// Check if command is part of a build process
pub fn is_build_context(event: &CommandEvent) -> bool {
    let build_indicators = [
        "make",
        "cmake",
        "ninja",
        "msbuild",
        "cargo",
        "rustc",
        "gcc",
        "g++",
        "clang",
        "go build",
        "go test",
        "npm run",
        "yarn ",
        "webpack",
        "vite",
        "mvn ",
        "gradle",
        "ant ",
        "docker build",
        "docker-compose",
    ];

    let cmdline_lower = event.cmdline.to_lowercase();
    for indicator in build_indicators {
        if cmdline_lower.contains(indicator) {
            return true;
        }
    }

    // Check working directory for build-related paths
    if let Some(ref cwd) = event.cwd {
        let cwd_lower = cwd.to_lowercase();
        if cwd_lower.contains("/build/")
            || cwd_lower.contains("/target/")
            || cwd_lower.contains("/node_modules/")
            || cwd_lower.contains("/dist/")
        {
            return true;
        }
    }

    false
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_event(exe: &str, cmdline: &str) -> CommandEvent {
        CommandEvent {
            ts: Utc::now(),
            proc_scope_key: "test".to_string(),
            exe_path: exe.to_string(),
            cmdline: cmdline.to_string(),
            cwd: None,
            user: None,
            parent_exe: None,
            evidence_ptr: None,
        }
    }

    #[test]
    fn test_discovery_categorization() {
        let event = make_event("/usr/bin/whoami", "whoami");
        let result = categorize_command(&event);
        assert_eq!(result.category, CommandCategory::Discovery);
    }

    #[test]
    fn test_privesc_categorization() {
        let event = make_event("/usr/bin/sudo", "sudo -i");
        let result = categorize_command(&event);
        assert_eq!(result.category, CommandCategory::PrivilegeEscalation);
    }

    #[test]
    fn test_credential_access_categorization() {
        let event = make_event(
            "/usr/bin/python",
            "python mimikatz.py sekurlsa::logonpasswords",
        );
        let result = categorize_command(&event);
        assert_eq!(result.category, CommandCategory::CredentialAccess);
    }

    #[test]
    fn test_development_categorization() {
        let event = make_event("/usr/bin/cargo", "cargo build --release");
        let result = categorize_command(&event);
        assert_eq!(result.category, CommandCategory::Development);
    }

    #[test]
    fn test_sudo_apt_is_not_privesc() {
        // Should NOT be privesc due to negative pattern
        let event = make_event("/usr/bin/sudo", "sudo apt-get update");
        let result = categorize_command(&event);
        // Might be Unknown or Development, but not PrivEsc
        assert_ne!(result.category, CommandCategory::PrivilegeEscalation);
    }

    #[test]
    fn test_alignment_computation() {
        let events = vec![
            make_event("/usr/bin/whoami", "whoami"),
            make_event("/usr/bin/id", "id"),
            make_event("/usr/bin/cat", "cat /etc/passwd"),
        ];

        let categorized = categorize_commands(&events);
        let result = compute_alignment(categorized);

        assert_eq!(
            *result
                .category_counts
                .get(&CommandCategory::Discovery)
                .unwrap(),
            3
        );
        assert!(result.summary.contains("Discovery") || result.summary.contains("benign"));
    }

    #[test]
    fn test_ide_context() {
        let mut event = make_event("/usr/bin/bash", "ls -la");
        event.parent_exe = Some("/usr/bin/code".to_string());
        assert!(is_ide_context(&event));

        event.parent_exe = Some("/usr/bin/bash".to_string());
        assert!(!is_ide_context(&event));
    }
}

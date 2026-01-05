// core/signals_windows.rs
// Windows-specific signals (deterministic, evidence-backed)
// Reuses core SignalEngine; these are signal types only
// Severity tiers: LOW (0.3-0.5), MEDIUM (0.5-0.7), HIGH (0.7-0.9), CRITICAL (0.9+)
// Consensus escalation: tamper + any high signal → escalate 1.5x
// Episode scoping: signals are keyed by (host, timeline, entity) and suppression_cooldown prevents re-firing

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SignalEvidence {
    pub stream_id: String,
    pub segment_id: String,
    pub record_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeContext {
    /// Host name (for multi-host correlation)
    pub host: String,
    /// Episode/case ID (links multiple signals)
    pub episode_id: Option<String>,
    /// Consensus escalation factor (1.0 = normal, 1.5 = escalated)
    pub consensus_multiplier: f32,
    /// Suppression cooldown in milliseconds
    pub suppression_cooldown_ms: i64,
    /// Primary evidence pointer
    pub evidence: SignalEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeverityTier {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WindowsSignal {
    /// LOLBin abuse: rundll32, regsvr32, mshta, powershell, wscript, certutil, bitsadmin, etc.
    LolbinAbuse {
        binary: String,
        command_hash: String,
    },

    /// Execution from user-writable paths (Downloads, Desktop, Temp, AppData)
    UserWritableExec {
        exe_path: String,
        parent_exe: Option<String>,
    },

    /// Interpreter (powershell, cmd, python) exec from writable location
    InterpreterExecFromWritable {
        interpreter: String,
        location: String,
    },

    /// Service persistence: new service install + binary path suspicious/writable
    SuspiciousServicePersistence {
        service_name: String,
        binary_path: String,
        is_writable: bool,
    },

    /// Scheduled task persistence: new task with suspicious action
    ScheduledTaskPersistence { task_name: String, action: String },

    /// Registry run key persistence: Run/RunOnce → suspicious target
    RegistryRunKeyPersistence { key_path: String, value: String },

    /// New remote IP seen for executable (lateral movement hint)
    NewRemoteIpForExe { exe: String, ip: String },

    /// High connection rate burst (potential C2 or worm)
    HighConnRateBurst {
        pid: i32,
        exe: String,
        conn_count: u32,
        window_secs: u32,
    },

    /// Logon anomaly: many failures followed by success
    LogonAnomalyBurst {
        account: String,
        failure_count: u32,
        success_ts: u64,
    },

    /// Defense evasion attempt: log clearing, security log tamper, Defender disable
    DefenseEvasionAttempt {
        technique: String,
        description: String,
    },

    /// Lateral movement hint: remote service/task creation
    LateralMovementHint {
        source_host: String,
        target_host: String,
        method: String,
    },

    /// WMI execution (visible process creation)
    WmiExecution {
        caller_exe: String,
        spawned_exe: String,
    },

    /// Script execution (PowerShell, VBScript)
    ScriptExecution {
        script_type: String,
        script_hash: String,
        source: Option<String>,
    },

    /// Credential dumping: LSASS access or similar
    CredentialDumpAttempt {
        tool: String,
        target_process: String,
    },

    /// Registry manipulation: suspicious hives or keys
    RegistryManipulation { key_path: String, action: String },

    // ========== Episode-scoped deterministic signals (Phase 3) ==========
    /// Process injection chain: Sysmon 8 (CreateRemoteThread) + network + child process corroboration
    ProcessInjectionChain {
        source_pid: i32,
        source_exe: String,
        target_pid: i32,
        target_exe: String,
        network_connects: u32,        // # of network connections post-injection
        child_processes: Vec<String>, // child execs spawned post-injection
        evidence: SignalEvidence,
    },

    /// LSASS access suspicion: Sysmon 10 + known credential dumping tool correlation
    LSASSAccessSuspicious {
        accessor_exe: String,
        accessor_pid: i32,
        access_granted: bool,
        correlated_tool: Option<String>, // e.g., "mimikatz", "procdump"
        evidence: SignalEvidence,
    },

    /// Remote persistence: remote logon (4624 RDP/network) + service/task creation on same host within TTL
    RemotePersistence {
        source_host: String,
        target_host: String,
        logon_ts: u64,
        persistence_type: String, // "service", "task", "registry"
        persistence_ts: u64,
        ttl_secs: u32,
        evidence: Vec<SignalEvidence>, // multiple evidence pointers
    },

    /// Log evasion: log clear + audit policy change within episode
    LogEvasion {
        evasion_type: String, // "log_clear", "audit_disable", "channel_disable"
        target: String,       // log name or audit category
        evidence: Vec<SignalEvidence>,
    },

    /// WMI persistence confirmed: Sysmon 19/20/21 events + subsequent process creation from WMI
    WmiPersistenceConfirmed {
        wmi_event_type: String, // "filter", "consumer", "binding"
        spawned_exe: Option<String>,
        time_delta_secs: u32,
        evidence: Vec<SignalEvidence>,
    },

    /// Admin share burst: multiple rapid 5140 events to C$, IPC$, ADMIN$ from new remote IPs
    AdminShareBurst {
        target_host: String,
        source_ips: Vec<String>,
        share_count: u32,
        window_secs: u32,
        evidence: Vec<SignalEvidence>,
    },

    /// Lateral movement via share access: 5140 to high-value shares + new remote endpoint
    LateralShareAccess {
        source_host: Option<String>,
        source_ip: String,
        target_host: String,
        target_share: String,
        is_new_endpoint: bool,
        evidence: SignalEvidence,
    },
}

impl WindowsSignal {
    /// Map to MITRE ATT&CK technique
    pub fn technique(&self) -> Option<&'static str> {
        match self {
            Self::LolbinAbuse { .. } => Some("T1218"),
            Self::UserWritableExec { .. } => Some("T1204.002"),
            Self::InterpreterExecFromWritable { .. } => Some("T1059"),
            Self::SuspiciousServicePersistence { .. } => Some("T1543.003"),
            Self::ScheduledTaskPersistence { .. } => Some("T1053.005"),
            Self::RegistryRunKeyPersistence { .. } => Some("T1547.001"),
            Self::NewRemoteIpForExe { .. } => Some("T1570"),
            Self::HighConnRateBurst { .. } => Some("T1071"),
            Self::LogonAnomalyBurst { .. } => Some("T1110"),
            Self::DefenseEvasionAttempt { .. } => Some("T1562"),
            Self::LateralMovementHint { .. } => Some("T1570"),
            Self::WmiExecution { .. } => Some("T1047"),
            Self::ScriptExecution { .. } => Some("T1059.001"),
            Self::CredentialDumpAttempt { .. } => Some("T1003"),
            Self::RegistryManipulation { .. } => Some("T1112"),
            // Phase 3 signals
            Self::ProcessInjectionChain { .. } => Some("T1055"),
            Self::LSASSAccessSuspicious { .. } => Some("T1003.001"),
            Self::RemotePersistence { .. } => Some("T1570+T1547/T1053"),
            Self::LogEvasion { .. } => Some("T1562"),
            Self::WmiPersistenceConfirmed { .. } => Some("T1084"),
            Self::AdminShareBurst { .. } => Some("T1135"),
            Self::LateralShareAccess { .. } => Some("T1021.002"),
        }
    }

    /// Discrete severity tier for this signal (low, medium, high, critical)
    pub fn severity(&self) -> &'static str {
        match self {
            Self::LolbinAbuse { .. } => "high",
            Self::UserWritableExec { .. } => "medium",
            Self::InterpreterExecFromWritable { .. } => "medium",
            Self::SuspiciousServicePersistence { .. } => "high",
            Self::ScheduledTaskPersistence { .. } => "high",
            Self::RegistryRunKeyPersistence { .. } => "medium",
            Self::NewRemoteIpForExe { .. } => "medium",
            Self::HighConnRateBurst { .. } => "high",
            Self::LogonAnomalyBurst { .. } => "high",
            Self::DefenseEvasionAttempt { .. } => "critical",
            Self::LateralMovementHint { .. } => "high",
            Self::WmiExecution { .. } => "medium",
            Self::ScriptExecution { .. } => "medium",
            Self::CredentialDumpAttempt { .. } => "critical",
            Self::RegistryManipulation { .. } => "low",
            // Phase 3 signals: higher severity due to multi-event correlation
            Self::ProcessInjectionChain { .. } => "critical",
            Self::LSASSAccessSuspicious { .. } => "critical",
            Self::RemotePersistence { .. } => "critical",
            Self::LogEvasion { .. } => "critical",
            Self::WmiPersistenceConfirmed { .. } => "high",
            Self::AdminShareBurst { .. } => "high",
            Self::LateralShareAccess { .. } => "high",
        }
    }

    /// Baseline score (0.0..=1.0) derived from severity tier
    pub fn baseline_score(&self) -> f32 {
        match self.severity() {
            "low" => 0.4,
            "medium" => 0.6,
            "high" => 0.75,
            "critical" => 0.95,
            _ => 0.5,
        }
    }

    /// Consensus escalation: if tamper detected + any high/critical signal, multiply baseline by 1.5
    pub fn escalated_score(&self, has_tamper: bool) -> f32 {
        let base = self.baseline_score();
        if has_tamper && base >= 0.7 {
            (base * 1.5).min(1.0)
        } else {
            base
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lolbin_abuse_technique() {
        let sig = WindowsSignal::LolbinAbuse {
            binary: "powershell.exe".to_string(),
            command_hash: "abc123".to_string(),
        };
        assert_eq!(sig.technique(), Some("T1218"));
    }

    #[test]
    fn test_baseline_scores() {
        let sig = WindowsSignal::DefenseEvasionAttempt {
            technique: "log_clear".to_string(),
            description: "Security log cleared".to_string(),
        };
        assert!(sig.baseline_score() >= 0.75);
    }

    #[test]
    fn test_process_injection_chain() {
        let sig = WindowsSignal::ProcessInjectionChain {
            source_pid: 100,
            source_exe: "rundll32.exe".to_string(),
            target_pid: 500,
            target_exe: "svchost.exe".to_string(),
            network_connects: 3,
            child_processes: vec!["cmd.exe".to_string()],
            evidence: SignalEvidence {
                stream_id: "s1".to_string(),
                segment_id: "g1".to_string(),
                record_index: 42,
            },
        };
        assert_eq!(sig.severity(), "critical");
        assert_eq!(sig.baseline_score(), 0.95);
    }

    #[test]
    fn test_escalated_score() {
        let sig = WindowsSignal::LSASSAccessSuspicious {
            accessor_exe: "cmd.exe".to_string(),
            accessor_pid: 200,
            access_granted: true,
            correlated_tool: Some("mimikatz".to_string()),
            evidence: SignalEvidence {
                stream_id: "s1".to_string(),
                segment_id: "g1".to_string(),
                record_index: 43,
            },
        };
        let base = sig.baseline_score();
        let escalated = sig.escalated_score(true);
        assert!(escalated > base);
        assert!(escalated <= 1.0);
    }
}

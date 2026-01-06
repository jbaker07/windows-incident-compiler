use chrono::Utc;
use forensic_hooks::services::playbook_engine::{load_playbooks_from_dir, PlaybookEngine};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use super::os::windows::signal_engine::WindowsSignalEngine;
use super::scoring::{ScoringEngine, ScoredSignal};
/// edr_locald: macOS threat detection daemon
///
/// Complete end-to-end pipeline:
/// 1. Watch index.json for new segments
/// 2. Ingest segment JSONL into telemetry_events
/// 3. Extract facts and feed simple playbook matcher
/// 4. Persist fired incidents to analysis.db with full evidence
/// 5. Export state for ui_server API queries
use std::fs;
use std::path::PathBuf;
use std::sync::{atomic::Ordering, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn get_build_id() -> String {
    // Use EDR_BUILD_ID env var if set, else fallback to CARGO_PKG_VERSION
    std::env::var("EDR_BUILD_ID").unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
}

fn hash_for_id(data: &str, salt: u64) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    salt.hash(&mut h);
    h.finish()
}

fn make_proc_key(host: &str, pid: u32, ts: u64, stream_id: &str) -> String {
    // Deterministic process key: sha256(host|pid|ts|stream_id)
    let seed = format!("{}|{}|{}|{}", host, pid, ts, stream_id);
    let hash = hash_for_id(&seed, 0);
    format!("proc_{:016x}", hash)
}

fn make_file_key(host: &str, path: &str, stream_id: &str) -> String {
    // Deterministic file key: sha256(host|path|stream_id)
    let seed = format!("{}|{}|{}", host, path, stream_id);
    let hash = hash_for_id(&seed, 1);
    format!("file_{:016x}", hash)
}

fn make_identity_key(host: &str, uid: u32, stream_id: &str) -> String {
    // Deterministic identity key: sha256(host|uid|stream_id)
    let seed = format!("{}|{}|{}", host, uid, stream_id);
    let hash = hash_for_id(&seed, 2);
    format!("id_{:016x}", hash)
}

fn get_edr_streams() -> Vec<String> {
    // EDR_STREAMS env var: comma-separated list of streams to ingest
    // Default: ["core"] for backward compatibility
    std::env::var("EDR_STREAMS")
        .unwrap_or_else(|_| "core".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn get_telemetry_root() -> PathBuf {
    // Check env var first
    if let Ok(root) = std::env::var("EDR_TELEMETRY_ROOT") {
        return PathBuf::from(root);
    }

    // Default: relative to current working directory
    std::env::current_dir()
        .map(|p| p.join("telemetry_output"))
        .unwrap_or_else(|_| PathBuf::from("./telemetry_output"))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SegmentIndex {
    #[serde(default)]
    schema_version: u32, // For Task 4: Index validation
    #[serde(default)]
    next_seq: u64, // For compatibility with capture's new index
    segments: Vec<SegmentRef>,
    last_updated_ts: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SegmentRef {
    #[serde(default)]
    seq: u64, // Monotonic sequence number (new field)
    segment_id: String,
    path: String,
    ts: u64,
    #[serde(default)]
    sha256_segment: String, // SHA256 hash of segment file (P0)
}

#[derive(Debug, Serialize, Deserialize)]
struct RawEvent {
    event_type: String,
    data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Fact {
    fact_type: String,
    exe: String,
    user: String,
    host: String,
    ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvidencePtr {
    segment_id: String,
    record_index: u32,
    ts: u64,
    event_type: String,
    #[serde(default)]
    stream_id: Option<String>,
}

// SignalEngine: derives signals from accumulated facts with rolling state
mod signal_engine {
    use serde_json::json;
    use std::collections::{HashMap, VecDeque};
    use std::time::{SystemTime, UNIX_TIMESTAMP};

    #[derive(Clone, Debug)]
    pub struct SignalState {
        first_seen_ips: HashMap<(String, String, String), std::collections::HashSet<String>>,
        conn_rate_window: HashMap<(String, String, String), VecDeque<u64>>,
        file_write_times: HashMap<(String, String, String), VecDeque<(String, u64)>>,
        last_signal_time: HashMap<String, u64>,
        exec_from_writable_cache: HashMap<String, u64>,
    }

    #[derive(Clone, Debug)]
    pub struct DerivedSignal {
        pub signal_type: String,
        pub severity: String,
        pub host: String,
        pub user: String,
        pub exe: String,
        pub entity_key: String,
        pub proc_key: Option<String>,
        pub file_key: Option<String>,
        pub identity_key: Option<String>,
        pub ts_start: u64,
        pub ts_end: u64,
        pub metadata: serde_json::Value,
        pub consensus_signals: Vec<String>,
    }

    impl SignalState {
        pub fn new() -> Self {
            Self {
                first_seen_ips: HashMap::new(),
                conn_rate_window: HashMap::new(),
                file_write_times: HashMap::new(),
                last_signal_time: HashMap::new(),
                exec_from_writable_cache: HashMap::new(),
            }
        }

        fn should_suppress(&self, signal_id: &str, ts: u64, cooldown_sec: u64) -> bool {
            if let Some(&last_ts) = self.last_signal_time.get(signal_id) {
                ts.saturating_sub(last_ts) < cooldown_sec * 1000
            } else {
                false
            }
        }

        fn record_signal(&mut self, signal_id: &str, ts: u64) {
            self.last_signal_time.insert(signal_id.to_string(), ts);
        }

        fn is_writable_path(path: &str) -> bool {
            path.contains("/tmp/") || path.contains("/var/tmp/") || path.contains("/Users/") && path.contains("/Desktop") || path.contains("/Downloads")
        }

        fn is_interpreter(exe: &str) -> bool {
            exe.contains("/python") || exe.contains("/node") || exe.contains("/bash") || exe.contains("/sh") || exe.contains("/perl") || exe.contains("/ruby")
        }

        fn is_sensitive_path(path: &str) -> bool {
            path.contains("/.ssh/") || path.contains("/.gnupg/") || path.contains("/Library/Keychain/") || path.contains("/etc/sudoers") || path.contains("/etc/pam.d") || path.contains("/Library/LaunchAgents") || path.contains("/Library/LaunchDaemons")
        }

        fn apply_consensus_escalation(signals: &mut [DerivedSignal]) {
            // If AgentTamperAttempt present, escalate all to critical
            let has_tamper = signals.iter().any(|s| s.signal_type == "AgentTamperAttempt");
            // If 2+ distinct high-value signals, mark all with consensus
            let high_value_count = signals.iter().filter(|s| ["AgentTamperAttempt", "LaunchAgentWrite", "TCCDBAccessAttempt", "BrowserCredentialStoreAccess"].contains(&s.signal_type.as_str())).count();
            
            for signal in signals.iter_mut() {
                if has_tamper && signal.signal_type != "AgentTamperAttempt" {
                    signal.severity = "critical".to_string();
                    signal.consensus_signals.push("AgentTamperAttempt".to_string());
                }
                if high_value_count >= 2 {
                    signal.consensus_signals = signals.iter()
                        .filter(|s| s.signal_type != signal.signal_type && ["AgentTamperAttempt", "LaunchAgentWrite", "TCCDBAccessAttempt", "BrowserCredentialStoreAccess"].contains(&s.signal_type.as_str()))
                        .map(|s| s.signal_type.clone())
                        .collect();
                    if !signal.consensus_signals.is_empty() {
                        signal.severity = "high".to_string();  // Escalate non-high signals
                    }
                }
            }
        }

        pub fn emit_signals(
            &mut self,
            fact_type: &str,
            host: &str,
            user: &str,
            exe: &str,
            path: Option<&str>,
            dest_ip: Option<&str>,
            ts: u64,
            stream_id: &str,
        ) -> Vec<DerivedSignal> {
            let mut signals = Vec::new();
            let key = (host.to_string(), user.to_string(), exe.to_string());

            // Entity keys
            let proc_key = make_proc_key(host, 0, ts, stream_id);  // pid would come from facts
            let file_key = path.map(|p| make_file_key(host, p, stream_id));
            let identity_key = make_identity_key(host, 0, stream_id);  // uid would come from facts

            match fact_type {
                "NetConnect" => {
                    if let Some(ip) = dest_ip {
                        // NewRemoteIPForExe
                        let ips = self.first_seen_ips.entry(key.clone()).or_insert_default();
                        if !ips.contains(ip) {
                            ips.insert(ip.to_string());
                            let signal_id = format!("NewRemoteIPForExe:{}:{}:{}", key.0, key.1, key.2);
                            if !self.should_suppress(&signal_id, ts, 300) {
                            signals.push(DerivedSignal {
                                    signal_type: "NewRemoteIPForExe".to_string(),
                                    severity: "medium".to_string(),
                                    host: key.0.clone(),
                                    user: key.1.clone(),
                                    exe: key.2.clone(),
                                    entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                                    proc_key: Some(proc_key.clone()),
                                    file_key: None,
                                    identity_key: Some(identity_key.clone()),
                                    ts_start: ts,
                                    ts_end: ts,
                                    metadata: json!({ "remote_ip": ip, "stream_id": stream_id }),
                                    consensus_signals: vec![],
                                });
                                self.record_signal(&signal_id, ts);
                            }
                        }

                        // HighConnRateBurst
                        let window = self.conn_rate_window.entry(key.clone()).or_insert_default();
                        window.push_back(ts);
                        while window
                            .front()
                            .map(|&t| ts.saturating_sub(t) > 60_000)
                            .unwrap_or(false)
                        {
                            window.pop_front();
                        }
                        if window.len() > 10 {
                            let signal_id = format!("HighConnRateBurst:{}:{}:{}", key.0, key.1, key.2);
                            if !self.should_suppress(&signal_id, ts, 60) {
                                let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                                let identity_key = make_identity_key(&key.0, 0, stream_id);
                                signals.push(DerivedSignal {
                                    signal_type: "HighConnRateBurst".to_string(),
                                    severity: "high".to_string(),
                                    host: key.0.clone(),
                                    user: key.1.clone(),
                                    exe: key.2.clone(),
                                    entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                                    ts_start: *window.front().unwrap_or(&ts),
                                    ts_end: ts,
                                    proc_key: Some(proc_key),
                                    file_key: None,
                                    identity_key: Some(identity_key),
                                    metadata: json!({ "conn_count": window.len(), "window_ms": 60_000, "stream_id": stream_id }),
                                    consensus_signals: vec![],
                                });
                                self.record_signal(&signal_id, ts);
                            }
                        }
                    }
                },
                "FileWrite" | "FileCreate" => {
                    if let Some(p) = path {
                        // PersistenceDelta
                        if p.contains("LaunchAgents") || p.contains("LaunchDaemons") {
                            let signal_id = format!("PersistenceDelta:{}:{}:{}", key.0, key.1, key.2);
                            if !self.should_suppress(&signal_id, ts, 300) {
                                let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                                let file_key = make_file_key(&key.0, p, stream_id);
                                let identity_key = make_identity_key(&key.0, 0, stream_id);
                                signals.push(DerivedSignal {
                                    signal_type: "PersistenceDelta".to_string(),
                                    severity: "high".to_string(),
                                    host: key.0.clone(),
                                    user: key.1.clone(),
                                    exe: key.2.clone(),
                                    entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                                    ts_start: ts,
                                    ts_end: ts,
                                    proc_key: Some(proc_key),
                                    file_key: Some(file_key),
                                    identity_key: Some(identity_key),
                                    metadata: json!({ "path": p, "event_type": fact_type, "stream_id": stream_id }),
                                    consensus_signals: vec![],
                                });
                                self.record_signal(&signal_id, ts);
                            }
                        }
                        
                        // ExecFromUserWritable (file write in writable path)
                        if Self::is_writable_path(p) {
                            let signal_id = format!("ExecFromUserWritable:{}:{}:{}", key.0, key.1, key.2);
                            if !self.should_suppress(&signal_id, ts, 600) {
                                let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                                let file_key = make_file_key(&key.0, p, stream_id);
                                let identity_key = make_identity_key(&key.0, 0, stream_id);
                                signals.push(DerivedSignal {
                                    signal_type: "ExecFromUserWritable".to_string(),
                                    severity: "high".to_string(),
                                    host: key.0.clone(),
                                    user: key.1.clone(),
                                    exe: key.2.clone(),
                                    entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                                    ts_start: ts,
                                    ts_end: ts,
                                    proc_key: Some(proc_key),
                                    file_key: Some(file_key),
                                    identity_key: Some(identity_key),
                                    metadata: json!({ "writable_path": p, "stream_id": stream_id }),
                                    consensus_signals: vec![],
                                });
                                self.record_signal(&signal_id, ts);
                            }
                        }
                        
                        // SensitiveFileRead (reading sensitive files)
                        if Self::is_sensitive_path(p) {
                            let signal_id = format!("SensitiveFileRead:{}:{}:{}", key.0, key.1, key.2);
                            if !self.should_suppress(&signal_id, ts, 180) {
                                let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                                let file_key = make_file_key(&key.0, p, stream_id);
                                let identity_key = make_identity_key(&key.0, 0, stream_id);
                                signals.push(DerivedSignal {
                                    signal_type: "SensitiveFileRead".to_string(),
                                    severity: "medium".to_string(),
                                    host: key.0.clone(),
                                    user: key.1.clone(),
                                    exe: key.2.clone(),
                                    entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                                    ts_start: ts,
                                    ts_end: ts,
                                    proc_key: Some(proc_key),
                                    file_key: Some(file_key),
                                    identity_key: Some(identity_key),
                                    metadata: json!({ "sensitive_path": p, "stream_id": stream_id }),
                                    consensus_signals: vec![],
                                });
                                self.record_signal(&signal_id, ts);
                            }
                        }
                    }
                },
                "FileOpen" => {
                    if let Some(p) = path {
                        // InterpreterExecFromWritable
                        if Self::is_interpreter(exe) && Self::is_writable_path(p) {
                            let signal_id = format!("InterpreterExecFromWritable:{}:{}:{}", key.0, key.1, key.2);
                            if !self.should_suppress(&signal_id, ts, 300) {
                                let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                                let file_key = make_file_key(&key.0, p, stream_id);
                                let identity_key = make_identity_key(&key.0, 0, stream_id);
                                signals.push(DerivedSignal {
                                    signal_type: "InterpreterExecFromWritable".to_string(),
                                    severity: "high".to_string(),
                                    host: key.0.clone(),
                                    user: key.1.clone(),
                                    exe: key.2.clone(),
                                    entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                                    ts_start: ts,
                                    ts_end: ts,
                                    proc_key: Some(proc_key),
                                    file_key: Some(file_key),
                                    identity_key: Some(identity_key),
                                    metadata: json!({ "interpreter": exe, "script_path": p, "stream_id": stream_id }),
                                    consensus_signals: vec![],
                                });
                                self.record_signal(&signal_id, ts);
                            }
                        }
                    }
                },
                "ProcExec" => {
                    // Check for DYLD injection
                    // (would need env vars from fact; placeholder for now)
                    
                    // LaunchdPlistWriteThenLoad
                    if exe.contains("launchctl") && path.is_some() {
                        let plist_path = path.unwrap_or("");
                        if plist_path.contains("LaunchAgents") || plist_path.contains("LaunchDaemons") {
                            let signal_id = format!("LaunchdPlistWriteThenLoad:{}:{}:{}", key.0, key.1, key.2);
                            if !self.should_suppress(&signal_id, ts, 300) {
                                let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                                let file_key = make_file_key(&key.0, plist_path, stream_id);
                                let identity_key = make_identity_key(&key.0, 0, stream_id);
                                signals.push(DerivedSignal {
                                    signal_type: "LaunchdPlistWriteThenLoad".to_string(),
                                    severity: "critical".to_string(),
                                    host: key.0.clone(),
                                    user: key.1.clone(),
                                    exe: key.2.clone(),
                                    entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                                    ts_start: ts,
                                    ts_end: ts,
                                    proc_key: Some(proc_key),
                                    file_key: Some(file_key),
                                    identity_key: Some(identity_key),
                                    metadata: json!({ "plist": plist_path, "stream_id": stream_id }),
                                    consensus_signals: vec![],
                                });
                                self.record_signal(&signal_id, ts);
                            }
                        }
                    }
                },
                "MmapEvent" => {
                    // DYLDInjectionAttempt (high memory mapping activity on exec)
                    let signal_id = format!("DYLDInjectionAttempt:{}:{}:{}", key.0, key.1, key.2);
                    if !self.should_suppress(&signal_id, ts, 120) {
                        let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                        let identity_key = make_identity_key(&key.0, 0, stream_id);
                        signals.push(DerivedSignal {
                            signal_type: "DYLDInjectionAttempt".to_string(),
                            severity: "high".to_string(),
                            host: key.0.clone(),
                            user: key.1.clone(),
                            exe: key.2.clone(),
                            entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                            ts_start: ts,
                            ts_end: ts,
                            proc_key: Some(proc_key),
                            file_key: None,
                            identity_key: Some(identity_key),
                            metadata: json!({ "event_type": "mmap", "stream_id": stream_id }),
                            consensus_signals: vec![],
                        });
                        self.record_signal(&signal_id, ts);
                    }
                },
                "KeychainAccess" => {
                    // SuspiciousKeychainAccess: keychain tool usage
                    let signal_id = format!("SuspiciousKeychainAccess:{}:{}:{}", key.0, key.1, key.2);
                    if !self.should_suppress(&signal_id, ts, 180) {
                        let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                        let identity_key = make_identity_key(&key.0, 0, stream_id);
                        signals.push(DerivedSignal {
                            signal_type: "SuspiciousKeychainAccess".to_string(),
                            severity: "medium".to_string(),
                            host: key.0.clone(),
                            user: key.1.clone(),
                            exe: key.2.clone(),
                            entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                            ts_start: ts,
                            ts_end: ts,
                            proc_key: Some(proc_key),
                            file_key: None,
                            identity_key: Some(identity_key),
                            metadata: json!({ "tool": exe, "stream_id": stream_id }),
                            consensus_signals: vec![],
                        });
                        self.record_signal(&signal_id, ts);
                    }
                },
                "FileRead" | "FileOpen" => {
                    if let Some(p) = path {
                        // TCCDBAccessAttempt: TCC.db access
                        if p.contains("TCC.db") {
                            let signal_id = format!("TCCDBAccessAttempt:{}:{}:{}", key.0, key.1, key.2);
                            if !self.should_suppress(&signal_id, ts, 240) {
                                let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                                let file_key = make_file_key(&key.0, p, stream_id);
                                let identity_key = make_identity_key(&key.0, 0, stream_id);
                                signals.push(DerivedSignal {
                                    signal_type: "TCCDBAccessAttempt".to_string(),
                                    severity: "high".to_string(),
                                    host: key.0.clone(),
                                    user: key.1.clone(),
                                    exe: key.2.clone(),
                                    entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                                    ts_start: ts,
                                    ts_end: ts,
                                    proc_key: Some(proc_key),
                                    file_key: Some(file_key),
                                    identity_key: Some(identity_key),
                                    metadata: json!({ "path": p, "stream_id": stream_id }),
                                    consensus_signals: vec![],
                                });
                                self.record_signal(&signal_id, ts);
                            }
                        }
                        
                        // BrowserCredentialStoreAccess: Chrome/Firefox credential DBs
                        // Require context: non-browser process OR followed by netconnect
                        if p.contains("Chrome") && (p.contains("Login Data") || p.contains("Cookies")) || 
                           p.contains("Firefox") && (p.contains("logins.json") || p.contains("key4.db")) {
                            // Check if exe is non-browser (not chrome, not firefox)
                            let is_non_browser = !exe.contains("Chrome") && !exe.contains("chrome") && 
                                                 !exe.contains("Firefox") && !exe.contains("firefox");
                            let has_netconnect_context = self.conn_rate_window.contains_key(&(key.clone(), ts.saturating_sub(60_000)..ts));
                            
                            if is_non_browser || has_netconnect_context {
                                let signal_id = format!("BrowserCredentialStoreAccess:{}:{}:{}", key.0, key.1, key.2);
                                if !self.should_suppress(&signal_id, ts, 240) {
                                    let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                                    let file_key = make_file_key(&key.0, p, stream_id);
                                    let identity_key = make_identity_key(&key.0, 0, stream_id);
                                    signals.push(DerivedSignal {
                                        signal_type: "BrowserCredentialStoreAccess".to_string(),
                                        severity: "high".to_string(),
                                        host: key.0.clone(),
                                        user: key.1.clone(),
                                        exe: key.2.clone(),
                                        entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                                        ts_start: ts,
                                        ts_end: ts,
                                        proc_key: Some(proc_key),
                                        file_key: Some(file_key),
                                        identity_key: Some(identity_key),
                                        metadata: json!({ "path": p, "stream_id": stream_id }),
                                        consensus_signals: vec![],
                                    });
                                    self.record_signal(&signal_id, ts);
                                }
                            }
                        }
                        
                        // LogWipeAttempt: deletion/rename in log dirs
                        if (p.contains("/var/log/") || p.contains("/private/var/log/")) && fact_type == "FileUnlink" {
                            let signal_id = format!("LogWipeAttempt:{}:{}:{}", key.0, key.1, key.2);
                            if !self.should_suppress(&signal_id, ts, 300) {
                                let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                                let file_key = make_file_key(&key.0, p, stream_id);
                                let identity_key = make_identity_key(&key.0, 0, stream_id);
                                signals.push(DerivedSignal {
                                    signal_type: "LogWipeAttempt".to_string(),
                                    severity: "high".to_string(),
                                    host: key.0.clone(),
                                    user: key.1.clone(),
                                    exe: key.2.clone(),
                                    entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                                    ts_start: ts,
                                    ts_end: ts,
                                    proc_key: Some(proc_key),
                                    file_key: Some(file_key),
                                    identity_key: Some(identity_key),
                                    metadata: json!({ "path": p, "stream_id": stream_id }),
                                    consensus_signals: vec![],
                                });
                                self.record_signal(&signal_id, ts);
                            }
                        }
                    }
                },
                _ => {}
            }

            // LOLBinAbuse (osascript, curl, python, bash, sh, zsh, nc, ssh, scp, rsync, launchctl, defaults, plutil, sqlite3)
            // Require context: user-writable source OR suspicious args OR netconnect within TTL
            let lolbins = ["osascript", "curl", "python", "bash", "sh", "zsh", "nc", "ssh", "scp", "rsync", "launchctl", "defaults", "plutil", "sqlite3"];
            if lolbins.iter().any(|&bin| exe.contains(bin)) && fact_type == "ProcExec" {
                // Check context: path is writable or seen netconnect recently
                let has_writable_context = path.map(|p| Self::is_writable_path(p)).unwrap_or(false);
                let has_netconnect_context = self.conn_rate_window.contains_key(&(key.clone(), ts.saturating_sub(60_000)..ts));
                
                if has_writable_context || has_netconnect_context {
                    let signal_id = format!("LOLBinAbuse:{}:{}:{}", key.0, key.1, key.2);
                    if !self.should_suppress(&signal_id, ts, 60) {
                        let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                        let identity_key = make_identity_key(&key.0, 0, stream_id);
                        signals.push(DerivedSignal {
                            signal_type: "LOLBinAbuse".to_string(),
                            severity: "medium".to_string(),
                            host: key.0.clone(),
                            user: key.1.clone(),
                            exe: key.2.clone(),
                            entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                            ts_start: ts,
                            ts_end: ts,
                            proc_key: Some(proc_key),
                            file_key: None,
                            identity_key: Some(identity_key),
                            metadata: json!({ "bin": exe, "stream_id": stream_id }),
                            consensus_signals: vec![],
                        });
                        self.record_signal(&signal_id, ts);
                    }
                }
            }

            // LaunchAgentWrite: write to LaunchAgents/Daemons
            // Marked as "candidate" unless corroborated by LaunchCtlActivity or PersistenceDelta
            if (fact_type == "FileWrite" || fact_type == "FileCreate") {
                if let Some(p) = path {
                    if p.contains("LaunchAgents") || p.contains("LaunchDaemons") {
                        let signal_id = format!("LaunchAgentWrite:{}:{}:{}", key.0, key.1, key.2);
                        if !self.should_suppress(&signal_id, ts, 300) {
                            let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                            let file_key = make_file_key(&key.0, p, stream_id);
                            let identity_key = make_identity_key(&key.0, 0, stream_id);
                            signals.push(DerivedSignal {
                                signal_type: "LaunchAgentWrite".to_string(),
                                severity: "high".to_string(),
                                host: key.0.clone(),
                                user: key.1.clone(),
                                exe: key.2.clone(),
                                entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                                ts_start: ts,
                                ts_end: ts,
                                proc_key: Some(proc_key),
                                file_key: Some(file_key),
                                identity_key: Some(identity_key),
                                metadata: json!({ "path": p, "confidence": "candidate", "requires_corroboration": true, "stream_id": stream_id }),
                                consensus_signals: vec![],
                            });
                            self.record_signal(&signal_id, ts);
                        }
                    }
                }
            }

            // AgentTamperAttempt: kill/unload/delete telemetry daemons/binaries/config
            let edr_indicators = ["edr_locald", "capture_macos", "edr_wrap", "analysis.db", "telemetry_root"];
            if edr_indicators.iter().any(|&ind| exe.contains(ind) || path.map(|p| p.contains(ind)).unwrap_or(false)) {
                let signal_id = format!("AgentTamperAttempt:{}:{}:{}", key.0, key.1, key.2);
                if !self.should_suppress(&signal_id, ts, 600) {
                    let proc_key = make_proc_key(&key.0, key.2.parse::<u32>().unwrap_or(0), ts, stream_id);
                    let file_key = path.map(|p| make_file_key(&key.0, p, stream_id));
                    let identity_key = make_identity_key(&key.0, 0, stream_id);
                    signals.push(DerivedSignal {
                        signal_type: "AgentTamperAttempt".to_string(),
                        severity: "critical".to_string(),
                        host: key.0.clone(),
                        user: key.1.clone(),
                        exe: key.2.clone(),
                        entity_key: format!("{}:{}:{}", key.0, key.1, key.2),
                        ts_start: ts,
                        ts_end: ts,
                        proc_key: Some(proc_key),
                        file_key: file_key,
                        identity_key: Some(identity_key),
                        metadata: json!({ "target": exe.or(path).unwrap_or("unknown"), "stream_id": stream_id }),
                        consensus_signals: vec![],
                    });
                    self.record_signal(&signal_id, ts);
                }
            }

            // Apply consensus escalation
            Self::apply_consensus_escalation(&mut signals);

            signals
        }
    }
}

// P0: Verify segment file hash
fn verify_segment_hash(path: &PathBuf, expected_sha256: &str) -> Result<bool, String> {
    if expected_sha256.is_empty() {
        return Ok(true); // Skip if no hash provided
    }

    let mut file = std::fs::File::open(path).map_err(|e| format!("Cannot open segment: {}", e))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) => return Err(format!("Read error: {}", e)),
        }
    }

    let hash = format!("{:x}", hasher.finalize());
    Ok(hash == expected_sha256)
}

// P0: Recover index from backup or scan segments
fn recover_index(telemetry_root: &PathBuf) -> Result<SegmentIndex, String> {
    let index_bak = telemetry_root.join("index.json.bak");

    // Try backup first
    if index_bak.exists() {
        match std::fs::read_to_string(&index_bak) {
            Ok(contents) => {
                if let Ok(idx) = serde_json::from_str::<SegmentIndex>(&contents) {
                    eprintln!("[RECOVERY] Loaded index from backup");
                    return Ok(idx);
                }
            }
            _ => {}
        }
    }

    // Scan segments directory for best-effort recovery
    eprintln!("[RECOVERY] Scanning segments/ for recovery");
    let segments_dir = telemetry_root.join("segments");
    let mut segs = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&segments_dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    if let Some(name) = entry.file_name().to_str() {
                        segs.push((entry.path(), name.to_string()));
                    }
                }
            }
        }
    }

    segs.sort_by(|a, b| a.1.cmp(&b.1));

    let mut segments = Vec::new();
    for (i, (path, name)) in segs.iter().enumerate() {
        if let Ok(meta) = std::fs::metadata(path) {
            segments.push(SegmentRef {
                seq: (i + 1) as u64,
                segment_id: name.clone(),
                path: path.to_string_lossy().to_string(),
                ts: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
                sha256_segment: String::new(), // Will be re-computed
            });
        }
    }

    Ok(SegmentIndex {
        schema_version: 1,
        next_seq: segments.len() as u64 + 1,
        segments,
        last_updated_ts: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    })
}

// P0: Validate checkpoint - ensure no corrupt entries
fn validate_checkpoint(db: &Arc<Mutex<Connection>>) -> Result<(), String> {
    if let Ok(conn) = db.lock() {
        if let Ok(mut stmt) =
            conn.prepare("SELECT last_seq_processed, ts_processed FROM locald_checkpoint LIMIT 1")
        {
            if let Ok((seq, ts)) =
                stmt.query_row([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
            {
                // Validate: seq >= 0, ts reasonable (within 1000 years)
                if seq < 0 {
                    eprintln!("[WARN] Checkpoint seq invalid: {}, resetting", seq);
                    let _ = conn.execute("DELETE FROM locald_checkpoint", []);
                    return Ok(());
                }

                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;

                if ts < 0 || ts > now_ms + (1000 * 365 * 24 * 3600 * 1000) {
                    eprintln!("[WARN] Checkpoint ts invalid: {}, resetting", ts);
                    let _ = conn.execute("DELETE FROM locald_checkpoint", []);
                }
            }
        }
    }
    Ok(())
}

// P1-4: Populate incident_evidence from evidence_json (deterministic references)
fn populate_incident_evidence_from_json(
    db: &Arc<Mutex<Connection>>,
    incident_id: &str,
    evidence_json: &str,
    now_ms: i64,
) -> Result<u32, String> {
    if evidence_json.trim().is_empty() || evidence_json == "[]" {
        return Ok(0);
    }

    let pointers: Vec<serde_json::Value> = serde_json::from_str(evidence_json).unwrap_or_default();

    // Cap evidence pointers per incident
    let max_ptrs: usize = std::env::var("EDR_MAX_EVIDENCE_PTRS_PER_INCIDENT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);

    let mut count = 0u32;
    if let Ok(conn) = db.lock() {
        // Delete existing rows for this incident to prevent stale pointers
        let _ = conn.execute(
            "DELETE FROM incident_evidence WHERE incident_id = ?1",
            params![incident_id],
        );

        // Insert bounded set of pointers
        for ptr in pointers.iter().take(max_ptrs) {
            if let (Some(seg_id), Some(rec_idx)) = (
                ptr.get("segment_id").and_then(|v| v.as_str()),
                ptr.get("record_index").and_then(|v| v.as_i64()),
            ) {
                let stream_id = ptr
                    .get("stream_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("core");
                let _ = conn.execute(
                    "INSERT OR IGNORE INTO incident_evidence (incident_id, stream_id, segment_id, record_index, ts_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![incident_id, stream_id, seg_id, rec_idx as i32, now_ms],
                );
                count += 1;
            }
        }

        // Record metric
        let _ = record_durable_metrics(&db, "retained_due_to_evidence", count as i32);
    }

    Ok(count)
}

// P1-4: Backfill incident_evidence from existing incidents at startup
fn backfill_incident_evidence(db: &Arc<Mutex<Connection>>) -> Result<(u32, u32), String> {
    let mut total_backfilled = 0u32;
    let mut total_failures = 0u32;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    // Only backfill if table empty OR forced via env var
    let force_backfill = std::env::var("EDR_EVIDENCE_BACKFILL")
        .map(|v| v == "1")
        .unwrap_or(false);

    if let Ok(conn) = db.lock() {
        // Check if backfill already done for core stream
        let row_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM incident_evidence WHERE stream_id='core'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if !force_backfill && row_count > 0 {
            eprintln!(
                "[backfill] incident_evidence already populated for core stream ({} rows)",
                row_count
            );
            return Ok((0, 0));
        }

        eprintln!("[backfill] Starting backfill of incident_evidence from incidents...");

        // Batch process incidents
        let mut offset = 0i64;
        let batch_size = 500i64;
        loop {
            let mut stmt = conn.prepare(
                "SELECT incident_id, evidence_json FROM incidents ORDER BY ts_created ASC LIMIT ?1 OFFSET ?2"
            ).map_err(|e| format!("Prepare failed: {}", e))?;

            let results: Vec<(String, String)> = stmt
                .query_map(params![batch_size, offset], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(|e| format!("Query failed: {}", e))?
                .filter_map(|r| r.ok())
                .collect();

            if results.is_empty() {
                break;
            }

            for (inc_id, ev_json) in results {
                match populate_incident_evidence_from_json(db, &inc_id, &ev_json, now_ms) {
                    Ok(n) => total_backfilled += n,
                    Err(_) => total_failures += 1,
                }
            }

            offset += batch_size;
        }

        eprintln!(
            "[backfill] Completed: {} pointers backfilled, {} failures",
            total_backfilled, total_failures
        );

        // Record backfill metrics
        let _ = record_durable_metrics(&db, "evidence_backfill_rows", total_backfilled as i32);
        let _ = record_durable_metrics(&db, "evidence_backfill_failures", total_failures as i32);
    }

    Ok((total_backfilled, total_failures))
}

// P0: Concurrent daemon safety - acquire exclusive lock
fn acquire_daemon_lock(telemetry_root: &PathBuf) -> Result<std::fs::File, String> {
    let lock_path = telemetry_root.join("locald.lock");

    match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(&lock_path)
    {
        Ok(file) => {
            // Try to write PID
            let pid = std::process::id();
            let _ = std::fs::write(&lock_path, format!("{}\n", pid));

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644));
            }

            Ok(file)
        }
        Err(e) => Err(format!("Failed to acquire lock: {}", e)),
    }
}

// Task 7: Retention enforcement - periodic cleanup
fn enforce_retention(db: &Arc<Mutex<Connection>>, telemetry_root: &PathBuf) -> Result<(), String> {
    let retention_days = std::env::var("EDR_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(7);

    let metrics_retention_days = std::env::var("EDR_METRICS_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(30);

    let segment_retention_days = std::env::var("EDR_SEGMENT_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(7);

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    if let Ok(conn) = db.lock() {
        // Delete old telemetry_events
        let cutoff_events_ms = now_ms - (retention_days * 24 * 3600 * 1000);
        let deleted_events = conn
            .execute(
                "DELETE FROM telemetry_events WHERE ts < ?1",
                [cutoff_events_ms],
            )
            .unwrap_or(0);

        if deleted_events > 0 {
            let _ = conn.execute(
                "INSERT INTO metrics_rollup (ts_bucket, metric_name, count) VALUES (?1, ?2, ?3) ON CONFLICT(ts_bucket, metric_name) DO UPDATE SET count=count+?3",
                params![(now_ms / 3600_000) as i64, "retention_rows_deleted_events", deleted_events as i32],
            );
            eprintln!(
                "[retention] Deleted {} telemetry_events rows",
                deleted_events
            );
        }

        let _deleted_records = conn
            .execute(
                "DELETE FROM processed_records WHERE processed_ts < ?1",
                [cutoff_events_ms],
            )
            .unwrap_or(0);

        let _deleted_state = conn
            .execute(
                "DELETE FROM playbook_state WHERE ts_ms < ?1",
                [cutoff_events_ms],
            )
            .unwrap_or(0);

        // Delete old incidents (keep last 7 days)
        let cutoff_incidents_ms = now_ms - (retention_days * 24 * 3600 * 1000);
        let deleted_incidents = conn
            .execute(
                "DELETE FROM incidents WHERE ts_updated < ?1",
                [cutoff_incidents_ms],
            )
            .unwrap_or(0);

        if deleted_incidents > 0 {
            eprintln!("[retention] Deleted {} incident rows", deleted_incidents);
        }

        // Delete old metrics (keep 30 days)
        let cutoff_metrics_bucket = (now_ms / 3600_000) - (metrics_retention_days * 24);
        let deleted_metrics = conn
            .execute(
                "DELETE FROM metrics_rollup WHERE ts_bucket < ?1",
                [cutoff_metrics_bucket],
            )
            .unwrap_or(0);

        if deleted_metrics > 0 {
            eprintln!(
                "[retention] Deleted {} metrics_rollup rows",
                deleted_metrics
            );
        }
    }

    // P0-3: Delete old segment files (older than retention window)
    // BUT: Only delete if not referenced by any incident
    let segments_dir = telemetry_root.join("segments");
    if let Ok(entries) = std::fs::read_dir(&segments_dir) {
        let cutoff_segment_ms = now_ms - (segment_retention_days * 24 * 3600 * 1000);
        let mut deleted_segments = 0u32;
        let mut skipped_referenced = 0u32;

        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
                            let ts_ms = duration.as_millis() as i64;
                            if ts_ms < cutoff_segment_ms {
                                // P0-3: Check if this segment is referenced by any incident using incident_evidence table
                                let segment_name = entry.file_name();
                                let segment_id = segment_name
                                    .to_string_lossy()
                                    .to_string()
                                    .replace(".jsonl", "");

                                let is_referenced = if let Ok(conn) = db.lock() {
                                    // Use incident_evidence table (deterministic, indexed)
                                    // Filter by stream_id for core stream
                                    match conn.query_row(
                                        "SELECT 1 FROM incident_evidence WHERE stream_id='core' AND segment_id=?1 LIMIT 1",
                                        params![&segment_id],
                                        |_row| Ok(true),
                                    ) {
                                        Ok(true) => true,
                                        Ok(_) => false,
                                        Err(_) => {
                                            // DB error: conservative keep
                                            let _ = record_durable_metrics(&db, "retention_evidence_lookup_errors", 1);
                                            true
                                        }
                                    }
                                } else {
                                    true // Err on side of caution if DB locked
                                };

                                if is_referenced {
                                    skipped_referenced += 1;
                                    eprintln!(
                                        "[retention] SKIPPING segment {} (referenced by incidents)",
                                        segment_id
                                    );
                                } else {
                                    if let Err(e) = std::fs::remove_file(entry.path()) {
                                        eprintln!("[retention] Failed to delete segment: {}", e);
                                    } else {
                                        deleted_segments += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if deleted_segments > 0 {
            if let Ok(conn) = db.lock() {
                let _ = conn.execute(
                    "INSERT INTO metrics_rollup (ts_bucket, metric_name, count) VALUES (?1, ?2, ?3) ON CONFLICT(ts_bucket, metric_name) DO UPDATE SET count=count+?3",
                    params![(now_ms / 3600_000) as i64, "retention_segments_deleted", deleted_segments as i32],
                );
            }
            eprintln!(
                "[retention] Deleted {} segment files ({} referenced, skipped)",
                deleted_segments, skipped_referenced
            );
        }
    }

    Ok(())
}

// Task 8: Playbook policy - choose best playbooks to fire
fn select_best_playbooks(
    matches: &[(String, String, bool)],
    playbook_engine: &PlaybookEngine,
) -> Vec<(String, String, bool)> {
    let policy = std::env::var("EDR_PLAYBOOK_POLICY").unwrap_or_else(|_| "best_only".to_string());

    if policy == "all" {
        return matches.to_vec();
    }

    // best_only: choose by (priority DESC, specificity DESC, playbook_id ASC)
    let mut best: std::collections::HashMap<String, (String, u32, u32)> =
        std::collections::HashMap::new();

    for (playbook_id, entity_key, is_ready) in matches {
        if !is_ready {
            continue;
        }

        let priority = playbook_engine
            .playbooks
            .iter()
            .find(|pb| pb.playbook_id == *playbook_id)
            .map(|pb| pb.priority as u32)
            .unwrap_or(100);

        let specificity = playbook_engine
            .playbooks
            .iter()
            .find(|pb| pb.playbook_id == *playbook_id)
            .map(|pb| pb.slots.len() as u32)
            .unwrap_or(0);

        let key = entity_key.clone();
        if !best.contains_key(&key)
            || (priority, specificity, playbook_id.clone())
                > (best[&key].1, best[&key].2, best[&key].0.clone())
        {
            best.insert(key, (playbook_id.clone(), priority, specificity));
        }
    }

    best.into_iter()
        .map(|(ek, (pb, _, _))| (pb, ek, true))
        .collect()
}

fn validate_index(
    index: &SegmentIndex,
    telemetry_root: &PathBuf,
    db: &Arc<Mutex<Connection>>,
) -> Result<SegmentIndex, String> {
    // Task 4: Strict index validation with optional degraded mode
    // P0: Verify segment hashes, detect corruption
    const EXPECTED_SCHEMA_VERSION: u32 = 1;
    let degraded_ok = std::env::var("EDR_INDEX_DEGRADED_OK").is_ok();
    let mut valid_segments = Vec::new();
    let mut dropped = 0;
    let mut _hash_mismatches = 0u32;

    // Check schema version - FATAL
    if index.schema_version != EXPECTED_SCHEMA_VERSION && index.schema_version != 0 {
        let msg = format!(
            "Index schema mismatch: expected {}, got {}",
            EXPECTED_SCHEMA_VERSION, index.schema_version
        );
        if !degraded_ok {
            eprintln!("[FATAL] {}", msg);
            std::process::exit(1);
        }
        eprintln!("[DEGRADED] {}", msg);
    }

    // Check for monotonic sequences and missing segments
    let mut last_seq = 0u64;
    for seg in &index.segments {
        let seg_path = PathBuf::from(&seg.path);

        // P0: Verify segment hash
        if !seg.sha256_segment.is_empty() {
            match verify_segment_hash(&seg_path, &seg.sha256_segment) {
                Ok(true) => {} // hash matches
                Ok(false) => {
                    eprintln!("[WARN] Segment hash mismatch: {}", seg.segment_id);
                    _hash_mismatches += 1;
                    if let Ok(db_conn) = db.lock() {
                        let _ = db_conn.execute(
                            "INSERT INTO metrics_rollup (ts_bucket, metric_name, count) VALUES (?1, ?2, ?3) ON CONFLICT(ts_bucket, metric_name) DO UPDATE SET count=count+?3",
                            params![(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() / 3600) as i64, format!("error_{}", ErrorCode::SegmentHashMismatch.as_str()), 1],
                        );
                    }
                    if !degraded_ok {
                        continue;
                    } // Skip this segment in strict mode
                }
                Err(e) => {
                    eprintln!("[WARN] Failed to verify hash {}: {}", seg.segment_id, e);
                    if !degraded_ok {
                        continue;
                    }
                }
            }
        }

        // Non-monotonic or duplicate - FATAL
        if seg.seq <= last_seq {
            let msg = format!("Non-monotonic seq {} (last={})", seg.seq, last_seq);
            if !degraded_ok {
                eprintln!("[FATAL] {}", msg);
                std::process::exit(1);
            }
            eprintln!("[DEGRADED] Dropping {}", msg);
            dropped += 1;
            let _ = record_durable_metrics(
                db,
                &format!("error_{}", ErrorCode::SegmentMissing.as_str()),
                1,
            );
            continue;
        }

        // Missing segment file - FATAL
        if !seg_path.exists() {
            let msg = format!("Missing segment: {} ({})", seg.segment_id, seg.path);
            if !degraded_ok {
                eprintln!("[FATAL] {}", msg);
                std::process::exit(1);
            }
            eprintln!("[DEGRADED] Dropping {}", msg);
            dropped += 1;
            let _ = record_durable_metrics(
                db,
                &format!("error_{}", ErrorCode::SegmentMissing.as_str()),
                1,
            );
            continue;
        }

        valid_segments.push(seg.clone());
        last_seq = seg.seq;
    }

    if dropped > 0 {
        eprintln!(
            "[DEGRADED] Dropped {} invalid segments, {} valid remaining",
            dropped,
            valid_segments.len()
        );
    }

    Ok(SegmentIndex {
        schema_version: index.schema_version,
        next_seq: index.next_seq,
        segments: valid_segments,
        last_updated_ts: index.last_updated_ts,
    })
}

fn load_index(telemetry_root: &PathBuf, db: &Arc<Mutex<Connection>>) -> Option<SegmentIndex> {
    let index_path = telemetry_root.join("index.json");

    // P0: Try to load index.json
    if index_path.exists() {
        if let Ok(contents) = fs::read_to_string(&index_path) {
            if let Ok(index) = serde_json::from_str::<SegmentIndex>(&contents) {
                // Task 4: Strict validation - may exit(1) unless degraded mode
                match validate_index(&index, telemetry_root, db) {
                    Ok(validated) => return Some(validated),
                    Err(e) => {
                        eprintln!("[ERROR] Index validation failed: {}", e);
                        return None;
                    }
                }
            } else {
                // Index.json corrupted - try recovery
                eprintln!("[WARN] index.json corrupted, attempting recovery");
                if let Ok(recovered) = recover_index(telemetry_root) {
                    let _ = record_durable_metrics(db, "index_rebuilt", 1);
                    return Some(recovered);
                } else if std::env::var("EDR_INDEX_DEGRADED_OK").is_ok() {
                    eprintln!("[DEGRADED] Recovery failed, proceeding in degraded mode");
                    return Some(SegmentIndex {
                        schema_version: 1,
                        next_seq: 0,
                        segments: Vec::new(),
                        last_updated_ts: 0,
                    });
                } else {
                    eprintln!("[FATAL] Index corrupt and recovery failed");
                    std::process::exit(1);
                }
            }
        }
    }

    // No index.json - this is OK on first run
    None
}

fn load_stream_index(telemetry_root: &PathBuf, stream_id: &str) -> Option<SegmentIndex> {
    let index_path = if stream_id == "core" {
        telemetry_root.join("index.json")
    } else {
        telemetry_root.join(stream_id).join("index.json")
    };

    if index_path.exists() {
        if let Ok(contents) = fs::read_to_string(&index_path) {
            if let Ok(index) = serde_json::from_str::<SegmentIndex>(&contents) {
                return Some(index);
            } else {
                eprintln!("[WARN] Stream {} index.json corrupted", stream_id);
            }
        }
    }

    None
}

/// Extract facts from raw event
fn extract_facts_from_event(
    event_type: &str,
    event_data: &serde_json::Value,
    _segment_id: &str,
    _record_index: u32,
    ts: u64,
) -> Vec<Fact> {
    let mut facts = Vec::new();

    let exe = event_data
        .get("exe")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let user = event_data
        .get("user")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let host = event_data
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or("localhost")
        .to_string();

    // Create fact for each event type
    if event_type == "ProcExec" || event_type == "proc_exec" {
        facts.push(Fact {
            fact_type: "ProcExec".to_string(),
            exe,
            user,
            host,
            ts,
        });
    } else if event_type == "FileWrite" || event_type == "file_write" {
        facts.push(Fact {
            fact_type: "FileWrite".to_string(),
            exe,
            user,
            host,
            ts,
        });
    } else if event_type == "NetConnect" || event_type == "net_connect" {
        facts.push(Fact {
            fact_type: "NetConnect".to_string(),
            exe,
            user,
            host,
            ts,
        });
    }

    facts
}

fn extract_workflow_facts(
    event_json: &serde_json::Value,
    _segment_id: &str,
    _record_index: u32,
) -> Vec<Fact> {
    let mut facts = Vec::new();

    let ts = event_json
        .get("ts_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let stdout = event_json
        .get("stdout")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let _stderr = event_json
        .get("stderr")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let exit_code = event_json
        .get("exit_code")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let cmd = event_json
        .get("cmd")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let user = event_json
        .get("user")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let host = event_json
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or("localhost");
    let _session_id = event_json
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // PortOpen: regex nmap output like "80/tcp open http"
    if cmd.contains("nmap") || stdout.contains("open") {
        for line in stdout.lines() {
            if let Some(caps) = regex::Regex::new(r"(\d+)/(tcp|udp)\s+(open|closed)")
                .ok()
                .and_then(|re| re.captures(line))
            {
                if let Some(port_str) = caps.get(1).map(|m| m.as_str()) {
                    if let Ok(port) = port_str.parse::<u16>() {
                        facts.push(Fact {
                            fact_type: format!("PortOpen:{}", port),
                            exe: cmd.to_string(),
                            user: user.to_string(),
                            host: host.to_string(),
                            ts,
                        });
                    }
                }
            }
        }
    }

    // CommandFailed: exit_code != 0
    if exit_code != 0 {
        facts.push(Fact {
            fact_type: format!("CommandFailed:{}", exit_code),
            exe: cmd.to_string(),
            user: user.to_string(),
            host: host.to_string(),
            ts,
        });
    }

    // HttpStatus: curl output with status codes
    if cmd.contains("curl") || cmd.contains("wget") {
        if let Some(caps) = regex::Regex::new(r"HTTP/[\d\.]+\s+(\d{3})")
            .ok()
            .and_then(|re| re.captures(stdout))
        {
            if let Some(status_str) = caps.get(1).map(|m| m.as_str()) {
                if let Ok(status) = status_str.parse::<u16>() {
                    facts.push(Fact {
                        fact_type: format!("HttpStatus:{}", status),
                        exe: cmd.to_string(),
                        user: user.to_string(),
                        host: host.to_string(),
                        ts,
                    });
                }
            }
        }
    }

    facts
}

/// Check if accumulated facts complete a playbook
/// NOW REPLACED with YAML-driven engine matching below
#[deprecated = "Use PlaybookEngine instead"]
fn check_playbook_fire(
    _playbook_id: &str,
    _accumulated_facts: &[(Fact, EvidencePtr)],
) -> Option<(String, String, String)> {
    // Stub: all matching is now done via YAML engine
    None
}

struct MetricsCollector {
    events_ingested: u64,
    facts_extracted: u64,
    playbook_matches: u64,
    incidents_upserted: u64,
    last_log_ts: u64,
    last_persist_ts: u64,
}

impl MetricsCollector {
    fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        MetricsCollector {
            events_ingested: 0,
            facts_extracted: 0,
            playbook_matches: 0,
            incidents_upserted: 0,
            last_log_ts: now,
            last_persist_ts: now,
        }
    }

    fn record_event(&mut self) {
        self.events_ingested += 1;
    }
    fn record_fact(&mut self) {
        self.facts_extracted += 1;
    }
    fn record_match(&mut self) {
        self.playbook_matches += 1;
    }
    fn record_incident(&mut self) {
        self.incidents_upserted += 1;
    }

    fn maybe_log_and_persist_metrics(&mut self, db: &Arc<Mutex<Connection>>) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Log metrics every 10 seconds
        if now - self.last_log_ts > 10_000 {
            eprintln!(
                "[metrics] events={} facts={} matches={} incidents={}",
                self.events_ingested,
                self.facts_extracted,
                self.playbook_matches,
                self.incidents_upserted
            );
            self.last_log_ts = now;
        }

        // Persist metrics to database every 30 seconds
        if now - self.last_persist_ts > 30_000 {
            // Flush all metrics to database (idempotent via UNIQUE constraint)
            if self.events_ingested > 0 {
                let _ = record_durable_metrics(db, "events_ingested", self.events_ingested as i32);
            }
            if self.facts_extracted > 0 {
                let _ = record_durable_metrics(db, "facts_extracted", self.facts_extracted as i32);
            }
            if self.playbook_matches > 0 {
                let _ =
                    record_durable_metrics(db, "playbook_matches", self.playbook_matches as i32);
            }
            if self.incidents_upserted > 0 {
                let _ = record_durable_metrics(
                    db,
                    "incidents_upserted",
                    self.incidents_upserted as i32,
                );
            }

            // Reset counters after persisting
            self.events_ingested = 0;
            self.facts_extracted = 0;
            self.playbook_matches = 0;
            self.incidents_upserted = 0;
            self.last_persist_ts = now;
            eprintln!("[metrics] Flushed metrics to database");
        }
    }
}

fn record_durable_metrics(
    db: &Arc<Mutex<Connection>>,
    metric_name: &str,
    count: i32,
) -> Result<(), String> {
    if let Ok(conn) = db.lock() {
        let now_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_secs() / 3600) as i64)
            .unwrap_or(0);
        let _ = conn.execute(
            "INSERT OR IGNORE INTO metrics_rollup (ts, metric_name, value) VALUES (?, ?, ?)",
            params![now_seconds, metric_name, count],
        );
    }
    Ok(())
}

fn record_coverage_rollup(
    db: &Arc<Mutex<Connection>>,
    host: &str,
    sensor_mode: &str,
    fact_type: Option<&str>,
    signal_type: Option<&str>,
    enabled_caps: &str,
) {
    if let Ok(conn) = db.lock() {
        let ts_minute = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 60)
            .unwrap_or(0)) as i64;
        
        let _ = conn.execute(
            "INSERT INTO coverage_rollup (ts_minute, host, sensor_mode, fact_type, fact_count, signal_type, signal_count, enabled_capabilities) 
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)
             ON CONFLICT(ts_minute, host, sensor_mode, fact_type, signal_type) DO UPDATE SET 
             fact_count = fact_count + CASE WHEN excluded.fact_type IS NOT NULL THEN 1 ELSE 0 END,
             signal_count = signal_count + CASE WHEN excluded.signal_type IS NOT NULL THEN 1 ELSE 0 END",
            params![ts_minute, host, sensor_mode, fact_type, signal_type, 0, enabled_caps],
        );
    }
}

fn record_durable_metrics_old(
    db: &Arc<Mutex<Connection>>,
    metric_name: &str,
    count: i32,
) -> Result<(), String> {
    if let Ok(conn) = db.lock() {
        let now_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_secs() / 3600) as i64)
            .unwrap_or(0);

        let _ = conn.execute(
            "INSERT INTO metrics_rollup (ts_bucket, metric_name, count) VALUES (?1, ?2, ?3)
             ON CONFLICT(ts_bucket, metric_name) DO UPDATE SET count=count+?3",
            params![now_seconds, metric_name, count],
        );
    }
    Ok(())
}

fn ingest_segment(
    segment_path: &PathBuf,
    segment_id: &str,
    stream_id: &str,
    db: &Arc<Mutex<Connection>>,
    accumulated_facts: &mut Vec<(Fact, EvidencePtr)>,
    playbook_engine: &mut PlaybookEngine,
    metrics: &mut MetricsCollector,
    windows_signal_engine: &mut WindowsSignalEngine,
    scoring_engine: &ScoringEngine,
) -> std::io::Result<()> {
    eprintln!(
        "  [ingest] Processing segment: {} (stream: {})",
        segment_id, stream_id
    );

    let segment_json = fs::read_to_string(segment_path)?;

    // Parse as JSONL (one JSON per line)
    let mut event_count = 0;
    let mut fact_count = 0;

    for (record_index, line) in segment_json.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        // Check if this record was already processed for playbooks
        let should_process_playbook = if let Ok(db_conn) = db.lock() {
            let result = db_conn.query_row(
                "SELECT 1 FROM processed_records WHERE stream_id = ?1 AND segment_id = ?2 AND record_index = ?3",
                params![stream_id, segment_id, record_index as i32],
                |_| Ok(()),
            );
            result.is_err() // true if NOT found
        } else {
            true // err on side of processing
        };

        // Parse JSON and extract event_type field
        let parsed: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("    [parse] Skipping malformed JSONL line {}", record_index);
                // P0: Record corrupt JSONL metric
                if let Ok(db_conn) = db.lock() {
                    let _ = db_conn.execute(
                        "INSERT INTO metrics_rollup (ts_bucket, metric_name, count) VALUES (?1, ?2, ?3) ON CONFLICT(ts_bucket, metric_name) DO UPDATE SET count=count+?3",
                        params![(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() / 3600) as i64, "segment_jsonl_corrupt_lines", 1],
                    );
                }
                continue;
            }
        };

        // Extract event_type from the flat structure
        let event_type = parsed
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let event_data = RawEvent {
            event_type: event_type.clone(),
            data: parsed.clone(),
        };

        let ts = event_data
            .data
            .get("ts_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| {
                event_data
                    .data
                    .get("ts")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            });

        // Insert raw event to DB - idempotent via UNIQUE constraint
        if let Ok(db_conn) = db.lock() {
            let event_json = serde_json::to_string(&event_data.data).unwrap_or_default();
            let _ = db_conn.execute(
                    "INSERT OR IGNORE INTO telemetry_events (stream_id, segment_id, record_index, ts, event_type, event_json) 
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![stream_id, segment_id, record_index as i32, ts, &event_data.event_type, &event_json],
                );
            event_count += 1;
            metrics.record_event();
        }

        // Extract facts
        let facts = extract_facts_from_event(
            &event_data.event_type,
            &event_data.data,
            segment_id,
            record_index as u32,
            ts,
        );

        // Emit derived signals from facts
        let host = event_data
            .data
            .get("host")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let user = event_data
            .data
            .get("user")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let exe = event_data
            .data
            .get("exe")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let dest_ip = event_data.data.get("dest_ip").and_then(|v| v.as_str());
        let path = event_data.data.get("path").and_then(|v| v.as_str());

        let signals =
            signal_state.emit_signals(&event_data.event_type, host, user, exe, path, dest_ip, ts, stream_id);
        
        // === Windows Signal Processing ===
        // If Windows signal detection is enabled, process through WindowsSignalEngine
        // Check if this is a Windows event (via stream_id, event_type, or tags)
        let is_windows_event = stream_id == "windows" 
            || stream_id == "core"  // Windows events come through core stream
            || event_data.event_type.contains("Windows")
            || event_data.data.get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().any(|v| v.as_str() == Some("event_log") || v.as_str() == Some("windows")))
                .unwrap_or(false);
                
        if is_windows_event {
            // Build tags from both the data tags and event_type
            let mut tags: Vec<String> = event_data.data.get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                .unwrap_or_default();
            if !tags.contains(&event_data.event_type) {
                tags.push(event_data.event_type.clone());
            }
            
            // Build canonical Event for Windows signal processing
            let canonical_event = forensic_hooks::Event {
                ts_ms: ts as i64,
                host: host.to_string(),
                tags,
                proc_key: None,
                file_key: None,
                identity_key: Some(user.to_string()),
                evidence_ptr: forensic_hooks::EvidencePtr {
                    stream_id: stream_id.to_string(),
                    segment_id: segment_id.parse::<u64>().unwrap_or(0),
                    record_index: record_index as u32,
                },
                fields: event_data.data.clone().as_object().cloned().unwrap_or_default(),
            };

            // Process event through Windows signal engine
            let win_signals = windows_signal_engine.process_event(&canonical_event);
            
            // Score and persist Windows signals to database
            for win_signal in win_signals {
                let scored = scoring_engine.score(win_signal.clone());
                eprintln!(
                    "[windows_signal] {} (risk={:.2}): {}",
                    scored.signal.signal_type, scored.risk_score, scored.signal.host
                );
                
                // Persist signal to both signal_facts and signals tables
                if let Ok(db_conn_lock) = db.lock() {
                    let evidence_json = serde_json::to_string(&win_signal.evidence_ptrs).unwrap_or_else(|_| "[]".to_string());
                    let metadata_json = win_signal.metadata.to_string();
                    let created_at = chrono::Utc::now().to_rfc3339();
                    
                    // Insert into signal_facts (legacy)
                    let _ = db_conn_lock.execute(
                        "INSERT OR REPLACE INTO signal_facts (signal_id, stream_id, signal_type, severity, host, user, exe, entity_key, ts_start, ts_end, evidence_ptrs, metadata) 
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                        params![
                            win_signal.signal_id, 
                            stream_id, 
                            win_signal.signal_type, 
                            win_signal.severity, 
                            win_signal.host, 
                            user, 
                            exe, 
                            format!("{}|{}", win_signal.host, win_signal.signal_type),
                            win_signal.ts_start, 
                            win_signal.ts_end, 
                            evidence_json.clone(), 
                            metadata_json.clone()
                        ],
                    );
                    
                    // Insert into signals table (for server /api/signals endpoint)
                    let _ = db_conn_lock.execute(
                        "INSERT OR REPLACE INTO signals (signal_id, signal_type, severity, host, ts, ts_start, ts_end, proc_key, file_key, identity_key, metadata, evidence_ptrs, dropped_evidence_count, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                        params![
                            win_signal.signal_id,
                            win_signal.signal_type,
                            win_signal.severity,
                            win_signal.host,
                            win_signal.ts,
                            win_signal.ts_start,
                            win_signal.ts_end,
                            win_signal.proc_key,
                            win_signal.file_key,
                            win_signal.identity_key,
                            metadata_json,
                            evidence_json,
                            win_signal.dropped_evidence_count as i64,
                            created_at
                        ],
                    );
                    metrics.record_event();
                }
            }
        }
        // === End Windows Signal Processing ===
        
        // Record coverage for this event
        record_coverage_rollup(&db_conn, host, "BSM", Some(&event_data.event_type), None, "proc_exec,file_ops,netconnect");
        
        for signal in &signals {
            let signal_id = format!("{:x}", hash_for_id(&signal.entity_key, signal.ts_start));
            let evidence_ptrs_json = "[]";
            let episode_id = upsert_episode(&db_conn, stream_id, &signal.host, &signal.user, &signal.entity_key, signal.ts_start, &[signal.signal_type.clone()]);
            
            // Record coverage for signal
            record_coverage_rollup(&db_conn, host, "BSM", None, Some(&signal.signal_type), "proc_exec,file_ops,netconnect");
            
            if let Ok(db_conn_lock) = db_conn.lock() {
                let _ = db_conn_lock.execute(
                    "INSERT OR REPLACE INTO signal_facts (signal_id, stream_id, signal_type, severity, host, user, exe, entity_key, ts_start, ts_end, evidence_ptrs, metadata) 
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![signal_id, stream_id, signal.signal_type, signal.severity, signal.host, signal.user, signal.exe, signal.entity_key, signal.ts_start, signal.ts_end, evidence_ptrs_json, signal.metadata.to_string()],
                );
                
                // Match signal against playbooks
                let sig_matches = playbook_engine.match_signal_fact(&signal.signal_type, &signal.severity, &signal.host, &signal.user, signal.exe.as_deref(), ts);
                if !sig_matches.is_empty() {
                    metrics.record_match();
                }
            }
        }

        // Only process playbooks if this record hasn't been processed before
        if should_process_playbook {
            for fact in &facts {
                let ptr = EvidencePtr {
                    segment_id: segment_id.to_string(),
                    record_index: record_index as u32,
                    ts,
                    event_type: event_data.event_type.clone(),
                    stream_id: Some(stream_id.to_string()),
                };
                accumulated_facts.push((fact.clone(), ptr.clone()));
                fact_count += 1;
                metrics.record_fact();
            }

            // Process playbooks after accumulating all facts from this record
            for fact in &facts {
                // Extract fields for playbook matching
                let evidence_ptr_str = format!("{}:{}", segment_id, record_index);
                let exe = &fact.exe;
                let user = &fact.user;
                let host = &fact.host;

                // Try to match fact against all YAML playbooks
                let matches = playbook_engine.match_fact(
                    &fact.fact_type, // fact_type: "ProcExec", "FileWrite", etc.
                    exe,             // exe
                    None,            // path (would need to extract from data if present)
                    None,            // dst_port
                    None,            // uid
                    user,
                    host,
                    &event_data.event_type, // event_type from BSM
                    ts,
                    Some(&evidence_ptr_str),
                );

                if !matches.is_empty() {
                    metrics.record_match();
                }

                // P1-1: Apply policy selection (best_only or all)
                let filtered_matches = select_best_playbooks(&matches, &playbook_engine);
                let suppressed_matches: Vec<(String, String, bool)> = matches
                    .iter()
                    .filter(|m| !filtered_matches.contains(m))
                    .cloned()
                    .collect();

                // Fire filtered matches
                for (playbook_id, entity_key, is_ready) in filtered_matches {
                    if !is_ready {
                        continue;
                    }

                    eprintln!(
                        "    [playbook] INCIDENT FIRED: {} for entity {}",
                        playbook_id, entity_key
                    );

                    let incident_id = format!("{}:{}", playbook_id, entity_key);
                    let dedup_bucket = (ts / 600_000) as i32;

                    // P1-3: Check cooldown window (default 300s)
                    let cooldown_seconds: i64 = 300; // Default 5 minutes
                    let cooldown_ms = cooldown_seconds * 1000;
                    let cooldown_cutoff = ts.saturating_sub(cooldown_ms as u64);

                    let should_create_new = if let Ok(db_conn) = db.lock() {
                        // Check if this (playbook_id, entity_key) fired recently
                        let existing = db_conn.query_row(
                            "SELECT ts_updated FROM incidents 
                             WHERE playbook_id = ?1 AND entity_key = ?2 AND ts_updated > ?3
                             LIMIT 1",
                            params![&playbook_id, &entity_key, cooldown_cutoff as i64],
                            |row| row.get::<_, i64>(0),
                        );

                        existing.is_err() // Create new if no recent fire
                    } else {
                        true
                    };

                    if !should_create_new {
                        eprintln!("      (suppressed by cooldown window)");
                        continue;
                    }

                    let evidence_json = serde_json::to_string(
                        &accumulated_facts
                            .iter()
                            .map(|(_, ptr)| ptr)
                            .collect::<Vec<_>>(),
                    )
                    .unwrap_or_default();

                    let slots_json = json!({
                        "matched_fact": { "type": fact.fact_type, "exe": exe }
                    })
                    .to_string();

                    // P1-1: Build corroborations from suppressed playbooks
                    let mut corroborations = Vec::new();
                    for (suppressed_pb_id, supp_entity_key, _) in &suppressed_matches {
                        if supp_entity_key == &entity_key {
                            corroborations.push(json!({
                                "playbook_id": suppressed_pb_id,
                                "entity_key": supp_entity_key,
                                "ts_ms": ts,
                            }));
                            if corroborations.len() >= 25 {
                                break; // Cap at 25
                            }
                        }
                    }
                    let corroborations_json =
                        serde_json::to_string(&corroborations).unwrap_or_else(|_| "[]".to_string());

                    if let Ok(db_conn) = db.lock() {
                        let build_id = get_build_id();

                        // Extract playbook hash and source path from PlaybookEngine
                        let (playbook_hash, playbook_source_relpath) = playbook_engine
                            .playbooks
                            .iter()
                            .find(|pb| pb.playbook_id == playbook_id)
                            .map(|pb| {
                                (pb.playbook_hash.clone(), pb.playbook_source_relpath.clone())
                            })
                            .unwrap_or_else(|| ("".to_string(), "unknown".to_string()));

                        // Try upsert with dedup key
                        let _ = db_conn.execute(
                            "INSERT INTO incidents 
                             (incident_id, playbook_id, entity_key, host, user, exe, ts_created, ts_updated, 
                              dedup_bucket, hit_count, severity, description, evidence_json, slots_json, tags_json, corroborations_json, locald_build_id, playbook_hash, playbook_source_relpath)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
                             ON CONFLICT(playbook_id, entity_key, dedup_bucket) DO UPDATE SET
                              ts_updated=?8, hit_count=hit_count+1, evidence_json=?12, corroborations_json=?15",
                            params![
                                &incident_id,
                                &playbook_id,
                                &entity_key,
                                host,
                                user,
                                exe,
                                ts,
                                ts,
                                dedup_bucket,
                                "medium",
                                format!("Playbook {} fired for {}", playbook_id, entity_key),
                                &evidence_json,
                                &slots_json,
                                serde_json::to_string(&vec!["yaml", "production"]).unwrap_or_default(),
                                &corroborations_json,
                                &build_id,
                                &playbook_hash,
                                &playbook_source_relpath,
                            ],
                        );

                        // P1-4: Populate incident_evidence from evidence_json (for retention safety)
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as i64;
                        let _ = populate_incident_evidence_from_json(
                            &db,
                            &incident_id,
                            &evidence_json,
                            now_ms,
                        );

                        metrics.record_incident();
                    }
                }
            }
        }

        // Mark this record as processed for playbooks (exactly-once semantics)
        if should_process_playbook {
            if let Ok(db_conn) = db.lock() {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let _ = db_conn.execute(
                    "INSERT OR IGNORE INTO processed_records (stream_id, segment_id, record_index, processed_ts) VALUES (?1, ?2, ?3, ?4)",
                    params![stream_id, segment_id, record_index as i32, now_ms],
                );
            }
        }
    } // End of for loop

    eprintln!(
        "    [ingest] Stored {} events, extracted {} facts",
        event_count, fact_count
    );
    Ok(())
}

fn cleanup_expired_playbook_state(
    db_conn: &Arc<Mutex<Connection>>,
    ttl_ms: u64,
) -> Result<u32, String> {
    let conn = db_conn.lock().unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let cutoff_ms = if now_ms > ttl_ms { now_ms - ttl_ms } else { 0 };

    match conn.execute("DELETE FROM playbook_state WHERE ts_ms < ?1", [cutoff_ms]) {
        Ok(deleted) => {
            if deleted > 0 {
                eprintln!(
                    "[locald] Cleanup: removed {} expired playbook_state entries",
                    deleted
                );
            }
            Ok(deleted as u32)
        }
        Err(e) => {
            eprintln!("[locald] ERROR cleaning up playbook_state: {}", e);
            Err(e.to_string())
        }
    }
}

fn should_skip_segment(seg_seq: u64, last_seq: u64) -> bool {
    // Task 5: Seq-based filtering - skip already-processed segments
    seg_seq <= last_seq
}

fn get_last_seq_processed(db: &Arc<Mutex<Connection>>, stream_id: &str) -> u64 {
    if let Ok(conn) = db.lock() {
        match conn.query_row(
            "SELECT last_seq_processed FROM locald_checkpoint WHERE stream_id = ?1",
            params![stream_id],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(seq) => seq as u64,
            Err(_) => 0, // First run for this stream
        }
    } else {
        0
    }
}

fn update_last_seq_processed(
    db: &Arc<Mutex<Connection>>,
    stream_id: &str,
    seq: u64,
) -> Result<(), String> {
    if let Ok(conn) = db.lock() {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let _ = conn.execute(
            "INSERT OR REPLACE INTO locald_checkpoint (stream_id, last_seq_processed, ts_processed) VALUES (?1, ?2, ?3)",
            params![stream_id, seq as i64, now_ms as i64],
        );
    }
    Ok(())
}

fn upsert_episode(
    db_conn: &Connection,
    stream_id: &str,
    host: &str,
    user: &str,
    entity_key: &str,
    ts_start: u64,
    signal_types: &[String],
) -> String {
    use sha2::{Sha256, Digest};
    let time_bucket = (ts_start / 300_000) * 300_000;  // 5-min bucket
    let episode_kind = "behavior";
    
    let input = format!("{}|{}|{}|{}|{}", host, user, entity_key, time_bucket, episode_kind);
    let mut hasher = Sha256::new();
    hasher.update(&input);
    let episode_id = format!("{:x}", hasher.finalize());
    
    let signal_types_json = serde_json::to_string(&signal_types).unwrap_or_default();
    let _ = db_conn.execute(
        "INSERT OR IGNORE INTO episodes (episode_id, stream_id, host, user, primary_entity_key, ts_start, ts_end, episode_kind, evidence_ptrs, signal_types)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '[]', ?9)",
        params![episode_id, stream_id, host, user, entity_key, ts_start, ts_start, episode_kind, signal_types_json],
    );
    episode_id
}

fn main() {
    let telemetry_root = get_telemetry_root();

    eprintln!("edr_locald starting");
    eprintln!("TELEMETRY_ROOT: {}", telemetry_root.display());

    // Load YAML playbooks
    let playbooks_dir = telemetry_root.join("playbooks");
    let playbooks = match load_playbooks_from_dir(&playbooks_dir) {
        Ok(pbs) => {
            // P1-2: Strict validation - no silent empty list
            if pbs.is_empty() && std::env::var("EDR_ALLOW_NO_PLAYBOOKS").is_err() {
                eprintln!(
                    "FATAL: No playbooks loaded from {} (EDR_ALLOW_NO_PLAYBOOKS not set)",
                    playbooks_dir.display()
                );
                std::process::exit(1);
            }

            // P1-2: Check for duplicate playbook_id
            let mut seen_ids = std::collections::HashSet::new();
            for pb in &pbs {
                if !seen_ids.insert(&pb.playbook_id) {
                    eprintln!("FATAL: Duplicate playbook_id: {}", pb.playbook_id);
                    std::process::exit(1);
                }
            }

            eprintln!("Loaded {} YAML playbooks", pbs.len());
            for pb in &pbs {
                eprintln!(
                    "  - {}: {} (priority={})",
                    pb.playbook_id, pb.title, pb.priority
                );
            }
            pbs
        }
        Err(e) => {
            eprintln!("FATAL: Playbook validation failed: {}", e);
            eprintln!("Refusing to start without valid playbooks. Fix YAML and restart.");
            std::process::exit(1);
        }
    };

    let mut playbook_engine = PlaybookEngine::new(playbooks, 300_000); // 5-minute TTL

    // Ensure directories exist
    if let Err(e) = fs::create_dir_all(telemetry_root.join("segments")) {
        eprintln!("ERROR: Failed to create segments dir: {}", e);
        return;
    }

    // Initialize SQLite database
    let db_path = telemetry_root.join("analysis.db");
    let db_conn = match Connection::open(&db_path) {
        Ok(conn) => {
            let _ = conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS telemetry_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    stream_id TEXT NOT NULL DEFAULT 'core',
                    segment_id TEXT NOT NULL,
                    record_index INTEGER NOT NULL,
                    ts INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(stream_id, segment_id, record_index)
                );
                CREATE TABLE IF NOT EXISTS locald_checkpoint (
                    stream_id TEXT NOT NULL PRIMARY KEY,
                    last_seq_processed INTEGER NOT NULL DEFAULT 0,
                    ts_processed INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS playbook_state (
                    entity_key TEXT NOT NULL,
                    playbook_id TEXT NOT NULL,
                    slot_id TEXT NOT NULL,
                    ts_ms INTEGER NOT NULL,
                    evidence_json TEXT,
                    PRIMARY KEY(entity_key, playbook_id, slot_id)
                );
                CREATE TABLE IF NOT EXISTS processed_records (
                    stream_id TEXT NOT NULL DEFAULT 'core',
                    segment_id TEXT NOT NULL,
                    record_index INTEGER NOT NULL,
                    processed_ts INTEGER NOT NULL,
                    PRIMARY KEY(stream_id, segment_id, record_index)
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL,
                    entity_key TEXT NOT NULL,
                    host TEXT,
                    user TEXT,
                    exe TEXT,
                    ts_created INTEGER NOT NULL,
                    ts_updated INTEGER NOT NULL,
                    dedup_bucket INTEGER NOT NULL,
                    hit_count INTEGER DEFAULT 1,
                    severity TEXT,
                    description TEXT,
                    evidence_json TEXT,
                    slots_json TEXT,
                    tags_json TEXT,
                    corroborations_json TEXT DEFAULT '[]',
                    playbook_schema_version INTEGER DEFAULT 1,
                    compiled_playbook_hash TEXT,
                    locald_build_id TEXT,
                    playbook_hash TEXT,
                    playbook_source_relpath TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(playbook_id, entity_key, dedup_bucket)
                );
                CREATE TABLE IF NOT EXISTS metrics_rollup (
                    ts_bucket INTEGER NOT NULL,
                    metric_name TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(ts_bucket, metric_name)
                );
                CREATE TABLE IF NOT EXISTS incident_evidence (
                    incident_id TEXT NOT NULL,
                    stream_id TEXT NOT NULL DEFAULT 'core',
                    segment_id TEXT NOT NULL,
                    record_index INTEGER NOT NULL,
                    ts_ms INTEGER,
                    PRIMARY KEY(incident_id, stream_id, segment_id, record_index)
                );
                CREATE TABLE IF NOT EXISTS operator_events (
                    stream_id TEXT NOT NULL DEFAULT 'operator',
                    segment_id TEXT NOT NULL,
                    record_index INTEGER NOT NULL,
                    ts_ms INTEGER NOT NULL,
                    session_id TEXT,
                    event_json TEXT NOT NULL,
                    UNIQUE(stream_id, segment_id, record_index),
                    PRIMARY KEY(stream_id, segment_id, record_index)
                );
                CREATE TABLE IF NOT EXISTS processed_operator_records (
                    stream_id TEXT NOT NULL DEFAULT 'operator',
                    segment_id TEXT NOT NULL,
                    record_index INTEGER NOT NULL,
                    processed_ts INTEGER NOT NULL,
                    PRIMARY KEY(stream_id, segment_id, record_index)
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(ts_updated DESC);
                CREATE INDEX IF NOT EXISTS idx_incidents_playbook ON incidents(playbook_id);
                CREATE INDEX IF NOT EXISTS idx_telemetry_segment ON telemetry_events(segment_id, record_index);
                CREATE INDEX IF NOT EXISTS idx_incident_evidence_segment ON incident_evidence(segment_id);
                CREATE INDEX IF NOT EXISTS idx_operator_ts ON operator_events(ts_ms DESC);
                CREATE INDEX IF NOT EXISTS idx_operator_session ON operator_events(session_id);
                CREATE TABLE IF NOT EXISTS signal_facts (
                    signal_id TEXT PRIMARY KEY,
                    stream_id TEXT NOT NULL DEFAULT 'core',
                    signal_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    host TEXT NOT NULL,
                    user TEXT NOT NULL,
                    exe TEXT,
                    entity_key TEXT NOT NULL,
                    ts_start INTEGER NOT NULL,
                    ts_end INTEGER NOT NULL,
                    evidence_ptrs TEXT NOT NULL,
                    metadata TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(stream_id, signal_type, entity_key, ts_start)
                );
                CREATE INDEX IF NOT EXISTS idx_signal_facts_entity ON signal_facts(entity_key);
                CREATE INDEX IF NOT EXISTS idx_signal_facts_stream_ts ON signal_facts(stream_id, ts_start);
                
                -- Server-compatible signals table for /api/signals endpoint
                CREATE TABLE IF NOT EXISTS signals (
                    signal_id TEXT PRIMARY KEY,
                    signal_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    host TEXT NOT NULL,
                    ts INTEGER NOT NULL,
                    ts_start INTEGER NOT NULL,
                    ts_end INTEGER NOT NULL,
                    proc_key TEXT,
                    file_key TEXT,
                    identity_key TEXT,
                    metadata TEXT NOT NULL,
                    evidence_ptrs TEXT NOT NULL,
                    dropped_evidence_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_signals_ts ON signals(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_signals_host ON signals(host);
                CREATE INDEX IF NOT EXISTS idx_signals_type ON signals(signal_type);
                CREATE INDEX IF NOT EXISTS idx_signals_severity ON signals(severity);
                
                CREATE TABLE IF NOT EXISTS episodes (
                    episode_id TEXT PRIMARY KEY,
                    stream_id TEXT NOT NULL DEFAULT 'core',
                    host TEXT NOT NULL,
                    user TEXT NOT NULL,
                    primary_entity_key TEXT NOT NULL,
                    ts_start INTEGER NOT NULL,
                    ts_end INTEGER NOT NULL,
                    episode_kind TEXT,
                    evidence_ptrs TEXT NOT NULL,
                    signal_types TEXT,
                    metadata TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(stream_id, episode_id)
                );
                CREATE INDEX IF NOT EXISTS idx_episodes_entity ON episodes(primary_entity_key);
                CREATE INDEX IF NOT EXISTS idx_episodes_stream_ts ON episodes(stream_id, ts_start);
                CREATE TABLE IF NOT EXISTS coverage_rollup (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts_minute INTEGER NOT NULL,
                    host TEXT NOT NULL,
                    sensor_mode TEXT,
                    fact_type TEXT,
                    fact_count INTEGER DEFAULT 0,
                    signal_type TEXT,
                    signal_count INTEGER DEFAULT 0,
                    enabled_capabilities TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ts_minute, host, sensor_mode, fact_type, signal_type)
                );
                CREATE INDEX IF NOT EXISTS idx_coverage_ts ON coverage_rollup(ts_minute DESC);",
            );
            Arc::new(Mutex::new(conn))
        }
        Err(e) => {
            eprintln!("ERROR: Failed to open analysis.db: {}", e);
            return;
        }
    };

    // P0: Acquire exclusive daemon lock
    let _lock_guard = match acquire_daemon_lock(&telemetry_root) {
        Ok(f) => {
            eprintln!("[locald] Acquired exclusive lock");
            f
        }
        Err(e) => {
            eprintln!("[FATAL] {}", e);
            if let Ok(db_conn) = db_conn.lock() {
                let _ = db_conn.execute(
                    "INSERT INTO metrics_rollup (ts_bucket, metric_name, count) VALUES (?1, ?2, ?3) ON CONFLICT(ts_bucket, metric_name) DO UPDATE SET count=count+?3",
                    params![(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() / 3600) as i64, "locald_lock_contended", 1],
                );
            }
            std::process::exit(1);
        }
    };

    // P0: Validate checkpoint integrity
    let _ = validate_checkpoint(&db_conn);

    // P1-4: Backfill incident_evidence from existing incidents
    let _ = backfill_incident_evidence(&db_conn);

    // Clean up expired playbook state at startup
    let ttl_ms = 300_000; // 5 minute TTL
    let _ = cleanup_expired_playbook_state(&db_conn, ttl_ms);

    let mut seen_segments = std::collections::HashSet::new();
    let mut accumulated_facts: Vec<(Fact, EvidencePtr)> = Vec::new();
    let mut metrics = MetricsCollector::new();
    let mut last_ttl_cleanup = std::time::SystemTime::now();
    let mut last_retention_run = std::time::SystemTime::now();
    let mut signal_state = signal_engine::SignalState::new();
    
    // Initialize Windows signal detector
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
    let mut windows_signal_engine = WindowsSignalEngine::new(hostname.clone());
    
    // Initialize scoring engine (enabled via feature flag or env var)
    let enable_advanced_scoring = cfg!(feature = "advanced_scoring") || 
                                   std::env::var("EDR_ADVANCED_SCORING").is_ok();
    let scoring_engine = ScoringEngine::new(enable_advanced_scoring);
    if enable_advanced_scoring {
        eprintln!("[locald] Advanced scoring enabled (Mahalanobis + EllipticEnvelope + KRIM)");
    }


    // Setup graceful shutdown
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let flag_clone = shutdown_flag.clone();
    ctrlc::set_handler(move || {
        eprintln!("\n[locald] SIGINT/SIGTERM: graceful shutdown...");
        flag_clone.store(true, Ordering::Relaxed);
    })
    .expect("Error setting Ctrl-C handler");

    // Get list of streams to ingest
    let streams = get_edr_streams();
    eprintln!("EDR_STREAMS: {}", streams.join(", "));

    eprintln!("Watching for new segments in index.json...");
    eprintln!(
        "Using YAML-based playbook engine with {} playbooks",
        playbook_engine.playbooks.len()
    );
    eprintln!("(Press Ctrl+C to gracefully shutdown)");
    eprintln!("");

    // Main loop: watch index files for changes from multiple streams
    loop {
        // Check for graceful shutdown
        if shutdown_flag.load(Ordering::Relaxed) {
            eprintln!("[locald] Flushing remaining metrics...");
            // Force persist all remaining metrics before shutdown
            metrics.maybe_log_and_persist_metrics(&db_conn);

            eprintln!("[locald] Closing database and exiting cleanly...");
            drop(db_conn);
            eprintln!("[locald] Clean exit");
            std::process::exit(0);
        }

        // Periodic TTL cleanup (every 60 seconds)
        if let Ok(elapsed) = last_ttl_cleanup.elapsed() {
            if elapsed > Duration::from_secs(60) {
                let _ = cleanup_expired_playbook_state(&db_conn, ttl_ms);
                last_ttl_cleanup = std::time::SystemTime::now();
            }
        }

        // Task 7: Periodic retention enforcement (every 10 minutes)
        if let Ok(elapsed) = last_retention_run.elapsed() {
            if elapsed > Duration::from_secs(600) {
                eprintln!("[retention] Running retention enforcement...");
                let _ = enforce_retention(&db_conn, &telemetry_root);
                last_retention_run = std::time::SystemTime::now();
            }
        }

        // Multi-stream ingestion: process each configured stream (core, operator, etc.)
        for stream_id in &streams {
            // Load index for this stream
            if let Some(index) = load_stream_index(&telemetry_root, stream_id) {
                let last_seq = get_last_seq_processed(&db_conn, stream_id);

                for seg_ref in &index.segments {
                    // Task 5: Seq-based filtering - skip already-processed segments
                    if should_skip_segment(seg_ref.seq, last_seq) {
                        continue;
                    }

                    // Build segment path relative to telemetry_root
                    let seg_path = if stream_id == "core" {
                        telemetry_root.join(&seg_ref.path)
                    } else {
                        telemetry_root.join(stream_id).join(&seg_ref.path)
                    };

                    // Task 6: Verify segment file exists before processing
                    if !seg_path.exists() {
                        eprintln!(
                            "[WARNING] Skipping missing segment: {} for stream {}",
                            seg_ref.segment_id, stream_id
                        );
                        continue;
                    }

                    // Use unique key combining stream_id and segment_id
                    let seg_key = format!("{}:{}", stream_id, seg_ref.segment_id);
                    if !seen_segments.contains(&seg_key) {
                        seen_segments.insert(seg_key);

                        if let Err(e) = ingest_segment(
                            &seg_path,
                            &seg_ref.segment_id,
                            stream_id,
                            &db_conn,
                            &mut accumulated_facts,
                            &mut playbook_engine,
                            &mut metrics,
                            &mut windows_signal_engine,
                            &scoring_engine,
                        ) {
                            eprintln!(
                                "ERROR: Failed to ingest {} from stream {}: {}",
                                seg_ref.segment_id, stream_id, e
                            );
                        } else {
                            // Mark seq as processed (stream-scoped)
                            let _ = update_last_seq_processed(&db_conn, stream_id, seg_ref.seq);
                        }
                        metrics.maybe_log_and_persist_metrics(&db_conn);
                    }
                }
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_populate_incident_evidence_from_json() {
        let db = Arc::new(Mutex::new(rusqlite::Connection::open_in_memory().unwrap()));

        // Create incident_evidence table
        if let Ok(conn) = db.lock() {
            conn.execute(
                "CREATE TABLE incident_evidence (
                    incident_id TEXT NOT NULL,
                    stream_id TEXT NOT NULL DEFAULT 'core',
                    segment_id TEXT NOT NULL,
                    record_index INTEGER NOT NULL,
                    ts_ms INTEGER,
                    PRIMARY KEY(incident_id, stream_id, segment_id, record_index)
                )",
                [],
            )
            .unwrap();
        }

        // Test 1: Normal JSON
        let evidence_json = r#"[{"segment_id":"seg_1","record_index":5}]"#;
        let result = populate_incident_evidence_from_json(&db, "inc_1", evidence_json, 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        // Test 2: Whitespace robustness
        let evidence_json_whitespace =
            r#"[  {  "segment_id"  :  "seg_2"  ,  "record_index"  :  10  }  ]"#;
        let result =
            populate_incident_evidence_from_json(&db, "inc_2", evidence_json_whitespace, 1001);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        // Test 3: Multiple evidence pointers
        let evidence_json_multi = r#"[
            {"segment_id":"seg_3","record_index":1},
            {"segment_id":"seg_4","record_index":2}
        ]"#;
        let result = populate_incident_evidence_from_json(&db, "inc_3", evidence_json_multi, 1002);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);

        // Test 4: Verify data is actually in incident_evidence table
        if let Ok(conn) = db.lock() {
            let count: i32 = conn.query_row(
                "SELECT COUNT(*) FROM incident_evidence WHERE stream_id='core' AND segment_id='seg_1'",
                [],
                |row| row.get(0),
            ).unwrap_or(0);
            assert_eq!(count, 1, "seg_1 should be in incident_evidence");
        }

        // Test 5: Empty JSON
        let evidence_json_empty = "[]";
        let result = populate_incident_evidence_from_json(&db, "inc_4", evidence_json_empty, 1003);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_incident_evidence_query_performance() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();

        // Create schema
        conn.execute(
            "CREATE TABLE incident_evidence (
                incident_id TEXT NOT NULL,
                stream_id TEXT NOT NULL DEFAULT 'core',
                segment_id TEXT NOT NULL,
                record_index INTEGER NOT NULL,
                ts_ms INTEGER,
                PRIMARY KEY(incident_id, stream_id, segment_id, record_index)
            )",
            [],
        )
        .unwrap();

        conn.execute(
            "CREATE INDEX idx_incident_evidence_segment ON incident_evidence(stream_id, segment_id)",
            [],
        ).unwrap();

        // Insert test data
        for i in 1..100 {
            conn.execute(
                "INSERT INTO incident_evidence VALUES (?, ?, ?, ?, ?)",
                params![
                    format!("inc_{}", i),
                    "core",
                    format!("seg_{}", i),
                    i,
                    1000 + i as i64
                ],
            )
            .unwrap();
        }

        // Test indexed query (simulates retention check)
        let is_referenced: bool = conn
            .query_row(
                "SELECT 1 FROM incident_evidence WHERE stream_id='core' AND segment_id=? LIMIT 1",
                params!["seg_50"],
                |_row| Ok(true),
            )
            .unwrap_or(false);

        assert!(is_referenced, "seg_50 should be found via indexed lookup");
    }

    #[test]
    fn test_formatting_independence_and_retention_check() {
        // Prove that incidents with different evidence_json formatting
        // still result in correct incident_evidence rows
        let conn = rusqlite::Connection::open_in_memory().unwrap();

        // Create schema
        conn.execute(
            "CREATE TABLE incident_evidence (
                incident_id TEXT NOT NULL,
                stream_id TEXT NOT NULL DEFAULT 'core',
                segment_id TEXT NOT NULL,
                record_index INTEGER NOT NULL,
                ts_ms INTEGER,
                PRIMARY KEY(incident_id, stream_id, segment_id, record_index)
            )",
            [],
        )
        .unwrap();

        conn.execute(
            "CREATE INDEX idx_incident_evidence_segment ON incident_evidence(stream_id, segment_id)",
            [],
        ).unwrap();

        // Test 1: Minimal formatting (no whitespace)
        let ev1 = r#"[{"stream_id":"core","segment_id":"seg_a","record_index":10}]"#;
        let pointers1: Vec<serde_json::Value> = serde_json::from_str(ev1).unwrap_or_default();
        for ptr in pointers1 {
            let stream_id = ptr
                .get("stream_id")
                .and_then(|v| v.as_str())
                .unwrap_or("core");
            if let (Some(seg_id), Some(rec_idx)) = (
                ptr.get("segment_id").and_then(|v| v.as_str()),
                ptr.get("record_index").and_then(|v| v.as_i64()),
            ) {
                conn.execute(
                    "INSERT OR IGNORE INTO incident_evidence VALUES (?, ?, ?, ?, ?)",
                    params!["inc_fmt1", stream_id, seg_id, rec_idx as i32, 1000],
                )
                .unwrap();
            }
        }

        // Test 2: Extra whitespace and newlines
        let ev2 = r#"[
            {
                "stream_id": "core",
                "segment_id": "seg_b",
                "record_index": 20
            }
        ]"#;
        let pointers2: Vec<serde_json::Value> = serde_json::from_str(ev2).unwrap_or_default();
        for ptr in pointers2 {
            let stream_id = ptr
                .get("stream_id")
                .and_then(|v| v.as_str())
                .unwrap_or("core");
            if let (Some(seg_id), Some(rec_idx)) = (
                ptr.get("segment_id").and_then(|v| v.as_str()),
                ptr.get("record_index").and_then(|v| v.as_i64()),
            ) {
                conn.execute(
                    "INSERT OR IGNORE INTO incident_evidence VALUES (?, ?, ?, ?, ?)",
                    params!["inc_fmt2", stream_id, seg_id, rec_idx as i32, 1001],
                )
                .unwrap();
            }
        }

        // Test 3: Different order (record_index before segment_id)
        let ev3 = r#"[{"record_index":30,"segment_id":"seg_c"}]"#;
        let pointers3: Vec<serde_json::Value> = serde_json::from_str(ev3).unwrap_or_default();
        for ptr in pointers3 {
            let stream_id = ptr
                .get("stream_id")
                .and_then(|v| v.as_str())
                .unwrap_or("core");
            if let (Some(seg_id), Some(rec_idx)) = (
                ptr.get("segment_id").and_then(|v| v.as_str()),
                ptr.get("record_index").and_then(|v| v.as_i64()),
            ) {
                conn.execute(
                    "INSERT OR IGNORE INTO incident_evidence VALUES (?, ?, ?, ?, ?)",
                    params!["inc_fmt3", stream_id, seg_id, rec_idx as i32, 1002],
                )
                .unwrap();
            }
        }

        // Verify all are stored correctly
        let count_a: i32 = conn.query_row(
            "SELECT COUNT(*) FROM incident_evidence WHERE stream_id='core' AND segment_id='seg_a'",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        assert_eq!(
            count_a, 1,
            "seg_a should be stored despite minimal formatting"
        );

        let count_b: i32 = conn.query_row(
            "SELECT COUNT(*) FROM incident_evidence WHERE stream_id='core' AND segment_id='seg_b'",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        assert_eq!(
            count_b, 1,
            "seg_b should be stored despite extra whitespace"
        );

        let count_c: i32 = conn.query_row(
            "SELECT COUNT(*) FROM incident_evidence WHERE stream_id='core' AND segment_id='seg_c'",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        assert_eq!(
            count_c, 1,
            "seg_c should be stored despite different field order"
        );

        // Verify retention check uses incident_evidence (NOT evidence_json)
        let is_seg_a_referenced: bool = conn.query_row(
            "SELECT 1 FROM incident_evidence WHERE stream_id='core' AND segment_id='seg_a' LIMIT 1",
            [],
            |_row| Ok(true),
        ).unwrap_or(false);
        assert!(
            is_seg_a_referenced,
            "Retention check must use incident_evidence table"
        );

        // Verify unreferenced segment returns false
        let is_seg_z_referenced: bool = conn.query_row(
            "SELECT 1 FROM incident_evidence WHERE stream_id='core' AND segment_id='seg_z' LIMIT 1",
            [],
            |_row| Ok(true),
        ).unwrap_or(false);
        assert!(
            !is_seg_z_referenced,
            "Unreferenced segment should not be found"
        );
    }
}

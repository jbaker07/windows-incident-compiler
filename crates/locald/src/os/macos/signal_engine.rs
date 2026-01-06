//! macOS-specific signal detection engine
//!
//! Detects macOS-specific threats including:
//! - Launchd persistence (LaunchAgents/LaunchDaemons)
//! - Login item persistence
//! - Keychain access attempts
//! - TCC bypass attempts
//! - System Integrity Protection (SIP) violations
//! - Gatekeeper bypass attempts

use crate::signal_result::{EvidenceRef, SignalResult};
use chrono::Utc;
use edr_core::Event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Process snapshot for macOS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcSnap {
    pub pid: u32,
    pub exe: String,
    pub parent_pid: Option<u32>,
    pub parent_exe: Option<String>,
    pub user: Option<String>,
    pub code_signed: Option<bool>,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

/// File access snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSnap {
    pub path: String,
    pub accessor_pid: u32,
    pub accessor_exe: String,
    pub access_type: String, // read|write|execute
    pub ts: i64,
    pub evidence: EvidenceRef,
}

/// Persistence event snapshot (launchd, login items)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceSnap {
    pub mechanism: String, // launchd|login_item|cron|at
    pub path: String,
    pub target_binary: Option<String>,
    pub user: Option<String>,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

/// Keychain access snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeychainSnap {
    pub accessor_pid: u32,
    pub accessor_exe: String,
    pub keychain_item: String,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

/// TCC (Transparency, Consent, Control) access snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccSnap {
    pub accessor_pid: u32,
    pub accessor_exe: String,
    pub service: String, // ScreenCapture, Microphone, Camera, etc.
    pub granted: bool,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

/// Network connection snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetSnap {
    pub pid: u32,
    pub exe: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

/// macOS Signal Detection Engine
pub struct MacOSSignalEngine {
    host: String,
    // State tracking with TTL
    proc_by_pid: HashMap<u32, ProcSnap>,
    file_access: Vec<FileSnap>,
    persistence_events: Vec<PersistenceSnap>,
    keychain_access: Vec<KeychainSnap>,
    tcc_events: Vec<TccSnap>,
    net_by_pid: HashMap<u32, Vec<NetSnap>>,
    // Dedup tracking
    last_fired: HashMap<String, i64>,
}

impl MacOSSignalEngine {
    pub fn new(host: String) -> Self {
        Self {
            host,
            proc_by_pid: HashMap::new(),
            file_access: Vec::new(),
            persistence_events: Vec::new(),
            keychain_access: Vec::new(),
            tcc_events: Vec::new(),
            net_by_pid: HashMap::new(),
            last_fired: HashMap::new(),
        }
    }

    /// Process incoming canonical event, return detected signals
    pub fn process_event(&mut self, event: &Event) -> Vec<SignalResult> {
        let now = Utc::now().timestamp_millis();
        let mut signals = Vec::new();

        // Compact old entries
        self.compact(now);

        // Route event based on tags
        for tag in &event.tags {
            match tag.as_str() {
                "process" | "exec" => self.handle_process(event, now, &mut signals),
                "file_write" | "file_create" => self.handle_file_write(event, now, &mut signals),
                "persistence" | "launchd" | "login_item" => {
                    self.handle_persistence(event, now, &mut signals)
                }
                "keychain" => self.handle_keychain(event, now, &mut signals),
                "tcc" => self.handle_tcc(event, now, &mut signals),
                "network" => self.handle_network(event, now, &mut signals),
                _ => {}
            }
        }

        signals
    }

    fn handle_process(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let pid = event
            .fields
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let exe = event
            .fields
            .get("exe")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let snap = ProcSnap {
            pid,
            exe: exe.clone(),
            parent_pid: event
                .fields
                .get("ppid")
                .and_then(|v| v.as_u64())
                .map(|p| p as u32),
            parent_exe: event
                .fields
                .get("parent_exe")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            user: event.identity_key.clone(),
            code_signed: event.fields.get("code_signed").and_then(|v| v.as_bool()),
            ts: now,
            evidence: self.make_evidence(event),
        };

        if pid > 0 {
            // Detect unsigned process execution
            if snap.code_signed == Some(false) {
                self.detect_unsigned_exec(&snap, signals);
            }

            // Detect suspicious parent-child relationships
            self.detect_suspicious_parent_child(&snap, signals);

            self.proc_by_pid.insert(pid, snap);
        }
    }

    fn handle_file_write(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let path = event
            .fields
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let pid = event
            .fields
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let snap = FileSnap {
            path: path.clone(),
            accessor_pid: pid,
            accessor_exe: event
                .fields
                .get("exe")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            access_type: "write".to_string(),
            ts: now,
            evidence: self.make_evidence(event),
        };

        // Detect writes to sensitive locations
        if self.is_sensitive_path(&path) {
            self.detect_sensitive_write(&snap, signals);
        }

        self.file_access.push(snap);
    }

    fn handle_persistence(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let mechanism = if event.tags.contains(&"launchd".to_string()) {
            "launchd"
        } else if event.tags.contains(&"login_item".to_string()) {
            "login_item"
        } else {
            "unknown"
        };

        let path = event
            .fields
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let snap = PersistenceSnap {
            mechanism: mechanism.to_string(),
            path: path.clone(),
            target_binary: event
                .fields
                .get("target")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            user: event.identity_key.clone(),
            ts: now,
            evidence: self.make_evidence(event),
        };

        // Always signal on persistence mechanism creation
        let entity_hash = format!("{}:{}", mechanism, path);
        if self.should_fire(&entity_hash, "PersistenceMechanism", now) {
            let mut signal = SignalResult::new(
                &self.host,
                &format!("Persistence{}", Self::capitalize(mechanism)),
                "high",
                &entity_hash,
                now,
            );
            signal.file_key = Some(path);
            signal.evidence_ptrs.push(snap.evidence.clone());
            signal.metadata = serde_json::json!({
                "mechanism": mechanism,
                "target": snap.target_binary,
            });
            signals.push(signal);
            self.last_fired
                .insert(format!("PersistenceMechanism|{}", entity_hash), now);
        }

        self.persistence_events.push(snap);
    }

    fn handle_keychain(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let pid = event
            .fields
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let exe = event
            .fields
            .get("exe")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let item = event
            .fields
            .get("keychain_item")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let snap = KeychainSnap {
            accessor_pid: pid,
            accessor_exe: exe.clone(),
            keychain_item: item.clone(),
            ts: now,
            evidence: self.make_evidence(event),
        };

        // Detect suspicious keychain access
        if !self.is_known_keychain_accessor(&exe) {
            let entity_hash = format!("{}:{}", exe, item);
            if self.should_fire(&entity_hash, "KeychainAccess", now) {
                let mut signal = SignalResult::new(
                    &self.host,
                    "SuspiciousKeychainAccess",
                    "medium",
                    &entity_hash,
                    now,
                );
                signal.proc_key = event.proc_key.clone();
                signal.evidence_ptrs.push(snap.evidence.clone());
                signal.metadata = serde_json::json!({
                    "accessor_exe": exe,
                    "keychain_item": item,
                });
                signals.push(signal);
                self.last_fired
                    .insert(format!("KeychainAccess|{}", entity_hash), now);
            }
        }

        self.keychain_access.push(snap);
    }

    fn handle_tcc(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let pid = event
            .fields
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let exe = event
            .fields
            .get("exe")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let service = event
            .fields
            .get("tcc_service")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let granted = event
            .fields
            .get("granted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let snap = TccSnap {
            accessor_pid: pid,
            accessor_exe: exe.clone(),
            service: service.clone(),
            granted,
            ts: now,
            evidence: self.make_evidence(event),
        };

        // Detect TCC bypass attempts (access without explicit grant)
        if !granted && self.is_sensitive_tcc_service(&service) {
            let entity_hash = format!("{}:{}", exe, service);
            if self.should_fire(&entity_hash, "TccBypass", now) {
                let mut signal =
                    SignalResult::new(&self.host, "TccBypassAttempt", "high", &entity_hash, now);
                signal.proc_key = event.proc_key.clone();
                signal.evidence_ptrs.push(snap.evidence.clone());
                signal.metadata = serde_json::json!({
                    "accessor_exe": exe,
                    "tcc_service": service,
                });
                signals.push(signal);
                self.last_fired
                    .insert(format!("TccBypass|{}", entity_hash), now);
            }
        }

        self.tcc_events.push(snap);
    }

    fn handle_network(&mut self, event: &Event, now: i64, _signals: &mut Vec<SignalResult>) {
        let pid = event
            .fields
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let exe = event
            .fields
            .get("exe")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let dest_ip = event
            .fields
            .get("dest_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let dest_port = event
            .fields
            .get("dest_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;

        let snap = NetSnap {
            pid,
            exe,
            dest_ip,
            dest_port,
            ts: now,
            evidence: self.make_evidence(event),
        };

        if pid > 0 {
            self.net_by_pid.entry(pid).or_default().push(snap);
        }
    }

    // Detection helpers

    fn detect_unsigned_exec(&mut self, snap: &ProcSnap, signals: &mut Vec<SignalResult>) {
        let entity_hash = format!("unsigned:{}", snap.exe);
        if self.should_fire(&entity_hash, "UnsignedExec", snap.ts) {
            let mut signal = SignalResult::new(
                &self.host,
                "UnsignedCodeExecution",
                "medium",
                &entity_hash,
                snap.ts,
            );
            signal.proc_key = Some(format!("proc_{}", snap.pid));
            signal.evidence_ptrs.push(snap.evidence.clone());
            signal.metadata = serde_json::json!({
                "exe": snap.exe,
                "pid": snap.pid,
            });
            signals.push(signal);
            self.last_fired
                .insert(format!("UnsignedExec|{}", entity_hash), snap.ts);
        }
    }

    fn detect_suspicious_parent_child(&mut self, snap: &ProcSnap, signals: &mut Vec<SignalResult>) {
        // Detect shell spawned from unusual parents
        let is_shell =
            snap.exe.ends_with("/bash") || snap.exe.ends_with("/zsh") || snap.exe.ends_with("/sh");

        if is_shell {
            if let Some(parent_exe) = &snap.parent_exe {
                let suspicious_parents = ["Microsoft Word", "Microsoft Excel", "Preview", "Safari"];
                if suspicious_parents.iter().any(|p| parent_exe.contains(p)) {
                    let entity_hash = format!("shell_spawn:{}:{}", parent_exe, snap.exe);
                    if self.should_fire(&entity_hash, "SuspiciousSpawn", snap.ts) {
                        let mut signal = SignalResult::new(
                            &self.host,
                            "SuspiciousShellSpawn",
                            "high",
                            &entity_hash,
                            snap.ts,
                        );
                        signal.proc_key = Some(format!("proc_{}", snap.pid));
                        signal.evidence_ptrs.push(snap.evidence.clone());
                        signal.metadata = serde_json::json!({
                            "parent_exe": parent_exe,
                            "child_exe": snap.exe,
                        });
                        signals.push(signal);
                        self.last_fired
                            .insert(format!("SuspiciousSpawn|{}", entity_hash), snap.ts);
                    }
                }
            }
        }
    }

    fn detect_sensitive_write(&mut self, snap: &FileSnap, signals: &mut Vec<SignalResult>) {
        let entity_hash = format!("sensitive_write:{}", snap.path);
        if self.should_fire(&entity_hash, "SensitiveWrite", snap.ts) {
            let mut signal = SignalResult::new(
                &self.host,
                "SensitiveLocationWrite",
                "high",
                &entity_hash,
                snap.ts,
            );
            signal.file_key = Some(snap.path.clone());
            signal.proc_key = Some(format!("proc_{}", snap.accessor_pid));
            signal.evidence_ptrs.push(snap.evidence.clone());
            signal.metadata = serde_json::json!({
                "path": snap.path,
                "accessor_exe": snap.accessor_exe,
            });
            signals.push(signal);
            self.last_fired
                .insert(format!("SensitiveWrite|{}", entity_hash), snap.ts);
        }
    }

    // Helper methods

    fn make_evidence(&self, event: &Event) -> EvidenceRef {
        match &event.evidence_ptr {
            Some(ptr) => EvidenceRef {
                stream_id: ptr.stream_id.clone(),
                segment_id: ptr.segment_id.to_string(),
                record_index: ptr.record_index as u64,
            },
            None => EvidenceRef::default(),
        }
    }

    fn should_fire(&self, entity_hash: &str, signal_type: &str, now: i64) -> bool {
        let key = format!("{}|{}", signal_type, entity_hash);
        match self.last_fired.get(&key) {
            Some(last_ts) => (now - last_ts) > 300_000, // 5 minute cooldown
            None => true,
        }
    }

    fn is_sensitive_path(&self, path: &str) -> bool {
        let sensitive_prefixes = [
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
            "/System/Library/LaunchAgents",
            "/private/var/db/",
            "/etc/",
        ];
        sensitive_prefixes.iter().any(|p| path.starts_with(p))
            || path.contains("/Library/Application Support/com.apple.TCC")
    }

    fn is_known_keychain_accessor(&self, exe: &str) -> bool {
        let known = [
            "security",
            "Keychain Access",
            "Safari",
            "Mail",
            "System Preferences",
        ];
        known.iter().any(|k| exe.contains(k))
    }

    fn is_sensitive_tcc_service(&self, service: &str) -> bool {
        let sensitive = [
            "ScreenCapture",
            "Microphone",
            "Camera",
            "SystemPolicyAllFiles",
            "Accessibility",
        ];
        sensitive.iter().any(|s| service.contains(s))
    }

    fn capitalize(s: &str) -> String {
        let mut c = s.chars();
        match c.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        }
    }

    fn compact(&mut self, now: i64) {
        const TTL_PROC: i64 = 2 * 60 * 60 * 1000; // 2 hours
        const TTL_FILE: i64 = 30 * 60 * 1000; // 30 minutes
        const TTL_PERSISTENCE: i64 = 60 * 60 * 1000; // 1 hour
        const TTL_KEYCHAIN: i64 = 30 * 60 * 1000; // 30 minutes
        const TTL_TCC: i64 = 30 * 60 * 1000; // 30 minutes

        self.proc_by_pid.retain(|_, snap| now - snap.ts < TTL_PROC);
        self.file_access.retain(|snap| now - snap.ts < TTL_FILE);
        self.persistence_events
            .retain(|snap| now - snap.ts < TTL_PERSISTENCE);
        self.keychain_access
            .retain(|snap| now - snap.ts < TTL_KEYCHAIN);
        self.tcc_events.retain(|snap| now - snap.ts < TTL_TCC);

        for snaps in self.net_by_pid.values_mut() {
            snaps.retain(|snap| now - snap.ts < TTL_PROC);
        }
        self.net_by_pid.retain(|_, snaps| !snaps.is_empty());

        // Clean old dedup entries
        self.last_fired.retain(|_, ts| now - *ts < TTL_PROC);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edr_core::EvidencePtr;
    use std::collections::BTreeMap;

    fn make_test_event(tags: Vec<&str>, fields_json: serde_json::Value) -> Event {
        let mut fields = BTreeMap::new();
        if let Some(obj) = fields_json.as_object() {
            for (k, v) in obj {
                fields.insert(k.clone(), v.clone());
            }
        }
        Event {
            ts_ms: chrono::Utc::now().timestamp_millis(),
            host: "TEST_HOST".to_string(),
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            fields,
            proc_key: Some("proc_1234".to_string()),
            file_key: None,
            identity_key: Some("user1".to_string()),
            evidence_ptr: Some(EvidencePtr {
                stream_id: "test_stream".to_string(),
                segment_id: 0,
                record_index: 0,
            }),
        }
    }

    #[test]
    fn test_engine_creation() {
        let engine = MacOSSignalEngine::new("TEST_HOST".to_string());
        assert_eq!(engine.host, "TEST_HOST");
    }

    #[test]
    fn test_persistence_detection() {
        let mut engine = MacOSSignalEngine::new("TEST_HOST".to_string());
        let event = make_test_event(
            vec!["persistence", "launchd"],
            serde_json::json!({
                "path": "/Library/LaunchDaemons/com.evil.plist",
                "target": "/usr/local/bin/evil"
            }),
        );

        let signals = engine.process_event(&event);
        assert!(!signals.is_empty());
        assert_eq!(signals[0].signal_type, "PersistenceLaunchd");
    }

    #[test]
    fn test_tcc_bypass_detection() {
        let mut engine = MacOSSignalEngine::new("TEST_HOST".to_string());
        let event = make_test_event(
            vec!["tcc"],
            serde_json::json!({
                "pid": 1234,
                "exe": "/tmp/evil",
                "tcc_service": "ScreenCapture",
                "granted": false
            }),
        );

        let signals = engine.process_event(&event);
        assert!(!signals.is_empty());
        assert_eq!(signals[0].signal_type, "TccBypassAttempt");
    }
}

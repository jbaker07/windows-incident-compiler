// windows/signal_engine.rs
// Windows signal detector with bounded buffers, TTL compaction, and dedup

use crate::signal_result::{EvidenceRef, SignalResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;

// Use edr_core Event
use edr_core::Event;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcSnap {
    pub pid: u32,
    pub exe: String,
    pub parent_pid: Option<u32>,
    pub parent_exe: Option<String>,
    pub user: Option<String>,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetSnap {
    pub pid: u32,
    pub exe: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiSnap {
    pub event_id: u32,
    pub event_type: String, // filter|consumer|binding
    pub ts: i64,
    pub evidence: EvidenceRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogonSnap {
    pub user: String,
    pub logon_type: String, // 3=network, 10=RDP
    pub source_ip: String,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSnap {
    pub service_name: String,
    pub image_path: String,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSnap {
    pub task_name: String,
    pub action: String,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsassSnap {
    pub accessor_pid: u32,
    pub accessor_exe: String,
    pub granted_access: String,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSnap {
    pub audit_type: String, // policy_change|log_clear
    pub detail: String,
    pub user: Option<String>,
    pub ts: i64,
    pub evidence: EvidenceRef,
}

pub struct WindowsSignalEngine {
    host: String,
    // TTL: 2 hours for process/net, 60 min for WMI/logon/service, 30 min for LSASS
    proc_by_pid: HashMap<u32, ProcSnap>,
    net_by_pid: HashMap<u32, Vec<NetSnap>>,
    wmi_events: Vec<WmiSnap>,
    logon_events: Vec<LogonSnap>,
    service_installs: Vec<ServiceSnap>,
    task_execs: Vec<TaskSnap>,
    lsass_access: Vec<LsassSnap>,
    audit_events: Vec<AuditSnap>,
    last_fired: HashMap<String, i64>, // key: (signal_type|entity_hash), value: last_fired_ts
    /// Workflow seed enabled (via EDR_WORKFLOW_SEED=1)
    workflow_seed_enabled: bool,
    /// Track if we've emitted workflow seed this run (emit once per boot)
    workflow_seed_emitted: bool,
}

impl WindowsSignalEngine {
    pub fn new(host: String) -> Self {
        // Check if workflow seed is enabled via env var
        let workflow_seed_enabled = env::var("EDR_WORKFLOW_SEED")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        Self {
            host,
            proc_by_pid: HashMap::new(),
            net_by_pid: HashMap::new(),
            wmi_events: Vec::new(),
            logon_events: Vec::new(),
            service_installs: Vec::new(),
            task_execs: Vec::new(),
            lsass_access: Vec::new(),
            audit_events: Vec::new(),
            last_fired: HashMap::new(),
            workflow_seed_enabled,
            workflow_seed_emitted: false,
        }
    }

    /// Extract evidence from event, with defaults if missing
    fn make_evidence(event: &Event) -> EvidenceRef {
        match &event.evidence_ptr {
            Some(ptr) => EvidenceRef {
                stream_id: ptr.stream_id.clone(),
                segment_id: ptr.segment_id.to_string(),
                record_index: ptr.record_index as u64,
            },
            None => EvidenceRef::default(),
        }
    }

    /// Process incoming canonical event, return detected signals
    pub fn process_event(&mut self, event: &Event) -> Vec<SignalResult> {
        let now = Utc::now().timestamp_millis();
        let mut signals = Vec::new();

        // Compact old entries before processing
        self.compact(now);

        // Check for workflow seed signal (enabled via EDR_WORKFLOW_SEED=1)
        // Triggers on any Windows event log event - emits once per boot
        if self.workflow_seed_enabled && !self.workflow_seed_emitted {
            if let Some(signal) = self.maybe_emit_workflow_seed(event, now) {
                signals.push(signal);
            }
        }

        // Route event based on tags
        for tag in &event.tags {
            match tag.as_str() {
                "process" => self.handle_process_creation(event, now, &mut signals),
                "network" => self.handle_network_connect(event, now, &mut signals),
                "wmi" => self.handle_wmi_event(event, now, &mut signals),
                "lateral_movement" if event.tags.contains(&"remote_logon".to_string()) => {
                    self.handle_remote_logon(event, now, &mut signals)
                }
                "service_installed" => self.handle_service_install(event, now, &mut signals),
                "task" if event.tags.contains(&"persistence".to_string()) => {
                    self.handle_task_exec(event, now, &mut signals)
                }
                "credential_access" if event.tags.contains(&"lsass_access".to_string()) => {
                    self.handle_lsass_access(event, now, &mut signals)
                }
                "log_cleared" | "audit_policy" => self.handle_audit_event(event, now, &mut signals),
                "network_access" if event.tags.contains(&"lateral_movement".to_string()) => {
                    self.handle_share_access(event, now, &mut signals)
                }
                _ => {}
            }
        }

        signals
    }

    fn handle_process_creation(
        &mut self,
        event: &Event,
        now: i64,
        _signals: &mut Vec<SignalResult>,
    ) {
        if let Some(_proc_key) = &event.proc_key {
            // Extract pid from fields
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
                exe,
                parent_pid: event
                    .fields
                    .get("ppid")
                    .and_then(|v| v.as_u64())
                    .map(|p| p as u32),
                parent_exe: None,
                user: event.identity_key.clone(),
                ts: now,
                evidence: Self::make_evidence(event),
            };
            if snap.pid > 0 {
                self.proc_by_pid.insert(snap.pid, snap);
            }
        }
    }

    fn handle_network_connect(
        &mut self,
        event: &Event,
        now: i64,
        _signals: &mut Vec<SignalResult>,
    ) {
        if let Some(_sock_key) = &event.file_key {
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
                .unwrap_or("0.0.0.0")
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
                evidence: Self::make_evidence(event),
            };
            if snap.pid > 0 {
                self.net_by_pid.entry(snap.pid).or_default().push(snap);
            }
        }
    }

    fn handle_wmi_event(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let event_id = if event.tags.contains(&"filter".to_string()) {
            19
        } else if event.tags.contains(&"consumer".to_string()) {
            20
        } else {
            21
        };

        let snap = WmiSnap {
            event_id,
            event_type: event
                .tags
                .iter()
                .find(|t| *t == "filter" || *t == "consumer" || *t == "binding")
                .cloned()
                .unwrap_or_default(),
            ts: now,
            evidence: Self::make_evidence(event),
        };
        self.wmi_events.push(snap);

        // Detect WmiPersistenceConfirmed if WMI event present
        self.detect_wmi_persistence(now, signals);
    }

    fn handle_remote_logon(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let snap = LogonSnap {
            user: event.identity_key.clone().unwrap_or_default(),
            logon_type: "remote".to_string(),
            source_ip: event
                .fields
                .get("source_ip")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0.0")
                .to_string(),
            ts: now,
            evidence: Self::make_evidence(event),
        };
        self.logon_events.push(snap);

        // Detect RemotePersistence if service/task created soon after
        self.detect_remote_persistence(now, signals);
    }

    fn handle_service_install(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let snap = ServiceSnap {
            service_name: event.proc_key.clone().unwrap_or_default(),
            image_path: event.file_key.clone().unwrap_or_default(),
            ts: now,
            evidence: Self::make_evidence(event),
        };
        self.service_installs.push(snap);

        // Check RemotePersistence
        self.detect_remote_persistence(now, signals);
    }

    fn handle_task_exec(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let snap = TaskSnap {
            task_name: event.proc_key.clone().unwrap_or_default(),
            action: event.file_key.clone().unwrap_or_default(),
            ts: now,
            evidence: Self::make_evidence(event),
        };
        self.task_execs.push(snap);

        self.detect_remote_persistence(now, signals);
    }

    fn handle_lsass_access(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let snap = LsassSnap {
            accessor_pid: event
                .fields
                .get("pid")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            accessor_exe: event
                .fields
                .get("exe")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            granted_access: "high".to_string(),
            ts: now,
            evidence: Self::make_evidence(event),
        };
        self.lsass_access.push(snap);

        self.detect_lsass_access_suspicious(now, signals);
    }

    fn handle_audit_event(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        let audit_type = if event.tags.contains(&"log_cleared".to_string()) {
            "log_clear"
        } else {
            "policy_change"
        };

        let snap = AuditSnap {
            audit_type: audit_type.to_string(),
            detail: event.tags.join(","),
            user: event.identity_key.clone(),
            ts: now,
            evidence: Self::make_evidence(event),
        };
        self.audit_events.push(snap);

        self.detect_log_evasion(now, signals);
    }

    fn handle_share_access(&mut self, event: &Event, now: i64, signals: &mut Vec<SignalResult>) {
        // Detect LateralShareAccess
        self.detect_lateral_share_access(event, now, signals);
    }

    // ============ DETECTORS ============

    fn detect_log_evasion(&mut self, now: i64, signals: &mut Vec<SignalResult>) {
        // Fire if log_clear + audit_change within 60 min
        let has_log_clear = self
            .audit_events
            .iter()
            .any(|e| e.audit_type == "log_clear" && now - e.ts < 3600000);
        let has_audit_change = self
            .audit_events
            .iter()
            .any(|e| e.audit_type == "policy_change" && now - e.ts < 3600000);

        if has_log_clear && has_audit_change {
            let entity_hash = "log_evasion";
            if self.should_fire("LogEvasion", entity_hash, 600) {
                // 10 min cooldown
                let evidence = self
                    .audit_events
                    .iter()
                    .filter(|e| now - e.ts < 3600000)
                    .map(|e| e.evidence.clone())
                    .collect::<Vec<_>>();

                let (capped, dropped) = SignalResult::cap_evidence(evidence);
                let signal_id =
                    SignalResult::compute_signal_id(&self.host, "LogEvasion", entity_hash, now);

                signals.push(SignalResult {
                    signal_id,
                    signal_type: "LogEvasion".to_string(),
                    severity: "critical".to_string(),
                    host: self.host.clone(),
                    ts: now,
                    ts_start: now - 3600000,
                    ts_end: now,
                    proc_key: None,
                    file_key: None,
                    identity_key: self.audit_events.last().and_then(|e| e.user.clone()),
                    evidence_ptrs: capped,
                    dropped_evidence_count: dropped,
                    metadata: serde_json::json!({
                        "has_log_clear": has_log_clear,
                        "has_audit_change": has_audit_change,
                    }),
                });

                self.record_fired("LogEvasion", entity_hash, now);
            }
        }
    }

    fn detect_wmi_persistence(&mut self, now: i64, signals: &mut Vec<SignalResult>) {
        // Fire if WMI event exists (simplified: just presence = persistence)
        if !self.wmi_events.is_empty() {
            let entity_hash = "wmi_persistence";
            if self.should_fire("WmiPersistenceConfirmed", entity_hash, 600) {
                let evidence = vec![self.wmi_events.last().unwrap().evidence.clone()];
                let signal_id = SignalResult::compute_signal_id(
                    &self.host,
                    "WmiPersistenceConfirmed",
                    entity_hash,
                    now,
                );

                signals.push(SignalResult {
                    signal_id,
                    signal_type: "WmiPersistenceConfirmed".to_string(),
                    severity: "high".to_string(),
                    host: self.host.clone(),
                    ts: now,
                    ts_start: now - 3600000,
                    ts_end: now,
                    proc_key: None,
                    file_key: None,
                    identity_key: None,
                    evidence_ptrs: evidence,
                    dropped_evidence_count: 0,
                    metadata: serde_json::json!({
                        "wmi_event_count": self.wmi_events.len(),
                    }),
                });

                self.record_fired("WmiPersistenceConfirmed", entity_hash, now);
            }
        }
    }

    fn detect_lsass_access_suspicious(&mut self, now: i64, signals: &mut Vec<SignalResult>) {
        // Fire on LSASS access (simplified: just presence)
        // Collect data first to avoid borrow issues
        let snap_data: Option<(String, i64, u32, EvidenceRef)> =
            self.lsass_access.iter().next_back().map(|snap| {
                (
                    snap.accessor_exe.clone(),
                    snap.ts,
                    snap.accessor_pid,
                    snap.evidence.clone(),
                )
            });

        if let Some((accessor_exe, ts, accessor_pid, evidence)) = snap_data {
            let entity_hash = accessor_exe.clone();
            if self.should_fire("LSASSAccessSuspicious", &entity_hash, 300) {
                // 5 min cooldown
                let signal_id = SignalResult::compute_signal_id(
                    &self.host,
                    "LSASSAccessSuspicious",
                    &entity_hash,
                    now,
                );

                signals.push(SignalResult {
                    signal_id,
                    signal_type: "LSASSAccessSuspicious".to_string(),
                    severity: "critical".to_string(),
                    host: self.host.clone(),
                    ts: now,
                    ts_start: ts,
                    ts_end: now,
                    proc_key: Some(format!("pid:{}", accessor_pid)),
                    file_key: None,
                    identity_key: None,
                    evidence_ptrs: vec![evidence],
                    dropped_evidence_count: 0,
                    metadata: serde_json::json!({
                        "accessor_exe": accessor_exe,
                        "accessor_pid": accessor_pid,
                    }),
                });

                self.record_fired("LSASSAccessSuspicious", &entity_hash, now);
            }
        }
    }

    fn detect_remote_persistence(&mut self, now: i64, signals: &mut Vec<SignalResult>) {
        // Collect data first to avoid borrow issues
        let logon_data: Option<(String, i64, String, EvidenceRef)> =
            self.logon_events.iter().next_back().map(|logon| {
                (
                    logon.user.clone(),
                    logon.ts,
                    logon.logon_type.clone(),
                    logon.evidence.clone(),
                )
            });

        if let Some((user, logon_ts, logon_type, logon_evidence)) = logon_data {
            let recent_services = self
                .service_installs
                .iter()
                .filter(|s| now - s.ts < 3600000)
                .count();
            let recent_tasks = self
                .task_execs
                .iter()
                .filter(|t| now - t.ts < 3600000)
                .count();

            if recent_services > 0 || recent_tasks > 0 {
                let entity_hash = user.clone();
                if self.should_fire("RemotePersistence", &entity_hash, 600) {
                    let mut evidence = vec![logon_evidence];
                    evidence.extend(
                        self.service_installs
                            .iter()
                            .rev()
                            .take(1)
                            .map(|s| s.evidence.clone()),
                    );
                    let (capped, dropped) = SignalResult::cap_evidence(evidence);

                    let signal_id = SignalResult::compute_signal_id(
                        &self.host,
                        "RemotePersistence",
                        &entity_hash,
                        now,
                    );

                    signals.push(SignalResult {
                        signal_id,
                        signal_type: "RemotePersistence".to_string(),
                        severity: "critical".to_string(),
                        host: self.host.clone(),
                        ts: now,
                        ts_start: logon_ts,
                        ts_end: now,
                        proc_key: None,
                        file_key: None,
                        identity_key: Some(user.clone()),
                        evidence_ptrs: capped,
                        dropped_evidence_count: dropped,
                        metadata: serde_json::json!({
                            "logon_type": logon_type,
                        }),
                    });

                    self.record_fired("RemotePersistence", &entity_hash, now);
                }
            }
        }
    }

    fn detect_lateral_share_access(
        &mut self,
        event: &Event,
        now: i64,
        signals: &mut Vec<SignalResult>,
    ) {
        // Fire on 5140 share access
        let share_name = event.file_key.clone().unwrap_or_default();
        if share_name.contains("C$") || share_name.contains("IPC$") || share_name.contains("ADMIN$")
        {
            let entity_hash = &format!(
                "{}|{}",
                event
                    .identity_key
                    .as_ref()
                    .unwrap_or(&"unknown".to_string()),
                &share_name
            );
            if self.should_fire("LateralShareAccess", entity_hash, 300) {
                let signal_id = SignalResult::compute_signal_id(
                    &self.host,
                    "LateralShareAccess",
                    entity_hash,
                    now,
                );

                signals.push(SignalResult {
                    signal_id,
                    signal_type: "LateralShareAccess".to_string(),
                    severity: "high".to_string(),
                    host: self.host.clone(),
                    ts: now,
                    ts_start: now,
                    ts_end: now,
                    proc_key: None,
                    file_key: event.file_key.clone(),
                    identity_key: event.identity_key.clone(),
                    evidence_ptrs: vec![Self::make_evidence(event)],
                    dropped_evidence_count: 0,
                    metadata: serde_json::json!({
                        "share": share_name,
                    }),
                });

                self.record_fired("LateralShareAccess", entity_hash, now);
            }
        }
    }

    // ============ WORKFLOW SEED (for E2E testing) ============

    /// Emit a workflow seed signal on first Windows event log event.
    /// Enabled via EDR_WORKFLOW_SEED=1 environment variable.
    /// Emits at most once per boot (dedup via workflow_seed_emitted flag).
    fn maybe_emit_workflow_seed(&mut self, event: &Event, now: i64) -> Option<SignalResult> {
        // Only trigger on Windows event log events (tag "event_log")
        if !event.tags.contains(&"event_log".to_string()) {
            return None;
        }

        // Extract provider and event_id for metadata
        let provider = event
            .fields
            .get("windows.provider")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let event_id = event
            .fields
            .get("windows.event_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let channel = event
            .fields
            .get("windows.channel")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Mark as emitted so we don't spam
        self.workflow_seed_emitted = true;

        // Deterministic entity hash based on host (so it's stable per machine)
        let entity_hash = format!("workflow_seed|{}", self.host);
        let signal_id =
            SignalResult::compute_signal_id(&self.host, "WorkflowSeed", &entity_hash, now);

        Some(SignalResult {
            signal_id,
            signal_type: "WorkflowSeed".to_string(),
            severity: "low".to_string(),
            host: self.host.clone(),
            ts: now,
            ts_start: now,
            ts_end: now,
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptrs: vec![Self::make_evidence(event)],
            dropped_evidence_count: 0,
            metadata: serde_json::json!({
                "purpose": "workflow_testing",
                "provider": provider,
                "event_id": event_id,
                "channel": channel,
                "signal_type": "workflow_seed",
                "note": "This signal exists solely for E2E verification. Enable via EDR_WORKFLOW_SEED=1."
            }),
        })
    }

    // ============ UTILITY ============

    fn should_fire(&self, signal_type: &str, entity_hash: &str, cooldown_ms: i64) -> bool {
        let key = format!("{}|{}", signal_type, entity_hash);
        if let Some(last_ts) = self.last_fired.get(&key) {
            let now = Utc::now().timestamp_millis();
            now - *last_ts >= cooldown_ms
        } else {
            true
        }
    }

    fn record_fired(&mut self, signal_type: &str, entity_hash: &str, ts: i64) {
        let key = format!("{}|{}", signal_type, entity_hash);
        self.last_fired.insert(key, ts);
    }

    fn compact(&mut self, now: i64) {
        // Remove entries older than TTL
        const PROC_TTL: i64 = 7200000; // 2 hours
        const NET_TTL: i64 = 600000; // 10 min
        const WMI_TTL: i64 = 3600000; // 60 min
        const LSASS_TTL: i64 = 1800000; // 30 min
        const AUDIT_TTL: i64 = 3600000; // 60 min

        self.proc_by_pid.retain(|_, p| now - p.ts < PROC_TTL);
        for nets in self.net_by_pid.values_mut() {
            nets.retain(|n| now - n.ts < NET_TTL);
        }
        self.net_by_pid.retain(|_, nets| !nets.is_empty());
        self.wmi_events.retain(|w| now - w.ts < WMI_TTL);
        self.logon_events.retain(|l| now - l.ts < AUDIT_TTL);
        self.service_installs.retain(|s| now - s.ts < AUDIT_TTL);
        self.task_execs.retain(|t| now - t.ts < AUDIT_TTL);
        self.lsass_access.retain(|l| now - l.ts < LSASS_TTL);
        self.audit_events.retain(|a| now - a.ts < AUDIT_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = WindowsSignalEngine::new("TEST_HOST".to_string());
        assert_eq!(engine.host, "TEST_HOST");
    }

    #[test]
    fn test_should_fire_first_time() {
        let engine = WindowsSignalEngine::new("HOST".to_string());
        assert!(engine.should_fire("TestSignal", "entity1", 600));
    }
}

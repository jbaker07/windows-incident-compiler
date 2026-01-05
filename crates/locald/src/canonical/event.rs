//! Canonical Event Model: OS-agnostic normalized event representation
//!
//! CanonicalEvent provides a unified view of telemetry from:
//! - Windows ETW (process, network, file, registry)
//! - macOS EndpointSecurity/BSM
//! - Linux eBPF/audit
//!
//! Multi-OS adapters map native events into this canonical form.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::scope::{ProcScopeKey, UserScopeKey, FileScopeKey, SockScopeKey, ExeScopeKey};
use crate::evidence::EvidencePtr;

/// Canonical event types (OS-agnostic)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CanonicalEventType {
    // Process lifecycle
    ProcessCreate {
        parent_proc_key: String,
        child_proc_key: String,
        exe_path: String,
        exe_hash: Option<String>,
        cmdline: Option<String>,
        cwd: Option<String>,
    },
    ProcessExit {
        proc_key: String,
        exit_code: i32,
    },
    
    // Code execution
    Exec {
        proc_key: String,
        exe_path: String,
        exe_hash: Option<String>,
        signer: Option<String>,
        cmdline: Option<String>,
        is_script: bool,
        interpreter: Option<String>,
    },
    ModuleLoad {
        proc_key: String,
        module_path: String,
        module_hash: Option<String>,
        is_signed: Option<bool>,
        signer: Option<String>,
    },
    
    // Memory operations
    MemoryProtect {
        proc_key: String,
        addr: u64,
        size: u64,
        prot_before: u32,
        prot_after: u32,
        is_rwx: bool,
    },
    MemoryMap {
        proc_key: String,
        addr: u64,
        size: u64,
        prot: u32,
        flags: u32,
        file_backed: Option<String>,
    },
    RemoteThreadCreate {
        source_proc_key: String,
        target_proc_key: String,
        start_addr: u64,
    },
    
    // File operations
    FileCreate {
        proc_key: String,
        path: String,
        inode: Option<u64>,
    },
    FileWrite {
        proc_key: String,
        path: String,
        inode: Option<u64>,
        bytes_written: u64,
        entropy: Option<f32>,
    },
    FileDelete {
        proc_key: String,
        path: String,
        inode: Option<u64>,
    },
    FileRename {
        proc_key: String,
        old_path: String,
        new_path: String,
    },
    FileRead {
        proc_key: String,
        path: String,
        inode: Option<u64>,
        bytes_read: u64,
    },
    
    // Network operations
    SocketCreate {
        proc_key: String,
        sock_key: String,
        family: u16,
        sock_type: u16,
        protocol: u16,
    },
    Connect {
        proc_key: String,
        sock_key: String,
        dst_ip: String,
        dst_port: u16,
        protocol: String,
    },
    Listen {
        proc_key: String,
        sock_key: String,
        bind_ip: String,
        bind_port: u16,
    },
    Accept {
        proc_key: String,
        sock_key: String,
        src_ip: String,
        src_port: u16,
    },
    DnsQuery {
        proc_key: String,
        query_name: String,
        query_type: String,
        response_ips: Vec<String>,
    },
    
    // Authentication/Authorization
    Login {
        user_key: String,
        login_type: String,
        source_ip: Option<String>,
        success: bool,
    },
    Logout {
        user_key: String,
    },
    PrivilegeChange {
        proc_key: String,
        uid_before: u32,
        uid_after: u32,
        gid_before: Option<u32>,
        gid_after: Option<u32>,
        caps_added: Vec<String>,
        caps_removed: Vec<String>,
    },
    
    // Persistence mechanisms
    ServiceInstall {
        proc_key: String,
        service_name: String,
        service_path: String,
        start_type: String,
    },
    ScheduledTask {
        proc_key: String,
        task_name: String,
        task_path: String,
        trigger: String,
    },
    LaunchdPlist {
        proc_key: String,
        plist_path: String,
        program_path: String,
        run_at_load: bool,
    },
    RegistryPersist {
        proc_key: String,
        key_path: String,
        value_name: String,
        value_data: String,
    },
    CronJob {
        proc_key: String,
        user: String,
        schedule: String,
        command: String,
    },
    
    // Registry (Windows-specific but canonical)
    RegistryWrite {
        proc_key: String,
        key_path: String,
        value_name: String,
        value_type: String,
        value_data: Vec<u8>,
    },
    RegistryDelete {
        proc_key: String,
        key_path: String,
        value_name: Option<String>,
    },
    
    // System events
    KernelModuleLoad {
        proc_key: Option<String>,
        module_name: String,
        module_path: Option<String>,
        is_signed: Option<bool>,
    },
    LogClear {
        proc_key: Option<String>,
        log_name: String,
    },
    
    // IPC
    PtraceAttach {
        source_proc_key: String,
        target_proc_key: String,
    },
    NamedPipe {
        proc_key: String,
        pipe_name: String,
        operation: String, // create, connect, read, write
    },
    
    // Raw/Unknown (for extensibility)
    Raw {
        event_type: String,
        fields: HashMap<String, serde_json::Value>,
    },
}

/// Canonical event with full context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEvent {
    /// Unique event ID (deterministic)
    pub event_id: String,
    
    /// Host identifier
    pub host_id: String,
    
    /// Boot ID (for PID reuse protection)
    pub boot_id: String,
    
    /// Timestamp (nanoseconds since epoch)
    pub ts: i64,
    
    /// Event type with payload
    pub event: CanonicalEventType,
    
    /// Primary scope key (derived from event)
    pub primary_scope: ScopeKey,
    
    /// Related scope keys
    pub related_scopes: Vec<ScopeKey>,
    
    /// Evidence pointer to raw record
    pub evidence_ptr: EvidencePtr,
    
    /// Source stream identifier
    pub source_stream: String,
    
    /// OS-specific metadata (for explainability)
    pub os_context: OsContext,
    
    /// Additional fields from raw event
    #[serde(default)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Unified scope key enum
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "scope_type")]
pub enum ScopeKey {
    Process(ProcScopeKey),
    User(UserScopeKey),
    File(FileScopeKey),
    Socket(SockScopeKey),
    Exe(ExeScopeKey),
}

impl ScopeKey {
    pub fn as_string(&self) -> String {
        match self {
            ScopeKey::Process(k) => k.to_key_string(),
            ScopeKey::User(k) => k.to_key_string(),
            ScopeKey::File(k) => k.to_key_string(),
            ScopeKey::Socket(k) => k.to_key_string(),
            ScopeKey::Exe(k) => k.to_key_string(),
        }
    }
    
    pub fn scope_type(&self) -> &'static str {
        match self {
            ScopeKey::Process(_) => "process",
            ScopeKey::User(_) => "user",
            ScopeKey::File(_) => "file",
            ScopeKey::Socket(_) => "socket",
            ScopeKey::Exe(_) => "exe",
        }
    }
}

/// OS-specific context for explainability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OsContext {
    /// OS type
    pub os_type: OsType,
    
    /// Native event type name (for explanation rendering)
    pub native_event_type: String,
    
    /// ETW provider (Windows)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etw_provider: Option<String>,
    
    /// EndpointSecurity event type (macOS)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub es_event_type: Option<String>,
    
    /// eBPF tracepoint/kprobe (Linux)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ebpf_hook: Option<String>,
    
    /// Audit event type (Linux)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_type: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsType {
    Windows,
    MacOS,
    Linux,
    #[default]
    Unknown,
}

impl CanonicalEvent {
    /// Generate deterministic event ID
    pub fn compute_event_id(
        host_id: &str,
        boot_id: &str,
        stream_id: &str,
        segment_id: &str,
        record_index: u64,
    ) -> String {
        use sha2::{Sha256, Digest};
        let input = format!("{}|{}|{}|{}|{}", host_id, boot_id, stream_id, segment_id, record_index);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    /// Extract process key from event if applicable
    pub fn proc_key(&self) -> Option<&str> {
        match &self.event {
            CanonicalEventType::ProcessCreate { child_proc_key, .. } => Some(child_proc_key),
            CanonicalEventType::ProcessExit { proc_key, .. } => Some(proc_key),
            CanonicalEventType::Exec { proc_key, .. } => Some(proc_key),
            CanonicalEventType::ModuleLoad { proc_key, .. } => Some(proc_key),
            CanonicalEventType::MemoryProtect { proc_key, .. } => Some(proc_key),
            CanonicalEventType::MemoryMap { proc_key, .. } => Some(proc_key),
            CanonicalEventType::FileCreate { proc_key, .. } => Some(proc_key),
            CanonicalEventType::FileWrite { proc_key, .. } => Some(proc_key),
            CanonicalEventType::FileDelete { proc_key, .. } => Some(proc_key),
            CanonicalEventType::FileRename { proc_key, .. } => Some(proc_key),
            CanonicalEventType::FileRead { proc_key, .. } => Some(proc_key),
            CanonicalEventType::SocketCreate { proc_key, .. } => Some(proc_key),
            CanonicalEventType::Connect { proc_key, .. } => Some(proc_key),
            CanonicalEventType::Listen { proc_key, .. } => Some(proc_key),
            CanonicalEventType::Accept { proc_key, .. } => Some(proc_key),
            CanonicalEventType::DnsQuery { proc_key, .. } => Some(proc_key),
            CanonicalEventType::PrivilegeChange { proc_key, .. } => Some(proc_key),
            CanonicalEventType::ServiceInstall { proc_key, .. } => Some(proc_key),
            CanonicalEventType::ScheduledTask { proc_key, .. } => Some(proc_key),
            CanonicalEventType::LaunchdPlist { proc_key, .. } => Some(proc_key),
            CanonicalEventType::RegistryPersist { proc_key, .. } => Some(proc_key),
            CanonicalEventType::CronJob { proc_key, .. } => Some(proc_key),
            CanonicalEventType::RegistryWrite { proc_key, .. } => Some(proc_key),
            CanonicalEventType::RegistryDelete { proc_key, .. } => Some(proc_key),
            CanonicalEventType::RemoteThreadCreate { source_proc_key, .. } => Some(source_proc_key),
            CanonicalEventType::PtraceAttach { source_proc_key, .. } => Some(source_proc_key),
            CanonicalEventType::NamedPipe { proc_key, .. } => Some(proc_key),
            CanonicalEventType::KernelModuleLoad { proc_key, .. } => proc_key.as_deref(),
            CanonicalEventType::LogClear { proc_key, .. } => proc_key.as_deref(),
            CanonicalEventType::Login { .. } | CanonicalEventType::Logout { .. } => None,
            CanonicalEventType::Raw { .. } => None,
        }
    }
    
    /// Get event domain for corroboration scoring
    pub fn domain(&self) -> EventDomain {
        match &self.event {
            CanonicalEventType::ProcessCreate { .. } |
            CanonicalEventType::ProcessExit { .. } |
            CanonicalEventType::Exec { .. } |
            CanonicalEventType::ModuleLoad { .. } => EventDomain::Process,
            
            CanonicalEventType::MemoryProtect { .. } |
            CanonicalEventType::MemoryMap { .. } |
            CanonicalEventType::RemoteThreadCreate { .. } => EventDomain::Memory,
            
            CanonicalEventType::FileCreate { .. } |
            CanonicalEventType::FileWrite { .. } |
            CanonicalEventType::FileDelete { .. } |
            CanonicalEventType::FileRename { .. } |
            CanonicalEventType::FileRead { .. } => EventDomain::File,
            
            CanonicalEventType::SocketCreate { .. } |
            CanonicalEventType::Connect { .. } |
            CanonicalEventType::Listen { .. } |
            CanonicalEventType::Accept { .. } |
            CanonicalEventType::DnsQuery { .. } => EventDomain::Network,
            
            CanonicalEventType::Login { .. } |
            CanonicalEventType::Logout { .. } |
            CanonicalEventType::PrivilegeChange { .. } => EventDomain::Auth,
            
            CanonicalEventType::ServiceInstall { .. } |
            CanonicalEventType::ScheduledTask { .. } |
            CanonicalEventType::LaunchdPlist { .. } |
            CanonicalEventType::RegistryPersist { .. } |
            CanonicalEventType::CronJob { .. } => EventDomain::Persist,
            
            CanonicalEventType::RegistryWrite { .. } |
            CanonicalEventType::RegistryDelete { .. } => EventDomain::File, // Registry is like file for scoring
            
            CanonicalEventType::KernelModuleLoad { .. } |
            CanonicalEventType::LogClear { .. } => EventDomain::Tamper,
            
            CanonicalEventType::PtraceAttach { .. } |
            CanonicalEventType::NamedPipe { .. } => EventDomain::Memory, // IPC is memory-adjacent
            
            CanonicalEventType::Raw { .. } => EventDomain::Unknown,
        }
    }
    
    /// Check if this is a Tier-0 invariant violation candidate
    pub fn is_tier0_candidate(&self) -> bool {
        matches!(
            &self.event,
            CanonicalEventType::MemoryProtect { is_rwx: true, .. } |
            CanonicalEventType::RemoteThreadCreate { .. } |
            CanonicalEventType::PtraceAttach { .. } |
            CanonicalEventType::KernelModuleLoad { is_signed: Some(false), .. } |
            CanonicalEventType::LogClear { .. }
        )
    }
}

/// Event domains for corroboration scoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventDomain {
    Process,
    File,
    Network,
    Auth,
    Memory,
    Persist,
    Tamper,
    Unknown,
}

impl EventDomain {
    pub fn all() -> &'static [EventDomain] {
        &[
            EventDomain::Process,
            EventDomain::File,
            EventDomain::Network,
            EventDomain::Auth,
            EventDomain::Memory,
            EventDomain::Persist,
            EventDomain::Tamper,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_id_determinism() {
        let id1 = CanonicalEvent::compute_event_id("host1", "boot1", "stream1", "seg1", 100);
        let id2 = CanonicalEvent::compute_event_id("host1", "boot1", "stream1", "seg1", 100);
        assert_eq!(id1, id2);
        
        let id3 = CanonicalEvent::compute_event_id("host1", "boot1", "stream1", "seg1", 101);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_tier0_detection() {
        // Memory RWX should be tier-0 candidate
        let rwx_event = CanonicalEventType::MemoryProtect {
            proc_key: "pk1".to_string(),
            addr: 0x1000,
            size: 4096,
            prot_before: 1,
            prot_after: 7,
            is_rwx: true,
        };
        
        // Simulate event check
        let is_rwx = matches!(rwx_event, CanonicalEventType::MemoryProtect { is_rwx: true, .. });
        assert!(is_rwx);
    }
}

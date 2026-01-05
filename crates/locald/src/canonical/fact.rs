//! Canonical Fact Model: Derived atoms from events
//!
//! Facts are deterministic derived atoms used by playbooks and explanations.
//! Each Fact is derived from one or more CanonicalEvents and carries evidence pointers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::evidence::EvidencePtr;

/// Canonical Fact - derived from events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    /// Unique fact ID (deterministic)
    pub fact_id: String,
    
    /// Timestamp of the fact (from earliest contributing event)
    pub ts: i64,
    
    /// Host identifier
    pub host_id: String,
    
    /// Scope key that this fact pertains to
    pub scope_key: String,
    
    /// Type of fact with payload
    pub fact_type: FactType,
    
    /// Additional fields (may contain "unknown" for missing data)
    pub fields: HashMap<String, FieldValue>,
    
    /// Evidence pointers supporting this fact
    pub evidence_ptrs: Vec<EvidencePtr>,
    
    /// Optional conflict set ID (if multiple sources disagree)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict_set_id: Option<String>,
    
    /// Visibility gaps (fields that couldn't be determined)
    #[serde(default)]
    pub visibility_gaps: Vec<String>,
}

/// Field value with certainty tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldValue {
    String(String),
    Int(i64),
    UInt(u64),
    Float(f64),
    Bool(bool),
    Bytes(Vec<u8>),
    List(Vec<FieldValue>),
    Unknown { reason: String },
}

impl FieldValue {
    pub fn string(s: impl Into<String>) -> Self {
        FieldValue::String(s.into())
    }
    
    pub fn unknown(reason: impl Into<String>) -> Self {
        FieldValue::Unknown { reason: reason.into() }
    }
    
    pub fn is_unknown(&self) -> bool {
        matches!(self, FieldValue::Unknown { .. })
    }
    
    pub fn as_string(&self) -> Option<&str> {
        match self {
            FieldValue::String(s) => Some(s),
            _ => None,
        }
    }
}

/// Fact types - derived semantic atoms
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FactType {
    /// Process spawned another process
    ProcSpawn {
        parent_proc_key: String,
        child_proc_key: String,
    },
    
    /// Executable was run
    Exec {
        proc_key: String,
        exe_hash: Option<String>,
        exe_path: String,
        signer: Option<String>,
        cmdline: Option<String>,
    },
    
    /// Outbound network connection
    OutboundConnect {
        proc_key: String,
        dst_ip: String,
        dst_port: u16,
        protocol: String,
        sock_key: Option<String>,
    },
    
    /// Inbound network connection
    InboundAccept {
        proc_key: String,
        src_ip: String,
        src_port: u16,
        protocol: String,
        sock_key: Option<String>,
    },
    
    /// DNS resolution
    DnsResolve {
        proc_key: String,
        query_name: String,
        resolved_ips: Vec<String>,
    },
    
    /// File write operation
    WritePath {
        proc_key: String,
        path: String,
        inode: Option<u64>,
        bytes_written: u64,
        entropy: Option<f32>,
    },
    
    /// File read operation
    ReadPath {
        proc_key: String,
        path: String,
        inode: Option<u64>,
        bytes_read: u64,
    },
    
    /// File creation
    CreatePath {
        proc_key: String,
        path: String,
        inode: Option<u64>,
    },
    
    /// File deletion
    DeletePath {
        proc_key: String,
        path: String,
    },
    
    /// Persistence artifact created/enabled
    PersistArtifact {
        proc_key: String,
        persist_type: PersistType,
        path: String,
        enabled: bool,
    },
    
    /// Privilege boundary crossing
    PrivilegeBoundary {
        proc_key: String,
        uid_before: u32,
        uid_after: u32,
        caps_added: Vec<String>,
        caps_removed: Vec<String>,
    },
    
    /// Memory protection change (RWX detection)
    MemWX {
        proc_key: String,
        addr: u64,
        size: u64,
        prot_before: u32,
        prot_after: u32,
    },
    
    /// Module/library loaded
    ModuleLoad {
        proc_key: String,
        module_path: String,
        module_hash: Option<String>,
        is_signed: Option<bool>,
    },
    
    /// Remote thread injection
    RemoteThread {
        source_proc_key: String,
        target_proc_key: String,
        start_addr: u64,
    },
    
    /// Ptrace/debugging attachment
    DebugAttach {
        source_proc_key: String,
        target_proc_key: String,
    },
    
    /// Kernel module loaded
    KernelModule {
        module_name: String,
        module_path: Option<String>,
        is_signed: Option<bool>,
    },
    
    /// Log/audit cleared
    LogCleared {
        proc_key: Option<String>,
        log_name: String,
    },
    
    /// Authentication event
    AuthEvent {
        user_key: String,
        auth_type: String,
        success: bool,
        source_ip: Option<String>,
    },
}

/// Persistence artifact types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PersistType {
    /// Windows service
    Service { service_name: String, start_type: String },
    /// Windows scheduled task
    ScheduledTask { task_name: String },
    /// Windows registry run key
    RegistryRunKey { key_path: String, value_name: String },
    /// macOS LaunchAgent/LaunchDaemon
    LaunchdPlist { run_at_load: bool },
    /// Linux cron job
    CronJob { schedule: String },
    /// Linux systemd unit
    SystemdUnit { unit_name: String },
    /// Other/generic
    Other { description: String },
}

impl Fact {
    /// Generate deterministic fact ID
    pub fn compute_fact_id(
        host_id: &str,
        scope_key: &str,
        fact_type: &FactType,
        ts: i64,
    ) -> String {
        use sha2::{Sha256, Digest};
        
        let type_str = match fact_type {
            FactType::ProcSpawn { parent_proc_key, child_proc_key } => 
                format!("spawn:{}:{}", parent_proc_key, child_proc_key),
            FactType::Exec { proc_key, exe_path, .. } => 
                format!("exec:{}:{}", proc_key, exe_path),
            FactType::OutboundConnect { proc_key, dst_ip, dst_port, .. } => 
                format!("connect:{}:{}:{}", proc_key, dst_ip, dst_port),
            FactType::InboundAccept { proc_key, src_ip, src_port, .. } =>
                format!("accept:{}:{}:{}", proc_key, src_ip, src_port),
            FactType::DnsResolve { proc_key, query_name, .. } =>
                format!("dns:{}:{}", proc_key, query_name),
            FactType::WritePath { proc_key, path, .. } => 
                format!("write:{}:{}", proc_key, path),
            FactType::ReadPath { proc_key, path, .. } =>
                format!("read:{}:{}", proc_key, path),
            FactType::CreatePath { proc_key, path, .. } =>
                format!("create:{}:{}", proc_key, path),
            FactType::DeletePath { proc_key, path, .. } =>
                format!("delete:{}:{}", proc_key, path),
            FactType::PersistArtifact { proc_key, path, .. } =>
                format!("persist:{}:{}", proc_key, path),
            FactType::PrivilegeBoundary { proc_key, uid_before, uid_after, .. } =>
                format!("priv:{}:{}:{}", proc_key, uid_before, uid_after),
            FactType::MemWX { proc_key, addr, .. } =>
                format!("memwx:{}:{:x}", proc_key, addr),
            FactType::ModuleLoad { proc_key, module_path, .. } =>
                format!("modload:{}:{}", proc_key, module_path),
            FactType::RemoteThread { source_proc_key, target_proc_key, .. } =>
                format!("rthread:{}:{}", source_proc_key, target_proc_key),
            FactType::DebugAttach { source_proc_key, target_proc_key } =>
                format!("debug:{}:{}", source_proc_key, target_proc_key),
            FactType::KernelModule { module_name, .. } =>
                format!("kmod:{}", module_name),
            FactType::LogCleared { log_name, .. } =>
                format!("logclear:{}", log_name),
            FactType::AuthEvent { user_key, auth_type, .. } =>
                format!("auth:{}:{}", user_key, auth_type),
        };
        
        let ts_bucket = ts / 1_000_000_000; // Second bucket
        let input = format!("{}|{}|{}|{}", host_id, scope_key, type_str, ts_bucket);
        
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        format!("fact:{:x}", hasher.finalize())
    }
    
    /// Get the primary process key if applicable
    pub fn proc_key(&self) -> Option<&str> {
        match &self.fact_type {
            FactType::ProcSpawn { child_proc_key, .. } => Some(child_proc_key),
            FactType::Exec { proc_key, .. } => Some(proc_key),
            FactType::OutboundConnect { proc_key, .. } => Some(proc_key),
            FactType::InboundAccept { proc_key, .. } => Some(proc_key),
            FactType::DnsResolve { proc_key, .. } => Some(proc_key),
            FactType::WritePath { proc_key, .. } => Some(proc_key),
            FactType::ReadPath { proc_key, .. } => Some(proc_key),
            FactType::CreatePath { proc_key, .. } => Some(proc_key),
            FactType::DeletePath { proc_key, .. } => Some(proc_key),
            FactType::PersistArtifact { proc_key, .. } => Some(proc_key),
            FactType::PrivilegeBoundary { proc_key, .. } => Some(proc_key),
            FactType::MemWX { proc_key, .. } => Some(proc_key),
            FactType::ModuleLoad { proc_key, .. } => Some(proc_key),
            FactType::RemoteThread { source_proc_key, .. } => Some(source_proc_key),
            FactType::DebugAttach { source_proc_key, .. } => Some(source_proc_key),
            FactType::KernelModule { .. } => None,
            FactType::LogCleared { proc_key, .. } => proc_key.as_deref(),
            FactType::AuthEvent { .. } => None,
        }
    }
    
    /// Get the domain of this fact
    pub fn domain(&self) -> FactDomain {
        match &self.fact_type {
            FactType::ProcSpawn { .. } | FactType::Exec { .. } | FactType::ModuleLoad { .. } => 
                FactDomain::Process,
            FactType::OutboundConnect { .. } | FactType::InboundAccept { .. } | FactType::DnsResolve { .. } => 
                FactDomain::Network,
            FactType::WritePath { .. } | FactType::ReadPath { .. } | FactType::CreatePath { .. } | FactType::DeletePath { .. } => 
                FactDomain::File,
            FactType::PersistArtifact { .. } => 
                FactDomain::Persist,
            FactType::PrivilegeBoundary { .. } | FactType::AuthEvent { .. } => 
                FactDomain::Auth,
            FactType::MemWX { .. } | FactType::RemoteThread { .. } | FactType::DebugAttach { .. } => 
                FactDomain::Memory,
            FactType::KernelModule { .. } | FactType::LogCleared { .. } => 
                FactDomain::Tamper,
        }
    }
    
    /// Check if this fact has visibility gaps
    pub fn has_visibility_gaps(&self) -> bool {
        !self.visibility_gaps.is_empty() || 
            self.fields.values().any(|v| v.is_unknown())
    }
    
    /// Check if this is a Tier-0 invariant fact
    pub fn is_tier0(&self) -> bool {
        matches!(
            &self.fact_type,
            FactType::MemWX { .. } |
            FactType::RemoteThread { .. } |
            FactType::DebugAttach { .. } |
            FactType::KernelModule { is_signed: Some(false), .. } |
            FactType::LogCleared { .. }
        )
    }
}

/// Fact domain for corroboration scoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FactDomain {
    Process,
    File,
    Network,
    Auth,
    Memory,
    Persist,
    Tamper,
}

impl FactDomain {
    pub fn all() -> &'static [FactDomain] {
        &[
            FactDomain::Process,
            FactDomain::File,
            FactDomain::Network,
            FactDomain::Auth,
            FactDomain::Memory,
            FactDomain::Persist,
            FactDomain::Tamper,
        ]
    }
}

/// Builder for creating facts
pub struct FactBuilder {
    ts: i64,
    host_id: String,
    scope_key: String,
    fact_type: FactType,
    fields: HashMap<String, FieldValue>,
    evidence_ptrs: Vec<EvidencePtr>,
    conflict_set_id: Option<String>,
    visibility_gaps: Vec<String>,
}

impl FactBuilder {
    pub fn new(host_id: impl Into<String>, scope_key: impl Into<String>, ts: i64, fact_type: FactType) -> Self {
        Self {
            ts,
            host_id: host_id.into(),
            scope_key: scope_key.into(),
            fact_type,
            fields: HashMap::new(),
            evidence_ptrs: Vec::new(),
            conflict_set_id: None,
            visibility_gaps: Vec::new(),
        }
    }
    
    pub fn with_field(mut self, key: impl Into<String>, value: FieldValue) -> Self {
        self.fields.insert(key.into(), value);
        self
    }
    
    pub fn with_evidence(mut self, ptr: EvidencePtr) -> Self {
        self.evidence_ptrs.push(ptr);
        self
    }
    
    pub fn with_evidences(mut self, ptrs: Vec<EvidencePtr>) -> Self {
        self.evidence_ptrs.extend(ptrs);
        self
    }
    
    pub fn with_conflict_set(mut self, id: impl Into<String>) -> Self {
        self.conflict_set_id = Some(id.into());
        self
    }
    
    pub fn with_visibility_gap(mut self, gap: impl Into<String>) -> Self {
        self.visibility_gaps.push(gap.into());
        self
    }
    
    pub fn build(self) -> Fact {
        let fact_id = Fact::compute_fact_id(&self.host_id, &self.scope_key, &self.fact_type, self.ts);
        
        Fact {
            fact_id,
            ts: self.ts,
            host_id: self.host_id,
            scope_key: self.scope_key,
            fact_type: self.fact_type,
            fields: self.fields,
            evidence_ptrs: self.evidence_ptrs,
            conflict_set_id: self.conflict_set_id,
            visibility_gaps: self.visibility_gaps,
        }
    }
}

/// Conflict set for disagreeing facts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictSet {
    pub conflict_id: String,
    pub fact_ids: Vec<String>,
    pub subject: String,
    pub description: String,
    pub resolution: Option<ConflictResolution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictResolution {
    /// Take the majority
    Majority { winning_fact_id: String },
    /// Take the most confident source
    HighestConfidence { winning_fact_id: String, source: String },
    /// Manual analyst resolution
    AnalystResolved { winning_fact_id: String, reason: String },
    /// Unresolved - keep both
    Unresolved,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fact_id_determinism() {
        let fact_type = FactType::Exec {
            proc_key: "proc:abc123".to_string(),
            exe_hash: Some("sha256:xyz".to_string()),
            exe_path: "/usr/bin/bash".to_string(),
            signer: None,
            cmdline: Some("-c whoami".to_string()),
        };
        
        let id1 = Fact::compute_fact_id("host1", "scope1", &fact_type, 1000000000);
        let id2 = Fact::compute_fact_id("host1", "scope1", &fact_type, 1000000000);
        
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_fact_builder() {
        let fact = FactBuilder::new(
            "host1",
            "proc:abc",
            1000000000,
            FactType::OutboundConnect {
                proc_key: "proc:abc".to_string(),
                dst_ip: "10.0.0.1".to_string(),
                dst_port: 443,
                protocol: "tcp".to_string(),
                sock_key: None,
            },
        )
        .with_evidence(EvidencePtr::minimal("stream", "seg", 0))
        .with_field("user_agent", FieldValue::unknown("not captured"))
        .build();
        
        assert!(fact.has_visibility_gaps());
        assert_eq!(fact.domain(), FactDomain::Network);
    }

    #[test]
    fn test_tier0_detection() {
        let memwx = FactType::MemWX {
            proc_key: "proc:abc".to_string(),
            addr: 0x7fff0000,
            size: 4096,
            prot_before: 1,
            prot_after: 7,
        };
        
        let fact = FactBuilder::new("host1", "proc:abc", 1000, memwx).build();
        assert!(fact.is_tier0());
        
        let exec = FactType::Exec {
            proc_key: "proc:abc".to_string(),
            exe_hash: None,
            exe_path: "/bin/ls".to_string(),
            signer: None,
            cmdline: None,
        };
        
        let fact2 = FactBuilder::new("host1", "proc:abc", 1000, exec).build();
        assert!(!fact2.is_tier0());
    }
}

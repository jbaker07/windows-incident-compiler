//! Canonical Fact Model: Deterministic derived atoms from events.
//!
//! Facts are used by playbooks and explanations. They are deterministically derived
//! from CanonicalEvents and support multiple evidence pointers.

use super::canonical_event::EvidencePtr;
use super::scope_keys::ScopeKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Fact Types: All detectable primitives
// ============================================================================

/// Enumeration of all fact types supported by the system
/// Note: Does not derive Eq/Hash due to f64 fields (entropy). Use fact_id for identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "fact_type", rename_all = "snake_case")]
pub enum FactType {
    /// Process spawned another process
    ProcSpawn {
        parent_proc_key: String,
        child_proc_key: String,
    },

    /// Executable execution
    Exec {
        exe_hash: Option<String>,
        path: String,
        signer: Option<String>,
        cmdline: Option<String>,
    },

    /// Outbound network connection
    OutboundConnect {
        dst_ip: String,
        dst_port: u16,
        proto: String,
        sock_id: Option<String>,
    },

    /// Inbound network connection (listen/accept)
    InboundConnect {
        src_ip: String,
        src_port: u16,
        proto: String,
        sock_id: Option<String>,
    },

    /// DNS resolution
    DnsResolve {
        query: String,
        responses: Vec<String>,
    },

    /// File write operation
    WritePath {
        path: String,
        inode: Option<u64>,
        bytes: Option<u64>,
        entropy: Option<f64>,
    },

    /// File read operation
    ReadPath {
        path: String,
        inode: Option<u64>,
        bytes: Option<u64>,
    },

    /// File creation
    CreatePath { path: String, inode: Option<u64> },

    /// File deletion
    DeletePath { path: String, inode: Option<u64> },

    /// File rename/move
    RenamePath { old_path: String, new_path: String },

    /// Persistence artifact created/modified
    PersistArtifact {
        artifact_type: PersistenceType,
        path_or_key: String,
        enable_action: bool,
    },

    /// Privilege boundary crossing
    PrivilegeBoundary {
        uid_before: u32,
        uid_after: u32,
        caps_before: Option<u64>,
        caps_after: Option<u64>,
    },

    /// Memory WX violation (write+execute)
    MemWX {
        addr: u64,
        size: u64,
        prot_before: u32,
        prot_after: u32,
    },

    /// Memory allocation for code
    MemAlloc {
        addr: u64,
        size: u64,
        protection: u32,
    },

    /// Module/library loaded
    ModuleLoad {
        path: String,
        hash: Option<String>,
        signer: Option<String>,
        is_kernel: bool,
    },

    /// Code injection into another process
    Injection {
        source_proc_key: String,
        target_proc_key: String,
        injection_type: InjectionType,
    },

    /// Registry modification (Windows)
    RegistryMod {
        key: String,
        value_name: Option<String>,
        operation: RegistryOp,
    },

    /// Authentication event
    AuthEvent {
        auth_type: AuthType,
        user: String,
        source: Option<String>,
        success: bool,
    },

    /// Log tampering
    LogTamper {
        log_type: String,
        action: TamperAction,
    },

    /// Security tool disabled
    SecurityToolDisable { tool_name: String, method: String },

    /// Command execution via shell
    ShellCommand {
        shell: String,
        command: String,
        is_encoded: bool,
    },

    /// Script execution
    ScriptExec {
        interpreter: String,
        script_path: Option<String>,
        script_content_hash: Option<String>,
    },

    /// Unknown/custom fact type
    Unknown {
        raw_type: String,
        fields: HashMap<String, serde_json::Value>,
    },
}

/// Types of persistence mechanisms
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceType {
    /// Windows service
    Service,
    /// Windows scheduled task
    ScheduledTask,
    /// Windows registry run key
    RegistryRunKey,
    /// macOS launch agent
    LaunchAgent,
    /// macOS launch daemon
    LaunchDaemon,
    /// Linux cron job
    CronJob,
    /// Linux systemd service
    SystemdService,
    /// SSH authorized keys
    SshAuthorizedKey,
    /// Shell profile modification
    ShellProfile,
    /// Other/unknown
    Other(String),
}

/// Types of code injection
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionType {
    /// Process hollowing
    ProcessHollowing,
    /// DLL injection
    DllInjection,
    /// Remote thread creation
    RemoteThread,
    /// APC injection
    ApcInjection,
    /// ptrace attach (Linux)
    PtraceAttach,
    /// dyld interpose (macOS)
    DyldInterpose,
    /// memfd_create + exec
    MemfdExec,
    /// Other
    Other(String),
}

/// Registry operation types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryOp {
    Create,
    SetValue,
    DeleteValue,
    DeleteKey,
}

/// Authentication event types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    Interactive,
    Network,
    Service,
    Unlock,
    RemoteInteractive,
    CachedInteractive,
    Sudo,
    Su,
    Ssh,
    Other(String),
}

/// Log tampering actions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperAction {
    Clear,
    Delete,
    Modify,
    Disable,
}

// ============================================================================
// Fact Structure
// ============================================================================

/// Field completeness indicator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldStatus {
    /// Field has a value
    Present,
    /// Field is unknown/missing from source
    Unknown,
    /// Field was redacted
    Redacted,
}

/// A canonical fact derived from one or more events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    /// Unique fact identifier (deterministic)
    pub fact_id: String,

    /// Timestamp of the fact (earliest evidence timestamp)
    pub ts: DateTime<Utc>,

    /// Host where fact was observed
    pub host_id: String,

    /// Scope key for entity grouping
    pub scope_key: ScopeKey,

    /// The fact type with its specific fields
    pub fact_type: FactType,

    /// Additional fields not captured in fact_type
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra_fields: HashMap<String, serde_json::Value>,

    /// Evidence pointers supporting this fact
    pub evidence_ptrs: Vec<EvidencePtr>,

    /// Field completeness tracking
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub field_status: HashMap<String, FieldStatus>,

    /// If facts conflict, they share a conflict_set_id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict_set_id: Option<String>,

    /// Confidence in this fact (0.0 to 1.0)
    pub confidence: f64,

    /// Whether this fact has visibility gaps
    pub has_visibility_gap: bool,

    /// Visibility gap details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility_gap_reason: Option<String>,
}

impl Fact {
    /// Create a new fact with the given parameters
    pub fn new(
        host_id: impl Into<String>,
        scope_key: ScopeKey,
        fact_type: FactType,
        evidence_ptrs: Vec<EvidencePtr>,
    ) -> Self {
        let host_id = host_id.into();
        let ts = evidence_ptrs
            .first()
            .and_then(|p| p.ts)
            .unwrap_or_else(Utc::now);

        let fact_id = Self::compute_fact_id(&host_id, &scope_key, &fact_type, &ts);

        Self {
            fact_id,
            ts,
            host_id,
            scope_key,
            fact_type,
            extra_fields: HashMap::new(),
            evidence_ptrs,
            field_status: HashMap::new(),
            conflict_set_id: None,
            confidence: 1.0,
            has_visibility_gap: false,
            visibility_gap_reason: None,
        }
    }

    /// Compute deterministic fact ID
    fn compute_fact_id(
        host_id: &str,
        scope_key: &ScopeKey,
        fact_type: &FactType,
        ts: &DateTime<Utc>,
    ) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(host_id.as_bytes());
        hasher.update(scope_key.to_string().as_bytes());
        hasher.update(format!("{:?}", fact_type).as_bytes());
        hasher.update(ts.timestamp().to_le_bytes());
        hex::encode(&hasher.finalize()[..16])
    }

    /// Mark a field as unknown
    pub fn mark_unknown(&mut self, field: impl Into<String>) {
        self.field_status.insert(field.into(), FieldStatus::Unknown);
        self.has_visibility_gap = true;
    }

    /// Add additional evidence pointer
    pub fn add_evidence(&mut self, ptr: EvidencePtr) {
        if !self.evidence_ptrs.contains(&ptr) {
            self.evidence_ptrs.push(ptr);
        }
    }

    /// Set conflict set ID for conflicting facts
    pub fn set_conflict(&mut self, conflict_id: impl Into<String>) {
        self.conflict_set_id = Some(conflict_id.into());
    }

    /// Get the domain category for this fact (for corroboration scoring)
    pub fn domain(&self) -> FactDomain {
        match &self.fact_type {
            FactType::ProcSpawn { .. } | FactType::Exec { .. } => FactDomain::Process,
            FactType::OutboundConnect { .. }
            | FactType::InboundConnect { .. }
            | FactType::DnsResolve { .. } => FactDomain::Network,
            FactType::WritePath { .. }
            | FactType::ReadPath { .. }
            | FactType::CreatePath { .. }
            | FactType::DeletePath { .. }
            | FactType::RenamePath { .. } => FactDomain::File,
            FactType::PersistArtifact { .. } | FactType::RegistryMod { .. } => FactDomain::Persist,
            FactType::PrivilegeBoundary { .. } | FactType::AuthEvent { .. } => FactDomain::Auth,
            FactType::MemWX { .. } | FactType::MemAlloc { .. } | FactType::Injection { .. } => {
                FactDomain::Memory
            }
            FactType::LogTamper { .. } | FactType::SecurityToolDisable { .. } => FactDomain::Tamper,
            FactType::ModuleLoad { .. } => FactDomain::Module,
            FactType::ShellCommand { .. } | FactType::ScriptExec { .. } => FactDomain::Execution,
            FactType::Unknown { .. } => FactDomain::Unknown,
        }
    }
}

/// Domain categories for corroboration scoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactDomain {
    Process,
    File,
    Network,
    Auth,
    Memory,
    Persist,
    Tamper,
    Module,
    Execution,
    Unknown,
}

impl FactDomain {
    /// All domains for iteration
    pub fn all() -> &'static [FactDomain] {
        &[
            FactDomain::Process,
            FactDomain::File,
            FactDomain::Network,
            FactDomain::Auth,
            FactDomain::Memory,
            FactDomain::Persist,
            FactDomain::Tamper,
            FactDomain::Module,
            FactDomain::Execution,
        ]
    }
}

// ============================================================================
// Fact Store
// ============================================================================

/// In-memory fact store with conflict tracking
#[derive(Debug, Default)]
pub struct FactStore {
    facts: HashMap<String, Fact>,
    by_scope: HashMap<String, Vec<String>>,
    by_host: HashMap<String, Vec<String>>,
    conflicts: HashMap<String, Vec<String>>,
}

impl FactStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a fact, handling conflicts
    pub fn insert(&mut self, fact: Fact) {
        let fact_id = fact.fact_id.clone();
        let scope_key = fact.scope_key.to_string();
        let host_id = fact.host_id.clone();

        self.by_scope
            .entry(scope_key)
            .or_default()
            .push(fact_id.clone());
        self.by_host
            .entry(host_id)
            .or_default()
            .push(fact_id.clone());

        if let Some(conflict_id) = &fact.conflict_set_id {
            self.conflicts
                .entry(conflict_id.clone())
                .or_default()
                .push(fact_id.clone());
        }

        self.facts.insert(fact_id, fact);
    }

    /// Get fact by ID
    pub fn get(&self, fact_id: &str) -> Option<&Fact> {
        self.facts.get(fact_id)
    }

    /// Get facts by scope key
    pub fn by_scope(&self, scope_key: &ScopeKey) -> Vec<&Fact> {
        self.by_scope
            .get(&scope_key.to_string())
            .map(|ids| ids.iter().filter_map(|id| self.facts.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get facts by host
    pub fn by_host(&self, host_id: &str) -> Vec<&Fact> {
        self.by_host
            .get(host_id)
            .map(|ids| ids.iter().filter_map(|id| self.facts.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get conflicting facts
    pub fn get_conflicts(&self, conflict_id: &str) -> Vec<&Fact> {
        self.conflicts
            .get(conflict_id)
            .map(|ids| ids.iter().filter_map(|id| self.facts.get(id)).collect())
            .unwrap_or_default()
    }

    /// Count facts by domain
    pub fn domain_counts(&self, scope_key: &ScopeKey) -> HashMap<FactDomain, usize> {
        let mut counts = HashMap::new();
        for fact in self.by_scope(scope_key) {
            *counts.entry(fact.domain()).or_insert(0) += 1;
        }
        counts
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fact_creation() {
        let ptr = EvidencePtr::new("stream", "seg", 0).with_timestamp(Utc::now());
        let fact = Fact::new(
            "host1",
            ScopeKey::Process {
                key: "proc123".to_string(),
            },
            FactType::Exec {
                exe_hash: Some("abc123".to_string()),
                path: "/bin/sh".to_string(),
                signer: None,
                cmdline: Some("-c whoami".to_string()),
            },
            vec![ptr],
        );

        assert!(!fact.fact_id.is_empty());
        assert_eq!(fact.domain(), FactDomain::Process);
    }

    #[test]
    fn test_fact_store() {
        let mut store = FactStore::new();
        let ptr = EvidencePtr::new("stream", "seg", 0).with_timestamp(Utc::now());
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };

        let fact = Fact::new(
            "host1",
            scope.clone(),
            FactType::OutboundConnect {
                dst_ip: "1.2.3.4".to_string(),
                dst_port: 443,
                proto: "tcp".to_string(),
                sock_id: None,
            },
            vec![ptr],
        );

        store.insert(fact);

        let facts = store.by_scope(&scope);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].domain(), FactDomain::Network);
    }
}

//! CanonicalEvent and EvidencePtr: Unified event model across Windows ETW, macOS ES/BSM, Linux eBPF/audit.
//!
//! EvidencePtr provides stable, deterministic references that survive replays and support
//! deref to either canonical DB records or raw segment files.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ============================================================================
// EvidencePtr: Stable, Deterministic Evidence Reference
// ============================================================================

/// EvidencePtr must be stable across replays and globally unique.
/// Format: { stream_id, segment_id, record_index, sha256_of_record_bytes(optional), ts(optional) }
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidencePtr {
    /// Stream identifier (e.g., "windows_etw_process", "macos_es_exec", "linux_ebpf_syscall")
    pub stream_id: String,
    /// Segment file identifier (rotating capture segment)
    pub segment_id: String,
    /// Record index within the segment (0-based)
    pub record_index: u64,
    /// Optional SHA256 of record bytes for integrity verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_sha256: Option<String>,
    /// Optional timestamp (do not trust alone; use for display/ordering hints)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<DateTime<Utc>>,
}

impl EvidencePtr {
    pub fn new(
        stream_id: impl Into<String>,
        segment_id: impl Into<String>,
        record_index: u64,
    ) -> Self {
        Self {
            stream_id: stream_id.into(),
            segment_id: segment_id.into(),
            record_index,
            record_sha256: None,
            ts: None,
        }
    }

    pub fn with_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.record_sha256 = Some(sha256.into());
        self
    }

    pub fn with_timestamp(mut self, ts: DateTime<Utc>) -> Self {
        self.ts = Some(ts);
        self
    }

    /// Compute deterministic key for DB lookups
    pub fn canonical_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.stream_id, self.segment_id, self.record_index
        )
    }

    /// Compute SHA256 from record bytes
    pub fn compute_sha256(record_bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(record_bytes);
        hex::encode(hasher.finalize())
    }
}

/// Result of dereferencing an EvidencePtr
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // RawSegment needs full bytes for forensic analysis
pub enum DerefResult {
    /// Successfully retrieved canonical event from DB
    Canonical(CanonicalEvent),
    /// Fell back to raw segment file
    RawSegment {
        segment_path: String,
        record_bytes: Vec<u8>,
    },
    /// Integrity verification failed
    IntegrityError {
        expected_sha256: String,
        actual_sha256: String,
    },
    /// Evidence not found (segment rotated/deleted)
    Missing { reason: String },
}

impl DerefResult {
    pub fn is_degraded(&self) -> bool {
        matches!(
            self,
            DerefResult::IntegrityError { .. } | DerefResult::Missing { .. }
        )
    }
}

// ============================================================================
// CanonicalEvent: Unified Event Model (Multi-OS)
// ============================================================================

/// Canonical event type enumeration covering all OS primitives
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CanonicalEventType {
    // Process events
    ProcessCreate,
    ProcessExit,
    ProcessExec,
    ThreadCreate,
    ThreadExit,

    // Memory events
    MemoryMap,
    MemoryProtect,
    MemoryAllocate,

    // File events
    FileCreate,
    FileOpen,
    FileRead,
    FileWrite,
    FileDelete,
    FileRename,
    FileSetAttributes,

    // Network events
    SocketCreate,
    SocketConnect,
    SocketAccept,
    SocketBind,
    SocketListen,
    SocketSend,
    SocketReceive,
    SocketClose,
    DnsQuery,

    // Registry events (Windows-specific but canonical)
    RegistryCreate,
    RegistryOpen,
    RegistrySetValue,
    RegistryDeleteValue,
    RegistryDeleteKey,

    // Authentication/privilege events
    UserLogon,
    UserLogoff,
    PrivilegeEscalation,
    CapabilityChange,
    TokenManipulation,

    // Module/library events
    ModuleLoad,
    ModuleUnload,
    KernelModuleLoad,
    KernelModuleUnload,

    // Persistence events
    ServiceCreate,
    ServiceStart,
    ServiceStop,
    ScheduledTaskCreate,
    LaunchAgentCreate, // macOS
    CronJobCreate,     // Linux

    // IPC events
    PipeCreate,
    PipeConnect,
    SharedMemoryCreate,
    SharedMemoryOpen,

    // Tamper events
    LogClear,
    AuditPolicyChange,
    SecurityToolDisable,

    // Generic/unknown
    Unknown { raw_type: String },
}

/// Process information attached to events
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub tid: Option<u32>,
    pub start_time: Option<DateTime<Utc>>,
    pub exe_path: Option<String>,
    pub exe_hash: Option<String>,
    pub cmdline: Option<String>,
    pub cwd: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub euid: Option<u32>,
    pub egid: Option<u32>,
    /// Windows: SID; Unix: uid string
    pub user_sid: Option<String>,
    pub username: Option<String>,
    /// Container context if applicable
    pub container_id: Option<String>,
    pub pid_namespace: Option<u64>,
    /// Code signing info
    pub signer: Option<String>,
    pub signature_status: Option<SignatureStatus>,
    /// Boot ID for PID reuse safety
    pub boot_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Valid,
    Invalid,
    NotSigned,
    Unknown,
}

/// File information attached to events
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileContext {
    pub path: Option<String>,
    pub inode: Option<u64>,
    pub device_id: Option<u64>,
    /// Windows: FileId
    pub file_id: Option<String>,
    pub size: Option<u64>,
    pub hash_sha256: Option<String>,
    pub hash_md5: Option<String>,
    pub entropy: Option<f64>,
    pub permissions: Option<u32>,
    pub owner_uid: Option<u32>,
    pub owner_gid: Option<u32>,
    /// Windows: volume serial
    pub volume_id: Option<String>,
    pub fs_uuid: Option<String>,
}

/// Network information attached to events
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkContext {
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub socket_inode: Option<u64>,
    /// Windows: socket handle
    pub socket_handle: Option<u64>,
    pub dns_query: Option<String>,
    pub dns_response: Option<Vec<String>>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub connection_state: Option<String>,
}

/// Memory operation context
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryContext {
    pub address: Option<u64>,
    pub size: Option<u64>,
    pub protection_before: Option<u32>,
    pub protection_after: Option<u32>,
    pub allocation_type: Option<String>,
    /// True if RWX or W->X transition
    pub is_wx_violation: Option<bool>,
}

/// Registry context (Windows, mapped from other persistence on Unix)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryContext {
    pub key_path: Option<String>,
    pub value_name: Option<String>,
    pub value_type: Option<String>,
    pub value_data: Option<String>,
    pub old_value_data: Option<String>,
}

/// Authentication/privilege context
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthContext {
    pub logon_type: Option<String>,
    pub auth_package: Option<String>,
    pub source_ip: Option<String>,
    pub target_user: Option<String>,
    pub target_domain: Option<String>,
    pub privileges_before: Option<Vec<String>>,
    pub privileges_after: Option<Vec<String>>,
    pub capabilities_before: Option<u64>,
    pub capabilities_after: Option<u64>,
}

/// OS-specific raw data preserved for debugging/forensics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "os", rename_all = "snake_case")]
pub enum OsSpecificContext {
    Windows {
        provider_guid: Option<String>,
        event_id: Option<u32>,
        task: Option<u16>,
        opcode: Option<u8>,
        keywords: Option<u64>,
        raw_payload: Option<serde_json::Value>,
    },
    MacOS {
        es_event_type: Option<String>,
        bsm_event_type: Option<u16>,
        audit_token: Option<Vec<u32>>,
        raw_payload: Option<serde_json::Value>,
    },
    Linux {
        syscall_nr: Option<u32>,
        syscall_name: Option<String>,
        audit_type: Option<u16>,
        ebpf_program: Option<String>,
        raw_payload: Option<serde_json::Value>,
    },
}

/// The unified canonical event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEvent {
    /// Deterministic evidence pointer
    pub evidence_ptr: EvidencePtr,

    /// Canonical event type
    pub event_type: CanonicalEventType,

    /// Host identifier (machine_id or hostname)
    pub host_id: String,

    /// Event timestamp (from source, may have clock skew)
    pub timestamp: DateTime<Utc>,

    /// Monotonic sequence within stream for ordering
    pub sequence: u64,

    /// Process context (actor)
    pub process: ProcessContext,

    /// Target process context (for injection, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_process: Option<ProcessContext>,

    /// File context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileContext>,

    /// Network context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkContext>,

    /// Memory context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryContext>,

    /// Registry context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistryContext>,

    /// Authentication context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthContext>,

    /// OS-specific raw context
    pub os_context: OsSpecificContext,

    /// Additional fields not fitting above categories
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, serde_json::Value>,
}

impl CanonicalEvent {
    /// Create a new canonical event with minimal required fields
    pub fn new(
        evidence_ptr: EvidencePtr,
        event_type: CanonicalEventType,
        host_id: impl Into<String>,
        timestamp: DateTime<Utc>,
        sequence: u64,
        os_context: OsSpecificContext,
    ) -> Self {
        Self {
            evidence_ptr,
            event_type,
            host_id: host_id.into(),
            timestamp,
            sequence,
            process: ProcessContext::default(),
            target_process: None,
            file: None,
            network: None,
            memory: None,
            registry: None,
            auth: None,
            os_context,
            extra: HashMap::new(),
        }
    }

    /// Check if this event has a WX memory violation
    pub fn has_wx_violation(&self) -> bool {
        self.memory
            .as_ref()
            .and_then(|m| m.is_wx_violation)
            .unwrap_or(false)
    }

    /// Get the effective user ID
    pub fn effective_uid(&self) -> Option<u32> {
        self.process.euid.or(self.process.uid)
    }

    /// Check if process is signed and valid
    pub fn is_signed_valid(&self) -> bool {
        matches!(self.process.signature_status, Some(SignatureStatus::Valid))
    }

    /// Extract a deterministic ordering key for sorting
    pub fn ordering_key(&self) -> (DateTime<Utc>, &str, &str, u64) {
        (
            self.timestamp,
            &self.evidence_ptr.stream_id,
            &self.evidence_ptr.segment_id,
            self.evidence_ptr.record_index,
        )
    }

    /// Create a simple test event from timestamp and stream info
    pub fn new_for_test(
        timestamp: DateTime<Utc>,
        stream_id: impl Into<String>,
        segment_id: impl Into<String>,
        record_index: u64,
    ) -> Self {
        let stream_id = stream_id.into();
        let segment_id = segment_id.into();

        Self {
            evidence_ptr: EvidencePtr::new(&stream_id, &segment_id, record_index),
            event_type: CanonicalEventType::ProcessCreate,
            host_id: "test_host".to_string(),
            timestamp,
            sequence: record_index,
            process: ProcessContext::default(),
            target_process: None,
            file: None,
            network: None,
            memory: None,
            registry: None,
            auth: None,
            os_context: OsSpecificContext::Windows {
                provider_guid: None,
                event_id: None,
                task: None,
                opcode: None,
                keywords: None,
                raw_payload: None,
            },
            extra: HashMap::new(),
        }
    }
}

// ============================================================================
// OS Adapter Traits
// ============================================================================

/// Trait for OS-specific event adapters
pub trait OsEventAdapter: Send + Sync {
    /// Convert raw OS event to canonical event
    fn to_canonical(
        &self,
        raw: &[u8],
        stream_id: &str,
        segment_id: &str,
        record_index: u64,
    ) -> anyhow::Result<CanonicalEvent>;

    /// Get supported stream IDs for this OS
    fn supported_streams(&self) -> Vec<String>;

    /// OS identifier
    fn os_name(&self) -> &'static str;
}

/// Windows ETW adapter placeholder
#[cfg(target_os = "windows")]
pub struct WindowsEtwAdapter;

/// macOS EndpointSecurity/BSM adapter placeholder
#[cfg(target_os = "macos")]
pub struct MacOsEsAdapter;

/// Linux eBPF/audit adapter placeholder
#[cfg(target_os = "linux")]
pub struct LinuxEbpfAdapter;

// ============================================================================
// Evidence Deref Engine
// ============================================================================

/// Engine for dereferencing EvidencePtrs
pub struct EvidenceDerefEngine {
    /// Database connection for canonical table lookups
    #[allow(dead_code)]
    db_path: String,
    /// Segment storage root path
    segment_root: String,
}

impl EvidenceDerefEngine {
    pub fn new(db_path: impl Into<String>, segment_root: impl Into<String>) -> Self {
        Self {
            db_path: db_path.into(),
            segment_root: segment_root.into(),
        }
    }

    /// Dereference an evidence pointer following the rules:
    /// 1. First attempt DB lookup (analysis.db canonical table keyed by EvidencePtr)
    /// 2. Fallback to segment file read using segment_id + record_index
    /// 3. Verify sha256 if present; if mismatch, return IntegrityError
    pub fn deref(&self, ptr: &EvidencePtr) -> DerefResult {
        // Try DB lookup first
        if let Some(event) = self.lookup_db(ptr) {
            // Verify integrity if sha256 present
            if let Some(expected) = &ptr.record_sha256 {
                let actual = self.compute_event_hash(&event);
                if &actual != expected {
                    return DerefResult::IntegrityError {
                        expected_sha256: expected.clone(),
                        actual_sha256: actual,
                    };
                }
            }
            return DerefResult::Canonical(event);
        }

        // Fallback to segment file
        match self.read_segment(ptr) {
            Ok(bytes) => {
                // Verify integrity if sha256 present
                if let Some(expected) = &ptr.record_sha256 {
                    let actual = EvidencePtr::compute_sha256(&bytes);
                    if actual != *expected {
                        return DerefResult::IntegrityError {
                            expected_sha256: expected.clone(),
                            actual_sha256: actual,
                        };
                    }
                }
                DerefResult::RawSegment {
                    segment_path: self.segment_path(ptr),
                    record_bytes: bytes,
                }
            }
            Err(e) => DerefResult::Missing {
                reason: format!("Segment read failed: {}", e),
            },
        }
    }

    /// Batch dereference multiple pointers
    pub fn deref_batch(&self, ptrs: &[EvidencePtr]) -> Vec<(EvidencePtr, DerefResult)> {
        ptrs.iter()
            .map(|ptr| (ptr.clone(), self.deref(ptr)))
            .collect()
    }

    fn lookup_db(&self, ptr: &EvidencePtr) -> Option<CanonicalEvent> {
        // TODO: Implement SQLite lookup
        // SELECT * FROM canonical_events WHERE stream_id = ? AND segment_id = ? AND record_index = ?
        let _ = ptr;
        None
    }

    fn read_segment(&self, ptr: &EvidencePtr) -> anyhow::Result<Vec<u8>> {
        use crate::safety::safe_join_under;
        use std::path::Path;

        let root = Path::new(&self.segment_root);

        // Construct relative path safely: stream_id/segment_id.segment
        let rel_path = format!("{}/{}.segment", ptr.stream_id, ptr.segment_id);
        let rel = Path::new(&rel_path);

        // Use safe_join_under to prevent path traversal attacks
        let safe_path = safe_join_under(root, rel)
            .map_err(|e| anyhow::anyhow!("Path safety check failed: {}", e))?;

        // Read the file
        std::fs::read(&safe_path)
            .map_err(|e| anyhow::anyhow!("Failed to read segment {}: {}", safe_path.display(), e))
    }

    fn segment_path(&self, ptr: &EvidencePtr) -> String {
        format!(
            "{}/{}/{}.segment",
            self.segment_root, ptr.stream_id, ptr.segment_id
        )
    }

    fn compute_event_hash(&self, event: &CanonicalEvent) -> String {
        let bytes = serde_json::to_vec(event).unwrap_or_default();
        EvidencePtr::compute_sha256(&bytes)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_deref_cannot_read_outside_root() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let segment_root = root.join("segments");
        fs::create_dir(&segment_root).unwrap();

        // Create a file outside the segment root
        let outside_file = root.join("secret.txt");
        fs::write(&outside_file, "secret data").unwrap();

        // Create an engine with the segment root
        let engine = EvidenceDerefEngine::new(
            root.join("db.sqlite").display().to_string(),
            segment_root.display().to_string(),
        );

        // Try to read the outside file using path traversal
        let ptr = EvidencePtr::new("stream", "../secret.txt", 0);
        let result = engine.deref(&ptr);

        // Should fail (not find the secret file)
        match result {
            DerefResult::Missing { .. } => {
                // Expected: either file not found or path safety error
            }
            _ => panic!("Should not be able to read outside root"),
        }
    }

    #[test]
    fn test_deref_with_valid_segment() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let segment_root = root.join("segments");
        fs::create_dir_all(segment_root.join("stream1")).unwrap();

        // Create a valid segment file
        let segment_data = b"test event data";
        let segment_file = segment_root.join("stream1/segment_001.segment");
        fs::write(&segment_file, segment_data).unwrap();

        let engine = EvidenceDerefEngine::new(
            root.join("db.sqlite").display().to_string(),
            segment_root.display().to_string(),
        );

        let ptr = EvidencePtr::new("stream1", "segment_001", 0);
        let result = engine.deref(&ptr);

        match result {
            DerefResult::RawSegment { record_bytes, .. } => {
                assert_eq!(record_bytes, segment_data);
            }
            _ => panic!("Should be able to read valid segment"),
        }
    }

    #[test]
    fn test_evidence_ptr_canonical_key() {
        let ptr = EvidencePtr::new("windows_etw_process", "segment_001", 42);
        assert_eq!(ptr.canonical_key(), "windows_etw_process:segment_001:42");
    }

    #[test]
    fn test_evidence_ptr_sha256() {
        let data = b"test record data";
        let hash = EvidencePtr::compute_sha256(data);
        assert_eq!(hash.len(), 64); // SHA256 hex is 64 chars
    }

    #[test]
    fn test_canonical_event_ordering() {
        let ts1 = Utc::now();
        let ts2 = ts1 + chrono::Duration::seconds(1);

        let ptr1 = EvidencePtr::new("stream", "seg", 0);
        let ptr2 = EvidencePtr::new("stream", "seg", 1);

        let event1 = CanonicalEvent::new(
            ptr1,
            CanonicalEventType::ProcessCreate,
            "host1",
            ts1,
            0,
            OsSpecificContext::Linux {
                syscall_nr: Some(59),
                syscall_name: Some("execve".to_string()),
                audit_type: None,
                ebpf_program: None,
                raw_payload: None,
            },
        );

        let event2 = CanonicalEvent::new(
            ptr2,
            CanonicalEventType::ProcessExec,
            "host1",
            ts2,
            1,
            OsSpecificContext::Linux {
                syscall_nr: Some(59),
                syscall_name: Some("execve".to_string()),
                audit_type: None,
                ebpf_program: None,
                raw_payload: None,
            },
        );

        assert!(event1.ordering_key() < event2.ordering_key());
    }
}

//! Scope Keys: Stable entity identifiers for hypotheses and incidents.
//!
//! All hypotheses/incidents must attach to a stable scope key that survives
//! PID reuse, container restarts, and other identity instabilities.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

// ============================================================================
// Scope Key Enum
// ============================================================================

/// Unified scope key enumeration for all entity types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "scope_type", rename_all = "snake_case")]
pub enum ScopeKey {
    /// Process scope: stable identity beyond PID
    Process { key: String },
    /// User scope: host + user identity
    User { key: String },
    /// Executable scope: host + exe hash
    Executable { key: String },
    /// Socket scope: network endpoint identity
    Socket { key: String },
    /// File scope: stable file identity
    File { key: String },
    /// Campaign scope: group of related processes (e.g., same exe_hash across hosts)
    Campaign { key: String },
    /// Session scope: user session identity
    Session { key: String },
}

impl fmt::Display for ScopeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeKey::Process { key } => write!(f, "proc:{}", key),
            ScopeKey::User { key } => write!(f, "user:{}", key),
            ScopeKey::Executable { key } => write!(f, "exe:{}", key),
            ScopeKey::Socket { key } => write!(f, "sock:{}", key),
            ScopeKey::File { key } => write!(f, "file:{}", key),
            ScopeKey::Campaign { key } => write!(f, "campaign:{}", key),
            ScopeKey::Session { key } => write!(f, "session:{}", key),
        }
    }
}

impl ScopeKey {
    /// Parse a scope key from string representation
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return None;
        }
        let key = parts[1].to_string();
        match parts[0] {
            "proc" => Some(ScopeKey::Process { key }),
            "user" => Some(ScopeKey::User { key }),
            "exe" => Some(ScopeKey::Executable { key }),
            "sock" => Some(ScopeKey::Socket { key }),
            "file" => Some(ScopeKey::File { key }),
            "campaign" => Some(ScopeKey::Campaign { key }),
            "session" => Some(ScopeKey::Session { key }),
            _ => None,
        }
    }

    /// Get the raw key value
    pub fn key(&self) -> &str {
        match self {
            ScopeKey::Process { key } => key,
            ScopeKey::User { key } => key,
            ScopeKey::Executable { key } => key,
            ScopeKey::Socket { key } => key,
            ScopeKey::File { key } => key,
            ScopeKey::Campaign { key } => key,
            ScopeKey::Session { key } => key,
        }
    }
}

// ============================================================================
// Process Scope Key
// ============================================================================

/// Builder for process scope keys
/// ProcKey = hash(host_id + boot_id + start_time + pid + exe_hash + ppid_start_time(optional))
#[derive(Debug, Clone)]
pub struct ProcScopeKeyBuilder {
    host_id: String,
    boot_id: Option<String>,
    start_time_ns: u64,
    pid: u32,
    exe_hash: Option<String>,
    ppid_start_time_ns: Option<u64>,
    container_id: Option<String>,
    pid_namespace: Option<u64>,
}

impl ProcScopeKeyBuilder {
    pub fn new(host_id: impl Into<String>, start_time_ns: u64, pid: u32) -> Self {
        Self {
            host_id: host_id.into(),
            boot_id: None,
            start_time_ns,
            pid,
            exe_hash: None,
            ppid_start_time_ns: None,
            container_id: None,
            pid_namespace: None,
        }
    }

    pub fn boot_id(mut self, boot_id: impl Into<String>) -> Self {
        self.boot_id = Some(boot_id.into());
        self
    }

    pub fn exe_hash(mut self, hash: impl Into<String>) -> Self {
        self.exe_hash = Some(hash.into());
        self
    }

    pub fn ppid_start_time(mut self, ppid_start_time_ns: u64) -> Self {
        self.ppid_start_time_ns = Some(ppid_start_time_ns);
        self
    }

    pub fn container_id(mut self, id: impl Into<String>) -> Self {
        self.container_id = Some(id.into());
        self
    }

    pub fn pid_namespace(mut self, ns: u64) -> Self {
        self.pid_namespace = Some(ns);
        self
    }

    /// Build the deterministic process scope key
    pub fn build(self) -> ScopeKey {
        let mut hasher = Sha256::new();
        hasher.update(self.host_id.as_bytes());

        if let Some(boot_id) = &self.boot_id {
            hasher.update(boot_id.as_bytes());
        }

        hasher.update(self.start_time_ns.to_le_bytes());
        hasher.update(self.pid.to_le_bytes());

        if let Some(exe_hash) = &self.exe_hash {
            hasher.update(exe_hash.as_bytes());
        }

        if let Some(ppid_start) = self.ppid_start_time_ns {
            hasher.update(ppid_start.to_le_bytes());
        }

        // Include container context for namespace isolation
        if let Some(container_id) = &self.container_id {
            hasher.update(container_id.as_bytes());
        }

        if let Some(pid_ns) = self.pid_namespace {
            hasher.update(pid_ns.to_le_bytes());
        }

        let hash = hex::encode(&hasher.finalize()[..16]);
        ScopeKey::Process { key: hash }
    }
}

// ============================================================================
// User Scope Key
// ============================================================================

/// Builder for user scope keys
/// UserScopeKey = host_id + uid (or SID on Windows)
#[derive(Debug, Clone)]
pub struct UserScopeKeyBuilder {
    host_id: String,
    uid: Option<u32>,
    sid: Option<String>, // Windows SID
    username: Option<String>,
}

impl UserScopeKeyBuilder {
    pub fn new(host_id: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            uid: None,
            sid: None,
            username: None,
        }
    }

    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    pub fn sid(mut self, sid: impl Into<String>) -> Self {
        self.sid = Some(sid.into());
        self
    }

    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn build(self) -> ScopeKey {
        let mut hasher = Sha256::new();
        hasher.update(self.host_id.as_bytes());

        if let Some(sid) = &self.sid {
            // Windows: use SID
            hasher.update(sid.as_bytes());
        } else if let Some(uid) = self.uid {
            // Unix: use UID
            hasher.update(uid.to_le_bytes());
        } else if let Some(username) = &self.username {
            // Fallback: use username
            hasher.update(username.as_bytes());
        }

        let hash = hex::encode(&hasher.finalize()[..16]);
        ScopeKey::User { key: hash }
    }
}

// ============================================================================
// Executable Scope Key
// ============================================================================

/// Builder for executable scope keys
/// ExeScopeKey = host_id + exe_hash (+ signer if desired)
#[derive(Debug, Clone)]
pub struct ExeScopeKeyBuilder {
    host_id: String,
    exe_hash: String,
    signer: Option<String>,
}

impl ExeScopeKeyBuilder {
    pub fn new(host_id: impl Into<String>, exe_hash: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            exe_hash: exe_hash.into(),
            signer: None,
        }
    }

    pub fn signer(mut self, signer: impl Into<String>) -> Self {
        self.signer = Some(signer.into());
        self
    }

    pub fn build(self) -> ScopeKey {
        let mut hasher = Sha256::new();
        hasher.update(self.host_id.as_bytes());
        hasher.update(self.exe_hash.as_bytes());

        if let Some(signer) = &self.signer {
            hasher.update(signer.as_bytes());
        }

        let hash = hex::encode(&hasher.finalize()[..16]);
        ScopeKey::Executable { key: hash }
    }
}

// ============================================================================
// Socket Scope Key
// ============================================================================

/// Builder for socket scope keys
/// SockScopeKey = host_id + sock_inode or (src_ip,src_port,dst_ip,dst_port,proto,ts_bucket)
#[derive(Debug, Clone)]
pub struct SockScopeKeyBuilder {
    host_id: String,
    sock_inode: Option<u64>,
    // Fallback: connection tuple
    src_ip: Option<String>,
    src_port: Option<u16>,
    dst_ip: Option<String>,
    dst_port: Option<u16>,
    proto: Option<String>,
    ts_bucket: Option<u64>, // Timestamp bucket for uniqueness
}

impl SockScopeKeyBuilder {
    pub fn new(host_id: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            sock_inode: None,
            src_ip: None,
            src_port: None,
            dst_ip: None,
            dst_port: None,
            proto: None,
            ts_bucket: None,
        }
    }

    pub fn sock_inode(mut self, inode: u64) -> Self {
        self.sock_inode = Some(inode);
        self
    }

    pub fn connection(
        mut self,
        src_ip: impl Into<String>,
        src_port: u16,
        dst_ip: impl Into<String>,
        dst_port: u16,
        proto: impl Into<String>,
    ) -> Self {
        self.src_ip = Some(src_ip.into());
        self.src_port = Some(src_port);
        self.dst_ip = Some(dst_ip.into());
        self.dst_port = Some(dst_port);
        self.proto = Some(proto.into());
        self
    }

    pub fn ts_bucket(mut self, bucket: u64) -> Self {
        self.ts_bucket = Some(bucket);
        self
    }

    pub fn build(self) -> ScopeKey {
        let mut hasher = Sha256::new();
        hasher.update(self.host_id.as_bytes());

        if let Some(inode) = self.sock_inode {
            // Prefer inode when available
            hasher.update(inode.to_le_bytes());
        } else {
            // Fall back to connection tuple
            if let Some(src_ip) = &self.src_ip {
                hasher.update(src_ip.as_bytes());
            }
            if let Some(src_port) = self.src_port {
                hasher.update(src_port.to_le_bytes());
            }
            if let Some(dst_ip) = &self.dst_ip {
                hasher.update(dst_ip.as_bytes());
            }
            if let Some(dst_port) = self.dst_port {
                hasher.update(dst_port.to_le_bytes());
            }
            if let Some(proto) = &self.proto {
                hasher.update(proto.as_bytes());
            }
            if let Some(bucket) = self.ts_bucket {
                hasher.update(bucket.to_le_bytes());
            }
        }

        let hash = hex::encode(&hasher.finalize()[..16]);
        ScopeKey::Socket { key: hash }
    }
}

// ============================================================================
// File Scope Key
// ============================================================================

/// Builder for file scope keys
/// FileScopeKey = host_id + inode or (path + fs_uuid) if inode not stable
#[derive(Debug, Clone)]
pub struct FileScopeKeyBuilder {
    host_id: String,
    inode: Option<u64>,
    device_id: Option<u64>,
    // Fallback for Windows or unstable inodes
    path: Option<String>,
    fs_uuid: Option<String>,
    // Windows: FileId
    file_id: Option<String>,
    volume_id: Option<String>,
}

impl FileScopeKeyBuilder {
    pub fn new(host_id: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            inode: None,
            device_id: None,
            path: None,
            fs_uuid: None,
            file_id: None,
            volume_id: None,
        }
    }

    pub fn inode(mut self, inode: u64, device_id: u64) -> Self {
        self.inode = Some(inode);
        self.device_id = Some(device_id);
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn fs_uuid(mut self, uuid: impl Into<String>) -> Self {
        self.fs_uuid = Some(uuid.into());
        self
    }

    /// Windows: use FileId + volume serial
    pub fn windows_file_id(
        mut self,
        file_id: impl Into<String>,
        volume_id: impl Into<String>,
    ) -> Self {
        self.file_id = Some(file_id.into());
        self.volume_id = Some(volume_id.into());
        self
    }

    pub fn build(self) -> ScopeKey {
        let mut hasher = Sha256::new();
        hasher.update(self.host_id.as_bytes());

        // Windows path
        if let (Some(file_id), Some(volume_id)) = (&self.file_id, &self.volume_id) {
            hasher.update(file_id.as_bytes());
            hasher.update(volume_id.as_bytes());
        } else if let (Some(inode), Some(device_id)) = (self.inode, self.device_id) {
            // Unix: prefer inode + device
            hasher.update(inode.to_le_bytes());
            hasher.update(device_id.to_le_bytes());
        } else {
            // Fallback: path + fs_uuid
            if let Some(path) = &self.path {
                hasher.update(path.as_bytes());
            }
            if let Some(fs_uuid) = &self.fs_uuid {
                hasher.update(fs_uuid.as_bytes());
            }
        }

        let hash = hex::encode(&hasher.finalize()[..16]);
        ScopeKey::File { key: hash }
    }
}

// ============================================================================
// Campaign Scope Key
// ============================================================================

/// Builder for campaign scope keys (multi-process, potentially multi-host)
#[derive(Debug, Clone)]
pub struct CampaignScopeKeyBuilder {
    exe_hash: Option<String>,
    user_key: Option<String>,
    host_pattern: Option<String>,
    time_bucket: Option<u64>,
}

impl CampaignScopeKeyBuilder {
    pub fn new() -> Self {
        Self {
            exe_hash: None,
            user_key: None,
            host_pattern: None,
            time_bucket: None,
        }
    }

    pub fn exe_hash(mut self, hash: impl Into<String>) -> Self {
        self.exe_hash = Some(hash.into());
        self
    }

    pub fn user_key(mut self, key: impl Into<String>) -> Self {
        self.user_key = Some(key.into());
        self
    }

    pub fn host_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.host_pattern = Some(pattern.into());
        self
    }

    pub fn time_bucket(mut self, bucket: u64) -> Self {
        self.time_bucket = Some(bucket);
        self
    }

    pub fn build(self) -> ScopeKey {
        let mut hasher = Sha256::new();

        if let Some(exe_hash) = &self.exe_hash {
            hasher.update(exe_hash.as_bytes());
        }
        if let Some(user_key) = &self.user_key {
            hasher.update(user_key.as_bytes());
        }
        if let Some(host_pattern) = &self.host_pattern {
            hasher.update(host_pattern.as_bytes());
        }
        if let Some(bucket) = self.time_bucket {
            hasher.update(bucket.to_le_bytes());
        }

        let hash = hex::encode(&hasher.finalize()[..16]);
        ScopeKey::Campaign { key: hash }
    }
}

impl Default for CampaignScopeKeyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Compute time bucket from timestamp
pub fn compute_time_bucket(ts_seconds: i64, bucket_seconds: i64) -> u64 {
    (ts_seconds / bucket_seconds) as u64
}

/// Default bucket sizes per scope type
pub mod bucket_sizes {
    /// Hypothesis bucket size (10 minutes)
    pub const HYPOTHESIS_BUCKET_SECS: i64 = 600;
    /// Incident bucket size (60 minutes)
    pub const INCIDENT_BUCKET_SECS: i64 = 3600;
    /// Socket bucket size (5 minutes)
    pub const SOCKET_BUCKET_SECS: i64 = 300;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_scope_key_determinism() {
        let key1 = ProcScopeKeyBuilder::new("host1", 1234567890, 1234)
            .boot_id("boot-abc")
            .exe_hash("sha256:deadbeef")
            .build();

        let key2 = ProcScopeKeyBuilder::new("host1", 1234567890, 1234)
            .boot_id("boot-abc")
            .exe_hash("sha256:deadbeef")
            .build();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_proc_scope_key_pid_reuse() {
        // Same PID but different start times should produce different keys
        let key1 = ProcScopeKeyBuilder::new("host1", 1000000000, 1234)
            .boot_id("boot-abc")
            .build();

        let key2 = ProcScopeKeyBuilder::new("host1", 2000000000, 1234) // Same PID, different start time
            .boot_id("boot-abc")
            .build();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_scope_key_parse_roundtrip() {
        let key = ScopeKey::Process {
            key: "abc123".to_string(),
        };
        let s = key.to_string();
        let parsed = ScopeKey::parse(&s).unwrap();
        assert_eq!(key, parsed);
    }

    #[test]
    fn test_file_scope_windows_vs_unix() {
        // Windows style
        let win_key = FileScopeKeyBuilder::new("host1")
            .windows_file_id("0x12345", "DEADBEEF")
            .build();

        // Unix style
        let unix_key = FileScopeKeyBuilder::new("host1").inode(12345, 8).build();

        // They should be different since they use different identity mechanisms
        assert_ne!(win_key, unix_key);
    }

    #[test]
    fn test_time_bucket() {
        let ts = 1609459200; // 2021-01-01 00:00:00 UTC
        let bucket = compute_time_bucket(ts, bucket_sizes::HYPOTHESIS_BUCKET_SECS);
        assert_eq!(bucket, (ts / 600) as u64);
    }
}

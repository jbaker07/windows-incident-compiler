//! Scope Keys: Stable entity identifiers safe from PID reuse and clock skew
//!
//! Each scope key provides a deterministic, globally unique identifier for entities:
//! - ProcScopeKey: Process identity (PID reuse safe)
//! - UserScopeKey: User identity
//! - ExeScopeKey: Executable identity
//! - SockScopeKey: Socket identity
//! - FileScopeKey: File identity

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// Process scope key - stable identity beyond PID
/// ProcKey = hash(host_id + boot_id + start_time + pid + exe_hash + ppid_start_time(optional))
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcScopeKey {
    pub host_id: String,
    pub boot_id: String,
    pub start_time_ns: i64,
    pub pid: u32,
    pub exe_hash: Option<String>,
    pub ppid_start_time_ns: Option<i64>,
    
    /// Optional container context
    pub container_id: Option<String>,
    pub pid_namespace: Option<u64>,
}

impl ProcScopeKey {
    /// Create new process scope key
    pub fn new(
        host_id: impl Into<String>,
        boot_id: impl Into<String>,
        start_time_ns: i64,
        pid: u32,
    ) -> Self {
        Self {
            host_id: host_id.into(),
            boot_id: boot_id.into(),
            start_time_ns,
            pid,
            exe_hash: None,
            ppid_start_time_ns: None,
            container_id: None,
            pid_namespace: None,
        }
    }
    
    pub fn with_exe_hash(mut self, hash: impl Into<String>) -> Self {
        self.exe_hash = Some(hash.into());
        self
    }
    
    pub fn with_parent(mut self, ppid_start_time_ns: i64) -> Self {
        self.ppid_start_time_ns = Some(ppid_start_time_ns);
        self
    }
    
    pub fn with_container(mut self, container_id: impl Into<String>, pid_ns: u64) -> Self {
        self.container_id = Some(container_id.into());
        self.pid_namespace = Some(pid_ns);
        self
    }
    
    /// Generate deterministic key hash
    pub fn to_key_string(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.host_id.as_bytes());
        hasher.update(b"|");
        hasher.update(self.boot_id.as_bytes());
        hasher.update(b"|");
        hasher.update(self.start_time_ns.to_le_bytes());
        hasher.update(b"|");
        hasher.update(self.pid.to_le_bytes());
        
        if let Some(ref exe_hash) = self.exe_hash {
            hasher.update(b"|exe:");
            hasher.update(exe_hash.as_bytes());
        }
        
        if let Some(ppid_start) = self.ppid_start_time_ns {
            hasher.update(b"|ppid:");
            hasher.update(ppid_start.to_le_bytes());
        }
        
        if let Some(ref container_id) = self.container_id {
            hasher.update(b"|ctr:");
            hasher.update(container_id.as_bytes());
        }
        
        if let Some(pid_ns) = self.pid_namespace {
            hasher.update(b"|ns:");
            hasher.update(pid_ns.to_le_bytes());
        }
        
        format!("proc:{:x}", hasher.finalize())
    }
    
    /// Check if two keys could refer to the same process (considering PID reuse)
    pub fn could_be_same_process(&self, other: &Self) -> bool {
        self.host_id == other.host_id
            && self.boot_id == other.boot_id
            && self.pid == other.pid
            && self.start_time_ns == other.start_time_ns
    }
}

/// User scope key - host_id + uid (or SID on Windows)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserScopeKey {
    pub host_id: String,
    /// Unix UID or Windows SID
    pub user_id: String,
    /// Human-readable username (informational)
    pub username: Option<String>,
    /// Domain (Windows)
    pub domain: Option<String>,
}

impl UserScopeKey {
    pub fn new(host_id: impl Into<String>, user_id: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            user_id: user_id.into(),
            username: None,
            domain: None,
        }
    }
    
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }
    
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }
    
    pub fn to_key_string(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.host_id.as_bytes());
        hasher.update(b"|");
        hasher.update(self.user_id.as_bytes());
        
        if let Some(ref domain) = self.domain {
            hasher.update(b"|dom:");
            hasher.update(domain.as_bytes());
        }
        
        format!("user:{:x}", hasher.finalize())
    }
}

/// Executable scope key - host_id + exe_hash (+ signer if desired)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExeScopeKey {
    pub host_id: String,
    pub exe_hash: String,
    pub signer: Option<String>,
    /// Informational path
    pub exe_path: Option<String>,
}

impl ExeScopeKey {
    pub fn new(host_id: impl Into<String>, exe_hash: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            exe_hash: exe_hash.into(),
            signer: None,
            exe_path: None,
        }
    }
    
    pub fn with_signer(mut self, signer: impl Into<String>) -> Self {
        self.signer = Some(signer.into());
        self
    }
    
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.exe_path = Some(path.into());
        self
    }
    
    pub fn to_key_string(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.host_id.as_bytes());
        hasher.update(b"|");
        hasher.update(self.exe_hash.as_bytes());
        
        if let Some(ref signer) = self.signer {
            hasher.update(b"|sign:");
            hasher.update(signer.as_bytes());
        }
        
        format!("exe:{:x}", hasher.finalize())
    }
}

/// Socket scope key - network connection identity
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SockScopeKey {
    pub host_id: String,
    /// Socket inode (Linux) or handle (Windows)
    pub sock_inode: Option<u64>,
    /// 5-tuple for TCP/UDP
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    /// Time bucket for disambiguation
    pub ts_bucket: Option<i64>,
}

impl SockScopeKey {
    pub fn from_inode(host_id: impl Into<String>, inode: u64) -> Self {
        Self {
            host_id: host_id.into(),
            sock_inode: Some(inode),
            src_ip: None,
            src_port: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            ts_bucket: None,
        }
    }
    
    pub fn from_tuple(
        host_id: impl Into<String>,
        src_ip: impl Into<String>,
        src_port: u16,
        dst_ip: impl Into<String>,
        dst_port: u16,
        protocol: impl Into<String>,
        ts_bucket: i64,
    ) -> Self {
        Self {
            host_id: host_id.into(),
            sock_inode: None,
            src_ip: Some(src_ip.into()),
            src_port: Some(src_port),
            dst_ip: Some(dst_ip.into()),
            dst_port: Some(dst_port),
            protocol: Some(protocol.into()),
            ts_bucket: Some(ts_bucket),
        }
    }
    
    pub fn to_key_string(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.host_id.as_bytes());
        
        if let Some(inode) = self.sock_inode {
            hasher.update(b"|inode:");
            hasher.update(inode.to_le_bytes());
        }
        
        if let Some(ref src_ip) = self.src_ip {
            hasher.update(b"|src:");
            hasher.update(src_ip.as_bytes());
            if let Some(port) = self.src_port {
                hasher.update(b":");
                hasher.update(port.to_le_bytes());
            }
        }
        
        if let Some(ref dst_ip) = self.dst_ip {
            hasher.update(b"|dst:");
            hasher.update(dst_ip.as_bytes());
            if let Some(port) = self.dst_port {
                hasher.update(b":");
                hasher.update(port.to_le_bytes());
            }
        }
        
        if let Some(ref proto) = self.protocol {
            hasher.update(b"|proto:");
            hasher.update(proto.as_bytes());
        }
        
        if let Some(ts) = self.ts_bucket {
            hasher.update(b"|ts:");
            hasher.update(ts.to_le_bytes());
        }
        
        format!("sock:{:x}", hasher.finalize())
    }
}

/// File scope key - file identity
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileScopeKey {
    pub host_id: String,
    /// Inode (Unix) - preferred
    pub inode: Option<u64>,
    /// FileId (Windows) - alternative
    pub file_id: Option<String>,
    /// Path + volume/fs_uuid fallback
    pub path: Option<String>,
    pub volume_id: Option<String>,
    pub fs_uuid: Option<String>,
}

impl FileScopeKey {
    pub fn from_inode(host_id: impl Into<String>, inode: u64) -> Self {
        Self {
            host_id: host_id.into(),
            inode: Some(inode),
            file_id: None,
            path: None,
            volume_id: None,
            fs_uuid: None,
        }
    }
    
    pub fn from_file_id(host_id: impl Into<String>, file_id: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            inode: None,
            file_id: Some(file_id.into()),
            path: None,
            volume_id: None,
            fs_uuid: None,
        }
    }
    
    pub fn from_path(
        host_id: impl Into<String>,
        path: impl Into<String>,
        volume_id: Option<String>,
    ) -> Self {
        Self {
            host_id: host_id.into(),
            inode: None,
            file_id: None,
            path: Some(path.into()),
            volume_id,
            fs_uuid: None,
        }
    }
    
    pub fn to_key_string(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.host_id.as_bytes());
        
        if let Some(inode) = self.inode {
            hasher.update(b"|inode:");
            hasher.update(inode.to_le_bytes());
        } else if let Some(ref file_id) = self.file_id {
            hasher.update(b"|fid:");
            hasher.update(file_id.as_bytes());
        } else if let Some(ref path) = self.path {
            hasher.update(b"|path:");
            hasher.update(path.as_bytes());
            if let Some(ref vol) = self.volume_id {
                hasher.update(b"|vol:");
                hasher.update(vol.as_bytes());
            }
            if let Some(ref fs_uuid) = self.fs_uuid {
                hasher.update(b"|fs:");
                hasher.update(fs_uuid.as_bytes());
            }
        }
        
        format!("file:{:x}", hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_key_determinism() {
        let key1 = ProcScopeKey::new("host1", "boot1", 1000000, 1234);
        let key2 = ProcScopeKey::new("host1", "boot1", 1000000, 1234);
        
        assert_eq!(key1.to_key_string(), key2.to_key_string());
    }

    #[test]
    fn test_proc_key_pid_reuse_protection() {
        // Same PID but different start times = different keys
        let key1 = ProcScopeKey::new("host1", "boot1", 1000000, 1234);
        let key2 = ProcScopeKey::new("host1", "boot1", 2000000, 1234); // PID reused
        
        assert_ne!(key1.to_key_string(), key2.to_key_string());
        assert!(!key1.could_be_same_process(&key2));
    }

    #[test]
    fn test_proc_key_boot_protection() {
        // Same PID/start_time but different boot = different keys
        let key1 = ProcScopeKey::new("host1", "boot1", 1000000, 1234);
        let key2 = ProcScopeKey::new("host1", "boot2", 1000000, 1234);
        
        assert_ne!(key1.to_key_string(), key2.to_key_string());
    }

    #[test]
    fn test_sock_key_from_tuple() {
        let key = SockScopeKey::from_tuple(
            "host1",
            "192.168.1.100",
            12345,
            "10.0.0.1",
            443,
            "tcp",
            1000,
        );
        
        let key_str = key.to_key_string();
        assert!(key_str.starts_with("sock:"));
    }

    #[test]
    fn test_file_key_windows_vs_unix() {
        let unix_key = FileScopeKey::from_inode("host1", 12345);
        let win_key = FileScopeKey::from_file_id("host1", "0x0000000000001234");
        
        // Both generate valid but different keys
        assert!(unix_key.to_key_string().starts_with("file:"));
        assert!(win_key.to_key_string().starts_with("file:"));
        assert_ne!(unix_key.to_key_string(), win_key.to_key_string());
    }
}

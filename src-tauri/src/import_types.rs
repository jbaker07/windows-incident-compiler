//! Import Types - Shared types for the import bundle workflow
//!
//! These types define the structure of imported bundles, manifest files,
//! and events extracted from imported content.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// MANIFEST TYPES
// ============================================================================

/// Import manifest - inventory of all files in an imported bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportManifest {
    /// Schema version for forward compatibility
    pub schema_version: u32,
    /// When the import was performed
    pub imported_at: DateTime<Utc>,
    /// Source type (zip or folder)
    pub source_type: ImportSourceType,
    /// Original source path
    pub source_path: String,
    /// Unique bundle identifier
    pub bundle_id: String,
    /// Associated run ID
    pub run_id: String,
    /// All files in the bundle
    pub files: Vec<ManifestFile>,
    /// Files that were rejected
    pub rejected: Vec<RejectedFile>,
    /// Import limits that were applied
    pub limits: ImportLimits,
    /// Summary statistics
    pub summary: ImportSummary,
}

/// Source type for the import
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImportSourceType {
    Zip,
    Folder,
}

/// A file entry in the manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    /// Relative path within the bundle
    pub rel_path: String,
    /// SHA256 hash of file content
    pub sha256: String,
    /// File size in bytes
    pub bytes: u64,
    /// Detected file kind
    pub kind: FileKind,
    /// Whether the file was successfully parsed
    pub parsed: bool,
    /// Parser that handled this file (if parsed)
    pub parser: Option<String>,
    /// Warnings during parsing
    pub warnings: Vec<String>,
    /// Number of events extracted (if parsed)
    pub events_extracted: Option<u64>,
}

/// Detected file kind
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    /// JSON Lines format
    Jsonl,
    /// Plain JSON
    Json,
    /// YAML
    Yaml,
    /// HAR (HTTP Archive)
    Har,
    /// Zeek conn.log
    ZeekConn,
    /// Zeek dns.log
    ZeekDns,
    /// Zeek http.log
    ZeekHttp,
    /// Zeek ssl.log
    ZeekSsl,
    /// Zeek files.log
    ZeekFiles,
    /// Generic Zeek log
    ZeekOther,
    /// CSV
    Csv,
    /// Plain text / log
    Text,
    /// PCAP (stored, not parsed)
    Pcap,
    /// Windows EVTX (stored, not parsed)
    Evtx,
    /// Nmap XML output
    NmapXml,
    /// Suricata EVE JSON
    SuricataEve,
    /// osquery JSON results
    Osquery,
    /// Velociraptor JSON/CSV export
    Velociraptor,
    /// YARA JSON output
    YaraJson,
    /// YARA plaintext output
    YaraText,
    /// OWASP ZAP JSON report
    ZapJson,
    /// Burp Suite XML export
    BurpXml,
    /// Windows EVTX-derived JSON
    EvtxJson,
    /// Atomic Red Team output
    AtomicOutput,
    /// PowerShell transcript
    PsTranscript,
    /// Bash/shell history
    ShellHistory,
    /// Gobuster output
    Gobuster,
    /// Ffuf output
    Ffuf,
    /// Generic recon tool output
    ReconOutput,
    /// Unknown binary/other
    Unknown,
}

impl FileKind {
    /// Check if this file kind should be parsed
    pub fn is_parseable(&self) -> bool {
        matches!(
            self,
            FileKind::Jsonl
                | FileKind::Json
                | FileKind::Yaml
                | FileKind::Har
                | FileKind::ZeekConn
                | FileKind::ZeekDns
                | FileKind::ZeekHttp
                | FileKind::ZeekSsl
                | FileKind::ZeekFiles
                | FileKind::ZeekOther
                | FileKind::Csv
                | FileKind::Text
                | FileKind::NmapXml
                | FileKind::SuricataEve
                | FileKind::Osquery
                | FileKind::Velociraptor
                | FileKind::YaraJson
                | FileKind::YaraText
                | FileKind::ZapJson
                | FileKind::BurpXml
                | FileKind::EvtxJson
                | FileKind::AtomicOutput
                | FileKind::PsTranscript
                | FileKind::ShellHistory
                | FileKind::Gobuster
                | FileKind::Ffuf
                | FileKind::ReconOutput
        )
    }
    
    /// Check if this is an artifact-only file (stored but not parsed for events)
    pub fn is_artifact_only(&self) -> bool {
        matches!(self, FileKind::Pcap | FileKind::Evtx)
    }

    /// Detect file kind from extension and filename
    pub fn detect(rel_path: &str) -> Self {
        let path_lower = rel_path.to_lowercase();
        let filename = std::path::Path::new(&path_lower)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let ext = std::path::Path::new(&path_lower)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        // Zeek logs by filename
        if filename == "conn.log" || filename.starts_with("conn.") {
            return FileKind::ZeekConn;
        }
        if filename == "dns.log" || filename.starts_with("dns.") {
            return FileKind::ZeekDns;
        }
        if filename == "http.log" || filename.starts_with("http.") && !filename.ends_with(".har") {
            return FileKind::ZeekHttp;
        }
        if filename == "ssl.log" || filename.starts_with("ssl.") {
            return FileKind::ZeekSsl;
        }
        if filename == "files.log" || filename.starts_with("files.") {
            return FileKind::ZeekFiles;
        }
        
        // Suricata EVE by filename
        if filename == "eve.json" || filename.starts_with("eve.") {
            return FileKind::SuricataEve;
        }
        
        // Nmap XML
        if filename.contains("nmap") && ext == "xml" {
            return FileKind::NmapXml;
        }
        
        // osquery
        if filename.contains("osquery") && (ext == "json" || ext == "jsonl") {
            return FileKind::Osquery;
        }
        
        // Velociraptor
        if filename.contains("velociraptor") || filename.contains("vr_") {
            return FileKind::Velociraptor;
        }
        
        // YARA
        if filename.contains("yara") {
            if ext == "json" {
                return FileKind::YaraJson;
            }
            return FileKind::YaraText;
        }
        
        // ZAP
        if filename.contains("zap") && ext == "json" {
            return FileKind::ZapJson;
        }
        
        // Burp
        if filename.contains("burp") && ext == "xml" {
            return FileKind::BurpXml;
        }
        
        // Atomic Red Team
        if filename.contains("atomic") || filename.contains("invoke-atomic") {
            return FileKind::AtomicOutput;
        }
        
        // PowerShell transcript
        if filename.contains("transcript") || filename.starts_with("powershell_") {
            return FileKind::PsTranscript;
        }
        
        // Shell history
        if filename == ".bash_history" || filename == ".zsh_history" || 
           filename == "ps_history" || filename.contains("history") {
            return FileKind::ShellHistory;
        }
        
        // Recon tools
        if filename.contains("gobuster") {
            return FileKind::Gobuster;
        }
        if filename.contains("ffuf") {
            return FileKind::Ffuf;
        }
        if filename.contains("dirb") || filename.contains("dirsearch") || 
           filename.contains("feroxbuster") {
            return FileKind::ReconOutput;
        }

        // By extension
        match ext {
            "jsonl" | "ndjson" => FileKind::Jsonl,
            "json" => {
                // Check for specific JSON types by content hint in filename
                if filename.contains("evtx") || filename.contains("winevt") {
                    FileKind::EvtxJson
                } else {
                    FileKind::Json
                }
            }
            "har" => FileKind::Har,
            "yaml" | "yml" => FileKind::Yaml,
            "csv" => FileKind::Csv,
            "txt" | "log" => FileKind::Text,
            "pcap" | "pcapng" | "cap" => FileKind::Pcap,
            "evtx" => FileKind::Evtx,
            "xml" => {
                // Try to detect XML type from filename
                if filename.contains("nmap") {
                    FileKind::NmapXml
                } else if filename.contains("burp") {
                    FileKind::BurpXml
                } else {
                    FileKind::Unknown
                }
            }
            _ => {
                // Check if it's a Zeek log by content hint (filename ends with .log)
                if ext == "log" {
                    FileKind::ZeekOther
                } else {
                    FileKind::Unknown
                }
            }
        }
    }
}

/// A rejected file (failed validation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedFile {
    /// Relative path (as seen in archive/folder)
    pub rel_path: String,
    /// Rejection reason
    pub reason: RejectionReason,
    /// Human-readable message
    pub message: String,
}

/// Reason a file was rejected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    PathTraversal,
    AbsolutePath,
    UncPath,
    Symlink,
    TooLarge,
    TooDeep,
    CompressionRatio,
    MaxFiles,
    MaxTotalSize,
    UnsupportedType,
}

/// Import limits configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportLimits {
    /// Maximum total uncompressed size in bytes
    pub max_total_bytes: u64,
    /// Maximum number of files
    pub max_files: u64,
    /// Maximum directory depth
    pub max_depth: u32,
    /// Maximum single file size
    pub max_single_file_bytes: u64,
    /// Maximum compression ratio (for zips)
    pub max_compression_ratio: f64,
    /// Maximum lines per file (for parsers)
    pub max_lines_per_file: u64,
    /// Maximum line length in bytes
    pub max_line_bytes: u64,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            max_total_bytes: 2 * 1024 * 1024 * 1024,    // 2GB
            max_files: 50_000,
            max_depth: 16,
            max_single_file_bytes: 200 * 1024 * 1024,  // 200MB
            max_compression_ratio: 200.0,
            max_lines_per_file: 10_000_000,            // 10M lines
            max_line_bytes: 1024 * 1024,               // 1MB per line
        }
    }
}

/// Summary statistics for an import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSummary {
    pub total_files: u64,
    pub total_bytes: u64,
    pub parsed_files: u64,
    pub rejected_files: u64,
    pub events_extracted: u64,
    pub file_kinds: HashMap<String, u64>,
}

// ============================================================================
// EVENT TYPES
// ============================================================================

/// Timestamp quality indicator
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimestampQuality {
    /// Precise timestamp from source
    Precise,
    /// Estimated from context or file metadata
    Estimated,
    /// Unknown - using import time
    Unknown,
}

/// Evidence pointer for imported content
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ImportEvidencePtr {
    /// Bundle identifier
    pub bundle_id: String,
    /// Relative path within bundle
    pub rel_path: String,
    /// Line number (for line-based formats)
    pub line_no: Option<u64>,
    /// JSON path (for structured formats like HAR)
    pub json_path: Option<String>,
    /// Byte offset (optional, for binary formats)
    pub byte_offset: Option<u64>,
}

impl ImportEvidencePtr {
    /// Encode as portable string (for use when edr_core isn't linked)
    pub fn to_stream_path(&self) -> String {
        format!("import:{}:{}", self.bundle_id, self.rel_path)
    }
    
    /// Get record index (line number or 0)
    pub fn record_index(&self) -> u32 {
        self.line_no.unwrap_or(0) as u32
    }
}

/// An event extracted from imported content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEvent {
    /// Unique event ID within the import
    pub event_id: String,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Quality of the timestamp
    pub timestamp_quality: TimestampQuality,
    /// Event type (e.g., "http_request", "dns_query", "process_start")
    pub event_type: String,
    /// Source file path
    pub source_file: String,
    /// Source line number (if applicable)
    pub source_line: Option<u64>,
    /// Event fields
    pub fields: HashMap<String, serde_json::Value>,
    /// Evidence pointer back to source
    pub evidence_ptr: ImportEvidencePtr,
    /// Tags for routing to playbooks
    pub tags: Vec<String>,
}

impl ImportEvent {
    /// Encode as portable fields for pipeline handoff (when edr_core isn't linked)
    pub fn to_portable_fields(&self, host_id: &str) -> serde_json::Value {
        serde_json::json!({
            "ts_ms": self.timestamp.timestamp_millis(),
            "host": host_id,
            "tags": self.tags,
            "fields": self.fields,
            "evidence_ptr": {
                "stream_id": format!("import:{}", self.evidence_ptr.bundle_id),
                "segment_id": self.evidence_ptr.rel_path.clone(),
                "record_index": self.evidence_ptr.line_no.unwrap_or(0),
            }
        })
    }
}

// ============================================================================
// IMPORT RESULT TYPES
// ============================================================================

/// Result of importing a bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub bundle_id: String,
    pub run_id: String,
    pub manifest_path: String,
    pub files_dir: String,
    pub summary: ImportSummary,
    pub success: bool,
    pub error: Option<String>,
}

/// Import status for progress reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportProgress {
    pub phase: ImportPhase,
    pub files_processed: u64,
    pub files_total: u64,
    pub bytes_processed: u64,
    pub bytes_total: u64,
    pub current_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImportPhase {
    Validating,
    Extracting,
    Hashing,
    Parsing,
    Complete,
    Failed,
}

// ============================================================================
// CASE EXPORT TYPES
// ============================================================================

/// Case export bundle structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseBundle {
    pub schema_version: u32,
    pub case_id: String,
    pub created_at: DateTime<Utc>,
    pub bundle_id: String,
    pub run_id: String,
    /// Manifest of imported files
    pub manifest: ImportManifest,
    /// Timeline of events
    pub timeline: Vec<TimelineEntry>,
    /// Detected entities
    pub entities: EntityIndex,
    /// Signals/detections
    pub signals: Vec<CaseSignal>,
    /// Explanation bundles (keyed by signal_id)
    pub explanations: HashMap<String, serde_json::Value>,
    /// Metrics/health gates
    pub metrics: serde_json::Value,
}

/// Timeline entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub summary: String,
    pub entities: Vec<String>,
    pub evidence_ptr: ImportEvidencePtr,
}

/// Entity index
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct EntityIndex {
    pub processes: Vec<EntityEntry>,
    pub files: Vec<EntityEntry>,
    pub network: Vec<EntityEntry>,
    pub users: Vec<EntityEntry>,
    pub other: Vec<EntityEntry>,
}


/// Entity entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityEntry {
    pub entity_type: String,
    pub key: String,
    pub display_name: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub event_count: u64,
}

/// Signal in case export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSignal {
    pub signal_id: String,
    pub playbook_id: String,
    pub playbook_title: String,
    pub severity: String,
    pub timestamp: DateTime<Utc>,
    pub summary: String,
    pub entities: Vec<String>,
}

// ============================================================================
// CANONICAL EVENT TYPES
// ============================================================================

/// Canonical event type enumeration for normalized events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalEventType {
    /// Network flow/connection (Zeek conn, firewall, netflow)
    NetFlow,
    /// DNS query/response
    DnsQuery,
    /// HTTP transaction
    HttpTxn,
    /// Process execution
    ProcessExec,
    /// Authentication event
    AuthEvent,
    /// File operation
    FileOp,
    /// Security finding/alert
    Finding,
    /// Artifact present but not parsed (PCAP, EVTX)
    ArtifactPresent,
    /// Generic text log line
    TextLogLine,
    /// Host discovery (nmap)
    HostDiscovered,
    /// Port/service discovery (nmap)
    PortDiscovered,
    /// YARA match
    YaraMatch,
    /// Web scan finding (ZAP, Burp)
    WebFinding,
    /// Test step (Atomic Red Team)
    TestStep,
    /// Recon command/output
    ReconCommand,
    /// Credential artifact
    CredentialArtifact,
    /// User/identity record
    UserRecord,
    /// Listening port record
    ListeningPort,
    /// File integrity record
    FileIntegrity,
    /// Network alert (Suricata)
    NetAlert,
    /// SSL/TLS certificate event
    SslCert,
    /// Generic row from table export
    TableRow,
}

// ============================================================================
// ENTITY KEY TYPES
// ============================================================================

/// Entity key types for cross-source correlation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EntityKeyType {
    /// Process key: hash of (host, pid, start_time) or (host, image_path, cmdline_hash)
    ProcKey,
    /// File key: hash of (path) or (sha256)
    FileKey,
    /// Identity key: hash of (user, domain) or (sid)
    IdentityKey,
    /// Network key: hash of (src_ip, dst_ip, dst_port, proto)
    NetKey,
    /// Host key: hash of (hostname) or (ip)
    HostKey,
    /// URL key: hash of normalized URL
    UrlKey,
    /// Domain key: hash of domain name
    DomainKey,
    /// IP key: the IP address itself
    IpKey,
}

/// An entity key extracted from events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EntityKey {
    pub key_type: EntityKeyType,
    pub value: String,
    pub display: String,
}

impl EntityKey {
    pub fn proc_key(host: &str, pid: u32, image: &str) -> Self {
        let value = format!("proc:{}:{}:{}", host, pid, image);
        Self {
            key_type: EntityKeyType::ProcKey,
            value: Self::hash_key(&value),
            display: format!("{}:{}", host, image.split('\\').next_back().unwrap_or(image)),
        }
    }
    
    pub fn file_key(path: &str) -> Self {
        Self {
            key_type: EntityKeyType::FileKey,
            value: Self::hash_key(path),
            display: path.split(['/', '\\']).next_back().unwrap_or(path).to_string(),
        }
    }
    
    pub fn file_key_sha256(sha256: &str) -> Self {
        Self {
            key_type: EntityKeyType::FileKey,
            value: sha256.to_lowercase(),
            display: format!("{}...", &sha256[..8.min(sha256.len())]),
        }
    }
    
    pub fn identity_key(user: &str, domain: Option<&str>) -> Self {
        let value = match domain {
            Some(d) => format!("id:{}\\{}", d, user),
            None => format!("id:{}", user),
        };
        Self {
            key_type: EntityKeyType::IdentityKey,
            value: Self::hash_key(&value),
            display: match domain {
                Some(d) => format!("{}\\{}", d, user),
                None => user.to_string(),
            },
        }
    }
    
    pub fn net_key(src_ip: &str, dst_ip: &str, dst_port: u16, proto: &str) -> Self {
        let value = format!("net:{}:{}:{}:{}", src_ip, dst_ip, dst_port, proto);
        Self {
            key_type: EntityKeyType::NetKey,
            value: Self::hash_key(&value),
            display: format!("{} → {}:{}", src_ip, dst_ip, dst_port),
        }
    }
    
    pub fn host_key(hostname: &str) -> Self {
        Self {
            key_type: EntityKeyType::HostKey,
            value: Self::hash_key(&format!("host:{}", hostname.to_lowercase())),
            display: hostname.to_string(),
        }
    }
    
    pub fn url_key(url: &str) -> Self {
        Self {
            key_type: EntityKeyType::UrlKey,
            value: Self::hash_key(url),
            display: if url.len() > 60 {
                format!("{}...", &url[..57])
            } else {
                url.to_string()
            },
        }
    }
    
    pub fn domain_key(domain: &str) -> Self {
        Self {
            key_type: EntityKeyType::DomainKey,
            value: domain.to_lowercase(),
            display: domain.to_string(),
        }
    }
    
    pub fn ip_key(ip: &str) -> Self {
        Self {
            key_type: EntityKeyType::IpKey,
            value: ip.to_string(),
            display: ip.to_string(),
        }
    }
    
    fn hash_key(input: &str) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        input.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

// ============================================================================
// FACT TYPES FOR ADAPTERS
// ============================================================================

/// Facts that adapters can safely extract
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "fact_type", rename_all = "snake_case")]
pub enum ImportedFact {
    /// Process fact from osquery/velociraptor
    Process {
        host: String,
        pid: u32,
        ppid: Option<u32>,
        name: String,
        path: Option<String>,
        cmdline: Option<String>,
        user: Option<String>,
        start_time: Option<DateTime<Utc>>,
    },
    /// User/identity fact
    User {
        username: String,
        domain: Option<String>,
        sid: Option<String>,
        groups: Vec<String>,
    },
    /// Listening port fact
    ListeningPort {
        host: String,
        port: u16,
        proto: String,
        pid: Option<u32>,
        process_name: Option<String>,
    },
    /// File fact
    File {
        path: String,
        sha256: Option<String>,
        size: Option<u64>,
        modified: Option<DateTime<Utc>>,
    },
    /// Network alert fact (Suricata)
    NetAlert {
        signature: String,
        signature_id: u64,
        category: String,
        severity: u32,
        src_ip: String,
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
        proto: String,
        flow_id: Option<u64>,
    },
    /// DNS anomaly fact
    DnsAnomaly {
        query: String,
        anomaly_type: String,
        src_ip: String,
    },
    /// HTTP anomaly fact
    HttpAnomaly {
        url: String,
        method: String,
        anomaly_type: String,
        src_ip: String,
    },
    /// Malware indicator fact (YARA)
    MalwareIndicator {
        rule: String,
        target_path: String,
        namespace: Option<String>,
        tags: Vec<String>,
        strings_matched: Vec<String>,
    },
    /// Web scan finding fact (ZAP/Burp)
    WebScanFinding {
        url: String,
        risk: String,
        confidence: String,
        plugin_id: Option<String>,
        name: String,
        description: Option<String>,
    },
    /// Technique observed fact (Atomic)
    TechniqueObserved {
        technique_id: String,
        technique_name: Option<String>,
        test_name: Option<String>,
        status: String,
        command: Option<String>,
    },
    /// Recon fact (HTB/CTF)
    Recon {
        tool: String,
        target: String,
        finding_type: String,
        finding: String,
    },
    /// Credential artifact fact
    CredentialArtifact {
        artifact_type: String,
        location: String,
        username: Option<String>,
        context: Option<String>,
    },
    /// Web enumeration fact
    WebEnum {
        url: String,
        status_code: u16,
        size: Option<u64>,
        tool: String,
    },
}

impl ImportedFact {
    /// Get the fact type name
    pub fn fact_type_name(&self) -> &'static str {
        match self {
            ImportedFact::Process { .. } => "process",
            ImportedFact::User { .. } => "user",
            ImportedFact::ListeningPort { .. } => "listening_port",
            ImportedFact::File { .. } => "file",
            ImportedFact::NetAlert { .. } => "net_alert",
            ImportedFact::DnsAnomaly { .. } => "dns_anomaly",
            ImportedFact::HttpAnomaly { .. } => "http_anomaly",
            ImportedFact::MalwareIndicator { .. } => "malware_indicator",
            ImportedFact::WebScanFinding { .. } => "web_scan_finding",
            ImportedFact::TechniqueObserved { .. } => "technique_observed",
            ImportedFact::Recon { .. } => "recon",
            ImportedFact::CredentialArtifact { .. } => "credential_artifact",
            ImportedFact::WebEnum { .. } => "web_enum",
        }
    }
}

// ============================================================================
// ADAPTER INPUT STATS
// ============================================================================

/// Statistics about what adapters processed
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdapterInputStats {
    pub har: AdapterStats,
    pub zeek: AdapterStats,
    pub suricata: AdapterStats,
    pub nmap: AdapterStats,
    pub atomic: AdapterStats,
    pub htb: AdapterStats,
    pub osquery: AdapterStats,
    pub velociraptor: AdapterStats,
    pub yara: AdapterStats,
    pub zap: AdapterStats,
    pub burp: AdapterStats,
    pub pcap: AdapterStats,
    pub plaintext: AdapterStats,
    pub evtx_json: AdapterStats,
    pub jsonl: AdapterStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdapterStats {
    pub files_seen: u64,
    pub files_parsed: u64,
    pub events_extracted: u64,
    pub facts_extracted: u64,
    pub errors: u64,
    pub warnings: u64,
    pub events_with_timestamp: u64,
    pub events_entity_linked: u64,
}


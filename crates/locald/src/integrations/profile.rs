//! IntegrationProfile: First-class integration metadata model
//!
//! Captures per-integration capabilities, health, and mapping metadata.
//! Used by locald for routing and by ui_server for capability visualization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ============================================================================
// Core Types
// ============================================================================

/// Fidelity level for fact support
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum Fidelity {
    /// Hard provenance: full telemetry, deterministic scope keys
    Hard,
    /// Soft provenance: partial data, requires joins for attribution
    Soft,
    /// Not supported by this integration
    #[default]
    None,
}

/// Integration mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationMode {
    /// Export incidents to this integration
    Export,
    /// Ingest events from this integration
    Ingest,
    /// Both export and ingest
    Both,
}

/// Integration type (vendor/protocol)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationType {
    Wazuh,
    Zeek,
    Suricata,
    Osquery,
    Elastic,
    Splunk,
    Syslog,
    JsonlFile,
    Custom(String),
}

impl IntegrationType {
    pub fn as_str(&self) -> &str {
        match self {
            IntegrationType::Wazuh => "wazuh",
            IntegrationType::Zeek => "zeek",
            IntegrationType::Suricata => "suricata",
            IntegrationType::Osquery => "osquery",
            IntegrationType::Elastic => "elastic",
            IntegrationType::Splunk => "splunk",
            IntegrationType::Syslog => "syslog",
            IntegrationType::JsonlFile => "jsonl_file",
            IntegrationType::Custom(s) => s,
        }
    }
}

/// Supported join keys for correlation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JoinKeySupport {
    /// Process key: pid + start_time + exe_hash
    pub proc_key: bool,
    /// File key: path + inode
    pub file_key: bool,
    /// Socket key: src_ip:port + dst_ip:port
    pub socket_key: bool,
    /// Identity key: uid + username
    pub identity_key: bool,
    /// DNS attribution: query → IP mapping
    pub dns_attribution: bool,
    /// Thread key: tid + start_time
    pub thread_key: bool,
}

impl JoinKeySupport {
    /// Create support profile for Wazuh
    pub fn wazuh() -> Self {
        Self {
            proc_key: true, // via Windows Event Log
            file_key: true,
            socket_key: true,
            identity_key: true,
            dns_attribution: false,
            thread_key: false,
        }
    }

    /// Create support profile for Zeek
    pub fn zeek() -> Self {
        Self {
            proc_key: false,
            file_key: false,
            socket_key: true, // primary strength
            identity_key: false,
            dns_attribution: true, // dns.log correlation
            thread_key: false,
        }
    }

    /// Create support profile for Osquery
    pub fn osquery() -> Self {
        Self {
            proc_key: true,   // process_events table
            file_key: true,   // file_events table
            socket_key: true, // socket_events table
            identity_key: true,
            dns_attribution: false,
            thread_key: false,
        }
    }

    /// Count number of supported join keys
    pub fn count(&self) -> usize {
        [
            self.proc_key,
            self.file_key,
            self.socket_key,
            self.identity_key,
            self.dns_attribution,
            self.thread_key,
        ]
        .iter()
        .filter(|&&x| x)
        .count()
    }
}

// ============================================================================
// IntegrationProfile
// ============================================================================

/// First-class integration profile capturing capabilities and health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationProfile {
    /// Unique integration identifier
    pub integration_id: String,

    /// Human-readable name
    pub name: String,

    /// Integration type/vendor
    pub integration_type: IntegrationType,

    /// Operating mode
    pub mode: IntegrationMode,

    /// Enabled/disabled flag
    pub enabled: bool,

    /// Facts supported with fidelity levels
    pub facts_supported: HashMap<String, Fidelity>,

    /// Join keys supported for correlation
    pub join_keys_supported: JoinKeySupport,

    /// Mapping/parser version for this integration
    pub mapping_version: String,

    /// Last event timestamp seen
    pub last_seen_ts: Option<DateTime<Utc>>,

    /// Events per second (rolling average)
    pub eps: f64,

    /// Parse error rate (0.0 to 1.0)
    pub parse_error_rate: f64,

    /// Total events processed
    pub events_processed: u64,

    /// Total events with errors
    pub events_errored: u64,

    /// Total facts created
    pub facts_created: u64,

    /// Health status
    pub health_status: HealthStatus,

    /// Configuration path/source
    pub config_source: Option<String>,

    /// Profile creation timestamp
    pub created_at: DateTime<Utc>,

    /// Profile last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// Health status for integrations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum HealthStatus {
    /// Healthy: receiving events, low error rate
    Healthy,
    /// Warning: high error rate or stale data
    Warning,
    /// Error: not receiving events or critical failure
    Error,
    /// Unknown: not enough data to determine
    #[default]
    Unknown,
}

impl IntegrationProfile {
    /// Create a new profile with defaults
    pub fn new(
        integration_id: impl Into<String>,
        name: impl Into<String>,
        integration_type: IntegrationType,
        mode: IntegrationMode,
    ) -> Self {
        let now = Utc::now();
        Self {
            integration_id: integration_id.into(),
            name: name.into(),
            integration_type,
            mode,
            enabled: true,
            facts_supported: HashMap::new(),
            join_keys_supported: JoinKeySupport::default(),
            mapping_version: "1.0".to_string(),
            last_seen_ts: None,
            eps: 0.0,
            parse_error_rate: 0.0,
            events_processed: 0,
            events_errored: 0,
            facts_created: 0,
            health_status: HealthStatus::Unknown,
            config_source: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a Wazuh integration profile
    pub fn wazuh(integration_id: impl Into<String>) -> Self {
        let mut profile = Self::new(
            integration_id,
            "Wazuh HIDS",
            IntegrationType::Wazuh,
            IntegrationMode::Both,
        );
        profile.join_keys_supported = JoinKeySupport::wazuh();
        profile.mapping_version = "wazuh_4.x".to_string();

        // Wazuh fact support (via Windows Event Log forwarding)
        profile
            .facts_supported
            .insert("exec".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("proc_spawn".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("write_path".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("outbound_connect".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("inbound_connect".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("privilege_boundary".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("vendor_alert".to_string(), Fidelity::Hard);

        profile
    }

    /// Create a Zeek integration profile
    pub fn zeek(integration_id: impl Into<String>) -> Self {
        let mut profile = Self::new(
            integration_id,
            "Zeek Network Monitor",
            IntegrationType::Zeek,
            IntegrationMode::Ingest,
        );
        profile.join_keys_supported = JoinKeySupport::zeek();
        profile.mapping_version = "zeek_6.x".to_string();

        // Zeek fact support (network only)
        profile
            .facts_supported
            .insert("outbound_connect".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("inbound_connect".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("dns_resolve".to_string(), Fidelity::Hard);
        profile
            .facts_supported
            .insert("vendor_alert".to_string(), Fidelity::Hard);

        profile
    }

    /// Create an Osquery integration profile
    pub fn osquery(integration_id: impl Into<String>) -> Self {
        let mut profile = Self::new(
            integration_id,
            "Osquery",
            IntegrationType::Osquery,
            IntegrationMode::Ingest,
        );
        profile.join_keys_supported = JoinKeySupport::osquery();
        profile.mapping_version = "osquery_5.x".to_string();

        // Osquery fact support
        profile
            .facts_supported
            .insert("exec".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("proc_spawn".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("write_path".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("read_path".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("outbound_connect".to_string(), Fidelity::Soft);
        profile
            .facts_supported
            .insert("vendor_alert".to_string(), Fidelity::Hard);

        profile
    }

    /// Create a JSONL file export profile
    pub fn jsonl_export(integration_id: impl Into<String>) -> Self {
        let mut profile = Self::new(
            integration_id,
            "JSONL File Export",
            IntegrationType::JsonlFile,
            IntegrationMode::Export,
        );
        profile.mapping_version = "export_1.0".to_string();
        // Export supports all fact types
        for fact_type in [
            "exec",
            "proc_spawn",
            "write_path",
            "read_path",
            "create_path",
            "delete_path",
            "outbound_connect",
            "inbound_connect",
            "dns_resolve",
            "privilege_boundary",
            "mem_wx",
            "persist_artifact",
            "vendor_alert",
        ] {
            profile
                .facts_supported
                .insert(fact_type.to_string(), Fidelity::Hard);
        }
        profile
    }

    /// Update statistics from event processing
    pub fn record_event(&mut self, success: bool, facts_created: u64) {
        self.events_processed += 1;
        if !success {
            self.events_errored += 1;
        }
        self.facts_created += facts_created;
        self.last_seen_ts = Some(Utc::now());
        self.updated_at = Utc::now();

        // Update error rate (rolling)
        if self.events_processed > 0 {
            self.parse_error_rate = self.events_errored as f64 / self.events_processed as f64;
        }

        // Update health status
        self.update_health_status();
    }

    /// Update EPS metric
    pub fn update_eps(&mut self, eps: f64) {
        self.eps = eps;
        self.updated_at = Utc::now();
        self.update_health_status();
    }

    /// Compute health status based on metrics
    fn update_health_status(&mut self) {
        // Stale check: no events in 5 minutes
        let stale = self
            .last_seen_ts
            .map(|ts| (Utc::now() - ts).num_minutes() > 5)
            .unwrap_or(true);

        if self.events_processed == 0 {
            self.health_status = HealthStatus::Unknown;
        } else if stale {
            self.health_status = HealthStatus::Error;
        } else if self.parse_error_rate > 0.1 {
            self.health_status = HealthStatus::Warning;
        } else {
            self.health_status = HealthStatus::Healthy;
        }
    }

    /// Get fact fidelity for a specific fact type
    pub fn fact_fidelity(&self, fact_type: &str) -> Fidelity {
        self.facts_supported
            .get(fact_type)
            .copied()
            .unwrap_or(Fidelity::None)
    }

    /// Check if this integration can provide a specific join key
    pub fn supports_join_key(&self, key_type: &str) -> bool {
        match key_type {
            "proc_key" => self.join_keys_supported.proc_key,
            "file_key" => self.join_keys_supported.file_key,
            "socket_key" => self.join_keys_supported.socket_key,
            "identity_key" => self.join_keys_supported.identity_key,
            "dns_attribution" => self.join_keys_supported.dns_attribution,
            "thread_key" => self.join_keys_supported.thread_key,
            _ => false,
        }
    }

    /// Compute a deterministic profile hash for versioning
    pub fn profile_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.integration_id.as_bytes());
        hasher.update(self.mapping_version.as_bytes());
        for (fact_type, fidelity) in &self.facts_supported {
            hasher.update(fact_type.as_bytes());
            hasher.update([*fidelity as u8]);
        }
        hex::encode(&hasher.finalize()[..8])
    }
}

// ============================================================================
// MappedEvent: Auditable mapping record
// ============================================================================

/// A mapped event with full provenance tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedEvent {
    /// Source integration ID
    pub integration_id: String,

    /// Original event ID from source (if present)
    pub raw_event_id: Option<String>,

    /// Stable hash of raw JSON
    pub raw_json_hash: String,

    /// Mapping version used
    pub mapping_version: String,

    /// Derived scope keys
    pub derived_scope_keys: Vec<DerivedScopeKey>,

    /// Timestamp of mapping
    pub mapped_at: DateTime<Utc>,

    /// Raw event (truncated for storage)
    pub raw_event_summary: Option<String>,

    /// Mapped canonical event (serialized)
    pub mapped_event: serde_json::Value,
}

/// A derived scope key with provenance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedScopeKey {
    /// Scope key string
    pub key: String,

    /// Scope key type
    pub key_type: String,

    /// Fidelity: Hard (deterministic) or Soft (heuristic)
    pub fidelity: Fidelity,

    /// Join confidence (0.0 to 1.0)
    pub join_confidence: f64,

    /// Reason for confidence level
    pub confidence_reason: Option<String>,
}

impl MappedEvent {
    /// Create a new mapped event record
    pub fn new(
        integration_id: impl Into<String>,
        raw_json: &serde_json::Value,
        mapping_version: impl Into<String>,
    ) -> Self {
        // Compute stable hash
        let raw_str = serde_json::to_string(raw_json).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(raw_str.as_bytes());
        let raw_json_hash = hex::encode(&hasher.finalize()[..16]);

        Self {
            integration_id: integration_id.into(),
            raw_event_id: raw_json
                .get("id")
                .or_else(|| raw_json.get("event_id"))
                .or_else(|| raw_json.get("uid"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            raw_json_hash,
            mapping_version: mapping_version.into(),
            derived_scope_keys: Vec::new(),
            mapped_at: Utc::now(),
            raw_event_summary: Some(raw_str.chars().take(500).collect()),
            mapped_event: serde_json::Value::Null,
        }
    }

    /// Add a derived scope key
    pub fn add_scope_key(
        &mut self,
        key: impl Into<String>,
        key_type: impl Into<String>,
        fidelity: Fidelity,
        join_confidence: f64,
    ) {
        self.derived_scope_keys.push(DerivedScopeKey {
            key: key.into(),
            key_type: key_type.into(),
            fidelity,
            join_confidence,
            confidence_reason: None,
        });
    }
}

// ============================================================================
// IntegrationProfileStore
// ============================================================================

/// In-memory store for integration profiles
#[derive(Debug, Default)]
pub struct IntegrationProfileStore {
    profiles: HashMap<String, IntegrationProfile>,
    /// Recent mapped events for sampling (bounded)
    sample_events: HashMap<String, Vec<MappedEvent>>,
    max_samples: usize,
}

impl IntegrationProfileStore {
    /// Create a new store
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            sample_events: HashMap::new(),
            max_samples: 100,
        }
    }

    /// Register or update a profile
    pub fn upsert(&mut self, profile: IntegrationProfile) {
        self.profiles
            .insert(profile.integration_id.clone(), profile);
    }

    /// Get a profile by ID
    pub fn get(&self, integration_id: &str) -> Option<&IntegrationProfile> {
        self.profiles.get(integration_id)
    }

    /// Get mutable profile by ID
    pub fn get_mut(&mut self, integration_id: &str) -> Option<&mut IntegrationProfile> {
        self.profiles.get_mut(integration_id)
    }

    /// List all profiles
    pub fn list(&self) -> Vec<&IntegrationProfile> {
        self.profiles.values().collect()
    }

    /// Record a sample event for an integration
    pub fn record_sample(&mut self, integration_id: &str, event: MappedEvent) {
        let samples = self
            .sample_events
            .entry(integration_id.to_string())
            .or_default();

        samples.push(event);

        // Keep bounded
        if samples.len() > self.max_samples {
            samples.remove(0);
        }
    }

    /// Get sample events for an integration
    pub fn get_samples(&self, integration_id: &str, limit: usize) -> Vec<&MappedEvent> {
        self.sample_events
            .get(integration_id)
            .map(|samples| samples.iter().rev().take(limit).collect())
            .unwrap_or_default()
    }

    /// Compute merged capabilities across all integrations
    pub fn merged_capabilities(&self) -> CapabilitiesMatrix {
        let mut matrix = CapabilitiesMatrix::default();

        for profile in self.profiles.values() {
            if !profile.enabled {
                continue;
            }

            // Add source
            matrix.sources.push(CapabilitySource {
                id: profile.integration_id.clone(),
                name: profile.name.clone(),
                source_type: SourceType::Integration,
                mode: profile.mode,
            });

            // Merge fact support
            for (fact_type, fidelity) in &profile.facts_supported {
                let entry = matrix
                    .fact_support
                    .entry(fact_type.clone())
                    .or_insert_with(HashMap::new);
                entry.insert(profile.integration_id.clone(), *fidelity);
            }

            // Merge join key support
            matrix.merge_join_keys(&profile.integration_id, &profile.join_keys_supported);
        }

        matrix
    }
}

// ============================================================================
// CapabilitiesMatrix
// ============================================================================

/// Merged capabilities matrix for visualization
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitiesMatrix {
    /// List of sources (collectors + integrations)
    pub sources: Vec<CapabilitySource>,

    /// FactType → Source → Fidelity mapping
    pub fact_support: HashMap<String, HashMap<String, Fidelity>>,

    /// JoinKey → Source → supported mapping
    pub join_key_support: HashMap<String, HashMap<String, bool>>,
}

/// A capability source (collector or integration)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySource {
    pub id: String,
    pub name: String,
    pub source_type: SourceType,
    pub mode: IntegrationMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    /// Our native collectors
    Collector,
    /// Third-party integration
    Integration,
}

impl CapabilitiesMatrix {
    /// Merge join key support from a profile
    pub fn merge_join_keys(&mut self, source_id: &str, support: &JoinKeySupport) {
        let keys = [
            ("proc_key", support.proc_key),
            ("file_key", support.file_key),
            ("socket_key", support.socket_key),
            ("identity_key", support.identity_key),
            ("dns_attribution", support.dns_attribution),
            ("thread_key", support.thread_key),
        ];

        for (key_name, supported) in keys {
            let entry = self
                .join_key_support
                .entry(key_name.to_string())
                .or_default();
            entry.insert(source_id.to_string(), supported);
        }
    }

    /// Add a native collector source
    pub fn add_collector(
        &mut self,
        id: impl Into<String>,
        name: impl Into<String>,
        facts: &[&str],
        join_keys: &JoinKeySupport,
    ) {
        let id = id.into();
        self.sources.push(CapabilitySource {
            id: id.clone(),
            name: name.into(),
            source_type: SourceType::Collector,
            mode: IntegrationMode::Ingest, // collectors always ingest
        });

        // Add hard fidelity for all supported facts
        for fact_type in facts {
            let entry = self.fact_support.entry(fact_type.to_string()).or_default();
            entry.insert(id.clone(), Fidelity::Hard);
        }

        self.merge_join_keys(&id, join_keys);
    }

    /// Get best fidelity for a fact type across all sources
    pub fn best_fidelity(&self, fact_type: &str) -> Fidelity {
        self.fact_support
            .get(fact_type)
            .map(|sources| {
                sources
                    .values()
                    .max_by_key(|f| match f {
                        Fidelity::Hard => 2,
                        Fidelity::Soft => 1,
                        Fidelity::None => 0,
                    })
                    .copied()
                    .unwrap_or(Fidelity::None)
            })
            .unwrap_or(Fidelity::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_creation() {
        let profile = IntegrationProfile::wazuh("wazuh_main");
        assert_eq!(profile.integration_id, "wazuh_main");
        assert_eq!(profile.integration_type, IntegrationType::Wazuh);
        assert!(profile.join_keys_supported.proc_key);
        assert!(profile.facts_supported.contains_key("exec"));
    }

    #[test]
    fn test_health_status_updates() {
        let mut profile = IntegrationProfile::wazuh("test");

        // Initial status is unknown
        assert_eq!(profile.health_status, HealthStatus::Unknown);

        // After successful events
        for _ in 0..100 {
            profile.record_event(true, 1);
        }
        assert_eq!(profile.health_status, HealthStatus::Healthy);

        // High error rate triggers warning
        for _ in 0..50 {
            profile.record_event(false, 0);
        }
        assert!(profile.parse_error_rate > 0.1);
    }

    #[test]
    fn test_capabilities_matrix() {
        let mut store = IntegrationProfileStore::new();
        store.upsert(IntegrationProfile::wazuh("wazuh"));
        store.upsert(IntegrationProfile::zeek("zeek"));

        let matrix = store.merged_capabilities();

        assert_eq!(matrix.sources.len(), 2);
        assert!(matrix.fact_support.contains_key("exec"));
        assert!(matrix.fact_support.contains_key("dns_resolve"));
    }

    #[test]
    fn test_mapped_event_hash_determinism() {
        let raw = serde_json::json!({
            "timestamp": "2024-01-01T00:00:00Z",
            "agent": {"name": "host1"}
        });

        let event1 = MappedEvent::new("test", &raw, "1.0");
        let event2 = MappedEvent::new("test", &raw, "1.0");

        assert_eq!(event1.raw_json_hash, event2.raw_json_hash);
    }
}

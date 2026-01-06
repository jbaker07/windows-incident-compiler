//! Slot Matcher: Playbook slot matching engine for hypothesis compilation.
//!
//! This module provides:
//! - PlaybookIndex: Pre-built index for fast fact→playbook matching
//! - SlotMatcher: Predicate evaluation for slot matching
//! - CapabilityGate: Soft/hard fact capability awareness
//!
//! Design goals:
//! - Deterministic: stable ordering, stable IDs
//! - Efficient: O(1) index lookups, avoid O(N*M) scans
//! - Capability-aware: DnsResolve SOFT facts only fill soft_required slots

use crate::hypothesis::{Fact, FactType, ScopeKey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

// ============================================================================
// Capability Model
// ============================================================================

/// Capability level for a fact source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLevel {
    /// Hard capability: always available, reliable
    Hard,
    /// Soft capability: best-effort, may be missing or inaccurate
    Soft,
    /// Unavailable: source not implemented or offline
    Unavailable,
}

/// Capability registry for fact types
#[derive(Debug, Clone, Default)]
pub struct CapabilityRegistry {
    /// Map from fact type discriminant to capability level
    capabilities: HashMap<String, CapabilityLevel>,
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        let mut reg = Self::default();
        // Default capabilities - most facts are HARD
        reg.set_capability("Exec", CapabilityLevel::Hard);
        reg.set_capability("ProcSpawn", CapabilityLevel::Hard);
        reg.set_capability("OutboundConnect", CapabilityLevel::Hard);
        reg.set_capability("InboundConnect", CapabilityLevel::Hard);
        reg.set_capability("WritePath", CapabilityLevel::Hard);
        reg.set_capability("ReadPath", CapabilityLevel::Hard);
        reg.set_capability("CreatePath", CapabilityLevel::Hard);
        reg.set_capability("DeletePath", CapabilityLevel::Hard);
        reg.set_capability("PersistArtifact", CapabilityLevel::Hard);
        reg.set_capability("ModuleLoad", CapabilityLevel::Hard);
        reg.set_capability("MemWX", CapabilityLevel::Hard);
        reg.set_capability("PrivilegeBoundary", CapabilityLevel::Hard);

        // SOFT capabilities - best-effort
        reg.set_capability("DnsResolve", CapabilityLevel::Soft);
        reg.set_capability("AuthEvent", CapabilityLevel::Soft);
        reg
    }

    pub fn set_capability(&mut self, fact_type: &str, level: CapabilityLevel) {
        self.capabilities.insert(fact_type.to_string(), level);
    }

    pub fn get_capability(&self, fact_type: &str) -> CapabilityLevel {
        self.capabilities
            .get(fact_type)
            .copied()
            .unwrap_or(CapabilityLevel::Hard)
    }

    /// Check if a fact can fill a required slot
    pub fn can_fill_required(&self, fact_type: &str, soft_required_allowed: bool) -> bool {
        match self.get_capability(fact_type) {
            CapabilityLevel::Hard => true,
            CapabilityLevel::Soft => soft_required_allowed,
            CapabilityLevel::Unavailable => false,
        }
    }
}

// ============================================================================
// Playbook Definition (parsed from YAML)
// ============================================================================

/// Predicate for matching facts to slots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotPredicate {
    /// Required fact type (e.g., "Exec", "OutboundConnect")
    pub fact_type: String,
    /// Optional event type filter
    #[serde(default)]
    pub event_types: Vec<String>,
    /// Optional path glob pattern
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_glob: Option<String>,
    /// Optional path regex pattern
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_regex: Option<String>,
    /// Optional exe name filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_filter: Option<String>,
    /// Optional port filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    /// Optional port range (min, max)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_range: Option<(u16, u16)>,
    /// Optional MITRE ATT&CK tags
    #[serde(default)]
    pub mitre_tags: Vec<String>,
    /// Optional detector tags
    #[serde(default)]
    pub detector_tags: Vec<String>,
    /// Whether this slot can be filled by SOFT capability facts
    #[serde(default)]
    pub soft_required: bool,
}

impl SlotPredicate {
    pub fn for_fact_type(fact_type: &str) -> Self {
        Self {
            fact_type: fact_type.to_string(),
            event_types: Vec::new(),
            path_glob: None,
            path_regex: None,
            exe_filter: None,
            dst_port: None,
            port_range: None,
            mitre_tags: Vec::new(),
            detector_tags: Vec::new(),
            soft_required: false,
        }
    }

    pub fn with_path_glob(mut self, glob: &str) -> Self {
        self.path_glob = Some(glob.to_string());
        self
    }

    pub fn with_exe_filter(mut self, exe: &str) -> Self {
        self.exe_filter = Some(exe.to_string());
        self
    }

    pub fn with_dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    pub fn with_soft_required(mut self, soft: bool) -> Self {
        self.soft_required = soft;
        self
    }
}

/// Slot definition with predicate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookSlot {
    /// Slot identifier
    pub slot_id: String,
    /// Human-readable name
    pub name: String,
    /// Whether this slot is required
    pub required: bool,
    /// TTL in seconds
    pub ttl_seconds: u64,
    /// Matching predicate
    pub predicate: SlotPredicate,
}

impl PlaybookSlot {
    pub fn required(slot_id: &str, name: &str, predicate: SlotPredicate) -> Self {
        Self {
            slot_id: slot_id.to_string(),
            name: name.to_string(),
            required: true,
            ttl_seconds: 300,
            predicate,
        }
    }

    pub fn optional(slot_id: &str, name: &str, predicate: SlotPredicate) -> Self {
        Self {
            slot_id: slot_id.to_string(),
            name: name.to_string(),
            required: false,
            ttl_seconds: 300,
            predicate,
        }
    }

    pub fn with_ttl(mut self, seconds: u64) -> Self {
        self.ttl_seconds = seconds;
        self
    }
}

/// Playbook definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookDef {
    /// Unique playbook identifier
    pub playbook_id: String,
    /// Human-readable title
    pub title: String,
    /// Security family (e.g., "persistence", "exfiltration")
    pub family: String,
    /// Severity level
    pub severity: String,
    /// Entity scope pattern (e.g., "host|user|exe")
    #[serde(default = "default_entity_scope")]
    pub entity_scope: String,
    /// TTL window in seconds
    pub ttl_seconds: u64,
    /// Cooldown after fire in seconds
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: u64,
    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,
    /// Slot definitions
    pub slots: Vec<PlaybookSlot>,
    /// Narrative template
    #[serde(skip_serializing_if = "Option::is_none")]
    pub narrative: Option<String>,
    /// Playbook hash for versioning
    #[serde(skip)]
    pub playbook_hash: String,
}

fn default_entity_scope() -> String {
    "host|user|exe".to_string()
}

fn default_cooldown() -> u64 {
    120
}

impl PlaybookDef {
    /// Get required slot IDs
    pub fn required_slot_ids(&self) -> Vec<&str> {
        self.slots
            .iter()
            .filter(|s| s.required)
            .map(|s| s.slot_id.as_str())
            .collect()
    }

    /// Get all fact types referenced by this playbook
    pub fn referenced_fact_types(&self) -> Vec<&str> {
        self.slots
            .iter()
            .map(|s| s.predicate.fact_type.as_str())
            .collect()
    }

    /// Compute deterministic hash
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.playbook_id.as_bytes());
        for slot in &self.slots {
            hasher.update(slot.slot_id.as_bytes());
            hasher.update(slot.predicate.fact_type.as_bytes());
        }
        hex::encode(&hasher.finalize()[..16])
    }
}

// ============================================================================
// Playbook Index (Fast Lookup)
// ============================================================================

/// Index entry for fast playbook lookup
#[derive(Debug, Clone)]
struct IndexEntry {
    playbook_id: String,
    slot_id: String,
}

/// Pre-built index for O(1) fact→playbook lookup
#[derive(Debug, Default)]
pub struct PlaybookIndex {
    /// Map: fact_type → list of (playbook_id, slot_id)
    by_fact_type: HashMap<String, Vec<IndexEntry>>,
    /// Map: playbook_id → PlaybookDef
    playbooks: BTreeMap<String, PlaybookDef>,
}

impl PlaybookIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a playbook to the index
    pub fn add_playbook(&mut self, mut playbook: PlaybookDef) {
        playbook.playbook_hash = playbook.compute_hash();

        // Index each slot by fact type
        for slot in &playbook.slots {
            let entry = IndexEntry {
                playbook_id: playbook.playbook_id.clone(),
                slot_id: slot.slot_id.clone(),
            };
            self.by_fact_type
                .entry(slot.predicate.fact_type.clone())
                .or_default()
                .push(entry);
        }

        self.playbooks
            .insert(playbook.playbook_id.clone(), playbook);
    }

    /// Get candidate playbooks for a fact type
    pub fn candidates_for_fact_type(&self, fact_type: &str) -> Vec<(&PlaybookDef, &str)> {
        self.by_fact_type
            .get(fact_type)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|e| {
                        self.playbooks
                            .get(&e.playbook_id)
                            .map(|pb| (pb, e.slot_id.as_str()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get playbook by ID
    pub fn get_playbook(&self, playbook_id: &str) -> Option<&PlaybookDef> {
        self.playbooks.get(playbook_id)
    }

    /// Get all playbook IDs (sorted for determinism)
    pub fn playbook_ids(&self) -> Vec<&str> {
        self.playbooks.keys().map(|s| s.as_str()).collect()
    }

    /// Total playbook count
    pub fn len(&self) -> usize {
        self.playbooks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.playbooks.is_empty()
    }
}

// ============================================================================
// Slot Matcher
// ============================================================================

/// Result of matching a fact against slots
#[derive(Debug, Clone)]
pub struct SlotMatchResult {
    pub playbook_id: String,
    pub slot_id: String,
    pub matched: bool,
    pub fill_strength: FillStrength,
}

/// Fill strength for matched slots
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillStrength {
    Strong,
    Weak,
}

/// Slot matcher: evaluates fact predicates
pub struct SlotMatcher {
    capability_registry: CapabilityRegistry,
}

impl Default for SlotMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl SlotMatcher {
    pub fn new() -> Self {
        Self {
            capability_registry: CapabilityRegistry::new(),
        }
    }

    pub fn with_capabilities(capability_registry: CapabilityRegistry) -> Self {
        Self {
            capability_registry,
        }
    }

    /// Get fact type discriminant string
    fn fact_type_discriminant(fact: &Fact) -> &'static str {
        match &fact.fact_type {
            FactType::ProcSpawn { .. } => "ProcSpawn",
            FactType::Exec { .. } => "Exec",
            FactType::OutboundConnect { .. } => "OutboundConnect",
            FactType::InboundConnect { .. } => "InboundConnect",
            FactType::DnsResolve { .. } => "DnsResolve",
            FactType::WritePath { .. } => "WritePath",
            FactType::ReadPath { .. } => "ReadPath",
            FactType::CreatePath { .. } => "CreatePath",
            FactType::DeletePath { .. } => "DeletePath",
            FactType::RenamePath { .. } => "RenamePath",
            FactType::PersistArtifact { .. } => "PersistArtifact",
            FactType::PrivilegeBoundary { .. } => "PrivilegeBoundary",
            FactType::MemWX { .. } => "MemWX",
            FactType::MemAlloc { .. } => "MemAlloc",
            FactType::ModuleLoad { .. } => "ModuleLoad",
            FactType::Injection { .. } => "Injection",
            FactType::RegistryMod { .. } => "RegistryMod",
            FactType::AuthEvent { .. } => "AuthEvent",
            FactType::LogTamper { .. } => "LogTamper",
            FactType::SecurityToolDisable { .. } => "SecurityToolDisable",
            FactType::ShellCommand { .. } => "ShellCommand",
            FactType::ScriptExec { .. } => "ScriptExec",
            FactType::Unknown { .. } => "Unknown",
        }
    }

    /// Match a fact against a slot predicate
    pub fn matches_slot(&self, fact: &Fact, slot: &PlaybookSlot) -> Option<FillStrength> {
        let fact_type = Self::fact_type_discriminant(fact);

        // Check fact type matches
        if slot.predicate.fact_type != fact_type {
            return None;
        }

        // Check capability gating for required slots
        if slot.required
            && !self
                .capability_registry
                .can_fill_required(fact_type, slot.predicate.soft_required)
        {
            return None;
        }

        // Evaluate additional predicate filters
        let strength = self.evaluate_predicate(fact, &slot.predicate)?;

        Some(strength)
    }

    /// Evaluate predicate filters
    fn evaluate_predicate(&self, fact: &Fact, pred: &SlotPredicate) -> Option<FillStrength> {
        let mut strength = FillStrength::Strong;

        // Path glob matching
        if let Some(glob_pattern) = &pred.path_glob {
            let path = self.extract_path(fact)?;
            if !Self::glob_matches(glob_pattern, &path) {
                return None;
            }
        }

        // Path regex matching
        if let Some(regex_pattern) = &pred.path_regex {
            let path = self.extract_path(fact)?;
            if let Ok(re) = regex::Regex::new(regex_pattern) {
                if !re.is_match(&path) {
                    return None;
                }
            } else {
                return None; // Invalid regex
            }
        }

        // Exe filter
        if let Some(exe_filter) = &pred.exe_filter {
            if let Some(exe_path) = self.extract_exe(fact) {
                if !exe_path.contains(exe_filter) {
                    return None;
                }
            } else {
                return None;
            }
        }

        // Port filter
        if let Some(expected_port) = pred.dst_port {
            if let Some(actual_port) = self.extract_dst_port(fact) {
                if actual_port != expected_port {
                    return None;
                }
            } else {
                return None;
            }
        }

        // Port range filter
        if let Some((min_port, max_port)) = pred.port_range {
            if let Some(actual_port) = self.extract_dst_port(fact) {
                if actual_port < min_port || actual_port > max_port {
                    return None;
                }
            } else {
                return None;
            }
        }

        // SOFT capability facts get Weak strength
        let fact_type = Self::fact_type_discriminant(fact);
        if self.capability_registry.get_capability(fact_type) == CapabilityLevel::Soft {
            strength = FillStrength::Weak;
        }

        Some(strength)
    }

    /// Extract path from fact
    fn extract_path(&self, fact: &Fact) -> Option<String> {
        match &fact.fact_type {
            FactType::Exec { path, .. } => Some(path.clone()),
            FactType::WritePath { path, .. } => Some(path.clone()),
            FactType::ReadPath { path, .. } => Some(path.clone()),
            FactType::CreatePath { path, .. } => Some(path.clone()),
            FactType::DeletePath { path, .. } => Some(path.clone()),
            FactType::RenamePath { old_path, .. } => Some(old_path.clone()),
            FactType::PersistArtifact { path_or_key, .. } => Some(path_or_key.clone()),
            FactType::ModuleLoad { path, .. } => Some(path.clone()),
            _ => None,
        }
    }

    /// Extract exe path from fact
    fn extract_exe(&self, fact: &Fact) -> Option<String> {
        match &fact.fact_type {
            FactType::Exec { path, .. } => Some(path.clone()),
            FactType::ShellCommand { shell, .. } => Some(shell.clone()),
            FactType::ScriptExec { interpreter, .. } => Some(interpreter.clone()),
            _ => None,
        }
    }

    /// Extract destination port from fact
    fn extract_dst_port(&self, fact: &Fact) -> Option<u16> {
        match &fact.fact_type {
            FactType::OutboundConnect { dst_port, .. } => Some(*dst_port),
            _ => None,
        }
    }

    /// Simple glob matching (supports * and **)
    fn glob_matches(pattern: &str, path: &str) -> bool {
        // Simple implementation - use glob crate for production
        if pattern.contains("**") {
            // ** matches any path segments (including nested)
            let parts: Vec<&str> = pattern.split("**").collect();
            if parts.len() == 2 {
                let prefix = parts[0].trim_end_matches('/');
                let suffix = parts[1].trim_start_matches('/');
                // For **/*.ext, prefix is empty, suffix is *.ext
                let prefix_ok = prefix.is_empty() || path.starts_with(prefix);
                // Handle suffix with * (e.g., *.plist)
                let suffix_ok = if suffix.contains('*') {
                    let suffix_parts: Vec<&str> = suffix.split('*').collect();
                    if suffix_parts.len() == 2 {
                        path.ends_with(suffix_parts[1])
                    } else {
                        path.ends_with(suffix)
                    }
                } else {
                    suffix.is_empty() || path.ends_with(suffix)
                };
                return prefix_ok && suffix_ok;
            }
        }
        if pattern.contains('*') {
            // * matches characters within a segment
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                return path.starts_with(parts[0]) && path.ends_with(parts[1]);
            }
        }
        // Exact match
        pattern == path
    }
}

// ============================================================================
// Hypothesis Key (for state tracking)
// ============================================================================

/// Key for tracking hypothesis state per (playbook, entity)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HypothesisKey {
    pub playbook_id: String,
    pub host_id: String,
    pub scope_key: String,
    pub time_bucket: i64,
}

impl HypothesisKey {
    pub fn new(
        playbook_id: &str,
        host_id: &str,
        scope_key: &ScopeKey,
        ts: DateTime<Utc>,
        bucket_seconds: i64,
    ) -> Self {
        let time_bucket = ts.timestamp() / bucket_seconds;
        Self {
            playbook_id: playbook_id.to_string(),
            host_id: host_id.to_string(),
            scope_key: scope_key.to_string(),
            time_bucket,
        }
    }

    /// Compute stable hypothesis ID
    pub fn to_hypothesis_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.playbook_id.as_bytes());
        hasher.update(self.host_id.as_bytes());
        hasher.update(self.scope_key.as_bytes());
        hasher.update(self.time_bucket.to_le_bytes());
        format!("hyp_{}", hex::encode(&hasher.finalize()[..16]))
    }
}

// ============================================================================
// Fact Index Key (for deduplication)
// ============================================================================

/// Key for deduplicating facts
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FactIndexKey {
    pub host_id: String,
    pub scope_key: String,
    pub time_bucket: i64,
    pub fact_type: String,
    pub salient_fields: String,
}

impl FactIndexKey {
    pub fn from_fact(fact: &Fact, bucket_seconds: i64) -> Self {
        let time_bucket = fact.ts.timestamp() / bucket_seconds;
        let fact_type = SlotMatcher::fact_type_discriminant(fact).to_string();

        // Extract salient fields for deduplication
        let salient_fields = match &fact.fact_type {
            FactType::Exec { path, .. } => path.clone(),
            FactType::OutboundConnect {
                dst_ip, dst_port, ..
            } => {
                format!("{}:{}", dst_ip, dst_port)
            }
            FactType::WritePath { path, .. } => path.clone(),
            FactType::DnsResolve { query, .. } => query.clone(),
            _ => format!("{:?}", fact.fact_type),
        };

        Self {
            host_id: fact.host_id.clone(),
            scope_key: fact.scope_key.to_string(),
            time_bucket,
            fact_type,
            salient_fields,
        }
    }
}

// ============================================================================
// Match Result
// ============================================================================

/// Result of matching a fact against all playbooks
#[derive(Debug, Clone)]
pub struct FactMatchResult {
    /// Hypotheses that were updated
    pub updated_hypothesis_ids: Vec<String>,
    /// Playbooks that fired (all required slots filled)
    pub fired_playbooks: Vec<PlaybookFireEvent>,
}

/// Event when a playbook fires
#[derive(Debug, Clone)]
pub struct PlaybookFireEvent {
    pub playbook_id: String,
    pub hypothesis_id: String,
    pub host_id: String,
    pub scope_key: ScopeKey,
    pub severity: String,
    pub slot_fills: Vec<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_playbook_index() {
        let mut index = PlaybookIndex::new();

        let playbook = PlaybookDef {
            playbook_id: "pb_test".to_string(),
            title: "Test Playbook".to_string(),
            family: "test".to_string(),
            severity: "high".to_string(),
            entity_scope: "host|user".to_string(),
            ttl_seconds: 300,
            cooldown_seconds: 60,
            tags: vec!["test".to_string()],
            slots: vec![
                PlaybookSlot::required(
                    "exec_slot",
                    "Process Exec",
                    SlotPredicate::for_fact_type("Exec"),
                ),
                PlaybookSlot::required(
                    "connect_slot",
                    "Outbound Connect",
                    SlotPredicate::for_fact_type("OutboundConnect"),
                ),
            ],
            narrative: None,
            playbook_hash: String::new(),
        };

        index.add_playbook(playbook);

        let candidates = index.candidates_for_fact_type("Exec");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0.playbook_id, "pb_test");
        assert_eq!(candidates[0].1, "exec_slot");
    }

    #[test]
    fn test_capability_gating() {
        let registry = CapabilityRegistry::new();

        // DNS is SOFT
        assert_eq!(registry.get_capability("DnsResolve"), CapabilityLevel::Soft);
        assert!(!registry.can_fill_required("DnsResolve", false));
        assert!(registry.can_fill_required("DnsResolve", true));

        // Exec is HARD
        assert_eq!(registry.get_capability("Exec"), CapabilityLevel::Hard);
        assert!(registry.can_fill_required("Exec", false));
    }

    #[test]
    fn test_hypothesis_key_determinism() {
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };
        let ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:05:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let key1 = HypothesisKey::new("pb_test", "host1", &scope, ts, 600);
        let key2 = HypothesisKey::new("pb_test", "host1", &scope, ts, 600);

        assert_eq!(key1.to_hypothesis_id(), key2.to_hypothesis_id());

        // Different time bucket should produce different ID
        let ts2 = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:15:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let key3 = HypothesisKey::new("pb_test", "host1", &scope, ts2, 600);
        assert_ne!(key1.to_hypothesis_id(), key3.to_hypothesis_id());
    }

    #[test]
    fn test_glob_matching() {
        assert!(SlotMatcher::glob_matches(
            "/Library/LaunchAgents/*.plist",
            "/Library/LaunchAgents/com.evil.plist"
        ));
        assert!(!SlotMatcher::glob_matches(
            "/Library/LaunchAgents/*.plist",
            "/Library/LaunchDaemons/com.evil.plist"
        ));
        assert!(SlotMatcher::glob_matches(
            "**/*.plist",
            "/any/path/file.plist"
        ));
    }
}

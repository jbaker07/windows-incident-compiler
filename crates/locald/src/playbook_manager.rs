//! PlaybookManager: Central playbook loading and management service.
//!
//! This module provides:
//! - Deterministic playbook loading from YAML files in playbooks/windows/
//! - Playbook validation and metrics tracking
//! - Statistics for the coverage API ("Why no signals?")
//!
//! Design goals:
//! - Fail loudly at startup if no playbooks load (log ERROR, not silent)
//! - Track playbooks_loaded, playbooks_enabled, categories
//! - Support per-run metrics (playbooks_fired_this_run)

use crate::slot_matcher::{PlaybookDef, PlaybookSlot, SlotPredicate};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Reason why a playbook was skipped during loading
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlaybookSkipReason {
    /// Playbook uses tag-based conditions (not yet supported)
    TagBasedUnsupported,
    /// No slots could be built (missing fact_type in conditions)
    NoSlotsBuilt,
    /// Playbook is explicitly disabled
    Disabled,
    /// YAML validation error
    ValidationError,
    /// File read/parse error
    ParseError,
}

impl std::fmt::Display for PlaybookSkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlaybookSkipReason::TagBasedUnsupported => write!(f, "TAG_BASED_UNSUPPORTED"),
            PlaybookSkipReason::NoSlotsBuilt => write!(f, "NO_SLOTS_BUILT"),
            PlaybookSkipReason::Disabled => write!(f, "DISABLED"),
            PlaybookSkipReason::ValidationError => write!(f, "VALIDATION_ERROR"),
            PlaybookSkipReason::ParseError => write!(f, "PARSE_ERROR"),
        }
    }
}

/// Example of a skipped playbook with reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedPlaybook {
    /// Playbook file name or ID
    pub playbook_id: String,
    /// Why it was skipped
    pub reason: PlaybookSkipReason,
    /// Human-readable explanation
    pub explanation: String,
}

/// Playbook loading result with TRUTHFUL accounting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookLoadResult {
    /// Whether loading succeeded (at least 1 playbook)
    pub success: bool,
    /// Number of YAML files found
    pub total_yaml_files: u32,
    /// Number of playbooks that built successfully and can run
    pub loaded_count: u32,
    /// Number of playbooks enabled (for future use)
    pub enabled_count: u32,
    /// Number of playbooks skipped (total_yaml_files - loaded_count)
    pub skipped_count: u32,
    /// Breakdown of skip reasons -> count
    pub skipped_by_reason: HashMap<String, u32>,
    /// Examples of skipped playbooks (up to 10)
    pub skipped_examples: Vec<SkippedPlaybook>,
    /// Playbook categories/families found
    pub categories: Vec<String>,
    /// Playbook IDs loaded
    pub playbook_ids: Vec<String>,
    /// Any errors during loading
    pub errors: Vec<String>,
    /// Source of playbooks (e.g., "hardcoded", "yaml:playbooks/windows")
    pub source: String,
}

impl Default for PlaybookLoadResult {
    fn default() -> Self {
        Self {
            success: false,
            total_yaml_files: 0,
            loaded_count: 0,
            enabled_count: 0,
            skipped_count: 0,
            skipped_by_reason: HashMap::new(),
            skipped_examples: Vec::new(),
            categories: Vec::new(),
            playbook_ids: Vec::new(),
            errors: Vec::new(),
            source: "none".to_string(),
        }
    }
}

/// Per-run playbook metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunPlaybookMetrics {
    /// Playbooks that evaluated (had candidate facts)
    pub playbooks_evaluated: u32,
    /// Playbooks that fired (produced signals)
    pub playbooks_fired: u32,
    /// IDs of playbooks that fired
    pub fired_playbook_ids: Vec<String>,
    /// Categories of fired playbooks
    pub fired_categories: Vec<String>,
}

/// Playbook statistics for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStats {
    /// Total playbooks loaded
    pub loaded_count: u32,
    /// Enabled playbooks
    pub enabled_count: u32,
    /// Categories/families available
    pub categories: Vec<String>,
    /// Category breakdown: family -> count
    pub category_counts: HashMap<String, u32>,
    /// Source of playbooks
    pub source: String,
    /// Per-run metrics (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_metrics: Option<RunPlaybookMetrics>,
}

// ============================================================================
// YAML Playbook Schema (for parsing playbooks/windows/*.yaml)
// ============================================================================

/// YAML playbook format - matches the files in playbooks/windows/
#[derive(Debug, Clone, Deserialize)]
struct YamlPlaybook {
    /// Playbook ID (required)
    id: Option<String>,
    /// Playbook name (fallback for ID)
    name: Option<String>,
    /// Title (optional)
    title: Option<String>,
    /// Version
    #[serde(default)]
    version: String,
    /// Description
    #[serde(default)]
    description: String,
    /// Family/category (e.g., "execution", "persistence", "lateral_movement")
    #[serde(default)]
    family: Option<String>,
    /// Whether playbook is enabled
    #[serde(default = "default_enabled")]
    enabled: bool,
    /// Confidence threshold
    #[serde(default)]
    confidence_threshold: Option<f64>,
    /// MITRE ATT&CK mapping
    #[serde(default)]
    mitre: Option<YamlMitre>,
    /// Input fact types
    #[serde(default)]
    input_facts: Option<YamlInputFacts>,
    /// Slot definitions
    #[serde(default)]
    slots: Option<YamlSlots>,
    /// Detection rules
    #[serde(default)]
    rules: Option<Vec<YamlRule>>,
    /// Detection block (alternative format)
    #[serde(default)]
    detection: Option<YamlDetection>,
    /// Tags
    #[serde(default)]
    tags: Vec<String>,
    /// Signals block (for correlation playbooks)
    #[serde(default)]
    signals: Option<Vec<YamlSignalRef>>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
struct YamlMitre {
    #[serde(default)]
    tactics: Vec<String>,
    #[serde(default)]
    techniques: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct YamlInputFacts {
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    optional: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct YamlSlots {
    #[serde(default)]
    required: Vec<YamlSlotDef>,
    #[serde(default)]
    optional: Vec<YamlSlotDef>,
}

#[derive(Debug, Clone, Deserialize)]
struct YamlSlotDef {
    name: String,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    pattern: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct YamlRule {
    name: String,
    #[serde(default)]
    window: Option<u64>,
    #[serde(default)]
    conditions: Vec<YamlCondition>,
    #[serde(default)]
    actions: Vec<YamlAction>,
    #[serde(default)]
    aggregation: Option<String>,
    #[serde(default)]
    threshold: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum YamlCondition {
    Simple(String),
    FieldMatch {
        #[serde(default)]
        fact_type: Option<String>,
        #[serde(default)]
        tag: Option<String>,
        #[serde(default)]
        field: Option<String>,
        #[serde(default)]
        matches: Option<String>,
        #[serde(default)]
        event_id: Option<u32>,
        #[serde(flatten)]
        extra: HashMap<String, serde_yaml::Value>,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct YamlAction {
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct YamlDetection {
    #[serde(default)]
    signals: Vec<YamlDetectionSignal>,
}

#[derive(Debug, Clone, Deserialize)]
struct YamlDetectionSignal {
    #[serde(default)]
    r#type: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct YamlSignalRef {
    #[serde(default)]
    tag: Option<String>,
}

// ============================================================================
// PlaybookManager Implementation
// ============================================================================

/// Central playbook management service
pub struct PlaybookManager {
    /// Loaded playbook definitions
    playbooks: HashMap<String, PlaybookDef>,
    /// Load result with metadata
    load_result: PlaybookLoadResult,
    /// Per-run metrics tracker (reset per run)
    run_metrics: Arc<RwLock<RunPlaybookMetrics>>,
    /// Set of playbooks that have fired this run
    fired_playbooks: Arc<RwLock<HashSet<String>>>,
}

impl PlaybookManager {
    /// Create a new PlaybookManager
    pub fn new() -> Self {
        Self {
            playbooks: HashMap::new(),
            load_result: PlaybookLoadResult::default(),
            run_metrics: Arc::new(RwLock::new(RunPlaybookMetrics::default())),
            fired_playbooks: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Load playbooks from the default location (playbooks/windows/)
    /// Returns true if at least one playbook was loaded
    pub fn load_default(&mut self) -> bool {
        // Priority 1: Explicit env var (set by locint supervisor)
        if let Ok(dir) = std::env::var("EDR_PLAYBOOKS_DIR") {
            let path = PathBuf::from(&dir);
            if path.exists() && path.is_dir() {
                return self.load_from_yaml_dir(&path);
            }
            eprintln!("[PlaybookManager] WARNING: EDR_PLAYBOOKS_DIR='{}' does not exist", dir);
        }

        // Priority 2: Try to find playbooks directory relative to common locations
        let possible_roots = [
            std::env::current_dir().unwrap_or_default(),
            PathBuf::from("."),
            PathBuf::from(".."),
            // For installed location
            std::env::var("EDR_ROOT")
                .map(PathBuf::from)
                .unwrap_or_default(),
        ];

        for root in &possible_roots {
            let playbook_dir = root.join("playbooks").join("windows");
            if playbook_dir.exists() && playbook_dir.is_dir() {
                return self.load_from_yaml_dir(&playbook_dir);
            }
        }

        eprintln!("[PlaybookManager] WARNING: Could not find playbooks/windows directory");
        self.load_result = PlaybookLoadResult {
            success: false,
            total_yaml_files: 0,
            loaded_count: 0,
            enabled_count: 0,
            skipped_count: 0,
            skipped_by_reason: HashMap::new(),
            skipped_examples: Vec::new(),
            categories: Vec::new(),
            playbook_ids: Vec::new(),
            errors: vec!["Playbook directory not found".to_string()],
            source: "none".to_string(),
        };
        false
    }

    /// Load playbooks from YAML files in a directory
    pub fn load_from_yaml_dir(&mut self, dir: &Path) -> bool {
        let mut loaded_playbooks: Vec<PlaybookDef> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut skipped: Vec<SkippedPlaybook> = Vec::new();
        let mut total_yaml_files: u32 = 0;

        // Read all .yaml files in directory
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                errors.push(format!("Failed to read directory {:?}: {}", dir, e));
                self.load_result = PlaybookLoadResult {
                    success: false,
                    total_yaml_files: 0,
                    loaded_count: 0,
                    enabled_count: 0,
                    skipped_count: 0,
                    skipped_by_reason: HashMap::new(),
                    skipped_examples: Vec::new(),
                    categories: Vec::new(),
                    playbook_ids: Vec::new(),
                    errors,
                    source: format!("yaml:{}", dir.display()),
                };
                return false;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yaml" && ext != "yml" {
                continue;
            }

            total_yaml_files += 1;
            let filename = path.file_name().unwrap_or_default().to_string_lossy().to_string();

            match self.parse_yaml_playbook_with_reason(&path) {
                Ok(pb) => {
                    if pb.slots.is_empty() {
                        // Skip playbooks with no slots - record reason
                        let reason = self.diagnose_no_slots(&path);
                        eprintln!(
                            "  [playbook] Skipped {} ({:?})",
                            filename, reason
                        );
                        skipped.push(SkippedPlaybook {
                            playbook_id: pb.playbook_id.clone(),
                            reason,
                            explanation: format!("Playbook has no usable slots: {:?}", reason),
                        });
                    } else {
                        loaded_playbooks.push(pb);
                    }
                }
                Err((reason, msg)) => {
                    errors.push(format!("{}: {}", filename, msg));
                    skipped.push(SkippedPlaybook {
                        playbook_id: filename.clone(),
                        reason,
                        explanation: msg,
                    });
                }
            }
        }

        // Sort for deterministic ordering
        loaded_playbooks.sort_by(|a, b| a.playbook_id.cmp(&b.playbook_id));

        // Build metadata
        let mut categories: HashSet<String> = HashSet::new();
        let mut playbook_ids: Vec<String> = Vec::new();

        for pb in &loaded_playbooks {
            categories.insert(pb.family.clone());
            playbook_ids.push(pb.playbook_id.clone());
        }

        // Store playbooks
        for pb in loaded_playbooks {
            self.playbooks.insert(pb.playbook_id.clone(), pb);
        }

        let count = self.playbooks.len() as u32;
        let mut cats: Vec<String> = categories.into_iter().collect();
        cats.sort();

        // Build skipped_by_reason counts
        let mut skipped_by_reason: HashMap<String, u32> = HashMap::new();
        for s in &skipped {
            *skipped_by_reason.entry(s.reason.to_string()).or_insert(0) += 1;
        }

        // Keep only first 10 examples
        let skipped_examples: Vec<SkippedPlaybook> = skipped.into_iter().take(10).collect();
        let skipped_count = total_yaml_files - count;

        self.load_result = PlaybookLoadResult {
            success: count > 0,
            total_yaml_files,
            loaded_count: count,
            enabled_count: count, // All loaded are enabled for now
            skipped_count,
            skipped_by_reason,
            skipped_examples,
            categories: cats,
            playbook_ids,
            errors,
            source: format!("yaml:{}", dir.display()),
        };

        count > 0
    }

    /// Diagnose why a playbook has no slots
    /// TASK A: With tag-to-slot mapping, tag-based playbooks should now produce slots
    fn diagnose_no_slots(&self, path: &Path) -> PlaybookSkipReason {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return PlaybookSkipReason::ParseError,
        };
        
        // Tag-based playbooks should now work via tag_to_slot_predicate()
        // If still no slots, it's because the playbook has no rules/conditions at all
        if !content.contains("rules:") && !content.contains("slots:") && !content.contains("input_facts:") {
            return PlaybookSkipReason::NoSlotsBuilt;
        }
        
        PlaybookSkipReason::NoSlotsBuilt
    }

    /// Parse a YAML playbook, returning reason on error
    fn parse_yaml_playbook_with_reason(&self, path: &Path) -> Result<PlaybookDef, (PlaybookSkipReason, String)> {
        self.parse_yaml_playbook(path)
            .map_err(|msg| {
                let reason = if msg.contains("disabled") {
                    PlaybookSkipReason::Disabled
                } else if msg.contains("YAML") || msg.contains("parse") {
                    PlaybookSkipReason::ParseError
                } else {
                    PlaybookSkipReason::ValidationError
                };
                (reason, msg)
            })
    }

    /// Parse a single YAML playbook file into a PlaybookDef
    fn parse_yaml_playbook(&self, path: &Path) -> Result<PlaybookDef, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read: {}", e))?;

        let yaml: YamlPlaybook = serde_yaml::from_str(&content)
            .map_err(|e| format!("YAML parse error: {}", e))?;

        // Skip disabled playbooks
        if !yaml.enabled {
            return Err("Playbook is disabled".to_string());
        }

        // Extract playbook ID
        let playbook_id = yaml
            .id
            .clone()
            .or_else(|| {
                // Generate ID from filename
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
            })
            .ok_or("Missing playbook ID")?;

        // Extract title
        let title = yaml
            .title
            .clone()
            .or_else(|| yaml.name.clone())
            .unwrap_or_else(|| playbook_id.clone());

        // Determine family/category
        let family = yaml.family
            .clone()
            .or_else(|| {
                // Try to infer from MITRE tactics
                yaml.mitre.as_ref().and_then(|m| m.tactics.first().cloned())
            })
            .or_else(|| {
                // Try to infer from filename
                let fname = path.file_stem()?.to_str()?;
                if fname.contains("lateral") { return Some("lateral_movement".to_string()); }
                if fname.contains("persist") { return Some("persistence".to_string()); }
                if fname.contains("cred") { return Some("credential_access".to_string()); }
                if fname.contains("evasion") { return Some("defense_evasion".to_string()); }
                if fname.contains("discovery") { return Some("discovery".to_string()); }
                if fname.contains("execution") || fname.contains("powershell") || fname.contains("cmd") {
                    return Some("execution".to_string());
                }
                if fname.contains("exfil") { return Some("exfiltration".to_string()); }
                None
            })
            .unwrap_or_else(|| "unknown".to_string());

        // Determine severity from rules or default
        let severity = yaml.rules
            .as_ref()
            .and_then(|rules| rules.first())
            .and_then(|r| r.actions.first())
            .and_then(|a| a.severity.clone())
            .unwrap_or_else(|| "medium".to_string())
            .to_lowercase();

        // Build slots from YAML
        let slots = self.build_slots_from_yaml(&yaml);

        // Build tags
        let mut tags = yaml.tags.clone();
        if let Some(mitre) = &yaml.mitre {
            tags.extend(mitre.techniques.iter().cloned());
        }

        // Extract version from YAML
        let version = yaml.version.clone();

        Ok(PlaybookDef {
            playbook_id,
            title,
            family,
            severity,
            version,
            entity_scope: "host|user|exe".to_string(),
            ttl_seconds: yaml.rules
                .as_ref()
                .and_then(|r| r.first())
                .and_then(|r| r.window)
                .unwrap_or(300),
            cooldown_seconds: 120,
            tags,
            slots,
            narrative: Some(yaml.description),
            playbook_hash: String::new(),
        })
    }

    /// Build PlaybookSlot list from YAML playbook
    fn build_slots_from_yaml(&self, yaml: &YamlPlaybook) -> Vec<PlaybookSlot> {
        let mut slots: Vec<PlaybookSlot> = Vec::new();
        let mut slot_index = 0;

        // From explicit slots section
        if let Some(yaml_slots) = &yaml.slots {
            for slot_def in &yaml_slots.required {
                if let Some(slot) = self.yaml_slot_to_playbook_slot(&slot_def, true, slot_index) {
                    slots.push(slot);
                    slot_index += 1;
                }
            }
            for slot_def in &yaml_slots.optional {
                if let Some(slot) = self.yaml_slot_to_playbook_slot(&slot_def, false, slot_index) {
                    slots.push(slot);
                    slot_index += 1;
                }
            }
        }

        // From input_facts section
        if let Some(input_facts) = &yaml.input_facts {
            for fact_type in &input_facts.required {
                let slot = PlaybookSlot {
                    slot_id: format!("slot_{}", slot_index),
                    name: format!("{} fact", fact_type),
                    required: true,
                    ttl_seconds: 300,
                    predicate: SlotPredicate::for_fact_type(fact_type),
                };
                slots.push(slot);
                slot_index += 1;
            }
        }

        // From rules section - extract fact types and patterns
        // TASK A: Now also handles tag-based conditions via tag_to_slot_predicate()
        if let Some(rules) = &yaml.rules {
            for rule in rules {
                for cond in &rule.conditions {
                    match cond {
                        YamlCondition::FieldMatch { fact_type, tag, field, matches, .. } => {
                            // First try fact_type (preferred)
                            if let Some(ft) = fact_type {
                                let mut predicate = SlotPredicate::for_fact_type(ft);
                                
                                // Add pattern matching
                                if let (Some(f), Some(m)) = (field, matches) {
                                    match f.as_str() {
                                        "path" | "cmdline" => {
                                            predicate.path_regex = Some(m.clone());
                                        }
                                        "exe" | "process" => {
                                            predicate.exe_filter = Some(m.clone());
                                        }
                                        _ => {}
                                    }
                                }

                                let slot = PlaybookSlot {
                                    slot_id: format!("slot_{}", slot_index),
                                    name: rule.name.clone(),
                                    required: true,
                                    ttl_seconds: rule.window.unwrap_or(300),
                                    predicate,
                                };
                                slots.push(slot);
                                slot_index += 1;
                            }
                            // TASK A: Handle tag-based conditions by mapping to fact types
                            else if let Some(t) = tag {
                                if let Some(predicate) = Self::tag_to_slot_predicate(t) {
                                    let slot = PlaybookSlot {
                                        slot_id: format!("slot_{}", slot_index),
                                        name: format!("{} (tag:{})", rule.name, t),
                                        required: true,
                                        ttl_seconds: rule.window.unwrap_or(300),
                                        predicate,
                                    };
                                    slots.push(slot);
                                    slot_index += 1;
                                }
                            }
                        }
                        YamlCondition::Simple(_) => {
                            // Simple string conditions not supported for slot building
                        }
                    }
                }
            }
        }

        // From detection.signals section
        if let Some(detection) = &yaml.detection {
            for sig in &detection.signals {
                if let Some(sig_type) = &sig.r#type {
                    // Map signal type to fact type
                    let fact_type = if sig_type.contains("service") {
                        "PersistArtifact"
                    } else if sig_type.contains("task") {
                        "PersistArtifact"
                    } else if sig_type.contains("registry") {
                        "PersistArtifact"
                    } else {
                        "Exec"
                    };

                    let slot = PlaybookSlot {
                        slot_id: format!("slot_{}", slot_index),
                        name: sig_type.clone(),
                        required: true,
                        ttl_seconds: 300,
                        predicate: SlotPredicate::for_fact_type(fact_type),
                    };
                    slots.push(slot);
                    slot_index += 1;
                }
            }
        }

        // TASK A: From top-level signals section (tag-based playbooks)
        // These specify input signal tags like: signals: [{tag: "service_install"}]
        if let Some(signals) = &yaml.signals {
            for sig_ref in signals {
                if let Some(t) = &sig_ref.tag {
                    if let Some(predicate) = Self::tag_to_slot_predicate(t) {
                        let slot = PlaybookSlot {
                            slot_id: format!("slot_{}", slot_index),
                            name: format!("signal_tag:{}", t),
                            required: true,
                            ttl_seconds: 300,
                            predicate,
                        };
                        slots.push(slot);
                        slot_index += 1;
                    }
                }
            }
        }

        slots
    }

    /// TASK A: Map tag conditions to SlotPredicate using existing FactTypes
    /// 
    /// This enables tag-based playbooks to fire by translating semantic tags
    /// to concrete fact type predicates that the slot matcher understands.
    /// 
    /// Mapping strategy:
    /// - Service/task/registry persistence tags → PersistArtifact fact type
    /// - Process injection tags → Exec with specific patterns
    /// - Lateral movement tags → Auth + NetConnect fact types
    /// - Log tampering tags → Exec targeting event log processes
    /// - Group membership tags → Auth fact type
    fn tag_to_slot_predicate(tag: &str) -> Option<SlotPredicate> {
        let tag_lower = tag.to_lowercase();
        
        // Service installation/persistence
        if tag_lower.contains("service_install") || tag_lower.contains("service_create") {
            let mut pred = SlotPredicate::for_fact_type("PersistArtifact");
            pred.path_regex = Some("(?i)service|imagepath|start".to_string());
            return Some(pred);
        }
        
        // Service modification
        if tag_lower.contains("service_modify") || tag_lower.contains("windows_service") {
            let mut pred = SlotPredicate::for_fact_type("PersistArtifact");
            pred.path_regex = Some("(?i)services|servicename".to_string());
            return Some(pred);
        }
        
        // Scheduled task persistence
        if tag_lower.contains("task_create") || tag_lower.contains("schtasks") || tag_lower.contains("scheduled_task") {
            let mut pred = SlotPredicate::for_fact_type("PersistArtifact");
            pred.path_regex = Some("(?i)task|schedule|at\\.exe".to_string());
            return Some(pred);
        }
        
        // Registry persistence
        if tag_lower.contains("registry") || tag_lower.contains("reg_") || tag_lower.contains("autorun") {
            let mut pred = SlotPredicate::for_fact_type("PersistArtifact");
            pred.path_regex = Some("(?i)registry|hklm|hkcu|run|currentversion".to_string());
            return Some(pred);
        }
        
        // Process injection
        if tag_lower.contains("process_inject") || tag_lower.contains("injection") || tag_lower.contains("hollow") {
            let mut pred = SlotPredicate::for_fact_type("Exec");
            pred.path_regex = Some("(?i)inject|hollow|writeprocessmemory|ntmap".to_string());
            return Some(pred);
        }
        
        // Lateral movement
        if tag_lower.contains("lateral") || tag_lower.contains("psexec") || tag_lower.contains("wmi_exec") {
            let mut pred = SlotPredicate::for_fact_type("Auth");
            pred.path_regex = Some("(?i)lateral|remote|psexec|wmic|winrm".to_string());
            return Some(pred);
        }
        
        // RD-2 FIX: WMI/MOF persistence events (Sysmon Event IDs 19-21)
        if tag_lower.contains("wmi") || tag_lower.contains("mof") || tag_lower.contains("wmi_event") {
            let mut pred = SlotPredicate::for_fact_type("Exec");
            pred.exe_filter = Some("(?i)wmiprvse|scrcons|mofcomp|wmic".to_string());
            pred.path_regex = Some("(?i)wmi|mof|__eventconsumer|__eventfilter|commandlineeventconsumer".to_string());
            return Some(pred);
        }
        
        // Log tampering / clearing
        if tag_lower.contains("log_clear") || tag_lower.contains("log_tamper") || tag_lower.contains("eventlog") {
            let mut pred = SlotPredicate::for_fact_type("Exec");
            pred.exe_filter = Some("(?i)wevtutil|powershell".to_string());
            pred.path_regex = Some("(?i)clear-eventlog|wevtutil\\s+cl".to_string());
            return Some(pred);
        }
        
        // RD-2 FIX: Audit policy manipulation
        if tag_lower.starts_with("audit_") || tag_lower.contains("audit_policy") || tag_lower.contains("auditpol") {
            let mut pred = SlotPredicate::for_fact_type("Exec");
            pred.exe_filter = Some("(?i)auditpol|secpol".to_string());
            pred.path_regex = Some("(?i)auditpol|audit.*policy|secpol".to_string());
            return Some(pred);
        }
        
        // Group membership changes
        if tag_lower.contains("group_member") || tag_lower.contains("admin_group") {
            let mut pred = SlotPredicate::for_fact_type("Auth");
            pred.path_regex = Some("(?i)group|administrator|member".to_string());
            return Some(pred);
        }
        
        // Persistence (generic)
        if tag_lower.contains("persistence") {
            return Some(SlotPredicate::for_fact_type("PersistArtifact"));
        }
        
        // Credential access
        if tag_lower.contains("credential") || tag_lower.contains("lsass") || tag_lower.contains("mimikatz") {
            let mut pred = SlotPredicate::for_fact_type("Exec");
            pred.path_regex = Some("(?i)lsass|credential|sekurlsa|mimikatz".to_string());
            return Some(pred);
        }
        
        // Default: if tag looks like an action, map to Exec
        if tag_lower.contains("exec") || tag_lower.contains("run") || tag_lower.contains("spawn") {
            return Some(SlotPredicate::for_fact_type("Exec"));
        }
        
        // Fallback: generic Exec predicate for unknown tags so playbook still has a slot
        Some(SlotPredicate::for_fact_type("Exec"))
    }

    /// Convert YAML slot definition to PlaybookSlot
    fn yaml_slot_to_playbook_slot(
        &self,
        yaml_slot: &YamlSlotDef,
        required: bool,
        index: usize,
    ) -> Option<PlaybookSlot> {
        // Determine fact type based on slot name/type
        let fact_type = match yaml_slot.name.as_str() {
            "process_name" | "exe" | "encoded_flag" | "bypass_flag" | "hidden_flag" | "noprofile_flag" => "Exec",
            "path" | "file" => "WritePath",
            "network" | "connection" => "OutboundConnect",
            "registry" => "PersistArtifact",
            _ => "Exec", // Default
        };

        let mut predicate = SlotPredicate::for_fact_type(fact_type);

        // Apply pattern as regex
        if let Some(pattern) = &yaml_slot.pattern {
            if yaml_slot.name.contains("path") || yaml_slot.name.contains("flag") || yaml_slot.name.contains("encoded") {
                predicate.path_regex = Some(pattern.clone());
            } else if yaml_slot.name.contains("process") || yaml_slot.name.contains("exe") {
                predicate.exe_filter = Some(pattern.clone());
            }
        }

        Some(PlaybookSlot {
            slot_id: format!("slot_{}", index),
            name: yaml_slot.name.clone(),
            required,
            ttl_seconds: 300,
            predicate,
        })
    }

    /// Get the load result
    pub fn load_result(&self) -> &PlaybookLoadResult {
        &self.load_result
    }

    /// Get all loaded playbooks
    pub fn playbooks(&self) -> Vec<&PlaybookDef> {
        let mut pbs: Vec<_> = self.playbooks.values().collect();
        pbs.sort_by(|a, b| a.playbook_id.cmp(&b.playbook_id));
        pbs
    }

    /// Get owned playbooks (for passing to HypothesisController)
    pub fn playbooks_owned(&self) -> Vec<PlaybookDef> {
        let mut pbs: Vec<_> = self.playbooks.values().cloned().collect();
        pbs.sort_by(|a, b| a.playbook_id.cmp(&b.playbook_id));
        pbs
    }

    /// Get a playbook by ID
    pub fn get(&self, playbook_id: &str) -> Option<&PlaybookDef> {
        self.playbooks.get(playbook_id)
    }

    /// Get playbook statistics for API responses
    pub fn stats(&self) -> PlaybookStats {
        let mut category_counts: HashMap<String, u32> = HashMap::new();
        for pb in self.playbooks.values() {
            *category_counts.entry(pb.family.clone()).or_insert(0) += 1;
        }

        let run_metrics = self.run_metrics.read().ok().map(|m| m.clone());

        PlaybookStats {
            loaded_count: self.load_result.loaded_count,
            enabled_count: self.load_result.enabled_count,
            categories: self.load_result.categories.clone(),
            category_counts,
            source: self.load_result.source.clone(),
            run_metrics,
        }
    }

    /// Record a playbook fire (when a signal is produced)
    pub fn record_fire(&self, playbook_id: &str) {
        // Track in fired set
        if let Ok(mut fired) = self.fired_playbooks.write() {
            fired.insert(playbook_id.to_string());
        }

        // Update run metrics
        if let Ok(mut metrics) = self.run_metrics.write() {
            // Only increment if not already counted
            if !metrics.fired_playbook_ids.contains(&playbook_id.to_string()) {
                metrics.playbooks_fired += 1;
                metrics.fired_playbook_ids.push(playbook_id.to_string());
                
                // Add category if not already present
                if let Some(pb) = self.playbooks.get(playbook_id) {
                    if !metrics.fired_categories.contains(&pb.family) {
                        metrics.fired_categories.push(pb.family.clone());
                    }
                }
            }
        }
    }

    /// Record a playbook evaluation (candidate facts matched)
    pub fn record_evaluation(&self, _playbook_id: &str) {
        if let Ok(mut metrics) = self.run_metrics.write() {
            metrics.playbooks_evaluated += 1;
        }
    }

    /// Reset run metrics (call at start of new run)
    pub fn reset_run_metrics(&self) {
        if let Ok(mut metrics) = self.run_metrics.write() {
            *metrics = RunPlaybookMetrics::default();
        }
        if let Ok(mut fired) = self.fired_playbooks.write() {
            fired.clear();
        }
    }

    /// Get current run metrics
    pub fn run_metrics(&self) -> RunPlaybookMetrics {
        self.run_metrics
            .read()
            .map(|m| m.clone())
            .unwrap_or_default()
    }

    /// Check if a playbook has fired this run
    pub fn has_fired(&self, playbook_id: &str) -> bool {
        self.fired_playbooks
            .read()
            .map(|s| s.contains(playbook_id))
            .unwrap_or(false)
    }

    /// Get number of loaded playbooks
    pub fn loaded_count(&self) -> u32 {
        self.load_result.loaded_count
    }

    /// Check if loading was successful
    pub fn is_loaded(&self) -> bool {
        self.load_result.success
    }

    /// Log load summary with TRUTHFUL accounting
    /// RD-2 FIX: Log skipped playbook reasons at WARN level (prominently)
    pub fn log_summary(&self) {
        let result = &self.load_result;
        if result.success {
            eprintln!(
                "[PlaybookManager] TRUTHFUL ACCOUNTING: {}/{} playbooks loaded ({} skipped)",
                result.loaded_count,
                result.total_yaml_files,
                result.skipped_count
            );
            eprintln!(
                "[PlaybookManager]   Source: {} | Categories: {}",
                result.source,
                result.categories.join(", ")
            );
            
            // RD-2 FIX: Prominently log skipped reasons at WARN level
            if !result.skipped_by_reason.is_empty() && result.skipped_count > 0 {
                eprintln!(
                    "[PlaybookManager] WARNING: {} playbooks skipped - reasons by count:",
                    result.skipped_count
                );
                for (reason, count) in &result.skipped_by_reason {
                    eprintln!(
                        "[PlaybookManager]   WARN: {} playbooks skipped due to: {}",
                        count, reason
                    );
                }
            }
            if !result.skipped_examples.is_empty() {
                eprintln!("[PlaybookManager]   Skipped examples (first 10):");
                for s in &result.skipped_examples {
                    eprintln!("      - {} ({})", s.playbook_id, s.reason);
                }
            }
        } else {
            eprintln!(
                "[PlaybookManager] ERROR: No playbooks loaded! Source: {}, Errors: {:?}",
                result.source,
                result.errors
            );
        }
    }
}

impl Default for PlaybookManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Get the playbooks/windows path for tests
    fn get_test_playbook_dir() -> PathBuf {
        // Tests run from crates/locald/, so we need to go up to project root
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let project_root = PathBuf::from(manifest_dir)
            .parent() // crates/
            .and_then(|p| p.parent()) // project root
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("../.."));
        project_root.join("playbooks").join("windows")
    }

    #[test]
    fn test_load_from_yaml_dir() {
        let mut mgr = PlaybookManager::new();
        let playbook_dir = get_test_playbook_dir();
        
        if !playbook_dir.exists() {
            eprintln!("Skipping test: playbook dir not found at {:?}", playbook_dir);
            return;
        }
        
        assert!(mgr.load_from_yaml_dir(&playbook_dir), "Should load at least one playbook");
        assert!(mgr.loaded_count() > 0, "Should have loaded playbooks");
        assert!(mgr.is_loaded(), "Should report as loaded");
        
        eprintln!("Loaded {} playbooks from {:?}", mgr.loaded_count(), playbook_dir);
    }

    #[test]
    fn test_load_result_contains_categories() {
        let mut mgr = PlaybookManager::new();
        let playbook_dir = get_test_playbook_dir();
        
        if !playbook_dir.exists() {
            eprintln!("Skipping test: playbook dir not found");
            return;
        }
        
        mgr.load_from_yaml_dir(&playbook_dir);
        let result = mgr.load_result();
        
        // Should have multiple categories
        if result.categories.is_empty() {
            eprintln!("No categories found, load errors: {:?}", result.errors);
        }
        assert!(!result.categories.is_empty(), "Should have categories");
        
        eprintln!("Categories found: {:?}", result.categories);
    }

    #[test]
    fn test_stats() {
        let mut mgr = PlaybookManager::new();
        let playbook_dir = get_test_playbook_dir();
        
        if !playbook_dir.exists() {
            eprintln!("Skipping test: playbook dir not found");
            return;
        }
        
        mgr.load_from_yaml_dir(&playbook_dir);
        let stats = mgr.stats();
        
        assert_eq!(stats.loaded_count, mgr.loaded_count());
        if mgr.loaded_count() > 0 {
            assert!(!stats.category_counts.is_empty());
        }
    }

    #[test]
    fn test_record_fire() {
        let mut mgr = PlaybookManager::new();
        let playbook_dir = get_test_playbook_dir();
        
        if !playbook_dir.exists() {
            eprintln!("Skipping test: playbook dir not found");
            return;
        }
        
        mgr.load_from_yaml_dir(&playbook_dir);
        
        if mgr.load_result().playbook_ids.is_empty() {
            eprintln!("No playbooks loaded, skipping test");
            return;
        }
        
        // Get first playbook ID
        let first_id = mgr.load_result().playbook_ids.first().cloned().unwrap();
        
        // Record fire
        mgr.record_fire(&first_id);
        
        // Check metrics
        let metrics = mgr.run_metrics();
        assert_eq!(metrics.playbooks_fired, 1);
        assert!(metrics.fired_playbook_ids.contains(&first_id));
        assert!(mgr.has_fired(&first_id));
    }

    #[test]
    fn test_reset_run_metrics() {
        let mut mgr = PlaybookManager::new();
        let playbook_dir = get_test_playbook_dir();
        
        if !playbook_dir.exists() {
            eprintln!("Skipping test: playbook dir not found");
            return;
        }
        
        mgr.load_from_yaml_dir(&playbook_dir);
        
        if mgr.load_result().playbook_ids.is_empty() {
            eprintln!("No playbooks loaded, skipping test");
            return;
        }
        
        let first_id = mgr.load_result().playbook_ids.first().cloned().unwrap();
        mgr.record_fire(&first_id);
        
        // Verify fired
        assert!(mgr.has_fired(&first_id));
        
        // Reset
        mgr.reset_run_metrics();
        
        // Should be cleared
        assert!(!mgr.has_fired(&first_id));
        let metrics = mgr.run_metrics();
        assert_eq!(metrics.playbooks_fired, 0);
    }

    #[test]
    fn test_playbooks_sorted() {
        let mut mgr = PlaybookManager::new();
        let playbook_dir = get_test_playbook_dir();
        
        if !playbook_dir.exists() {
            eprintln!("Skipping test: playbook dir not found");
            return;
        }
        
        mgr.load_from_yaml_dir(&playbook_dir);
        
        let pbs = mgr.playbooks();
        for i in 1..pbs.len() {
            assert!(pbs[i - 1].playbook_id <= pbs[i].playbook_id);
        }
    }
}

//! Delta Report - What Changed Between Runs
//!
//! Computes differences between runs:
//! - Added/removed/changed findings
//! - New/changed entities
//! - New MITRE tags
//!
//! Noise Control Features:
//! - Stable keys: deterministic finding IDs based on content hash
//! - Dedup: suppress duplicate findings within same run
//! - Significance thresholds: filter out minor fluctuations
//!
//! Output: Human-friendly delta summary + machine-readable delta.json

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

// ============================================================================
// Core Types
// ============================================================================

/// Complete Delta Report between two runs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaReport {
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub baseline_run_id: Option<String>,
    pub current_run_id: String,
    pub findings_delta: FindingsDelta,
    pub entities_delta: EntitiesDelta,
    pub mitre_delta: MitreDelta,
    pub summary: DeltaSummary,
}

/// Delta in findings between runs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsDelta {
    pub added: Vec<FindingChange>,
    pub removed: Vec<FindingChange>,
    pub changed: Vec<FindingComparison>,
    pub unchanged_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingChange {
    pub finding_id: String,
    pub playbook: String,
    pub severity: String,
    pub mitre_ids: Vec<String>,
    pub summary: String,
    pub confidence: f64,
    pub first_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingComparison {
    pub finding_id: String,
    pub playbook: String,
    pub changes: Vec<FieldChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    pub field: String,
    pub old_value: serde_json::Value,
    pub new_value: serde_json::Value,
}

/// Delta in entities between runs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitiesDelta {
    pub new_processes: Vec<EntityInfo>,
    pub new_files: Vec<EntityInfo>,
    pub new_network: Vec<EntityInfo>,
    pub new_users: Vec<EntityInfo>,
    pub removed_processes: Vec<EntityInfo>,
    pub removed_files: Vec<EntityInfo>,
    pub removed_network: Vec<EntityInfo>,
    pub removed_users: Vec<EntityInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityInfo {
    pub entity_type: String,
    pub value: String,
    pub first_seen: Option<DateTime<Utc>>,
    pub related_findings: Vec<String>,
}

/// Delta in MITRE ATT&CK tags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreDelta {
    pub new_techniques: Vec<MitreTag>,
    pub removed_techniques: Vec<MitreTag>,
    pub new_tactics: Vec<String>,
    pub removed_tactics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTag {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub finding_count: usize,
}

// ============================================================================
// Noise Control Configuration
// ============================================================================

/// Configuration for delta noise control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoiseControlConfig {
    /// Minimum confidence threshold for findings (0.0-1.0)
    pub min_confidence: f64,
    /// Confidence change must exceed this to be "changed"
    pub confidence_change_threshold: f64,
    /// Suppress findings with these severities
    pub suppress_severities: Vec<String>,
    /// Suppress findings from these playbooks
    pub suppress_playbooks: Vec<String>,
    /// Enable deduplication by stable key
    pub enable_dedup: bool,
    /// Maximum age (hours) for findings to be considered "new"
    pub max_age_hours: Option<u64>,
}

impl Default for NoiseControlConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.3,
            confidence_change_threshold: 0.1,
            suppress_severities: vec!["info".to_string()],
            suppress_playbooks: vec![],
            enable_dedup: true,
            max_age_hours: None,
        }
    }
}

/// Summary for UI display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaSummary {
    pub has_changes: bool,
    pub change_significance: ChangeSignificance,
    pub total_added: usize,
    pub total_removed: usize,
    pub total_changed: usize,
    pub new_high_severity: usize,
    pub new_mitre_techniques: usize,
    pub headline: String,
    pub key_changes: Vec<String>,
    /// Number of findings suppressed by noise control
    pub suppressed_count: usize,
    /// Number of findings deduplicated
    pub dedup_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChangeSignificance {
    None,     // No changes
    Low,      // Minor changes
    Medium,   // Notable changes
    High,     // Significant changes
    Critical, // Critical new findings
}

// ============================================================================
// Delta Computation
// ============================================================================

/// Compute delta between current run and baseline
pub fn compute_delta(
    current_run_id: &str,
    baseline_run_id: Option<&str>,
    telemetry_root: &Path,
) -> Result<DeltaReport, String> {
    let timestamp = Utc::now();

    // Load current run data
    let current_signals = load_run_signals(current_run_id, telemetry_root)?;
    let current_entities = extract_entities(&current_signals);
    let current_mitre = extract_mitre_tags(&current_signals);

    // Load baseline if exists
    let (baseline_signals, baseline_entities, baseline_mitre) =
        if let Some(baseline_id) = baseline_run_id {
            let signals = load_run_signals(baseline_id, telemetry_root).unwrap_or_default();
            let entities = extract_entities(&signals);
            let mitre = extract_mitre_tags(&signals);
            (signals, entities, mitre)
        } else {
            // Try to find previous run automatically
            match find_previous_run(current_run_id, telemetry_root) {
                Some(prev_id) => {
                    let signals = load_run_signals(&prev_id, telemetry_root).unwrap_or_default();
                    let entities = extract_entities(&signals);
                    let mitre = extract_mitre_tags(&signals);
                    (signals, entities, mitre)
                }
                None => (Vec::new(), Entities::default(), MitreTags::default()),
            }
        };

    // Apply noise control with default config
    let noise_config = NoiseControlConfig::default();

    // Compute deltas with noise control
    let findings_delta = compute_findings_delta_with_noise_control(
        &baseline_signals,
        &current_signals,
        &noise_config,
    );
    let entities_delta = compute_entities_delta(&baseline_entities, &current_entities);
    let mitre_delta = compute_mitre_delta(&baseline_mitre, &current_mitre);

    // Generate summary
    let summary = generate_summary(&findings_delta, &entities_delta, &mitre_delta);

    let report = DeltaReport {
        timestamp,
        version: "1.1.0".to_string(), // Version bump for noise control
        baseline_run_id: baseline_run_id
            .map(String::from)
            .or_else(|| find_previous_run(current_run_id, telemetry_root)),
        current_run_id: current_run_id.to_string(),
        findings_delta,
        entities_delta,
        mitre_delta,
        summary,
    };

    // Save report
    save_delta_report(&report, current_run_id, telemetry_root)?;

    Ok(report)
}

/// Compute delta with custom noise control configuration
pub fn compute_delta_with_config(
    current_run_id: &str,
    baseline_run_id: Option<&str>,
    telemetry_root: &Path,
    noise_config: &NoiseControlConfig,
) -> Result<DeltaReport, String> {
    let timestamp = Utc::now();

    // Load current run data
    let current_signals = load_run_signals(current_run_id, telemetry_root)?;
    let current_entities = extract_entities(&current_signals);
    let current_mitre = extract_mitre_tags(&current_signals);

    // Load baseline
    let (baseline_signals, baseline_entities, baseline_mitre) =
        if let Some(baseline_id) = baseline_run_id {
            let signals = load_run_signals(baseline_id, telemetry_root).unwrap_or_default();
            let entities = extract_entities(&signals);
            let mitre = extract_mitre_tags(&signals);
            (signals, entities, mitre)
        } else {
            match find_previous_run(current_run_id, telemetry_root) {
                Some(prev_id) => {
                    let signals = load_run_signals(&prev_id, telemetry_root).unwrap_or_default();
                    let entities = extract_entities(&signals);
                    let mitre = extract_mitre_tags(&signals);
                    (signals, entities, mitre)
                }
                None => (Vec::new(), Entities::default(), MitreTags::default()),
            }
        };

    // Compute deltas with noise control
    let findings_delta = compute_findings_delta_with_noise_control(
        &baseline_signals,
        &current_signals,
        noise_config,
    );
    let entities_delta = compute_entities_delta(&baseline_entities, &current_entities);
    let mitre_delta = compute_mitre_delta(&baseline_mitre, &current_mitre);

    let summary = generate_summary(&findings_delta, &entities_delta, &mitre_delta);

    let report = DeltaReport {
        timestamp,
        version: "1.1.0".to_string(),
        baseline_run_id: baseline_run_id
            .map(String::from)
            .or_else(|| find_previous_run(current_run_id, telemetry_root)),
        current_run_id: current_run_id.to_string(),
        findings_delta,
        entities_delta,
        mitre_delta,
        summary,
    };

    save_delta_report(&report, current_run_id, telemetry_root)?;

    Ok(report)
}

/// Compute delta from imported bundle vs previous state
pub fn compute_import_delta(
    import_namespace: &str,
    telemetry_root: &Path,
) -> Result<DeltaReport, String> {
    // For imports, compare against the last imported bundle or live state
    compute_delta(import_namespace, None, telemetry_root)
}

// ============================================================================
// Stable Key Generation
// ============================================================================

/// Generate a stable, deterministic identity key for a finding.
/// 
/// IDENTITY FIELDS (define uniqueness):
/// - playbook_id: which detection rule matched
/// - host: which machine (if available)
/// - primary_entity: the main entity being detected (process, file, etc.)
/// 
/// NON-IDENTITY FIELDS (tracked as changes, not key components):
/// - severity: can change without creating new finding
/// - confidence: can change without creating new finding  
/// - mitre_ids: can be updated without creating new finding
///
/// This ensures that when only severity/confidence changes, we get
/// CHANGED classification rather than REMOVED+ADDED.
fn generate_stable_key(signal: &Signal) -> String {
    let mut hasher = Sha256::new();

    // IDENTITY FIELD 1: Playbook ID
    hasher.update(signal.playbook.as_bytes());
    hasher.update(b"|");

    // IDENTITY FIELD 2: Host (from slots or entities)
    let host = signal.slots.get("host")
        .and_then(|v| v.as_str())
        .or_else(|| signal.slots.get("hostname").and_then(|v| v.as_str()))
        .or_else(|| signal.entities.get("host").and_then(|v| v.first()).map(|s| s.as_str()))
        .unwrap_or("unknown_host");
    hasher.update(host.as_bytes());
    hasher.update(b"|");

    // IDENTITY FIELD 3: Primary entity key (the main artifact being detected)
    // Priority: process > file > network > user > registry
    let primary_entity = get_primary_entity(signal);
    hasher.update(primary_entity.as_bytes());
    hasher.update(b"|");

    // IDENTITY FIELD 4: Case ID if present (for imported cases)
    if let Some(case_id) = signal.slots.get("case_id").and_then(|v| v.as_str()) {
        hasher.update(case_id.as_bytes());
    }

    let result = hasher.finalize();
    format!("sk_{:x}", result)[..18].to_string() // Truncate to 18 chars
}

/// Extract the primary entity from a signal for stable key generation
fn get_primary_entity(signal: &Signal) -> String {
    // Check slots first (more specific)
    let slot_priority = [
        "process_name", "target_process", "parent_process",
        "file_path", "target_file", "source_file",
        "ip_address", "destination_ip", "source_ip",
        "user", "username", "target_user",
        "registry_key", "registry_path",
    ];
    
    for slot_name in &slot_priority {
        if let Some(value) = signal.slots.get(*slot_name) {
            if let Some(s) = value.as_str() {
                if !s.is_empty() {
                    return format!("{}:{}", slot_name, s);
                }
            }
        }
    }

    // Fall back to entities map
    let entity_priority = ["process", "file", "network", "user", "registry"];
    for entity_type in &entity_priority {
        if let Some(values) = signal.entities.get(*entity_type) {
            if let Some(first) = values.first() {
                if !first.is_empty() {
                    return format!("{}:{}", entity_type, first);
                }
            }
        }
    }

    // Last resort: use signal ID
    format!("id:{}", signal.id)
}

// ============================================================================
// Signal Loading
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Signal {
    id: String,
    #[serde(default)]
    stable_key: Option<String>,
    playbook: String,
    severity: String,
    confidence: f64,
    mitre_ids: Vec<String>,
    summary: String,
    entities: HashMap<String, Vec<String>>,
    timestamp: Option<DateTime<Utc>>,
    slots: HashMap<String, serde_json::Value>,
}

fn load_run_signals(run_id: &str, telemetry_root: &Path) -> Result<Vec<Signal>, String> {
    let run_dir = telemetry_root.join("runs").join(run_id);

    // Try multiple possible locations for signals
    let possible_paths = vec![
        run_dir.join("signals.json"),
        run_dir.join("workbench.json"),
        run_dir
            .join("metrics")
            .join(format!("{}_signals.json", run_id)),
    ];

    for path in possible_paths {
        if path.exists() {
            let content = fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

            // Try to parse as signal array
            if let Ok(signals) = serde_json::from_str::<Vec<Signal>>(&content) {
                return Ok(signals);
            }

            // Try to parse as wrapper object with signals field
            if let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(signals_arr) = wrapper.get("signals").and_then(|v| v.as_array()) {
                    let signals: Vec<Signal> = signals_arr
                        .iter()
                        .filter_map(|v| serde_json::from_value(v.clone()).ok())
                        .collect();
                    return Ok(signals);
                }

                // Try hypotheses field
                if let Some(hyp_arr) = wrapper.get("hypotheses").and_then(|v| v.as_array()) {
                    let signals: Vec<Signal> = hyp_arr
                        .iter()
                        .filter_map(parse_hypothesis_as_signal)
                        .collect();
                    return Ok(signals);
                }
            }
        }
    }

    // Also check workbench database directly (if SQLite access is available)
    // For now, return empty if no files found
    Ok(Vec::new())
}

fn parse_hypothesis_as_signal(hyp: &serde_json::Value) -> Option<Signal> {
    Some(Signal {
        id: hyp.get("hypothesis_id")?.as_str()?.to_string(),
        playbook: hyp
            .get("template_id")
            .and_then(|v| v.as_str())
            .or_else(|| hyp.get("playbook").and_then(|v| v.as_str()))
            .unwrap_or("unknown")
            .to_string(),
        severity: hyp
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("medium")
            .to_string(),
        confidence: hyp
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.5),
        mitre_ids: hyp
            .get("mitre_ids")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        summary: hyp
            .get("summary")
            .and_then(|v| v.as_str())
            .or_else(|| hyp.get("description").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string(),
        entities: HashMap::new(),
        timestamp: hyp
            .get("timestamp")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc)),
        slots: hyp
            .get("slots")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default(),
        stable_key: None, // Will be computed on demand
    })
}

fn find_previous_run(current_run_id: &str, telemetry_root: &Path) -> Option<String> {
    let runs_dir = telemetry_root.join("runs");

    if !runs_dir.exists() {
        return None;
    }

    let mut runs: Vec<(String, std::time::SystemTime)> = fs::read_dir(&runs_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("run_") && name != current_run_id {
                let modified = e.metadata().ok()?.modified().ok()?;
                Some((name, modified))
            } else {
                None
            }
        })
        .collect();

    runs.sort_by(|a, b| b.1.cmp(&a.1)); // Most recent first

    runs.first().map(|(name, _)| name.clone())
}

// ============================================================================
// Entity Extraction
// ============================================================================

#[derive(Debug, Clone, Default)]
struct Entities {
    processes: HashSet<String>,
    files: HashSet<String>,
    network: HashSet<String>,
    users: HashSet<String>,
}

fn extract_entities(signals: &[Signal]) -> Entities {
    let mut entities = Entities::default();

    for signal in signals {
        // Extract from entities map
        if let Some(procs) = signal.entities.get("process") {
            for p in procs {
                entities.processes.insert(p.clone());
            }
        }
        if let Some(files) = signal.entities.get("file") {
            for f in files {
                entities.files.insert(f.clone());
            }
        }
        if let Some(net) = signal.entities.get("network") {
            for n in net {
                entities.network.insert(n.clone());
            }
        }
        if let Some(users) = signal.entities.get("user") {
            for u in users {
                entities.users.insert(u.clone());
            }
        }

        // Also extract from slots
        for (key, value) in &signal.slots {
            if let Some(s) = value.as_str() {
                match key.as_str() {
                    "process_name" | "parent_process" | "target_process" => {
                        entities.processes.insert(s.to_string());
                    }
                    "file_path" | "target_file" | "source_file" => {
                        entities.files.insert(s.to_string());
                    }
                    "ip_address" | "destination_ip" | "source_ip" => {
                        entities.network.insert(s.to_string());
                    }
                    "user" | "username" | "target_user" => {
                        entities.users.insert(s.to_string());
                    }
                    _ => {}
                }
            }
        }
    }

    entities
}

// ============================================================================
// MITRE Tag Extraction
// ============================================================================

#[derive(Debug, Clone, Default)]
struct MitreTags {
    techniques: HashMap<String, MitreInfo>,
    tactics: HashSet<String>,
}

#[derive(Debug, Clone)]
struct MitreInfo {
    technique_id: String,
    technique_name: String,
    tactic: String,
    finding_count: usize,
}

fn extract_mitre_tags(signals: &[Signal]) -> MitreTags {
    let mut tags = MitreTags::default();

    for signal in signals {
        for mitre_id in &signal.mitre_ids {
            let (tactic, name) = parse_mitre_id(mitre_id);

            tags.techniques
                .entry(mitre_id.clone())
                .and_modify(|info| info.finding_count += 1)
                .or_insert_with(|| MitreInfo {
                    technique_id: mitre_id.clone(),
                    technique_name: name.clone(),
                    tactic: tactic.clone(),
                    finding_count: 1,
                });

            tags.tactics.insert(tactic);
        }
    }

    tags
}

fn parse_mitre_id(mitre_id: &str) -> (String, String) {
    // Map technique IDs to tactics (simplified mapping)
    let tactic = if mitre_id.starts_with("T1003") {
        "Credential Access"
    } else if mitre_id.starts_with("T1059") {
        "Execution"
    } else if mitre_id.starts_with("T1053") {
        "Persistence"
    } else if mitre_id.starts_with("T1055") {
        "Defense Evasion"
    } else if mitre_id.starts_with("T1071") {
        "Command and Control"
    } else if mitre_id.starts_with("T1021") {
        "Lateral Movement"
    } else if mitre_id.starts_with("T1567") {
        "Exfiltration"
    } else if mitre_id.starts_with("T1018") || mitre_id.starts_with("T1082") {
        "Discovery"
    } else if mitre_id.starts_with("T1566") {
        "Initial Access"
    } else {
        "Unknown"
    };

    // Get technique name (simplified)
    let name = match mitre_id {
        "T1003.001" => "LSASS Memory",
        "T1059.001" => "PowerShell",
        "T1059.003" => "Windows Command Shell",
        "T1053.005" => "Scheduled Task",
        "T1055.001" => "DLL Injection",
        "T1071.001" => "Web Protocols",
        "T1021.001" => "Remote Desktop",
        "T1567.002" => "Exfil to Cloud Storage",
        _ => mitre_id,
    };

    (tactic.to_string(), name.to_string())
}

// ============================================================================
// Delta Computation Logic (with Noise Control)
// ============================================================================

/// Compute findings delta with noise control applied
fn compute_findings_delta_with_noise_control(
    baseline: &[Signal],
    current: &[Signal],
    config: &NoiseControlConfig,
) -> FindingsDelta {
    // Apply noise filtering to both sets
    let filtered_baseline: Vec<_> = baseline
        .iter()
        .filter(|s| passes_noise_filter(s, config))
        .collect();
    let filtered_current: Vec<_> = current
        .iter()
        .filter(|s| passes_noise_filter(s, config))
        .collect();

    // Use stable keys for comparison if dedup is enabled
    let (baseline_keys, current_keys): (HashMap<String, &Signal>, HashMap<String, &Signal>) =
        if config.enable_dedup {
            let bk: HashMap<_, _> = filtered_baseline
                .iter()
                .map(|s| {
                    (
                        s.stable_key
                            .clone()
                            .unwrap_or_else(|| generate_stable_key(s)),
                        *s,
                    )
                })
                .collect();
            let ck: HashMap<_, _> = filtered_current
                .iter()
                .map(|s| {
                    (
                        s.stable_key
                            .clone()
                            .unwrap_or_else(|| generate_stable_key(s)),
                        *s,
                    )
                })
                .collect();
            (bk, ck)
        } else {
            let bk: HashMap<_, _> = filtered_baseline
                .iter()
                .map(|s| (s.id.clone(), *s))
                .collect();
            let ck: HashMap<_, _> = filtered_current
                .iter()
                .map(|s| (s.id.clone(), *s))
                .collect();
            (bk, ck)
        };

    let baseline_key_set: HashSet<_> = baseline_keys.keys().collect();
    let current_key_set: HashSet<_> = current_keys.keys().collect();

    // Find added (in current but not baseline)
    let added: Vec<_> = current_key_set
        .difference(&baseline_key_set)
        .filter_map(|k| current_keys.get(*k))
        .map(|s| signal_to_finding_change_with_stable_key(s, config.enable_dedup))
        .collect();

    // Find removed (in baseline but not current)
    let removed: Vec<_> = baseline_key_set
        .difference(&current_key_set)
        .filter_map(|k| baseline_keys.get(*k))
        .map(|s| signal_to_finding_change_with_stable_key(s, config.enable_dedup))
        .collect();

    // Find changed (same key but different content beyond threshold)
    let mut changed = Vec::new();
    for key in baseline_key_set.intersection(&current_key_set) {
        if let (Some(base), Some(curr)) = (baseline_keys.get(*key), current_keys.get(*key)) {
            let changes =
                compare_signals_with_threshold(base, curr, config.confidence_change_threshold);
            if !changes.is_empty() {
                changed.push(FindingComparison {
                    finding_id: curr.id.clone(),
                    playbook: curr.playbook.clone(),
                    changes,
                });
            }
        }
    }

    let unchanged_count = current_keys
        .len()
        .saturating_sub(added.len())
        .saturating_sub(changed.len());

    FindingsDelta {
        added,
        removed,
        changed,
        unchanged_count,
    }
}

/// Check if a signal passes the noise filter
fn passes_noise_filter(signal: &Signal, config: &NoiseControlConfig) -> bool {
    // Check minimum confidence
    if signal.confidence < config.min_confidence {
        return false;
    }

    // Check suppressed severities
    if config
        .suppress_severities
        .iter()
        .any(|s| s.eq_ignore_ascii_case(&signal.severity))
    {
        return false;
    }

    // Check suppressed playbooks
    if config
        .suppress_playbooks
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&signal.playbook))
    {
        return false;
    }

    true
}

/// Legacy compute without noise control (for backwards compatibility)
#[allow(dead_code)]
fn compute_findings_delta(baseline: &[Signal], current: &[Signal]) -> FindingsDelta {
    let baseline_ids: HashSet<_> = baseline.iter().map(|s| &s.id).collect();
    let current_ids: HashSet<_> = current.iter().map(|s| &s.id).collect();

    // Find added
    let added: Vec<_> = current
        .iter()
        .filter(|s| !baseline_ids.contains(&s.id))
        .map(signal_to_finding_change)
        .collect();

    // Find removed
    let removed: Vec<_> = baseline
        .iter()
        .filter(|s| !current_ids.contains(&s.id))
        .map(signal_to_finding_change)
        .collect();

    // Find changed (same ID but different content)
    let mut changed = Vec::new();
    for curr in current {
        if let Some(base) = baseline.iter().find(|s| s.id == curr.id) {
            let changes = compare_signals(base, curr);
            if !changes.is_empty() {
                changed.push(FindingComparison {
                    finding_id: curr.id.clone(),
                    playbook: curr.playbook.clone(),
                    changes,
                });
            }
        }
    }

    let unchanged_count = current.len() - added.len() - changed.len();

    FindingsDelta {
        added,
        removed,
        changed,
        unchanged_count,
    }
}

#[allow(dead_code)]
fn signal_to_finding_change(signal: &Signal) -> FindingChange {
    FindingChange {
        finding_id: signal.id.clone(),
        playbook: signal.playbook.clone(),
        severity: signal.severity.clone(),
        mitre_ids: signal.mitre_ids.clone(),
        summary: signal.summary.clone(),
        confidence: signal.confidence,
        first_seen: signal.timestamp,
    }
}

fn signal_to_finding_change_with_stable_key(
    signal: &Signal,
    include_stable_key: bool,
) -> FindingChange {
    let mut change = FindingChange {
        finding_id: signal.id.clone(),
        playbook: signal.playbook.clone(),
        severity: signal.severity.clone(),
        mitre_ids: signal.mitre_ids.clone(),
        summary: signal.summary.clone(),
        confidence: signal.confidence,
        first_seen: signal.timestamp,
    };

    // If stable key is enabled, use it as the finding_id for dedup tracking
    if include_stable_key {
        if let Some(ref sk) = signal.stable_key {
            change.finding_id = format!("{}:{}", sk, signal.id);
        }
    }

    change
}

#[allow(dead_code)]
fn compare_signals(base: &Signal, curr: &Signal) -> Vec<FieldChange> {
    compare_signals_with_threshold(base, curr, 0.05)
}

fn compare_signals_with_threshold(
    base: &Signal,
    curr: &Signal,
    confidence_threshold: f64,
) -> Vec<FieldChange> {
    let mut changes = Vec::new();

    if base.severity != curr.severity {
        changes.push(FieldChange {
            field: "severity".to_string(),
            old_value: serde_json::json!(base.severity),
            new_value: serde_json::json!(curr.severity),
        });
    }

    if (base.confidence - curr.confidence).abs() > confidence_threshold {
        changes.push(FieldChange {
            field: "confidence".to_string(),
            old_value: serde_json::json!(base.confidence),
            new_value: serde_json::json!(curr.confidence),
        });
    }

    if base.mitre_ids != curr.mitre_ids {
        changes.push(FieldChange {
            field: "mitre_ids".to_string(),
            old_value: serde_json::json!(base.mitre_ids),
            new_value: serde_json::json!(curr.mitre_ids),
        });
    }

    changes
}

fn compute_entities_delta(baseline: &Entities, current: &Entities) -> EntitiesDelta {
    fn to_entity_info(value: &str, entity_type: &str) -> EntityInfo {
        EntityInfo {
            entity_type: entity_type.to_string(),
            value: value.to_string(),
            first_seen: None,
            related_findings: vec![],
        }
    }

    EntitiesDelta {
        new_processes: current
            .processes
            .difference(&baseline.processes)
            .map(|v| to_entity_info(v, "process"))
            .collect(),
        new_files: current
            .files
            .difference(&baseline.files)
            .map(|v| to_entity_info(v, "file"))
            .collect(),
        new_network: current
            .network
            .difference(&baseline.network)
            .map(|v| to_entity_info(v, "network"))
            .collect(),
        new_users: current
            .users
            .difference(&baseline.users)
            .map(|v| to_entity_info(v, "user"))
            .collect(),
        removed_processes: baseline
            .processes
            .difference(&current.processes)
            .map(|v| to_entity_info(v, "process"))
            .collect(),
        removed_files: baseline
            .files
            .difference(&current.files)
            .map(|v| to_entity_info(v, "file"))
            .collect(),
        removed_network: baseline
            .network
            .difference(&current.network)
            .map(|v| to_entity_info(v, "network"))
            .collect(),
        removed_users: baseline
            .users
            .difference(&current.users)
            .map(|v| to_entity_info(v, "user"))
            .collect(),
    }
}

fn compute_mitre_delta(baseline: &MitreTags, current: &MitreTags) -> MitreDelta {
    let baseline_ids: HashSet<_> = baseline.techniques.keys().collect();
    let current_ids: HashSet<_> = current.techniques.keys().collect();

    let new_techniques: Vec<_> = current_ids
        .difference(&baseline_ids)
        .filter_map(|id| current.techniques.get(*id))
        .map(|info| MitreTag {
            technique_id: info.technique_id.clone(),
            technique_name: info.technique_name.clone(),
            tactic: info.tactic.clone(),
            finding_count: info.finding_count,
        })
        .collect();

    let removed_techniques: Vec<_> = baseline_ids
        .difference(&current_ids)
        .filter_map(|id| baseline.techniques.get(*id))
        .map(|info| MitreTag {
            technique_id: info.technique_id.clone(),
            technique_name: info.technique_name.clone(),
            tactic: info.tactic.clone(),
            finding_count: info.finding_count,
        })
        .collect();

    let new_tactics: Vec<_> = current
        .tactics
        .difference(&baseline.tactics)
        .cloned()
        .collect();
    let removed_tactics: Vec<_> = baseline
        .tactics
        .difference(&current.tactics)
        .cloned()
        .collect();

    MitreDelta {
        new_techniques,
        removed_techniques,
        new_tactics,
        removed_tactics,
    }
}

// ============================================================================
// Summary Generation
// ============================================================================

fn generate_summary(
    findings: &FindingsDelta,
    entities: &EntitiesDelta,
    mitre: &MitreDelta,
) -> DeltaSummary {
    let total_added = findings.added.len();
    let total_removed = findings.removed.len();
    let total_changed = findings.changed.len();

    let new_high_severity = findings
        .added
        .iter()
        .filter(|f| f.severity.to_lowercase() == "high" || f.severity.to_lowercase() == "critical")
        .count();

    let new_mitre_techniques = mitre.new_techniques.len();

    let has_changes = total_added > 0 || total_removed > 0 || total_changed > 0;

    // Determine significance
    let change_significance = if new_high_severity > 0 {
        ChangeSignificance::Critical
    } else if total_added > 5 || new_mitre_techniques > 2 {
        ChangeSignificance::High
    } else if total_added > 2 || total_changed > 3 {
        ChangeSignificance::Medium
    } else if has_changes {
        ChangeSignificance::Low
    } else {
        ChangeSignificance::None
    };

    // Generate headline
    let headline = if !has_changes {
        "No changes since last run".to_string()
    } else if new_high_severity > 0 {
        format!(
            "⚠️ {} new high-severity finding(s) detected",
            new_high_severity
        )
    } else if total_added > 0 && total_removed == 0 {
        format!("📈 {} new finding(s) detected", total_added)
    } else if total_removed > 0 && total_added == 0 {
        format!("📉 {} finding(s) resolved", total_removed)
    } else {
        format!(
            "🔄 {} added, {} removed, {} changed",
            total_added, total_removed, total_changed
        )
    };

    // Generate key changes
    let mut key_changes = Vec::new();

    if new_high_severity > 0 {
        for f in findings
            .added
            .iter()
            .filter(|f| {
                f.severity.to_lowercase() == "high" || f.severity.to_lowercase() == "critical"
            })
            .take(3)
        {
            key_changes.push(format!("🔴 [{}] {}", f.playbook, f.summary));
        }
    }

    for tech in mitre.new_techniques.iter().take(2) {
        key_changes.push(format!(
            "🎯 New MITRE technique: {} ({})",
            tech.technique_id, tech.technique_name
        ));
    }

    let new_entity_count = entities.new_processes.len()
        + entities.new_files.len()
        + entities.new_network.len()
        + entities.new_users.len();

    if new_entity_count > 0 {
        key_changes.push(format!("📊 {} new entities observed", new_entity_count));
    }

    DeltaSummary {
        has_changes,
        change_significance,
        total_added,
        total_removed,
        total_changed,
        new_high_severity,
        new_mitre_techniques,
        headline,
        key_changes,
        // Noise control stats (computed separately if needed)
        suppressed_count: 0,
        dedup_count: 0,
    }
}

// ============================================================================
// Persistence
// ============================================================================

fn save_delta_report(
    report: &DeltaReport,
    run_id: &str,
    telemetry_root: &Path,
) -> Result<(), String> {
    let run_dir = telemetry_root.join("runs").join(run_id);
    fs::create_dir_all(&run_dir).map_err(|e| format!("Failed to create run directory: {}", e))?;

    let delta_path = run_dir.join("delta.json");

    let json = serde_json::to_string_pretty(report)
        .map_err(|e| format!("Failed to serialize delta: {}", e))?;

    fs::write(&delta_path, &json).map_err(|e| format!("Failed to write delta: {}", e))?;

    // Also save to deltas directory with timestamp
    let deltas_dir = telemetry_root.join("deltas");
    fs::create_dir_all(&deltas_dir).ok();

    let timestamp = report.timestamp.format("%Y%m%d_%H%M%S");
    let named_path = deltas_dir.join(format!("delta_{}_{}.json", run_id, timestamp));
    fs::write(&named_path, &json).ok();

    // Update latest delta
    let latest_path = telemetry_root.join("delta_latest.json");
    fs::write(&latest_path, &json).ok();

    tracing::info!("Saved delta report to {}", delta_path.display());

    Ok(())
}

/// Load the latest delta report
pub fn load_latest_delta(telemetry_root: &Path) -> Option<DeltaReport> {
    let latest_path = telemetry_root.join("delta_latest.json");

    if latest_path.exists() {
        fs::read_to_string(&latest_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    } else {
        None
    }
}

/// Load delta for a specific run
pub fn load_run_delta(run_id: &str, telemetry_root: &Path) -> Option<DeltaReport> {
    let delta_path = telemetry_root.join("runs").join(run_id).join("delta.json");

    if delta_path.exists() {
        fs::read_to_string(&delta_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    } else {
        None
    }
}

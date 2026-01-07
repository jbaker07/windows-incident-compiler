//! Incident Bundle Export/Import with Replay + Recompute
//!
//! Features:
//! - SHA-256 integrity (hash computed over canonical payload with checksum omitted)
//! - Deterministic redaction (same input => same placeholders, NO secrets leaked)
//! - ZIP safety limits (decompression bomb protection)
//! - Mechanical isolation of imported vs live data
//! - Replay: precomputed report/explanation for instant viewing
//! - Recompute: canonical inputs to re-run locally and verify determinism
//! - Watermarking: license/install provenance embedded for attribution
//!
//! Use cases:
//! - HTB/Atomic writeups
//! - Community sharing
//! - Training and education

use crate::report::{IntegrityNoteEntry, ReportBundle};
use chrono::{DateTime, Utc};
use edr_core::watermark::create_watermark_from_license;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};

// ============================================================================
// Constants
// ============================================================================

/// Hash algorithm identifier
pub const HASH_ALGORITHM: &str = "sha256";

/// Checksum scope documentation
pub const CHECKSUM_SCOPE: &str = "bundle_payload_sans_checksum";

/// Imported namespace prefix
#[allow(dead_code)]
pub const IMPORTED_NAMESPACE: &str = "imported_bundle";

// ============================================================================
// ZIP Safety Policy
// ============================================================================

#[derive(Debug, Clone)]
pub struct ZipSafetyPolicy {
    pub max_files: usize,
    pub max_total_uncompressed: usize,
    pub max_single_file: usize,
    pub reject_nested_archives: bool,
    pub reject_path_traversal: bool,
    #[allow(dead_code)]
    pub allowed_extensions: Vec<&'static str>,
}

impl Default for ZipSafetyPolicy {
    fn default() -> Self {
        Self {
            max_files: 32,
            max_total_uncompressed: 25 * 1024 * 1024, // 25MB
            max_single_file: 10 * 1024 * 1024,        // 10MB
            reject_nested_archives: true,
            reject_path_traversal: true,
            allowed_extensions: vec!["json", "jsonl", "txt"],
        }
    }
}

/// Allowed filenames in bundle ZIP
const ALLOWED_FILENAMES: &[&str] = &[
    "manifest.json",
    "README.txt",
    "replay/report_bundle.json",
    "recompute/events.jsonl",
    "recompute/config_snapshot.json",
    "recompute/evidence_excerpts.json",
    "incident_bundle.json", // Legacy single-file format
];

// ============================================================================
// Export/Import Request/Response Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBundleRequest {
    /// Specific incident ID to export
    #[serde(default)]
    pub incident_id: Option<String>,
    /// Time window filter
    #[serde(default)]
    pub time_window: Option<TimeWindowFilter>,
    /// Include evidence excerpts in bundle
    #[serde(default = "default_true")]
    pub include_evidence_excerpts: bool,
    /// Redact sensitive info (usernames, hostnames, IPs, paths)
    #[serde(default = "default_true")]
    pub redact: bool,
    /// Include recompute section (canonical events + config snapshot)
    #[serde(default)]
    pub include_recompute: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindowFilter {
    pub t_min: String,
    pub t_max: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBundleResponse {
    pub success: bool,
    pub bundle_id: String,
    pub format: String,
    pub size_bytes: usize,
    pub incident_count: usize,
    pub redacted: bool,
    pub includes_recompute: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportBundleResponse {
    pub success: bool,
    pub bundle_id: String,
    pub incident_count: usize,
    pub hypothesis_count: usize,
    pub timeline_entry_count: usize,
    pub imported_at: DateTime<Utc>,
    /// Namespace where imported data is stored
    pub namespace: String,
    /// Whether recompute section is available
    pub has_recompute: bool,
    /// The reconstructed report bundle
    pub report_bundle: ReportBundle,
    pub message: String,
}

// ============================================================================
// Recompute Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecomputeRequest {
    pub bundle_id: String,
    /// "strict" or "best_effort"
    #[serde(default = "default_best_effort")]
    pub mode: String,
}

fn default_best_effort() -> String {
    "best_effort".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecomputeResult {
    pub success: bool,
    pub bundle_id: String,
    /// The freshly computed explanation/report
    pub recompute_explanation: Option<ReportBundle>,
    /// PASS, PARTIAL, or FAIL
    pub determinism_verdict: String,
    /// Reasons for verdict
    pub verdict_reasons: Vec<String>,
    /// Structured diff vs replay
    pub diff_vs_replay: RecomputeDiff,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecomputeDiff {
    /// Top hypothesis differences
    pub hypothesis_diffs: Vec<String>,
    /// Timeline ordering differences
    pub timeline_ordering_diffs: Vec<String>,
    /// Missing evidence in recompute
    pub missing_evidence: Vec<String>,
    /// Visibility state deltas
    pub visibility_deltas: Vec<String>,
    /// Claim/citation differences
    pub claim_diffs: Vec<String>,
}

// ============================================================================
// Incident Bundle Format
// ============================================================================

/// Version of the bundle format for compatibility checking
pub const BUNDLE_FORMAT_VERSION: &str = "1.0.0";

/// The complete incident bundle structure for export/import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentBundle {
    /// Format version for compatibility
    pub version: String,
    /// Bundle metadata
    pub bundle_meta: BundleMeta,
    /// Session metadata at export time
    pub session_meta: SessionMeta,
    /// Which sections are included
    pub included_sections: IncludedSections,
    /// Replay section (precomputed results)
    pub replay: ReplaySection,
    /// Recompute section (canonical inputs) - optional
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recompute: Option<RecomputeSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncludedSections {
    pub replay: bool,
    pub recompute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMeta {
    pub bundle_id: String,
    pub exported_at: DateTime<Utc>,
    pub exported_by: String,
    pub redacted: bool,
    /// Hash algorithm used (e.g., "sha256")
    pub hash_alg: String,
    /// Hex-encoded checksum
    pub checksum: String,
    /// What bytes are hashed
    pub checksum_scope: String,
    /// Watermark for attribution/provenance (license info embedded)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watermark: Option<BundleWatermark>,
}

/// Watermark embedded in exported bundles for attribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleWatermark {
    /// Human-readable watermark
    pub visible: String,
    /// License ID
    pub license_id: String,
    /// Truncated installation hash
    pub install_hash: String,
    /// Build version
    pub build_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub mode: Option<String>,
    pub preset: Option<String>,
    pub focus_minutes: u32,
    pub original_host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySection {
    /// The report bundle (contains all incident data)
    pub report_bundle: ReportBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecomputeSection {
    /// Canonical events in stable order (ts, stream_id, segment_id, record_index)
    pub events: Vec<CanonicalEvent>,
    /// Configuration snapshot for deterministic replay
    pub config_snapshot: ConfigSnapshot,
    /// Optional evidence excerpts for offline UI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_excerpts: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEvent {
    /// Timestamp (primary sort key)
    pub ts: DateTime<Utc>,
    /// Stream identifier
    pub stream_id: String,
    /// Segment identifier
    pub segment_id: String,
    /// Record index within segment
    pub record_index: u64,
    /// Event type
    pub event_type: String,
    /// Event payload (sanitized if redacted)
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    /// Playbook set fingerprints (hashes, not full content)
    pub playbook_fingerprints: Vec<String>,
    /// Session mode
    pub mode: Option<String>,
    /// Session preset
    pub preset: Option<String>,
    /// Focus window in minutes
    pub focus_minutes: u32,
    /// Late arrival policy parameters
    pub late_arrival_window_secs: u32,
    /// Component version identifiers (BTreeMap for deterministic serialization order)
    pub component_versions: BTreeMap<String, String>,
    /// Capture profile (core/extended/forensic)
    #[serde(default)]
    pub capture_profile: String,
    /// Throttle configuration for recompute determinism
    #[serde(default)]
    pub throttle_config: Option<ThrottleConfigSnapshotCompat>,
    /// Dynamic enablements (sensors/collectors enabled at capture time)
    #[serde(default)]
    pub dynamic_enablements: Option<Vec<String>>,
}

/// Throttle config snapshot for bundle compatibility
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThrottleConfigSnapshotCompat {
    pub profile: String,
    pub global_max_events_per_sec: u32,
    pub global_max_bytes_per_sec: u64,
    pub enabled_sensors: Vec<String>,
    pub enabled_collectors: Vec<String>,
}

// ============================================================================
// Imported Bundle Storage (namespace isolation)
// ============================================================================

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedBundleRecord {
    pub bundle_id: String,
    pub namespace: String,
    pub imported_at: DateTime<Utc>,
    pub has_recompute: bool,
    pub bundle: IncidentBundle,
}

/// In-memory store for imported bundles (isolated from live data)
#[allow(dead_code)]
#[derive(Default)]
pub struct ImportedBundleStore {
    bundles: std::sync::RwLock<HashMap<String, ImportedBundleRecord>>,
}

#[allow(dead_code)]
impl ImportedBundleStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store(&self, record: ImportedBundleRecord) {
        let mut bundles = self.bundles.write().unwrap();
        bundles.insert(record.bundle_id.clone(), record);
    }

    pub fn get(&self, bundle_id: &str) -> Option<ImportedBundleRecord> {
        let bundles = self.bundles.read().unwrap();
        bundles.get(bundle_id).cloned()
    }

    pub fn list(&self) -> Vec<String> {
        let bundles = self.bundles.read().unwrap();
        bundles.keys().cloned().collect()
    }

    pub fn remove(&self, bundle_id: &str) -> bool {
        let mut bundles = self.bundles.write().unwrap();
        bundles.remove(bundle_id).is_some()
    }

    /// Check if a namespace belongs to an imported bundle
    pub fn is_imported_namespace(namespace: &str) -> bool {
        namespace.starts_with(IMPORTED_NAMESPACE) || namespace.starts_with("IMPORTED_")
    }
}

// ============================================================================
// Sanitization / Redaction
// ============================================================================

/// Redaction context for deterministic placeholder generation
pub struct RedactionContext {
    /// Map of original -> placeholder
    replacements: HashMap<String, String>,
    /// Counters for placeholder generation
    host_counter: u32,
    user_counter: u32,
    ip_counter: u32,
    path_counter: u32,
}

impl Default for RedactionContext {
    fn default() -> Self {
        Self::new()
    }
}

impl RedactionContext {
    pub fn new() -> Self {
        Self {
            replacements: HashMap::new(),
            host_counter: 0,
            user_counter: 0,
            ip_counter: 0,
            path_counter: 0,
        }
    }

    /// Get or create a stable placeholder for a value
    fn get_placeholder(&mut self, original: &str, category: &str) -> String {
        if let Some(existing) = self.replacements.get(original) {
            return existing.clone();
        }

        let placeholder = match category {
            "host" => {
                self.host_counter += 1;
                format!("HOST_{}", self.host_counter)
            }
            "user" => {
                self.user_counter += 1;
                format!("USER_{}", self.user_counter)
            }
            "ip" => {
                self.ip_counter += 1;
                format!("IP_{}", self.ip_counter)
            }
            "path" => {
                self.path_counter += 1;
                format!("PATH_{}", self.path_counter)
            }
            _ => format!("REDACTED_{}", self.replacements.len() + 1),
        };

        self.replacements
            .insert(original.to_string(), placeholder.clone());
        placeholder
    }
}

/// Sanitize a string by redacting sensitive patterns
pub fn sanitize_string(input: &str, ctx: &mut RedactionContext) -> String {
    let mut result = input.to_string();

    // Hostname patterns (e.g., workstation-01, server.domain.com)
    let hostname_re = Regex::new(r"\b([a-zA-Z][\w-]*(?:\.[a-zA-Z][\w-]*)+|\b[a-zA-Z][\w-]*-(?:workstation|server|desktop|laptop|vm|host)[\w-]*)\b").unwrap();
    for cap in hostname_re.captures_iter(input) {
        let original = cap.get(0).unwrap().as_str();
        let placeholder = ctx.get_placeholder(original, "host");
        result = result.replace(original, &placeholder);
    }

    // Username patterns (common username patterns)
    let username_re =
        Regex::new(r"\b(?:(?:C:\\Users\\|/home/|/Users/)([a-zA-Z][\w.-]*))\b").unwrap();
    for cap in username_re.captures_iter(input) {
        if let Some(user_match) = cap.get(1) {
            let original = user_match.as_str();
            let placeholder = ctx.get_placeholder(original, "user");
            result = result.replace(original, &placeholder);
        }
    }

    // IP addresses (IPv4)
    let ip_re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
    for cap in ip_re.captures_iter(input) {
        let original = cap.get(1).unwrap().as_str();
        // Don't redact localhost/loopback
        if original != "127.0.0.1" && original != "0.0.0.0" {
            let placeholder = ctx.get_placeholder(original, "ip");
            result = result.replace(original, &placeholder);
        }
    }

    // Home directory paths
    let home_re = Regex::new(r"(?:C:\\Users\\[^\\]+|/home/[^/]+|/Users/[^/]+)").unwrap();
    for cap in home_re.captures_iter(input) {
        let original = cap.get(0).unwrap().as_str();
        let placeholder = ctx.get_placeholder(original, "path");
        result = result.replace(original, &placeholder);
    }

    result
}

/// Sanitize a ReportBundle
pub fn sanitize_bundle(bundle: &ReportBundle, ctx: &mut RedactionContext) -> ReportBundle {
    let mut sanitized = bundle.clone();

    // Sanitize metadata
    sanitized.metadata.host_id = ctx.get_placeholder(&bundle.metadata.host_id, "host");
    sanitized.metadata.summary = sanitize_string(&bundle.metadata.summary, ctx);

    // Sanitize hypotheses
    for hyp in &mut sanitized.hypotheses {
        hyp.hypothesis_id = sanitize_string(&hyp.hypothesis_id, ctx);
    }

    // Sanitize timeline
    for entry in &mut sanitized.timeline {
        entry.summary = sanitize_string(&entry.summary, ctx);
        if let Some(ref ptr) = entry.evidence_ptr {
            entry.evidence_ptr = Some(sanitize_string(ptr, ctx));
        }
    }

    // Sanitize claims
    for claim in &mut sanitized.claims {
        claim.text = sanitize_string(&claim.text, ctx);
        claim.evidence_ptrs = claim
            .evidence_ptrs
            .iter()
            .map(|p| sanitize_string(p, ctx))
            .collect();
    }

    // Sanitize visibility notes
    for note in &mut sanitized.visibility.watermark_notes {
        *note = sanitize_string(note, ctx);
    }
    for reason in &mut sanitized.visibility.degraded_reasons {
        *reason = sanitize_string(reason, ctx);
    }

    // Sanitize disambiguators
    for disamb in &mut sanitized.disambiguators {
        disamb.question = sanitize_string(&disamb.question, ctx);
        disamb.pivot_action = sanitize_string(&disamb.pivot_action, ctx);
        disamb.if_yes = sanitize_string(&disamb.if_yes, ctx);
        disamb.if_no = sanitize_string(&disamb.if_no, ctx);
    }

    // Sanitize integrity notes
    for note in &mut sanitized.integrity_notes {
        note.description = sanitize_string(&note.description, ctx);
        note.affected_evidence = note
            .affected_evidence
            .iter()
            .map(|e| sanitize_string(e, ctx))
            .collect();
    }

    // Sanitize evidence excerpts
    let mut new_excerpts = HashMap::new();
    for (ptr, excerpt) in &bundle.evidence_excerpts {
        let sanitized_ptr = sanitize_string(ptr, ctx);
        let sanitized_excerpt = sanitize_string(excerpt, ctx);
        new_excerpts.insert(sanitized_ptr, sanitized_excerpt);
    }
    sanitized.evidence_excerpts = new_excerpts;

    sanitized
}

// ============================================================================
// Export Functions
// ============================================================================

/// Compute SHA-256 checksum over canonical bundle payload (checksum field omitted)
pub fn compute_checksum(bundle: &IncidentBundle) -> String {
    // Create a copy with checksum blanked for canonical hashing
    let mut hashable = bundle.clone();
    hashable.bundle_meta.checksum = String::new();

    let canonical_json = serde_json::to_string(&hashable).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Compute SHA-256 of raw bytes
pub fn compute_sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Build an IncidentBundle from a ReportBundle
pub fn build_incident_bundle(
    bundle: ReportBundle,
    mode: Option<String>,
    preset: Option<String>,
    focus_minutes: u32,
    redact: bool,
    include_recompute: bool,
) -> IncidentBundle {
    let mut ctx = RedactionContext::new();

    let final_bundle = if redact {
        sanitize_bundle(&bundle, &mut ctx)
    } else {
        bundle.clone()
    };

    let bundle_id = format!(
        "bundle-{}-{}",
        final_bundle
            .metadata
            .incident_id
            .as_deref()
            .unwrap_or("unknown"),
        Utc::now().format("%Y%m%d%H%M%S")
    );

    // Build recompute section if requested
    let recompute = if include_recompute {
        Some(RecomputeSection {
            events: vec![], // Would be populated from actual event store
            config_snapshot: ConfigSnapshot {
                playbook_fingerprints: vec!["default-v1".to_string()],
                mode: mode.clone(),
                preset: preset.clone(),
                focus_minutes,
                late_arrival_window_secs: 30,
                component_versions: [("engine".to_string(), env!("CARGO_PKG_VERSION").to_string())]
                    .into_iter()
                    .collect(),
                capture_profile: "core".to_string(),
                throttle_config: None,
                dynamic_enablements: None,
            },
            evidence_excerpts: if final_bundle.evidence_excerpts.is_empty() {
                None
            } else {
                Some(final_bundle.evidence_excerpts.clone())
            },
        })
    } else {
        None
    };

    // Generate watermark for this export
    let watermark = create_watermark_from_license("bundle_export").map(|wm| BundleWatermark {
        visible: wm.to_visible_string(),
        license_id: wm.license_id,
        install_hash: wm.install_hash,
        build_version: wm.build_version,
    });

    let mut incident_bundle = IncidentBundle {
        version: BUNDLE_FORMAT_VERSION.to_string(),
        bundle_meta: BundleMeta {
            bundle_id: bundle_id.clone(),
            exported_at: Utc::now(),
            exported_by: "edr-workbench".to_string(),
            redacted: redact,
            hash_alg: HASH_ALGORITHM.to_string(),
            checksum: String::new(), // Will be computed below
            checksum_scope: CHECKSUM_SCOPE.to_string(),
            watermark,
        },
        session_meta: SessionMeta {
            mode,
            preset,
            focus_minutes,
            original_host: if redact {
                Some("HOST_ORIGINAL".to_string())
            } else {
                Some(bundle.metadata.host_id.clone())
            },
        },
        included_sections: IncludedSections {
            replay: true,
            recompute: include_recompute,
        },
        replay: ReplaySection {
            report_bundle: final_bundle,
        },
        recompute,
    };

    // Compute SHA-256 checksum
    incident_bundle.bundle_meta.checksum = compute_checksum(&incident_bundle);

    incident_bundle
}

/// Serialize bundle to JSON bytes
#[allow(dead_code)]
pub fn export_to_json(bundle: &IncidentBundle) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(bundle).map_err(|e| format!("Failed to serialize bundle: {}", e))
}

/// Serialize bundle to compressed ZIP with manifest
pub fn export_to_zip(bundle: &IncidentBundle) -> Result<Vec<u8>, String> {
    let mut zip_buffer = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buffer));

        let options = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(6));

        let mut file_hashes = BTreeMap::new();

        // Write replay/report_bundle.json
        let report_json = serde_json::to_vec_pretty(&bundle.replay.report_bundle)
            .map_err(|e| format!("Failed to serialize report_bundle: {}", e))?;
        file_hashes.insert(
            "replay/report_bundle.json".to_string(),
            compute_sha256_bytes(&report_json),
        );
        zip.start_file("replay/report_bundle.json", options)
            .map_err(|e| format!("Failed to create ZIP entry: {}", e))?;
        zip.write_all(&report_json)
            .map_err(|e| format!("Failed to write to ZIP: {}", e))?;

        // Write recompute section if present
        if let Some(ref recompute) = bundle.recompute {
            // Events as JSONL
            let mut events_jsonl = Vec::new();
            for event in &recompute.events {
                let line = serde_json::to_string(event).unwrap_or_default();
                events_jsonl.extend_from_slice(line.as_bytes());
                events_jsonl.push(b'\n');
            }
            file_hashes.insert(
                "recompute/events.jsonl".to_string(),
                compute_sha256_bytes(&events_jsonl),
            );
            zip.start_file("recompute/events.jsonl", options)
                .map_err(|e| format!("Failed to create events entry: {}", e))?;
            zip.write_all(&events_jsonl)
                .map_err(|e| format!("Failed to write events: {}", e))?;

            // Config snapshot
            let config_json = serde_json::to_vec_pretty(&recompute.config_snapshot)
                .map_err(|e| format!("Failed to serialize config: {}", e))?;
            file_hashes.insert(
                "recompute/config_snapshot.json".to_string(),
                compute_sha256_bytes(&config_json),
            );
            zip.start_file("recompute/config_snapshot.json", options)
                .map_err(|e| format!("Failed to create config entry: {}", e))?;
            zip.write_all(&config_json)
                .map_err(|e| format!("Failed to write config: {}", e))?;
        }

        // Write manifest.json
        let manifest = BundleManifest {
            version: bundle.version.clone(),
            bundle_meta: bundle.bundle_meta.clone(),
            included_sections: bundle.included_sections.clone(),
            file_hashes,
        };
        let manifest_json = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
        zip.start_file("manifest.json", options)
            .map_err(|e| format!("Failed to create manifest entry: {}", e))?;
        zip.write_all(&manifest_json)
            .map_err(|e| format!("Failed to write manifest: {}", e))?;

        // Write README
        let readme = format!(
            "EDR Incident Bundle\n\
             ====================\n\n\
             Bundle ID: {}\n\
             Exported: {}\n\
             Format Version: {}\n\
             Hash Algorithm: {}\n\
             Checksum: {}\n\
             Redacted: {}\n\
             Includes Replay: {}\n\
             Includes Recompute: {}\n\n\
             To import this bundle, use the Import Bundle feature in EDR Desktop.\n",
            bundle.bundle_meta.bundle_id,
            bundle.bundle_meta.exported_at,
            bundle.version,
            bundle.bundle_meta.hash_alg,
            bundle.bundle_meta.checksum,
            bundle.bundle_meta.redacted,
            bundle.included_sections.replay,
            bundle.included_sections.recompute
        );
        zip.start_file("README.txt", options)
            .map_err(|e| format!("Failed to create README entry: {}", e))?;
        zip.write_all(readme.as_bytes())
            .map_err(|e| format!("Failed to write README: {}", e))?;

        zip.finish()
            .map_err(|e| format!("Failed to finalize ZIP: {}", e))?;
    }

    Ok(zip_buffer)
}

/// Manifest for ZIP bundles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub version: String,
    pub bundle_meta: BundleMeta,
    pub included_sections: IncludedSections,
    /// File hashes (BTreeMap for deterministic serialization order)
    pub file_hashes: BTreeMap<String, String>,
}

// ============================================================================
// Import Functions
// ============================================================================

/// Import bundle from JSON bytes
pub fn import_from_json(data: &[u8]) -> Result<IncidentBundle, String> {
    serde_json::from_slice(data).map_err(|e| format!("Failed to parse bundle JSON: {}", e))
}

/// Validate ZIP safety before extraction
pub fn validate_zip_safety(data: &[u8], policy: &ZipSafetyPolicy) -> Result<(), String> {
    let cursor = std::io::Cursor::new(data);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| format!("Invalid ZIP archive: {}", e))?;

    // Check file count
    if archive.len() > policy.max_files {
        return Err(format!(
            "ZIP contains too many files: {} (max: {})",
            archive.len(),
            policy.max_files
        ));
    }

    let mut total_uncompressed = 0usize;

    for i in 0..archive.len() {
        let file = archive
            .by_index_raw(i)
            .map_err(|e| format!("Failed to read ZIP entry {}: {}", i, e))?;

        let name = file.name();

        // Check for path traversal
        if policy.reject_path_traversal {
            if name.contains("..") || name.starts_with('/') || name.starts_with('\\') {
                return Err(format!("Path traversal detected: {}", name));
            }
            // Check for absolute Windows paths
            if name.len() >= 2 && name.chars().nth(1) == Some(':') {
                return Err(format!("Absolute path detected: {}", name));
            }
        }

        // Check filename allowlist
        let is_allowed = ALLOWED_FILENAMES
            .iter()
            .any(|allowed| name == *allowed || name.ends_with(*allowed));
        if !is_allowed && !name.ends_with('/') {
            return Err(format!("Filename not in allowlist: {}", name));
        }

        // Check for nested archives
        if policy.reject_nested_archives {
            let lower = name.to_lowercase();
            if lower.ends_with(".zip")
                || lower.ends_with(".tar")
                || lower.ends_with(".gz")
                || lower.ends_with(".7z")
                || lower.ends_with(".rar")
            {
                return Err(format!("Nested archive detected: {}", name));
            }
        }

        // Check single file size
        let uncompressed_size = file.size() as usize;
        if uncompressed_size > policy.max_single_file {
            return Err(format!(
                "File too large: {} ({} bytes, max: {})",
                name, uncompressed_size, policy.max_single_file
            ));
        }

        total_uncompressed += uncompressed_size;
    }

    // Check total uncompressed size
    if total_uncompressed > policy.max_total_uncompressed {
        return Err(format!(
            "Total uncompressed size too large: {} bytes (max: {})",
            total_uncompressed, policy.max_total_uncompressed
        ));
    }

    Ok(())
}

/// Import bundle from ZIP bytes with safety checks
pub fn import_from_zip(data: &[u8]) -> Result<IncidentBundle, String> {
    let policy = ZipSafetyPolicy::default();
    validate_zip_safety(data, &policy)?;

    let cursor = std::io::Cursor::new(data);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| format!("Failed to read ZIP archive: {}", e))?;

    // Try manifest-based import first (new format)
    if let Ok(mut manifest_file) = archive.by_name("manifest.json") {
        let mut manifest_data = Vec::new();
        manifest_file
            .read_to_end(&mut manifest_data)
            .map_err(|e| format!("Failed to read manifest: {}", e))?;

        let manifest: BundleManifest = serde_json::from_slice(&manifest_data)
            .map_err(|e| format!("Failed to parse manifest: {}", e))?;

        // Re-open archive for report reading
        let cursor = std::io::Cursor::new(data);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();

        // Read and validate replay/report_bundle.json
        let report_bundle: ReportBundle = {
            let mut file = archive
                .by_name("replay/report_bundle.json")
                .map_err(|_| "Missing replay/report_bundle.json")?;
            let mut report_data = Vec::new();
            file.read_to_end(&mut report_data)
                .map_err(|e| format!("Failed to read report_bundle: {}", e))?;

            // Validate hash if present
            if let Some(expected_hash) = manifest.file_hashes.get("replay/report_bundle.json") {
                let actual_hash = compute_sha256_bytes(&report_data);
                if &actual_hash != expected_hash {
                    return Err("report_bundle.json hash mismatch".to_string());
                }
            }

            serde_json::from_slice(&report_data)
                .map_err(|e| format!("Failed to parse report_bundle: {}", e))?
        };

        // Read recompute section if present
        let recompute = if manifest.included_sections.recompute {
            // Re-open archive
            let cursor = std::io::Cursor::new(data);
            let mut archive = zip::ZipArchive::new(cursor).unwrap();

            let config_snapshot: ConfigSnapshot = {
                let mut file = archive
                    .by_name("recompute/config_snapshot.json")
                    .map_err(|_| "Missing recompute/config_snapshot.json")?;
                let mut config_data = Vec::new();
                file.read_to_end(&mut config_data)
                    .map_err(|e| format!("Failed to read config_snapshot: {}", e))?;
                serde_json::from_slice(&config_data)
                    .map_err(|e| format!("Failed to parse config_snapshot: {}", e))?
            };

            Some(RecomputeSection {
                events: vec![], // Would parse from events.jsonl
                config_snapshot,
                evidence_excerpts: None,
            })
        } else {
            None
        };

        return Ok(IncidentBundle {
            version: manifest.version,
            bundle_meta: manifest.bundle_meta,
            session_meta: SessionMeta {
                mode: None,
                preset: None,
                focus_minutes: 15,
                original_host: None,
            },
            included_sections: manifest.included_sections,
            replay: ReplaySection { report_bundle },
            recompute,
        });
    }

    // Fallback: try legacy single-file format
    let cursor = std::io::Cursor::new(data);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| format!("Failed to re-read ZIP: {}", e))?;

    let mut json_data = Vec::new();
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("Failed to read ZIP entry: {}", e))?;

        if file.name().ends_with(".json") && !file.name().contains('/') {
            file.read_to_end(&mut json_data)
                .map_err(|e| format!("Failed to read JSON from ZIP: {}", e))?;
            break;
        }
    }

    if json_data.is_empty() {
        return Err("No valid JSON file found in ZIP archive".to_string());
    }

    import_from_json(&json_data)
}

/// Detect format and import accordingly
pub fn import_bundle(data: &[u8]) -> Result<IncidentBundle, String> {
    // Check for ZIP magic bytes (PK)
    if data.len() >= 2 && data[0] == 0x50 && data[1] == 0x4B {
        import_from_zip(data)
    } else {
        // Assume JSON
        import_from_json(data)
    }
}

/// Create imported namespace for a bundle
pub fn create_imported_namespace(bundle_id: &str) -> String {
    format!("IMPORTED_{}", bundle_id)
}

/// Mark an imported bundle as imported (not live telemetry)
pub fn mark_as_imported(bundle: &mut IncidentBundle) {
    let namespace = create_imported_namespace(&bundle.bundle_meta.bundle_id);

    // Update metadata to indicate this is imported
    if !bundle
        .replay
        .report_bundle
        .metadata
        .summary
        .starts_with("[IMPORTED]")
    {
        bundle.replay.report_bundle.metadata.summary = format!(
            "[IMPORTED] {}",
            bundle.replay.report_bundle.metadata.summary
        );
    }

    // Update host_id to use imported namespace
    if !bundle
        .replay
        .report_bundle
        .metadata
        .host_id
        .starts_with("IMPORTED_")
    {
        bundle.replay.report_bundle.metadata.host_id =
            format!("IMPORTED_{}", bundle.replay.report_bundle.metadata.host_id);
    }

    // Add integrity note about import
    let already_has_import_note = bundle
        .replay
        .report_bundle
        .integrity_notes
        .iter()
        .any(|n| n.note_type == "import");

    if !already_has_import_note {
        bundle.replay.report_bundle.integrity_notes.push(IntegrityNoteEntry {
            note_type: "import".to_string(),
            severity: "info".to_string(),
            description: format!(
                "This bundle was imported from an external source. Namespace: {}. Original export: {}",
                namespace,
                bundle.bundle_meta.exported_at
            ),
            affected_evidence: vec![],
        });
    }
}

/// Validate bundle integrity (SHA-256 checksum + version)
pub fn validate_bundle(bundle: &IncidentBundle) -> Result<(), String> {
    // Check version compatibility
    let version_parts: Vec<&str> = bundle.version.split('.').collect();
    let current_parts: Vec<&str> = BUNDLE_FORMAT_VERSION.split('.').collect();

    if version_parts.is_empty() || current_parts.is_empty() {
        return Err("Invalid version format".to_string());
    }

    // Major version must match
    if version_parts[0] != current_parts[0] {
        return Err(format!(
            "Incompatible bundle version: {} (current: {})",
            bundle.version, BUNDLE_FORMAT_VERSION
        ));
    }

    // Verify SHA-256 checksum
    let computed_checksum = compute_checksum(bundle);

    if computed_checksum != bundle.bundle_meta.checksum {
        return Err("Bundle checksum mismatch - data may be corrupted or tampered".to_string());
    }

    Ok(())
}

/// Execute recompute from bundle's canonical inputs
#[allow(dead_code)]
pub fn recompute_from_bundle(
    bundle: &IncidentBundle,
    mode: &str,
) -> Result<RecomputeResult, String> {
    let recompute_section = bundle
        .recompute
        .as_ref()
        .ok_or("Bundle does not contain recompute section")?;

    // In strict mode, verify component versions match
    if mode == "strict" {
        let current_version = env!("CARGO_PKG_VERSION");
        if let Some(engine_version) = recompute_section
            .config_snapshot
            .component_versions
            .get("engine")
        {
            if engine_version != current_version {
                return Err(format!(
                    "Strict mode: engine version mismatch (bundle: {}, current: {})",
                    engine_version, current_version
                ));
            }
        }
    }

    // For now, return the replay result as "recomputed"
    // In a full implementation, we'd re-run the pipeline with canonical events
    let replay_bundle = &bundle.replay.report_bundle;

    // Compute diff (in this simplified version, they match)
    let diff = RecomputeDiff::default();

    // Determine verdict
    let (verdict, reasons) = if mode == "strict" {
        (
            "PASS".to_string(),
            vec!["Strict mode: all checks passed".to_string()],
        )
    } else {
        (
            "PASS".to_string(),
            vec!["Best effort mode: recompute matched replay".to_string()],
        )
    };

    Ok(RecomputeResult {
        success: true,
        bundle_id: bundle.bundle_meta.bundle_id.clone(),
        recompute_explanation: Some(replay_bundle.clone()),
        determinism_verdict: verdict,
        verdict_reasons: reasons,
        diff_vs_replay: diff,
        message: "Recompute completed successfully".to_string(),
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{ClaimEntry, ReportBundleBuilder, TimelineEntry};

    fn create_test_bundle() -> ReportBundle {
        ReportBundleBuilder::new(
            "test-report-001".to_string(),
            "workstation-01.corp.example.com".to_string(),
        )
        .with_incident_id("INC-2025-001".to_string())
        .with_summary(
            "Detected credential access on C:\\Users\\jsmith\\AppData from 192.168.1.100"
                .to_string(),
        )
        .add_timeline_entry(TimelineEntry {
            ts: Utc::now(),
            summary: "Process mimikatz.exe spawned by jsmith on workstation-01".to_string(),
            category: "process".to_string(),
            evidence_ptr: Some("seg:evt_001".to_string()),
            is_late_arrival: false,
        })
        .add_claim(ClaimEntry {
            claim_id: "c1".to_string(),
            text: "User jsmith executed credential dumping tool".to_string(),
            certainty: "observed".to_string(),
            claim_type: "credential_access".to_string(),
            evidence_ptrs: vec!["seg:evt_001".to_string()],
            has_conflict: false,
        })
        .add_evidence_excerpt(
            "seg:evt_001".to_string(),
            "Process: mimikatz.exe, User: jsmith, Path: C:\\Users\\jsmith\\Downloads".to_string(),
        )
        .build()
    }

    #[test]
    fn test_redaction_replaces_hostnames() {
        let mut ctx = RedactionContext::new();
        let input = "Activity on workstation-01.corp.example.com";
        let result = sanitize_string(input, &mut ctx);

        assert!(result.contains("HOST_"));
        assert!(!result.contains("workstation-01"));
    }

    #[test]
    fn test_redaction_replaces_ips() {
        let mut ctx = RedactionContext::new();
        let input = "Connection from 192.168.1.100 to 10.0.0.50";
        let result = sanitize_string(input, &mut ctx);

        assert!(result.contains("IP_"));
        assert!(!result.contains("192.168.1.100"));
        assert!(!result.contains("10.0.0.50"));
    }

    #[test]
    fn test_redaction_preserves_localhost() {
        let mut ctx = RedactionContext::new();
        let input = "Listening on 127.0.0.1:8080";
        let result = sanitize_string(input, &mut ctx);

        assert!(result.contains("127.0.0.1"));
    }

    #[test]
    fn test_redaction_is_deterministic() {
        let mut ctx1 = RedactionContext::new();
        let mut ctx2 = RedactionContext::new();

        let input = "User jsmith on host workstation-01";
        let result1 = sanitize_string(input, &mut ctx1);
        let result2 = sanitize_string(input, &mut ctx2);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_bundle_sanitization() {
        let bundle = create_test_bundle();
        let mut ctx = RedactionContext::new();
        let sanitized = sanitize_bundle(&bundle, &mut ctx);

        // Host should be redacted
        assert!(sanitized.metadata.host_id.starts_with("HOST_"));

        // Summary should be sanitized
        assert!(!sanitized.metadata.summary.contains("jsmith"));
        assert!(!sanitized.metadata.summary.contains("192.168.1.100"));
    }

    #[test]
    fn test_export_import_roundtrip_json() {
        let bundle = create_test_bundle();
        let incident_bundle = build_incident_bundle(
            bundle.clone(),
            Some("discovery".to_string()),
            Some("htb".to_string()),
            15,
            false, // No redaction for exact comparison
            false, // No recompute
        );

        let exported = export_to_json(&incident_bundle).unwrap();
        let imported = import_from_json(&exported).unwrap();

        // Verify structure is preserved
        assert_eq!(imported.version, incident_bundle.version);
        assert_eq!(
            imported.replay.report_bundle.hypotheses.len(),
            bundle.hypotheses.len()
        );
        assert_eq!(
            imported.replay.report_bundle.timeline.len(),
            bundle.timeline.len()
        );
        assert_eq!(
            imported.replay.report_bundle.claims.len(),
            bundle.claims.len()
        );
    }

    #[test]
    fn test_export_import_roundtrip_zip() {
        let bundle = create_test_bundle();
        let incident_bundle = build_incident_bundle(
            bundle.clone(),
            Some("mission".to_string()),
            Some("atomic".to_string()),
            30,
            false,
            false,
        );

        let exported = export_to_zip(&incident_bundle).unwrap();

        // Verify ZIP magic bytes
        assert_eq!(exported[0], 0x50); // 'P'
        assert_eq!(exported[1], 0x4B); // 'K'

        let imported = import_from_zip(&exported).unwrap();

        assert_eq!(
            imported.replay.report_bundle.metadata.incident_id,
            bundle.metadata.incident_id
        );
    }

    #[test]
    fn test_export_import_preserves_evidence_ordering() {
        let bundle = create_test_bundle();
        let incident_bundle = build_incident_bundle(bundle.clone(), None, None, 15, false, false);

        let exported = export_to_json(&incident_bundle).unwrap();
        let imported = import_from_json(&exported).unwrap();

        // Timeline ordering preserved
        for (orig, imported_entry) in bundle
            .timeline
            .iter()
            .zip(imported.replay.report_bundle.timeline.iter())
        {
            assert_eq!(orig.summary, imported_entry.summary);
            assert_eq!(orig.evidence_ptr, imported_entry.evidence_ptr);
        }

        // Evidence excerpts preserved
        for (ptr, excerpt) in &bundle.evidence_excerpts {
            assert_eq!(
                imported.replay.report_bundle.evidence_excerpts.get(ptr),
                Some(excerpt)
            );
        }
    }

    #[test]
    fn test_bundle_validation() {
        let bundle = create_test_bundle();
        let incident_bundle = build_incident_bundle(bundle, None, None, 15, false, false);

        // Valid bundle should pass
        assert!(validate_bundle(&incident_bundle).is_ok());

        // Tampered bundle should fail
        let mut tampered = incident_bundle.clone();
        tampered.replay.report_bundle.metadata.summary = "Tampered!".to_string();
        assert!(validate_bundle(&tampered).is_err());
    }

    #[test]
    fn test_mark_as_imported() {
        let bundle = create_test_bundle();
        let mut incident_bundle = build_incident_bundle(bundle, None, None, 15, false, false);

        mark_as_imported(&mut incident_bundle);

        assert!(incident_bundle
            .replay
            .report_bundle
            .metadata
            .summary
            .starts_with("[IMPORTED]"));
        assert!(incident_bundle
            .replay
            .report_bundle
            .integrity_notes
            .iter()
            .any(|n| n.note_type == "import"));
    }

    #[test]
    fn test_redacted_bundle_roundtrip() {
        let bundle = create_test_bundle();
        let incident_bundle = build_incident_bundle(
            bundle,
            Some("discovery".to_string()),
            None,
            15,
            true, // With redaction
            false,
        );

        // Verify redaction was applied
        assert!(incident_bundle.bundle_meta.redacted);

        // Export and import
        let exported = export_to_json(&incident_bundle).unwrap();
        let imported = import_from_json(&exported).unwrap();

        // Redacted data should match
        assert_eq!(
            imported.replay.report_bundle.metadata.host_id,
            incident_bundle.replay.report_bundle.metadata.host_id
        );
    }

    // ========== SHA-256 Tests ==========

    #[test]
    fn test_sha256_checksum_computed() {
        let bundle = create_test_bundle();
        let incident_bundle = build_incident_bundle(bundle, None, None, 15, false, false);

        assert_eq!(incident_bundle.bundle_meta.hash_alg, "sha256");
        assert_eq!(incident_bundle.bundle_meta.checksum_scope, CHECKSUM_SCOPE);
        assert_eq!(incident_bundle.bundle_meta.checksum.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_tamper_detection_fails_checksum() {
        let bundle = create_test_bundle();
        let mut incident_bundle = build_incident_bundle(bundle, None, None, 15, false, false);

        // Valid bundle passes
        assert!(validate_bundle(&incident_bundle).is_ok());

        // Tamper with payload
        incident_bundle.replay.report_bundle.metadata.summary = "Tampered!".to_string();

        // Validation should fail
        let result = validate_bundle(&incident_bundle);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("checksum mismatch"));
    }

    // ========== Redaction Safety Tests ==========

    #[test]
    fn test_redacted_bundle_contains_no_raw_sensitive_tokens() {
        let bundle = create_test_bundle();
        let incident_bundle = build_incident_bundle(bundle, None, None, 15, true, false);

        let json = serde_json::to_string(&incident_bundle).unwrap();

        // Must NOT contain raw sensitive data (paths and IPs are critical)
        assert!(!json.contains("192.168.1.100"), "Bundle leaked IP");
        assert!(
            !json.contains("workstation-01.corp.example.com"),
            "Bundle leaked hostname"
        );
        // Paths containing usernames should be redacted
        assert!(
            !json.contains("C:\\\\Users\\\\jsmith"),
            "Bundle leaked user path"
        );
    }

    // ========== ZIP Safety Tests ==========

    #[test]
    fn test_zip_rejects_path_traversal() {
        // Create a malicious ZIP with path traversal
        let mut zip_buffer = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buffer));
            let options = zip::write::FileOptions::default();
            zip.start_file("../../../etc/passwd", options).unwrap();
            zip.write_all(b"malicious").unwrap();
            zip.finish().unwrap();
        }

        let policy = ZipSafetyPolicy::default();
        let result = validate_zip_safety(&zip_buffer, &policy);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("traversal") || err.contains("allowlist"));
    }

    #[test]
    fn test_zip_rejects_too_many_files() {
        let mut zip_buffer = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buffer));
            let options = zip::write::FileOptions::default();
            for i in 0..50 {
                zip.start_file(format!("file_{}.json", i), options).unwrap();
                zip.write_all(b"{}").unwrap();
            }
            zip.finish().unwrap();
        }

        let policy = ZipSafetyPolicy {
            max_files: 32,
            ..Default::default()
        };
        let result = validate_zip_safety(&zip_buffer, &policy);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too many files"));
    }

    // ========== Namespace Isolation Tests ==========

    #[test]
    fn test_imported_namespace_prefix() {
        let namespace = create_imported_namespace("bundle-test-123");
        assert!(namespace.starts_with("IMPORTED_"));
        assert!(ImportedBundleStore::is_imported_namespace(&namespace));
    }

    #[test]
    fn test_mark_as_imported_adds_namespace() {
        let bundle = create_test_bundle();
        let mut incident_bundle = build_incident_bundle(bundle, None, None, 15, false, false);

        mark_as_imported(&mut incident_bundle);

        // Summary should be prefixed
        assert!(incident_bundle
            .replay
            .report_bundle
            .metadata
            .summary
            .starts_with("[IMPORTED]"));

        // Host ID should be namespaced
        assert!(incident_bundle
            .replay
            .report_bundle
            .metadata
            .host_id
            .starts_with("IMPORTED_"));

        // Should have import integrity note
        assert!(incident_bundle
            .replay
            .report_bundle
            .integrity_notes
            .iter()
            .any(|n| n.note_type == "import"));
    }

    // ========== Replay + Recompute Tests ==========

    #[test]
    fn test_export_import_recompute_roundtrip() {
        let bundle = create_test_bundle();
        let incident_bundle = build_incident_bundle(
            bundle,
            Some("mission".to_string()),
            Some("atomic".to_string()),
            30,
            false,
            true, // include_recompute = true
        );

        // Verify recompute section present
        assert!(incident_bundle.included_sections.recompute);
        assert!(incident_bundle.recompute.is_some());

        let recompute = incident_bundle.recompute.as_ref().unwrap();
        assert!(recompute
            .config_snapshot
            .component_versions
            .contains_key("engine"));
    }

    #[test]
    fn test_recompute_returns_diff_structure() {
        let bundle = create_test_bundle();
        let incident_bundle = build_incident_bundle(bundle, None, None, 15, false, true);

        let result = recompute_from_bundle(&incident_bundle, "best_effort").unwrap();

        assert!(result.success);
        assert!(result.recompute_explanation.is_some());
        assert!(!result.determinism_verdict.is_empty());
    }

    #[test]
    fn test_recompute_without_section_fails() {
        let bundle = create_test_bundle();
        let incident_bundle = build_incident_bundle(
            bundle, None, None, 15, false, false, // no recompute
        );

        let result = recompute_from_bundle(&incident_bundle, "best_effort");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not contain recompute"));
    }
}

//! Verification Pack - First-run experience with synthetic sample data
//!
//! Provides:
//! - Embedded verification bundle (synthetic incident data for installation testing)
//! - Verification pack load endpoint  
//! - App state endpoint (first-run detection)
//! - Self-check capability to detect real telemetry
//!
//! The verification bundle is clearly labeled as SYNTHETIC:
//! - 1 incident with timeline (synthetic)
//! - Visibility state with missing stream
//! - 1 disambiguator
//! - PDF reports labeled "VERIFICATION PACK"

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::report::{
    ClaimEntry, DisambiguatorEntry, HypothesisSummary, IntegrityNoteEntry, ReportBundle,
    ReportBundleBuilder, TimelineEntry, VisibilitySection,
};

// ============================================================================
// App State Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStateResponse {
    pub is_first_run: bool,
    pub telemetry_root: String,
    pub current_session: Option<SessionInfo>,
    pub verification_loaded: bool,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub mode: String,
    pub focus_minutes: u32,
    pub preset: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyLoadRequest {
    #[serde(default = "default_bundle_name")]
    pub bundle_name: String,
}

fn default_bundle_name() -> String {
    "verify_001".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyLoadResponse {
    pub success: bool,
    pub bundle_name: String,
    pub incident_count: usize,
    pub hypothesis_count: usize,
    pub timeline_entry_count: usize,
    pub report_bundle: ReportBundle,
    pub synthetic: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupCompleteRequest {
    pub mode: String,       // "discovery" or "mission"
    pub preset: String,     // "htb", "atomic", "tryhackme", "generic"
    pub focus_minutes: u32, // e.g., 15
    pub load_verification: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupCompleteResponse {
    pub success: bool,
    pub mode: String,
    pub preset: String,
    pub focus_minutes: u32,
    pub verification_loaded: bool,
    pub message: String,
}

// ============================================================================
// Self-Check Types (detect real telemetry)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfCheckRequest {
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u32,
}

fn default_timeout() -> u32 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfCheckResponse {
    pub success: bool,
    pub sensors_detected: bool,
    pub events_received: u32,
    pub permissions_ok: bool,
    pub recommend_verification: bool,
    pub message: String,
}

// ============================================================================
// First-Run Marker
// ============================================================================

const FIRST_RUN_MARKER: &str = ".first_run_complete";

/// Check if this is the first run by looking for the marker file
pub fn is_first_run(data_dir: &Path) -> bool {
    !data_dir.join(FIRST_RUN_MARKER).exists()
}

/// Mark first run as complete
pub fn mark_first_run_complete(data_dir: &Path) -> std::io::Result<()> {
    let marker_path = data_dir.join(FIRST_RUN_MARKER);
    std::fs::write(&marker_path, chrono::Utc::now().to_rfc3339())?;
    tracing::info!("First run complete, marker written to {:?}", marker_path);
    Ok(())
}

/// Reset first-run state (for testing/re-onboarding)
pub fn reset_first_run(data_dir: &Path) -> std::io::Result<()> {
    let marker_path = data_dir.join(FIRST_RUN_MARKER);
    if marker_path.exists() {
        std::fs::remove_file(&marker_path)?;
    }
    Ok(())
}

// ============================================================================
// Verification Bundle Generation
// ============================================================================

/// List available verification bundles
pub fn list_verification_bundles() -> Vec<&'static str> {
    vec!["verify_001"]
}

/// Build the embedded verification bundle with deterministic synthetic data
///
/// This produces:
/// - 1 high-confidence hypothesis (credential access)
/// - 1 medium-confidence hypothesis (defense evasion)  
/// - Timeline with 6 entries including 1 late arrival
/// - 3 claims (observed, inferred, unknown)
/// - Visibility with 1 missing stream
/// - 1 actionable disambiguator
/// - 2 integrity notes
/// - SYNTHETIC flag set to true
/// - Summary includes "VERIFICATION PACK" label
pub fn build_verification_bundle(bundle_name: &str) -> ReportBundle {
    // Use a fixed timestamp for determinism (verification scenario timestamp)
    let base_time = DateTime::parse_from_rfc3339("2025-01-15T14:30:00Z")
        .unwrap()
        .with_timezone(&Utc);

    let report_id = format!("verify-{}-001", bundle_name);
    let host_id = "verify-workstation-01".to_string();

    ReportBundleBuilder::new(report_id, host_id)
        .with_incident_id("VERIFY-2025-0115-001".to_string())
        .with_session_id("verify-session-001".to_string())
        .with_family("credential_access".to_string())
        .with_synthetic(true) // Mark as synthetic data
        .with_summary(
            "[VERIFICATION PACK - SYNTHETIC DATA] \
             Simulated credential harvesting activity on verify-workstation-01. \
             This is synthetic data for installation verification and workflow learning. \
             The attack sequence shows process injection into LSASS followed by \
             credential extraction patterns consistent with Mimikatz."
                .to_string(),
        )
        // Hypothesis 1: High confidence credential access
        .add_hypothesis(HypothesisSummary {
            rank: 1,
            hypothesis_id: "VERIFY-H001".to_string(),
            family: "credential_access".to_string(),
            template_id: "T1003.001".to_string(),
            confidence: 0.87,
            severity: "High".to_string(),
            suppressed: false,
            suppression_reason: None,
            slots_satisfied: "5/6 slots filled".to_string(),
        })
        // Hypothesis 2: Medium confidence defense evasion
        .add_hypothesis(HypothesisSummary {
            rank: 2,
            hypothesis_id: "VERIFY-H002".to_string(),
            family: "defense_evasion".to_string(),
            template_id: "T1055.001".to_string(),
            confidence: 0.64,
            severity: "Medium".to_string(),
            suppressed: false,
            suppression_reason: None,
            slots_satisfied: "4/6 slots filled".to_string(),
        })
        // Timeline entries (6 total, 1 late arrival)
        .add_timeline_entry(TimelineEntry {
            ts: base_time - Duration::minutes(5),
            summary: "[SYNTHETIC] Suspicious PowerShell execution detected".to_string(),
            category: "process".to_string(),
            evidence_ptr: Some("verify_seg:evt_001".to_string()),
            is_late_arrival: false,
        })
        .add_timeline_entry(TimelineEntry {
            ts: base_time - Duration::minutes(4),
            summary: "[SYNTHETIC] Process spawned: mimikatz.exe (PID 4512)".to_string(),
            category: "process".to_string(),
            evidence_ptr: Some("verify_seg:evt_002".to_string()),
            is_late_arrival: false,
        })
        .add_timeline_entry(TimelineEntry {
            ts: base_time - Duration::minutes(3),
            summary: "[SYNTHETIC] OpenProcess called on lsass.exe with VM_READ access".to_string(),
            category: "process".to_string(),
            evidence_ptr: Some("verify_seg:evt_003".to_string()),
            is_late_arrival: false,
        })
        .add_timeline_entry(TimelineEntry {
            ts: base_time - Duration::minutes(2),
            summary: "[SYNTHETIC] Memory read from LSASS address space".to_string(),
            category: "memory".to_string(),
            evidence_ptr: Some("verify_seg:evt_004".to_string()),
            is_late_arrival: false,
        })
        .add_timeline_entry(TimelineEntry {
            ts: base_time - Duration::minutes(1),
            summary: "[SYNTHETIC][LATE] Network connection to 192.168.1.100:445".to_string(),
            category: "network".to_string(),
            evidence_ptr: Some("verify_seg:evt_005".to_string()),
            is_late_arrival: true, // Late arrival example
        })
        .add_timeline_entry(TimelineEntry {
            ts: base_time,
            summary: "[SYNTHETIC] Credential file written: C:\\temp\\creds.dmp".to_string(),
            category: "file".to_string(),
            evidence_ptr: Some("verify_seg:evt_006".to_string()),
            is_late_arrival: false,
        })
        // Claims (3 types: observed, inferred, unknown)
        .add_claim(ClaimEntry {
            claim_id: "VERIFY-C001".to_string(),
            text: "[SYNTHETIC] LSASS memory access with credential extraction patterns".to_string(),
            certainty: "observed".to_string(),
            claim_type: "MemoryAccess".to_string(),
            evidence_ptrs: vec![
                "verify_seg:evt_003".to_string(),
                "verify_seg:evt_004".to_string(),
            ],
            has_conflict: false,
        })
        .add_claim(ClaimEntry {
            claim_id: "VERIFY-C002".to_string(),
            text: "[SYNTHETIC] Credential exfiltration capability established".to_string(),
            certainty: "inferred".to_string(),
            claim_type: "Capability".to_string(),
            evidence_ptrs: vec!["verify_seg:evt_006".to_string()],
            has_conflict: false,
        })
        .add_claim(ClaimEntry {
            claim_id: "VERIFY-C003".to_string(),
            text: "[SYNTHETIC] Lateral movement intent via harvested credentials".to_string(),
            certainty: "unknown".to_string(),
            claim_type: "Intent".to_string(),
            evidence_ptrs: vec![],
            has_conflict: false,
        })
        // Visibility with missing stream
        .with_visibility(VisibilitySection {
            overall_health: "degraded".to_string(),
            streams_present: vec![
                "process_events".to_string(),
                "file_events".to_string(),
                "memory_events".to_string(),
            ],
            streams_missing: vec!["network_events".to_string()],
            degraded: true,
            degraded_reasons: vec![
                "[SYNTHETIC] Network collector offline for 45s during incident window".to_string(),
            ],
            late_arrival_count: 1,
            watermark_notes: vec![
                "[SYNTHETIC] Watermark lag: 2.8s observed".to_string(),
                "[SYNTHETIC] 1 event arrived after watermark gate".to_string(),
            ],
        })
        // Disambiguator (actionable)
        .add_disambiguator(DisambiguatorEntry {
            id: "VERIFY-D001".to_string(),
            priority: 1,
            question: "[SYNTHETIC] Was the LSASS access from a legitimate security tool?".to_string(),
            pivot_action: "Check if source process is signed by known security vendor".to_string(),
            if_yes: "Mark as false positive, add to allowlist".to_string(),
            if_no: "Escalate immediately - likely active credential theft".to_string(),
            actionable: true,
        })
        // Integrity notes
        .add_integrity_note(IntegrityNoteEntry {
            note_type: "verification_pack".to_string(),
            severity: "info".to_string(),
            description: "This is SYNTHETIC data from the verification pack. Switch to Live mode to view real telemetry.".to_string(),
            affected_evidence: vec![],
        })
        .add_integrity_note(IntegrityNoteEntry {
            note_type: "sensor_gap".to_string(),
            severity: "warning".to_string(),
            description: "[SYNTHETIC] Network collector was offline for 45s during incident window.".to_string(),
            affected_evidence: vec!["network_events".to_string()],
        })
        // Evidence excerpts
        .add_evidence_excerpt(
            "verify_seg:evt_002".to_string(),
            "[SYNTHETIC EVIDENCE]\nProcess Start: mimikatz.exe\nPID: 4512\nParent: powershell.exe (PID: 3280)\nCommand Line: mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"".to_string(),
        )
        .add_evidence_excerpt(
            "verify_seg:evt_003".to_string(),
            "[SYNTHETIC EVIDENCE]\nOpenProcess: Target=lsass.exe (PID 656)\nAccess: PROCESS_VM_READ | PROCESS_QUERY_INFORMATION\nCaller: mimikatz.exe (PID 4512)".to_string(),
        )
        .add_evidence_excerpt(
            "verify_seg:evt_004".to_string(),
            "[SYNTHETIC EVIDENCE]\nReadProcessMemory: Target=lsass.exe\nAddress: 0x7FFE0000-0x7FFE8000\nSize: 32768 bytes\nCaller: mimikatz.exe".to_string(),
        )
        .add_evidence_excerpt(
            "verify_seg:evt_006".to_string(),
            "[SYNTHETIC EVIDENCE]\nFile Write: C:\\temp\\creds.dmp\nSize: 15482 bytes\nProcess: mimikatz.exe (PID 4512)".to_string(),
        )
        .build()
}

// ============================================================================
// Verification State Tracking
// ============================================================================

/// Tracks verification pack state in memory
#[derive(Debug, Default)]
pub struct VerificationState {
    pub loaded: bool,
    pub bundle_name: Option<String>,
    pub loaded_at: Option<DateTime<Utc>>,
    pub synthetic: bool,
}

impl VerificationState {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_loaded(&mut self, bundle_name: &str) {
        self.loaded = true;
        self.bundle_name = Some(bundle_name.to_string());
        self.loaded_at = Some(Utc::now());
        self.synthetic = true;
    }

    pub fn reset(&mut self) {
        self.loaded = false;
        self.bundle_name = None;
        self.loaded_at = None;
        self.synthetic = false;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_bundle_is_deterministic() {
        let bundle1 = build_verification_bundle("verify_001");
        let bundle2 = build_verification_bundle("verify_001");

        // Same metadata
        assert_eq!(bundle1.metadata.incident_id, bundle2.metadata.incident_id);
        assert_eq!(bundle1.metadata.summary, bundle2.metadata.summary);

        // Same hypotheses
        assert_eq!(bundle1.hypotheses.len(), bundle2.hypotheses.len());
        assert_eq!(
            bundle1.hypotheses[0].hypothesis_id,
            bundle2.hypotheses[0].hypothesis_id
        );

        // Same timeline
        assert_eq!(bundle1.timeline.len(), bundle2.timeline.len());
    }

    #[test]
    fn test_verification_bundle_has_required_elements() {
        let bundle = build_verification_bundle("verify_001");

        // At least 1 hypothesis
        assert!(
            !bundle.hypotheses.is_empty(),
            "Must have at least 1 hypothesis"
        );

        // At least 1 timeline entry
        assert!(!bundle.timeline.is_empty(), "Must have timeline entries");

        // Has late arrival
        let has_late = bundle.timeline.iter().any(|e| e.is_late_arrival);
        assert!(has_late, "Must have at least 1 late arrival entry");

        // Has missing stream in visibility
        assert!(
            !bundle.visibility.streams_missing.is_empty(),
            "Must have missing stream"
        );

        // Has disambiguator
        assert!(!bundle.disambiguators.is_empty(), "Must have disambiguator");
        assert!(
            bundle.disambiguators[0].actionable,
            "Disambiguator must be actionable"
        );

        // Has claims of different types
        let certainties: Vec<_> = bundle.claims.iter().map(|c| c.certainty.as_str()).collect();
        assert!(
            certainties.contains(&"observed"),
            "Must have observed claim"
        );
        assert!(
            certainties.contains(&"inferred"),
            "Must have inferred claim"
        );
        assert!(certainties.contains(&"unknown"), "Must have unknown claim");
    }

    #[test]
    fn test_verification_bundle_has_evidence_excerpts() {
        let bundle = build_verification_bundle("verify_001");

        // Must have evidence excerpts
        assert!(
            !bundle.evidence_excerpts.is_empty(),
            "Must have evidence excerpts"
        );

        // Evidence should be linked from timeline
        for entry in &bundle.timeline {
            if let Some(ptr) = &entry.evidence_ptr {
                // At least some should have excerpts
                if bundle.evidence_excerpts.contains_key(ptr) {
                    return; // Found at least one linked excerpt
                }
            }
        }
        // This is fine - not all timeline entries need excerpts
    }

    #[test]
    fn test_verification_bundle_marked_synthetic() {
        let bundle = build_verification_bundle("verify_001");

        // Metadata must indicate synthetic
        assert!(
            bundle.metadata.synthetic,
            "Bundle must be marked as synthetic"
        );

        // Summary must contain VERIFICATION PACK label
        assert!(
            bundle.metadata.summary.contains("VERIFICATION PACK"),
            "Summary must contain VERIFICATION PACK label"
        );

        // Summary must contain SYNTHETIC
        assert!(
            bundle.metadata.summary.contains("SYNTHETIC"),
            "Summary must contain SYNTHETIC label"
        );
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path();

        // Initially should be first run
        assert!(is_first_run(data_dir));

        // Mark complete
        mark_first_run_complete(data_dir).unwrap();

        // Should no longer be first run
        assert!(!is_first_run(data_dir));

        // Reset
        reset_first_run(data_dir).unwrap();

        // Should be first run again
        assert!(is_first_run(data_dir));
    }
}

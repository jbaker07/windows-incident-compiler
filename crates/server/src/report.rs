//! PDF Report Generation from ExplanationResponse
//!
//! Generates local-only PDF reports with:
//! - Evidence pointers and excerpts
//! - Visibility state
//! - Claims table (observed vs inferred vs missing)
//! - Disambiguators and integrity notes
//!
//! Rendering strategy: `genpdf` (pure Rust, no external dependencies)

use chrono::{DateTime, Utc};
use genpdf::elements::{Break, Paragraph};
use genpdf::fonts;
use genpdf::style::{Color, Style};
use genpdf::{Document, Element, SimplePageDecorator};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Report Request/Response Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRequest {
    /// Session ID (uses latest if not provided)
    #[serde(default)]
    pub session_id: Option<String>,
    /// Focus window override
    #[serde(default)]
    pub focus_window: Option<FocusWindowSpec>,
    /// Specific incident ID
    #[serde(default)]
    pub incident_id: Option<String>,
    /// Whether to include evidence excerpts
    #[serde(default = "default_true")]
    pub include_excerpts: bool,
    /// Whether to include visibility details
    #[serde(default = "default_true")]
    pub include_visibility: bool,
    /// Whether to include disambiguators
    #[serde(default = "default_true")]
    pub include_disambiguators: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FocusWindowSpec {
    pub t_min: String,
    pub t_max: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportResponse {
    pub success: bool,
    pub report_id: String,
    pub file_path: Option<String>,
    pub size_bytes: usize,
    pub message: Option<String>,
}

// ============================================================================
// ReportBundle - Derived from ExplanationResponse
// ============================================================================

/// A structured bundle ready for PDF rendering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportBundle {
    /// Report metadata
    pub metadata: ReportMetadata,
    /// Top-3 hypothesis summary
    pub hypotheses: Vec<HypothesisSummary>,
    /// Timeline entries (stable ordering)
    pub timeline: Vec<TimelineEntry>,
    /// Claims table
    pub claims: Vec<ClaimEntry>,
    /// Visibility section
    pub visibility: VisibilitySection,
    /// Disambiguators section
    pub disambiguators: Vec<DisambiguatorEntry>,
    /// Integrity notes
    pub integrity_notes: Vec<IntegrityNoteEntry>,
    /// Evidence excerpts (if requested)
    pub evidence_excerpts: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub incident_id: Option<String>,
    pub session_id: Option<String>,
    pub family: Option<String>,
    pub host_id: String,
    pub time_window: Option<TimeWindow>,
    pub summary: String,
    /// True if this is synthetic data (verification pack)
    #[serde(default)]
    pub synthetic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub t_min: DateTime<Utc>,
    pub t_max: DateTime<Utc>,
    pub duration_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisSummary {
    pub rank: u32,
    pub hypothesis_id: String,
    pub family: String,
    pub template_id: String,
    pub confidence: f64,
    pub severity: String,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
    pub slots_satisfied: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub ts: DateTime<Utc>,
    pub summary: String,
    pub category: String,
    pub evidence_ptr: Option<String>,
    pub is_late_arrival: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimEntry {
    pub claim_id: String,
    pub text: String,
    pub certainty: String, // "observed", "inferred", "unknown"
    pub claim_type: String,
    pub evidence_ptrs: Vec<String>,
    pub has_conflict: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilitySection {
    pub overall_health: String,
    pub streams_present: Vec<String>,
    pub streams_missing: Vec<String>,
    pub degraded: bool,
    pub degraded_reasons: Vec<String>,
    pub late_arrival_count: u32,
    pub watermark_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisambiguatorEntry {
    pub id: String,
    pub priority: u32,
    pub question: String,
    pub pivot_action: String,
    pub if_yes: String,
    pub if_no: String,
    pub actionable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityNoteEntry {
    pub note_type: String,
    pub severity: String,
    pub description: String,
    pub affected_evidence: Vec<String>,
}

// ============================================================================
// PDF Renderer
// ============================================================================

/// Font directories to search on different platforms
const FONT_DIRS: &[&str] = &[
    "./fonts",
    "/usr/share/fonts/liberation",
    "/usr/share/fonts/truetype/liberation",
    "/usr/share/fonts/truetype/dejavu",
    "/System/Library/Fonts",
    "/Library/Fonts",
    "/System/Library/Fonts/Supplemental",
];

/// Get the fonts directory relative to the crate root
fn get_crate_fonts_dir() -> Option<std::path::PathBuf> {
    // Try CARGO_MANIFEST_DIR first (available during build)
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let fonts_dir = std::path::PathBuf::from(manifest_dir).join("fonts");
        if fonts_dir.exists() {
            return Some(fonts_dir);
        }
    }

    // Try relative to current executable (for tests)
    if let Ok(exe_path) = std::env::current_exe() {
        // Navigate from target/debug/deps up to crate root
        if let Some(target_dir) = exe_path.ancestors().nth(4) {
            let fonts_dir = target_dir.join("crates/server/fonts");
            if fonts_dir.exists() {
                return Some(fonts_dir);
            }
        }
    }

    None
}

/// Pure Rust PDF renderer using genpdf
pub struct PdfRenderer {
    // Using built-in fonts, no stored font family needed
}

impl PdfRenderer {
    /// Create a new PDF renderer with built-in fonts
    pub fn new() -> Result<Self, String> {
        Ok(Self {})
    }

    /// Render ReportBundle to PDF bytes
    pub fn render(&self, bundle: &ReportBundle) -> Result<Vec<u8>, String> {
        // Build list of font directories to search
        let mut font_dirs: Vec<std::path::PathBuf> =
            FONT_DIRS.iter().map(std::path::PathBuf::from).collect();

        // Add crate-relative fonts directory (for embedded fonts)
        if let Some(crate_fonts) = get_crate_fonts_dir() {
            font_dirs.insert(0, crate_fonts);
        }

        // Try to load fonts from system directories
        // Liberation fonts are commonly available on Linux/macOS
        // Use None for builtin to ensure fonts are embedded (required for unicode support)
        let font_family = font_dirs
            .iter()
            .filter(|path| path.exists())
            .find_map(|dir| {
                let dir_str = dir.to_str().unwrap_or(".");
                // Try Liberation fonts first - must be embedded (no builtin) for unicode support
                fonts::from_files(dir_str, "LiberationSans", None).ok()
            })
            .ok_or_else(|| {
                format!(
                    "No suitable fonts found. Searched: {:?}. Please install Liberation fonts.",
                    font_dirs
                )
            })?;

        // Create document
        let mut doc = Document::new(font_family);
        doc.set_title(format!(
            "Security Analysis Report - {}",
            bundle.metadata.report_id
        ));
        doc.set_minimal_conformance();
        doc.set_line_spacing(1.25);

        // Add page decorator with margins and header
        let mut decorator = SimplePageDecorator::new();
        decorator.set_margins(15);
        doc.set_page_decorator(decorator);

        // =====================================================================
        // VERIFICATION PACK BANNER (if synthetic)
        // =====================================================================
        if bundle.metadata.synthetic {
            doc.push(
                Paragraph::new("══════════════════════════════════════════════════════════════")
                    .styled(Style::new().bold().with_font_size(10)),
            );
            doc.push(
                Paragraph::new("⚠️  VERIFICATION PACK - SYNTHETIC DATA  ⚠️")
                    .styled(Style::new().bold().with_font_size(14)),
            );
            doc.push(
                Paragraph::new(
                    "This report contains synthetic data for installation verification.",
                )
                .styled(Style::new().italic().with_font_size(10)),
            );
            doc.push(
                Paragraph::new("This is NOT a real security incident. Do not file or escalate.")
                    .styled(Style::new().italic().with_font_size(10)),
            );
            doc.push(
                Paragraph::new("══════════════════════════════════════════════════════════════")
                    .styled(Style::new().bold().with_font_size(10)),
            );
            doc.push(Break::new(1.0));
        }

        // =====================================================================
        // HEADER
        // =====================================================================
        doc.push(
            Paragraph::new("SECURITY ANALYSIS REPORT")
                .styled(Style::new().bold().with_font_size(18)),
        );
        doc.push(Break::new(0.5));

        doc.push(
            Paragraph::new(format!("Report ID: {}", bundle.metadata.report_id))
                .styled(Style::new().with_font_size(10)),
        );
        doc.push(
            Paragraph::new(format!(
                "Generated: {}",
                bundle.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
            ))
            .styled(Style::new().with_font_size(10)),
        );
        doc.push(
            Paragraph::new(format!("Host: {}", bundle.metadata.host_id))
                .styled(Style::new().with_font_size(10)),
        );

        if let Some(ref incident_id) = bundle.metadata.incident_id {
            // Check if this is an imported incident and add warning banner
            if incident_id.starts_with("imported_") {
                doc.push(
                    Paragraph::new("⚠️ IMPORTED BUNDLE - This report is from external data, not live telemetry")
                        .styled(Style::new().bold().with_font_size(11)),
                );
                doc.push(Break::new(0.3));
            }
            doc.push(
                Paragraph::new(format!("Incident: {}", incident_id))
                    .styled(Style::new().with_font_size(10)),
            );
        }
        if let Some(ref family) = bundle.metadata.family {
            doc.push(
                Paragraph::new(format!("Family: {}", family))
                    .styled(Style::new().with_font_size(10)),
            );
        }
        if let Some(ref window) = bundle.metadata.time_window {
            doc.push(
                Paragraph::new(format!(
                    "Time Window: {} to {} ({}s)",
                    window.t_min.format("%H:%M:%S"),
                    window.t_max.format("%H:%M:%S"),
                    window.duration_seconds
                ))
                .styled(Style::new().with_font_size(10)),
            );
        }

        doc.push(Break::new(1.0));

        // =====================================================================
        // EXECUTIVE SUMMARY
        // =====================================================================
        doc.push(
            Paragraph::new("EXECUTIVE SUMMARY").styled(Style::new().bold().with_font_size(14)),
        );
        doc.push(Break::new(0.3));

        if !bundle.metadata.summary.is_empty() {
            doc.push(
                Paragraph::new(&bundle.metadata.summary).styled(Style::new().with_font_size(11)),
            );
        } else {
            doc.push(
                Paragraph::new("No summary available.")
                    .styled(Style::new().italic().with_font_size(11)),
            );
        }

        doc.push(Break::new(1.0));

        // =====================================================================
        // TOP-3 HYPOTHESES
        // =====================================================================
        if !bundle.hypotheses.is_empty() {
            doc.push(
                Paragraph::new("TOP HYPOTHESES").styled(Style::new().bold().with_font_size(14)),
            );
            doc.push(Break::new(0.3));

            for hyp in &bundle.hypotheses {
                let status = if hyp.suppressed {
                    format!(
                        " [SUPPRESSED: {}]",
                        hyp.suppression_reason.as_deref().unwrap_or("unknown")
                    )
                } else {
                    String::new()
                };

                doc.push(
                    Paragraph::new(format!(
                        "#{} {} ({}) - Confidence: {:.0}% - Severity: {}{}",
                        hyp.rank,
                        hyp.family,
                        hyp.template_id,
                        hyp.confidence * 100.0,
                        hyp.severity,
                        status
                    ))
                    .styled(Style::new().with_font_size(11)),
                );

                doc.push(
                    Paragraph::new(format!("   Slots: {}", hyp.slots_satisfied))
                        .styled(Style::new().with_font_size(10)),
                );
            }

            doc.push(Break::new(1.0));
        }

        // =====================================================================
        // CLAIMS TABLE: What We Know vs Infer vs Missing
        // =====================================================================
        doc.push(Paragraph::new("CLAIMS ANALYSIS").styled(Style::new().bold().with_font_size(14)));
        doc.push(Break::new(0.3));

        let observed: Vec<_> = bundle
            .claims
            .iter()
            .filter(|c| c.certainty == "observed")
            .collect();
        let inferred: Vec<_> = bundle
            .claims
            .iter()
            .filter(|c| c.certainty == "inferred_from_rules")
            .collect();
        let unknown: Vec<_> = bundle
            .claims
            .iter()
            .filter(|c| c.certainty == "unknown")
            .collect();

        doc.push(
            Paragraph::new(format!(
                "What We KNOW (Observed): {} claims",
                observed.len()
            ))
            .styled(Style::new().bold().with_font_size(11)),
        );
        for claim in observed.iter().take(10) {
            let conflict_marker = if claim.has_conflict {
                " [CONFLICT]"
            } else {
                ""
            };
            doc.push(
                Paragraph::new(format!("  • {}{}", claim.text, conflict_marker))
                    .styled(Style::new().with_font_size(10)),
            );
            if !claim.evidence_ptrs.is_empty() {
                doc.push(
                    Paragraph::new(format!("    Evidence: {}", claim.evidence_ptrs.join(", ")))
                        .styled(
                            Style::new()
                                .with_font_size(9)
                                .with_color(Color::Rgb(100, 100, 100)),
                        ),
                );
            }
        }
        if observed.len() > 10 {
            doc.push(
                Paragraph::new(format!("    ... and {} more", observed.len() - 10))
                    .styled(Style::new().italic().with_font_size(9)),
            );
        }

        doc.push(Break::new(0.5));

        doc.push(
            Paragraph::new(format!(
                "What We INFER (From Rules): {} claims",
                inferred.len()
            ))
            .styled(Style::new().bold().with_font_size(11)),
        );
        for claim in inferred.iter().take(5) {
            doc.push(
                Paragraph::new(format!("  • {}", claim.text))
                    .styled(Style::new().with_font_size(10)),
            );
        }

        doc.push(Break::new(0.5));

        doc.push(
            Paragraph::new(format!("What's MISSING/UNKNOWN: {} claims", unknown.len()))
                .styled(Style::new().bold().with_font_size(11)),
        );
        for claim in unknown.iter().take(5) {
            doc.push(
                Paragraph::new(format!("  • {}", claim.text))
                    .styled(Style::new().with_font_size(10)),
            );
        }

        doc.push(Break::new(1.0));

        // =====================================================================
        // TIMELINE
        // =====================================================================
        if !bundle.timeline.is_empty() {
            doc.push(
                Paragraph::new("EVENT TIMELINE").styled(Style::new().bold().with_font_size(14)),
            );
            doc.push(Break::new(0.3));

            for entry in bundle.timeline.iter().take(20) {
                let late_marker = if entry.is_late_arrival {
                    " [LATE ARRIVAL]"
                } else {
                    ""
                };
                doc.push(
                    Paragraph::new(format!(
                        "{} | {} | {}{}",
                        entry.ts.format("%H:%M:%S"),
                        entry.category,
                        entry.summary,
                        late_marker
                    ))
                    .styled(Style::new().with_font_size(10)),
                );

                if let Some(ref ptr) = entry.evidence_ptr {
                    doc.push(
                        Paragraph::new(format!("         Evidence: {}", ptr)).styled(
                            Style::new()
                                .with_font_size(9)
                                .with_color(Color::Rgb(100, 100, 100)),
                        ),
                    );
                }
            }
            if bundle.timeline.len() > 20 {
                doc.push(
                    Paragraph::new(format!(
                        "... and {} more events",
                        bundle.timeline.len() - 20
                    ))
                    .styled(Style::new().italic().with_font_size(9)),
                );
            }

            doc.push(Break::new(1.0));
        }

        // =====================================================================
        // VISIBILITY STATE
        // =====================================================================
        doc.push(Paragraph::new("VISIBILITY STATE").styled(Style::new().bold().with_font_size(14)));
        doc.push(Break::new(0.3));

        doc.push(
            Paragraph::new(format!(
                "Overall Health: {}",
                bundle.visibility.overall_health
            ))
            .styled(Style::new().with_font_size(11)),
        );

        if bundle.visibility.degraded {
            doc.push(
                Paragraph::new("⚠ DEGRADED").styled(
                    Style::new()
                        .bold()
                        .with_font_size(11)
                        .with_color(Color::Rgb(200, 100, 0)),
                ),
            );
            for reason in &bundle.visibility.degraded_reasons {
                doc.push(
                    Paragraph::new(format!("  - {}", reason))
                        .styled(Style::new().with_font_size(10)),
                );
            }
        }

        if !bundle.visibility.streams_present.is_empty() {
            doc.push(
                Paragraph::new(format!(
                    "Streams Present: {}",
                    bundle.visibility.streams_present.join(", ")
                ))
                .styled(Style::new().with_font_size(10)),
            );
        }
        if !bundle.visibility.streams_missing.is_empty() {
            doc.push(
                Paragraph::new(format!(
                    "Streams Missing: {}",
                    bundle.visibility.streams_missing.join(", ")
                ))
                .styled(
                    Style::new()
                        .with_font_size(10)
                        .with_color(Color::Rgb(200, 0, 0)),
                ),
            );
        }

        if bundle.visibility.late_arrival_count > 0 {
            doc.push(
                Paragraph::new(format!(
                    "Late Arrivals: {} events",
                    bundle.visibility.late_arrival_count
                ))
                .styled(Style::new().with_font_size(10)),
            );
        }

        for note in &bundle.visibility.watermark_notes {
            doc.push(
                Paragraph::new(format!("  Note: {}", note)).styled(Style::new().with_font_size(9)),
            );
        }

        doc.push(Break::new(1.0));

        // =====================================================================
        // DISAMBIGUATORS (Open Questions)
        // =====================================================================
        if !bundle.disambiguators.is_empty() {
            doc.push(
                Paragraph::new("OPEN QUESTIONS & SUGGESTED PIVOTS")
                    .styled(Style::new().bold().with_font_size(14)),
            );
            doc.push(Break::new(0.3));

            for disamb in &bundle.disambiguators {
                let actionable = if disamb.actionable {
                    ""
                } else {
                    " [NOT ACTIONABLE]"
                };
                doc.push(
                    Paragraph::new(format!(
                        "Q{}: {}{}",
                        disamb.priority, disamb.question, actionable
                    ))
                    .styled(Style::new().with_font_size(11)),
                );
                doc.push(
                    Paragraph::new(format!("  Action: {}", disamb.pivot_action))
                        .styled(Style::new().with_font_size(10)),
                );
                doc.push(
                    Paragraph::new(format!("  If YES: {}", disamb.if_yes))
                        .styled(Style::new().with_font_size(10)),
                );
                doc.push(
                    Paragraph::new(format!("  If NO: {}", disamb.if_no))
                        .styled(Style::new().with_font_size(10)),
                );
                doc.push(Break::new(0.3));
            }

            doc.push(Break::new(0.5));
        }

        // =====================================================================
        // INTEGRITY NOTES
        // =====================================================================
        if !bundle.integrity_notes.is_empty() {
            doc.push(
                Paragraph::new("INTEGRITY NOTES").styled(Style::new().bold().with_font_size(14)),
            );
            doc.push(Break::new(0.3));

            for note in &bundle.integrity_notes {
                let severity_style = if note.severity == "error" {
                    Style::new()
                        .with_font_size(10)
                        .with_color(Color::Rgb(200, 0, 0))
                } else {
                    Style::new()
                        .with_font_size(10)
                        .with_color(Color::Rgb(200, 150, 0))
                };

                doc.push(
                    Paragraph::new(format!(
                        "[{}] {}: {}",
                        note.severity.to_uppercase(),
                        note.note_type,
                        note.description
                    ))
                    .styled(severity_style),
                );

                if !note.affected_evidence.is_empty() {
                    doc.push(
                        Paragraph::new(format!(
                            "  Affected: {}",
                            note.affected_evidence.join(", ")
                        ))
                        .styled(Style::new().with_font_size(9)),
                    );
                }
            }

            doc.push(Break::new(1.0));
        }

        // =====================================================================
        // EVIDENCE EXCERPTS (if included)
        // =====================================================================
        if !bundle.evidence_excerpts.is_empty() {
            doc.push(
                Paragraph::new("EVIDENCE EXCERPTS").styled(Style::new().bold().with_font_size(14)),
            );
            doc.push(Break::new(0.3));

            for (ptr, excerpt) in &bundle.evidence_excerpts {
                doc.push(
                    Paragraph::new(format!("[{}]", ptr))
                        .styled(Style::new().bold().with_font_size(10)),
                );
                // Truncate long excerpts
                let truncated = if excerpt.len() > 500 {
                    format!("{}...", &excerpt[..500])
                } else {
                    excerpt.clone()
                };
                doc.push(Paragraph::new(&truncated).styled(Style::new().with_font_size(9)));
                doc.push(Break::new(0.3));
            }
        }

        // =====================================================================
        // FOOTER
        // =====================================================================
        doc.push(Break::new(1.0));
        doc.push(
            Paragraph::new("--- END OF REPORT ---").styled(
                Style::new()
                    .italic()
                    .with_font_size(9)
                    .with_color(Color::Rgb(128, 128, 128)),
            ),
        );
        doc.push(
            Paragraph::new("Generated by EDR Analysis Engine (local-only, no network calls)")
                .styled(
                    Style::new()
                        .with_font_size(8)
                        .with_color(Color::Rgb(128, 128, 128)),
                ),
        );

        // Render to bytes
        let mut buffer = Vec::new();
        doc.render(&mut buffer)
            .map_err(|e| format!("PDF render failed: {}", e))?;

        Ok(buffer)
    }
}

impl Default for PdfRenderer {
    fn default() -> Self {
        Self::new().unwrap_or(Self {})
    }
}

// ============================================================================
// Bundle Builder - Converts ExplanationResponse to ReportBundle
// ============================================================================

/// Build a ReportBundle from ExplanationResponse and related data
pub struct ReportBundleBuilder {
    bundle: ReportBundle,
}

impl ReportBundleBuilder {
    pub fn new(report_id: String, host_id: String) -> Self {
        Self {
            bundle: ReportBundle {
                metadata: ReportMetadata {
                    report_id,
                    generated_at: Utc::now(),
                    incident_id: None,
                    session_id: None,
                    family: None,
                    host_id,
                    time_window: None,
                    summary: String::new(),
                    synthetic: false,
                },
                hypotheses: Vec::new(),
                timeline: Vec::new(),
                claims: Vec::new(),
                visibility: VisibilitySection {
                    overall_health: "unknown".to_string(),
                    streams_present: Vec::new(),
                    streams_missing: Vec::new(),
                    degraded: false,
                    degraded_reasons: Vec::new(),
                    late_arrival_count: 0,
                    watermark_notes: Vec::new(),
                },
                disambiguators: Vec::new(),
                integrity_notes: Vec::new(),
                evidence_excerpts: HashMap::new(),
            },
        }
    }

    pub fn with_incident_id(mut self, id: String) -> Self {
        self.bundle.metadata.incident_id = Some(id);
        self
    }

    pub fn with_session_id(mut self, id: String) -> Self {
        self.bundle.metadata.session_id = Some(id);
        self
    }

    pub fn with_family(mut self, family: String) -> Self {
        self.bundle.metadata.family = Some(family);
        self
    }

    /// Override the generated_at timestamp (for deterministic golden bundle generation)
    #[allow(dead_code)]
    pub fn with_generated_at(mut self, ts: DateTime<Utc>) -> Self {
        self.bundle.metadata.generated_at = ts;
        self
    }

    pub fn with_summary(mut self, summary: String) -> Self {
        self.bundle.metadata.summary = summary;
        self
    }

    /// Mark this bundle as containing synthetic (verification pack) data
    pub fn with_synthetic(mut self, synthetic: bool) -> Self {
        self.bundle.metadata.synthetic = synthetic;
        self
    }

    #[allow(dead_code)]
    pub fn with_time_window(mut self, t_min: DateTime<Utc>, t_max: DateTime<Utc>) -> Self {
        self.bundle.metadata.time_window = Some(TimeWindow {
            t_min,
            t_max,
            duration_seconds: t_max.signed_duration_since(t_min).num_seconds(),
        });
        self
    }

    pub fn add_hypothesis(mut self, hyp: HypothesisSummary) -> Self {
        self.bundle.hypotheses.push(hyp);
        self
    }

    pub fn add_timeline_entry(mut self, entry: TimelineEntry) -> Self {
        self.bundle.timeline.push(entry);
        self
    }

    pub fn add_claim(mut self, claim: ClaimEntry) -> Self {
        self.bundle.claims.push(claim);
        self
    }

    pub fn with_visibility(mut self, vis: VisibilitySection) -> Self {
        self.bundle.visibility = vis;
        self
    }

    pub fn add_disambiguator(mut self, disamb: DisambiguatorEntry) -> Self {
        self.bundle.disambiguators.push(disamb);
        self
    }

    pub fn add_integrity_note(mut self, note: IntegrityNoteEntry) -> Self {
        self.bundle.integrity_notes.push(note);
        self
    }

    pub fn add_evidence_excerpt(mut self, ptr: String, excerpt: String) -> Self {
        self.bundle.evidence_excerpts.insert(ptr, excerpt);
        self
    }

    pub fn build(mut self) -> ReportBundle {
        // Sort timeline by timestamp for stable ordering
        self.bundle.timeline.sort_by_key(|e| e.ts);
        // Sort hypotheses by rank
        self.bundle.hypotheses.sort_by_key(|h| h.rank);
        // Sort disambiguators by priority
        self.bundle.disambiguators.sort_by_key(|d| d.priority);

        self.bundle
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_bundle_builder() {
        let bundle = ReportBundleBuilder::new("report_001".to_string(), "test_host".to_string())
            .with_summary("Test summary".to_string())
            .with_family("credential_access".to_string())
            .add_claim(ClaimEntry {
                claim_id: "claim_1".to_string(),
                text: "Process executed mimikatz.exe".to_string(),
                certainty: "observed".to_string(),
                claim_type: "ProcessExecution".to_string(),
                evidence_ptrs: vec!["seg_001:0".to_string()],
                has_conflict: false,
            })
            .build();

        assert_eq!(bundle.metadata.report_id, "report_001");
        assert_eq!(bundle.metadata.host_id, "test_host");
        assert_eq!(bundle.claims.len(), 1);
    }

    #[test]
    fn test_visibility_section() {
        let vis = VisibilitySection {
            overall_health: "degraded".to_string(),
            streams_present: vec!["process_events".to_string()],
            streams_missing: vec!["network_events".to_string()],
            degraded: true,
            degraded_reasons: vec!["Network collector offline".to_string()],
            late_arrival_count: 3,
            watermark_notes: vec!["Watermark lag: 5s".to_string()],
        };

        assert!(vis.degraded);
        assert_eq!(vis.streams_missing.len(), 1);
    }

    #[test]
    fn test_claim_certainty_categorization() {
        let claims = [
            ClaimEntry {
                claim_id: "c1".to_string(),
                text: "Observed fact".to_string(),
                certainty: "observed".to_string(),
                claim_type: "ProcessExecution".to_string(),
                evidence_ptrs: vec![],
                has_conflict: false,
            },
            ClaimEntry {
                claim_id: "c2".to_string(),
                text: "Inferred fact".to_string(),
                certainty: "inferred_from_rules".to_string(),
                claim_type: "Relationship".to_string(),
                evidence_ptrs: vec![],
                has_conflict: false,
            },
            ClaimEntry {
                claim_id: "c3".to_string(),
                text: "Unknown fact".to_string(),
                certainty: "unknown".to_string(),
                claim_type: "Other".to_string(),
                evidence_ptrs: vec![],
                has_conflict: false,
            },
        ];

        let observed: Vec<_> = claims
            .iter()
            .filter(|c| c.certainty == "observed")
            .collect();
        let inferred: Vec<_> = claims
            .iter()
            .filter(|c| c.certainty == "inferred_from_rules")
            .collect();
        let unknown: Vec<_> = claims.iter().filter(|c| c.certainty == "unknown").collect();

        assert_eq!(observed.len(), 1);
        assert_eq!(inferred.len(), 1);
        assert_eq!(unknown.len(), 1);
    }
}

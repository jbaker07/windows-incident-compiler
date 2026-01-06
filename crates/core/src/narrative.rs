//! NarrativeDoc: Evidence-Cited Copilot Narration Schema
//!
//! Every sentence in a narrative must be auditable:
//! - Observations MUST include >=1 EvidencePointer (or dereferenced excerpt).
//! - Inferences MUST be labeled as inference and MUST include supporting facts/slots.
//!
//! This module provides the NarrativeDoc schema that synthesizes:
//! - ExplanationBundle (slot fills, evidence ptrs)
//! - ArbitrationDoc (top-3 hypotheses)
//! - DisambiguationQuestions (missing evidence, capability gaps)
//! - MissionSpec (if in mission mode)

use crate::EvidencePtr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// NarrativeDoc - Top-Level Schema
// ============================================================================

/// Evidence-cited narrative document for a signal/incident.
/// Every claim must be verifiable against underlying data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeDoc {
    /// Unique narrative ID (format: "narr_{signal_id}_{version}")
    pub narrative_id: String,

    /// Signal or incident ID this narrative explains
    pub signal_id: String,

    /// Version number for deterministic regeneration
    pub version: u32,

    /// Ordered sentences forming the narrative
    pub sentences: Vec<NarrativeSentence>,

    /// Top-3 hypotheses arbitration results
    pub arbitration: ArbitrationDoc,

    /// Disambiguation questions for ambiguous/incomplete hypotheses
    pub disambiguation: DisambiguationDoc,

    /// Mode context (Discovery vs Mission)
    pub mode_context: ModeContext,

    /// Summary statistics
    pub stats: NarrativeStats,

    /// Generation timestamp (epoch ms)
    pub generated_at_ms: i64,

    /// Hash of inputs for determinism verification
    pub input_hash: String,
}

/// A single sentence in the narrative with its receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeSentence {
    /// Unique sentence ID within this narrative
    pub sentence_id: String,

    /// Sentence ordering index
    pub index: u32,

    /// The natural language text of the sentence
    pub text: String,

    /// Type of sentence (observation vs inference)
    pub sentence_type: SentenceType,

    /// Receipts proving this sentence (REQUIRED)
    pub receipts: SentenceReceipts,

    /// Confidence level (0.0-1.0)
    pub confidence: f64,

    /// User actions applied to this sentence
    #[serde(default)]
    pub user_actions: Vec<UserAction>,
}

/// Sentence type determines required receipt fields
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SentenceType {
    /// Direct observation from telemetry - MUST have evidence_ptrs
    Observation,
    /// Inference from multiple facts - MUST have supporting_facts/slots
    Inference,
    /// Context/background sentence - may have weaker receipts
    Context,
    /// Summary sentence synthesizing prior sentences
    Summary,
}

/// Receipts proving a sentence's validity.
/// For Observations: evidence_ptrs is REQUIRED (>=1).
/// For Inferences: supporting_facts + supporting_slots is REQUIRED.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SentenceReceipts {
    /// Evidence pointers to raw telemetry records
    /// REQUIRED for Observation sentences (>=1)
    #[serde(default)]
    pub evidence_ptrs: Vec<EvidencePtr>,

    /// Dereferenced excerpts for quick verification
    #[serde(default)]
    pub excerpts: Vec<DereferencedExcerpt>,

    /// Supporting fact IDs that justify this sentence
    /// REQUIRED for Inference sentences
    #[serde(default)]
    pub supporting_facts: Vec<String>,

    /// Supporting slot IDs that provide context
    /// REQUIRED for Inference sentences
    #[serde(default)]
    pub supporting_slots: Vec<String>,

    /// Claim IDs from ExplanationBundle that back this sentence
    #[serde(default)]
    pub claim_ids: Vec<String>,

    /// Reference to prior sentences (for Summary type)
    #[serde(default)]
    pub prior_sentence_ids: Vec<String>,
}

/// Dereferenced excerpt from telemetry for quick display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DereferencedExcerpt {
    /// Evidence pointer this excerpt came from
    pub ptr: EvidencePtr,

    /// Excerpt text (first 200-500 chars)
    pub excerpt: String,

    /// Source description (e.g., "Security/4688", "Sysmon/1")
    pub source: String,

    /// Timestamp of the record (epoch ms)
    pub ts_ms: i64,
}

// ============================================================================
// ArbitrationDoc - Top-3 Hypotheses
// ============================================================================

/// Top-3 hypotheses arbitration results with win/loss reasoning.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArbitrationDoc {
    /// Top-ranked hypothesis (winner)
    pub winner: Option<RankedHypothesisDoc>,

    /// Second-ranked hypothesis
    pub runner_up: Option<RankedHypothesisDoc>,

    /// Third-ranked hypothesis  
    pub third: Option<RankedHypothesisDoc>,

    /// Why #1 won over #2 and #3
    pub win_reasons: Vec<String>,

    /// Why #2 lost to #1
    pub runner_up_loss_reasons: Vec<String>,

    /// Why #3 lost to #1 and #2
    pub third_loss_reasons: Vec<String>,

    /// Total candidates considered
    pub total_candidates: usize,

    /// Arbitration timestamp
    pub arbitrated_at_ms: i64,
}

/// A ranked hypothesis with its evidence status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedHypothesisDoc {
    /// Hypothesis ID
    pub hypothesis_id: String,

    /// Playbook/family
    pub playbook_id: String,
    pub family: String,

    /// Rank score (0.0-1.0)
    pub rank_score: f64,

    /// Slot fill status summary
    pub slot_status: SlotStatusSummary,

    /// Key evidence pointers supporting this hypothesis
    pub key_evidence: Vec<EvidencePtr>,

    /// Missing observables that would strengthen this hypothesis
    pub missing_observables: Vec<MissingObservable>,

    /// Capability gaps (telemetry sources not present)
    pub capability_gaps: Vec<CapabilityGap>,

    /// MITRE technique IDs
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
}

/// Slot fill status summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotStatusSummary {
    /// Total required slots
    pub required_total: usize,
    /// Required slots filled
    pub required_filled: usize,
    /// Total optional slots
    pub optional_total: usize,
    /// Optional slots filled
    pub optional_filled: usize,
    /// Per-slot details
    pub slot_details: Vec<SlotDetail>,
}

/// Individual slot detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotDetail {
    pub slot_id: String,
    pub slot_name: String,
    pub required: bool,
    pub filled: bool,
    pub fact_count: usize,
    pub evidence_ptr_count: usize,
}

/// Missing observable that would strengthen a hypothesis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingObservable {
    /// What's missing (e.g., "process creation event for child process")
    pub description: String,
    /// Fact type expected
    pub expected_fact_type: String,
    /// Slot that would be filled
    pub target_slot_id: Option<String>,
    /// How much this would increase confidence
    pub confidence_impact: f64,
}

/// Capability gap (missing telemetry source)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGap {
    /// Missing stream/channel
    pub stream_id: String,
    /// Human-readable description
    pub description: String,
    /// Which observables this would provide
    pub would_provide: Vec<String>,
    /// Remediation suggestion
    pub remediation: Option<String>,
}

// ============================================================================
// DisambiguationDoc - Questions and Pivots
// ============================================================================

/// Disambiguation questions for ambiguous or incomplete hypotheses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisambiguationDoc {
    /// Questions to help narrow down hypotheses
    pub questions: Vec<DisambiguationQuestion>,

    /// Suggested pivot actions
    pub pivot_actions: Vec<PivotAction>,

    /// Capability-based suggestions (what telemetry to enable)
    pub capability_suggestions: Vec<CapabilitySuggestion>,

    /// Ambiguity score (0.0 = clear winner, 1.0 = highly ambiguous)
    pub ambiguity_score: f64,
}

/// A question to help disambiguate hypotheses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisambiguationQuestion {
    /// Question ID
    pub question_id: String,

    /// Natural language question
    pub question_text: String,

    /// What answering this would resolve
    pub resolves: String,

    /// Which hypotheses this would affect
    pub affects_hypotheses: Vec<String>,

    /// Suggested investigation steps
    pub investigation_steps: Vec<String>,

    /// Priority (1=highest)
    pub priority: u8,
}

/// Suggested pivot action for investigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotAction {
    /// Action ID
    pub action_id: String,

    /// Human-readable label
    pub label: String,

    /// Action type (e.g., "search", "filter", "expand_window")
    pub action_type: String,

    /// Parameters for the action
    pub params: HashMap<String, serde_json::Value>,

    /// Expected outcome
    pub expected_outcome: String,
}

/// Suggestion to enable additional telemetry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySuggestion {
    /// Missing capability
    pub capability: String,

    /// How to enable it
    pub how_to_enable: String,

    /// What it would help resolve
    pub would_resolve: Vec<String>,

    /// Impact on detection quality
    pub detection_impact: String,
}

// ============================================================================
// ModeContext - Discovery vs Mission
// ============================================================================

/// Mode context for narrative generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeContext {
    /// Current mode
    pub mode: NarrativeMode,

    /// Mission spec (if in mission mode)
    pub mission_spec: Option<MissionSpec>,

    /// Playbooks evaluated (may be filtered in mission mode)
    pub playbooks_evaluated: Vec<String>,

    /// Playbooks filtered out (in mission mode)
    pub playbooks_filtered: Vec<String>,
}

/// Narrative mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NarrativeMode {
    /// Discovery: broad compile, propose hypotheses, prioritize
    Discovery,
    /// Mission: focused on specific objective, tight output
    Mission,
}

/// Mission specification for focused analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MissionSpec {
    /// Mission ID
    pub mission_id: String,

    /// Mission name/title
    pub name: String,

    /// Mission objective (natural language)
    pub objective: String,

    /// Allowed playbook families (empty = all)
    #[serde(default)]
    pub allowed_families: Vec<String>,

    /// Allowed playbook IDs (empty = all in allowed_families)
    #[serde(default)]
    pub allowed_playbooks: Vec<String>,

    /// Expected observables the analyst expects to find
    #[serde(default)]
    pub expected_observables: Vec<ExpectedObservable>,

    /// Focus window constraints
    pub focus_window: Option<MissionFocusWindow>,

    /// Created timestamp
    pub created_at_ms: i64,

    /// Last updated timestamp
    pub updated_at_ms: i64,
}

/// Expected observable in mission spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedObservable {
    /// Observable description
    pub description: String,
    /// Fact type expected
    pub fact_type: String,
    /// Optional: specific entity (proc name, file path, etc.)
    pub entity_filter: Option<String>,
}

/// Focus window for mission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionFocusWindow {
    /// Start time (epoch ms)
    pub start_ms: i64,
    /// End time (epoch ms)
    pub end_ms: i64,
}

// ============================================================================
// User Actions
// ============================================================================

/// User action on a sentence or evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAction {
    /// Action type
    pub action_type: UserActionType,
    /// Timestamp
    pub ts_ms: i64,
    /// Optional notes
    pub notes: Option<String>,
}

/// Types of user actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserActionType {
    /// Pin evidence as important
    PinEvidence,
    /// Hide evidence from narrative
    HideEvidence,
    /// Mark as verified
    MarkVerified,
    /// Mark as false positive
    MarkFalsePositive,
    /// Request more detail
    RequestDetail,
}

// ============================================================================
// Narrative Statistics
// ============================================================================

/// Statistics about the narrative
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeStats {
    /// Total sentences
    pub sentence_count: usize,
    /// Observation sentences
    pub observation_count: usize,
    /// Inference sentences
    pub inference_count: usize,
    /// Total evidence pointers referenced
    pub evidence_ptr_count: usize,
    /// Total facts referenced
    pub fact_count: usize,
    /// Unique slots referenced
    pub slot_count: usize,
}

// ============================================================================
// Builders
// ============================================================================

impl NarrativeDoc {
    /// Create a new narrative document builder
    pub fn builder(signal_id: impl Into<String>) -> NarrativeDocBuilder {
        NarrativeDocBuilder::new(signal_id)
    }
}

/// Builder for NarrativeDoc
pub struct NarrativeDocBuilder {
    signal_id: String,
    version: u32,
    sentences: Vec<NarrativeSentence>,
    arbitration: Option<ArbitrationDoc>,
    disambiguation: Option<DisambiguationDoc>,
    mode_context: Option<ModeContext>,
}

impl NarrativeDocBuilder {
    pub fn new(signal_id: impl Into<String>) -> Self {
        Self {
            signal_id: signal_id.into(),
            version: 1,
            sentences: Vec::new(),
            arbitration: None,
            disambiguation: None,
            mode_context: None,
        }
    }

    pub fn version(mut self, v: u32) -> Self {
        self.version = v;
        self
    }

    pub fn add_observation(
        mut self,
        text: impl Into<String>,
        evidence_ptrs: Vec<EvidencePtr>,
        excerpts: Vec<DereferencedExcerpt>,
    ) -> Self {
        let idx = self.sentences.len() as u32;
        self.sentences.push(NarrativeSentence {
            sentence_id: format!("s_{}", idx),
            index: idx,
            text: text.into(),
            sentence_type: SentenceType::Observation,
            receipts: SentenceReceipts {
                evidence_ptrs,
                excerpts,
                supporting_facts: Vec::new(),
                supporting_slots: Vec::new(),
                claim_ids: Vec::new(),
                prior_sentence_ids: Vec::new(),
            },
            confidence: 1.0,
            user_actions: Vec::new(),
        });
        self
    }

    pub fn add_inference(
        mut self,
        text: impl Into<String>,
        supporting_facts: Vec<String>,
        supporting_slots: Vec<String>,
        confidence: f64,
    ) -> Self {
        let idx = self.sentences.len() as u32;
        self.sentences.push(NarrativeSentence {
            sentence_id: format!("s_{}", idx),
            index: idx,
            text: text.into(),
            sentence_type: SentenceType::Inference,
            receipts: SentenceReceipts {
                evidence_ptrs: Vec::new(),
                excerpts: Vec::new(),
                supporting_facts,
                supporting_slots,
                claim_ids: Vec::new(),
                prior_sentence_ids: Vec::new(),
            },
            confidence,
            user_actions: Vec::new(),
        });
        self
    }

    pub fn arbitration(mut self, arb: ArbitrationDoc) -> Self {
        self.arbitration = Some(arb);
        self
    }

    pub fn disambiguation(mut self, dis: DisambiguationDoc) -> Self {
        self.disambiguation = Some(dis);
        self
    }

    pub fn mode_context(mut self, ctx: ModeContext) -> Self {
        self.mode_context = Some(ctx);
        self
    }

    pub fn build(self) -> NarrativeDoc {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let narrative_id = format!("narr_{}_{}", self.signal_id, self.version);

        // Compute stats
        let mut stats = NarrativeStats {
            sentence_count: self.sentences.len(),
            observation_count: 0,
            inference_count: 0,
            evidence_ptr_count: 0,
            fact_count: 0,
            slot_count: 0,
        };

        let mut all_slots = std::collections::HashSet::new();
        for s in &self.sentences {
            match s.sentence_type {
                SentenceType::Observation => stats.observation_count += 1,
                SentenceType::Inference => stats.inference_count += 1,
                _ => {}
            }
            stats.evidence_ptr_count += s.receipts.evidence_ptrs.len();
            stats.fact_count += s.receipts.supporting_facts.len();
            for slot in &s.receipts.supporting_slots {
                all_slots.insert(slot.clone());
            }
        }
        stats.slot_count = all_slots.len();

        // Compute input hash for determinism
        let input_hash = compute_input_hash(&self.signal_id, self.version, &self.sentences);

        NarrativeDoc {
            narrative_id,
            signal_id: self.signal_id,
            version: self.version,
            sentences: self.sentences,
            arbitration: self.arbitration.unwrap_or_else(|| ArbitrationDoc {
                winner: None,
                runner_up: None,
                third: None,
                win_reasons: Vec::new(),
                runner_up_loss_reasons: Vec::new(),
                third_loss_reasons: Vec::new(),
                total_candidates: 0,
                arbitrated_at_ms: now_ms,
            }),
            disambiguation: self.disambiguation.unwrap_or_else(|| DisambiguationDoc {
                questions: Vec::new(),
                pivot_actions: Vec::new(),
                capability_suggestions: Vec::new(),
                ambiguity_score: 0.0,
            }),
            mode_context: self.mode_context.unwrap_or_else(|| ModeContext {
                mode: NarrativeMode::Discovery,
                mission_spec: None,
                playbooks_evaluated: Vec::new(),
                playbooks_filtered: Vec::new(),
            }),
            stats,
            generated_at_ms: now_ms,
            input_hash,
        }
    }
}

/// Compute deterministic hash of inputs
fn compute_input_hash(signal_id: &str, version: u32, sentences: &[NarrativeSentence]) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    signal_id.hash(&mut hasher);
    version.hash(&mut hasher);
    sentences.len().hash(&mut hasher);
    for s in sentences {
        s.text.hash(&mut hasher);
        s.receipts.evidence_ptrs.len().hash(&mut hasher);
        s.receipts.supporting_facts.len().hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

// ============================================================================
// Validation
// ============================================================================

/// Validation errors for narrative documents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeValidationError {
    pub sentence_id: Option<String>,
    pub error_type: NarrativeValidationErrorType,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NarrativeValidationErrorType {
    /// Observation sentence missing evidence pointers
    ObservationMissingEvidence,
    /// Inference sentence missing supporting facts/slots
    InferenceMissingSupportingData,
    /// Arbitration missing required hypotheses
    ArbitrationIncomplete,
    /// Mission mode active but no mission spec
    MissionModeMissingSpec,
}

impl NarrativeDoc {
    /// Validate that the narrative meets all requirements.
    /// Returns list of validation errors (empty = valid).
    pub fn validate(&self) -> Vec<NarrativeValidationError> {
        let mut errors = Vec::new();

        // Check each sentence
        for sentence in &self.sentences {
            match sentence.sentence_type {
                SentenceType::Observation => {
                    // Observations MUST have at least 1 evidence pointer
                    if sentence.receipts.evidence_ptrs.is_empty() {
                        errors.push(NarrativeValidationError {
                            sentence_id: Some(sentence.sentence_id.clone()),
                            error_type: NarrativeValidationErrorType::ObservationMissingEvidence,
                            message: format!(
                                "Observation sentence '{}' has no evidence pointers",
                                &sentence.text[..sentence.text.len().min(50)]
                            ),
                        });
                    }
                }
                SentenceType::Inference => {
                    // Inferences MUST have supporting facts OR slots
                    if sentence.receipts.supporting_facts.is_empty()
                        && sentence.receipts.supporting_slots.is_empty()
                    {
                        errors.push(NarrativeValidationError {
                            sentence_id: Some(sentence.sentence_id.clone()),
                            error_type:
                                NarrativeValidationErrorType::InferenceMissingSupportingData,
                            message: format!(
                                "Inference sentence '{}' has no supporting facts or slots",
                                &sentence.text[..sentence.text.len().min(50)]
                            ),
                        });
                    }
                }
                _ => {}
            }
        }

        // Check mission mode has spec
        if self.mode_context.mode == NarrativeMode::Mission
            && self.mode_context.mission_spec.is_none()
        {
            errors.push(NarrativeValidationError {
                sentence_id: None,
                error_type: NarrativeValidationErrorType::MissionModeMissingSpec,
                message: "Mission mode active but no mission spec provided".to_string(),
            });
        }

        errors
    }

    /// Check if this narrative is valid
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

impl Default for DisambiguationDoc {
    fn default() -> Self {
        Self {
            questions: Vec::new(),
            pivot_actions: Vec::new(),
            capability_suggestions: Vec::new(),
            ambiguity_score: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_narrative_validation_observation() {
        // Valid observation with evidence
        let narrative = NarrativeDoc::builder("sig_001")
            .add_observation(
                "Process cmd.exe was spawned.",
                vec![EvidencePtr {
                    stream_id: "process_exec".to_string(),
                    segment_id: 1,
                    record_index: 42,
                }],
                Vec::new(),
            )
            .build();

        assert!(narrative.is_valid());

        // Invalid observation without evidence - build manually
        let mut invalid = narrative.clone();
        invalid.sentences[0].receipts.evidence_ptrs.clear();
        let errors = invalid.validate();
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].error_type,
            NarrativeValidationErrorType::ObservationMissingEvidence
        );
    }

    #[test]
    fn test_narrative_validation_inference() {
        // Valid inference with supporting facts
        let narrative = NarrativeDoc::builder("sig_002")
            .add_inference(
                "This indicates potential lateral movement.",
                vec!["fact_001".to_string(), "fact_002".to_string()],
                vec!["slot_network".to_string()],
                0.85,
            )
            .build();

        assert!(narrative.is_valid());

        // Invalid inference without support - build manually
        let mut invalid = narrative.clone();
        invalid.sentences[0].receipts.supporting_facts.clear();
        invalid.sentences[0].receipts.supporting_slots.clear();
        let errors = invalid.validate();
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].error_type,
            NarrativeValidationErrorType::InferenceMissingSupportingData
        );
    }

    #[test]
    fn test_arbitration_doc() {
        let arb = ArbitrationDoc {
            winner: Some(RankedHypothesisDoc {
                hypothesis_id: "hyp_001".to_string(),
                playbook_id: "credential_lsass_access".to_string(),
                family: "credential_access".to_string(),
                rank_score: 0.92,
                slot_status: SlotStatusSummary {
                    required_total: 3,
                    required_filled: 3,
                    optional_total: 2,
                    optional_filled: 1,
                    slot_details: Vec::new(),
                },
                key_evidence: vec![EvidencePtr {
                    stream_id: "sysmon".to_string(),
                    segment_id: 1,
                    record_index: 100,
                }],
                missing_observables: Vec::new(),
                capability_gaps: Vec::new(),
                mitre_techniques: vec!["T1003.001".to_string()],
            }),
            runner_up: None,
            third: None,
            win_reasons: vec!["All required slots filled with high-confidence facts".to_string()],
            runner_up_loss_reasons: Vec::new(),
            third_loss_reasons: Vec::new(),
            total_candidates: 1,
            arbitrated_at_ms: chrono::Utc::now().timestamp_millis(),
        };

        assert!(arb.winner.is_some());
        assert_eq!(arb.winner.as_ref().unwrap().rank_score, 0.92);
    }
}

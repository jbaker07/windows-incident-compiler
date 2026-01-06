//! NarrativeBuilder: Synthesize NarrativeDoc from existing structured objects.
//!
//! This module builds evidence-cited narratives from:
//! - ExplanationBundle (slots, facts, evidence pointers)
//! - ArbitrationResponse (top-3 hypotheses)
//! - Capability registry (for gap analysis)
//!
//! CRITICAL: The narrative builder NEVER invents facts or evidence.
//! Every sentence must be derivable from existing objects.

use edr_core::{
    ArbitrationDoc, CapabilityGap, CapabilitySuggestion, DereferencedExcerpt, DisambiguationDoc,
    DisambiguationQuestion, EvidencePtr, ExplanationBundle, MissingObservable, MissionSpec,
    ModeContext, NarrativeDoc, NarrativeMode, NarrativeSentence, PivotAction, RankedHypothesisDoc,
    SentenceReceipts, SentenceType, SlotDetail, SlotStatus, SlotStatusSummary,
};
use std::collections::{HashMap, HashSet};

/// Builder that synthesizes NarrativeDoc from existing structured objects.
///
/// # Design Principle
/// The builder only uses data already present in:
/// - ExplanationBundle (from explanation_builder.rs)
/// - Slot fills and evidence pointers
/// - Capability registry metadata
///
/// It NEVER fabricates evidence or invents facts.
pub struct NarrativeBuilder {
    signal_id: String,
    explanation: Option<ExplanationBundle>,
    top3_hypotheses: Vec<HypothesisInput>,
    capability_registry: HashMap<String, CapabilityInfo>,
    mission_spec: Option<MissionSpec>,
    mode: NarrativeMode,
    telemetry_root: Option<std::path::PathBuf>,
}

/// Input for a hypothesis from ArbitrationResponse
#[derive(Debug, Clone)]
pub struct HypothesisInput {
    pub hypothesis_id: String,
    pub playbook_id: String,
    pub family: String,
    pub rank_score: f64,
    pub slot_fills: Vec<SlotFillInput>,
    pub evidence_ptrs: Vec<EvidencePtr>,
    pub mitre_techniques: Vec<String>,
}

/// Input for a slot fill
#[derive(Debug, Clone)]
pub struct SlotFillInput {
    pub slot_id: String,
    pub slot_name: String,
    pub required: bool,
    pub filled: bool,
    pub fact_ids: Vec<String>,
    pub evidence_ptrs: Vec<EvidencePtr>,
}

/// Capability info from registry
#[derive(Debug, Clone)]
pub struct CapabilityInfo {
    pub stream_id: String,
    pub description: String,
    pub enabled: bool,
    pub provides_fact_types: Vec<String>,
}

impl NarrativeBuilder {
    pub fn new(signal_id: impl Into<String>) -> Self {
        Self {
            signal_id: signal_id.into(),
            explanation: None,
            top3_hypotheses: Vec::new(),
            capability_registry: HashMap::new(),
            mission_spec: None,
            mode: NarrativeMode::Discovery,
            telemetry_root: None,
        }
    }

    /// Set the explanation bundle (required)
    pub fn with_explanation(mut self, explanation: ExplanationBundle) -> Self {
        self.explanation = Some(explanation);
        self
    }

    /// Add top-3 hypotheses for arbitration
    pub fn with_hypotheses(mut self, hypotheses: Vec<HypothesisInput>) -> Self {
        self.top3_hypotheses = hypotheses;
        self
    }

    /// Set capability registry for gap analysis
    pub fn with_capabilities(mut self, capabilities: HashMap<String, CapabilityInfo>) -> Self {
        self.capability_registry = capabilities;
        self
    }

    /// Set mission spec (switches to mission mode)
    pub fn with_mission(mut self, spec: MissionSpec) -> Self {
        self.mission_spec = Some(spec);
        self.mode = NarrativeMode::Mission;
        self
    }

    /// Set mode explicitly
    pub fn with_mode(mut self, mode: NarrativeMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set telemetry root for evidence dereference
    pub fn with_telemetry_root(mut self, path: std::path::PathBuf) -> Self {
        self.telemetry_root = Some(path);
        self
    }

    /// Build the narrative document
    pub fn build(self) -> NarrativeDoc {
        let explanation = self.explanation.as_ref();

        // Build sentences from explanation bundle
        let sentences = self.build_sentences(explanation);

        // Build arbitration doc from hypotheses
        let arbitration = self.build_arbitration_doc();

        // Build disambiguation doc
        let disambiguation = self.build_disambiguation_doc(explanation);

        // Build mode context
        let mode_context = self.build_mode_context(explanation);

        // Assemble final document by adding sentences using builder methods
        let mut builder = NarrativeDoc::builder(&self.signal_id);

        for sentence in sentences {
            match sentence.sentence_type {
                SentenceType::Observation => {
                    builder = builder.add_observation(
                        sentence.text,
                        sentence.receipts.evidence_ptrs,
                        sentence.receipts.excerpts,
                    );
                }
                SentenceType::Inference => {
                    builder = builder.add_inference(
                        sentence.text,
                        sentence.receipts.supporting_facts,
                        sentence.receipts.supporting_slots,
                        sentence.confidence,
                    );
                }
                _ => {
                    // For other types, use add_inference with empty supports
                    builder = builder.add_inference(
                        sentence.text,
                        Vec::new(),
                        Vec::new(),
                        sentence.confidence,
                    );
                }
            }
        }

        builder
            .arbitration(arbitration)
            .disambiguation(disambiguation)
            .mode_context(mode_context)
            .build()
    }

    /// Build sentences from explanation bundle.
    /// Each sentence is either an observation (with evidence ptrs) or inference (with supporting facts).
    fn build_sentences(&self, explanation: Option<&ExplanationBundle>) -> Vec<NarrativeSentence> {
        let mut sentences = Vec::new();
        let mut idx = 0u32;

        let Some(exp) = explanation else {
            // No explanation - return minimal narrative
            sentences.push(NarrativeSentence {
                sentence_id: format!("s_{}", idx),
                index: idx,
                text: "Signal detected but explanation unavailable.".to_string(),
                sentence_type: SentenceType::Context,
                receipts: SentenceReceipts::default(),
                confidence: 0.5,
                user_actions: Vec::new(),
            });
            return sentences;
        };

        // 1. Opening context sentence (from playbook metadata)
        sentences.push(NarrativeSentence {
            sentence_id: format!("s_{}", idx),
            index: idx,
            text: format!(
                "Playbook '{}' ({}) matched with {} slots filled.",
                exp.playbook_title,
                exp.family,
                exp.slots
                    .iter()
                    .filter(|s| s.status == SlotStatus::Filled)
                    .count()
            ),
            sentence_type: SentenceType::Context,
            receipts: SentenceReceipts::default(),
            confidence: 1.0,
            user_actions: Vec::new(),
        });
        idx += 1;

        // 2. For each filled slot, emit an observation sentence with evidence
        for slot in &exp.slots {
            if slot.status != SlotStatus::Filled && slot.status != SlotStatus::Partial {
                continue;
            }

            // Collect evidence pointers from matched facts
            let evidence_ptrs: Vec<EvidencePtr> = slot
                .matched_facts
                .iter()
                .flat_map(|f| f.evidence_ptrs.clone())
                .collect();

            if evidence_ptrs.is_empty() {
                // Skip if no evidence (shouldn't happen for filled slots)
                continue;
            }

            // Build observation sentence
            let fact_types: HashSet<_> = slot
                .matched_facts
                .iter()
                .map(|f| f.fact_type.as_str())
                .collect();
            let fact_types_str = fact_types.into_iter().collect::<Vec<_>>().join(", ");

            let text = format!(
                "{} slot '{}' satisfied by {} fact(s) of type [{}].",
                if slot.required {
                    "Required"
                } else {
                    "Optional"
                },
                slot.name,
                slot.matched_facts.len(),
                fact_types_str
            );

            // Build excerpts from evidence (if available)
            let excerpts = self.deref_evidence(&evidence_ptrs);

            sentences.push(NarrativeSentence {
                sentence_id: format!("s_{}", idx),
                index: idx,
                text,
                sentence_type: SentenceType::Observation,
                receipts: SentenceReceipts {
                    evidence_ptrs,
                    excerpts,
                    supporting_facts: slot
                        .matched_facts
                        .iter()
                        .map(|f| f.fact_id.clone())
                        .collect(),
                    supporting_slots: vec![slot.slot_id.clone()],
                    claim_ids: Vec::new(),
                    prior_sentence_ids: Vec::new(),
                },
                confidence: 1.0,
                user_actions: Vec::new(),
            });
            idx += 1;
        }

        // 3. If we have the summary, add it as inference with slot references
        if !exp.summary.is_empty() {
            let filled_slots: Vec<String> = exp
                .slots
                .iter()
                .filter(|s| s.status == SlotStatus::Filled)
                .map(|s| s.slot_id.clone())
                .collect();

            let fact_ids: Vec<String> = exp
                .slots
                .iter()
                .flat_map(|s| s.matched_facts.iter().map(|f| f.fact_id.clone()))
                .collect();

            sentences.push(NarrativeSentence {
                sentence_id: format!("s_{}", idx),
                index: idx,
                text: format!("INFERENCE: {}", exp.summary),
                sentence_type: SentenceType::Inference,
                receipts: SentenceReceipts {
                    evidence_ptrs: Vec::new(),
                    excerpts: Vec::new(),
                    supporting_facts: fact_ids,
                    supporting_slots: filled_slots,
                    claim_ids: Vec::new(),
                    prior_sentence_ids: (0..idx).map(|i| format!("s_{}", i)).collect(),
                },
                confidence: 0.85, // Inference confidence is lower than direct observation
                user_actions: Vec::new(),
            });
            idx += 1;
        }

        // 4. Add limitations as context sentences
        for limitation in &exp.limitations {
            sentences.push(NarrativeSentence {
                sentence_id: format!("s_{}", idx),
                index: idx,
                text: format!("LIMITATION: {}", limitation),
                sentence_type: SentenceType::Context,
                receipts: SentenceReceipts::default(),
                confidence: 1.0,
                user_actions: Vec::new(),
            });
            idx += 1;
        }

        sentences
    }

    /// Dereference evidence pointers to excerpts
    fn deref_evidence(&self, ptrs: &[EvidencePtr]) -> Vec<DereferencedExcerpt> {
        // NOTE: In production, this would read from telemetry_root/segments/
        // For now, we return placeholder excerpts indicating where to find the data
        ptrs.iter()
            .take(5) // Limit to 5 excerpts
            .map(|ptr| DereferencedExcerpt {
                ptr: ptr.clone(),
                excerpt: format!(
                    "[Evidence at stream={}, segment={}, record={}]",
                    ptr.stream_id, ptr.segment_id, ptr.record_index
                ),
                source: ptr.stream_id.clone(),
                ts_ms: 0, // Would be populated from actual record
            })
            .collect()
    }

    /// Build arbitration doc from hypotheses
    fn build_arbitration_doc(&self) -> ArbitrationDoc {
        let now_ms = chrono::Utc::now().timestamp_millis();

        if self.top3_hypotheses.is_empty() {
            return ArbitrationDoc {
                winner: None,
                runner_up: None,
                third: None,
                win_reasons: Vec::new(),
                runner_up_loss_reasons: Vec::new(),
                third_loss_reasons: Vec::new(),
                total_candidates: 0,
                arbitrated_at_ms: now_ms,
            };
        }

        // Sort by rank score descending
        let mut sorted = self.top3_hypotheses.clone();
        sorted.sort_by(|a, b| {
            b.rank_score
                .partial_cmp(&a.rank_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let build_ranked = |h: &HypothesisInput| -> RankedHypothesisDoc {
            let slot_status = SlotStatusSummary {
                required_total: h.slot_fills.iter().filter(|s| s.required).count(),
                required_filled: h
                    .slot_fills
                    .iter()
                    .filter(|s| s.required && s.filled)
                    .count(),
                optional_total: h.slot_fills.iter().filter(|s| !s.required).count(),
                optional_filled: h
                    .slot_fills
                    .iter()
                    .filter(|s| !s.required && s.filled)
                    .count(),
                slot_details: h
                    .slot_fills
                    .iter()
                    .map(|s| SlotDetail {
                        slot_id: s.slot_id.clone(),
                        slot_name: s.slot_name.clone(),
                        required: s.required,
                        filled: s.filled,
                        fact_count: s.fact_ids.len(),
                        evidence_ptr_count: s.evidence_ptrs.len(),
                    })
                    .collect(),
            };

            // Determine missing observables from unfilled required slots
            let missing_observables: Vec<MissingObservable> = h
                .slot_fills
                .iter()
                .filter(|s| s.required && !s.filled)
                .map(|s| MissingObservable {
                    description: format!("Slot '{}' not filled", s.slot_name),
                    expected_fact_type: "Unknown".to_string(), // Would come from playbook predicate
                    target_slot_id: Some(s.slot_id.clone()),
                    confidence_impact: 0.2,
                })
                .collect();

            // Capability gaps from registry
            let capability_gaps: Vec<CapabilityGap> = self
                .capability_registry
                .iter()
                .filter(|(_, info)| !info.enabled)
                .map(|(_, info)| CapabilityGap {
                    stream_id: info.stream_id.clone(),
                    description: info.description.clone(),
                    would_provide: info.provides_fact_types.clone(),
                    remediation: Some("Enable this telemetry source".to_string()),
                })
                .collect();

            RankedHypothesisDoc {
                hypothesis_id: h.hypothesis_id.clone(),
                playbook_id: h.playbook_id.clone(),
                family: h.family.clone(),
                rank_score: h.rank_score,
                slot_status,
                key_evidence: h.evidence_ptrs.clone(),
                missing_observables,
                capability_gaps,
                mitre_techniques: h.mitre_techniques.clone(),
            }
        };

        let winner = sorted.first().map(build_ranked);
        let runner_up = sorted.get(1).map(build_ranked);
        let third = sorted.get(2).map(build_ranked);

        // Build win/loss reasons from slot status comparison
        let mut win_reasons = Vec::new();
        let mut runner_up_loss_reasons = Vec::new();
        let mut third_loss_reasons = Vec::new();

        if let Some(w) = &winner {
            win_reasons.push(format!(
                "Highest rank score ({:.2}) with {}/{} required slots filled",
                w.rank_score, w.slot_status.required_filled, w.slot_status.required_total
            ));
            if !w.key_evidence.is_empty() {
                win_reasons.push(format!(
                    "{} evidence pointers supporting",
                    w.key_evidence.len()
                ));
            }
        }

        if let (Some(w), Some(r)) = (&winner, &runner_up) {
            if r.rank_score < w.rank_score {
                runner_up_loss_reasons.push(format!(
                    "Lower rank score ({:.2} vs {:.2})",
                    r.rank_score, w.rank_score
                ));
            }
            if r.slot_status.required_filled < w.slot_status.required_filled {
                runner_up_loss_reasons.push(format!(
                    "Fewer required slots filled ({} vs {})",
                    r.slot_status.required_filled, w.slot_status.required_filled
                ));
            }
            if !r.missing_observables.is_empty() {
                runner_up_loss_reasons.push(format!(
                    "{} missing observables",
                    r.missing_observables.len()
                ));
            }
        }

        if let (Some(w), Some(t)) = (&winner, &third) {
            if t.rank_score < w.rank_score {
                third_loss_reasons.push(format!(
                    "Lower rank score ({:.2} vs {:.2})",
                    t.rank_score, w.rank_score
                ));
            }
            if t.slot_status.required_filled < w.slot_status.required_filled {
                third_loss_reasons.push(format!(
                    "Fewer required slots filled ({} vs {})",
                    t.slot_status.required_filled, w.slot_status.required_filled
                ));
            }
        }

        ArbitrationDoc {
            winner,
            runner_up,
            third,
            win_reasons,
            runner_up_loss_reasons,
            third_loss_reasons,
            total_candidates: self.top3_hypotheses.len(),
            arbitrated_at_ms: now_ms,
        }
    }

    /// Build disambiguation doc from missing slots and capability gaps
    fn build_disambiguation_doc(
        &self,
        explanation: Option<&ExplanationBundle>,
    ) -> DisambiguationDoc {
        let mut questions = Vec::new();
        let mut pivot_actions = Vec::new();
        let mut capability_suggestions = Vec::new();
        let mut ambiguity_score = 0.0;

        // Calculate ambiguity from hypothesis spread
        if self.top3_hypotheses.len() >= 2 {
            let scores: Vec<f64> = self.top3_hypotheses.iter().map(|h| h.rank_score).collect();
            if scores.len() >= 2 {
                let spread = scores[0] - scores[1];
                ambiguity_score = 1.0 - spread.min(1.0);
            }
        }

        // Generate questions from unfilled slots
        if let Some(exp) = explanation {
            for (idx, slot) in exp.slots.iter().enumerate() {
                if slot.status == SlotStatus::Empty && slot.required {
                    questions.push(DisambiguationQuestion {
                        question_id: format!("q_{}", idx),
                        question_text: format!(
                            "What evidence would fill the '{}' slot ({})?",
                            slot.name, slot.predicate_desc
                        ),
                        resolves: "Would confirm or deny hypothesis match".to_string(),
                        affects_hypotheses: vec![exp.playbook_id.clone()],
                        investigation_steps: vec![
                            format!(
                                "Search for {} events in the time window",
                                slot.predicate_desc
                            ),
                            "Expand focus window if needed".to_string(),
                            "Check if telemetry source is enabled".to_string(),
                        ],
                        priority: 1,
                    });

                    // Add pivot action for this slot
                    pivot_actions.push(PivotAction {
                        action_id: format!("pivot_{}", idx),
                        label: format!("Search for {}", slot.name),
                        action_type: "search".to_string(),
                        params: {
                            let mut p = HashMap::new();
                            p.insert("slot_id".to_string(), serde_json::json!(slot.slot_id));
                            p.insert(
                                "predicate".to_string(),
                                serde_json::json!(slot.predicate_desc),
                            );
                            p
                        },
                        expected_outcome: format!("Find events matching {}", slot.predicate_desc),
                    });
                }
            }
        }

        // Generate capability suggestions from gaps
        for (stream_id, info) in &self.capability_registry {
            if !info.enabled {
                capability_suggestions.push(CapabilitySuggestion {
                    capability: stream_id.clone(),
                    how_to_enable: format!("Enable {} telemetry source", info.description),
                    would_resolve: info
                        .provides_fact_types
                        .iter()
                        .map(|t| format!("Missing {} facts", t))
                        .collect(),
                    detection_impact: "May improve detection coverage".to_string(),
                });
            }
        }

        DisambiguationDoc {
            questions,
            pivot_actions,
            capability_suggestions,
            ambiguity_score,
        }
    }

    /// Build mode context
    fn build_mode_context(&self, explanation: Option<&ExplanationBundle>) -> ModeContext {
        let playbooks_evaluated = explanation
            .map(|e| vec![e.playbook_id.clone()])
            .unwrap_or_default();

        // In mission mode, we would filter playbooks based on mission spec
        let playbooks_filtered = if self.mode == NarrativeMode::Mission {
            if let Some(_spec) = &self.mission_spec {
                // Playbooks not in allowed list would be filtered
                Vec::new() // Placeholder - would be populated by actual filtering logic
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        ModeContext {
            mode: self.mode,
            mission_spec: self.mission_spec.clone(),
            playbooks_evaluated,
            playbooks_filtered,
        }
    }
}

/// Convert from existing ArbitrationResponse to our HypothesisInput format
pub fn convert_arbitration_response(response: &serde_json::Value) -> Vec<HypothesisInput> {
    let mut inputs = Vec::new();

    // Parse top3 array from ArbitrationResponse
    if let Some(top3) = response.get("top3").and_then(|v| v.as_array()) {
        for hyp in top3 {
            let hypothesis_id = hyp
                .get("hypothesis_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            let playbook_id = hyp
                .get("playbook_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            let family = hyp
                .get("family")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            let rank_score = hyp
                .get("rank_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            // Parse slot fills if present
            let slot_fills = parse_slot_fills(hyp.get("slot_fills"));

            // Parse evidence pointers
            let evidence_ptrs = parse_evidence_ptrs(hyp.get("evidence_ptrs"));

            // Parse MITRE techniques
            let mitre_techniques = hyp
                .get("mitre_techniques")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            inputs.push(HypothesisInput {
                hypothesis_id,
                playbook_id,
                family,
                rank_score,
                slot_fills,
                evidence_ptrs,
                mitre_techniques,
            });
        }
    }

    inputs
}

fn parse_slot_fills(value: Option<&serde_json::Value>) -> Vec<SlotFillInput> {
    let Some(arr) = value.and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    arr.iter()
        .filter_map(|slot| {
            let slot_id = slot.get("slot_id")?.as_str()?.to_string();
            let slot_name = slot
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(&slot_id)
                .to_string();
            let required = slot
                .get("required")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let filled = slot
                .get("filled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let fact_ids = slot
                .get("fact_ids")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let evidence_ptrs = parse_evidence_ptrs(slot.get("evidence_ptrs"));

            Some(SlotFillInput {
                slot_id,
                slot_name,
                required,
                filled,
                fact_ids,
                evidence_ptrs,
            })
        })
        .collect()
}

fn parse_evidence_ptrs(value: Option<&serde_json::Value>) -> Vec<EvidencePtr> {
    let Some(arr) = value.and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    arr.iter()
        .filter_map(|ptr| {
            let stream_id = ptr.get("stream_id")?.as_str()?.to_string();
            let segment_id = ptr.get("segment_id")?.as_u64()?;
            let record_index = ptr.get("record_index")?.as_u64()? as u32;

            Some(EvidencePtr {
                stream_id,
                segment_id,
                record_index,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_narrative_builder_empty() {
        let builder = NarrativeBuilder::new("sig_001");
        let doc = builder.build();

        assert_eq!(doc.signal_id, "sig_001");
        assert!(!doc.sentences.is_empty()); // At least context sentence
        assert!(doc.arbitration.winner.is_none());
    }

    #[test]
    fn test_narrative_builder_with_hypotheses() {
        let hypotheses = vec![
            HypothesisInput {
                hypothesis_id: "hyp_001".to_string(),
                playbook_id: "credential_lsass_access".to_string(),
                family: "credential_access".to_string(),
                rank_score: 0.92,
                slot_fills: vec![SlotFillInput {
                    slot_id: "slot_1".to_string(),
                    slot_name: "LSASS Access".to_string(),
                    required: true,
                    filled: true,
                    fact_ids: vec!["fact_001".to_string()],
                    evidence_ptrs: vec![EvidencePtr {
                        stream_id: "sysmon".to_string(),
                        segment_id: 1,
                        record_index: 100,
                    }],
                }],
                evidence_ptrs: vec![EvidencePtr {
                    stream_id: "sysmon".to_string(),
                    segment_id: 1,
                    record_index: 100,
                }],
                mitre_techniques: vec!["T1003.001".to_string()],
            },
            HypothesisInput {
                hypothesis_id: "hyp_002".to_string(),
                playbook_id: "persistence_service".to_string(),
                family: "persistence".to_string(),
                rank_score: 0.75,
                slot_fills: Vec::new(),
                evidence_ptrs: Vec::new(),
                mitre_techniques: Vec::new(),
            },
        ];

        let builder = NarrativeBuilder::new("sig_001").with_hypotheses(hypotheses);
        let doc = builder.build();

        assert!(doc.arbitration.winner.is_some());
        let winner = doc.arbitration.winner.as_ref().unwrap();
        assert_eq!(winner.hypothesis_id, "hyp_001");
        assert_eq!(winner.rank_score, 0.92);
        assert!(!doc.arbitration.win_reasons.is_empty());
    }

    #[test]
    fn test_disambiguation_generation() {
        let mut capabilities = HashMap::new();
        capabilities.insert(
            "sysmon".to_string(),
            CapabilityInfo {
                stream_id: "sysmon".to_string(),
                description: "Sysmon Process Events".to_string(),
                enabled: true,
                provides_fact_types: vec!["ProcSpawn".to_string()],
            },
        );
        capabilities.insert(
            "etw_security".to_string(),
            CapabilityInfo {
                stream_id: "etw_security".to_string(),
                description: "Windows Security Events".to_string(),
                enabled: false,
                provides_fact_types: vec!["AuthEvent".to_string()],
            },
        );

        let builder = NarrativeBuilder::new("sig_001").with_capabilities(capabilities);
        let doc = builder.build();

        // Should have capability suggestion for disabled source
        assert!(!doc.disambiguation.capability_suggestions.is_empty());
        assert!(doc
            .disambiguation
            .capability_suggestions
            .iter()
            .any(|s| s.capability == "etw_security"));
    }
}

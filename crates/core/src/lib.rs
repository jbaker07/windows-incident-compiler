pub mod error;
pub mod event;
pub mod event_keys;
pub mod evidence_ptr;
pub mod explain;
pub mod narrative;
pub mod severity;
pub mod signal_result;

#[cfg(test)]
mod event_validation_test;

// ─────────────────────────────────────────────────────────────────────────────
// Pro feature gate
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` when the crate is compiled with the `pro` feature.
/// Use this for runtime checks; prefer `#[cfg(feature = "pro")]` for compile-time gating.
#[inline]
pub const fn pro_enabled() -> bool {
    cfg!(feature = "pro")
}

pub use error::{ErrorCode, ErrorReport};
pub use event::Event;
pub use evidence_ptr::EvidencePtr;
pub use explain::{
    EntityBundle, EvidenceExcerpt, ExplanationBundle, ExplanationBundleBuilder,
    ExplanationCounters, FactEntityKeys, MatchedFact, SlotExplanation, SlotStatus,
};
pub use narrative::{
    ArbitrationDoc, CapabilityGap, CapabilitySuggestion, DereferencedExcerpt, DisambiguationDoc,
    DisambiguationQuestion, ExpectedObservable, MissingObservable, MissionFocusWindow, MissionSpec,
    ModeContext, NarrativeDoc, NarrativeDocBuilder, NarrativeMode, NarrativeSentence,
    NarrativeStats, NarrativeValidationError, NarrativeValidationErrorType, PivotAction,
    RankedHypothesisDoc, SentenceReceipts, SentenceType, SlotDetail, SlotStatusSummary, UserAction,
    UserActionType,
};
pub use severity::Severity;
pub use signal_result::SignalResult;

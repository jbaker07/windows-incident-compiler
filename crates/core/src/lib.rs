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

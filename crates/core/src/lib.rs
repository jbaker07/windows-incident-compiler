pub mod error;
pub mod event;
pub mod event_keys;
pub mod evidence_ptr;
pub mod explain;
pub mod install_id;
pub mod license;
pub mod license_manager;
pub mod narrative;
pub mod severity;
pub mod signal_result;

// Pro-only modules (compile-time gated for code that's only needed in pro builds)
#[cfg(feature = "pro")]
pub mod diff;

#[cfg(test)]
mod event_validation_test;

// ─────────────────────────────────────────────────────────────────────────────
// License-based runtime feature gates (replaces compile-time pro feature)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` when the crate is compiled with the `pro` feature.
/// DEPRECATED: Use `license_manager::has_entitlement()` for runtime checks instead.
/// This function is kept for backward compatibility during the transition.
#[inline]
pub const fn pro_enabled() -> bool {
    cfg!(feature = "pro")
}

/// Check if diff mode is enabled via license entitlement.
/// This is the new runtime check that should replace `pro_enabled()`.
pub fn diff_mode_enabled() -> bool {
    license_manager::diff_mode_enabled()
}

pub use error::{ErrorCode, ErrorReport};
pub use event::Event;
pub use evidence_ptr::EvidencePtr;
pub use explain::{
    EntityBundle, EvidenceExcerpt, ExplanationBundle, ExplanationBundleBuilder,
    ExplanationCounters, FactEntityKeys, MatchedFact, SlotExplanation, SlotStatus,
};
pub use install_id::{
    get_edr_data_dir, get_install_id_path, get_license_path, get_or_create_install_id,
};
pub use license::{
    base64_encode, entitlements, LicensePayload, LicenseVerifyResult, SignedLicense,
    LICENSE_PUBLIC_KEY_B64,
};
pub use license_manager::{
    diff_mode_enabled as check_diff_mode, global_license_manager, has_entitlement, LicenseManager,
    LicenseStatus,
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
// Pro-only re-exports
#[cfg(feature = "pro")]
pub use diff::{
    diff_snapshots, ChangedSignal, DiffResult, DiffSignal, DiffSummary, FieldChange, SignalDelta,
    SignalSnapshot, SnapshotSignal,
};

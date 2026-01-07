pub mod error;
pub mod event;
pub mod event_keys;
pub mod evidence_ptr;
pub mod explain;
pub mod install_id;
pub mod license;
pub mod license_manager;
pub mod license_protection;
pub mod machine_fingerprint;
pub mod narrative;
pub mod severity;
pub mod signal_result;
pub mod watermark;

// Diff module: always compiled, runtime-gated via license entitlement
// (Previously compile-time gated, now "one binary" approach)
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
    base64_encode, entitlements, get_all_public_keys, LicensePayload, LicenseVerifyResult,
    SignedLicense, LICENSE_PUBLIC_KEYS_ROTATED, LICENSE_PUBLIC_KEY_B64,
};
pub use license_manager::{
    diff_mode_enabled as check_diff_mode, global_license_manager, has_entitlement, LicenseManager,
    LicenseStatus,
};
pub use machine_fingerprint::MachineFingerprint;
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

// Diff types: always available, usage is runtime-gated via license
pub use diff::{
    diff_snapshots, ChangedSignal, DiffResult, DiffSignal, DiffSummary, FieldChange, SignalDelta,
    SignalSnapshot, SnapshotSignal,
};

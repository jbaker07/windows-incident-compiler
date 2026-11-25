//! Hypothesis and Incident Detection System
//!
//! A deterministic, evidence-based system for detecting security incidents
//! with explainability, multi-OS support, and developer-laptop awareness.
//!
//! # Architecture Overview
//!
//! ```text
//! Events → Facts → Hypotheses → Incidents
//!    ↓        ↓         ↓            ↓
//! EvidencePtr  ScopeKey   Slots     Timeline
//!    ↓        ↓         ↓            ↓
//! Deref   Deterministic Promotion  Explain
//! ```
//!
//! # Key Concepts
//!
//! - **CanonicalEvent**: Unified event representation across OS platforms
//! - **EvidencePtr**: Cryptographic pointer to raw evidence (segment/record)
//! - **Fact**: Deterministic derived atom from events
//! - **ScopeKey**: Stable entity identifier surviving PID/handle reuse
//! - **HypothesisState**: State machine tracking attack pattern slots
//! - **Incident**: Promoted hypothesis with timeline and entity graph
//! - **Session**: Discovery or Mission mode with focus windows
//! - **Arbitration**: Top-3 ranking algorithm with absorption
//! - **Explanation**: Claims-based response with OS lexicon
//! - **Copilot**: Natural language rendering with citations (never invents facts)
//!
//! # Production Robustness Features
//!
//! - **Visibility**: Machine-readable collector health, drop rates, gaps
//! - **Ordering**: Deterministic event ordering with watermarks
//! - **Closure**: Clear incident lifecycle and closure semantics
//! - **Audit**: Trust/suppression changes with provenance and rollback
//! - **Versioning**: Component versioning for reproducible explanations
//! - **Changes**: Diff view for "no incident but something changed" UX
//!
//! # Hard Invariants (CRITICAL)
//!
//! - **Determinism**: Same input → byte-identical output (golden replay)
//! - **Global Ordering**: (ts_nanos, stream_id, segment_id, record_index) everywhere
//! - **Tier-0**: Memory RWX, credential access, etc. CANNOT be suppressed
//! - **Prompt Hardening**: Copilot cannot be steered by hostile inputs

pub mod api;
pub mod arbitration;
pub mod canonical_event;
pub mod canonical_fact;
pub mod command_alignment;
pub mod copilot;
pub mod disambiguator;
pub mod explanation;
pub mod hypothesis_state;
pub mod incident;
pub mod promotion;
pub mod scope_keys;
pub mod session;
pub mod storage;

// Production robustness modules
pub mod audit;
pub mod changes;
pub mod closure;
pub mod ordering;
pub mod versioning;
pub mod visibility;

// Hard invariant enforcement modules
pub mod determinism;
pub mod hardening;
pub mod tier0;

// Re-export core types
pub use api::{ApiError, ApiResponse, HypothesisApi};
pub use arbitration::{
    ArbitrationEngine, ArbitrationResponse, RankedHypothesis, SuppressedHypothesis,
    SuppressionReason,
};
pub use canonical_event::{
    CanonicalEvent, EvidencePtr, FileContext, NetworkContext, ProcessContext,
};
pub use canonical_fact::{Fact, FactDomain, FactStore, FactType};
pub use command_alignment::{CommandAlignmentResult, CommandCategory, CommandEvent};
pub use copilot::{CopilotAnswer, CopilotRequest, CopilotService, DefaultCopilot, OutputFormat};
pub use disambiguator::{generate_disambiguators, Disambiguator, PivotAction};
pub use explanation::{
    Claim, ClaimCertainty, ExplanationBuilder, ExplanationResponse, ExplanationVisibilityState,
    QueryContext,
};
pub use hypothesis_state::{HypothesisState, HypothesisStatus, Slot, SlotFill, SlotRequirement};
pub use incident::{Incident, IncidentStatus, IncidentStore, TimelineEntry, TimelineEntryKind};
pub use promotion::{
    calculate_confidence, calculate_maturity, check_promotion, PromotionDecision, Severity,
};
pub use scope_keys::{ProcScopeKeyBuilder, ScopeKey, UserScopeKeyBuilder};
pub use session::{AnalystAction, Assertion, Checkpoint, FocusWindow, Session, SessionMode};
pub use storage::{EventQuery, HypothesisQuery, HypothesisStorage, InMemoryStorage, IncidentQuery};

// Re-export production robustness types
pub use audit::{Actor, ActorType, AuditAction, AuditEntry, AuditEntryBuilder, AuditLog};
pub use changes::{
    ChangeDomain, ChangeTracker, ChangeType, ChangeWindow, DetectedChange, DiffEngine,
};
pub use closure::{
    ClosurePolicy, IncidentLifecycle, IncidentLifecycleState, LateEventResult, LifecycleManager,
};
pub use ordering::{
    EventMerger, EventOrderKey, GlobalWatermark, LateArrivalAction, LateArrivalAuditRecord,
    LateArrivalGate, LateArrivalPolicy, LateArrivalResult, StreamWatermark,
};
pub use versioning::{
    ComponentVersion, SessionConfigVersion, VersionDiff, VersionRegistry, VersionedExplanation,
};
pub use visibility::{
    CanClaimResult, CollectorHealth, CollectorStatus, CriticalGap, WindowVisibility,
};

// Re-export hard invariant types
pub use determinism::{
    DeterminismChecker, GlobalOrderKey, GoldenInputBundle, GoldenOutput, GoldenVerifyResult,
    StableKeyFormulas,
};
pub use hardening::{
    CopilotInputValidator, HardeningConfig, PivotValidator, SanitizedString, StringSanitizer,
};
pub use tier0::{SuppressionCheckResult, SuppressionChecker, SuppressionPolicy, Tier0Invariant};

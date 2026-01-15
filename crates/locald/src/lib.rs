//! EDR Local Detection Daemon
//!
//! The locald crate provides the signal detection and orchestration layer.
//! It processes Events from agents, runs detection logic, and persists signals.
//!
//! ## Architecture
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────────────┐
//!  │                         locald                              │
//!  │                                                             │
//!  │   ┌─────────────┐    ┌─────────────────┐    ┌───────────┐  │
//!  │   │  Pipeline   │───▶│  Orchestrator   │───▶│   Sinks   │  │
//!  │   │ (normalize) │    │ (detect/route)  │    │ (persist) │  │
//!  │   └─────────────┘    └────────┬────────┘    └───────────┘  │
//!  │                               │                             │
//!  │           ┌───────────────────┼───────────────────┐         │
//!  │           ▼                   ▼                   ▼         │
//!  │   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  │
//!  │   │ MacOS Engine  │  │ Linux Engine  │  │Windows Engine │  │
//!  │   └───────────────┘  └───────────────┘  └───────────────┘  │
//!  └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Feature Gating
//!
//! - `core` (default): Core detection loop only
//! - `integrations`: SIEM/vendor integrations

// ─────────────────────────────────────────────────────────────────────────────
// CORE modules: always compiled (required for core loop)
// ─────────────────────────────────────────────────────────────────────────────

pub mod os;
pub mod pipeline;
pub mod signal_orchestrator;
pub mod signal_result;

// Platform-agnostic modules
pub mod baseline;
pub mod playbook_loader;
pub mod playbook_manager;
pub mod scoring;
pub mod signal_persistence;

// Slot matcher: playbook slot matching engine
pub mod slot_matcher;
#[cfg(test)]
mod slot_matcher_tests;

// E2E integration tests for YAML playbook loading and firing
#[cfg(test)]
mod e2e_playbook_test;

// Evidence system with path safety (Ship Hardening)
pub mod evidence;

// Evidence dereference helper (for explainability)
pub mod evidence_deref;

// Explanation reason codes (for availability tracking)
pub mod explanation_reason;
// Explanation builder (for API responses)
pub mod explanation_builder;

// Credibility locks: path safety, namespace isolation, ZIP safety
pub mod safety;

// Hypothesis/Incident detection system (incident compiler)
pub mod hypothesis;

// HypothesisController: Runtime wiring for the incident compiler
pub mod hypothesis_controller;

// ─────────────────────────────────────────────────────────────────────────────
// NON-CORE modules: compile-time gated via Cargo features
// ─────────────────────────────────────────────────────────────────────────────

// Narrative builder: evidence-cited narration (Pro feature)
#[cfg(feature = "narrative")]
pub mod narrative_builder;

// Integration layer: export incidents + ingest third-party alerts
#[cfg(feature = "integrations")]
pub mod integrations;

// ─────────────────────────────────────────────────────────────────────────────
// CORE re-exports: always available
// ─────────────────────────────────────────────────────────────────────────────

pub use os::linux::LinuxSignalEngine;
pub use os::macos::MacOSSignalEngine;
pub use os::windows::WindowsSignalEngine;
pub use pipeline::{
    AsyncPipelineRunner, HttpSink, LogSink, MemorySink, Pipeline, PipelineStats, SignalSink,
    TelemetryInput,
};
pub use signal_orchestrator::{Platform, SignalOrchestrator};
pub use signal_result::{EvidenceRef, SignalResult};

// Re-export scoring and baseline types
pub use baseline::{BaselineQuery, BaselineStore, BaselineUpdater, HostBaseline};
pub use playbook_loader::{load_playbook_paths, Platform as PlaybookPlatform};
pub use scoring::{ScoredSignal, ScoringEngine};

// Re-export hypothesis controller
pub use hypothesis_controller::HypothesisController;

// Re-export slot matcher types
pub use slot_matcher::{
    CapabilityLevel, CapabilityRegistry, PlaybookDef, PlaybookIndex, PlaybookSlot, SlotMatcher,
    SlotPredicate,
};

// Re-export hypothesis types for incident compiler
pub use hypothesis::{
    // Arbitration and explanation
    ArbitrationEngine,
    ArbitrationResponse,
    // Core types
    CanonicalEvent,
    Claim,
    ClaimCertainty,
    // Visibility (production robustness)
    CollectorHealth,
    CollectorStatus,
    CriticalGap,
    DeterminismChecker,
    EvidencePtr,
    ExplanationBuilder,
    ExplanationResponse,
    Fact,
    FactDomain,
    FactStore,
    FactType,
    // Determinism
    GlobalOrderKey,
    GlobalWatermark,
    HypothesisState,
    HypothesisStatus,
    // Storage
    HypothesisStorage,
    InMemoryStorage,
    Incident,
    IncidentStatus,
    IncidentStore,
    LateArrivalAction,
    // Late arrival (Fix D)
    LateArrivalPolicy,
    RankedHypothesis,
    ScopeKey,
    Slot,
    SlotRequirement,
    SuppressedHypothesis,
    SuppressionReason,
    TimelineEntry,
    TimelineEntryKind,
    WindowVisibility,
};

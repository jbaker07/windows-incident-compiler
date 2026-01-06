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
//! ## Usage
//!
//! ```ignore
//! use edr_locald::{Pipeline, Platform, MemorySink};
//! use std::sync::Arc;
//!
//! let mut pipeline = Pipeline::new("hostname", Platform::MacOS);
//! pipeline.add_sink(Arc::new(MemorySink::new()));
//!
//! // Process telemetry from agents
//! let signals = pipeline.process(telemetry_input);
//! ```

pub mod os;
pub mod pipeline;
pub mod signal_orchestrator;
pub mod signal_result;

// Platform-agnostic modules
pub mod baseline;
pub mod playbook_loader;
pub mod scoring;
pub mod signal_persistence;

// Slot matcher: playbook slot matching engine
pub mod slot_matcher;
#[cfg(test)]
mod slot_matcher_tests;

// Evidence system with path safety (Ship Hardening)
pub mod evidence;

// Evidence dereference helper (for explainability)
pub mod evidence_deref;

// Explanation builder (for API responses)
pub mod explanation_builder;

// Narrative builder (evidence-cited narration)
pub mod narrative_builder;

// Credibility locks: path safety, namespace isolation, ZIP safety
pub mod safety;

// Hypothesis/Incident detection system (incident compiler)
// Uses path attribute to include from workspace root (legacy location)
#[path = "../../../locald/hypothesis/mod.rs"]
pub mod hypothesis;

// HypothesisController: Runtime wiring for the incident compiler
pub mod hypothesis_controller;

// Integration layer: export incidents + ingest third-party alerts
pub mod integrations;

// Main daemon - has legacy dependencies, skip for now
// pub mod edr_locald;

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

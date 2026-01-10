//! EDR Desktop Library
//! 
//! Re-exports for testing and potential library use
//!
//! Modules:
//! - `supervisor`: Process lifecycle management for capture, locald, server
//! - `grounded_gates`: GROUNDED 4-gate health validation (reads ONLY from disk/DB/API artifacts)
//! - `health_gates`: Legacy 4-gate health validation (for backward compat)
//! - `scenario_profiles`: Scenario profiles with expected outcomes for validation testing
//! - `logging`: Logging setup
//! - `port`: Port allocation
//! - `importer`: Safe import of evidence bundles (folders/zips)
//! - `import_types`: Types for import manifests and events
//! - `missions`: Mission types, profiles, and configurations
//! - `run_metrics`: Metrics collection and instrumentation
//! - `quality_gates`: Quality gate evaluation and regression engine
//! - `scenario_packs`: Windows scenario packs for mission execution
//! - `mission_commands`: Tauri commands for mission workflow
//! - `baseline`: Baseline run management and regression comparison
//! - `pipeline_counters`: Real-time counters from capture/locald/server

pub mod baseline;
pub mod grounded_gates;
pub mod health_gates;
pub mod importer;
pub mod import_types;
pub mod logging;
pub mod mission_commands;
pub mod missions;
pub mod pipeline_counters;
pub mod port;
pub mod quality_gates;
pub mod run_metrics;
pub mod scenario_packs;
pub mod scenario_profiles;
pub mod supervisor;

// Re-export commonly used types for bin crates
pub use importer::SafeImporter;
pub use import_types::ImportLimits;

// Re-export mission workflow types
pub use missions::{MissionConfig, MissionProfile, MissionType, CaptureProfile};
pub use run_metrics::{MetricsCollector, RunSummary};
pub use quality_gates::{QualityGatesEngine, QualityReport, GateResult, GateStatus};
pub use scenario_packs::{ScenarioPack, ScenarioCategory, PackExecutionResult};
pub use mission_commands::MissionStateHandle;
pub use baseline::{BaselineManager, BaselineMetadata, BaselineComparison};
pub use pipeline_counters::{PipelineCounters, PipelineCounterFetcher};

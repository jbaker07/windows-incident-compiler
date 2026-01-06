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

pub mod grounded_gates;
pub mod health_gates;
pub mod importer;
pub mod import_types;
pub mod logging;
pub mod port;
pub mod scenario_profiles;
pub mod supervisor;

// Re-export commonly used types for bin crates
pub use importer::SafeImporter;
pub use import_types::ImportLimits;

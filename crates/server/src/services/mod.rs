//! LocInt Service Layer
//!
//! This module contains the business logic extracted from locint.rs.
//! All services are pure functions or thin wrappers - the handler layer
//! in locint.rs calls these services.
//!
//! ## Module Structure
//!
//! - `run_control`: Run lifecycle (start/stop/status/metrics)
//! - `signals`: Signal queries, explainability, statistics
//! - `evidence`: Evidence dereference and segment access
//! - `diff`: Diff v2 with phase/baseline/marker modes
//! - `baseline`: Baseline management (Pro tier)
//! - `capability`: Capability model and detection plan
//! - `chains`: Micro chains registry and compilation (canonical backend source of truth)
//! - `export_import`: Bundle export/import and case packs
//! - `meta`: Route registry, contract, features, dataflow
//! - `packs`: Content pack discovery and validation
//! - `run_brief`: Run brief endpoint orchestrator (RUN_BRIEF-1)
//! - `run_brief_repo`: Database queries for run brief
//! - `episodes`: Episode clustering logic
//! - `evidence_ptrs`: Evidence pointer parsing utilities
//!
//! ## Design Principles
//!
//! 1. **No endpoint paths here** - routes defined in locint.rs router only
//! 2. **No tier gating here** - gates remain in handler layer
//! 3. **Pure business logic** - services return data, handlers format responses
//! 4. **Shared types** - common types exported from this mod.rs
//! 5. **Behavior preservation** - identical logic, just reorganized

pub mod baseline;
pub mod capability;
pub mod chains;
pub mod diff;
pub mod episodes;
pub mod evidence;
pub mod evidence_ptrs;
pub mod export_import;
pub mod meta;
pub mod packs;
pub mod run_brief;
pub mod run_brief_repo;
pub mod run_control;
pub mod signals;
pub mod types;

// Re-export commonly used types
pub use types::*;

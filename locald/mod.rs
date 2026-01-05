// locald/mod.rs
// Shared detection and signal runtime
// Ingests Events, runs detection engines, emits Signals/Incidents

pub mod edr_locald;
pub mod signal_orchestrator;
pub mod signal_persistence;
pub mod playbook_loader;
pub mod scoring;
pub mod baseline;
pub mod hypothesis;

#[path = "../locald/os/mod.rs"]
pub mod os;

pub use edr_locald::*;

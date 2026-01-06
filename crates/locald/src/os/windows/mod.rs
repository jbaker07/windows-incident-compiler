//! Windows-specific signal detection

pub mod fact_extractor;
pub mod playbooks;
pub mod signal_engine;
pub mod signals_windows;

pub use fact_extractor::extract_facts;
pub use playbooks::windows_playbooks;
pub use signal_engine::WindowsSignalEngine;

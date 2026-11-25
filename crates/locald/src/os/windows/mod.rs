//! Windows-specific signal detection

pub mod event_xml;
pub mod fact_extractor;
pub mod signal_engine;
pub mod signals_windows;

pub use event_xml::flatten_event_xml;
pub use fact_extractor::extract_facts;
pub use signal_engine::WindowsSignalEngine;

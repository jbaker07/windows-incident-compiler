//! Windows EDR Agent
//!
//! Captures security events from Windows Event Log, Sysmon, ETW,
//! and Defender sources.

pub mod telemetry;
pub mod telemetry_types;

pub mod bookmark_manager;
pub mod capture_windows_rotating;
pub mod config;
pub mod evtlog_state;
pub mod host;
pub mod self_test;
pub mod sensors;
pub mod wevt_bookmarks;
pub mod wevt_reader;

pub use sensors::*;
pub use telemetry::TelemetryRecord;
pub use telemetry_types::TelemetryOutput;

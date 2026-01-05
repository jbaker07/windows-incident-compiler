// windows/sensors/mod.rs
// Windows telemetry collectors + adapters → canonical core::Event
// Supports: Event Logs, Sysmon, ETW (feature-gated), Defender/AMSI

#[cfg(target_os = "windows")]
pub mod attack_surface;
pub mod collect;
pub mod defender_adapter;
pub mod primitives;
pub mod etw_adapter;
pub mod evtx_collector;
pub mod lateral_movement_monitor;
pub mod log_tamper_monitor;
pub mod powershell_monitor;
pub mod registry_monitor;
pub mod service_monitor;
pub mod sysmon_adapter;
pub mod sysmon_adapter_ext;
pub mod task_scheduler_monitor;
pub mod wmi_monitor;

pub use defender_adapter::DefenderAdapter;
pub use etw_adapter::EtwAdapter;
pub use evtx_collector::EvtxCollector;
pub use lateral_movement_monitor::LateralMovementMonitor;
pub use log_tamper_monitor::LogTamperMonitor;
pub use powershell_monitor::PowerShellMonitor;
pub use registry_monitor::RegistryMonitor;
pub use service_monitor::ServiceMonitor;
pub use sysmon_adapter::SysmonAdapter;
pub use sysmon_adapter_ext::SysmonAdapterExt;
pub use task_scheduler_monitor::TaskSchedulerMonitor;
pub use wmi_monitor::WmiMonitor;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Per-minute coverage rollup (for health/metrics)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRollup {
    pub minute_ts: DateTime<Utc>,
    pub host: String,
    pub sensor_kind: WindowsSensorKind,
    pub event_count: u64,
    pub error_count: u64,
    pub rate_limited_count: u64,
}

impl Default for CoverageRollup {
    fn default() -> Self {
        Self {
            minute_ts: Utc::now(),
            host: "unknown".to_string(),
            sensor_kind: WindowsSensorKind::Sysmon,
            event_count: 0,
            error_count: 0,
            rate_limited_count: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WindowsSensorKind {
    #[serde(rename = "windows_evtx")]
    EvtxLog,
    #[serde(rename = "windows_sysmon")]
    Sysmon,
    #[serde(rename = "windows_sysmon_ext")]
    SysmonExt,
    #[serde(rename = "windows_etw")]
    Etw,
    #[serde(rename = "windows_defender")]
    Defender,
    #[serde(rename = "windows_amsi")]
    Amsi,
    #[serde(rename = "windows_service")]
    Service,
    #[serde(rename = "windows_task_scheduler")]
    TaskScheduler,
    #[serde(rename = "windows_registry")]
    Registry,
    #[serde(rename = "windows_log_tamper")]
    LogTamper,
    #[serde(rename = "windows_lateral_movement")]
    LateralMovement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsCapabilityConfig {
    /// Enable Sysmon adapters if available
    pub enable_sysmon: bool,
    /// Enable extended Sysmon event handling (IDs 8, 10, 15, 17-21, 25, 26)
    pub enable_sysmon_ext: bool,
    /// Enable ETW collection (requires elevation; feature-gated)
    pub enable_etw: bool,
    /// Enable Defender/AMSI logs if present
    pub enable_defender: bool,
    /// Enable service monitoring (7045, 4697 events)
    pub enable_service_monitor: bool,
    /// Enable task scheduler monitoring (106, 140, 200 events)
    pub enable_task_scheduler: bool,
    /// Enable registry monitoring (Sysmon 12-14, registry events)
    pub enable_registry_monitor: bool,
    /// Enable log tampering detection (4688, 1102 events)
    pub enable_log_tamper_monitor: bool,
    /// Enable lateral movement detection (4624, 4769, 5140 events)
    pub enable_lateral_movement_monitor: bool,
    /// Rate limit for high-volume sources (events/sec)
    pub rate_limit: u32,
    /// Rate limit for ETW (events/sec) - typically much higher volume
    pub rate_limit_etw: u32,
    /// Rate limit for EVTX collection (events/sec)
    pub rate_limit_evtx: u32,
    /// Redact sensitive fields (PowerShell commands, etc.)
    pub redact_sensitive: bool,
}

impl Default for WindowsCapabilityConfig {
    fn default() -> Self {
        Self {
            enable_sysmon: true,
            enable_sysmon_ext: true,
            enable_etw: cfg!(feature = "windows_etw"),
            enable_defender: true,
            enable_service_monitor: true,
            enable_task_scheduler: true,
            enable_registry_monitor: true,
            enable_log_tamper_monitor: true,
            enable_lateral_movement_monitor: true,
            rate_limit: 1000,
            rate_limit_etw: 500,   // ETW can be very noisy
            rate_limit_evtx: 1000, // EVTX collected in batches
            redact_sensitive: true,
        }
    }
}

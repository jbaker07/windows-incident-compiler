//! Windows unified sensor collection
//! Calls all available monitors via gating, emits canonical events

use crate::host::HostCtx;
use edr_core::Event;

/// Collect events from all Windows sources with per-module gating, using a
/// reader that lives only for this call. Long running callers such as the
/// capture agent use `collect_all_with` so the read position carries over.
pub fn collect_all(host: &HostCtx) -> Vec<Event> {
    let mut reader = crate::wevt_reader::WevtReader::new();
    collect_all_with(&mut reader, host)
}

/// Collect events from all Windows sources with per-module gating. `reader`
/// keeps the per-channel read position and dedup state between calls.
pub fn collect_all_with(reader: &mut crate::wevt_reader::WevtReader, host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // EVTX-based sources (always try, but gated by config)
    events.extend(collect_evtx_events(reader, host));

    // Monitor-based sources (all gated)
    events.extend(collect_monitors(host));

    // Sort deterministically
    sort_events(&mut events);
    events
}

/// Collect EVTX events using real WEVTAPI reader
#[cfg_attr(not(target_os = "windows"), allow(unused_variables))]
fn collect_evtx_events(reader: &mut crate::wevt_reader::WevtReader, _host: &HostCtx) -> Vec<Event> {
    // `mut` is required on Windows (the WEVTAPI block below pushes/extends);
    // on other targets the collection stays empty, so the binding looks immutable.
    #[allow(unused_mut)]
    let mut events = Vec::new();

    #[cfg(target_os = "windows")]
    {
        // Poll WEVTAPI - returns Vec<WevtRecord> with NO EvidencePtr
        match reader.poll() {
            Ok(wevt_records) => {
                let polled = wevt_records.len();

                // Convert WevtRecord to core::Event with metadata but WITHOUT EvidencePtr
                // Metadata includes: windows.channel, windows.source_record_id (for dedup/debug)
                // EvidencePtr will be assigned in capture_windows_rotating.rs only (via segment state)
                for record in wevt_records {
                    let event = record.to_event();

                    // Normalize to attack surface events if applicable
                    #[cfg(target_os = "windows")]
                    {
                        let normalized =
                            crate::sensors::attack_surface::normalize_to_attack_surface(&event);
                        events.extend(normalized);
                    }

                    // Also keep raw event for full visibility
                    events.push(event);
                }

                if polled > 0 {
                    let stats = reader.stats();
                    eprintln!(
                        "[collect_evtx] Polled {} records ({} events after normalizing), totals: {} read, {} render failed",
                        polled,
                        events.len(),
                        stats.events_read_total,
                        stats.render_failed_total
                    );
                }
            }
            Err(e) => {
                eprintln!("[collect_evtx] WEVTAPI error: {}", e);
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Non-Windows: return empty (event logs not available)
    }

    events
}

fn collect_monitors(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Registry monitor
    if should_collect_module("registry_monitor") {
        events.extend(crate::sensors::registry_monitor::RegistryMonitor::collect(
            host,
        ));
    }

    // Service monitor
    if should_collect_module("service_monitor") {
        events.extend(crate::sensors::service_monitor::ServiceMonitor::collect(
            host,
        ));
    }

    // Task scheduler monitor
    if should_collect_module("task_scheduler_monitor") {
        events.extend(crate::sensors::task_scheduler_monitor::TaskSchedulerMonitor::collect(host));
    }

    // Log tamper monitor
    if should_collect_module("log_tamper_monitor") {
        events.extend(crate::sensors::log_tamper_monitor::LogTamperMonitor::collect(host));
    }

    // Lateral movement monitor
    if should_collect_module("lateral_movement_monitor") {
        events.extend(
            crate::sensors::lateral_movement_monitor::LateralMovementMonitor::collect(host),
        );
    }

    // PowerShell monitor
    if should_collect_module("powershell_monitor") {
        events.extend(crate::sensors::powershell_monitor::PowerShellMonitor::collect(host));
    }

    // WMI monitor
    if should_collect_module("wmi_monitor") {
        events.extend(crate::sensors::wmi_monitor::WmiMonitor::collect(host));
    }

    events
}

pub fn should_collect_module(module: &str) -> bool {
    let (should_poll, _cfg) = crate::config::should_poll(module);
    should_poll
}

pub fn should_collect_module_pub(module: &str) -> bool {
    should_collect_module(module)
}

fn sort_events(events: &mut [Event]) {
    events.sort_by_key(|a| a.ts_ms);
}

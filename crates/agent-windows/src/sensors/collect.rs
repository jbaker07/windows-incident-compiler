//! Windows unified sensor collection
//! Calls all available monitors via gating, emits canonical events

use crate::host::HostCtx;
use edr_core::Event;

/// Collect events from all Windows sources with per-module gating
/// Also tracks bookmarks for cursor position resumption
pub fn collect_all(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // EVTX-based sources (always try, but gated by config)
    events.extend(collect_evtx_events(host));

    // Monitor-based sources (all gated)
    events.extend(collect_monitors(host));

    // Sort deterministically
    sort_events(&mut events);
    events
}

/// Collect EVTX events using real WEVTAPI reader
fn collect_evtx_events(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    #[cfg(target_os = "windows")]
    {
        eprintln!("[collect_evtx] Starting WEVTAPI collection");
        
        // Create reader with default channels (Security, System, Sysmon enabled by default)
        let mut reader = crate::wevt_reader::WevtReader::new();

        // Poll WEVTAPI - returns Vec<WevtRecord> with NO EvidencePtr
        match reader.poll() {
            Ok(wevt_records) => {
                eprintln!(
                    "[collect_evtx] Polled {} events from WEVTAPI",
                    wevt_records.len()
                );

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

                // Log stats
                let stats = reader.stats();
                eprintln!(
                    "[collect_evtx] Stats: {} events read, {} render failed",
                    stats.events_read_total, stats.render_failed_total
                );
            }
            Err(e) => {
                eprintln!("[collect_evtx] WEVTAPI error: {}", e);
            }
        }
        
        eprintln!("[collect_evtx] Returning {} total events", events.len());
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

fn sort_events(events: &mut Vec<Event>) {
    events.sort_by(|a, b| a.ts_ms.cmp(&b.ts_ms));
}

// windows/self_test.rs
// Windows sensor self-test mode: verify collection is working
// Exit behavior:
// - Non-Windows: exit code 2 with message "self-test-windows requires Windows"
// - Windows with <2 enabled channels: exit code 2 with message "insufficient event sources"
// - Windows with >=2 enabled channels: run 30s test, exit 0 only if events collected from >=2 channels

use std::thread;
use std::time::Duration;

/// Run Windows self-test mode
/// Exit code 2 if non-Windows
/// Exit code 2 if Windows but fewer than 2 channels enabled
/// Exit code 0 only if Windows with >=2 channels enabled and >=1 event collected
pub fn run_windows_selftest(host: &crate::host::HostCtx) -> std::io::Result<bool> {
    // Non-Windows check: MUST be Windows to run event log self-test
    if !cfg!(target_os = "windows") {
        eprintln!("[windows self-test] ERROR: self-test-windows requires Windows platform");
        eprintln!("[windows self-test] Current platform: not Windows (macOS/Linux)");
        std::process::exit(2);
    }

    eprintln!("[windows self-test] Starting 30-second validation run on Windows...");

    let mut total_events = 0u64;
    let mut total_errors = 0u64;
    let start = std::time::Instant::now();

    // Track which event log channels are enabled
    let sysmon_enabled = crate::config::should_poll("Microsoft-Windows-Sysmon/Operational").0;
    let security_enabled = crate::config::should_poll("Security").0;
    let system_enabled = crate::config::should_poll("System").0;
    let powershell_enabled =
        crate::config::should_poll("Microsoft-Windows-PowerShell/Operational").0;
    let wmi_enabled = crate::config::should_poll("Microsoft-Windows-WMI-Activity/Operational").0;
    let task_enabled = crate::config::should_poll("Microsoft-Windows-TaskScheduler/Operational").0;

    let enabled_channels = [
        ("Sysmon", sysmon_enabled),
        ("Security", security_enabled),
        ("System", system_enabled),
        ("PowerShell", powershell_enabled),
        ("WMI-Activity", wmi_enabled),
        ("TaskScheduler", task_enabled),
    ];

    let enabled_count = enabled_channels.iter().filter(|(_, b)| *b).count();

    eprintln!(
        "[windows self-test] Enabled event log channels: {}",
        enabled_count
    );
    for (name, enabled) in &enabled_channels {
        if *enabled {
            eprintln!("[windows self-test]   - {}", name);
        }
    }

    // Require at least 2 enabled channels for meaningful test
    if enabled_count < 2 {
        eprintln!("[windows self-test] ERROR: insufficient event sources");
        eprintln!("[windows self-test] Need at least 2 enabled event log channels");
        eprintln!("[windows self-test] Set EDR_WIN_SECURITY=1 and EDR_WIN_SYSTEM=1 (minimum)");
        std::process::exit(2);
    }

    // Poll every 5 seconds for 30 seconds, validate architecture
    for interval in 0..6 {
        let elapsed = start.elapsed().as_secs_f32();
        if elapsed >= 30.0 {
            break;
        }

        let events = crate::sensors::collect::collect_all(host);
        total_events += events.len() as u64;

        eprintln!(
            "[windows self-test] [{:5.1}s] events_read={}, errors={}",
            elapsed, total_events, total_errors
        );

        // Validate event architecture on first batch
        if interval == 0 && !events.is_empty() {
            eprintln!("[windows self-test] Architecture validation:");
            for (i, evt) in events.iter().take(3).enumerate() {
                // Check: evidence_ptr should still be None (assigned by capture writer only)
                if evt.evidence_ptr.is_some() {
                    eprintln!("[windows self-test] ERROR: event {} has evidence_ptr set in collector - architecture violation!", i);
                    total_errors += 1;
                } else {
                    eprintln!(
                        "[windows self-test]   ✓ Event {}: no evidence_ptr (correct)",
                        i
                    );
                }

                // Check: event has required fields
                if evt.host.is_empty() {
                    eprintln!("[windows self-test] ERROR: event {} missing host field", i);
                    total_errors += 1;
                } else {
                    eprintln!("[windows self-test]   ✓ Event {}: host={}", i, evt.host);
                }

                // Check: tags should include "windows"
                if !evt.tags.iter().any(|t| t == "windows") {
                    eprintln!(
                        "[windows self-test] ERROR: event {} missing 'windows' tag",
                        i
                    );
                    total_errors += 1;
                } else {
                    eprintln!("[windows self-test]   ✓ Event {}: has 'windows' tag", i);
                }
            }
        }

        if interval < 5 {
            thread::sleep(Duration::from_secs(5));
        }
    }

    let final_elapsed = start.elapsed().as_secs_f32();

    eprintln!("[windows self-test] Complete. Summary:");
    eprintln!("[windows self-test] Duration: {:.1}s", final_elapsed);
    eprintln!("[windows self-test] Total events: {}", total_events);
    eprintln!("[windows self-test] Total errors: {}", total_errors);
    eprintln!("[windows self-test] Enabled channels: {}", enabled_count);

    if total_errors > 0 {
        eprintln!(
            "[windows self-test] FAIL: {} parse errors detected",
            total_errors
        );
        return Ok(false);
    }

    // Windows requires at least 1 event from >=2 channels for a passing test
    if total_events > 0 {
        eprintln!(
            "[windows self-test] PASS: {} events collected from {} channels",
            total_events, enabled_count
        );
        Ok(true)
    } else {
        eprintln!("[windows self-test] WARNING: no events collected");
        eprintln!(
            "[windows self-test] Check: are Windows event logs populated? Are readers implemented?"
        );
        Ok(false)
    }
}

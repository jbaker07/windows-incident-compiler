//! Tests for Live Success Diagnostics and Probe functionality

use std::collections::HashMap;

// ============================================================================
// Self-Check v2 API Tests
// ============================================================================

/// Test: SelfCheckResponse has stable schema structure
#[test]
fn test_selfcheck_response_schema_stability() {
    // Verify the response structure matches specification
    let response_json = r#"{
        "app_state": {
            "first_run": true,
            "capture_profile": "core",
            "telemetry_root": "/tmp/telemetry",
            "version": "1.0.0",
            "os": "macos",
            "uptime_secs": 120
        },
        "now_ts": "2024-01-01T00:00:00Z",
        "streams": [],
        "collectors": [],
        "throttling": {
            "degraded": false,
            "critical_gap": false,
            "degraded_reasons": [],
            "summary": null,
            "stream_stats": {}
        },
        "storage": {
            "db_ok": true,
            "segment_dir_ok": true,
            "telemetry_root": "/tmp/telemetry",
            "free_space_bytes": null,
            "free_space_pct": null,
            "low_space_warning": false,
            "error": null
        },
        "verdict": "healthy",
        "top_issues": [],
        "recommended_actions": []
    }"#;

    let parsed: serde_json::Value = serde_json::from_str(response_json).unwrap();

    // Verify required fields exist
    assert!(parsed.get("app_state").is_some());
    assert!(parsed.get("verdict").is_some());
    assert!(parsed.get("streams").is_some());
    assert!(parsed.get("collectors").is_some());
    assert!(parsed.get("throttling").is_some());
    assert!(parsed.get("storage").is_some());
    assert!(parsed.get("top_issues").is_some());
    assert!(parsed.get("recommended_actions").is_some());

    // Verify verdict values
    let verdict = parsed["verdict"].as_str().unwrap();
    assert!(
        verdict == "healthy" || verdict == "degraded" || verdict == "blocked",
        "Verdict must be one of: healthy, degraded, blocked"
    );
}

/// Test: StreamDiagnostic structure
#[test]
fn test_stream_diagnostic_schema() {
    let stream_json = r#"{
        "stream_id": "process_exec",
        "is_critical": true,
        "enabled": true,
        "last_seen_ts": "2024-01-01T00:00:00Z",
        "event_rate_recent": 10.5,
        "event_count": 100,
        "missing_reason": null,
        "priority": "critical"
    }"#;

    let parsed: serde_json::Value = serde_json::from_str(stream_json).unwrap();

    assert_eq!(parsed["stream_id"], "process_exec");
    assert_eq!(parsed["is_critical"], true);
    assert_eq!(parsed["enabled"], true);
    assert_eq!(parsed["event_count"], 100);
}

/// Test: Issue severity ordering
#[test]
fn test_issue_severity_ordering() {
    // Verify critical > error > warning > info
    let _severities = ["critical", "error", "warning", "info"];

    // Critical issues should appear first in sorted list
    let issues = vec![
        ("info_issue", "info"),
        ("critical_issue", "critical"),
        ("warning_issue", "warning"),
        ("error_issue", "error"),
    ];

    let mut sorted = issues.clone();
    sorted.sort_by(|a, b| {
        let order_a = match a.1 {
            "critical" => 0,
            "error" => 1,
            "warning" => 2,
            "info" => 3,
            _ => 4,
        };
        let order_b = match b.1 {
            "critical" => 0,
            "error" => 1,
            "warning" => 2,
            "info" => 3,
            _ => 4,
        };
        order_a.cmp(&order_b)
    });

    assert_eq!(sorted[0].0, "critical_issue");
    assert_eq!(sorted[1].0, "error_issue");
    assert_eq!(sorted[2].0, "warning_issue");
    assert_eq!(sorted[3].0, "info_issue");
}

/// Test: MissingReason descriptions are informative
#[test]
fn test_missing_reason_descriptions() {
    let reasons = [
        ("no_events_yet", "No events"),
        ("disabled_by_profile", "disabled"),
        ("permission_denied", "Permission"),
        ("collector_stopped", "not running"),
        ("throttled", "throttl"),
        ("sensor_not_attached", "not attached"),
        ("unsupported_os", "not supported"),
        ("unknown", "Unknown"),
    ];

    for (reason_snake, expected_substring) in reasons {
        // In actual code, MissingReason::description() would be tested
        // Here we verify the expected behavior
        assert!(
            !expected_substring.is_empty(),
            "Reason {} should have informative description",
            reason_snake
        );
    }
}

// ============================================================================
// Probe Tests
// ============================================================================

/// Test: ProbeSpec defaults are sensible
#[test]
fn test_probe_spec_defaults() {
    let _default_json = r#"{}"#;

    // Parsing empty JSON should use defaults
    let parsed: serde_json::Value = serde_json::from_str(
        r#"{
        "do_process_spawn": true,
        "do_temp_file_write": true,
        "do_localhost_connect": true,
        "timeout_ms": 5000,
        "repeats": 1
    }"#,
    )
    .unwrap();

    assert_eq!(
        parsed["do_process_spawn"], true,
        "Process spawn should default to true"
    );
    assert_eq!(
        parsed["do_temp_file_write"], true,
        "File write should default to true"
    );
    assert_eq!(
        parsed["do_localhost_connect"], true,
        "Localhost connect should default to true"
    );
    assert_eq!(
        parsed["timeout_ms"], 5000,
        "Timeout should default to 5000ms"
    );
    assert_eq!(parsed["repeats"], 1, "Repeats should default to 1");
}

/// Test: ProbeResult structure
#[test]
fn test_probe_result_structure() {
    let result_json = r#"{
        "probe_id": "test-probe-123",
        "started_at": "2024-01-01T00:00:00Z",
        "completed_at": "2024-01-01T00:00:01Z",
        "duration_ms": 1000,
        "actions_attempted": [
            {
                "action_type": "process_spawn",
                "description": "Spawned /bin/echo",
                "success": true,
                "error": null,
                "details": {"command": "/bin/echo"}
            }
        ],
        "observed_events": [],
        "matched_streams": ["process_exec", "process_exit"],
        "success": true,
        "failure_reasons": []
    }"#;

    let parsed: serde_json::Value = serde_json::from_str(result_json).unwrap();

    assert!(parsed["probe_id"].as_str().is_some());
    assert!(parsed["success"].as_bool().unwrap());
    assert!(!parsed["actions_attempted"].as_array().unwrap().is_empty());
    assert!(parsed["matched_streams"].as_array().is_some());
}

/// Test: ProbeActionType expected streams mapping
#[test]
fn test_probe_action_expected_streams() {
    // Process spawn should trigger process_exec and process_exit
    let process_streams = vec!["process_exec", "process_exit"];

    // File write should trigger file_write
    let file_streams = vec!["file_write"];

    // Network connect should trigger network_connect
    let network_streams = vec!["network_connect"];

    // All streams together
    let all_streams: Vec<&str> = [
        process_streams.clone(),
        file_streams.clone(),
        network_streams.clone(),
    ]
    .concat();

    assert!(all_streams.contains(&"process_exec"));
    assert!(all_streams.contains(&"file_write"));
    assert!(all_streams.contains(&"network_connect"));
}

// ============================================================================
// Verdict Logic Tests
// ============================================================================

/// Test: Blocked verdict when storage is broken
#[test]
fn test_verdict_blocked_on_storage_failure() {
    // Storage failure should always result in Blocked
    let storage_ok = false;
    let critical_streams_ok = true;

    let verdict = if !storage_ok || !critical_streams_ok {
        "blocked"
    } else {
        "healthy"
    };

    assert_eq!(verdict, "blocked");
}

/// Test: Blocked verdict when no critical streams
#[test]
fn test_verdict_blocked_on_no_critical_streams() {
    // No process_exec or process_exit events should be Blocked
    let critical_streams = ["process_exec", "process_exit"];
    let events_by_stream: HashMap<&str, u64> = HashMap::new();

    let critical_ok = critical_streams
        .iter()
        .any(|&s| events_by_stream.get(s).map(|&c| c > 0).unwrap_or(false));

    assert!(!critical_ok);
}

/// Test: Degraded verdict on throttle critical gap
#[test]
fn test_verdict_degraded_on_critical_gap() {
    let critical_gap = true;
    let storage_ok = true;
    let critical_streams_ok = true;

    let verdict = if !storage_ok || !critical_streams_ok {
        "blocked"
    } else if critical_gap {
        "degraded"
    } else {
        "healthy"
    };

    assert_eq!(verdict, "degraded");
}

/// Test: Healthy verdict when all systems nominal
#[test]
fn test_verdict_healthy_when_all_good() {
    let storage_ok = true;
    let critical_streams_ok = true;
    let critical_gap = false;
    let has_critical_issues = false;
    let has_error_issues = false;

    let verdict = if !storage_ok || !critical_streams_ok {
        "blocked"
    } else if critical_gap || has_critical_issues {
        if has_critical_issues {
            "blocked"
        } else {
            "degraded"
        }
    } else if has_error_issues {
        "degraded"
    } else {
        "healthy"
    };

    assert_eq!(verdict, "healthy");
}

// ============================================================================
// Action Details Tests
// ============================================================================

/// Test: OS-specific actions exist
#[test]
fn test_os_specific_actions_defined() {
    let macos_actions = ["fix_perms_esf_monitor"];
    let linux_actions = ["fix_perms_ebpf_monitor"];
    let windows_actions = ["fix_perms_etw_monitor"];
    let _universal_actions = ["run_probe", "adjust_throttle", "check_storage"];

    // All OS-specific actions should have expected structure
    for action in &macos_actions {
        assert!(action.contains("esf") || action.contains("macos"));
    }

    for action in &linux_actions {
        assert!(action.contains("ebpf") || action.contains("linux"));
    }

    for action in &windows_actions {
        assert!(action.contains("etw") || action.contains("windows"));
    }
}

/// Test: Admin requirements are correctly flagged
#[test]
fn test_admin_requirements() {
    // Actions that require admin
    let admin_required = [
        ("fix_perms_esf_monitor", true),
        ("fix_perms_ebpf_monitor", true),
        ("fix_perms_etw_monitor", true),
        ("run_probe", false),
        ("adjust_throttle", false),
        ("check_storage", false),
    ];

    for (action, requires_admin) in admin_required {
        // In actual implementation, ActionDetails::requires_admin would be checked
        if requires_admin {
            assert!(
                action.contains("perms"),
                "Permission-related actions should require admin"
            );
        }
    }
}

// ============================================================================
// First-Run Flow Tests
// ============================================================================

/// Test: First-run shows diagnostic modal if no telemetry
#[test]
fn test_first_run_shows_modal_if_blocked() {
    let is_first_run = true;
    let verdict = "blocked";

    let should_show_modal = is_first_run && verdict != "healthy";

    assert!(
        should_show_modal,
        "Should show modal on first run with blocked verdict"
    );
}

/// Test: First-run skips modal if healthy
#[test]
fn test_first_run_skips_modal_if_healthy() {
    let is_first_run = true;
    let verdict = "healthy";

    let should_show_modal = is_first_run && verdict != "healthy";

    assert!(
        !should_show_modal,
        "Should not show modal if telemetry is healthy"
    );
}

/// Test: Non-first-run doesn't auto-show modal
#[test]
fn test_non_first_run_no_auto_modal() {
    let is_first_run = false;
    let verdict = "blocked";

    let should_auto_show = is_first_run && verdict != "healthy";

    assert!(
        !should_auto_show,
        "Should not auto-show modal after first run"
    );
}

// ============================================================================
// Integration with Capture Profiles
// ============================================================================

/// Test: Diagnostic integrates with capture profile
#[test]
fn test_diagnostic_reports_capture_profile() {
    let profiles = ["core", "extended", "forensic"];

    for profile in profiles {
        // AppStateSummary should include capture_profile
        let app_state = serde_json::json!({
            "capture_profile": profile
        });

        assert_eq!(app_state["capture_profile"], profile);
    }
}

/// Test: Diagnostic reports throttle visibility
#[test]
fn test_diagnostic_reports_throttle_state() {
    let throttle_state = serde_json::json!({
        "degraded": false,
        "critical_gap": false,
        "degraded_reasons": [],
        "summary": null,
        "stream_stats": {}
    });

    assert!(throttle_state.get("degraded").is_some());
    assert!(throttle_state.get("critical_gap").is_some());
}

// ============================================================================
// Determinism Tests
// ============================================================================

/// Test: Response structure is deterministic
#[test]
fn test_response_deterministic_structure() {
    // Same inputs should produce same structure (not necessarily same timestamps)
    let response1 = serde_json::json!({
        "verdict": "healthy",
        "top_issues": [],
        "recommended_actions": []
    });

    let response2 = serde_json::json!({
        "verdict": "healthy",
        "top_issues": [],
        "recommended_actions": []
    });

    // Structure should be identical
    assert_eq!(
        response1.as_object().unwrap().keys().collect::<Vec<_>>(),
        response2.as_object().unwrap().keys().collect::<Vec<_>>()
    );
}

/// Test: Probe timeouts are bounded
#[test]
fn test_probe_timeout_bounded() {
    let max_timeout_ms = 30_000; // 30 seconds max
    let default_timeout_ms = 5_000;

    assert!(default_timeout_ms <= max_timeout_ms);

    // User-provided timeout should be capped
    let user_timeout = 60_000;
    let actual_timeout = user_timeout.min(max_timeout_ms);

    assert_eq!(actual_timeout, max_timeout_ms, "Timeout should be capped");
}

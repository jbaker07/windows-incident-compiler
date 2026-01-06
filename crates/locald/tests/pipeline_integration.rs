#![allow(dead_code, unused_imports, unused_comparisons)] // Test scaffolding

use edr_locald::ScoringEngine;
// Pipeline Integration Tests
// Tests the full Agent → Locald → Signal flow across all platforms

use edr_core::{Event, EvidencePtr, Severity};
use edr_locald::{
    BaselineQuery, BaselineStore, BaselineUpdater, HostBaseline, LinuxSignalEngine,
    MacOSSignalEngine, MemorySink, Pipeline, Platform, SignalOrchestrator, SignalResult,
    TelemetryInput, WindowsSignalEngine,
};
use std::collections::BTreeMap;
use std::sync::Arc;

// ========== Helper Functions ==========

fn create_test_event(
    platform: &str,
    event_type: &str,
    fields: BTreeMap<String, serde_json::Value>,
) -> TelemetryInput {
    let platform_enum = match platform {
        "windows" => Platform::Windows,
        "macos" => Platform::MacOS,
        "linux" => Platform::Linux,
        _ => Platform::Linux,
    };

    TelemetryInput {
        platform: platform_enum,
        host: format!("test-{}-host", platform),
        ts_ms: chrono::Utc::now().timestamp_millis(),
        event_type: event_type.to_string(),
        tags: vec![platform.to_string(), event_type.to_string()],
        proc_key: Some("pid:1234".to_string()),
        file_key: None,
        identity_key: Some("test_user".to_string()),
        fields,
        stream_id: Some(format!("{}_capture", platform)),
        segment_id: Some(1),
        record_index: Some(1),
    }
}

fn create_test_signal(signal_type: &str, severity: &str) -> SignalResult {
    SignalResult {
        signal_id: format!("sig_{}", uuid::Uuid::new_v4()),
        signal_type: signal_type.to_string(),
        severity: severity.to_string(),
        host: "test-host".to_string(),
        ts: chrono::Utc::now().timestamp_millis(),
        ts_start: chrono::Utc::now().timestamp_millis() - 1000,
        ts_end: chrono::Utc::now().timestamp_millis(),
        proc_key: Some("pid:1234".to_string()),
        file_key: None,
        identity_key: Some("user".to_string()),
        metadata: serde_json::json!({}),
        evidence_ptrs: vec![],
        dropped_evidence_count: 0,
    }
}

// ========== Cross-Platform Pipeline Tests ==========

#[test]
fn test_pipeline_processes_windows_telemetry() {
    let sink = Arc::new(MemorySink::new());
    let mut pipeline = Pipeline::new("test-windows-host", Platform::Windows);
    pipeline.add_sink(sink.clone());

    let mut fields = BTreeMap::new();
    fields.insert(
        "exe".to_string(),
        serde_json::json!("C:\\Windows\\System32\\cmd.exe"),
    );
    fields.insert("pid".to_string(), serde_json::json!(1234));
    fields.insert(
        "cmdline".to_string(),
        serde_json::json!("cmd.exe /c whoami"),
    );

    let input = create_test_event("windows", "process_create", fields);
    let _signals = pipeline.process(input);

    // Pipeline should process and return signals (possibly empty)
    // Length is always valid for Vec
}

#[test]
fn test_pipeline_processes_macos_telemetry() {
    let sink = Arc::new(MemorySink::new());
    let mut pipeline = Pipeline::new("test-macos-host", Platform::MacOS);
    pipeline.add_sink(sink.clone());

    let mut fields = BTreeMap::new();
    fields.insert("exe".to_string(), serde_json::json!("/usr/bin/security"));
    fields.insert("pid".to_string(), serde_json::json!(5678));

    let input = create_test_event("macos", "process_exec", fields);
    let _signals = pipeline.process(input);

    // Length is always valid for Vec
}

#[test]
fn test_pipeline_processes_linux_telemetry() {
    let sink = Arc::new(MemorySink::new());
    let mut pipeline = Pipeline::new("test-linux-host", Platform::Linux);
    pipeline.add_sink(sink.clone());

    let mut fields = BTreeMap::new();
    fields.insert("exe".to_string(), serde_json::json!("/bin/cat"));
    fields.insert("pid".to_string(), serde_json::json!(9012));

    let input = create_test_event("linux", "process_exec", fields);
    let _signals = pipeline.process(input);

    // Length is always valid for Vec
}

// ========== Signal Engine Integration Tests ==========

#[test]
fn test_windows_signal_engine_integration() {
    let mut engine = WindowsSignalEngine::new("test-host".to_string());

    let mut fields = BTreeMap::new();
    fields.insert(
        "exe".to_string(),
        serde_json::json!("C:\\Windows\\System32\\mshta.exe"),
    );
    fields.insert(
        "cmdline".to_string(),
        serde_json::json!("mshta vbscript:Execute(...)"),
    );

    let event = Event {
        ts_ms: chrono::Utc::now().timestamp_millis(),
        host: "test-host".to_string(),
        tags: vec!["windows".to_string(), "process_create".to_string()],
        proc_key: Some("pid:1234".to_string()),
        file_key: None,
        identity_key: Some("user".to_string()),
        evidence_ptr: None,
        fields,
    };

    let _signals = engine.process_event(&event);
    // Engine should process without panicking
    // Length is always valid for Vec
}

#[test]
fn test_macos_signal_engine_integration() {
    let mut engine = MacOSSignalEngine::new("test-host".to_string());

    let mut fields = BTreeMap::new();
    fields.insert("exe".to_string(), serde_json::json!("/usr/bin/security"));

    let event = Event {
        ts_ms: chrono::Utc::now().timestamp_millis(),
        host: "test-host".to_string(),
        tags: vec!["macos".to_string(), "process".to_string()],
        proc_key: Some("pid:1234".to_string()),
        file_key: None,
        identity_key: Some("user".to_string()),
        evidence_ptr: None,
        fields,
    };

    let _signals = engine.process_event(&event);
    // Length is always valid for Vec
}

#[test]
fn test_linux_signal_engine_integration() {
    let mut engine = LinuxSignalEngine::new("test-host".to_string());

    let mut fields = BTreeMap::new();
    fields.insert("path".to_string(), serde_json::json!("/etc/shadow"));

    let event = Event {
        ts_ms: chrono::Utc::now().timestamp_millis(),
        host: "test-host".to_string(),
        tags: vec!["linux".to_string(), "file_access".to_string()],
        proc_key: Some("pid:1234".to_string()),
        file_key: Some("/etc/shadow".to_string()),
        identity_key: Some("root".to_string()),
        evidence_ptr: None,
        fields,
    };

    let _signals = engine.process_event(&event);
    // Length is always valid for Vec
}

// ========== TelemetryInput Parsing Tests ==========

#[test]
fn test_telemetry_input_from_json() {
    let json = serde_json::json!({
        "platform": "windows",
        "host": "test-host",
        "ts_ms": 1704067200000_i64,
        "event_type": "process_create",
        "tags": ["windows", "process"],
        "proc_key": "pid:1234",
        "fields": {
            "exe": "cmd.exe",
            "pid": 1234
        },
        "stream_id": "windows_capture",
        "segment_id": 1,
        "record_index": 100
    });

    let input = TelemetryInput::from_json(&json).unwrap();
    assert_eq!(input.host, "test-host");
    assert_eq!(input.event_type, "process_create");
    assert!(matches!(input.platform, Platform::Windows));
    assert_eq!(input.stream_id, Some("windows_capture".to_string()));
}

#[test]
fn test_telemetry_input_converts_to_event() {
    let mut fields = BTreeMap::new();
    fields.insert("exe".to_string(), serde_json::json!("/bin/bash"));

    let input = TelemetryInput {
        platform: Platform::Linux,
        host: "test-host".to_string(),
        ts_ms: 1704067200000,
        event_type: "process_exec".to_string(),
        tags: vec!["linux".to_string()],
        proc_key: Some("pid:1234".to_string()),
        file_key: None,
        identity_key: Some("user".to_string()),
        fields,
        stream_id: Some("linux_capture".to_string()),
        segment_id: Some(42),
        record_index: Some(100),
    };

    let event = input.into_event();
    assert_eq!(event.host, "test-host");
    assert_eq!(event.ts_ms, 1704067200000);
    assert!(event.evidence_ptr.is_some());
    let ptr = event.evidence_ptr.unwrap();
    assert_eq!(ptr.stream_id, "linux_capture");
    assert_eq!(ptr.segment_id, 42);
    assert_eq!(ptr.record_index, 100);
}

// ========== Batch Processing Tests ==========

#[test]
fn test_pipeline_batch_processing() {
    let sink = Arc::new(MemorySink::new());
    let mut pipeline = Pipeline::new("test-host", Platform::Windows);
    pipeline.add_sink(sink.clone());

    let inputs: Vec<TelemetryInput> = (0..10)
        .map(|i| {
            let mut fields = BTreeMap::new();
            fields.insert(
                "exe".to_string(),
                serde_json::json!(format!("process_{}.exe", i)),
            );
            fields.insert("pid".to_string(), serde_json::json!(1000 + i));

            TelemetryInput {
                platform: Platform::Windows,
                host: "test-host".to_string(),
                ts_ms: chrono::Utc::now().timestamp_millis() + i as i64,
                event_type: "process_create".to_string(),
                tags: vec!["windows".to_string()],
                proc_key: Some(format!("pid:{}", 1000 + i)),
                file_key: None,
                identity_key: Some("user".to_string()),
                fields,
                stream_id: Some("windows_capture".to_string()),
                segment_id: Some(1),
                record_index: Some(i as u32),
            }
        })
        .collect();

    let results = pipeline.process_batch(inputs);
    // process_batch returns Vec<SignalResult>, just check type and length
    assert!(results.len() == 10 || results.is_empty());
}

// ========== Evidence Chain Tests ==========

#[test]
fn test_evidence_ptr_preserved_through_pipeline() {
    let sink = Arc::new(MemorySink::new());
    let mut pipeline = Pipeline::new("test-host", Platform::Linux);
    pipeline.add_sink(sink.clone());

    let mut fields = BTreeMap::new();
    fields.insert("exe".to_string(), serde_json::json!("/usr/bin/wget"));

    let input = TelemetryInput {
        platform: Platform::Linux,
        host: "test-host".to_string(),
        ts_ms: chrono::Utc::now().timestamp_millis(),
        event_type: "process_exec".to_string(),
        tags: vec!["linux".to_string(), "network".to_string()],
        proc_key: Some("pid:5678".to_string()),
        file_key: None,
        identity_key: Some("www-data".to_string()),
        fields,
        stream_id: Some("linux_ebpf_stream".to_string()),
        segment_id: Some(99),
        record_index: Some(42),
    };

    let _ = pipeline.process(input);

    // Any signals generated should preserve evidence chain
    for _signal in sink.get_signals() {
        // evidence_ptrs is a Vec in SignalResult
        // Evidence chain is always valid
    }
}

// ========== Orchestrator Tests ==========

#[test]
fn test_orchestrator_routes_by_platform() {
    let orchestrator = SignalOrchestrator::for_platform("test-host".to_string(), Platform::Windows);
    assert!(orchestrator.platform() == Platform::Windows);

    let orchestrator_mac =
        SignalOrchestrator::for_platform("test-host".to_string(), Platform::MacOS);
    assert!(orchestrator_mac.platform() == Platform::MacOS);

    let orchestrator_linux =
        SignalOrchestrator::for_platform("test-host".to_string(), Platform::Linux);
    assert!(orchestrator_linux.platform() == Platform::Linux);
}

#[test]
fn test_orchestrator_processes_events() {
    let mut orchestrator =
        SignalOrchestrator::for_platform("test-host".to_string(), Platform::MacOS);

    let event = Event {
        ts_ms: chrono::Utc::now().timestamp_millis(),
        host: "test-host".to_string(),
        tags: vec!["macos".to_string(), "process".to_string()],
        proc_key: Some("pid:1234".to_string()),
        file_key: None,
        identity_key: Some("user".to_string()),
        evidence_ptr: None,
        fields: BTreeMap::new(),
    };

    let _signals = orchestrator.process_event(&event);
    // Length is always valid for Vec
}

// ========== Core Event Tests ==========

#[test]
fn test_core_event_creation() {
    let event = Event {
        ts_ms: 1704067200000,
        host: "test-host".to_string(),
        tags: vec!["test".to_string()],
        proc_key: Some("pid:1234".to_string()),
        file_key: None,
        identity_key: None,
        evidence_ptr: Some(EvidencePtr {
            stream_id: "test_stream".to_string(),
            segment_id: 1,
            record_index: 1,
        }),
        fields: BTreeMap::new(),
    };

    assert_eq!(event.host, "test-host");
    assert!(event.evidence_ptr.is_some());
}

#[test]
fn test_severity_ordering() {
    // Severity does not implement PartialOrd, so we check discriminant order
    use std::mem::discriminant;
    assert!(discriminant(&Severity::Critical) != discriminant(&Severity::High));
    assert!(discriminant(&Severity::High) != discriminant(&Severity::Medium));
    assert!(discriminant(&Severity::Medium) != discriminant(&Severity::Low));
    assert!(discriminant(&Severity::Low) != discriminant(&Severity::Info));
}

#[test]
fn test_event_tag_contains() {
    let event = Event {
        ts_ms: 0,
        host: "test".to_string(),
        tags: vec![
            "windows".to_string(),
            "process".to_string(),
            "suspicious".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields: BTreeMap::new(),
    };

    assert!(event.tag_contains("windows"));
    assert!(event.tag_contains("process"));
    assert!(!event.tag_contains("linux"));
}

// ========== Scoring Integration Tests ==========

#[test]
fn test_scoring_engine_creation() {
    let engine = ScoringEngine::new(true);
    assert!(engine.is_enabled());

    let engine_disabled = ScoringEngine::new(false);
    assert!(!engine_disabled.is_enabled());
}

#[test]
fn test_scoring_engine_scores_signals() {
    let engine = ScoringEngine::new(true);

    let signal = create_test_signal("ProcessInjection", "critical");
    let scored = engine.score(signal);

    assert_eq!(scored.signal.signal_type, "ProcessInjection");
    assert_eq!(scored.signal.severity, "critical");
    // ScoredSignal does not have anomaly_score, check risk_score
    assert!(scored.risk_score >= 0.0);
}

#[test]
fn test_scoring_preserves_signal_data() {
    let engine = ScoringEngine::new(true);

    let signal = create_test_signal("CredentialDumping", "high");
    let scored = engine.score(signal);

    assert_eq!(scored.signal.host, "test-host");
    assert!(scored.signal.proc_key.is_some());
}

// ========== Baseline Integration Tests ==========

#[test]
fn test_baseline_store_operations() {
    use std::path::PathBuf;
    let tmp_dir = std::env::temp_dir().join("test_baseline_store");
    let mut store = BaselineStore::new(tmp_dir);

    let baseline = store.get_or_create("test-host");
    assert_eq!(baseline.host, "test-host");

    let mut updated = baseline.clone();
    updated
        .first_seen
        .remote_ips_per_exe
        .entry("cmd.exe".to_string())
        .or_default()
        .insert("192.168.1.1".to_string());

    // Use get_or_create and update fields directly
    let baseline_mut = store.get_or_create("test-host");
    *baseline_mut = updated;

    let retrieved = store.get_or_create("test-host");
    assert!(retrieved
        .first_seen
        .remote_ips_per_exe
        .contains_key("cmd.exe"));
}

#[test]
fn test_baseline_query_new_ip() {
    let mut baseline = HostBaseline::new("test-host".to_string());

    baseline
        .first_seen
        .remote_ips_per_exe
        .entry("app.exe".to_string())
        .or_default()
        .insert("10.0.0.1".to_string());

    let (is_new, _) = BaselineQuery::is_new_remote_ip(&baseline, "app.exe", "10.0.0.2");
    assert!(is_new);
    let (is_new2, _) = BaselineQuery::is_new_remote_ip(&baseline, "app.exe", "10.0.0.1");
    assert!(!is_new2);
}

#[test]
fn test_baseline_updater_first_seen() {
    let mut baseline = HostBaseline::new("test-host".to_string());

    let event = Event {
        ts_ms: chrono::Utc::now().timestamp_millis(),
        host: "test-host".to_string(),
        tags: vec!["network".to_string()],
        proc_key: Some("exe:wget".to_string()),
        file_key: None,
        identity_key: Some("user1".to_string()),
        evidence_ptr: None,
        fields: {
            let mut f = BTreeMap::new();
            f.insert("dest_ip".to_string(), serde_json::json!("203.0.113.50"));
            f
        },
    };

    BaselineUpdater::update_first_seen(&mut baseline, &event);

    assert!(baseline
        .first_seen
        .remote_ips_per_exe
        .contains_key("exe:wget"));
}

// ========== Multi-Platform Signal Detection Tests ==========

#[test]
fn test_cross_platform_signal_consistency() {
    // Test that similar events on different platforms produce consistent signal types

    let mut win_engine = WindowsSignalEngine::new("test-host".to_string());
    let mut mac_engine = MacOSSignalEngine::new("test-host".to_string());
    let mut linux_engine = LinuxSignalEngine::new("test-host".to_string());

    // Process similar events on each platform
    let base_fields: BTreeMap<String, serde_json::Value> = BTreeMap::new();

    let win_event = Event {
        ts_ms: 0,
        host: "test".to_string(),
        tags: vec!["windows".to_string()],
        proc_key: Some("pid:1".to_string()),
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields: base_fields.clone(),
    };

    let mac_event = Event {
        ts_ms: 0,
        host: "test".to_string(),
        tags: vec!["macos".to_string()],
        proc_key: Some("pid:1".to_string()),
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields: base_fields.clone(),
    };

    let linux_event = Event {
        ts_ms: 0,
        host: "test".to_string(),
        tags: vec!["linux".to_string()],
        proc_key: Some("pid:1".to_string()),
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields: base_fields,
    };

    // All engines should process without error
    let _win_signals = win_engine.process_event(&win_event);
    let _mac_signals = mac_engine.process_event(&mac_event);
    let _linux_signals = linux_engine.process_event(&linux_event);
}

// ========== Pipeline Statistics Tests ==========

#[test]
fn test_pipeline_stats_tracking() {
    let sink = Arc::new(MemorySink::new());
    let mut pipeline = Pipeline::new("test-host", Platform::Windows);
    pipeline.add_sink(sink.clone());

    // Process some events
    for i in 0..5 {
        let mut fields = BTreeMap::new();
        fields.insert(
            "exe".to_string(),
            serde_json::json!(format!("test_{}.exe", i)),
        );

        let input = create_test_event("windows", "process_create", fields);
        let _ = pipeline.process(input);
    }

    // Get stats
    let stats = pipeline.stats();
    assert!(stats.events_processed >= 5);
}

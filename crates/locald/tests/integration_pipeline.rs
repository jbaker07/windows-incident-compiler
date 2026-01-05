// Integration test: Agent → Locald → Server pipeline
// This test simulates an agent sending events to locald, which processes and forwards to the server.

use edr_locald::{MemorySink, Pipeline, Platform, TelemetryInput};
use std::sync::Arc;

#[test]
fn test_agent_to_locald_pipeline() {
    // Simulate a telemetry input from an agent
    // Simulate a WMI event to trigger WmiPersistenceConfirmed
    let input = TelemetryInput {
        platform: Platform::Windows,
        host: "test-host".to_string(),
        ts_ms: 1700000000000,
        event_type: "wmi_event".to_string(),
        tags: vec![
            "windows".to_string(),
            "wmi".to_string(),
            "filter".to_string(),
        ],
        proc_key: Some("wmi:filter:1234".to_string()),
        file_key: None,
        identity_key: Some("user1".to_string()),
        fields: [
            ("event_id".to_string(), serde_json::json!(19)),
            ("event_type".to_string(), serde_json::json!("filter")),
            ("user".to_string(), serde_json::json!("user1")),
        ]
        .into_iter()
        .collect(),
        stream_id: None,
        segment_id: None,
        record_index: None,
    };

    // Set up the locald pipeline
    let mut pipeline = Pipeline::new("test-host", Platform::Windows);
    let sink = Arc::new(MemorySink::new());
    pipeline.add_sink(sink.clone());

    // Process the event
    let signals = pipeline.process(input);
    assert!(
        !signals.is_empty(),
        "Pipeline should emit at least one signal"
    );

    // Check that the signal contains expected fields
    let signal = &signals[0];
    assert_eq!(signal.host, "test-host");
    assert_eq!(signal.signal_type, "WmiPersistenceConfirmed");
    assert!(
        signal.severity == "critical"
            || signal.severity == "high"
            || signal.severity == "medium"
            || signal.severity == "low"
    );
    assert!(signal.ts > 0);

    // Check that the sink received the signal
    let sink_signals = sink.get_signals();
    assert_eq!(sink_signals.len(), signals.len());
}

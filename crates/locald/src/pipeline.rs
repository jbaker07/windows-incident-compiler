//! Event Processing Pipeline
//!
//! This module provides the integration layer that connects:
//! - Agents (macOS, Linux, Windows) producing TelemetryRecords
//! - Locald signal detection engines
//! - Server for persistence and alerting
//!
//! ## Architecture
//!
//! ```text
//!  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//!  │   macOS     │     │   Linux     │     │  Windows    │
//!  │   Agent     │     │   Agent     │     │   Agent     │
//!  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
//!         │                   │                   │
//!         │  TelemetryRecord  │  TelemetryRecord  │
//!         └───────────────────┼───────────────────┘
//!                             │
//!                             ▼
//!                   ┌─────────────────┐
//!                   │    Pipeline     │
//!                   │  (normalize)    │
//!                   └────────┬────────┘
//!                            │
//!                            │ Event
//!                            ▼
//!                   ┌─────────────────┐
//!                   │   Orchestrator  │
//!                   │ (signal detect) │
//!                   └────────┬────────┘
//!                            │
//!                            │ SignalResult
//!                            ▼
//!                   ┌─────────────────┐
//!                   │   SignalSink    │
//!                   │ (persist/alert) │
//!                   └─────────────────┘
//! ```

use crate::{Platform, SignalOrchestrator, SignalResult};
use edr_core::{Event, EvidencePtr};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Represents a telemetry record from any agent
/// This is the common interface that agents should implement
#[derive(Debug, Clone)]
pub struct TelemetryInput {
    pub platform: Platform,
    pub host: String,
    pub ts_ms: i64,
    pub event_type: String,
    pub tags: Vec<String>,
    pub proc_key: Option<String>,
    pub file_key: Option<String>,
    pub identity_key: Option<String>,
    pub fields: BTreeMap<String, serde_json::Value>,
    /// Source segment for evidence chain
    pub stream_id: Option<String>,
    pub segment_id: Option<u64>,
    pub record_index: Option<u32>,
}

impl TelemetryInput {
    /// Convert to edr_core::Event for processing
    pub fn into_event(self) -> Event {
        let evidence_ptr = match (self.stream_id, self.segment_id, self.record_index) {
            (Some(stream), Some(seg), Some(idx)) => Some(EvidencePtr {
                stream_id: stream,
                segment_id: seg,
                record_index: idx,
            }),
            _ => None,
        };

        Event {
            ts_ms: self.ts_ms,
            host: self.host,
            tags: self.tags,
            proc_key: self.proc_key,
            file_key: self.file_key,
            identity_key: self.identity_key,
            evidence_ptr,
            fields: self.fields,
        }
    }

    /// Create from JSON (for network transport)
    pub fn from_json(json: &serde_json::Value) -> Result<Self, String> {
        let platform_str = json
            .get("platform")
            .and_then(|v| v.as_str())
            .ok_or("missing platform")?;

        let platform = match platform_str.to_lowercase().as_str() {
            "windows" => Platform::Windows,
            "macos" | "darwin" => Platform::MacOS,
            "linux" => Platform::Linux,
            _ => return Err(format!("unknown platform: {}", platform_str)),
        };

        let host = json
            .get("host")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let ts_ms = json
            .get("ts_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

        let event_type = json
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let tags: Vec<String> = json
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let mut fields = BTreeMap::new();
        if let Some(obj) = json.get("fields").and_then(|v| v.as_object()) {
            for (k, v) in obj {
                fields.insert(k.clone(), v.clone());
            }
        }

        Ok(Self {
            platform,
            host,
            ts_ms,
            event_type,
            tags,
            proc_key: json
                .get("proc_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            file_key: json
                .get("file_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            identity_key: json
                .get("identity_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            fields,
            stream_id: json
                .get("stream_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            segment_id: json.get("segment_id").and_then(|v| v.as_u64()),
            record_index: json
                .get("record_index")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
        })
    }
}

/// Trait for signal persistence and forwarding
pub trait SignalSink: Send + Sync {
    /// Persist or forward a batch of signals
    fn send(&self, signals: Vec<SignalResult>) -> Result<(), String>;

    /// Flush any buffered signals
    fn flush(&self) -> Result<(), String>;
}

/// In-memory signal sink for testing
pub struct MemorySink {
    signals: std::sync::Mutex<Vec<SignalResult>>,
}

impl MemorySink {
    pub fn new() -> Self {
        Self {
            signals: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn get_signals(&self) -> Vec<SignalResult> {
        self.signals.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.signals.lock().unwrap().clear();
    }
}

impl Default for MemorySink {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalSink for MemorySink {
    fn send(&self, signals: Vec<SignalResult>) -> Result<(), String> {
        self.signals.lock().unwrap().extend(signals);
        Ok(())
    }

    fn flush(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Logging sink that prints signals to stderr
pub struct LogSink {
    prefix: String,
}

impl LogSink {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
        }
    }
}

impl SignalSink for LogSink {
    fn send(&self, signals: Vec<SignalResult>) -> Result<(), String> {
        for signal in signals {
            eprintln!(
                "[{}] SIGNAL: {} ({}): host={} severity={}",
                self.prefix, signal.signal_type, signal.signal_id, signal.host, signal.severity
            );
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), String> {
        Ok(())
    }
}

/// HTTP sink that forwards signals to a server endpoint
pub struct HttpSink {
    endpoint: String,
    client: reqwest::Client,
}

impl HttpSink {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            client: reqwest::Client::new(),
        }
    }
}

impl SignalSink for HttpSink {
    fn send(&self, signals: Vec<SignalResult>) -> Result<(), String> {
        // Fire-and-forget async send
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();

        tokio::spawn(async move {
            let _ = client.post(&endpoint).json(&signals).send().await;
        });

        Ok(())
    }

    fn flush(&self) -> Result<(), String> {
        // HTTP sink is fire-and-forget, nothing to flush
        Ok(())
    }
}

/// The main event processing pipeline
pub struct Pipeline {
    orchestrator: SignalOrchestrator,
    sinks: Vec<Arc<dyn SignalSink>>,
    stats: PipelineStats,
}

#[derive(Debug, Default, Clone)]
pub struct PipelineStats {
    pub events_processed: u64,
    pub signals_generated: u64,
    pub errors: u64,
}

impl Pipeline {
    /// Create a new pipeline for a specific platform
    pub fn new(host: &str, platform: Platform) -> Self {
        let orchestrator = SignalOrchestrator::for_platform(host.to_string(), platform);
        Self {
            orchestrator,
            sinks: Vec::new(),
            stats: PipelineStats::default(),
        }
    }

    /// Add a signal sink
    pub fn add_sink(&mut self, sink: Arc<dyn SignalSink>) {
        self.sinks.push(sink);
    }

    /// Process a single telemetry input
    pub fn process(&mut self, input: TelemetryInput) -> Vec<SignalResult> {
        let event = input.into_event();
        let signals = self.orchestrator.process_event(&event);

        self.stats.events_processed += 1;
        self.stats.signals_generated += signals.len() as u64;

        // Send to all sinks
        for sink in &self.sinks {
            if let Err(e) = sink.send(signals.clone()) {
                eprintln!("[pipeline] sink error: {}", e);
                self.stats.errors += 1;
            }
        }

        signals
    }

    /// Process a batch of telemetry inputs
    pub fn process_batch(&mut self, inputs: Vec<TelemetryInput>) -> Vec<SignalResult> {
        let events: Vec<Event> = inputs.into_iter().map(|i| i.into_event()).collect();
        let signals = self.orchestrator.process_batch(&events);

        self.stats.events_processed += events.len() as u64;
        self.stats.signals_generated += signals.len() as u64;

        // Send to all sinks
        for sink in &self.sinks {
            if let Err(e) = sink.send(signals.clone()) {
                eprintln!("[pipeline] sink error: {}", e);
                self.stats.errors += 1;
            }
        }

        signals
    }

    /// Get pipeline statistics
    pub fn stats(&self) -> &PipelineStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = PipelineStats::default();
    }

    /// Flush all sinks
    pub fn flush(&self) -> Result<(), String> {
        for sink in &self.sinks {
            sink.flush()?;
        }
        Ok(())
    }
}

/// Async pipeline runner using channels
pub struct AsyncPipelineRunner {
    tx: mpsc::Sender<TelemetryInput>,
}

impl AsyncPipelineRunner {
    /// Start an async pipeline runner
    /// Returns the sender for submitting telemetry and a handle to the runner task
    pub fn start(
        host: String,
        platform: Platform,
        sinks: Vec<Arc<dyn SignalSink>>,
        buffer_size: usize,
    ) -> (Self, tokio::task::JoinHandle<PipelineStats>) {
        let (tx, mut rx) = mpsc::channel::<TelemetryInput>(buffer_size);

        let handle = tokio::spawn(async move {
            let mut pipeline = Pipeline::new(&host, platform);
            for sink in sinks {
                pipeline.add_sink(sink);
            }

            while let Some(input) = rx.recv().await {
                let _ = pipeline.process(input);
            }

            // Flush on shutdown
            let _ = pipeline.flush();
            pipeline.stats().clone()
        });

        (Self { tx }, handle)
    }

    /// Submit telemetry to the pipeline
    pub async fn submit(
        &self,
        input: TelemetryInput,
    ) -> Result<(), mpsc::error::SendError<TelemetryInput>> {
        self.tx.send(input).await
    }

    /// Check if the pipeline is still accepting input
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_input(platform: Platform, tags: Vec<&str>) -> TelemetryInput {
        let mut fields = BTreeMap::new();
        fields.insert("exe".to_string(), serde_json::json!("/tmp/test"));
        fields.insert("pid".to_string(), serde_json::json!(1234));

        TelemetryInput {
            platform,
            host: "TEST_HOST".to_string(),
            ts_ms: chrono::Utc::now().timestamp_millis(),
            event_type: "test".to_string(),
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            proc_key: Some("proc_1234".to_string()),
            file_key: None,
            identity_key: Some("user1".to_string()),
            fields,
            stream_id: Some("test_stream".to_string()),
            segment_id: Some(1),
            record_index: Some(0),
        }
    }

    #[test]
    fn test_telemetry_input_to_event() {
        let input = make_test_input(Platform::MacOS, vec!["process", "exec"]);
        let event = input.into_event();

        assert_eq!(event.host, "TEST_HOST");
        assert!(event.evidence_ptr.is_some());
        assert_eq!(event.tags, vec!["process", "exec"]);
    }

    #[test]
    fn test_pipeline_creation() {
        let pipeline = Pipeline::new("TEST_HOST", Platform::MacOS);
        assert_eq!(pipeline.stats().events_processed, 0);
    }

    #[test]
    fn test_pipeline_with_memory_sink() {
        let mut pipeline = Pipeline::new("TEST_HOST", Platform::MacOS);
        let sink = Arc::new(MemorySink::new());
        pipeline.add_sink(sink.clone());

        // Process a persistence event that should trigger a signal
        let mut input = make_test_input(Platform::MacOS, vec!["persistence", "launchd"]);
        input.fields.insert(
            "path".to_string(),
            serde_json::json!("/Library/LaunchDaemons/com.evil.plist"),
        );
        input.fields.insert(
            "target".to_string(),
            serde_json::json!("/usr/local/bin/evil"),
        );

        let signals = pipeline.process(input);

        assert_eq!(pipeline.stats().events_processed, 1);
        assert!(!signals.is_empty(), "Should generate persistence signal");
        assert_eq!(sink.get_signals().len(), signals.len());
    }

    #[test]
    fn test_pipeline_batch_processing() {
        let mut pipeline = Pipeline::new("TEST_HOST", Platform::Linux);
        let sink = Arc::new(MemorySink::new());
        pipeline.add_sink(sink.clone());

        let inputs = vec![
            make_test_input(Platform::Linux, vec!["process", "exec"]),
            make_test_input(Platform::Linux, vec!["file_read"]),
            make_test_input(Platform::Linux, vec!["network"]),
        ];

        let _ = pipeline.process_batch(inputs);
        assert_eq!(pipeline.stats().events_processed, 3);
    }

    #[test]
    fn test_telemetry_from_json() {
        let json = serde_json::json!({
            "platform": "windows",
            "host": "WIN-TEST",
            "ts_ms": 1234567890,
            "event_type": "process_create",
            "tags": ["process", "exec"],
            "fields": {
                "pid": 1234,
                "exe": "C:\\Windows\\System32\\cmd.exe"
            },
            "stream_id": "stream_001",
            "segment_id": 5,
            "record_index": 10
        });

        let input = TelemetryInput::from_json(&json).unwrap();
        assert_eq!(input.platform, Platform::Windows);
        assert_eq!(input.host, "WIN-TEST");
        assert_eq!(input.ts_ms, 1234567890);
        assert!(input.stream_id.is_some());
    }

    #[test]
    fn test_log_sink() {
        let sink = LogSink::new("TEST");
        let signals = vec![SignalResult::new("HOST", "TestSignal", "low", "entity1", 0)];
        assert!(sink.send(signals).is_ok());
    }
}

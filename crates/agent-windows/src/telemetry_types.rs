//! Telemetry output types for macOS detection modules
//!
//! These types are used by detection scanners to report findings.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Compact telemetry output used by detection modules.
/// `confidence` is a normalized value between 0.0 and 1.0.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelemetryOutput {
    /// Category of the detection (e.g., "network", "process", "persistence")
    pub category: String,
    /// Signal name (e.g., "dns_tunnel", "suspicious_port")
    pub signal: String,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f32,
    /// Flexible key-value data fields
    pub data: HashMap<String, String>,
}

impl TelemetryOutput {
    /// Create a new TelemetryOutput with empty data and confidence=0.0
    pub fn new(category: impl Into<String>, signal: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            signal: signal.into(),
            confidence: 0.0,
            data: HashMap::new(),
        }
    }

    /// Set confidence with tolerance for 0..1 or 0..100 (legacy callers).
    /// Values > 1.0 are interpreted as percentages and normalized.
    pub fn with_confidence(mut self, c: f32) -> Self {
        self.confidence = if c > 1.0 {
            (c / 100.0).clamp(0.0, 1.0)
        } else {
            c.clamp(0.0, 1.0)
        };
        self
    }

    /// Set confidence as a percentage (0..100).
    pub fn with_confidence_pct(mut self, pct: f32) -> Self {
        self.confidence = (pct / 100.0).clamp(0.0, 1.0);
        self
    }

    /// Add a single data key/value.
    pub fn with_kv(mut self, k: impl Into<String>, v: impl ToString) -> Self {
        self.data.insert(k.into(), v.to_string());
        self
    }

    /// Extend data with an iterator of (k, v).
    pub fn with_data<I, K, V>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: ToString,
    {
        for (k, v) in iter {
            self.data.insert(k.into(), v.to_string());
        }
        self
    }
}

/// Memory anomaly types for detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryAnomalyType {
    HighEntropy,
    SuspiciousAllocation,
    ShellcodePattern,
    UnmappedExecution,
    Unknown,
}

impl Default for MemoryAnomalyType {
    fn default() -> Self {
        MemoryAnomalyType::Unknown
    }
}

impl std::fmt::Display for MemoryAnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_output_builder() {
        let output = TelemetryOutput::new("process", "suspicious_spawn")
            .with_confidence(0.85)
            .with_kv("pid", 1234)
            .with_kv("exe", "/bin/bash");

        assert_eq!(output.category, "process");
        assert_eq!(output.signal, "suspicious_spawn");
        assert!((output.confidence - 0.85).abs() < 0.001);
        assert_eq!(output.data.get("pid"), Some(&"1234".to_string()));
    }

    #[test]
    fn test_confidence_normalization() {
        // 0..1 range stays as-is
        let o1 = TelemetryOutput::new("test", "test").with_confidence(0.5);
        assert!((o1.confidence - 0.5).abs() < 0.001);

        // > 1.0 is treated as percentage
        let o2 = TelemetryOutput::new("test", "test").with_confidence(75.0);
        assert!((o2.confidence - 0.75).abs() < 0.001);
    }
}

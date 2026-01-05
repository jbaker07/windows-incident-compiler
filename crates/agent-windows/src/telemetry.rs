//! Telemetry record types for macOS event processing
//!
//! TelemetryRecord represents a normalized process/event record
//! extracted from raw OpenBSM or EndpointSecurity events.

use serde::{Deserialize, Serialize};

/// Normalized telemetry record from OS-level events
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct TelemetryRecord {
    /// Event timestamp (Unix milliseconds)
    pub timestamp: u64,
    /// Process ID
    pub pid: i32,
    /// Parent process ID
    pub ppid: i32,
    /// User ID
    pub uid: u32,
    /// Binary path (e.g., /usr/bin/curl)
    pub binary_path: String,
    /// Full command line
    pub command_line: String,
    /// Current working directory
    pub cwd: String,
    /// Environment variables (optional)
    pub env_vars: Option<Vec<String>>,
    /// Event tags (e.g., ["exec", "network"])
    pub tags: Vec<String>,
    /// Risk score (0-100, optional)
    pub risk_score: Option<u32>,
}

impl TelemetryRecord {
    /// Create a new empty TelemetryRecord
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a TelemetryRecord with basic process info
    pub fn from_process(pid: i32, ppid: i32, uid: u32, binary_path: &str) -> Self {
        Self {
            pid,
            ppid,
            uid,
            binary_path: binary_path.to_string(),
            ..Default::default()
        }
    }

    /// Add a tag to this record
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set the timestamp
    pub fn with_timestamp(mut self, ts: u64) -> Self {
        self.timestamp = ts;
        self
    }

    /// Set the command line
    pub fn with_command_line(mut self, cmd: impl Into<String>) -> Self {
        self.command_line = cmd.into();
        self
    }

    /// Set the current working directory
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = cwd.into();
        self
    }

    /// Set the risk score
    pub fn with_risk_score(mut self, score: u32) -> Self {
        self.risk_score = Some(score.min(100));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_record_builder() {
        let record = TelemetryRecord::from_process(1234, 1000, 501, "/bin/bash")
            .with_tag("exec")
            .with_command_line("bash -c 'echo hello'")
            .with_cwd("/tmp")
            .with_timestamp(1700000000000)
            .with_risk_score(25);

        assert_eq!(record.pid, 1234);
        assert_eq!(record.ppid, 1000);
        assert_eq!(record.uid, 501);
        assert_eq!(record.binary_path, "/bin/bash");
        assert_eq!(record.tags, vec!["exec"]);
        assert_eq!(record.command_line, "bash -c 'echo hello'");
        assert_eq!(record.cwd, "/tmp");
        assert_eq!(record.risk_score, Some(25));
    }

    #[test]
    fn test_risk_score_clamping() {
        let record = TelemetryRecord::new().with_risk_score(150);
        assert_eq!(record.risk_score, Some(100));
    }
}

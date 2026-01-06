// locald/signal_persistence.rs
// Persist detected signals to JSONL file

use crate::SignalResult;
use std::fs::OpenOptions;
use std::io::Write;

pub struct SignalPersister {
    signals_path: String,
}

impl SignalPersister {
    pub fn new(telemetry_root: &str) -> Self {
        Self {
            signals_path: format!("{}/signals.jsonl", telemetry_root),
        }
    }

    /// Append signal to JSONL file
    pub fn persist(&self, signal: &SignalResult) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.signals_path)?;

        let line = serde_json::to_string(signal)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    /// Persist multiple signals
    pub fn persist_batch(&self, signals: &[SignalResult]) -> std::io::Result<()> {
        if signals.is_empty() {
            return Ok(());
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.signals_path)?;

        for signal in signals {
            let line = serde_json::to_string(signal)?;
            writeln!(file, "{}", line)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_persist_signal() {
        let tmpdir = TempDir::new().unwrap();
        let persister = SignalPersister::new(tmpdir.path().to_str().unwrap());

        let signal = SignalResult {
            signal_id: "test123".to_string(),
            signal_type: "TestSignal".to_string(),
            severity: "high".to_string(),
            host: "test_host".to_string(),
            ts: 1000000,
            ts_start: 999000,
            ts_end: 1001000,
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptrs: vec![],
            dropped_evidence_count: 0,
            metadata: serde_json::json!({}),
        };

        persister.persist(&signal).unwrap();

        let content =
            fs::read_to_string(format!("{}/signals.jsonl", tmpdir.path().display())).unwrap();
        assert!(content.contains("test123"));
        assert!(content.contains("TestSignal"));
    }
}

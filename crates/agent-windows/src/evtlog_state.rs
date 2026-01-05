// windows/evtlog_state.rs
// Windows event log state tracking - tracks read position per log channel
// Analogous to linux/capture_linux_rotating.rs but for Windows Event Logs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelReadState {
    pub channel: String,
    pub record_number: u64,
    pub last_event_ts: Option<DateTime<Utc>>,
    pub total_records_read: u64,
    pub read_errors: u64,
    pub last_poll_ts: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogReadState {
    pub version: u32,
    pub last_updated: DateTime<Utc>,
    pub channels: BTreeMap<String, ChannelReadState>,
}

impl EventLogReadState {
    pub fn new() -> Self {
        Self {
            version: 1,
            last_updated: Utc::now(),
            channels: BTreeMap::new(),
        }
    }

    pub fn load_from_file(path: &Path) -> std::io::Result<Self> {
        if path.exists() {
            let content = fs::read_to_string(path)?;
            let state: EventLogReadState = serde_json::from_str(&content)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            Ok(state)
        } else {
            Ok(Self::new())
        }
    }

    pub fn save_to_file(&self, path: &Path) -> std::io::Result<()> {
        let mut updated = self.clone();
        updated.last_updated = Utc::now();
        let content = serde_json::to_string_pretty(&updated)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn update_channel(
        &mut self,
        channel: &str,
        record_number: u64,
        event_ts: Option<DateTime<Utc>>,
    ) {
        let entry = self
            .channels
            .entry(channel.to_string())
            .or_insert_with(|| ChannelReadState {
                channel: channel.to_string(),
                record_number: 0,
                last_event_ts: None,
                total_records_read: 0,
                read_errors: 0,
                last_poll_ts: Utc::now(),
            });

        entry.record_number = record_number;
        if let Some(ts) = event_ts {
            entry.last_event_ts = Some(ts);
        }
        entry.total_records_read += 1;
        entry.last_poll_ts = Utc::now();
    }

    pub fn mark_read_error(&mut self, channel: &str) {
        let entry = self
            .channels
            .entry(channel.to_string())
            .or_insert_with(|| ChannelReadState {
                channel: channel.to_string(),
                record_number: 0,
                last_event_ts: None,
                total_records_read: 0,
                read_errors: 0,
                last_poll_ts: Utc::now(),
            });

        entry.read_errors += 1;
    }

    pub fn get_resume_record_number(&self, channel: &str) -> Option<u64> {
        self.channels.get(channel).map(|c| c.record_number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_log_read_state_new() {
        let state = EventLogReadState::new();
        assert_eq!(state.version, 1);
        assert!(state.channels.is_empty());
    }

    #[test]
    fn test_update_channel() {
        let mut state = EventLogReadState::new();
        state.update_channel("Security", 1000, Some(Utc::now()));

        assert!(state.channels.contains_key("Security"));
        let ch = &state.channels["Security"];
        assert_eq!(ch.record_number, 1000);
        assert_eq!(ch.total_records_read, 1);
    }

    #[test]
    fn test_mark_read_error() {
        let mut state = EventLogReadState::new();
        state.mark_read_error("System");
        state.mark_read_error("System");

        let ch = &state.channels["System"];
        assert_eq!(ch.read_errors, 2);
    }
}

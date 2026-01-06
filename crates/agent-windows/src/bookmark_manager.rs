//! Windows Event Log cursor statistics - STATS ONLY, NOT RESUMPTION
//!
//! ARCHITECTURE NOTE: This is NOT a real WEVTAPI bookmark manager yet.
//! It tracks cursor stats (event counts, timestamps) for telemetry/debugging only.
//!
//! Current implementation:
//! - Tracks event count + last timestamp per channel (stats only)
//! - Persists to JSON for observability
//! - Does NOT support resumption (no EvtUpdateBookmark/EvtSeek)
//!
//! To implement real resumption:
//! - Call EvtCreateBookmark() to get opaque XML from EvtQuery cursor
//! - Call EvtUpdateBookmark(bookmark, event_handle) for each event
//! - Call EvtSeek(query_handle, EvtSeekRelativeToBookmark, bookmark) on restart
//! - Until then: this is cursor observation only

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::ops::Deref;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelBookmark {
    pub channel_name: String,
    /// STATS ONLY: bookmark XML placeholder (not used for resumption yet)
    /// Kept for future EvtUpdateBookmark integration when real resume is implemented
    pub bookmark_xml: String,
    /// STATS ONLY: last record ID observed (for dedup/debug, not resumption)
    pub last_record_id: u64,
    /// STATS ONLY: Last successfully processed event timestamp (telemetry only)
    pub last_event_ts: Option<DateTime<Utc>>,
    /// STATS ONLY: Total events processed from this channel
    pub total_events: u64,
    /// STATS ONLY: Total parse errors observed
    pub total_errors: u64,
    /// STATS ONLY: Last update time
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BookmarkState {
    pub version: u32,
    pub bookmarks: BTreeMap<String, ChannelBookmark>,
}

impl Default for BookmarkState {
    fn default() -> Self {
        Self {
            version: 1,
            bookmarks: BTreeMap::new(),
        }
    }
}

pub struct BookmarkManager {
    state_file: PathBuf,
    state: RefCell<BookmarkState>,
}

impl Default for BookmarkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BookmarkManager {
    pub fn new() -> Self {
        // Default to temp telemetry root for development/testing
        let telemetry_root = std::env::temp_dir().join("telemetry");
        let _ = fs::create_dir_all(&telemetry_root);

        let state_file = telemetry_root.join("bookmark_state.json");
        let state = Self::load_state(&state_file).unwrap_or_default();

        Self {
            state_file,
            state: RefCell::new(state),
        }
    }

    pub fn with_telemetry_root(telemetry_root: &std::path::Path) -> Self {
        let state_file = telemetry_root.join("bookmark_state.json");
        let state = Self::load_state(&state_file).unwrap_or_default();

        Self {
            state_file,
            state: RefCell::new(state),
        }
    }

    #[cfg(test)]
    pub fn new_for_testing() -> Self {
        Self {
            state_file: PathBuf::from("/tmp/test_bookmark_state.json"),
            state: RefCell::new(BookmarkState::default()),
        }
    }

    fn load_state(path: &PathBuf) -> Result<BookmarkState, Box<dyn std::error::Error>> {
        if path.exists() {
            let content = fs::read_to_string(path)?;
            let state = serde_json::from_str(&content)?;
            Ok(state)
        } else {
            Ok(BookmarkState::default())
        }
    }

    pub fn save_state(&self) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_json::to_string_pretty(&self.state.borrow().deref())?;
        fs::write(&self.state_file, content)?;
        Ok(())
    }

    /// Get bookmark XML for resuming from last position
    /// STUB: Returns empty string (not used yet)
    /// Real implementation: EvtQuery would populate this via EvtUpdateBookmark
    pub fn get_bookmark(&self, channel: &str) -> Option<String> {
        self.state
            .borrow()
            .bookmarks
            .get(channel)
            .map(|b| b.bookmark_xml.clone())
    }

    /// Record cursor statistics (event count, last timestamp) after polling
    /// STATS ONLY: This does NOT implement real bookmark resumption
    ///
    /// Real resumption requires:
    /// - EvtUpdateBookmark(bookmark_handle, event_handle) during polling
    /// - EvtSeek(query_handle, EvtSeekRelativeToBookmark, bookmark) on restart
    ///
    /// Until those are implemented: this is cursor observation only (do NOT rely on for resumption)
    pub fn update_bookmark(
        &self,
        channel: &str,
        event_count: u64,
        event_ts: Option<DateTime<Utc>>,
    ) {
        let mut state = self.state.borrow_mut();
        let bm = state
            .bookmarks
            .entry(channel.to_string())
            .or_insert(ChannelBookmark {
                channel_name: channel.to_string(),
                bookmark_xml: String::new(),
                last_record_id: 0,
                last_event_ts: None,
                total_events: 0,
                total_errors: 0,
                updated_at: Utc::now(),
            });

        // Increment totals
        bm.total_events += event_count;
        if let Some(ts) = event_ts {
            bm.last_event_ts = Some(ts);
        }
        bm.updated_at = Utc::now();

        // Persist immediately to disk
        let _ = self.save_state();
    }

    pub fn get_stats(&self, channel: &str) -> Option<(u64, u64, Option<DateTime<Utc>>, u64)> {
        self.state.borrow().bookmarks.get(channel).map(|b| {
            (
                b.total_events,
                b.total_errors,
                b.last_event_ts,
                b.last_record_id,
            )
        })
    }

    /// Get the full path to the bookmark state file
    pub fn get_bookmark_path(&self) -> String {
        self.state_file.to_string_lossy().to_string()
    }

    /// Print per-channel bookmark statistics to stderr
    pub fn print_stats(&self) {
        let state = self.state.borrow();
        if state.bookmarks.is_empty() {
            eprintln!("[bookmark] No channels tracked yet");
            return;
        }

        for (channel, bm) in &state.bookmarks {
            let ts_str = bm
                .last_event_ts
                .map(|ts| ts.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "never".to_string());
            eprintln!(
                "[bookmark] {}: {} events, {} errors, last: {}",
                channel, bm.total_events, bm.total_errors, ts_str
            );
        }
    }
}

// windows/wevt_bookmarks.rs
// Real WEVTAPI bookmark persistence with atomic writes
// Stores channel-specific bookmark XML for resumption

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelBookmarkState {
    /// Real WEVTAPI bookmark XML for EvtCreateBookmark/EvtSeek
    pub bookmark_xml: String,
    /// Last event timestamp from this channel (informational)
    pub last_event_ts: Option<DateTime<Utc>>,
    /// Last source_record_id seen (diagnostic, for dedup)
    pub last_source_record_id: Option<u64>,
    /// Total events successfully processed from this channel
    pub total_events_processed: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BookmarkState {
    pub version: u32,
    pub bookmarks: BTreeMap<String, ChannelBookmarkState>,
}

impl Default for BookmarkState {
    fn default() -> Self {
        Self {
            version: 1,
            bookmarks: BTreeMap::new(),
        }
    }
}

pub struct WevtBookmarkManager {
    state_file: PathBuf,
    state: Mutex<BookmarkState>,
}

impl WevtBookmarkManager {
    pub fn new(state_file: PathBuf) -> Self {
        let state = Self::load_state(&state_file).unwrap_or_default();

        Self {
            state_file,
            state: std::sync::Mutex::new(state),
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

    pub fn get_bookmark_xml(&self, channel: &str) -> String {
        self.state
            .lock()
            .unwrap()
            .bookmarks
            .get(channel)
            .map(|b| b.bookmark_xml.clone())
            .unwrap_or_default()
    }

    pub fn set_bookmark(
        &self,
        channel: &str,
        bookmark_xml: &str,
        last_source_record_id: Option<u64>,
    ) {
        let mut state = self.state.lock().unwrap();
        state
            .bookmarks
            .entry(channel.to_string())
            .and_modify(|b| {
                b.bookmark_xml = bookmark_xml.to_string();
                b.last_event_ts = Some(Utc::now());
                b.last_source_record_id = last_source_record_id;
                b.total_events_processed += 1;
            })
            .or_insert_with(|| ChannelBookmarkState {
                bookmark_xml: bookmark_xml.to_string(),
                last_event_ts: Some(Utc::now()),
                last_source_record_id,
                total_events_processed: 1,
            });

        // Persist after every update
        drop(state); // Release lock before writing
        let _ = self.save_state();
    }

    fn save_state(&self) -> Result<(), Box<dyn std::error::Error>> {
        let state = self.state.lock().unwrap();
        let content = serde_json::to_string_pretty(&*state)?;
        let tmp_file = self.state_file.with_extension("tmp");
        fs::write(&tmp_file, content)?;
        fs::rename(&tmp_file, &self.state_file)?;
        Ok(())
    }

    pub fn get_stats(&self, channel: &str) -> Option<(u64, Option<DateTime<Utc>>, Option<u64>)> {
        self.state.lock().unwrap().bookmarks.get(channel).map(|b| {
            (
                b.total_events_processed,
                b.last_event_ts,
                b.last_source_record_id,
            )
        })
    }
}

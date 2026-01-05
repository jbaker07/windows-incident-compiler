// workbench/session.rs
// Capture session management - start/stop, markers, state

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use uuid::Uuid;

/// Capture session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSession {
    pub id: String,
    pub state: SessionState,
    pub started_at: Option<u64>,
    pub stopped_at: Option<u64>,

    // Capture stats
    pub events_captured: u64,
    pub markers: Vec<Marker>,

    // Linked document
    pub document_id: Option<String>,

    // Recent terminal commands (if captured)
    pub terminal_history: VecDeque<TerminalCommand>,

    // Recent browser activity (if captured)
    pub browser_history: VecDeque<BrowserActivity>,
}

impl CaptureSession {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            state: SessionState::Idle,
            started_at: None,
            stopped_at: None,
            events_captured: 0,
            markers: vec![],
            document_id: None,
            terminal_history: VecDeque::with_capacity(100),
            browser_history: VecDeque::with_capacity(100),
        }
    }

    pub fn start(&mut self) {
        self.state = SessionState::Capturing;
        self.started_at = Some(now_ms());
        self.stopped_at = None;
        self.events_captured = 0;
    }

    pub fn stop(&mut self) {
        self.state = SessionState::Stopped;
        self.stopped_at = Some(now_ms());
    }

    pub fn pause(&mut self) {
        self.state = SessionState::Paused;
    }

    pub fn resume(&mut self) {
        self.state = SessionState::Capturing;
    }

    pub fn add_marker(&mut self, marker_type: MarkerType, note: Option<String>) {
        self.markers.push(Marker {
            id: Uuid::new_v4().to_string(),
            timestamp: now_ms(),
            marker_type,
            note,
        });
    }

    pub fn is_capturing(&self) -> bool {
        matches!(self.state, SessionState::Capturing)
    }

    pub fn add_terminal_command(&mut self, cmd: TerminalCommand) {
        if self.terminal_history.len() >= 100 {
            self.terminal_history.pop_front();
        }
        self.terminal_history.push_back(cmd);
    }

    pub fn add_browser_activity(&mut self, activity: BrowserActivity) {
        if self.browser_history.len() >= 100 {
            self.browser_history.pop_front();
        }
        self.browser_history.push_back(activity);
    }
}

impl Default for CaptureSession {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Idle,      // Not started
    Capturing, // Actively capturing
    Paused,    // Temporarily paused
    Stopped,   // Finished
}

/// User-placed marker during capture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Marker {
    pub id: String,
    pub timestamp: u64,
    pub marker_type: MarkerType,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarkerType {
    Important,   // "Mark Important" button
    PhaseStart,  // Start of attack phase
    PhaseEnd,    // End of attack phase
    Note,        // Generic note
    AttackStart, // User indicates attack begins
    AttackEnd,   // User indicates attack ends
}

/// Terminal command captured
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalCommand {
    pub timestamp: u64,
    pub command: String,
    pub working_dir: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
}

/// Browser activity captured
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserActivity {
    pub timestamp: u64,
    pub url: String,
    pub title: Option<String>,
    pub activity_type: BrowserActivityType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserActivityType {
    PageLoad,
    FormSubmit,
    Download,
    Upload,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle() {
        let mut session = CaptureSession::new();
        assert_eq!(session.state, SessionState::Idle);

        session.start();
        assert_eq!(session.state, SessionState::Capturing);
        assert!(session.started_at.is_some());

        session.pause();
        assert_eq!(session.state, SessionState::Paused);

        session.resume();
        assert_eq!(session.state, SessionState::Capturing);

        session.stop();
        assert_eq!(session.state, SessionState::Stopped);
        assert!(session.stopped_at.is_some());
    }

    #[test]
    fn test_markers() {
        let mut session = CaptureSession::new();
        session.start();

        session.add_marker(MarkerType::Important, Some("User clicked important".into()));
        session.add_marker(MarkerType::AttackStart, None);

        assert_eq!(session.markers.len(), 2);
        assert_eq!(session.markers[0].marker_type, MarkerType::Important);
    }
}

// workbench/document.rs
// Editable document model - everything the user can customize

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// The main editable document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: String,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    // Sections the user can edit
    pub summary: EditableText,
    pub timeline: Timeline,
    pub technique: TechniqueMapping,
    pub impact: EditableText,
    pub evidence: EvidenceSection,
    pub custom_sections: Vec<CustomSection>,

    // Metadata
    pub tags: Vec<String>,
    pub author: Option<String>,
}

impl Document {
    pub fn new(title: &str, author: &str) -> Self {
        let now = chrono::Utc::now();

        Self {
            id: Uuid::new_v4().to_string(),
            title: title.to_string(),
            created_at: now,
            updated_at: now,
            summary: EditableText::new("Summary", ""),
            timeline: Timeline::new(),
            technique: TechniqueMapping::default(),
            impact: EditableText::new("Impact Analysis", ""),
            evidence: EvidenceSection::new(),
            custom_sections: vec![],
            tags: vec![],
            author: Some(author.to_string()),
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = chrono::Utc::now();
    }
}

/// Editable text block with user modifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditableText {
    pub heading: String,
    pub content: String,
    pub auto_generated: Option<String>, // System suggestion
    pub user_edited: bool,
}

impl EditableText {
    pub fn new(heading: &str, content: &str) -> Self {
        Self {
            heading: heading.to_string(),
            content: content.to_string(),
            auto_generated: None,
            user_edited: false,
        }
    }

    pub fn set_auto(&mut self, suggestion: &str) {
        self.auto_generated = Some(suggestion.to_string());
        if !self.user_edited {
            self.content = suggestion.to_string();
        }
    }

    pub fn edit(&mut self, new_content: &str) {
        self.content = new_content.to_string();
        self.user_edited = true;
    }
}

/// Timeline of events - user can reorder, add, remove, annotate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    pub entries: Vec<TimelineEntry>,
}

impl Default for Timeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Timeline {
    pub fn new() -> Self {
        Self { entries: vec![] }
    }

    pub fn add_entry(&mut self, entry: TimelineEntry) {
        self.entries.push(entry);
        self.entries.sort_by_key(|e| e.timestamp);
    }

    pub fn reorder(&mut self, entry_id: &str, new_index: usize) {
        if let Some(pos) = self.entries.iter().position(|e| e.id == entry_id) {
            let entry = self.entries.remove(pos);
            let idx = new_index.min(self.entries.len());
            self.entries.insert(idx, entry);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub id: String,
    pub timestamp: u64,
    pub title: String,
    pub description: String,
    pub event_type: String,

    // User controls
    pub included: bool, // Include in export?
    pub starred: bool,  // User marked important
    pub annotation: Option<String>,

    // Link to raw evidence
    pub evidence_ptr: Option<EvidencePointer>,

    // Display
    pub icon: Option<String>,  // emoji or icon name
    pub color: Option<String>, // hex color for timeline
}

impl TimelineEntry {
    pub fn from_event(ts: u64, title: &str, event_type: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: ts,
            title: title.to_string(),
            description: String::new(),
            event_type: event_type.to_string(),
            included: true,
            starred: false,
            annotation: None,
            evidence_ptr: None,
            icon: None,
            color: None,
        }
    }
}

/// MITRE ATT&CK technique mapping
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TechniqueMapping {
    pub technique_id: Option<String>,   // e.g., "T1003.001"
    pub technique_name: Option<String>, // e.g., "OS Credential Dumping: LSASS Memory"
    pub tactic: Option<String>,         // e.g., "Credential Access"
    pub confidence: Option<String>,     // "high", "medium", "low"
    pub auto_detected: bool,
    pub user_override: bool,
    pub notes: Option<String>,
}

/// Evidence section with selectable events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSection {
    pub events: Vec<EventSelection>,
    pub show_raw: bool,           // Show raw JSON in export?
    pub group_by: Option<String>, // "time", "type", "process"
}

impl Default for EvidenceSection {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceSection {
    pub fn new() -> Self {
        Self {
            events: vec![],
            show_raw: false,
            group_by: Some("time".to_string()),
        }
    }
}

/// User selection state for an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSelection {
    pub event_id: String,
    pub selected: bool,
    pub starred: bool,
    pub annotation: Option<Annotation>,
    pub evidence_ptr: EvidencePointer,

    // Cached display data
    pub display_title: String,
    pub display_time: String,
    pub display_type: String,
    pub display_details: BTreeMap<String, serde_json::Value>,
}

/// User annotation on an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: String,
    pub text: String,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Annotation {
    pub fn new(text: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            id: Uuid::new_v4().to_string(),
            text: text.to_string(),
            created_at: now,
            updated_at: now,
        }
    }
}

/// Pointer to raw evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePointer {
    pub segment_id: String,
    pub record_index: usize,
    pub timestamp: u64,
    pub event_type: String,
}

/// Custom section added by user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSection {
    pub id: String,
    pub heading: String,
    pub content: String,
    pub order: usize,
}

impl CustomSection {
    pub fn new(heading: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            heading: heading.to_string(),
            content: String::new(),
            order: 0,
        }
    }
}

/// Section enum for ordering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Section {
    Summary,
    Timeline,
    Technique,
    Impact,
    Evidence,
    Custom(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_document_creation() {
        let doc = Document::new("Test Attack", "Tester");
        assert_eq!(doc.title, "Test Attack");
        assert!(!doc.id.is_empty());
    }

    #[test]
    fn test_editable_text_user_override() {
        let mut text = EditableText::new("Summary", "");
        text.set_auto("System generated summary");
        assert_eq!(text.content, "System generated summary");
        assert!(!text.user_edited);

        text.edit("User wrote this");
        assert_eq!(text.content, "User wrote this");
        assert!(text.user_edited);

        // Auto suggestion should not override user edit
        text.set_auto("New auto suggestion");
        assert_eq!(text.content, "User wrote this");
    }

    #[test]
    fn test_timeline_ordering() {
        let mut timeline = Timeline::new();
        timeline.add_entry(TimelineEntry::from_event(1000, "First", "exec"));
        timeline.add_entry(TimelineEntry::from_event(3000, "Third", "exec"));
        timeline.add_entry(TimelineEntry::from_event(2000, "Second", "exec"));

        assert_eq!(timeline.entries[0].title, "First");
        assert_eq!(timeline.entries[1].title, "Second");
        assert_eq!(timeline.entries[2].title, "Third");
    }
}

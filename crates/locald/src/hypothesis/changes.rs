//! Change Detection and Diff Views
//!
//! "No incident, but something changed" UX:
//! Diff view as a core product feature.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Change Types
// ============================================================================

/// A detected change in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedChange {
    /// Unique ID for this change
    pub id: String,
    /// When the change was detected
    pub detected_at: DateTime<Utc>,
    /// Type of change
    pub change_type: ChangeType,
    /// Domain affected
    pub domain: ChangeDomain,
    /// Entity that changed
    pub entity: ChangeEntity,
    /// Previous state
    pub before: Option<serde_json::Value>,
    /// New state
    pub after: serde_json::Value,
    /// Significance level
    pub significance: ChangeSignificance,
    /// Whether this change led to an incident
    pub resulted_in_incident: bool,
    /// Related incident ID if any
    pub incident_id: Option<String>,
    /// Human-readable summary
    pub summary: String,
}

/// Type of change
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    /// New entity appeared
    Created,
    /// Entity was modified
    Modified,
    /// Entity was removed
    Removed,
    /// Entity behavior changed
    BehaviorChange,
    /// Configuration changed
    ConfigChange,
    /// Trust level changed
    TrustChange,
    /// Threshold crossed
    ThresholdCrossed,
    /// Pattern emerged
    PatternEmerged,
    /// Pattern ceased
    PatternCeased,
    /// Baseline deviation
    BaselineDeviation,
}

/// Domain of change
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ChangeDomain {
    Process,
    Network,
    File,
    Registry,
    User,
    Authentication,
    Service,
    Configuration,
    Security,
    System,
}

/// The entity that changed
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeEntity {
    Process {
        pid: u32,
        name: String,
        path: Option<String>,
    },
    Connection {
        local: String,
        remote: String,
        protocol: String,
    },
    File {
        path: String,
    },
    RegistryKey {
        key: String,
    },
    User {
        username: String,
        domain: Option<String>,
    },
    Service {
        name: String,
    },
    Config {
        key: String,
    },
    Baseline {
        name: String,
    },
}

impl ChangeEntity {
    pub fn identifier(&self) -> String {
        match self {
            Self::Process { name, path, .. } => path.clone().unwrap_or_else(|| name.clone()),
            Self::Connection { local, remote, .. } => format!("{} -> {}", local, remote),
            Self::File { path } => path.clone(),
            Self::RegistryKey { key } => key.clone(),
            Self::User { username, domain } => {
                if let Some(d) = domain {
                    format!("{}\\{}", d, username)
                } else {
                    username.clone()
                }
            }
            Self::Service { name } => name.clone(),
            Self::Config { key } => key.clone(),
            Self::Baseline { name } => name.clone(),
        }
    }
}

/// How significant is the change
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ChangeSignificance {
    /// Informational only
    Info,
    /// Notable but not concerning
    Low,
    /// Worth attention
    Medium,
    /// Potentially concerning
    High,
    /// Requires investigation
    Critical,
}

// ============================================================================
// Change Window
// ============================================================================

/// A window of changes for comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeWindow {
    /// Window start time
    pub start: DateTime<Utc>,
    /// Window end time
    pub end: DateTime<Utc>,
    /// All changes in window
    pub changes: Vec<DetectedChange>,
    /// Summary statistics
    pub stats: ChangeStats,
}

/// Statistics about changes in a window
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChangeStats {
    pub total_changes: usize,
    pub by_type: HashMap<ChangeType, usize>,
    pub by_domain: HashMap<ChangeDomain, usize>,
    pub by_significance: HashMap<String, usize>,
    pub incident_generating: usize,
    pub non_incident: usize,
}

impl ChangeWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self {
            start,
            end,
            changes: Vec::new(),
            stats: ChangeStats::default(),
        }
    }

    pub fn add_change(&mut self, change: DetectedChange) {
        self.stats.total_changes += 1;
        *self
            .stats
            .by_type
            .entry(change.change_type.clone())
            .or_insert(0) += 1;
        *self
            .stats
            .by_domain
            .entry(change.domain.clone())
            .or_insert(0) += 1;
        *self
            .stats
            .by_significance
            .entry(format!("{:?}", change.significance))
            .or_insert(0) += 1;

        if change.resulted_in_incident {
            self.stats.incident_generating += 1;
        } else {
            self.stats.non_incident += 1;
        }

        self.changes.push(change);
    }

    pub fn changes_by_significance(&self, min: ChangeSignificance) -> Vec<&DetectedChange> {
        self.changes
            .iter()
            .filter(|c| c.significance >= min)
            .collect()
    }

    pub fn changes_by_domain(&self, domain: &ChangeDomain) -> Vec<&DetectedChange> {
        self.changes
            .iter()
            .filter(|c| &c.domain == domain)
            .collect()
    }

    pub fn changes_without_incidents(&self) -> Vec<&DetectedChange> {
        self.changes
            .iter()
            .filter(|c| !c.resulted_in_incident)
            .collect()
    }
}

// ============================================================================
// Diff Engine
// ============================================================================

/// Engine for computing diffs between states
pub struct DiffEngine {
    /// Minimum significance to report
    min_significance: ChangeSignificance,
    /// Whether to track non-incident changes
    #[allow(dead_code)]
    track_non_incident: bool,
}

impl DiffEngine {
    pub fn new() -> Self {
        Self {
            min_significance: ChangeSignificance::Low,
            track_non_incident: true,
        }
    }

    pub fn with_min_significance(mut self, sig: ChangeSignificance) -> Self {
        self.min_significance = sig;
        self
    }

    /// Compute diff between two snapshots
    pub fn compute_diff(&self, before: &StateSnapshot, after: &StateSnapshot) -> StateDiff {
        let mut diff = StateDiff {
            before_time: before.timestamp,
            after_time: after.timestamp,
            added: Vec::new(),
            removed: Vec::new(),
            modified: Vec::new(),
        };

        // Find removed and modified entities
        for (key, before_val) in &before.entities {
            if let Some(after_val) = after.entities.get(key) {
                // Check if modified
                if before_val != after_val {
                    diff.modified.push(EntityDiff {
                        entity_key: key.clone(),
                        before: before_val.clone(),
                        after: after_val.clone(),
                        fields_changed: Self::diff_fields(before_val, after_val),
                    });
                }
            } else {
                // Removed
                diff.removed.push(EntityRemoved {
                    entity_key: key.clone(),
                    last_state: before_val.clone(),
                });
            }
        }

        // Find added entities
        for (key, after_val) in &after.entities {
            if !before.entities.contains_key(key) {
                diff.added.push(EntityAdded {
                    entity_key: key.clone(),
                    state: after_val.clone(),
                });
            }
        }

        diff
    }

    fn diff_fields(before: &serde_json::Value, after: &serde_json::Value) -> Vec<String> {
        let mut changed = Vec::new();

        if let (serde_json::Value::Object(b), serde_json::Value::Object(a)) = (before, after) {
            for (key, before_val) in b {
                if let Some(after_val) = a.get(key) {
                    if before_val != after_val {
                        changed.push(key.clone());
                    }
                } else {
                    changed.push(format!("-{}", key));
                }
            }
            for key in a.keys() {
                if !b.contains_key(key) {
                    changed.push(format!("+{}", key));
                }
            }
        }

        changed
    }

    /// Convert a diff to detected changes
    pub fn diff_to_changes(
        &self,
        diff: &StateDiff,
        domain: ChangeDomain,
        now: DateTime<Utc>,
    ) -> Vec<DetectedChange> {
        let mut changes = Vec::new();
        let mut id_counter = 0;

        for added in &diff.added {
            id_counter += 1;
            changes.push(DetectedChange {
                id: format!("chg_{}_{}", now.timestamp(), id_counter),
                detected_at: now,
                change_type: ChangeType::Created,
                domain: domain.clone(),
                entity: ChangeEntity::Config {
                    key: added.entity_key.clone(),
                },
                before: None,
                after: added.state.clone(),
                significance: ChangeSignificance::Medium,
                resulted_in_incident: false,
                incident_id: None,
                summary: format!("New entity: {}", added.entity_key),
            });
        }

        for removed in &diff.removed {
            id_counter += 1;
            changes.push(DetectedChange {
                id: format!("chg_{}_{}", now.timestamp(), id_counter),
                detected_at: now,
                change_type: ChangeType::Removed,
                domain: domain.clone(),
                entity: ChangeEntity::Config {
                    key: removed.entity_key.clone(),
                },
                before: Some(removed.last_state.clone()),
                after: serde_json::Value::Null,
                significance: ChangeSignificance::Medium,
                resulted_in_incident: false,
                incident_id: None,
                summary: format!("Removed entity: {}", removed.entity_key),
            });
        }

        for modified in &diff.modified {
            id_counter += 1;
            changes.push(DetectedChange {
                id: format!("chg_{}_{}", now.timestamp(), id_counter),
                detected_at: now,
                change_type: ChangeType::Modified,
                domain: domain.clone(),
                entity: ChangeEntity::Config {
                    key: modified.entity_key.clone(),
                },
                before: Some(modified.before.clone()),
                after: modified.after.clone(),
                significance: ChangeSignificance::Low,
                resulted_in_incident: false,
                incident_id: None,
                summary: format!(
                    "Modified entity: {} ({})",
                    modified.entity_key,
                    modified.fields_changed.join(", ")
                ),
            });
        }

        // Filter by significance
        changes
            .into_iter()
            .filter(|c| c.significance >= self.min_significance)
            .collect()
    }
}

impl Default for DiffEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// State Snapshots
// ============================================================================

/// A snapshot of system state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub timestamp: DateTime<Utc>,
    pub entities: HashMap<String, serde_json::Value>,
}

impl StateSnapshot {
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            entities: HashMap::new(),
        }
    }

    pub fn add<T: Serialize>(&mut self, key: impl Into<String>, value: &T) {
        if let Ok(v) = serde_json::to_value(value) {
            self.entities.insert(key.into(), v);
        }
    }
}

impl Default for StateSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

/// Diff between two states
#[derive(Debug, Clone)]
pub struct StateDiff {
    pub before_time: DateTime<Utc>,
    pub after_time: DateTime<Utc>,
    pub added: Vec<EntityAdded>,
    pub removed: Vec<EntityRemoved>,
    pub modified: Vec<EntityDiff>,
}

impl StateDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    pub fn summary(&self) -> String {
        format!(
            "{} added, {} removed, {} modified",
            self.added.len(),
            self.removed.len(),
            self.modified.len()
        )
    }
}

#[derive(Debug, Clone)]
pub struct EntityAdded {
    pub entity_key: String,
    pub state: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct EntityRemoved {
    pub entity_key: String,
    pub last_state: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct EntityDiff {
    pub entity_key: String,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
    pub fields_changed: Vec<String>,
}

// ============================================================================
// Change Renderer
// ============================================================================

/// Renders changes for display
pub struct ChangeRenderer;

impl ChangeRenderer {
    /// Render a change window as a summary
    pub fn render_summary(window: &ChangeWindow) -> String {
        let mut lines = Vec::new();

        lines.push(format!(
            "Changes from {} to {}",
            window.start.format("%Y-%m-%d %H:%M:%S"),
            window.end.format("%Y-%m-%d %H:%M:%S")
        ));
        lines.push(String::new());

        lines.push(format!(
            "Total: {} changes ({} generated incidents, {} did not)",
            window.stats.total_changes, window.stats.incident_generating, window.stats.non_incident
        ));
        lines.push(String::new());

        if !window.stats.by_significance.is_empty() {
            lines.push("By Significance:".to_string());
            for (sig, count) in &window.stats.by_significance {
                lines.push(format!("  {}: {}", sig, count));
            }
            lines.push(String::new());
        }

        if !window.stats.by_domain.is_empty() {
            lines.push("By Domain:".to_string());
            for (domain, count) in &window.stats.by_domain {
                lines.push(format!("  {:?}: {}", domain, count));
            }
        }

        lines.join("\n")
    }

    /// Render changes as a diff view
    pub fn render_diff(changes: &[DetectedChange]) -> String {
        let mut lines = Vec::new();

        for change in changes {
            let prefix = match change.change_type {
                ChangeType::Created => "+",
                ChangeType::Removed => "-",
                ChangeType::Modified => "~",
                _ => "*",
            };

            let sig = match change.significance {
                ChangeSignificance::Critical => "[!!!]",
                ChangeSignificance::High => "[!!]",
                ChangeSignificance::Medium => "[!]",
                ChangeSignificance::Low => "[.]",
                ChangeSignificance::Info => "[ ]",
            };

            lines.push(format!(
                "{} {} {:?}: {}",
                prefix, sig, change.domain, change.summary
            ));

            if let Some(ref before) = change.before {
                lines.push(format!("  - {}", Self::format_value(before)));
            }
            lines.push(format!("  + {}", Self::format_value(&change.after)));
        }

        lines.join("\n")
    }

    fn format_value(v: &serde_json::Value) -> String {
        match v {
            serde_json::Value::Null => "(null)".to_string(),
            serde_json::Value::String(s) => s.clone(),
            _ => serde_json::to_string(v).unwrap_or_else(|_| "(error)".to_string()),
        }
    }
}

// ============================================================================
// Change Tracker
// ============================================================================

/// Tracks changes over time
pub struct ChangeTracker {
    /// Rolling window of changes
    changes: Vec<DetectedChange>,
    /// Maximum changes to keep
    max_changes: usize,
    /// Entity state cache
    entity_states: HashMap<String, serde_json::Value>,
}

impl ChangeTracker {
    pub fn new(max_changes: usize) -> Self {
        Self {
            changes: Vec::new(),
            max_changes,
            entity_states: HashMap::new(),
        }
    }

    /// Record a change
    pub fn record(&mut self, change: DetectedChange) {
        // Update entity state
        let key = change.entity.identifier();
        match change.change_type {
            ChangeType::Removed => {
                self.entity_states.remove(&key);
            }
            _ => {
                self.entity_states.insert(key, change.after.clone());
            }
        }

        // Store change
        self.changes.push(change);

        // Trim if needed
        if self.changes.len() > self.max_changes {
            self.changes.remove(0);
        }
    }

    /// Get changes in a time range
    pub fn changes_in_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> ChangeWindow {
        let mut window = ChangeWindow::new(start, end);

        for change in &self.changes {
            if change.detected_at >= start && change.detected_at <= end {
                window.add_change(change.clone());
            }
        }

        window
    }

    /// Get recent changes
    pub fn recent(&self, count: usize) -> Vec<&DetectedChange> {
        self.changes.iter().rev().take(count).collect()
    }

    /// Get changes that didn't result in incidents
    pub fn silent_changes(&self, since: DateTime<Utc>) -> Vec<&DetectedChange> {
        self.changes
            .iter()
            .filter(|c| c.detected_at >= since && !c.resulted_in_incident)
            .collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_state_diff() {
        let mut before = StateSnapshot::new();
        before.add("entity_a", &serde_json::json!({"status": "active"}));
        before.add("entity_b", &serde_json::json!({"count": 5}));

        let mut after = StateSnapshot::new();
        after.add("entity_a", &serde_json::json!({"status": "inactive"}));
        after.add("entity_c", &serde_json::json!({"new": true}));

        let engine = DiffEngine::new();
        let diff = engine.compute_diff(&before, &after);

        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.modified.len(), 1);

        assert_eq!(diff.added[0].entity_key, "entity_c");
        assert_eq!(diff.removed[0].entity_key, "entity_b");
        assert_eq!(diff.modified[0].entity_key, "entity_a");
    }

    #[test]
    fn test_change_window() {
        let now = Utc::now();
        let mut window = ChangeWindow::new(now - Duration::hours(1), now);

        window.add_change(DetectedChange {
            id: "chg_1".to_string(),
            detected_at: now,
            change_type: ChangeType::Created,
            domain: ChangeDomain::Process,
            entity: ChangeEntity::Process {
                pid: 1234,
                name: "test.exe".to_string(),
                path: None,
            },
            before: None,
            after: serde_json::json!({"running": true}),
            significance: ChangeSignificance::Medium,
            resulted_in_incident: false,
            incident_id: None,
            summary: "New process".to_string(),
        });

        assert_eq!(window.stats.total_changes, 1);
        assert_eq!(window.stats.non_incident, 1);
        assert_eq!(window.changes_without_incidents().len(), 1);
    }

    #[test]
    fn test_change_tracker() {
        let mut tracker = ChangeTracker::new(100);
        let now = Utc::now();

        tracker.record(DetectedChange {
            id: "chg_1".to_string(),
            detected_at: now,
            change_type: ChangeType::Created,
            domain: ChangeDomain::File,
            entity: ChangeEntity::File {
                path: "/tmp/test".to_string(),
            },
            before: None,
            after: serde_json::json!({"exists": true}),
            significance: ChangeSignificance::Low,
            resulted_in_incident: false,
            incident_id: None,
            summary: "New file".to_string(),
        });

        let silent = tracker.silent_changes(now - Duration::hours(1));
        assert_eq!(silent.len(), 1);

        let recent = tracker.recent(10);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn test_change_renderer() {
        let changes = vec![DetectedChange {
            id: "chg_1".to_string(),
            detected_at: Utc::now(),
            change_type: ChangeType::Modified,
            domain: ChangeDomain::Configuration,
            entity: ChangeEntity::Config {
                key: "firewall.enabled".to_string(),
            },
            before: Some(serde_json::json!(true)),
            after: serde_json::json!(false),
            significance: ChangeSignificance::High,
            resulted_in_incident: false,
            incident_id: None,
            summary: "Firewall disabled".to_string(),
        }];

        let rendered = ChangeRenderer::render_diff(&changes);
        assert!(rendered.contains("Firewall disabled"));
        assert!(rendered.contains("[!!]"));
    }
}

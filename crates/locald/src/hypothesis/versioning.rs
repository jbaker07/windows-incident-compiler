//! Versioning for Explanation Determinism
//!
//! Every component that affects explanations must be versioned.
//! Enables reproducible explanations and debugging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ============================================================================
// Component Versions
// ============================================================================

/// Version information for a component
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComponentVersion {
    /// Semantic version
    pub version: String,
    /// Git commit hash or build ID
    pub build_id: Option<String>,
    /// When this version was built/released
    pub build_time: Option<DateTime<Utc>>,
    /// Content hash for integrity verification
    pub content_hash: Option<String>,
}

impl ComponentVersion {
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            build_id: None,
            build_time: None,
            content_hash: None,
        }
    }

    pub fn with_build_id(mut self, build_id: impl Into<String>) -> Self {
        self.build_id = Some(build_id.into());
        self
    }

    pub fn with_content_hash(mut self, hash: impl Into<String>) -> Self {
        self.content_hash = Some(hash.into());
        self
    }

    /// Check if this version matches another exactly
    pub fn matches(&self, other: &ComponentVersion) -> bool {
        // If both have content hashes, use those
        if let (Some(h1), Some(h2)) = (&self.content_hash, &other.content_hash) {
            return h1 == h2;
        }
        // Otherwise compare version strings
        self.version == other.version
    }
}

// ============================================================================
// Session Configuration Version
// ============================================================================

/// Complete versioned session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfigVersion {
    /// Session config version
    pub session_config: ComponentVersion,
    /// Playbook pack version
    pub playbook_pack: ComponentVersion,
    /// Lexicon version (terminology/explanations)
    pub lexicon: ComponentVersion,
    /// Scorer version (risk scoring algorithm)
    pub scorer: ComponentVersion,
    /// Template version (copilot templates)
    pub templates: ComponentVersion,
    /// Rule engine version
    pub rule_engine: ComponentVersion,
    /// Evidence schema version
    pub evidence_schema: ComponentVersion,
    /// Additional component versions
    pub additional: BTreeMap<String, ComponentVersion>,
}

impl SessionConfigVersion {
    pub fn new() -> Self {
        Self {
            session_config: ComponentVersion::new("1.0.0"),
            playbook_pack: ComponentVersion::new("1.0.0"),
            lexicon: ComponentVersion::new("1.0.0"),
            scorer: ComponentVersion::new("1.0.0"),
            templates: ComponentVersion::new("1.0.0"),
            rule_engine: ComponentVersion::new("1.0.0"),
            evidence_schema: ComponentVersion::new("1.0.0"),
            additional: BTreeMap::new(),
        }
    }

    /// Compute a combined version fingerprint
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();

        // Add all core components
        hasher.update(self.session_config.version.as_bytes());
        hasher.update(self.playbook_pack.version.as_bytes());
        hasher.update(self.lexicon.version.as_bytes());
        hasher.update(self.scorer.version.as_bytes());
        hasher.update(self.templates.version.as_bytes());
        hasher.update(self.rule_engine.version.as_bytes());
        hasher.update(self.evidence_schema.version.as_bytes());

        // Add additional components (sorted by key for determinism)
        for (key, ver) in &self.additional {
            hasher.update(key.as_bytes());
            hasher.update(ver.version.as_bytes());
        }

        hex::encode(&hasher.finalize()[..8])
    }

    /// Check if two configs are compatible for comparison
    pub fn is_compatible_with(&self, other: &SessionConfigVersion) -> VersionCompatibility {
        let mut issues = Vec::new();

        // Check core components
        if !self.scorer.matches(&other.scorer) {
            issues.push(VersionIssue {
                component: "scorer".to_string(),
                expected: self.scorer.clone(),
                actual: other.scorer.clone(),
                severity: IssueSeverity::Breaking,
            });
        }

        if !self.evidence_schema.matches(&other.evidence_schema) {
            issues.push(VersionIssue {
                component: "evidence_schema".to_string(),
                expected: self.evidence_schema.clone(),
                actual: other.evidence_schema.clone(),
                severity: IssueSeverity::Breaking,
            });
        }

        if !self.playbook_pack.matches(&other.playbook_pack) {
            issues.push(VersionIssue {
                component: "playbook_pack".to_string(),
                expected: self.playbook_pack.clone(),
                actual: other.playbook_pack.clone(),
                severity: IssueSeverity::Warning,
            });
        }

        if !self.lexicon.matches(&other.lexicon) {
            issues.push(VersionIssue {
                component: "lexicon".to_string(),
                expected: self.lexicon.clone(),
                actual: other.lexicon.clone(),
                severity: IssueSeverity::Cosmetic,
            });
        }

        if !self.templates.matches(&other.templates) {
            issues.push(VersionIssue {
                component: "templates".to_string(),
                expected: self.templates.clone(),
                actual: other.templates.clone(),
                severity: IssueSeverity::Cosmetic,
            });
        }

        if issues.is_empty() {
            VersionCompatibility::Compatible
        } else if issues.iter().any(|i| i.severity == IssueSeverity::Breaking) {
            VersionCompatibility::Incompatible { issues }
        } else {
            VersionCompatibility::PartiallyCompatible { issues }
        }
    }

    /// Add an additional component version
    pub fn add_component(&mut self, name: impl Into<String>, version: ComponentVersion) {
        self.additional.insert(name.into(), version);
    }
}

impl Default for SessionConfigVersion {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of version compatibility check
#[derive(Debug, Clone)]
pub enum VersionCompatibility {
    Compatible,
    PartiallyCompatible { issues: Vec<VersionIssue> },
    Incompatible { issues: Vec<VersionIssue> },
}

impl VersionCompatibility {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Compatible | Self::PartiallyCompatible { .. })
    }
}

/// A version compatibility issue
#[derive(Debug, Clone)]
pub struct VersionIssue {
    pub component: String,
    pub expected: ComponentVersion,
    pub actual: ComponentVersion,
    pub severity: IssueSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueSeverity {
    /// Will cause incorrect results
    Breaking,
    /// May cause differences
    Warning,
    /// Cosmetic differences only
    Cosmetic,
}

// ============================================================================
// Versioned Explanation
// ============================================================================

/// An explanation with version context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedExplanation {
    /// The explanation text
    pub text: String,
    /// Session config fingerprint when generated
    pub config_fingerprint: String,
    /// Individual component versions at generation time
    pub component_versions: SessionConfigVersion,
    /// When the explanation was generated
    pub generated_at: DateTime<Utc>,
    /// Hash of the input evidence
    pub evidence_hash: String,
}

impl VersionedExplanation {
    pub fn new(
        text: impl Into<String>,
        config: &SessionConfigVersion,
        evidence_hash: impl Into<String>,
    ) -> Self {
        Self {
            text: text.into(),
            config_fingerprint: config.fingerprint(),
            component_versions: config.clone(),
            generated_at: Utc::now(),
            evidence_hash: evidence_hash.into(),
        }
    }

    /// Check if this explanation would be reproduced with current config
    pub fn is_reproducible_with(&self, current_config: &SessionConfigVersion) -> bool {
        self.config_fingerprint == current_config.fingerprint()
    }

    /// Get compatibility status with current config
    pub fn compatibility_with(
        &self,
        current_config: &SessionConfigVersion,
    ) -> VersionCompatibility {
        self.component_versions.is_compatible_with(current_config)
    }
}

// ============================================================================
// Version Registry
// ============================================================================

/// Registry for tracking version changes over time
pub struct VersionRegistry {
    /// History of session configs
    history: Vec<VersionSnapshot>,
    /// Current active version
    current: SessionConfigVersion,
}

/// A snapshot of version state at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionSnapshot {
    pub config: SessionConfigVersion,
    pub fingerprint: String,
    pub timestamp: DateTime<Utc>,
    pub change_description: Option<String>,
}

impl VersionRegistry {
    pub fn new(initial: SessionConfigVersion) -> Self {
        let fingerprint = initial.fingerprint();
        let snapshot = VersionSnapshot {
            config: initial.clone(),
            fingerprint,
            timestamp: Utc::now(),
            change_description: Some("Initial version".to_string()),
        };

        Self {
            history: vec![snapshot],
            current: initial,
        }
    }

    /// Update the current version
    pub fn update(&mut self, new_config: SessionConfigVersion, description: impl Into<String>) {
        let fingerprint = new_config.fingerprint();

        // Don't record if fingerprint hasn't changed
        if fingerprint == self.current.fingerprint() {
            return;
        }

        let snapshot = VersionSnapshot {
            config: new_config.clone(),
            fingerprint,
            timestamp: Utc::now(),
            change_description: Some(description.into()),
        };

        self.history.push(snapshot);
        self.current = new_config;
    }

    /// Get current version
    pub fn current(&self) -> &SessionConfigVersion {
        &self.current
    }

    /// Get current fingerprint
    pub fn current_fingerprint(&self) -> String {
        self.current.fingerprint()
    }

    /// Get version at a specific time
    pub fn version_at(&self, time: DateTime<Utc>) -> Option<&VersionSnapshot> {
        self.history.iter().rfind(|s| s.timestamp <= time)
    }

    /// Get version by fingerprint
    pub fn version_by_fingerprint(&self, fingerprint: &str) -> Option<&VersionSnapshot> {
        self.history.iter().find(|s| s.fingerprint == fingerprint)
    }

    /// Get all version history
    pub fn history(&self) -> &[VersionSnapshot] {
        &self.history
    }

    /// Get changes between two fingerprints
    pub fn changes_between(
        &self,
        from_fingerprint: &str,
        to_fingerprint: &str,
    ) -> Option<VersionDiff> {
        let from = self.version_by_fingerprint(from_fingerprint)?;
        let to = self.version_by_fingerprint(to_fingerprint)?;

        Some(VersionDiff::compute(&from.config, &to.config))
    }
}

// ============================================================================
// Version Diff
// ============================================================================

/// Differences between two version configurations
#[derive(Debug, Clone)]
pub struct VersionDiff {
    pub changes: Vec<VersionChange>,
    pub from_fingerprint: String,
    pub to_fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct VersionChange {
    pub component: String,
    pub from_version: String,
    pub to_version: String,
    pub impact: ChangeImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeImpact {
    /// No functional change
    None,
    /// Cosmetic/text changes only
    Cosmetic,
    /// May affect detection
    Detection,
    /// May affect scoring
    Scoring,
    /// Major structural change
    Structural,
}

impl VersionDiff {
    pub fn compute(from: &SessionConfigVersion, to: &SessionConfigVersion) -> Self {
        let mut changes = Vec::new();

        // Compare core components
        Self::check_component(
            &mut changes,
            "session_config",
            &from.session_config,
            &to.session_config,
            ChangeImpact::Structural,
        );
        Self::check_component(
            &mut changes,
            "playbook_pack",
            &from.playbook_pack,
            &to.playbook_pack,
            ChangeImpact::Detection,
        );
        Self::check_component(
            &mut changes,
            "lexicon",
            &from.lexicon,
            &to.lexicon,
            ChangeImpact::Cosmetic,
        );
        Self::check_component(
            &mut changes,
            "scorer",
            &from.scorer,
            &to.scorer,
            ChangeImpact::Scoring,
        );
        Self::check_component(
            &mut changes,
            "templates",
            &from.templates,
            &to.templates,
            ChangeImpact::Cosmetic,
        );
        Self::check_component(
            &mut changes,
            "rule_engine",
            &from.rule_engine,
            &to.rule_engine,
            ChangeImpact::Detection,
        );
        Self::check_component(
            &mut changes,
            "evidence_schema",
            &from.evidence_schema,
            &to.evidence_schema,
            ChangeImpact::Structural,
        );

        // Compare additional components
        for (key, from_ver) in &from.additional {
            if let Some(to_ver) = to.additional.get(key) {
                Self::check_component(&mut changes, key, from_ver, to_ver, ChangeImpact::Detection);
            } else {
                changes.push(VersionChange {
                    component: key.clone(),
                    from_version: from_ver.version.clone(),
                    to_version: "(removed)".to_string(),
                    impact: ChangeImpact::Structural,
                });
            }
        }

        for (key, to_ver) in &to.additional {
            if !from.additional.contains_key(key) {
                changes.push(VersionChange {
                    component: key.clone(),
                    from_version: "(new)".to_string(),
                    to_version: to_ver.version.clone(),
                    impact: ChangeImpact::Structural,
                });
            }
        }

        Self {
            changes,
            from_fingerprint: from.fingerprint(),
            to_fingerprint: to.fingerprint(),
        }
    }

    fn check_component(
        changes: &mut Vec<VersionChange>,
        name: &str,
        from: &ComponentVersion,
        to: &ComponentVersion,
        impact: ChangeImpact,
    ) {
        if !from.matches(to) {
            changes.push(VersionChange {
                component: name.to_string(),
                from_version: from.version.clone(),
                to_version: to.version.clone(),
                impact,
            });
        }
    }

    pub fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }

    pub fn has_breaking_changes(&self) -> bool {
        self.changes
            .iter()
            .any(|c| matches!(c.impact, ChangeImpact::Structural | ChangeImpact::Scoring))
    }

    pub fn summary(&self) -> String {
        if self.changes.is_empty() {
            return "No version changes".to_string();
        }

        let mut parts = Vec::new();
        for change in &self.changes {
            parts.push(format!(
                "{}: {} → {} ({:?})",
                change.component, change.from_version, change.to_version, change.impact
            ));
        }
        parts.join("; ")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_version() {
        let v1 = ComponentVersion::new("1.0.0");
        let v2 = ComponentVersion::new("1.0.0");
        let v3 = ComponentVersion::new("1.0.1");

        assert!(v1.matches(&v2));
        assert!(!v1.matches(&v3));
    }

    #[test]
    fn test_content_hash_matching() {
        let v1 = ComponentVersion::new("1.0.0").with_content_hash("abc123");
        let v2 = ComponentVersion::new("1.0.1").with_content_hash("abc123");
        let v3 = ComponentVersion::new("1.0.0").with_content_hash("def456");

        // Same hash = match, even if version differs
        assert!(v1.matches(&v2));
        // Different hash = no match
        assert!(!v1.matches(&v3));
    }

    #[test]
    fn test_session_config_fingerprint() {
        let config1 = SessionConfigVersion::new();
        let mut config2 = SessionConfigVersion::new();

        assert_eq!(config1.fingerprint(), config2.fingerprint());

        config2.scorer = ComponentVersion::new("2.0.0");
        assert_ne!(config1.fingerprint(), config2.fingerprint());
    }

    #[test]
    fn test_compatibility_check() {
        let config1 = SessionConfigVersion::new();
        let mut config2 = SessionConfigVersion::new();

        // Should be compatible
        let compat = config1.is_compatible_with(&config2);
        assert!(matches!(compat, VersionCompatibility::Compatible));

        // Change scorer - should be incompatible
        config2.scorer = ComponentVersion::new("2.0.0");
        let compat = config1.is_compatible_with(&config2);
        assert!(matches!(compat, VersionCompatibility::Incompatible { .. }));
    }

    #[test]
    fn test_version_registry() {
        let initial = SessionConfigVersion::new();
        let mut registry = VersionRegistry::new(initial);

        let fingerprint1 = registry.current_fingerprint();

        let mut updated = SessionConfigVersion::new();
        updated.lexicon = ComponentVersion::new("1.1.0");
        registry.update(updated, "Updated lexicon");

        let fingerprint2 = registry.current_fingerprint();
        assert_ne!(fingerprint1, fingerprint2);
        assert_eq!(registry.history().len(), 2);

        // Get diff
        let diff = registry
            .changes_between(&fingerprint1, &fingerprint2)
            .unwrap();
        assert!(diff.has_changes());
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].component, "lexicon");
    }

    #[test]
    fn test_versioned_explanation() {
        let config = SessionConfigVersion::new();
        let explanation =
            VersionedExplanation::new("Test explanation", &config, "evidence_hash_123");

        assert!(explanation.is_reproducible_with(&config));

        let mut new_config = SessionConfigVersion::new();
        new_config.templates = ComponentVersion::new("1.1.0");
        assert!(!explanation.is_reproducible_with(&new_config));
    }
}

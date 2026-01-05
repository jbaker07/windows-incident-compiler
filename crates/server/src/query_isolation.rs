//! Query Namespace Isolation: Ship Hardening for Imported vs Live Data
//!
//! Prevents accidental mixing of imported and live data in queries:
//! - Default: Live data ONLY (imported bundles excluded)
//! - Explicit opt-in: include_imported=true to see imported data
//! - Clear UI indicators when showing imported data
//!
//! This module provides query filtering and namespace detection utilities.

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Namespace prefix for imported bundles
pub const IMPORTED_NAMESPACE_PREFIX: &str = "imported_bundle";

/// Directory prefix for imported bundle storage
pub const IMPORTED_DIR_PREFIX: &str = "IMPORTED_";

// ============================================================================
// Query Filter Types
// ============================================================================

/// Query filter for namespace isolation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceFilter {
    /// Include live data (default: true)
    #[serde(default = "default_true")]
    pub include_live: bool,

    /// Include imported data (default: false - opt-in only)
    #[serde(default)]
    pub include_imported: bool,

    /// If set, only include specific bundle IDs from imported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imported_bundle_ids: Option<Vec<String>>,
}

fn default_true() -> bool {
    true
}

impl Default for NamespaceFilter {
    fn default() -> Self {
        Self {
            include_live: true,
            include_imported: false, // Critical: default to NOT including imported
            imported_bundle_ids: None,
        }
    }
}

impl NamespaceFilter {
    /// Live data only (default, safe mode)
    pub fn live_only() -> Self {
        Self::default()
    }

    /// Imported data only
    pub fn imported_only() -> Self {
        Self {
            include_live: false,
            include_imported: true,
            imported_bundle_ids: None,
        }
    }

    /// Include both live and imported
    pub fn all() -> Self {
        Self {
            include_live: true,
            include_imported: true,
            imported_bundle_ids: None,
        }
    }

    /// Specific imported bundle only
    pub fn specific_bundle(bundle_id: &str) -> Self {
        Self {
            include_live: false,
            include_imported: true,
            imported_bundle_ids: Some(vec![bundle_id.to_string()]),
        }
    }

    /// Check if a namespace should be included based on this filter
    pub fn should_include(&self, namespace: &str) -> bool {
        let is_imported = is_imported_namespace(namespace);

        if is_imported {
            if !self.include_imported {
                return false;
            }

            // Check specific bundle filter
            if let Some(ref allowed_ids) = self.imported_bundle_ids {
                if let Some(bundle_id) = extract_bundle_id(namespace) {
                    return allowed_ids.iter().any(|id| id == &bundle_id);
                }
                return false;
            }

            true
        } else {
            self.include_live
        }
    }

    /// Filter a list of namespaces
    pub fn filter_namespaces<'a>(&self, namespaces: &'a [String]) -> Vec<&'a String> {
        namespaces
            .iter()
            .filter(|ns| self.should_include(ns))
            .collect()
    }
}

// ============================================================================
// Query Source Indicator
// ============================================================================

/// Indicates the source of query results for UI display
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuerySource {
    /// Results are from live telemetry only
    Live,
    /// Results are from imported bundle only
    Imported,
    /// Results are mixed (requires explicit opt-in)
    Mixed,
}

impl QuerySource {
    /// Determine source from namespace filter
    pub fn from_filter(filter: &NamespaceFilter) -> Self {
        match (filter.include_live, filter.include_imported) {
            (true, false) => Self::Live,
            (false, true) => Self::Imported,
            (true, true) => Self::Mixed,
            (false, false) => Self::Live, // Edge case, treat as live
        }
    }

    /// UI display string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Imported => "imported",
            Self::Mixed => "mixed",
        }
    }

    /// UI indicator badge
    pub fn badge(&self) -> &'static str {
        match self {
            Self::Live => "🟢 Live",
            Self::Imported => "📦 Imported",
            Self::Mixed => "⚠️ Mixed",
        }
    }
}

// ============================================================================
// Namespace Detection
// ============================================================================

/// Check if a namespace is from an imported bundle
pub fn is_imported_namespace(namespace: &str) -> bool {
    namespace.starts_with(IMPORTED_NAMESPACE_PREFIX)
        || namespace.starts_with(IMPORTED_DIR_PREFIX)
        || namespace.contains("/imported/")
        || namespace.contains("\\imported\\")
}

/// Extract bundle ID from imported namespace
pub fn extract_bundle_id(namespace: &str) -> Option<String> {
    // Format: imported_bundle_<bundle_id> or IMPORTED_<bundle_id>
    if let Some(rest) = namespace.strip_prefix("imported_bundle_") {
        // Take until next separator
        let bundle_id = rest.split(&['/', '\\', ':'][..]).next()?;
        return Some(bundle_id.to_string());
    }

    if let Some(rest) = namespace.strip_prefix(IMPORTED_DIR_PREFIX) {
        let bundle_id = rest.split(&['/', '\\', ':'][..]).next()?;
        return Some(bundle_id.to_string());
    }

    // Check for path-based format
    for part in namespace.split(&['/', '\\'][..]) {
        if let Some(rest) = part.strip_prefix(IMPORTED_DIR_PREFIX) {
            return Some(rest.to_string());
        }
    }

    None
}

/// Generate namespace for an imported bundle
pub fn make_imported_namespace(bundle_id: &str) -> String {
    format!("{}_{}", IMPORTED_NAMESPACE_PREFIX, bundle_id)
}

// ============================================================================
// Query Result Wrapper
// ============================================================================

/// Wrapper for query results that includes source indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolatedQueryResult<T> {
    /// The actual query results
    pub results: T,

    /// Source indicator for UI
    pub source: QuerySource,

    /// The filter that was applied
    pub applied_filter: NamespaceFilter,

    /// Warning if mixed results are present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

impl<T> IsolatedQueryResult<T> {
    /// Create result from live-only query
    pub fn live(results: T) -> Self {
        Self {
            results,
            source: QuerySource::Live,
            applied_filter: NamespaceFilter::live_only(),
            warning: None,
        }
    }

    /// Create result from imported-only query
    pub fn imported(results: T, bundle_id: Option<&str>) -> Self {
        Self {
            results,
            source: QuerySource::Imported,
            applied_filter: if let Some(id) = bundle_id {
                NamespaceFilter::specific_bundle(id)
            } else {
                NamespaceFilter::imported_only()
            },
            warning: None,
        }
    }

    /// Create result from mixed query (with warning)
    pub fn mixed(results: T) -> Self {
        Self {
            results,
            source: QuerySource::Mixed,
            applied_filter: NamespaceFilter::all(),
            warning: Some(
                "Results include both live and imported data. \
                 Imported data may not reflect current system state."
                    .to_string(),
            ),
        }
    }

    /// Create from filter
    pub fn from_filter(results: T, filter: &NamespaceFilter) -> Self {
        let source = QuerySource::from_filter(filter);
        let warning = if source == QuerySource::Mixed {
            Some(
                "Results include both live and imported data. \
                 Imported data may not reflect current system state."
                    .to_string(),
            )
        } else {
            None
        };

        Self {
            results,
            source,
            applied_filter: filter.clone(),
            warning,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_filter_excludes_imported() {
        let filter = NamespaceFilter::default();

        assert!(filter.should_include("live_stream"));
        assert!(filter.should_include("process_exec"));

        // Imported should be excluded by default
        assert!(!filter.should_include("imported_bundle_test123"));
        assert!(!filter.should_include("IMPORTED_test123"));
    }

    #[test]
    fn test_explicit_include_imported() {
        let filter = NamespaceFilter::all();

        assert!(filter.should_include("live_stream"));
        assert!(filter.should_include("imported_bundle_test123"));
    }

    #[test]
    fn test_imported_only() {
        let filter = NamespaceFilter::imported_only();

        assert!(!filter.should_include("live_stream"));
        assert!(filter.should_include("imported_bundle_test123"));
    }

    #[test]
    fn test_specific_bundle() {
        let filter = NamespaceFilter::specific_bundle("bundle-abc");

        assert!(!filter.should_include("live_stream"));
        assert!(!filter.should_include("imported_bundle_other"));
        assert!(filter.should_include("imported_bundle_bundle-abc"));
    }

    #[test]
    fn test_is_imported_namespace() {
        assert!(is_imported_namespace("imported_bundle_test"));
        assert!(is_imported_namespace("IMPORTED_test"));
        assert!(is_imported_namespace(
            "/telemetry/imported/IMPORTED_test/events"
        ));

        assert!(!is_imported_namespace("live_stream"));
        assert!(!is_imported_namespace("process_exec"));
    }

    #[test]
    fn test_extract_bundle_id() {
        assert_eq!(
            extract_bundle_id("imported_bundle_test-123"),
            Some("test-123".to_string())
        );
        assert_eq!(
            extract_bundle_id("IMPORTED_abc-def"),
            Some("abc-def".to_string())
        );
        assert_eq!(extract_bundle_id("live_stream"), None);
    }

    #[test]
    fn test_make_imported_namespace() {
        assert_eq!(
            make_imported_namespace("bundle-123"),
            "imported_bundle_bundle-123"
        );
    }

    #[test]
    fn test_query_source_from_filter() {
        assert_eq!(
            QuerySource::from_filter(&NamespaceFilter::live_only()),
            QuerySource::Live
        );
        assert_eq!(
            QuerySource::from_filter(&NamespaceFilter::imported_only()),
            QuerySource::Imported
        );
        assert_eq!(
            QuerySource::from_filter(&NamespaceFilter::all()),
            QuerySource::Mixed
        );
    }

    #[test]
    fn test_filter_namespaces() {
        let namespaces = vec![
            "live_stream".to_string(),
            "imported_bundle_test".to_string(),
            "process_exec".to_string(),
            "IMPORTED_bundle2".to_string(),
        ];

        let filter = NamespaceFilter::live_only();
        let filtered = filter.filter_namespaces(&namespaces);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|n| *n == "live_stream"));
        assert!(filtered.iter().any(|n| *n == "process_exec"));
    }
}

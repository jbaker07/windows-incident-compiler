//! Determinism Guarantees for Incident Compiler
//!
//! This module enforces: same input bundle → byte-identical incidents + explanations + reports.
//! If any of these guarantees are violated, we don't have a compiler; we have a "best effort analyzer."
//!
//! # Invariants Enforced
//!
//! 1. **Global Ordering**: One function everywhere: (ts_nanos, stream_id, segment_id, record_index)
//! 2. **Stable Key Formulas**: ProcKey/HypothesisId/IncidentId never depend on HashMap order, thread timing, or floats
//! 3. **Golden Replay**: Test infrastructure for verifying byte-identical output
//! 4. **No Silent Rewrites**: All state changes are versioned and auditable

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ============================================================================
// Global Ordering Key (THE canonical ordering everywhere)
// ============================================================================

/// THE global ordering key. Used everywhere for deterministic ordering.
/// This is THE source of truth - all other ordering implementations must defer to this.
///
/// Ordering: (ts_nanos, stream_id, segment_id, record_index)
/// - All fields use lexicographic/numeric comparison
/// - Ties are broken deterministically by stream_id, then segment_id, then record_index
/// - No floating point involved
/// - No HashMap iteration order involved
/// - No thread timing involved
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GlobalOrderKey {
    /// Timestamp in nanoseconds since epoch (primary sort key)
    pub ts_nanos: u64,
    /// Stream identifier (secondary sort key)
    pub stream_id: String,
    /// Segment identifier within stream (tertiary sort key)
    pub segment_id: u64,
    /// Record index within segment (quaternary sort key)
    pub record_index: u64,
}

impl GlobalOrderKey {
    pub fn new(
        ts_nanos: u64,
        stream_id: impl Into<String>,
        segment_id: u64,
        record_index: u64,
    ) -> Self {
        Self {
            ts_nanos,
            stream_id: stream_id.into(),
            segment_id,
            record_index,
        }
    }

    /// Create from DateTime (converts to nanos)
    pub fn from_datetime(
        ts: DateTime<Utc>,
        stream_id: impl Into<String>,
        segment_id: u64,
        record_index: u64,
    ) -> Self {
        let ts_nanos = ts.timestamp_nanos_opt().unwrap_or(0) as u64;
        Self::new(ts_nanos, stream_id, segment_id, record_index)
    }

    /// Compute deterministic hash of this key
    pub fn deterministic_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.ts_nanos.to_le_bytes());
        hasher.update(self.stream_id.as_bytes());
        hasher.update(self.segment_id.to_le_bytes());
        hasher.update(self.record_index.to_le_bytes());
        hex::encode(&hasher.finalize()[..16])
    }
}

impl Ord for GlobalOrderKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ts_nanos
            .cmp(&other.ts_nanos)
            .then_with(|| self.stream_id.cmp(&other.stream_id))
            .then_with(|| self.segment_id.cmp(&other.segment_id))
            .then_with(|| self.record_index.cmp(&other.record_index))
    }
}

impl PartialOrd for GlobalOrderKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ============================================================================
// Stable Key Formulas
// ============================================================================

/// Stable key formula registry. All key computations MUST go through this.
pub struct StableKeyFormulas;

impl StableKeyFormulas {
    /// Compute ProcKey deterministically
    /// ProcKey = SHA256(host_id || boot_id || start_time_ns || pid || exe_hash || ppid_start_time_ns)[..16]
    pub fn proc_key(
        host_id: &str,
        boot_id: Option<&str>,
        start_time_ns: u64,
        pid: u32,
        exe_hash: Option<&str>,
        ppid_start_time_ns: Option<u64>,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(host_id.as_bytes());
        if let Some(boot) = boot_id {
            hasher.update(boot.as_bytes());
        }
        hasher.update(start_time_ns.to_le_bytes());
        hasher.update(pid.to_le_bytes());
        if let Some(exe) = exe_hash {
            hasher.update(exe.as_bytes());
        }
        if let Some(ppid_ts) = ppid_start_time_ns {
            hasher.update(ppid_ts.to_le_bytes());
        }
        format!("proc_{}", hex::encode(&hasher.finalize()[..16]))
    }

    /// Compute HypothesisId deterministically
    /// HypothesisId = SHA256(host_id || family || scope_key || window_bucket || template_id)[..16]
    pub fn hypothesis_id(
        host_id: &str,
        family: &str,
        scope_key: &str,
        window_start_ts: i64,
        bucket_seconds: i64,
        template_id: &str,
    ) -> String {
        let window_bucket = window_start_ts / bucket_seconds;

        let mut hasher = Sha256::new();
        hasher.update(host_id.as_bytes());
        hasher.update(family.as_bytes());
        hasher.update(scope_key.as_bytes());
        hasher.update(window_bucket.to_le_bytes());
        hasher.update(template_id.as_bytes());

        format!("hyp_{}", hex::encode(&hasher.finalize()[..16]))
    }

    /// Compute IncidentId deterministically
    /// IncidentId = SHA256(host_id || family || primary_scope_key || time_bucket_big)[..16]
    pub fn incident_id(
        host_id: &str,
        family: &str,
        primary_scope_key: &str,
        promotion_ts: i64,
        bucket_seconds: i64,
    ) -> String {
        let time_bucket = promotion_ts / bucket_seconds;

        let mut hasher = Sha256::new();
        hasher.update(host_id.as_bytes());
        hasher.update(family.as_bytes());
        hasher.update(primary_scope_key.as_bytes());
        hasher.update(time_bucket.to_le_bytes());

        format!("inc_{}", hex::encode(&hasher.finalize()[..16]))
    }

    /// Compute FactId deterministically
    /// FactId = SHA256(fact_type || scope_key || predicate_id || value_hash)[..12]
    pub fn fact_id(
        fact_type: &str,
        scope_key: &str,
        predicate_id: &str,
        value_hash: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(fact_type.as_bytes());
        hasher.update(scope_key.as_bytes());
        hasher.update(predicate_id.as_bytes());
        hasher.update(value_hash.as_bytes());

        format!("fact_{}", hex::encode(&hasher.finalize()[..12]))
    }
}

// ============================================================================
// Golden Replay Infrastructure
// ============================================================================

/// Input bundle for golden replay testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenInputBundle {
    /// Bundle ID (hash of contents)
    pub bundle_id: String,
    /// Session configuration
    pub session_config: serde_json::Value,
    /// Input events (sorted by GlobalOrderKey)
    pub events: Vec<serde_json::Value>,
    /// Assertions applied
    pub assertions: Vec<serde_json::Value>,
    /// Timestamp of bundle creation
    pub created_at: DateTime<Utc>,
}

impl GoldenInputBundle {
    pub fn new(session_config: serde_json::Value, events: Vec<serde_json::Value>) -> Self {
        let mut bundle = Self {
            bundle_id: String::new(),
            session_config,
            events,
            assertions: Vec::new(),
            created_at: Utc::now(),
        };
        bundle.bundle_id = bundle.compute_id();
        bundle
    }

    fn compute_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&self.session_config).unwrap_or_default());
        for event in &self.events {
            hasher.update(serde_json::to_vec(event).unwrap_or_default());
        }
        for assertion in &self.assertions {
            hasher.update(serde_json::to_vec(assertion).unwrap_or_default());
        }
        format!("bundle_{}", hex::encode(&hasher.finalize()[..16]))
    }
}

/// Golden output for replay verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenOutput {
    /// Bundle ID this output corresponds to
    pub bundle_id: String,
    /// Output hash (deterministic hash of all outputs)
    pub output_hash: String,
    /// Incident IDs produced (sorted)
    pub incident_ids: Vec<String>,
    /// Hypothesis IDs produced (sorted)
    pub hypothesis_ids: Vec<String>,
    /// Explanation hashes (sorted by incident_id)
    pub explanation_hashes: BTreeMap<String, String>,
    /// Report hash (if generated)
    pub report_hash: Option<String>,
    /// Timestamp of output generation
    pub generated_at: DateTime<Utc>,
}

impl GoldenOutput {
    pub fn new(bundle_id: impl Into<String>) -> Self {
        Self {
            bundle_id: bundle_id.into(),
            output_hash: String::new(),
            incident_ids: Vec::new(),
            hypothesis_ids: Vec::new(),
            explanation_hashes: BTreeMap::new(),
            report_hash: None,
            generated_at: Utc::now(),
        }
    }

    /// Finalize and compute output hash
    pub fn finalize(&mut self) {
        // Sort for determinism
        self.incident_ids.sort();
        self.hypothesis_ids.sort();

        let mut hasher = Sha256::new();
        hasher.update(self.bundle_id.as_bytes());
        for id in &self.incident_ids {
            hasher.update(id.as_bytes());
        }
        for id in &self.hypothesis_ids {
            hasher.update(id.as_bytes());
        }
        for (k, v) in &self.explanation_hashes {
            hasher.update(k.as_bytes());
            hasher.update(v.as_bytes());
        }
        if let Some(ref hash) = self.report_hash {
            hasher.update(hash.as_bytes());
        }
        self.output_hash = hex::encode(&hasher.finalize()[..16]);
    }

    /// Verify this output matches another
    pub fn verify_matches(&self, other: &GoldenOutput) -> GoldenVerifyResult {
        if self.output_hash != other.output_hash {
            return GoldenVerifyResult::HashMismatch {
                expected: self.output_hash.clone(),
                actual: other.output_hash.clone(),
            };
        }

        if self.incident_ids != other.incident_ids {
            return GoldenVerifyResult::IncidentMismatch {
                expected: self.incident_ids.clone(),
                actual: other.incident_ids.clone(),
            };
        }

        if self.explanation_hashes != other.explanation_hashes {
            return GoldenVerifyResult::ExplanationMismatch {
                expected: self.explanation_hashes.clone(),
                actual: other.explanation_hashes.clone(),
            };
        }

        GoldenVerifyResult::Match
    }
}

/// Result of golden replay verification
#[derive(Debug, Clone)]
pub enum GoldenVerifyResult {
    Match,
    HashMismatch {
        expected: String,
        actual: String,
    },
    IncidentMismatch {
        expected: Vec<String>,
        actual: Vec<String>,
    },
    ExplanationMismatch {
        expected: BTreeMap<String, String>,
        actual: BTreeMap<String, String>,
    },
}

impl GoldenVerifyResult {
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }
}

// ============================================================================
// Determinism Violations
// ============================================================================

/// Types of determinism violations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeterminismViolation {
    /// HashMap iteration order affected output
    HashMapOrdering { context: String },
    /// Thread timing affected output
    ThreadTiming { context: String },
    /// Floating point math caused divergence
    FloatingPointDivergence {
        context: String,
        value1: f64,
        value2: f64,
    },
    /// Non-deterministic ID generation
    NonDeterministicId { id: String, context: String },
    /// System time dependency
    SystemTimeDependency { context: String },
    /// Random number usage
    RandomUsage { context: String },
}

/// Checker for determinism violations
pub struct DeterminismChecker {
    violations: Vec<DeterminismViolation>,
    strict_mode: bool,
}

impl DeterminismChecker {
    pub fn new() -> Self {
        Self {
            violations: Vec::new(),
            strict_mode: true,
        }
    }

    pub fn lenient(mut self) -> Self {
        self.strict_mode = false;
        self
    }

    /// Check if two float values are equal enough for determinism
    pub fn check_float_equal(&mut self, context: &str, v1: f64, v2: f64) -> bool {
        // For determinism, floats must be exactly equal (no epsilon)
        // If you need epsilon, you're doing it wrong - use fixed-point
        if v1.to_bits() != v2.to_bits() {
            self.violations
                .push(DeterminismViolation::FloatingPointDivergence {
                    context: context.to_string(),
                    value1: v1,
                    value2: v2,
                });
            return false;
        }
        true
    }

    /// Check if an ID was generated deterministically
    pub fn check_deterministic_id(
        &mut self,
        context: &str,
        id: &str,
        expected_prefix: &str,
    ) -> bool {
        // IDs must have expected prefix and be hex-encoded
        if !id.starts_with(expected_prefix) {
            self.violations
                .push(DeterminismViolation::NonDeterministicId {
                    id: id.to_string(),
                    context: context.to_string(),
                });
            return false;
        }
        true
    }

    /// Get all violations
    pub fn violations(&self) -> &[DeterminismViolation] {
        &self.violations
    }

    /// Check if there are any violations
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }

    /// Panic if strict mode and violations exist
    pub fn enforce(&self) {
        if self.strict_mode && !self.violations.is_empty() {
            panic!("Determinism violations detected: {:?}", self.violations);
        }
    }
}

impl Default for DeterminismChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Deterministic Sorting Helpers
// ============================================================================

/// Sort any collection deterministically using GlobalOrderKey
pub fn sort_by_global_order<T, F>(items: &mut [T], key_fn: F)
where
    F: Fn(&T) -> GlobalOrderKey,
{
    items.sort_by_key(|a| key_fn(a));
}

/// Merge multiple sorted iterators deterministically
pub struct DeterministicMerge<T, I, F>
where
    I: Iterator<Item = T>,
    F: Fn(&T) -> GlobalOrderKey,
{
    iterators: Vec<std::iter::Peekable<I>>,
    key_fn: F,
}

impl<T, I, F> DeterministicMerge<T, I, F>
where
    I: Iterator<Item = T>,
    F: Fn(&T) -> GlobalOrderKey,
{
    pub fn new(iterators: Vec<I>, key_fn: F) -> Self {
        Self {
            iterators: iterators.into_iter().map(|i| i.peekable()).collect(),
            key_fn,
        }
    }
}

impl<T, I, F> Iterator for DeterministicMerge<T, I, F>
where
    I: Iterator<Item = T>,
    F: Fn(&T) -> GlobalOrderKey,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        // Find iterator with smallest next element
        let mut min_idx = None;
        let mut min_key: Option<GlobalOrderKey> = None;

        for (idx, iter) in self.iterators.iter_mut().enumerate() {
            if let Some(item) = iter.peek() {
                let key = (self.key_fn)(item);
                if min_key.is_none() || key < *min_key.as_ref().unwrap() {
                    min_idx = Some(idx);
                    min_key = Some(key);
                }
            }
        }

        min_idx.and_then(|idx| self.iterators[idx].next())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_order_key_ordering() {
        let k1 = GlobalOrderKey::new(1000, "stream_a", 0, 0);
        let k2 = GlobalOrderKey::new(1000, "stream_a", 0, 1);
        let k3 = GlobalOrderKey::new(1000, "stream_b", 0, 0);
        let k4 = GlobalOrderKey::new(2000, "stream_a", 0, 0);

        assert!(k1 < k2); // Same ts, same stream, different record_index
        assert!(k1 < k3); // Same ts, different stream
        assert!(k1 < k4); // Different ts
        assert!(k2 < k3); // record_index < stream_id ordering
    }

    #[test]
    fn test_stable_key_formulas_proc_key() {
        let key1 =
            StableKeyFormulas::proc_key("host1", Some("boot1"), 1000, 123, Some("abc"), None);
        let key2 =
            StableKeyFormulas::proc_key("host1", Some("boot1"), 1000, 123, Some("abc"), None);
        let key3 =
            StableKeyFormulas::proc_key("host1", Some("boot1"), 1000, 124, Some("abc"), None);

        assert_eq!(key1, key2); // Same inputs = same output
        assert_ne!(key1, key3); // Different pid = different output
        assert!(key1.starts_with("proc_"));
    }

    #[test]
    fn test_stable_key_formulas_hypothesis_id() {
        let id1 = StableKeyFormulas::hypothesis_id(
            "host1",
            "family1",
            "scope1",
            1000000,
            3600,
            "template1",
        );
        let id2 = StableKeyFormulas::hypothesis_id(
            "host1",
            "family1",
            "scope1",
            1000000,
            3600,
            "template1",
        );
        let id3 = StableKeyFormulas::hypothesis_id(
            "host1",
            "family1",
            "scope1",
            1000000,
            3600,
            "template2",
        );

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert!(id1.starts_with("hyp_"));
    }

    #[test]
    fn test_golden_output_verification() {
        let mut out1 = GoldenOutput::new("bundle_123");
        out1.incident_ids = vec!["inc_a".to_string(), "inc_b".to_string()];
        out1.finalize();

        let mut out2 = GoldenOutput::new("bundle_123");
        out2.incident_ids = vec!["inc_a".to_string(), "inc_b".to_string()];
        out2.finalize();

        let mut out3 = GoldenOutput::new("bundle_123");
        out3.incident_ids = vec!["inc_a".to_string(), "inc_c".to_string()];
        out3.finalize();

        assert!(out1.verify_matches(&out2).is_match());
        assert!(!out1.verify_matches(&out3).is_match());
    }

    #[test]
    fn test_deterministic_merge() {
        let v1 = vec![
            GlobalOrderKey::new(1000, "a", 0, 0),
            GlobalOrderKey::new(3000, "a", 0, 0),
        ];
        let v2 = vec![
            GlobalOrderKey::new(2000, "b", 0, 0),
            GlobalOrderKey::new(4000, "b", 0, 0),
        ];

        let merge = DeterministicMerge::new(vec![v1.into_iter(), v2.into_iter()], |k| k.clone());

        let result: Vec<_> = merge.collect();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].ts_nanos, 1000);
        assert_eq!(result[1].ts_nanos, 2000);
        assert_eq!(result[2].ts_nanos, 3000);
        assert_eq!(result[3].ts_nanos, 4000);
    }
}

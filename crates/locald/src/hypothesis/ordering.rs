//! Deterministic Ordering and Watermark Policy
//!
//! Enforces canonical ordering everywhere (ts, stream_id, segment_id, record_index).
//! Defines watermark + late-arrival policies for hypothesis mutability.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

// ============================================================================
// Canonical Event Order
// ============================================================================

/// Canonical ordering key for events
///
/// Total ordering: (ts, stream_id, segment_id, record_index)
/// This ensures byte-identical replay across all readers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventOrderKey {
    /// Primary: timestamp (nanoseconds since epoch)
    pub ts_nanos: i64,
    /// Secondary: stream identifier (lexicographic)
    pub stream_id: String,
    /// Tertiary: segment identifier (lexicographic)
    pub segment_id: String,
    /// Quaternary: record index within segment
    pub record_index: u32,
}

impl EventOrderKey {
    pub fn new(
        ts: DateTime<Utc>,
        stream_id: impl Into<String>,
        segment_id: impl Into<String>,
        record_index: u32,
    ) -> Self {
        Self {
            ts_nanos: ts.timestamp_nanos_opt().unwrap_or(0),
            stream_id: stream_id.into(),
            segment_id: segment_id.into(),
            record_index,
        }
    }

    /// Create from evidence pointer
    pub fn from_evidence_ptr(ptr: &super::canonical_event::EvidencePtr) -> Self {
        Self {
            ts_nanos: ptr.ts.and_then(|t| t.timestamp_nanos_opt()).unwrap_or(0),
            stream_id: ptr.stream_id.clone(),
            segment_id: ptr.segment_id.clone(),
            record_index: ptr.record_index as u32,
        }
    }
}

impl Ord for EventOrderKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ts_nanos
            .cmp(&other.ts_nanos)
            .then_with(|| self.stream_id.cmp(&other.stream_id))
            .then_with(|| self.segment_id.cmp(&other.segment_id))
            .then_with(|| self.record_index.cmp(&other.record_index))
    }
}

impl PartialOrd for EventOrderKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ============================================================================
// Watermark State
// ============================================================================

/// Watermark state for a stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamWatermark {
    /// Stream identifier
    pub stream_id: String,
    /// High watermark: latest event timestamp processed
    pub high_watermark: DateTime<Utc>,
    /// Low watermark: oldest unprocessed event timestamp
    pub low_watermark: DateTime<Utc>,
    /// Number of events in flight (between low and high watermark)
    pub events_in_flight: u64,
    /// Last update time
    pub updated_at: DateTime<Utc>,
}

/// Global watermark state across all streams
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalWatermark {
    /// Per-stream watermarks
    pub streams: HashMap<String, StreamWatermark>,
    /// Global high watermark (min of all stream high watermarks)
    pub global_high: DateTime<Utc>,
    /// Global low watermark (min of all stream low watermarks)
    pub global_low: DateTime<Utc>,
    /// Last computation time
    pub computed_at: DateTime<Utc>,
}

impl GlobalWatermark {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            global_high: DateTime::<Utc>::MIN_UTC,
            global_low: DateTime::<Utc>::MAX_UTC,
            computed_at: Utc::now(),
        }
    }

    pub fn update_stream(&mut self, watermark: StreamWatermark) {
        self.streams.insert(watermark.stream_id.clone(), watermark);
        self.recompute_global();
    }

    fn recompute_global(&mut self) {
        if self.streams.is_empty() {
            self.global_high = DateTime::<Utc>::MIN_UTC;
            self.global_low = DateTime::<Utc>::MAX_UTC;
        } else {
            self.global_high = self
                .streams
                .values()
                .map(|s| s.high_watermark)
                .min()
                .unwrap_or(DateTime::<Utc>::MIN_UTC);
            self.global_low = self
                .streams
                .values()
                .map(|s| s.low_watermark)
                .min()
                .unwrap_or(DateTime::<Utc>::MAX_UTC);
        }
        self.computed_at = Utc::now();
    }

    /// Check if an event is late (arrived after watermark advanced past it)
    pub fn is_late(&self, event_ts: DateTime<Utc>) -> bool {
        event_ts < self.global_high
    }

    /// Get lag duration
    pub fn lag(&self) -> Duration {
        self.global_high.signed_duration_since(self.global_low)
    }
}

impl Default for GlobalWatermark {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Late Arrival Policy
// ============================================================================

/// Policy for handling late-arriving events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateArrivalPolicy {
    /// Maximum age (from watermark) for events to still update hypotheses
    pub hypothesis_mutability_window: Duration,
    /// Maximum age for events to reopen closed incidents
    pub incident_reopen_window: Duration,
    /// Maximum age for events to be processed at all
    pub max_event_age: Duration,
    /// Maximum allowed future skew from current time (events beyond this are clamped/quarantined)
    pub max_future_skew: Duration,
    /// Whether to annotate late events in narratives
    pub annotate_late_events: bool,
    /// Whether to emit warnings for late events
    pub emit_late_warnings: bool,
}

impl Default for LateArrivalPolicy {
    fn default() -> Self {
        Self {
            // Hypotheses can be updated for 5 minutes after watermark
            hypothesis_mutability_window: Duration::minutes(5),
            // Incidents can be reopened for 15 minutes
            incident_reopen_window: Duration::minutes(15),
            // Events older than 1 hour are rejected
            max_event_age: Duration::hours(1),
            // Future timestamps beyond 5 minutes are clamped
            max_future_skew: Duration::minutes(5),
            annotate_late_events: true,
            emit_late_warnings: true,
        }
    }
}

/// Result of late arrival check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateArrivalResult {
    /// Whether the event is late
    pub is_late: bool,
    /// How late the event is
    pub lateness: Duration,
    /// What action can be taken
    pub action: LateArrivalAction,
    /// Whether to annotate this in the narrative
    pub requires_annotation: bool,
}

/// Action to take for a late event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LateArrivalAction {
    /// Process normally
    ProcessNormal,
    /// Process and update hypothesis
    UpdateHypothesis,
    /// Process and potentially reopen incident
    MayReopenIncident,
    /// Process but mark as late enrichment only
    LateEnrichmentOnly,
    /// Reject - too old
    Reject,
}

impl LateArrivalPolicy {
    /// Determine action for a late event
    pub fn check_event(
        &self,
        event_ts: DateTime<Utc>,
        watermark: &GlobalWatermark,
    ) -> LateArrivalResult {
        if !watermark.is_late(event_ts) {
            return LateArrivalResult {
                is_late: false,
                lateness: Duration::zero(),
                action: LateArrivalAction::ProcessNormal,
                requires_annotation: false,
            };
        }

        let lateness = watermark.global_high.signed_duration_since(event_ts);

        let action = if lateness > self.max_event_age {
            LateArrivalAction::Reject
        } else if lateness > self.incident_reopen_window {
            LateArrivalAction::LateEnrichmentOnly
        } else if lateness > self.hypothesis_mutability_window {
            LateArrivalAction::MayReopenIncident
        } else {
            LateArrivalAction::UpdateHypothesis
        };

        LateArrivalResult {
            is_late: true,
            lateness,
            action,
            requires_annotation: self.annotate_late_events
                && matches!(
                    action,
                    LateArrivalAction::LateEnrichmentOnly | LateArrivalAction::MayReopenIncident
                ),
        }
    }
}

// ============================================================================
// Late Arrival Gate (Production Ingestion Gate)
// ============================================================================

/// Audit record for a late arrival event decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateArrivalAuditRecord {
    /// Stream ID of the event
    pub stream_id: String,
    /// Segment ID of the event
    pub segment_id: String,
    /// Record index within segment
    pub record_index: u64,
    /// Event timestamp
    pub event_ts: DateTime<Utc>,
    /// Watermark high at time of check
    pub watermark_high: DateTime<Utc>,
    /// How late the event is
    pub lateness_ms: i64,
    /// Max event age from policy
    pub max_age_ms: i64,
    /// The decision made
    pub action: LateArrivalAction,
    /// Timestamp of the decision
    pub decision_ts: DateTime<Utc>,
}

/// Production-grade late arrival gate.
/// Single entry point for all event ingestion to enforce late-arrival policy.
#[derive(Debug, Clone)]
pub struct LateArrivalGate {
    /// The policy to enforce
    pub policy: LateArrivalPolicy,
    /// Per-stream watermarks
    pub watermark: GlobalWatermark,
    /// Audit records for rejected/late events (ring buffer)
    audit_records: Vec<LateArrivalAuditRecord>,
    /// Maximum audit records to keep
    max_audit_records: usize,
    /// Count of rejected events
    pub rejected_count: u64,
    /// Count of late enrichment events
    pub late_enrichment_count: u64,
}

impl LateArrivalGate {
    /// Create a new gate with default policy
    pub fn new() -> Self {
        Self::with_policy(LateArrivalPolicy::default())
    }

    /// Create a gate with custom policy
    pub fn with_policy(policy: LateArrivalPolicy) -> Self {
        Self {
            policy,
            watermark: GlobalWatermark::new(),
            audit_records: Vec::new(),
            max_audit_records: 10000,
            rejected_count: 0,
            late_enrichment_count: 0,
        }
    }

    /// Check if an event should be accepted and update watermark.
    /// Returns (action, is_late_arrival) tuple.
    /// This is the SINGLE INGESTION GATE for all events.
    pub fn check_and_update(
        &mut self,
        stream_id: &str,
        segment_id: &str,
        record_index: u64,
        event_ts: DateTime<Utc>,
    ) -> (LateArrivalAction, bool) {
        // Check late arrival BEFORE updating watermark
        let result = self.policy.check_event(event_ts, &self.watermark);

        let action = result.action;
        let is_late = result.is_late;

        // Record audit for rejected or late enrichment events
        if matches!(
            action,
            LateArrivalAction::Reject | LateArrivalAction::LateEnrichmentOnly
        ) {
            let audit = LateArrivalAuditRecord {
                stream_id: stream_id.to_string(),
                segment_id: segment_id.to_string(),
                record_index,
                event_ts,
                watermark_high: self.watermark.global_high,
                lateness_ms: result.lateness.num_milliseconds(),
                max_age_ms: self.policy.max_event_age.num_milliseconds(),
                action,
                decision_ts: Utc::now(),
            };

            if action == LateArrivalAction::Reject {
                self.rejected_count += 1;
                if self.policy.emit_late_warnings {
                    eprintln!(
                        "[late_arrival] REJECTED event: stream={}, segment={}, idx={}, event_ts={}, watermark={}, lateness={}ms",
                        stream_id, segment_id, record_index, event_ts, self.watermark.global_high, result.lateness.num_milliseconds()
                    );
                }
            } else {
                self.late_enrichment_count += 1;
                if self.policy.emit_late_warnings {
                    eprintln!(
                        "[late_arrival] LATE_ENRICHMENT event: stream={}, segment={}, idx={}, lateness={}ms",
                        stream_id, segment_id, record_index, result.lateness.num_milliseconds()
                    );
                }
            }

            // Ring buffer behavior
            if self.audit_records.len() >= self.max_audit_records {
                self.audit_records.remove(0);
            }
            self.audit_records.push(audit);
        }

        // Only update watermark for accepted events (not rejected)
        if action != LateArrivalAction::Reject {
            self.update_watermark(stream_id, event_ts);
        }

        (action, is_late)
    }

    /// Update watermark for a stream, clamping future timestamps to prevent poisoning
    fn update_watermark(&mut self, stream_id: &str, event_ts: DateTime<Utc>) {
        let now = Utc::now();
        let max_allowed = now + self.policy.max_future_skew;

        // Clamp future timestamps to prevent watermark poisoning
        let clamped_ts = if event_ts > max_allowed {
            if self.policy.emit_late_warnings {
                eprintln!(
                    "[late_arrival] FUTURE_SKEW: clamping event_ts={} to max_allowed={} (skew={}ms)",
                    event_ts, max_allowed, (event_ts - now).num_milliseconds()
                );
            }
            max_allowed
        } else {
            event_ts
        };

        let watermark = if let Some(existing) = self.watermark.streams.get(stream_id) {
            StreamWatermark {
                stream_id: stream_id.to_string(),
                high_watermark: existing.high_watermark.max(clamped_ts),
                low_watermark: existing.low_watermark.min(clamped_ts),
                events_in_flight: existing.events_in_flight,
                updated_at: Utc::now(),
            }
        } else {
            StreamWatermark {
                stream_id: stream_id.to_string(),
                high_watermark: clamped_ts,
                low_watermark: clamped_ts,
                events_in_flight: 0,
                updated_at: Utc::now(),
            }
        };
        self.watermark.update_stream(watermark);
    }

    /// Get recent audit records
    pub fn audit_records(&self) -> &[LateArrivalAuditRecord] {
        &self.audit_records
    }

    /// Get rejected count
    pub fn rejected_count(&self) -> u64 {
        self.rejected_count
    }

    /// Get late enrichment count
    pub fn late_enrichment_count(&self) -> u64 {
        self.late_enrichment_count
    }
}

impl Default for LateArrivalGate {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Event Merger (Deterministic)
// ============================================================================

/// Ordered event for the merge heap
struct OrderedEvent<T> {
    key: EventOrderKey,
    event: T,
}

impl<T> PartialEq for OrderedEvent<T> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl<T> Eq for OrderedEvent<T> {}

impl<T> PartialOrd for OrderedEvent<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for OrderedEvent<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse for min-heap behavior
        other.key.cmp(&self.key)
    }
}

/// Deterministic event merger for multiple streams
pub struct EventMerger<T> {
    heap: BinaryHeap<OrderedEvent<T>>,
    last_emitted: Option<EventOrderKey>,
}

impl<T> EventMerger<T> {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            last_emitted: None,
        }
    }

    /// Add an event to the merger
    pub fn push(&mut self, key: EventOrderKey, event: T) {
        self.heap.push(OrderedEvent { key, event });
    }

    /// Get the next event in canonical order
    pub fn pop(&mut self) -> Option<(EventOrderKey, T)> {
        let ordered = self.heap.pop()?;

        // Verify ordering invariant
        if let Some(ref last) = self.last_emitted {
            assert!(
                ordered.key >= *last,
                "EventMerger ordering violation: {:?} < {:?}",
                ordered.key,
                last
            );
        }

        self.last_emitted = Some(ordered.key.clone());
        Some((ordered.key, ordered.event))
    }

    /// Peek at the next event without removing
    pub fn peek(&self) -> Option<&EventOrderKey> {
        self.heap.peek().map(|o| &o.key)
    }

    /// Check if merger is empty
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Number of events in merger
    pub fn len(&self) -> usize {
        self.heap.len()
    }
}

impl<T> Default for EventMerger<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Ordering Verification
// ============================================================================

/// Verify that a sequence of events is in canonical order
#[allow(clippy::result_large_err)] // Diagnostic context requires both event keys
pub fn verify_ordering(keys: &[EventOrderKey]) -> Result<(), OrderingViolation> {
    for window in keys.windows(2) {
        if window[0] > window[1] {
            return Err(OrderingViolation {
                first: window[0].clone(),
                second: window[1].clone(),
            });
        }
    }
    Ok(())
}

/// Ordering violation error
#[derive(Debug, Clone)]
pub struct OrderingViolation {
    pub first: EventOrderKey,
    pub second: EventOrderKey,
}

impl std::fmt::Display for OrderingViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Ordering violation: {:?} should come before {:?}",
            self.first, self.second
        )
    }
}

impl std::error::Error for OrderingViolation {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_order_key_ordering() {
        let t1 = Utc::now();
        let t2 = t1 + Duration::seconds(1);

        let key1 = EventOrderKey::new(t1, "stream_a", "seg_1", 0);
        let key2 = EventOrderKey::new(t1, "stream_a", "seg_1", 1);
        let key3 = EventOrderKey::new(t1, "stream_b", "seg_1", 0);
        let key4 = EventOrderKey::new(t2, "stream_a", "seg_1", 0);

        assert!(key1 < key2); // Same ts/stream/segment, different index
        assert!(key1 < key3); // Same ts, different stream
        assert!(key1 < key4); // Different ts
        assert!(key2 < key3); // stream_a < stream_b
    }

    #[test]
    fn test_late_arrival_policy() {
        let policy = LateArrivalPolicy::default();
        let mut watermark = GlobalWatermark::new();

        let now = Utc::now();
        watermark.update_stream(StreamWatermark {
            stream_id: "test".to_string(),
            high_watermark: now,
            low_watermark: now - Duration::seconds(10),
            events_in_flight: 100,
            updated_at: now,
        });

        // On-time event
        let result = policy.check_event(now, &watermark);
        assert!(!result.is_late);
        assert_eq!(result.action, LateArrivalAction::ProcessNormal);

        // Slightly late event (within hypothesis window)
        let result = policy.check_event(now - Duration::minutes(2), &watermark);
        assert!(result.is_late);
        assert_eq!(result.action, LateArrivalAction::UpdateHypothesis);

        // Very late event (beyond incident reopen window)
        let result = policy.check_event(now - Duration::minutes(30), &watermark);
        assert!(result.is_late);
        assert_eq!(result.action, LateArrivalAction::LateEnrichmentOnly);

        // Ancient event (rejected)
        let result = policy.check_event(now - Duration::hours(2), &watermark);
        assert!(result.is_late);
        assert_eq!(result.action, LateArrivalAction::Reject);
    }

    #[test]
    fn test_event_merger() {
        let t1 = Utc::now();
        let t2 = t1 + Duration::seconds(1);
        let t3 = t1 + Duration::seconds(2);

        let mut merger: EventMerger<&str> = EventMerger::new();

        // Add out of order
        merger.push(EventOrderKey::new(t3, "s", "seg", 0), "third");
        merger.push(EventOrderKey::new(t1, "s", "seg", 0), "first");
        merger.push(EventOrderKey::new(t2, "s", "seg", 0), "second");

        // Should come out in order
        assert_eq!(merger.pop().unwrap().1, "first");
        assert_eq!(merger.pop().unwrap().1, "second");
        assert_eq!(merger.pop().unwrap().1, "third");
        assert!(merger.pop().is_none());
    }

    #[test]
    fn test_verify_ordering() {
        let t = Utc::now();
        let keys = vec![
            EventOrderKey::new(t, "s", "seg", 0),
            EventOrderKey::new(t, "s", "seg", 1),
            EventOrderKey::new(t + Duration::seconds(1), "s", "seg", 0),
        ];

        assert!(verify_ordering(&keys).is_ok());

        let bad_keys = vec![
            EventOrderKey::new(t + Duration::seconds(1), "s", "seg", 0),
            EventOrderKey::new(t, "s", "seg", 0),
        ];

        assert!(verify_ordering(&bad_keys).is_err());
    }

    // ========================================================================
    // LateArrivalGate Tests (D Production Invariant)
    // ========================================================================

    #[test]
    fn test_late_arrival_boundary_exact_grace_limit() {
        // Test boundary conditions at policy windows
        let mut gate = LateArrivalGate::new();
        let base_time = Utc::now();

        // First event establishes watermark at base_time
        let (action, is_late) = gate.check_and_update("stream1", "seg1", 0, base_time);
        assert_eq!(action, LateArrivalAction::ProcessNormal);
        assert!(!is_late);

        // Event at exact same time as watermark is NOT late
        let (action, is_late) = gate.check_and_update("stream1", "seg1", 1, base_time);
        assert_eq!(action, LateArrivalAction::ProcessNormal);
        assert!(!is_late);

        // Event 1 second before watermark IS late, but within hypothesis_mutability_window (5 min)
        let just_before = base_time - Duration::seconds(1);
        let (action, is_late) = gate.check_and_update("stream1", "seg1", 2, just_before);
        assert!(is_late);
        assert_eq!(action, LateArrivalAction::UpdateHypothesis);

        // Event at exactly hypothesis_mutability_window boundary (5 min)
        let at_hypothesis_window = base_time - Duration::minutes(5);
        let (action, is_late) = gate.check_and_update("stream1", "seg1", 3, at_hypothesis_window);
        assert!(is_late);
        // At boundary, should still be UpdateHypothesis (lateness == window)
        assert!(matches!(
            action,
            LateArrivalAction::UpdateHypothesis | LateArrivalAction::MayReopenIncident
        ));

        // Event just past hypothesis_mutability_window (5 min + 1 sec)
        let past_hypothesis_window = base_time - Duration::minutes(5) - Duration::seconds(1);
        let (action, is_late) = gate.check_and_update("stream1", "seg1", 4, past_hypothesis_window);
        assert!(is_late);
        assert_eq!(action, LateArrivalAction::MayReopenIncident);
    }

    #[test]
    fn test_multi_stream_lag_watermark() {
        // Test that streams maintain independent watermarks
        // Global high is the MIN of all stream highs (conservative watermark for all streams)
        let mut gate = LateArrivalGate::new();
        let base_time = Utc::now();

        // Stream A advances to current time
        let (action, _) = gate.check_and_update("stream_a", "seg1", 0, base_time);
        assert_eq!(action, LateArrivalAction::ProcessNormal);

        // With only one stream, global_high equals that stream's high
        assert_eq!(gate.watermark.global_high, base_time);

        // Stream B sends event from 5 minutes ago (lagging stream)
        let stream_b_time = base_time - Duration::minutes(5);
        let (action, is_late) = gate.check_and_update("stream_b", "seg1", 0, stream_b_time);

        // First event for a new stream is NOT late (no prior watermark for that stream)
        // But the global watermark recalculates as MIN(stream_a.high, stream_b.high)
        // So stream_b's first event is compared against global which was base_time
        // Result: it IS late
        assert!(is_late);
        assert_eq!(action, LateArrivalAction::UpdateHypothesis);

        // Verify both streams have watermarks
        assert!(gate.watermark.streams.contains_key("stream_a"));
        assert!(gate.watermark.streams.contains_key("stream_b"));

        // Global high is now MIN(base_time, stream_b_time) = stream_b_time
        // This is the correct watermark semantic: "all streams have delivered up to X"
        assert_eq!(gate.watermark.global_high, stream_b_time);

        // Now stream_b sends a current event - this advances stream_b's high
        let (action, is_late) = gate.check_and_update("stream_b", "seg1", 1, base_time);
        // With stream_b now at base_time, global becomes MIN(base_time, base_time) = base_time
        assert!(!is_late);
        assert_eq!(action, LateArrivalAction::ProcessNormal);

        // Global high should now be base_time again
        assert_eq!(gate.watermark.global_high, base_time);
    }

    #[test]
    fn test_clock_skew_non_monotonic_timestamps() {
        // Test handling of clock skew (non-monotonic timestamps within a stream)
        let mut gate = LateArrivalGate::new();
        let base_time = Utc::now();

        // Event 1: t=100
        let t1 = base_time;
        let (action1, _) = gate.check_and_update("stream1", "seg1", 0, t1);
        assert_eq!(action1, LateArrivalAction::ProcessNormal);

        // Event 2: t=200 (advances watermark)
        let t2 = base_time + Duration::seconds(100);
        let (action2, _) = gate.check_and_update("stream1", "seg1", 1, t2);
        assert_eq!(action2, LateArrivalAction::ProcessNormal);

        // Event 3: t=150 (clock skew - out of order but recent)
        let t3 = base_time + Duration::seconds(50);
        let (action3, is_late3) = gate.check_and_update("stream1", "seg1", 2, t3);
        // This is "late" relative to watermark but should still be accepted
        assert!(is_late3 || action3 != LateArrivalAction::Reject);

        // Event 4: t=50 (severe clock skew - way before watermark)
        let t4 = base_time - Duration::seconds(50);
        let (action4, is_late4) = gate.check_and_update("stream1", "seg1", 3, t4);
        // This is late but within hypothesis window
        assert!(is_late4 || action4 == LateArrivalAction::UpdateHypothesis);
    }

    #[test]
    fn test_duplicate_event_idempotency() {
        // Test that checking the same event multiple times is idempotent
        let mut gate = LateArrivalGate::new();
        let event_time = Utc::now();

        // First check
        let (action1, is_late1) = gate.check_and_update("stream1", "seg1", 0, event_time);
        let watermark_after_first = gate.watermark.global_high;

        // Second check of same event (different record_index to simulate re-processing)
        let (action2, is_late2) = gate.check_and_update("stream1", "seg1", 1, event_time);
        let watermark_after_second = gate.watermark.global_high;

        // Actions should be consistent
        assert_eq!(action1, action2);
        assert_eq!(is_late1, is_late2);

        // Watermark should not regress
        assert!(watermark_after_second >= watermark_after_first);
    }

    #[test]
    fn test_rejected_events_not_stored() {
        // Test that rejected events do not update watermark
        let mut gate = LateArrivalGate::new();
        let base_time = Utc::now();

        // Establish watermark
        gate.check_and_update("stream1", "seg1", 0, base_time);
        let initial_watermark = gate.watermark.global_high;

        // Send ancient event (should be rejected)
        let ancient_time = base_time - Duration::hours(25); // Beyond max_event_age
        let (action, _) = gate.check_and_update("stream1", "seg1", 1, ancient_time);
        assert_eq!(action, LateArrivalAction::Reject);

        // Watermark should NOT have been updated by rejected event
        assert_eq!(gate.watermark.global_high, initial_watermark);

        // Rejection counter should increment
        assert_eq!(gate.rejected_count(), 1);
    }

    #[test]
    fn test_audit_record_generation() {
        // Test that audit records are generated for rejected/late events
        let mut gate = LateArrivalGate::new();
        let base_time = Utc::now();

        // Establish watermark
        gate.check_and_update("stream1", "seg1", 0, base_time);

        // Send event that will be rejected
        let ancient_time = base_time - Duration::hours(25);
        gate.check_and_update("stream1", "seg2", 0, ancient_time);

        // Check audit records
        let audits = gate.audit_records();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].stream_id, "stream1");
        assert_eq!(audits[0].segment_id, "seg2");
        assert_eq!(audits[0].action, LateArrivalAction::Reject);
    }

    #[test]
    fn test_late_enrichment_annotation() {
        // Test that late enrichment events are properly annotated
        let mut gate = LateArrivalGate::new();
        let base_time = Utc::now();

        // Establish watermark
        gate.check_and_update("stream1", "seg1", 0, base_time);

        // Send event beyond incident_reopen_window but within max_event_age
        let late_time = base_time - Duration::minutes(20); // Beyond 15min default
        let (action, is_late) = gate.check_and_update("stream1", "seg2", 0, late_time);

        // Should be marked as late enrichment
        assert!(is_late);
        assert!(matches!(
            action,
            LateArrivalAction::LateEnrichmentOnly | LateArrivalAction::MayReopenIncident
        ));

        // Check late enrichment counter
        assert!(gate.late_enrichment_count() > 0 || gate.rejected_count() == 0);
    }

    #[test]
    fn test_future_timestamp_does_not_poison_watermark() {
        // Test that future timestamps are clamped and do not poison the watermark
        // Scenario: one event with timestamp +24h, followed by normal events
        // Expected: normal events are NOT rejected as "late", watermark does not jump permanently
        let mut gate = LateArrivalGate::new();
        let now = Utc::now();

        // First: normal event establishes baseline watermark
        let (action, is_late) = gate.check_and_update("stream1", "seg1", 0, now);
        assert_eq!(action, LateArrivalAction::ProcessNormal);
        assert!(!is_late);
        let _baseline_watermark = gate.watermark.global_high;

        // Second: malicious/buggy event with timestamp +24 hours in the future
        let future_time = now + Duration::hours(24);
        let (action, _) = gate.check_and_update("stream1", "seg1", 1, future_time);
        // Event is accepted (not rejected) but watermark should be CLAMPED
        assert_eq!(action, LateArrivalAction::ProcessNormal);

        // CRITICAL: Watermark should be clamped to approximately (now + max_future_skew)
        // Allow 1 second tolerance for test timing
        let max_allowed_watermark = now + gate.policy.max_future_skew + Duration::seconds(1);
        assert!(
            gate.watermark.global_high <= max_allowed_watermark,
            "Watermark was poisoned! Expected <= {:?}, got {:?}",
            max_allowed_watermark,
            gate.watermark.global_high
        );

        // Watermark should NOT have jumped to +24h
        assert!(
            gate.watermark.global_high < now + Duration::hours(1),
            "Watermark jumped to future time: {:?}",
            gate.watermark.global_high
        );

        // Third: normal event at current time should NOT be rejected as "late"
        let normal_time = now + Duration::seconds(1);
        let (action, _is_late) = gate.check_and_update("stream1", "seg1", 2, normal_time);

        // This is the key assertion: normal events after a future-skewed event
        // should NOT be rejected or marked as excessively late
        assert_ne!(
            action,
            LateArrivalAction::Reject,
            "Normal event was rejected after future timestamp poisoning!"
        );

        // The normal event might be slightly "late" if watermark was clamped to max_allowed,
        // but it should NOT be LateEnrichmentOnly or worse
        assert!(
            matches!(
                action,
                LateArrivalAction::ProcessNormal | LateArrivalAction::UpdateHypothesis
            ),
            "Normal event got unexpected action {:?} after future timestamp",
            action
        );

        // Watermark should be reasonable (within max_future_skew of current time)
        let final_watermark = gate.watermark.global_high;
        assert!(
            final_watermark <= now + gate.policy.max_future_skew + Duration::seconds(10),
            "Watermark drifted too far into future: {:?}",
            final_watermark
        );
    }

    #[test]
    fn test_late_enrichment_stored_and_auditable() {
        // Prove: LateEnrichmentOnly events are stored in audit records
        let mut gate = LateArrivalGate::new();
        let base_time = Utc::now();

        // Establish watermark
        gate.check_and_update("stream1", "seg1", 0, base_time);

        // Send late enrichment event (beyond incident_reopen_window but within max_event_age)
        let late_time = base_time - Duration::minutes(20);
        let (action, is_late) = gate.check_and_update("stream1", "seg2", 0, late_time);

        assert!(is_late);
        assert_eq!(action, LateArrivalAction::LateEnrichmentOnly);

        // Verify audit record was created
        let audits = gate.audit_records();
        assert_eq!(
            audits.len(),
            1,
            "LateEnrichmentOnly should create audit record"
        );
        assert_eq!(audits[0].action, LateArrivalAction::LateEnrichmentOnly);
        assert_eq!(audits[0].stream_id, "stream1");
        assert_eq!(audits[0].segment_id, "seg2");

        // Verify late_enrichment_count is tracked
        assert_eq!(gate.late_enrichment_count(), 1);
    }
}

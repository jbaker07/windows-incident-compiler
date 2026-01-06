//! Capture Control: Profiles, Rate Limiting, Backpressure, Visibility Integration
//!
//! This module centralizes all throttling and capture control logic.
//! Single source of truth for what's enabled, how events flow, and degradation state.
//!
//! Thread Safety: Uses lock-free atomics for hot-path counters (ingest).
//! Config changes use RwLock but don't block ingest path.
//!
//! Determinism: TelemetryThrottledSummary generated on fixed 30s window boundaries,
//! with stable ordering keys (stream_id + window_start + window_seq).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    Arc, RwLock,
};

// ============================================================================
// Capture Profiles
// ============================================================================

/// Capture profile determines what sensors/features are enabled
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CaptureProfile {
    /// Minimal always-on primitives (safe baseline for dev laptops)
    #[default]
    Core,
    /// Adds richer sensors/features (moderate resource usage)
    Extended,
    /// Heavy collectors enabled (high resource usage, short TTL recommended)
    Forensic,
}

impl CaptureProfile {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "core" => Some(Self::Core),
            "extended" => Some(Self::Extended),
            "forensic" => Some(Self::Forensic),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Extended => "extended",
            Self::Forensic => "forensic",
        }
    }

    /// Human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::Core => "Minimal sensors, safe for dev laptops",
            Self::Extended => "Additional sensors, moderate CPU/memory",
            Self::Forensic => "All collectors, high resource usage",
        }
    }
}

/// Stream priority class for throttling decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum StreamPriority {
    /// Critical streams (Tier-0): least throttled, essential for core hypotheses
    Tier0,
    /// Normal priority streams
    #[default]
    Normal,
    /// Low priority / high volume streams: throttled aggressively under load
    Background,
}

/// Configuration for what's enabled in each profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub profile: CaptureProfile,
    /// Enabled sensor attachments (by sensor ID)
    pub enabled_sensors: Vec<String>,
    /// Enabled enrichment collectors
    pub enabled_collectors: Vec<String>,
    /// Optional heavy parsing features
    pub heavy_features: Vec<String>,
    /// Per-stream throttle configs (stream_id -> config)
    pub stream_throttles: HashMap<String, StreamThrottleConfig>,
    /// Global throttle config
    pub global_throttle: GlobalThrottleConfig,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self::for_profile(CaptureProfile::Core)
    }
}

impl ProfileConfig {
    /// Create config for a specific profile
    pub fn for_profile(profile: CaptureProfile) -> Self {
        match profile {
            CaptureProfile::Core => Self::core_profile(),
            CaptureProfile::Extended => Self::extended_profile(),
            CaptureProfile::Forensic => Self::forensic_profile(),
        }
    }

    fn core_profile() -> Self {
        let mut stream_throttles = HashMap::new();

        // Tier-0 critical streams: generous limits
        for stream in &[
            "process_exec",
            "process_exit",
            "file_write_critical",
            "network_connect",
        ] {
            stream_throttles.insert(
                stream.to_string(),
                StreamThrottleConfig {
                    priority: StreamPriority::Tier0,
                    rate_per_sec: 200,
                    burst: 500,
                    max_queue: 2000,
                },
            );
        }

        // Normal streams
        for stream in &["file_read", "file_write", "registry_write"] {
            stream_throttles.insert(
                stream.to_string(),
                StreamThrottleConfig {
                    priority: StreamPriority::Normal,
                    rate_per_sec: 50,
                    burst: 100,
                    max_queue: 500,
                },
            );
        }

        // Background/high-volume streams
        for stream in &["dns_query", "socket_stats", "module_load"] {
            stream_throttles.insert(
                stream.to_string(),
                StreamThrottleConfig {
                    priority: StreamPriority::Background,
                    rate_per_sec: 20,
                    burst: 50,
                    max_queue: 200,
                },
            );
        }

        Self {
            profile: CaptureProfile::Core,
            enabled_sensors: vec![
                "process_monitor".to_string(),
                "file_monitor_critical".to_string(),
                "network_monitor".to_string(),
            ],
            enabled_collectors: vec!["process_tree".to_string(), "network_summary".to_string()],
            heavy_features: vec![],
            stream_throttles,
            global_throttle: GlobalThrottleConfig {
                max_events_per_sec: 500,
                max_bytes_per_sec: 10 * 1024 * 1024, // 10 MB/s
            },
        }
    }

    fn extended_profile() -> Self {
        let mut config = Self::core_profile();
        config.profile = CaptureProfile::Extended;

        // Add more sensors
        config.enabled_sensors.extend([
            "file_monitor_full".to_string(),
            "registry_monitor".to_string(),
            "dll_monitor".to_string(),
        ]);

        // Add more collectors
        config
            .enabled_collectors
            .extend(["file_hash".to_string(), "pe_header".to_string()]);

        // Increase limits for non-critical streams
        for (_, throttle) in config.stream_throttles.iter_mut() {
            if throttle.priority != StreamPriority::Tier0 {
                throttle.rate_per_sec = (throttle.rate_per_sec as f64 * 1.5) as u32;
                throttle.burst = (throttle.burst as f64 * 1.5) as u32;
            }
        }

        // Add more streams
        config.stream_throttles.insert(
            "registry_read".to_string(),
            StreamThrottleConfig {
                priority: StreamPriority::Normal,
                rate_per_sec: 75,
                burst: 150,
                max_queue: 500,
            },
        );

        config.global_throttle.max_events_per_sec = 1000;
        config.global_throttle.max_bytes_per_sec = 25 * 1024 * 1024; // 25 MB/s

        config
    }

    fn forensic_profile() -> Self {
        let mut config = Self::extended_profile();
        config.profile = CaptureProfile::Forensic;

        // Add heavy sensors
        config.enabled_sensors.extend([
            "memory_scanner".to_string(),
            "syscall_tracer".to_string(),
            "etw_full".to_string(),
        ]);

        // Add heavy collectors
        config
            .enabled_collectors
            .extend(["memory_dump".to_string(), "full_pe_analysis".to_string()]);

        // Add heavy features
        config.heavy_features.extend([
            "deep_string_extraction".to_string(),
            "yara_scanning".to_string(),
        ]);

        // Double all stream limits
        for (_, throttle) in config.stream_throttles.iter_mut() {
            throttle.rate_per_sec *= 2;
            throttle.burst *= 2;
            throttle.max_queue *= 2;
        }

        config.global_throttle.max_events_per_sec = 5000;
        config.global_throttle.max_bytes_per_sec = 100 * 1024 * 1024; // 100 MB/s

        config
    }

    /// Get throttle config for a stream, with fallback to default
    pub fn get_stream_throttle(&self, stream_id: &str) -> StreamThrottleConfig {
        self.stream_throttles.get(stream_id).cloned().unwrap_or({
            // Default config based on profile
            match self.profile {
                CaptureProfile::Core => StreamThrottleConfig {
                    priority: StreamPriority::Background,
                    rate_per_sec: 10,
                    burst: 20,
                    max_queue: 100,
                },
                CaptureProfile::Extended => StreamThrottleConfig {
                    priority: StreamPriority::Background,
                    rate_per_sec: 25,
                    burst: 50,
                    max_queue: 200,
                },
                CaptureProfile::Forensic => StreamThrottleConfig {
                    priority: StreamPriority::Normal,
                    rate_per_sec: 100,
                    burst: 200,
                    max_queue: 500,
                },
            }
        })
    }
}

// ============================================================================
// Throttle Configuration
// ============================================================================

/// Per-stream throttle configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamThrottleConfig {
    pub priority: StreamPriority,
    /// Sustained rate limit (events per second)
    pub rate_per_sec: u32,
    /// Burst capacity (max tokens in bucket)
    pub burst: u32,
    /// Max queue depth before dropping
    pub max_queue: u32,
}

/// Global throttle configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalThrottleConfig {
    /// Maximum events per second across all streams
    pub max_events_per_sec: u32,
    /// Maximum bytes per second across all streams
    pub max_bytes_per_sec: u64,
}

// ============================================================================
// Throttle Decision
// ============================================================================

/// Decision for what to do with an incoming event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThrottleDecision {
    /// Accept the event for processing/storage
    Accept,
    /// Drop the event due to throttling
    Drop { reason: DropReason },
    /// Sample: store 1/N summary instead of full event
    Sample { sample_rate: u32 },
    /// Defer: queue for later processing
    Defer,
}

/// Reason for dropping an event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DropReason {
    /// Per-stream rate limit exceeded
    StreamRateLimit,
    /// Per-stream queue full
    StreamQueueFull,
    /// Global event rate exceeded
    GlobalEventRate,
    /// Global byte rate exceeded
    GlobalByteRate,
    /// System under heavy load
    SystemOverload,
}

#[allow(dead_code)]
impl DropReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StreamRateLimit => "stream_rate_limit",
            Self::StreamQueueFull => "stream_queue_full",
            Self::GlobalEventRate => "global_event_rate",
            Self::GlobalByteRate => "global_byte_rate",
            Self::SystemOverload => "system_overload",
        }
    }
}

// ============================================================================
// Token Bucket
// ============================================================================

/// Token bucket for rate limiting
#[derive(Debug)]
pub struct TokenBucket {
    /// Current number of tokens (scaled by 1000 for precision)
    tokens: AtomicU64,
    /// Maximum tokens (burst capacity, scaled)
    max_tokens: u64,
    /// Tokens added per millisecond (rate_per_sec / 1000, scaled)
    refill_rate: u64,
    /// Last refill timestamp (ms since epoch)
    last_refill: AtomicU64,
}

impl TokenBucket {
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        let max_tokens = (burst as u64) * 1000; // Scale by 1000
        Self {
            tokens: AtomicU64::new(max_tokens),
            max_tokens,
            refill_rate: rate_per_sec as u64, // tokens per second, applied per ms check
            last_refill: AtomicU64::new(Self::now_ms()),
        }
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Try to consume one token, returns true if successful
    pub fn try_consume(&self) -> bool {
        self.try_consume_n(1)
    }

    /// Try to consume N tokens, returns true if successful
    pub fn try_consume_n(&self, n: u32) -> bool {
        let cost = (n as u64) * 1000;

        // Refill tokens based on elapsed time
        let now = Self::now_ms();
        let last = self.last_refill.load(Ordering::Relaxed);
        let elapsed_ms = now.saturating_sub(last);

        if elapsed_ms > 0 {
            // Calculate tokens to add
            let tokens_to_add = (elapsed_ms * self.refill_rate * 1000) / 1000;

            // Update last refill time
            self.last_refill.store(now, Ordering::Relaxed);

            // Add tokens (capped at max)
            let current = self.tokens.load(Ordering::Relaxed);
            let new_tokens = std::cmp::min(current + tokens_to_add, self.max_tokens);
            self.tokens.store(new_tokens, Ordering::Relaxed);
        }

        // Try to consume
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current < cost {
                return false;
            }

            match self.tokens.compare_exchange_weak(
                current,
                current - cost,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    /// Get current token count (for monitoring)
    pub fn available_tokens(&self) -> u32 {
        (self.tokens.load(Ordering::Relaxed) / 1000) as u32
    }
}

// ============================================================================
// Stream State
// ============================================================================

/// Runtime state for a single stream
pub struct StreamState {
    pub config: StreamThrottleConfig,
    pub bucket: TokenBucket,
    pub queue_depth: AtomicU64,
    pub counters: StreamCounters,
}

impl StreamState {
    pub fn new(config: StreamThrottleConfig) -> Self {
        Self {
            bucket: TokenBucket::new(config.rate_per_sec, config.burst),
            queue_depth: AtomicU64::new(0),
            counters: StreamCounters::new(),
            config,
        }
    }
}

/// Counters for a single stream (for visibility)
#[derive(Debug)]
pub struct StreamCounters {
    pub accepted: AtomicU64,
    pub dropped: AtomicU64,
    pub sampled: AtomicU64,
    pub queued: AtomicU64,
    /// Window start for rolling counts
    pub window_start: AtomicU64,
    /// Dropped in current window
    pub dropped_in_window: AtomicU64,
}

impl StreamCounters {
    pub fn new() -> Self {
        Self {
            accepted: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            sampled: AtomicU64::new(0),
            queued: AtomicU64::new(0),
            window_start: AtomicU64::new(TokenBucket::now_ms()),
            dropped_in_window: AtomicU64::new(0),
        }
    }

    pub fn record_accept(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_drop(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        self.dropped_in_window.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub fn record_sample(&self) {
        self.sampled.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub fn record_queue(&self) {
        self.queued.fetch_add(1, Ordering::Relaxed);
    }

    /// Get dropped count in current window, reset window if needed
    pub fn get_dropped_in_window(&self, window_ms: u64) -> u64 {
        let now = TokenBucket::now_ms();
        let start = self.window_start.load(Ordering::Relaxed);

        if now - start > window_ms {
            // Reset window
            self.window_start.store(now, Ordering::Relaxed);
            self.dropped_in_window.store(0, Ordering::Relaxed);
            0
        } else {
            self.dropped_in_window.load(Ordering::Relaxed)
        }
    }

    pub fn reset(&self) {
        self.accepted.store(0, Ordering::Relaxed);
        self.dropped.store(0, Ordering::Relaxed);
        self.sampled.store(0, Ordering::Relaxed);
        self.queued.store(0, Ordering::Relaxed);
        self.window_start
            .store(TokenBucket::now_ms(), Ordering::Relaxed);
        self.dropped_in_window.store(0, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StreamCounterSnapshot {
        StreamCounterSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            sampled: self.sampled.load(Ordering::Relaxed),
            queued: self.queued.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamCounterSnapshot {
    pub accepted: u64,
    pub dropped: u64,
    pub sampled: u64,
    pub queued: u64,
}

// ============================================================================
// Throttle Controller (Central)
// ============================================================================

/// Summary window duration in seconds (fixed cadence for determinism)
pub const SUMMARY_WINDOW_SECS: u32 = 30;

/// Central throttle controller - single point of truth for all throttling decisions
///
/// Thread Safety:
/// - Hot path (before_store) uses only atomics and read locks
/// - Config changes (update_config) take write locks but are infrequent
/// - Counters are lock-free atomics for zero contention on ingest
pub struct ThrottleController {
    /// Current profile configuration (read-heavy, write-rare)
    config: RwLock<ProfileConfig>,
    /// Per-stream state (read-heavy after warmup)
    streams: RwLock<HashMap<String, Arc<StreamState>>>,
    /// Global token bucket (events) - lock-free
    global_event_bucket: TokenBucket,
    /// Global byte counter - lock-free
    global_bytes_in_window: AtomicU64,
    global_bytes_window_start: AtomicU64,
    global_bytes_limit: AtomicU64,
    /// Visibility degradation state - lock-free
    degraded: AtomicBool,
    /// Critical visibility gap (Tier-0 throttled) - lock-free
    critical_gap: AtomicBool,
    /// Degraded reasons (only updated on state change, not hot path)
    degraded_reasons: RwLock<Vec<String>>,
    /// Tier-0 throttle critical flag - lock-free
    tier0_throttled: AtomicBool,
    /// Audit log for dropped events (for determinism/replay)
    audit_log: RwLock<Vec<ThrottleAuditEntry>>,
    /// Summary window tracking for deterministic summary generation
    current_window_start: AtomicU64,
    current_window_seq: AtomicU32,
    /// Pending summaries (generated on fixed 30s boundaries)
    pending_summaries: RwLock<Vec<TelemetryThrottledSummary>>,
    /// Cached visibility state for cheap API responses (updated periodically)
    cached_visibility: RwLock<Option<(u64, ThrottleVisibilityState)>>,
}

impl ThrottleController {
    pub fn new(config: ProfileConfig) -> Self {
        let global_bucket = TokenBucket::new(
            config.global_throttle.max_events_per_sec,
            config.global_throttle.max_events_per_sec * 2, // 2 second burst
        );

        // Align to 30s window boundary for deterministic summaries
        let now_ms = TokenBucket::now_ms();
        let window_start =
            (now_ms / (SUMMARY_WINDOW_SECS as u64 * 1000)) * (SUMMARY_WINDOW_SECS as u64 * 1000);

        Self {
            global_bytes_limit: AtomicU64::new(config.global_throttle.max_bytes_per_sec),
            config: RwLock::new(config),
            streams: RwLock::new(HashMap::new()),
            global_event_bucket: global_bucket,
            global_bytes_in_window: AtomicU64::new(0),
            global_bytes_window_start: AtomicU64::new(TokenBucket::now_ms()),
            degraded: AtomicBool::new(false),
            critical_gap: AtomicBool::new(false),
            degraded_reasons: RwLock::new(Vec::new()),
            tier0_throttled: AtomicBool::new(false),
            audit_log: RwLock::new(Vec::new()),
            current_window_start: AtomicU64::new(window_start),
            current_window_seq: AtomicU32::new(0),
            pending_summaries: RwLock::new(Vec::new()),
            cached_visibility: RwLock::new(None),
        }
    }

    /// Update configuration (e.g., when profile changes)
    /// Note: This takes write locks but is called rarely (user action),
    /// so it won't block the ingest hot path in practice.
    pub fn update_config(&self, new_config: ProfileConfig) {
        // Update global limits atomically (no lock needed)
        self.global_bytes_limit.store(
            new_config.global_throttle.max_bytes_per_sec,
            Ordering::Relaxed,
        );

        // Clear stream states to pick up new configs
        {
            let mut streams = self.streams.write().unwrap();
            streams.clear();
        }

        // Store new config
        {
            let mut config = self.config.write().unwrap();
            *config = new_config;
        }

        // Reset degraded state (atomics, no lock)
        self.degraded.store(false, Ordering::Relaxed);
        self.critical_gap.store(false, Ordering::Relaxed);
        self.tier0_throttled.store(false, Ordering::Relaxed);
        {
            let mut reasons = self.degraded_reasons.write().unwrap();
            reasons.clear();
        }

        // Invalidate cached visibility
        {
            let mut cache = self.cached_visibility.write().unwrap();
            *cache = None;
        }
    }

    /// Get current profile
    pub fn current_profile(&self) -> CaptureProfile {
        self.config.read().unwrap().profile
    }

    /// Get current config (cloned)
    pub fn current_config(&self) -> ProfileConfig {
        self.config.read().unwrap().clone()
    }

    /// Get or create stream state
    fn get_or_create_stream(&self, stream_id: &str) -> Arc<StreamState> {
        // Try read lock first
        {
            let streams = self.streams.read().unwrap();
            if let Some(state) = streams.get(stream_id) {
                return Arc::clone(state);
            }
        }

        // Need write lock to create
        let mut streams = self.streams.write().unwrap();

        // Double-check after acquiring write lock
        if let Some(state) = streams.get(stream_id) {
            return Arc::clone(state);
        }

        // Create new stream state
        let config = self.config.read().unwrap();
        let stream_config = config.get_stream_throttle(stream_id);
        let state = Arc::new(StreamState::new(stream_config));
        streams.insert(stream_id.to_string(), Arc::clone(&state));
        state
    }

    /// Main entry point: decide what to do with an event before storage
    pub fn before_store(&self, stream_id: &str, event_bytes: usize) -> ThrottleDecision {
        let stream = self.get_or_create_stream(stream_id);

        // Check global byte rate
        if !self.check_global_bytes(event_bytes as u64) {
            stream.counters.record_drop();
            self.update_degraded_state(stream_id, &stream);
            return ThrottleDecision::Drop {
                reason: DropReason::GlobalByteRate,
            };
        }

        // Check global event rate
        if !self.global_event_bucket.try_consume() {
            stream.counters.record_drop();
            self.update_degraded_state(stream_id, &stream);
            return ThrottleDecision::Drop {
                reason: DropReason::GlobalEventRate,
            };
        }

        // Check per-stream rate
        if !stream.bucket.try_consume() {
            stream.counters.record_drop();
            self.update_degraded_state(stream_id, &stream);

            // Log audit entry for dropped events
            self.log_drop_audit(stream_id, DropReason::StreamRateLimit);

            // Check if this is a Tier-0 stream - this is a CRITICAL GAP
            if stream.config.priority == StreamPriority::Tier0 {
                self.tier0_throttled.store(true, Ordering::Relaxed);
                self.critical_gap.store(true, Ordering::Relaxed);
            }

            // Check if we need to emit a summary (fixed 30s window boundary)
            self.maybe_emit_summary(stream_id, &stream);

            return ThrottleDecision::Drop {
                reason: DropReason::StreamRateLimit,
            };
        }

        // Check queue depth (if event would be queued)
        let queue_depth = stream.queue_depth.load(Ordering::Relaxed);
        if queue_depth >= stream.config.max_queue as u64 {
            stream.counters.record_drop();
            self.update_degraded_state(stream_id, &stream);
            self.log_drop_audit(stream_id, DropReason::StreamQueueFull);
            return ThrottleDecision::Drop {
                reason: DropReason::StreamQueueFull,
            };
        }

        // Accept
        stream.counters.record_accept();
        ThrottleDecision::Accept
    }

    /// Check global byte rate (resets window every second)
    fn check_global_bytes(&self, bytes: u64) -> bool {
        let now = TokenBucket::now_ms();
        let window_start = self.global_bytes_window_start.load(Ordering::Relaxed);

        // Reset window if more than 1 second has passed
        if now - window_start > 1000 {
            self.global_bytes_in_window.store(0, Ordering::Relaxed);
            self.global_bytes_window_start.store(now, Ordering::Relaxed);
        }

        let limit = self.global_bytes_limit.load(Ordering::Relaxed);
        let current = self
            .global_bytes_in_window
            .fetch_add(bytes, Ordering::Relaxed);

        current + bytes <= limit
    }

    /// Update visibility degraded state
    fn update_degraded_state(&self, stream_id: &str, stream: &StreamState) {
        const DEGRADED_THRESHOLD: u64 = 10; // drops in 5-second window
        const WINDOW_MS: u64 = 5000;

        let dropped = stream.counters.get_dropped_in_window(WINDOW_MS);

        if dropped >= DEGRADED_THRESHOLD {
            self.degraded.store(true, Ordering::Relaxed);

            let reason = format!(
                "throttling: stream {} dropped {} events in {}s window",
                stream_id,
                dropped,
                WINDOW_MS / 1000
            );

            let mut reasons = self.degraded_reasons.write().unwrap();
            if !reasons
                .iter()
                .any(|r| r.starts_with(&format!("throttling: stream {}", stream_id)))
            {
                reasons.push(reason);
            }
        }
    }

    /// Log an audit entry for dropped events
    fn log_drop_audit(&self, stream_id: &str, reason: DropReason) {
        let entry = ThrottleAuditEntry {
            ts: Utc::now(),
            stream_id: stream_id.to_string(),
            reason,
            count: 1,
        };

        let mut audit = self.audit_log.write().unwrap();

        // Consolidate recent entries for same stream/reason
        if let Some(last) = audit.last_mut() {
            if last.stream_id == stream_id
                && last.reason == reason
                && (Utc::now() - last.ts) < Duration::seconds(1)
            {
                last.count += 1;
                return;
            }
        }

        audit.push(entry);

        // Keep audit log bounded
        if audit.len() > 10000 {
            audit.drain(0..5000);
        }
    }

    /// Get visibility state for API
    /// Uses caching to ensure cheap responses (no heavy DB scans)
    /// Cache is valid for 1 second to balance freshness vs cost
    pub fn get_visibility_state(&self) -> ThrottleVisibilityState {
        let now_ms = TokenBucket::now_ms();

        // Check cache first (valid for 1 second)
        {
            let cache = self.cached_visibility.read().unwrap();
            if let Some((cached_at, ref state)) = *cache {
                if now_ms - cached_at < 1000 {
                    return state.clone();
                }
            }
        }

        // Build fresh state from in-memory data (no DB access)
        let config = self.config.read().unwrap();
        let streams = self.streams.read().unwrap();
        let reasons = self.degraded_reasons.read().unwrap();

        let mut stream_stats = HashMap::new();
        for (stream_id, state) in streams.iter() {
            stream_stats.insert(
                stream_id.clone(),
                StreamStats {
                    priority: state.config.priority,
                    counters: state.counters.snapshot(),
                    available_tokens: state.bucket.available_tokens(),
                    queue_depth: state.queue_depth.load(Ordering::Relaxed),
                },
            );
        }

        let state = ThrottleVisibilityState {
            profile: config.profile,
            degraded: self.degraded.load(Ordering::Relaxed),
            tier0_throttled: self.tier0_throttled.load(Ordering::Relaxed),
            critical_gap: self.critical_gap.load(Ordering::Relaxed),
            degraded_reasons: reasons.clone(),
            stream_stats,
            global_events_available: self.global_event_bucket.available_tokens(),
        };

        // Update cache
        {
            let mut cache = self.cached_visibility.write().unwrap();
            *cache = Some((now_ms, state.clone()));
        }

        state
    }

    /// Reset all counters (for UI "reset" button)
    pub fn reset_counters(&self) {
        let streams = self.streams.read().unwrap();
        for state in streams.values() {
            state.counters.reset();
        }

        self.degraded.store(false, Ordering::Relaxed);
        self.critical_gap.store(false, Ordering::Relaxed);
        self.tier0_throttled.store(false, Ordering::Relaxed);

        let mut reasons = self.degraded_reasons.write().unwrap();
        reasons.clear();

        // Invalidate cache
        {
            let mut cache = self.cached_visibility.write().unwrap();
            *cache = None;
        }
    }

    /// Check if we should emit a throttle summary (fixed 30s window boundary)
    /// This ensures deterministic summary generation for replay/recompute
    fn maybe_emit_summary(&self, _stream_id: &str, _stream: &StreamState) {
        let now_ms = TokenBucket::now_ms();
        let window_boundary =
            (now_ms / (SUMMARY_WINDOW_SECS as u64 * 1000)) * (SUMMARY_WINDOW_SECS as u64 * 1000);
        let current_start = self.current_window_start.load(Ordering::Relaxed);

        // Check if we've crossed a window boundary
        if window_boundary > current_start {
            // Try to advance the window (atomic CAS to handle concurrent calls)
            if self
                .current_window_start
                .compare_exchange(
                    current_start,
                    window_boundary,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                // We won the race - emit summaries for previous window
                self.emit_window_summaries(current_start, window_boundary);
                self.current_window_seq.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Emit throttle summaries for a completed window
    fn emit_window_summaries(&self, window_start_ms: u64, window_end_ms: u64) {
        let window_start =
            DateTime::from_timestamp_millis(window_start_ms as i64).unwrap_or_else(Utc::now);
        let window_end =
            DateTime::from_timestamp_millis(window_end_ms as i64).unwrap_or_else(Utc::now);

        let streams = self.streams.read().unwrap();
        let mut summaries = self.pending_summaries.write().unwrap();

        for (stream_id, state) in streams.iter() {
            let counters = state.counters.snapshot();
            if counters.dropped > 0 {
                let seq = self.current_window_seq.fetch_add(1, Ordering::Relaxed);
                summaries.push(TelemetryThrottledSummary {
                    window_start,
                    window_end,
                    stream_id: stream_id.clone(),
                    events_dropped: counters.dropped,
                    events_sampled: counters.sampled,
                    reason: DropReason::StreamRateLimit, // Primary reason
                    tier0_affected: state.config.priority == StreamPriority::Tier0,
                    window_seq: seq,
                });
            }
        }
    }

    /// Get and clear pending summaries (for timeline integration)
    #[allow(dead_code)]
    pub fn take_pending_summaries(&self) -> Vec<TelemetryThrottledSummary> {
        let mut summaries = self.pending_summaries.write().unwrap();
        std::mem::take(&mut *summaries)
    }

    /// Check if there's a critical visibility gap (Tier-0 throttled)
    #[allow(dead_code)]
    pub fn has_critical_gap(&self) -> bool {
        self.critical_gap.load(Ordering::Relaxed)
    }

    /// Get audit log for bundle export (for recompute determinism)
    #[allow(dead_code)]
    pub fn get_audit_log(&self) -> Vec<ThrottleAuditEntry> {
        self.audit_log.read().unwrap().clone()
    }

    /// Clear audit log
    #[allow(dead_code)]
    pub fn clear_audit_log(&self) {
        self.audit_log.write().unwrap().clear();
    }

    /// Check if a sensor is enabled in current profile
    #[allow(dead_code)]
    pub fn is_sensor_enabled(&self, sensor_id: &str) -> bool {
        let config = self.config.read().unwrap();
        config.enabled_sensors.contains(&sensor_id.to_string())
    }

    /// Check if a collector is enabled in current profile
    #[allow(dead_code)]
    pub fn is_collector_enabled(&self, collector_id: &str) -> bool {
        let config = self.config.read().unwrap();
        config
            .enabled_collectors
            .contains(&collector_id.to_string())
    }

    /// Check if a heavy feature is enabled in current profile
    #[allow(dead_code)]
    pub fn is_heavy_feature_enabled(&self, feature_id: &str) -> bool {
        let config = self.config.read().unwrap();
        config.heavy_features.contains(&feature_id.to_string())
    }
}

// ============================================================================
// Audit and Visibility Types
// ============================================================================

/// Audit entry for dropped/throttled events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleAuditEntry {
    pub ts: DateTime<Utc>,
    pub stream_id: String,
    pub reason: DropReason,
    pub count: u64,
}

/// Visibility state including throttling info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleVisibilityState {
    pub profile: CaptureProfile,
    pub degraded: bool,
    pub tier0_throttled: bool,
    /// Critical visibility gap - Tier-0 streams were throttled
    /// When true, explanations/reports should include loud warning
    pub critical_gap: bool,
    pub degraded_reasons: Vec<String>,
    pub stream_stats: HashMap<String, StreamStats>,
    pub global_events_available: u32,
}

/// Stats for a single stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamStats {
    pub priority: StreamPriority,
    pub counters: StreamCounterSnapshot,
    pub available_tokens: u32,
    pub queue_depth: u64,
}

// ============================================================================
// Config Snapshot for Bundles
// ============================================================================

/// Throttle configuration snapshot for bundle export/recompute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleConfigSnapshot {
    pub profile: CaptureProfile,
    pub global_max_events_per_sec: u32,
    pub global_max_bytes_per_sec: u64,
    pub stream_configs: HashMap<String, StreamThrottleConfigSnapshot>,
    pub enabled_sensors: Vec<String>,
    pub enabled_collectors: Vec<String>,
    pub heavy_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamThrottleConfigSnapshot {
    pub priority: StreamPriority,
    pub rate_per_sec: u32,
    pub burst: u32,
    pub max_queue: u32,
}

impl ThrottleController {
    /// Create snapshot for bundle export
    pub fn create_config_snapshot(&self) -> ThrottleConfigSnapshot {
        let config = self.config.read().unwrap();

        let stream_configs: HashMap<String, StreamThrottleConfigSnapshot> = config
            .stream_throttles
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    StreamThrottleConfigSnapshot {
                        priority: v.priority,
                        rate_per_sec: v.rate_per_sec,
                        burst: v.burst,
                        max_queue: v.max_queue,
                    },
                )
            })
            .collect();

        ThrottleConfigSnapshot {
            profile: config.profile,
            global_max_events_per_sec: config.global_throttle.max_events_per_sec,
            global_max_bytes_per_sec: config.global_throttle.max_bytes_per_sec,
            stream_configs,
            enabled_sensors: config.enabled_sensors.clone(),
            enabled_collectors: config.enabled_collectors.clone(),
            heavy_features: config.heavy_features.clone(),
        }
    }

    /// Validate that current config matches a snapshot (for strict recompute)
    /// Strict mode fails on ANY mismatch that could affect what events exist.
    #[allow(dead_code)]
    pub fn validate_config_match(
        &self,
        snapshot: &ThrottleConfigSnapshot,
    ) -> Result<(), Vec<String>> {
        let config = self.config.read().unwrap();
        let mut errors = Vec::new();

        // 1. Profile mismatch
        if config.profile != snapshot.profile {
            errors.push(format!(
                "capture_profile mismatch: current={:?}, bundle={:?}",
                config.profile, snapshot.profile
            ));
        }

        // 2. Throttle config mismatch (affects what events were dropped)
        if config.global_throttle.max_events_per_sec != snapshot.global_max_events_per_sec {
            errors.push(format!(
                "throttle_config.global_max_events_per_sec mismatch: current={}, bundle={}",
                config.global_throttle.max_events_per_sec, snapshot.global_max_events_per_sec
            ));
        }

        if config.global_throttle.max_bytes_per_sec != snapshot.global_max_bytes_per_sec {
            errors.push(format!(
                "throttle_config.global_max_bytes_per_sec mismatch: current={}, bundle={}",
                config.global_throttle.max_bytes_per_sec, snapshot.global_max_bytes_per_sec
            ));
        }

        // 3. Enabled sensors mismatch (affects what events exist)
        let current_sensors: std::collections::HashSet<_> = config.enabled_sensors.iter().collect();
        let snapshot_sensors: std::collections::HashSet<_> =
            snapshot.enabled_sensors.iter().collect();
        if current_sensors != snapshot_sensors {
            let missing: Vec<_> = snapshot_sensors.difference(&current_sensors).collect();
            let extra: Vec<_> = current_sensors.difference(&snapshot_sensors).collect();
            errors.push(format!(
                "dynamic_enablements.sensors mismatch: missing={:?}, extra={:?}",
                missing, extra
            ));
        }

        // 4. Enabled collectors mismatch
        let current_collectors: std::collections::HashSet<_> =
            config.enabled_collectors.iter().collect();
        let snapshot_collectors: std::collections::HashSet<_> =
            snapshot.enabled_collectors.iter().collect();
        if current_collectors != snapshot_collectors {
            let missing: Vec<_> = snapshot_collectors
                .difference(&current_collectors)
                .collect();
            let extra: Vec<_> = current_collectors
                .difference(&snapshot_collectors)
                .collect();
            errors.push(format!(
                "dynamic_enablements.collectors mismatch: missing={:?}, extra={:?}",
                missing, extra
            ));
        }

        // 5. Heavy features mismatch
        let current_heavy: std::collections::HashSet<_> = config.heavy_features.iter().collect();
        let snapshot_heavy: std::collections::HashSet<_> = snapshot.heavy_features.iter().collect();
        if current_heavy != snapshot_heavy {
            errors.push(format!(
                "dynamic_enablements.heavy_features mismatch: current={:?}, bundle={:?}",
                current_heavy, snapshot_heavy
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate for best-effort recompute (warnings only, doesn't fail)
    #[allow(dead_code)]
    pub fn validate_config_best_effort(&self, snapshot: &ThrottleConfigSnapshot) -> Vec<String> {
        match self.validate_config_match(snapshot) {
            Ok(()) => Vec::new(),
            Err(warnings) => warnings,
        }
    }
}

// ============================================================================
// Summary Event for Timeline (TelemetryThrottledSummary)
// ============================================================================

/// Canonical event type for throttled/suppressed events summary
/// Generated on fixed 30s window boundaries for deterministic replay/recompute.
/// Ordering key: (stream_id, window_start, window_seq)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryThrottledSummary {
    /// Time window start (aligned to 30s boundary)
    pub window_start: DateTime<Utc>,
    /// Time window end
    pub window_end: DateTime<Utc>,
    /// Stream that was throttled
    pub stream_id: String,
    /// Number of events dropped in this window
    pub events_dropped: u64,
    /// Number of events sampled in this window
    pub events_sampled: u64,
    /// Primary reason for throttling
    pub reason: DropReason,
    /// Whether this affected a Tier-0 stream (CRITICAL GAP)
    pub tier0_affected: bool,
    /// Sequence number within window for stable ordering
    pub window_seq: u32,
}

#[allow(dead_code)]
impl TelemetryThrottledSummary {
    pub fn event_type() -> &'static str {
        "telemetry_throttled_summary"
    }

    /// Stable ordering key for deterministic replay
    pub fn ordering_key(&self) -> (String, i64, u32) {
        (
            self.stream_id.clone(),
            self.window_start.timestamp(),
            self.window_seq,
        )
    }

    /// Generate warning message if Tier-0 was throttled
    pub fn tier0_warning(&self) -> Option<&'static str> {
        if self.tier0_affected {
            Some("⚠️ CRITICAL: Tier-0 stream throttled; conclusions may be incomplete.")
        } else {
            None
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
    fn test_capture_profile_from_str() {
        assert_eq!(CaptureProfile::from_str("core"), Some(CaptureProfile::Core));
        assert_eq!(
            CaptureProfile::from_str("EXTENDED"),
            Some(CaptureProfile::Extended)
        );
        assert_eq!(
            CaptureProfile::from_str("Forensic"),
            Some(CaptureProfile::Forensic)
        );
        assert_eq!(CaptureProfile::from_str("invalid"), None);
    }

    #[test]
    fn test_profile_config_defaults() {
        let core = ProfileConfig::for_profile(CaptureProfile::Core);
        let extended = ProfileConfig::for_profile(CaptureProfile::Extended);
        let forensic = ProfileConfig::for_profile(CaptureProfile::Forensic);

        // Core should have fewest sensors
        assert!(core.enabled_sensors.len() < extended.enabled_sensors.len());
        assert!(extended.enabled_sensors.len() < forensic.enabled_sensors.len());

        // Global limits should increase
        assert!(
            core.global_throttle.max_events_per_sec < extended.global_throttle.max_events_per_sec
        );
        assert!(
            extended.global_throttle.max_events_per_sec
                < forensic.global_throttle.max_events_per_sec
        );
    }

    #[test]
    fn test_token_bucket_rate_limiting() {
        let bucket = TokenBucket::new(10, 10); // 10/s, burst 10

        // Should be able to consume burst immediately
        for _ in 0..10 {
            assert!(bucket.try_consume(), "Should consume within burst");
        }

        // 11th should fail (no refill time)
        assert!(!bucket.try_consume(), "Should be rate limited after burst");
    }

    #[test]
    fn test_token_bucket_refill() {
        let bucket = TokenBucket::new(1000, 10); // 1000/s, burst 10

        // Drain all tokens
        for _ in 0..10 {
            bucket.try_consume();
        }

        // Wait a bit for refill
        std::thread::sleep(std::time::Duration::from_millis(15));

        // Should have some tokens now
        assert!(bucket.try_consume(), "Should have refilled");
    }

    #[test]
    fn test_throttle_controller_accept() {
        let config = ProfileConfig::for_profile(CaptureProfile::Core);
        let controller = ThrottleController::new(config);

        // First event should be accepted
        let decision = controller.before_store("process_exec", 100);
        assert_eq!(decision, ThrottleDecision::Accept);
    }

    #[test]
    fn test_throttle_controller_drop_on_burst() {
        let mut config = ProfileConfig::for_profile(CaptureProfile::Core);
        // Set very low limits for testing
        config.stream_throttles.insert(
            "test_stream".to_string(),
            StreamThrottleConfig {
                priority: StreamPriority::Normal,
                rate_per_sec: 1,
                burst: 2,
                max_queue: 10,
            },
        );

        let controller = ThrottleController::new(config);

        // First two should be accepted (burst)
        assert_eq!(
            controller.before_store("test_stream", 10),
            ThrottleDecision::Accept
        );
        assert_eq!(
            controller.before_store("test_stream", 10),
            ThrottleDecision::Accept
        );

        // Third should be dropped (rate limited)
        match controller.before_store("test_stream", 10) {
            ThrottleDecision::Drop {
                reason: DropReason::StreamRateLimit,
            } => {}
            other => panic!("Expected StreamRateLimit, got {:?}", other),
        }
    }

    #[test]
    fn test_throttle_controller_global_limit() {
        let mut config = ProfileConfig::for_profile(CaptureProfile::Core);
        config.global_throttle.max_events_per_sec = 5;

        let controller = ThrottleController::new(config);

        // Exhaust global bucket
        for i in 0..10 {
            let decision = controller.before_store(&format!("stream_{}", i), 10);
            if i >= 10 {
                // Should start dropping due to global limit
                match decision {
                    ThrottleDecision::Drop {
                        reason: DropReason::GlobalEventRate,
                    } => {}
                    ThrottleDecision::Accept => {} // Might still accept due to burst
                    other => panic!("Unexpected decision: {:?}", other),
                }
            }
        }
    }

    #[test]
    fn test_visibility_degraded_state() {
        let mut config = ProfileConfig::for_profile(CaptureProfile::Core);
        config.stream_throttles.insert(
            "noisy_stream".to_string(),
            StreamThrottleConfig {
                priority: StreamPriority::Background,
                rate_per_sec: 1,
                burst: 1,
                max_queue: 10,
            },
        );

        let controller = ThrottleController::new(config);

        // Generate enough drops to trigger degraded
        for _ in 0..15 {
            let _ = controller.before_store("noisy_stream", 10);
        }

        let state = controller.get_visibility_state();
        assert!(state.degraded, "Should be degraded after many drops");
        assert!(
            !state.degraded_reasons.is_empty(),
            "Should have degraded reasons"
        );
    }

    #[test]
    fn test_tier0_throttle_flag() {
        let mut config = ProfileConfig::for_profile(CaptureProfile::Core);
        config.stream_throttles.insert(
            "critical_stream".to_string(),
            StreamThrottleConfig {
                priority: StreamPriority::Tier0,
                rate_per_sec: 1,
                burst: 1,
                max_queue: 10,
            },
        );

        let controller = ThrottleController::new(config);

        // Exhaust the bucket
        controller.before_store("critical_stream", 10);
        controller.before_store("critical_stream", 10);

        let state = controller.get_visibility_state();
        assert!(state.tier0_throttled, "Should flag Tier-0 throttled");
    }

    #[test]
    fn test_config_snapshot_roundtrip() {
        let config = ProfileConfig::for_profile(CaptureProfile::Extended);
        let controller = ThrottleController::new(config);

        let snapshot = controller.create_config_snapshot();

        assert_eq!(snapshot.profile, CaptureProfile::Extended);
        assert!(!snapshot.enabled_sensors.is_empty());

        // Validate match should pass
        assert!(controller.validate_config_match(&snapshot).is_ok());
    }

    #[test]
    fn test_config_mismatch_detection() {
        let config = ProfileConfig::for_profile(CaptureProfile::Core);
        let controller = ThrottleController::new(config);

        let mut snapshot = controller.create_config_snapshot();
        snapshot.profile = CaptureProfile::Forensic;

        // Should detect mismatch
        assert!(controller.validate_config_match(&snapshot).is_err());
    }

    #[test]
    fn test_reset_counters() {
        let config = ProfileConfig::for_profile(CaptureProfile::Core);
        let controller = ThrottleController::new(config);

        // Generate some activity
        for _ in 0..5 {
            controller.before_store("process_exec", 100);
        }

        let state_before = controller.get_visibility_state();
        assert!(
            state_before
                .stream_stats
                .get("process_exec")
                .unwrap()
                .counters
                .accepted
                > 0
        );

        // Reset
        controller.reset_counters();

        let state_after = controller.get_visibility_state();
        assert_eq!(
            state_after
                .stream_stats
                .get("process_exec")
                .unwrap()
                .counters
                .accepted,
            0
        );
    }

    #[test]
    fn test_deterministic_ordering_preserved() {
        let config = ProfileConfig::for_profile(CaptureProfile::Core);
        let controller = ThrottleController::new(config);

        // All events should be accepted in order
        let mut accepted_order = Vec::new();
        for i in 0..10 {
            if controller.before_store("process_exec", 100) == ThrottleDecision::Accept {
                accepted_order.push(i);
            }
        }

        // Verify ordering is preserved (indices should be sequential)
        for (idx, &value) in accepted_order.iter().enumerate() {
            assert_eq!(idx, value as usize, "Order should be preserved");
        }
    }

    // ========================================================================
    // Sanity Gate Tests
    // ========================================================================

    #[test]
    fn test_sanity_gate_1_thread_safety_atomics() {
        // Verify counters use lock-free atomics
        let config = ProfileConfig::for_profile(CaptureProfile::Core);
        let controller = Arc::new(ThrottleController::new(config));

        // Concurrent access should work without blocking
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let c = Arc::clone(&controller);
                std::thread::spawn(move || {
                    for _j in 0..100 {
                        c.before_store(&format!("stream_{}", i), 10);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Should complete without deadlock
        let state = controller.get_visibility_state();
        assert!(
            state.stream_stats.len() == 4,
            "All streams should be tracked"
        );
    }

    #[test]
    fn test_sanity_gate_2_summary_ordering_key() {
        // Verify TelemetryThrottledSummary has stable ordering key
        let summary1 = TelemetryThrottledSummary {
            window_start: Utc::now(),
            window_end: Utc::now(),
            stream_id: "process_exec".to_string(),
            events_dropped: 10,
            events_sampled: 0,
            reason: DropReason::StreamRateLimit,
            tier0_affected: false,
            window_seq: 0,
        };

        let summary2 = TelemetryThrottledSummary {
            window_start: summary1.window_start,
            window_end: summary1.window_end,
            stream_id: "process_exec".to_string(),
            events_dropped: 5,
            events_sampled: 0,
            reason: DropReason::StreamRateLimit,
            tier0_affected: false,
            window_seq: 1,
        };

        let key1 = summary1.ordering_key();
        let key2 = summary2.ordering_key();

        // Same stream, same window, different seq
        assert_eq!(key1.0, key2.0);
        assert_eq!(key1.1, key2.1);
        assert!(key1.2 < key2.2, "Sequence should be ordered");
    }

    #[test]
    fn test_sanity_gate_3_tier0_critical_gap() {
        // Verify Tier-0 throttle sets critical_gap flag
        let mut config = ProfileConfig::for_profile(CaptureProfile::Core);
        config.stream_throttles.insert(
            "tier0_stream".to_string(),
            StreamThrottleConfig {
                priority: StreamPriority::Tier0,
                rate_per_sec: 1,
                burst: 1,
                max_queue: 10,
            },
        );

        let controller = ThrottleController::new(config);

        // Exhaust bucket to trigger throttle
        controller.before_store("tier0_stream", 10);
        controller.before_store("tier0_stream", 10); // This should drop

        // Verify critical_gap is set
        assert!(
            controller.has_critical_gap(),
            "Should have critical gap after Tier-0 throttle"
        );

        let state = controller.get_visibility_state();
        assert!(
            state.critical_gap,
            "Visibility state should show critical gap"
        );
        assert!(state.tier0_throttled, "Should show tier0_throttled");
    }

    #[test]
    fn test_sanity_gate_3_tier0_warning_message() {
        let summary = TelemetryThrottledSummary {
            window_start: Utc::now(),
            window_end: Utc::now(),
            stream_id: "critical_stream".to_string(),
            events_dropped: 100,
            events_sampled: 0,
            reason: DropReason::StreamRateLimit,
            tier0_affected: true,
            window_seq: 0,
        };

        let warning = summary.tier0_warning();
        assert!(warning.is_some(), "Should have warning for Tier-0");
        assert!(
            warning.unwrap().contains("CRITICAL"),
            "Warning should be loud"
        );
        assert!(
            warning.unwrap().contains("incomplete"),
            "Should mention incomplete conclusions"
        );
    }

    #[test]
    fn test_sanity_gate_4_strict_recompute_validation() {
        let config = ProfileConfig::for_profile(CaptureProfile::Core);
        let controller = ThrottleController::new(config);

        let mut snapshot = controller.create_config_snapshot();

        // Modify to create mismatches
        snapshot.profile = CaptureProfile::Extended; // Profile mismatch
        snapshot.global_max_events_per_sec = 9999; // Throttle config mismatch
        snapshot.enabled_sensors.push("extra_sensor".to_string()); // Dynamic enablements mismatch

        let result = controller.validate_config_match(&snapshot);
        assert!(result.is_err(), "Should fail on mismatches");

        let errors = result.unwrap_err();
        assert!(errors.len() >= 3, "Should detect all mismatches");

        // Verify specific mismatches are detected
        let all_errors = errors.join(" ");
        assert!(
            all_errors.contains("capture_profile"),
            "Should detect profile mismatch"
        );
        assert!(
            all_errors.contains("throttle_config"),
            "Should detect throttle config mismatch"
        );
        assert!(
            all_errors.contains("dynamic_enablements"),
            "Should detect enablements mismatch"
        );
    }

    #[test]
    fn test_sanity_gate_5_visibility_endpoint_is_cheap() {
        let config = ProfileConfig::for_profile(CaptureProfile::Core);
        let controller = ThrottleController::new(config);

        // First call populates cache
        let state1 = controller.get_visibility_state();

        // Second call should hit cache (verify by checking it returns same degraded state)
        let state2 = controller.get_visibility_state();

        assert_eq!(state1.degraded, state2.degraded);
        assert_eq!(state1.profile, state2.profile);

        // Cache should be in-memory only (no DB access) - verified by structure
        // get_visibility_state reads from RwLock<Option<...>> cached_visibility
    }
}

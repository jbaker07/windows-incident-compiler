//! Visibility and Coverage Accounting
//!
//! Machine-readable visibility state per window: which collectors were enabled,
//! their health, drop rate, backlog/watermark status. Distinguishes "didn't happen"
//! from "didn't see."

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Collector Health
// ============================================================================

/// Health status of a collector/stream
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorHealth {
    /// Fully operational, no issues
    Healthy,
    /// Operational but with elevated drop rate or latency
    Degraded,
    /// Experiencing issues, data may be incomplete
    Unhealthy,
    /// Not receiving data
    Offline,
    /// Unknown status (no health check data)
    Unknown,
}

impl CollectorHealth {
    pub fn is_usable(&self) -> bool {
        matches!(self, CollectorHealth::Healthy | CollectorHealth::Degraded)
    }

    pub fn confidence_factor(&self) -> f64 {
        match self {
            CollectorHealth::Healthy => 1.0,
            CollectorHealth::Degraded => 0.8,
            CollectorHealth::Unhealthy => 0.5,
            CollectorHealth::Offline => 0.0,
            CollectorHealth::Unknown => 0.6,
        }
    }
}

// ============================================================================
// Collector Status
// ============================================================================

/// Detailed status of a single collector/stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorStatus {
    /// Stream identifier
    pub stream_id: String,
    /// Human-readable name
    pub name: String,
    /// Collector type (etw, es, ebpf, audit, etc.)
    pub collector_type: CollectorType,
    /// Current health status
    pub health: CollectorHealth,
    /// Whether this collector was enabled for the window
    pub enabled: bool,
    /// Whether we received any data from this collector in the window
    pub received_data: bool,
    /// Drop rate (0.0 = no drops, 1.0 = 100% dropped)
    pub drop_rate: f64,
    /// Events per second (average over window)
    pub events_per_second: f64,
    /// Current backlog size (events waiting to be processed)
    pub backlog_size: u64,
    /// High watermark timestamp (latest event time seen)
    pub high_watermark: Option<DateTime<Utc>>,
    /// Low watermark timestamp (oldest unprocessed event)
    pub low_watermark: Option<DateTime<Utc>>,
    /// Last health check timestamp
    pub last_health_check: Option<DateTime<Utc>>,
    /// Last event received timestamp
    pub last_event_ts: Option<DateTime<Utc>>,
    /// Error messages if unhealthy
    pub error_messages: Vec<String>,
    /// Platform-specific metadata
    pub metadata: HashMap<String, String>,
}

/// Type of collector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorType {
    /// Windows ETW
    WindowsEtw,
    /// macOS Endpoint Security
    MacosEndpointSecurity,
    /// macOS BSM Audit
    MacosBsm,
    /// Linux eBPF
    LinuxEbpf,
    /// Linux Audit
    LinuxAudit,
    /// File integrity monitoring
    FileIntegrity,
    /// Network capture
    NetworkCapture,
    /// Custom/other
    Custom,
}

impl CollectorStatus {
    pub fn new(stream_id: impl Into<String>, collector_type: CollectorType) -> Self {
        let stream_id = stream_id.into();
        Self {
            name: stream_id.clone(),
            stream_id,
            collector_type,
            health: CollectorHealth::Unknown,
            enabled: false,
            received_data: false,
            drop_rate: 0.0,
            events_per_second: 0.0,
            backlog_size: 0,
            high_watermark: None,
            low_watermark: None,
            last_health_check: None,
            last_event_ts: None,
            error_messages: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Check if this collector can provide reliable data
    pub fn is_reliable(&self) -> bool {
        self.enabled && self.health.is_usable() && self.drop_rate < 0.1
    }

    /// Get confidence factor for claims based on this collector
    pub fn claim_confidence(&self) -> f64 {
        if !self.enabled {
            return 0.0;
        }
        let health_factor = self.health.confidence_factor();
        let drop_factor = 1.0 - self.drop_rate;
        health_factor * drop_factor
    }

    /// Update watermarks from an event timestamp
    pub fn update_watermarks(&mut self, event_ts: DateTime<Utc>) {
        match self.high_watermark {
            Some(hw) if event_ts > hw => self.high_watermark = Some(event_ts),
            None => self.high_watermark = Some(event_ts),
            _ => {}
        }
        self.last_event_ts = Some(event_ts);
        self.received_data = true;
    }
}

// ============================================================================
// Window Visibility
// ============================================================================

/// Complete visibility state for a time window
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowVisibility {
    /// Window start time
    pub window_start: DateTime<Utc>,
    /// Window end time
    pub window_end: DateTime<Utc>,
    /// Host ID
    pub host_id: String,
    /// Status of each collector
    pub collectors: HashMap<String, CollectorStatus>,
    /// Overall visibility score (0.0-1.0)
    pub visibility_score: f64,
    /// Critical collectors that are missing or unhealthy
    pub critical_gaps: Vec<CriticalGap>,
    /// Visibility assessment
    pub assessment: VisibilityAssessment,
    /// When this visibility state was computed
    pub computed_at: DateTime<Utc>,
}

/// A critical visibility gap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalGap {
    /// Stream ID that's missing/unhealthy
    pub stream_id: String,
    /// Type of gap
    pub gap_type: GapType,
    /// Analysis domains affected
    pub affected_domains: Vec<String>,
    /// Impact description
    pub impact: String,
    /// Suggested remediation
    pub remediation: Option<String>,
}

/// Type of visibility gap
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapType {
    /// Collector not enabled
    NotEnabled,
    /// Collector offline
    Offline,
    /// High drop rate
    HighDropRate,
    /// High latency (watermark lag)
    HighLatency,
    /// No data received
    NoData,
    /// Partial coverage (some events but not all expected)
    PartialCoverage,
}

/// Overall visibility assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityAssessment {
    /// All critical collectors healthy
    Full,
    /// Minor gaps, analysis mostly reliable
    Adequate,
    /// Significant gaps, analysis may miss activity
    Limited,
    /// Major gaps, cannot make reliable claims
    Degraded,
    /// Insufficient visibility for analysis
    Blind,
}

impl WindowVisibility {
    pub fn new(
        host_id: impl Into<String>,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
    ) -> Self {
        Self {
            window_start,
            window_end,
            host_id: host_id.into(),
            collectors: HashMap::new(),
            visibility_score: 0.0,
            critical_gaps: Vec::new(),
            assessment: VisibilityAssessment::Blind,
            computed_at: Utc::now(),
        }
    }

    /// Add or update a collector status
    pub fn set_collector(&mut self, status: CollectorStatus) {
        self.collectors.insert(status.stream_id.clone(), status);
    }

    /// Compute overall visibility score and assessment
    pub fn compute_assessment(&mut self) {
        let critical_streams = get_critical_streams();
        let mut total_weight = 0.0;
        let mut weighted_score = 0.0;
        let mut gaps = Vec::new();

        for (stream_id, weight, domain) in &critical_streams {
            total_weight += weight;

            if let Some(collector) = self.collectors.get(*stream_id) {
                if collector.is_reliable() {
                    weighted_score += weight * collector.claim_confidence();
                } else {
                    // Record gap
                    let gap_type = if !collector.enabled {
                        GapType::NotEnabled
                    } else if matches!(collector.health, CollectorHealth::Offline) {
                        GapType::Offline
                    } else if collector.drop_rate > 0.1 {
                        GapType::HighDropRate
                    } else if !collector.received_data {
                        GapType::NoData
                    } else {
                        GapType::PartialCoverage
                    };

                    gaps.push(CriticalGap {
                        stream_id: stream_id.to_string(),
                        gap_type,
                        affected_domains: vec![domain.to_string()],
                        impact: format!("{} visibility affected", domain),
                        remediation: None,
                    });
                }
            } else {
                // Stream not present at all
                gaps.push(CriticalGap {
                    stream_id: stream_id.to_string(),
                    gap_type: GapType::NotEnabled,
                    affected_domains: vec![domain.to_string()],
                    impact: format!("{} visibility not available", domain),
                    remediation: Some(format!("Enable {} collector", stream_id)),
                });
            }
        }

        self.visibility_score = if total_weight > 0.0 {
            weighted_score / total_weight
        } else {
            0.0
        };

        self.critical_gaps = gaps;
        self.assessment = match self.visibility_score {
            s if s >= 0.9 => VisibilityAssessment::Full,
            s if s >= 0.7 => VisibilityAssessment::Adequate,
            s if s >= 0.5 => VisibilityAssessment::Limited,
            s if s >= 0.2 => VisibilityAssessment::Degraded,
            _ => VisibilityAssessment::Blind,
        };

        self.computed_at = Utc::now();
    }

    /// Check if we can make claims about a specific domain
    pub fn can_claim(&self, domain: &str) -> CanClaimResult {
        let streams_for_domain = get_streams_for_domain(domain);
        let mut usable_streams = Vec::new();
        let mut missing_streams = Vec::new();

        for stream_id in streams_for_domain {
            if let Some(collector) = self.collectors.get(stream_id) {
                if collector.is_reliable() {
                    usable_streams.push(stream_id.to_string());
                } else {
                    missing_streams.push(stream_id.to_string());
                }
            } else {
                missing_streams.push(stream_id.to_string());
            }
        }

        if usable_streams.is_empty() {
            CanClaimResult::No {
                reason: format!("No reliable streams for {}", domain),
                missing_streams,
            }
        } else if missing_streams.is_empty() {
            CanClaimResult::Yes {
                confidence: 1.0,
                streams: usable_streams,
            }
        } else {
            let confidence =
                usable_streams.len() as f64 / (usable_streams.len() + missing_streams.len()) as f64;
            CanClaimResult::Partial {
                confidence,
                usable_streams,
                missing_streams,
            }
        }
    }

    /// Get human-readable summary
    pub fn summary(&self) -> String {
        let collector_summary: Vec<String> = self
            .collectors
            .values()
            .filter(|c| c.enabled)
            .map(|c| format!("{}: {:?}", c.name, c.health))
            .collect();

        format!(
            "Visibility: {:?} ({:.0}%) | Collectors: {} | Gaps: {}",
            self.assessment,
            self.visibility_score * 100.0,
            collector_summary.join(", "),
            self.critical_gaps.len()
        )
    }
}

/// Result of can_claim check
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CanClaimResult {
    Yes {
        confidence: f64,
        streams: Vec<String>,
    },
    Partial {
        confidence: f64,
        usable_streams: Vec<String>,
        missing_streams: Vec<String>,
    },
    No {
        reason: String,
        missing_streams: Vec<String>,
    },
}

// ============================================================================
// Critical Stream Definitions
// ============================================================================

/// Get list of critical streams with weights and domains
fn get_critical_streams() -> Vec<(&'static str, f64, &'static str)> {
    vec![
        // Process execution - highest priority
        ("windows_etw_process", 1.0, "Process"),
        ("macos_es_exec", 1.0, "Process"),
        ("linux_ebpf_execve", 1.0, "Process"),
        // Network
        ("windows_etw_network", 0.8, "Network"),
        ("macos_es_network", 0.8, "Network"),
        ("linux_ebpf_connect", 0.8, "Network"),
        // File
        ("windows_etw_file", 0.7, "File"),
        ("macos_es_file", 0.7, "File"),
        ("linux_ebpf_file", 0.7, "File"),
        // Memory (for advanced detection)
        ("windows_etw_memory", 0.6, "Memory"),
        ("macos_es_mprotect", 0.6, "Memory"),
        ("linux_ebpf_mprotect", 0.6, "Memory"),
        // Auth
        ("windows_etw_auth", 0.5, "Auth"),
        ("macos_bsm_auth", 0.5, "Auth"),
        ("linux_audit_auth", 0.5, "Auth"),
    ]
}

/// Get streams for a specific domain
fn get_streams_for_domain(domain: &str) -> Vec<&'static str> {
    match domain.to_lowercase().as_str() {
        "process" => vec!["windows_etw_process", "macos_es_exec", "linux_ebpf_execve"],
        "network" => vec![
            "windows_etw_network",
            "macos_es_network",
            "linux_ebpf_connect",
        ],
        "file" => vec!["windows_etw_file", "macos_es_file", "linux_ebpf_file"],
        "memory" => vec![
            "windows_etw_memory",
            "macos_es_mprotect",
            "linux_ebpf_mprotect",
        ],
        "auth" => vec!["windows_etw_auth", "macos_bsm_auth", "linux_audit_auth"],
        _ => vec![],
    }
}

// ============================================================================
// Visibility Diff
// ============================================================================

/// Diff between two visibility states
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilityDiff {
    /// Collectors that became healthy
    pub became_healthy: Vec<String>,
    /// Collectors that became unhealthy
    pub became_unhealthy: Vec<String>,
    /// Collectors that were added
    pub added: Vec<String>,
    /// Collectors that were removed
    pub removed: Vec<String>,
    /// Assessment change
    pub assessment_change: Option<(VisibilityAssessment, VisibilityAssessment)>,
    /// Score change
    pub score_change: f64,
}

impl VisibilityDiff {
    pub fn compute(before: &WindowVisibility, after: &WindowVisibility) -> Self {
        let mut became_healthy = Vec::new();
        let mut became_unhealthy = Vec::new();
        let mut added = Vec::new();
        let mut removed = Vec::new();

        // Check for changes in existing collectors
        for (stream_id, after_status) in &after.collectors {
            if let Some(before_status) = before.collectors.get(stream_id) {
                let was_healthy = before_status.health.is_usable();
                let is_healthy = after_status.health.is_usable();

                if !was_healthy && is_healthy {
                    became_healthy.push(stream_id.clone());
                } else if was_healthy && !is_healthy {
                    became_unhealthy.push(stream_id.clone());
                }
            } else {
                added.push(stream_id.clone());
            }
        }

        // Check for removed collectors
        for stream_id in before.collectors.keys() {
            if !after.collectors.contains_key(stream_id) {
                removed.push(stream_id.clone());
            }
        }

        let assessment_change = if before.assessment != after.assessment {
            Some((before.assessment, after.assessment))
        } else {
            None
        };

        VisibilityDiff {
            became_healthy,
            became_unhealthy,
            added,
            removed,
            assessment_change,
            score_change: after.visibility_score - before.visibility_score,
        }
    }

    pub fn has_changes(&self) -> bool {
        !self.became_healthy.is_empty()
            || !self.became_unhealthy.is_empty()
            || !self.added.is_empty()
            || !self.removed.is_empty()
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
    fn test_collector_confidence() {
        let mut collector = CollectorStatus::new("test_stream", CollectorType::WindowsEtw);
        collector.enabled = true;
        collector.health = CollectorHealth::Healthy;
        collector.drop_rate = 0.0;

        assert_eq!(collector.claim_confidence(), 1.0);

        collector.health = CollectorHealth::Degraded;
        assert!(collector.claim_confidence() < 1.0);

        collector.drop_rate = 0.5;
        assert!(collector.claim_confidence() < 0.5);
    }

    #[test]
    fn test_visibility_assessment() {
        let mut visibility =
            WindowVisibility::new("host1", Utc::now() - Duration::hours(1), Utc::now());

        // Add healthy process collector
        let mut process_collector =
            CollectorStatus::new("windows_etw_process", CollectorType::WindowsEtw);
        process_collector.enabled = true;
        process_collector.health = CollectorHealth::Healthy;
        process_collector.received_data = true;
        visibility.set_collector(process_collector);

        visibility.compute_assessment();

        assert!(visibility.visibility_score > 0.0);
        assert!(!visibility.critical_gaps.is_empty()); // Missing other collectors
    }

    #[test]
    fn test_can_claim() {
        let mut visibility =
            WindowVisibility::new("host1", Utc::now() - Duration::hours(1), Utc::now());

        // No collectors - should not be able to claim
        let result = visibility.can_claim("Process");
        assert!(matches!(result, CanClaimResult::No { .. }));

        // Add healthy process collector
        let mut process_collector =
            CollectorStatus::new("windows_etw_process", CollectorType::WindowsEtw);
        process_collector.enabled = true;
        process_collector.health = CollectorHealth::Healthy;
        process_collector.received_data = true;
        visibility.set_collector(process_collector);

        let result = visibility.can_claim("Process");
        assert!(matches!(result, CanClaimResult::Partial { .. }));
    }
}

// scoring/scored_signal.rs
// ScoredSignal: wraps SignalResult with advanced scoring (Mahalanobis, EllipticEnvelope, KRIM)

use crate::SignalResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredSignal {
    pub signal: SignalResult,

    // Advanced scoring fields (populated when advanced_scoring feature is enabled)
    pub mahalanobis_distance: Option<f64>, // Mahalanobis distance from normal
    pub elliptic_envelope_score: Option<f64>, // EllipticEnvelope anomaly score [0.0, 1.0]
    pub krim_score: Option<f64>,           // KRIM entropy-based score [0.0, 1.0]

    // Combined risk score (weighted average of above, when available)
    pub risk_score: f64, // [0.0, 1.0] - derived from signal severity or advanced scores
}

impl ScoredSignal {
    /// Create a ScoredSignal from a raw SignalResult
    /// Risk score defaults to severity-based if no advanced scoring
    pub fn from_signal(signal: SignalResult) -> Self {
        let severity_risk = match signal.severity.as_str() {
            "critical" => 0.95,
            "high" => 0.75,
            "medium" => 0.50,
            "low" => 0.25,
            _ => 0.10,
        };

        ScoredSignal {
            signal,
            mahalanobis_distance: None,
            elliptic_envelope_score: None,
            krim_score: None,
            risk_score: severity_risk,
        }
    }

    /// Update risk score based on advanced scoring results
    /// Applies weighted combination when multiple scores available
    pub fn update_risk_score(&mut self) {
        let mut score = 0.0;
        let mut weights = 0.0;

        if let Some(maha_dist) = self.mahalanobis_distance {
            // Maha: sigmoid(x) maps distance to [0, 1]
            let maha_score = 1.0 / (1.0 + (-maha_dist).exp());
            score += maha_score * 0.4;
            weights += 0.4;
        }

        if let Some(envelope) = self.elliptic_envelope_score {
            score += envelope * 0.3;
            weights += 0.3;
        }

        if let Some(krim) = self.krim_score {
            score += krim * 0.3;
            weights += 0.3;
        }

        // If no advanced scores, use severity-based risk
        if weights > 0.0 {
            self.risk_score = score / weights;
        }
    }

    /// Serialize to JSON for output to signals.jsonl or scored_signals.jsonl
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "signal": serde_json::to_value(&self.signal).unwrap_or(serde_json::Value::Null),
            "mahalanobis_distance": self.mahalanobis_distance,
            "elliptic_envelope_score": self.elliptic_envelope_score,
            "krim_score": self.krim_score,
            "risk_score": self.risk_score,
        })
    }

    /// Convert to canonical ScoringBreakdown for API responses
    /// Uses edr_core's canonical scoring types for consistency
    pub fn to_scoring_breakdown(&self) -> edr_core::ScoringBreakdown {
        use edr_core::{reason_codes, ScoringBreakdown, ScoringReason};

        let mut reasons = Vec::new();

        // Add severity-based reason
        let (sev_code, sev_label, sev_weight) = match self.signal.severity.as_str() {
            "critical" => (reason_codes::SEVERITY_CRITICAL, "Critical severity", 0.95),
            "high" => (reason_codes::SEVERITY_HIGH, "High severity", 0.75),
            "medium" => (reason_codes::SEVERITY_MEDIUM, "Medium severity", 0.50),
            "low" => (reason_codes::SEVERITY_LOW, "Low severity", 0.25),
            _ => (reason_codes::SEVERITY_LOW, "Unknown severity", 0.10),
        };
        reasons.push(ScoringReason::new(sev_code, sev_label, sev_weight));

        // Add advanced scoring reasons if present
        if let Some(maha) = self.mahalanobis_distance {
            reasons.push(
                ScoringReason::new(
                    reason_codes::MAHALANOBIS_ANOMALY,
                    "Mahalanobis anomaly distance",
                    (maha / 10.0).clamp(0.0, 1.0),
                )
                .with_detail(format!("Statistical distance from normal: {:.2}", maha)),
            );
        }

        if let Some(env) = self.elliptic_envelope_score {
            reasons.push(
                ScoringReason::new(
                    reason_codes::ELLIPTIC_ENVELOPE,
                    "Elliptic envelope anomaly",
                    env,
                )
                .with_detail(format!("Outlier score: {:.2}", env)),
            );
        }

        if let Some(k) = self.krim_score {
            reasons.push(
                ScoringReason::new(reason_codes::KRIM_ENTROPY, "KRIM entropy score", k)
                    .with_detail(format!("Entropy-based anomaly: {:.2}", k)),
            );
        }

        ScoringBreakdown::new(self.risk_score, reasons).with_advanced(
            self.mahalanobis_distance,
            self.elliptic_envelope_score,
            self.krim_score,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scored_signal_from_critical() {
        let signal = SignalResult {
            signal_id: "sig_123".to_string(),
            signal_type: "LogEvasion".to_string(),
            severity: "critical".to_string(),
            host: "TEST_HOST".to_string(),
            ts: 1000000,
            ts_start: 900000,
            ts_end: 1000000,
            proc_key: None,
            file_key: None,
            identity_key: Some("user1".to_string()),
            evidence_ptrs: vec![],
            dropped_evidence_count: 0,
            metadata: serde_json::json!({}),
        };

        let scored = ScoredSignal::from_signal(signal);
        assert_eq!(scored.risk_score, 0.95);
        assert!(scored.mahalanobis_distance.is_none());
    }
}

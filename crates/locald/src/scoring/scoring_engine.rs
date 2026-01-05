// scoring/scoring_engine.rs
// Advanced scoring orchestration: applies Mahalanobis, EllipticEnvelope, KRIM to signals

use super::elliptic_envelope_lite::EllipticEnvelopeLite;
use super::krim_lite::KrimLite;
use super::mahalanobis::MahalanobisCalculator;
use super::scored_signal::ScoredSignal;
use crate::SignalResult;
use std::collections::HashMap;

/// Advanced scoring engine: applies statistical models to SignalResults
pub struct ScoringEngine {
    mahalanobis: MahalanobisCalculator,
    elliptic: EllipticEnvelopeLite,
    krim: KrimLite,
    enabled: bool,
}

impl ScoringEngine {
    /// Returns true if advanced scoring is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    /// Create a new scoring engine (disabled by default)
    pub fn new(enabled: bool) -> Self {
        Self {
            mahalanobis: MahalanobisCalculator::new(),
            elliptic: EllipticEnvelopeLite::new(0.1), // Assume 10% contamination
            krim: KrimLite::new(),
            enabled,
        }
    }

    /// Train scoring models on historical baseline (normal behavior)
    pub fn train(&mut self, baseline_signals: &[SignalResult]) {
        if !self.enabled || baseline_signals.is_empty() {
            return;
        }

        // Extract feature vectors from signals
        let mut maha_samples = Vec::new();
        let mut elliptic_samples = Vec::new();

        for signal in baseline_signals {
            let features = self.extract_features(signal);
            maha_samples.push(features.clone());
            elliptic_samples.push(features);
        }

        // Train Mahalanobis
        self.mahalanobis.fit(&maha_samples);

        // Train EllipticEnvelope
        self.elliptic.fit(&elliptic_samples);
    }

    /// Score a signal using enabled models
    pub fn score(&self, signal: SignalResult) -> ScoredSignal {
        let mut scored = ScoredSignal::from_signal(signal.clone());

        if !self.enabled {
            return scored;
        }

        let features = self.extract_features(&signal);

        // Apply Mahalanobis distance
        scored.mahalanobis_distance = Some(self.mahalanobis.distance(&features));

        // Apply EllipticEnvelope
        scored.elliptic_envelope_score = Some(self.elliptic.score(&features));

        // Apply KRIM (without full baseline, returns 0.5)
        scored.krim_score = Some(self.krim.score(&features, &HashMap::new()));

        // Update combined risk score
        scored.update_risk_score();

        scored
    }

    /// Score a batch of signals
    pub fn score_batch(&self, signals: Vec<SignalResult>) -> Vec<ScoredSignal> {
        signals.into_iter().map(|s| self.score(s)).collect()
    }

    /// Extract normalized feature vector from a SignalResult
    fn extract_features(&self, signal: &SignalResult) -> HashMap<String, f64> {
        let mut features = HashMap::new();

        // Severity as numeric feature
        let severity_val = match signal.severity.as_str() {
            "critical" => 4.0,
            "high" => 3.0,
            "medium" => 2.0,
            "low" => 1.0,
            _ => 0.5,
        };
        features.insert("severity".to_string(), severity_val);

        // Time-based features
        let duration_ms = (signal.ts_end - signal.ts_start).max(0) as f64;
        features.insert("duration_ms".to_string(), duration_ms);

        // Evidence count
        let evidence_count =
            (signal.evidence_ptrs.len() + signal.dropped_evidence_count as usize) as f64;
        features.insert("evidence_count".to_string(), evidence_count);

        // Signal type encoding (simplistic hash)
        let type_hash = signal.signal_type.chars().map(|c| c as u32).sum::<u32>() as f64 % 10.0;
        features.insert("signal_type_hash".to_string(), type_hash);

        features
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scoring_engine_disabled() {
        let engine = ScoringEngine::new(false);

        let signal = SignalResult {
            signal_id: "sig_123".to_string(),
            signal_type: "LogEvasion".to_string(),
            severity: "critical".to_string(),
            host: "HOST".to_string(),
            ts: 1000000,
            ts_start: 900000,
            ts_end: 1000000,
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptrs: vec![],
            dropped_evidence_count: 0,
            metadata: serde_json::json!({}),
        };

        let scored = engine.score(signal);
        assert!(scored.mahalanobis_distance.is_none());
        assert!(scored.elliptic_envelope_score.is_none());
        assert!(scored.krim_score.is_none());
    }

    #[test]
    fn test_scoring_engine_enabled() {
        let engine = ScoringEngine::new(true);

        let signal = SignalResult {
            signal_id: "sig_123".to_string(),
            signal_type: "LogEvasion".to_string(),
            severity: "high".to_string(),
            host: "HOST".to_string(),
            ts: 1000000,
            ts_start: 900000,
            ts_end: 1000000,
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptrs: vec![],
            dropped_evidence_count: 0,
            metadata: serde_json::json!({}),
        };

        let scored = engine.score(signal);
        assert!(scored.mahalanobis_distance.is_some());
        assert!(scored.elliptic_envelope_score.is_some());
        assert!(scored.krim_score.is_some());
        assert!(scored.risk_score >= 0.0 && scored.risk_score <= 1.0);
    }
}

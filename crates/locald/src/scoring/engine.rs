//! Scoring engine: orchestrates statistical models for signal scoring

use super::scored_signal::ScoredSignal;
use super::mahalanobis::MahalanobisCalculator;
use super::elliptic_envelope::EllipticEnvelope;
use super::krim::Krim;
use crate::SignalResult;
use std::collections::HashMap;

/// Advanced scoring engine that applies statistical models to SignalResults
pub struct ScoringEngine {
    mahalanobis: MahalanobisCalculator,
    elliptic: EllipticEnvelope,
    krim: Krim,
    enabled: bool,
}

impl ScoringEngine {
    /// Create a new scoring engine
    /// 
    /// # Arguments
    /// * `enabled` - Whether to apply advanced scoring (disabled by default for performance)
    pub fn new(enabled: bool) -> Self {
        Self {
            mahalanobis: MahalanobisCalculator::new(),
            elliptic: EllipticEnvelope::new(0.1),  // 10% contamination
            krim: Krim::new(),
            enabled,
        }
    }

    /// Train scoring models on historical baseline (normal behavior)
    pub fn train(&mut self, baseline_signals: &[SignalResult]) {
        if !self.enabled || baseline_signals.is_empty() {
            return;
        }

        // Extract feature vectors from signals
        let samples: Vec<HashMap<String, f64>> = baseline_signals
            .iter()
            .map(|s| self.extract_features(s))
            .collect();

        self.mahalanobis.fit(&samples);
        self.elliptic.fit(&samples);
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
        let evidence_count = (signal.evidence_ptrs.len() + signal.dropped_evidence_count) as f64;
        features.insert("evidence_count".to_string(), evidence_count);

        // Signal type encoding (simplistic hash)
        let type_hash = signal.signal_type.chars().map(|c| c as u32).sum::<u32>() as f64 % 10.0;
        features.insert("signal_type_hash".to_string(), type_hash);

        features
    }
    
    /// Check if scoring is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    
    /// Enable or disable scoring
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Default for ScoringEngine {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scoring_engine_disabled() {
        let engine = ScoringEngine::new(false);
        
        let signal = SignalResult::new("HOST", "LogEvasion", "critical", "entity1", 1000000);

        let scored = engine.score(signal);
        assert!(scored.mahalanobis_distance.is_none());
        assert!(scored.elliptic_envelope_score.is_none());
        assert!(scored.krim_score.is_none());
    }

    #[test]
    fn test_scoring_engine_enabled() {
        let engine = ScoringEngine::new(true);

        let signal = SignalResult::new("HOST", "LogEvasion", "high", "entity1", 1000000);

        let scored = engine.score(signal);
        assert!(scored.mahalanobis_distance.is_some());
        assert!(scored.elliptic_envelope_score.is_some());
        assert!(scored.krim_score.is_some());
    }

    #[test]
    fn test_score_batch() {
        let engine = ScoringEngine::new(true);

        let signals = vec![
            SignalResult::new("HOST", "Signal1", "high", "e1", 1000),
            SignalResult::new("HOST", "Signal2", "low", "e2", 2000),
        ];

        let scored = engine.score_batch(signals);
        assert_eq!(scored.len(), 2);
    }
}

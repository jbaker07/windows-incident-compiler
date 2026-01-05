// scoring/krim_lite.rs
// KRIM (Kernel-based Robust Isolation Model): entropy-based anomaly detection

use std::collections::HashMap;

/// Lightweight KRIM: kernel-based isolation via entropy
pub struct KrimLite {
    // For now, a simplified version that computes entropy of sequences
    // Full KRIM would use isolation trees
}

impl KrimLite {
    pub fn new() -> Self {
        Self {}
    }

    /// Compute KRIM anomaly score based on feature entropy
    /// Returns [0.0, 1.0] where 1.0 = strong anomaly
    pub fn score(&self, features: &HashMap<String, f64>, baseline: &HashMap<String, Vec<f64>>) -> f64 {
        if baseline.is_empty() {
            return 0.5;
        }

        let mut total_score = 0.0;
        let mut feature_count = 0.0;

        for (feature_name, value) in features {
            if let Some(baseline_values) = baseline.get(feature_name) {
                // Compute position percentile in baseline distribution
                let percentile = self.compute_percentile(*value, baseline_values);
                
                // Distance from the mean (0.5 = normal, 0.0 or 1.0 = extreme)
                let entropy_score = 1.0 - (percentile - 0.5).abs() * 2.0;
                
                // Invert: high entropy (near 0.5) means normal, low means anomalous
                let anomaly_component = 1.0 - entropy_score;
                total_score += anomaly_component;
                feature_count += 1.0;
            }
        }

        if feature_count > 0.0 {
            total_score / feature_count
        } else {
            0.5
        }
    }

    /// Compute empirical CDF: returns percentile [0.0, 1.0]
    fn compute_percentile(&self, value: f64, baseline: &[f64]) -> f64 {
        if baseline.is_empty() {
            return 0.5;
        }

        let count = baseline.iter().filter(|&&x| x <= value).count();
        count as f64 / baseline.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_krim_score() {
        let krim = KrimLite::new();

        // Baseline distribution
        let mut baseline = HashMap::new();
        baseline.insert("cpu".to_string(), vec![0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]);
        baseline.insert("memory".to_string(), vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6]);

        // Normal point (within baseline range)
        let mut normal = HashMap::new();
        normal.insert("cpu".to_string(), 0.5);
        normal.insert("memory".to_string(), 0.3);
        let normal_score = krim.score(&normal, &baseline);

        // Anomalous point (far from baseline)
        let mut anomaly = HashMap::new();
        anomaly.insert("cpu".to_string(), 10.0);
        anomaly.insert("memory".to_string(), 10.0);
        let anomaly_score = krim.score(&anomaly, &baseline);

        assert!(normal_score < anomaly_score);
    }
}

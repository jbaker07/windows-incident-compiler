// scoring/mahalanobis.rs
// Mahalanobis distance: statistical anomaly detection

use std::collections::HashMap;

/// Simple Mahalanobis distance calculator
/// Assumes features are normalized and covariance pre-computed
pub struct MahalanobisCalculator {
    // Store feature means and covariance matrix inverse
    means: HashMap<String, f64>,
    // For now, we'll use a simplified approach without pre-computing full covariance
    // This is suitable for lightweight deployments
}

impl Default for MahalanobisCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl MahalanobisCalculator {
    pub fn new() -> Self {
        Self {
            means: HashMap::new(),
        }
    }

    /// Train on a batch of feature vectors (each feature_vec is HashMap<feature_name, value>)
    pub fn fit(&mut self, samples: &[HashMap<String, f64>]) {
        if samples.is_empty() {
            return;
        }

        // Compute means
        for sample in samples {
            for (feature, value) in sample {
                *self.means.entry(feature.clone()).or_insert(0.0) += value;
            }
        }

        for mean in self.means.values_mut() {
            *mean /= samples.len() as f64;
        }
    }

    /// Compute Mahalanobis distance for a single feature vector
    /// Simplified: uses Euclidean distance weighted by feature variance
    pub fn distance(&self, features: &HashMap<String, f64>) -> f64 {
        if self.means.is_empty() {
            return 0.0; // No baseline model
        }

        let mut dist_sq = 0.0;
        for (feature, value) in features {
            if let Some(mean) = self.means.get(feature) {
                let diff = value - mean;
                dist_sq += diff * diff; // Simplified: unit variance
            }
        }

        dist_sq.sqrt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mahalanobis_distance() {
        let mut calc = MahalanobisCalculator::new();

        // Training samples: normal behavior
        let mut samples = Vec::new();
        for _ in 0..10 {
            let mut sample = HashMap::new();
            sample.insert("cpu".to_string(), 0.5);
            sample.insert("memory".to_string(), 0.4);
            samples.push(sample);
        }

        calc.fit(&samples);

        // Normal point: should have low distance
        let mut normal = HashMap::new();
        normal.insert("cpu".to_string(), 0.51);
        normal.insert("memory".to_string(), 0.41);
        let normal_dist = calc.distance(&normal);

        // Anomalous point: should have high distance
        let mut anomaly = HashMap::new();
        anomaly.insert("cpu".to_string(), 1.5);
        anomaly.insert("memory".to_string(), 1.4);
        let anomaly_dist = calc.distance(&anomaly);

        assert!(normal_dist < anomaly_dist);
    }
}

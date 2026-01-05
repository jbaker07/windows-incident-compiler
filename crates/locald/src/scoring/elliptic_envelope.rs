//! EllipticEnvelope: robust covariance-based anomaly detection

use std::collections::HashMap;

/// Lightweight EllipticEnvelope for anomaly detection
/// Assumes elliptical distribution of normal data
pub struct EllipticEnvelope {
    means: HashMap<String, f64>,
    variances: HashMap<String, f64>,
    contamination: f64,
    threshold: f64,
}

impl EllipticEnvelope {
    /// Create a new EllipticEnvelope
    /// 
    /// # Arguments
    /// * `contamination` - Expected fraction of outliers (0.01 to 0.5)
    pub fn new(contamination: f64) -> Self {
        Self {
            means: HashMap::new(),
            variances: HashMap::new(),
            contamination: contamination.clamp(0.01, 0.5),
            threshold: 0.0,
        }
    }

    /// Fit model on training data (assumed to be normal behavior)
    pub fn fit(&mut self, samples: &[HashMap<String, f64>]) {
        if samples.is_empty() {
            return;
        }

        // Compute means
        self.means.clear();
        self.variances.clear();
        
        for sample in samples {
            for (feature, value) in sample {
                *self.means.entry(feature.clone()).or_insert(0.0) += value;
            }
        }

        let n = samples.len() as f64;
        for mean in self.means.values_mut() {
            *mean /= n;
        }

        // Compute variances
        for sample in samples {
            for (feature, value) in sample {
                if let Some(mean) = self.means.get(feature) {
                    let diff = value - mean;
                    *self.variances.entry(feature.clone()).or_insert(0.0) += diff * diff;
                }
            }
        }

        for var in self.variances.values_mut() {
            *var /= n;
            if *var < 1e-6 {
                *var = 1e-6;  // Avoid division by zero
            }
        }

        // Compute threshold based on contamination
        let chi2_quantile = 1.0 / (1.0 - self.contamination);
        self.threshold = chi2_quantile.ln() * 2.0;
    }

    /// Score an observation: returns [0.0, 1.0] where 1.0 = strong anomaly
    pub fn score(&self, features: &HashMap<String, f64>) -> f64 {
        if self.means.is_empty() {
            return 0.5;  // Unknown
        }

        let mut dist = 0.0;
        for (feature, value) in features {
            if let (Some(mean), Some(var)) = (self.means.get(feature), self.variances.get(feature)) {
                let diff = value - mean;
                dist += (diff * diff) / var;
            }
        }

        // Normalize distance to [0, 1] using sigmoid
        1.0 / (1.0 + (-dist).exp())
    }
    
    /// Check if the model has been trained
    pub fn is_trained(&self) -> bool {
        !self.means.is_empty()
    }
    
    /// Get the threshold for anomaly detection
    pub fn threshold(&self) -> f64 {
        self.threshold
    }
}

impl Default for EllipticEnvelope {
    fn default() -> Self {
        Self::new(0.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elliptic_envelope_fit_and_score() {
        let mut envelope = EllipticEnvelope::new(0.1);

        // Training data: normal behavior
        let mut samples = Vec::new();
        for i in 0..20 {
            let mut sample = HashMap::new();
            sample.insert("cpu".to_string(), 0.5 + (i as f64 * 0.01));
            sample.insert("memory".to_string(), 0.4 + (i as f64 * 0.005));
            samples.push(sample);
        }

        envelope.fit(&samples);

        // Normal point: lower score
        let mut normal = HashMap::new();
        normal.insert("cpu".to_string(), 0.55);
        normal.insert("memory".to_string(), 0.42);
        let normal_score = envelope.score(&normal);

        // Anomalous point: higher score
        let mut anomaly = HashMap::new();
        anomaly.insert("cpu".to_string(), 5.0);
        anomaly.insert("memory".to_string(), 5.0);
        let anomaly_score = envelope.score(&anomaly);

        assert!(normal_score < anomaly_score);
    }

    #[test]
    fn test_untrained_returns_half() {
        let envelope = EllipticEnvelope::new(0.1);
        let mut features = HashMap::new();
        features.insert("cpu".to_string(), 0.5);
        
        assert_eq!(envelope.score(&features), 0.5);
    }
}

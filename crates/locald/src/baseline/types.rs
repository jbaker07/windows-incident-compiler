// locald/baseline/types.rs
// Baseline data structures (shared across all OSes)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// First-seen sets: track novel occurrences per exe/identity
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FirstSeenBaseline {
    /// Per exe_key: set of remote IPs ever seen
    pub remote_ips_per_exe: HashMap<String, HashSet<String>>,

    /// Per identity_key: set of exe_keys ever executed
    pub exes_per_identity: HashMap<String, HashSet<String>>,

    /// Per exe_key: set of parent exes
    pub parent_exes: HashMap<String, HashSet<String>>,

    /// Per exe_key: set of child exes
    pub child_exes: HashMap<String, HashSet<String>>,

    /// Per exe_key: set of file path prefixes written/executed
    pub file_prefixes_per_exe: HashMap<String, HashSet<String>>,

    /// Per identity_key: set of activity tags (e.g., "process", "network", "file")
    pub activity_tags_per_identity: HashMap<String, HashSet<String>>,
}

/// Rate baseline: EMA-based tracking for burst detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateBaseline {
    /// EMA value
    pub ema: f64,
    /// EMA variance
    pub ema_var: f64,
    /// Last timestamp (in minutes)
    pub last_ts_min: i64,
    /// Count of samples
    pub sample_count: u32,
}

impl Default for RateBaseline {
    fn default() -> Self {
        Self::new()
    }
}

impl RateBaseline {
    pub fn new() -> Self {
        Self {
            ema: 0.0,
            ema_var: 0.0,
            last_ts_min: 0,
            sample_count: 0,
        }
    }

    /// Update EMA with new rate observation
    /// alpha: smoothing factor (typically 0.1-0.3)
    pub fn update(&mut self, observed_rate: f64, alpha: f64, now_min: i64) {
        if self.sample_count == 0 {
            self.ema = observed_rate;
            self.ema_var = 0.0;
        } else {
            let delta = observed_rate - self.ema;
            self.ema = self.ema * (1.0 - alpha) + observed_rate * alpha;
            self.ema_var = self.ema_var * (1.0 - alpha) + delta * delta * alpha;
        }
        self.last_ts_min = now_min;
        self.sample_count += 1;
    }

    /// Check if rate is anomalous
    /// threshold_k: how many standard deviations (typically 2.0-3.0)
    /// min_floor: minimum expected rate
    pub fn is_burst(&self, observed_rate: f64, threshold_k: f64, min_floor: f64) -> bool {
        let threshold = (self.ema + threshold_k * self.ema_var.sqrt()).max(min_floor);
        observed_rate > threshold
    }
}

/// Distribution baseline: track feature vectors for Mahalanobis-style detection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeatureVectorBaseline {
    /// Mean values per feature
    pub means: HashMap<String, f64>,
    /// Variance per feature
    pub variances: HashMap<String, f64>,
    /// Sample count
    pub sample_count: u32,
}

impl FeatureVectorBaseline {
    pub fn new() -> Self {
        Self {
            means: HashMap::new(),
            variances: HashMap::new(),
            sample_count: 0,
        }
    }

    /// Update means and variances (Welford online algorithm)
    pub fn update(&mut self, features: &HashMap<String, f64>) {
        let n = (self.sample_count + 1) as f64;

        for (feature_name, value) in features {
            let mean = self.means.entry(feature_name.clone()).or_insert(0.0);
            let delta = value - *mean;
            *mean += delta / n;

            let variance = self.variances.entry(feature_name.clone()).or_insert(0.0);
            let delta2 = value - *mean;
            *variance += delta * delta2;
        }

        self.sample_count += 1;
    }

    /// Compute Mahalanobis-like distance (simplified: Euclidean with variance weighting)
    pub fn distance(&self, features: &HashMap<String, f64>) -> f64 {
        if self.sample_count < 2 {
            return 0.0; // No baseline yet
        }

        let mut dist_sq = 0.0;
        for (feature_name, value) in features {
            if let (Some(mean), Some(var)) = (
                self.means.get(feature_name),
                self.variances.get(feature_name),
            ) {
                let normalized_var = *var / (self.sample_count as f64 - 1.0);
                let normalized_var = normalized_var.max(1e-6); // Avoid division by zero
                let diff = value - mean;
                dist_sq += (diff * diff) / normalized_var;
            }
        }

        dist_sq.sqrt()
    }
}

/// Per-host baseline state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostBaseline {
    pub host: String,

    /// First-seen baselines
    pub first_seen: FirstSeenBaseline,

    /// Rate baselines keyed by metric name and context
    /// Key format: "metric:context" (e.g., "admin_share_access:per_host", "connections:per_exe:exe_key")
    pub rate_baselines: HashMap<String, RateBaseline>,

    /// Distribution baselines keyed by feature vector type
    /// Key format: "network", "auth", "process_chain"
    pub feature_vector_baselines: HashMap<String, FeatureVectorBaseline>,

    /// Last update timestamp (ms)
    pub last_updated_ts: i64,
}

impl HostBaseline {
    pub fn new(host: String) -> Self {
        Self {
            host,
            first_seen: FirstSeenBaseline::default(),
            rate_baselines: HashMap::new(),
            feature_vector_baselines: HashMap::new(),
            last_updated_ts: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_baseline_ema() {
        let mut baseline = RateBaseline::new();
        baseline.update(10.0, 0.1, 0);
        baseline.update(15.0, 0.1, 1);
        baseline.update(12.0, 0.1, 2);

        assert!(baseline.ema > 10.0 && baseline.ema < 15.0);
    }

    #[test]
    fn test_rate_baseline_burst() {
        let mut baseline = RateBaseline::new();
        // Need variance in the data for meaningful threshold
        baseline.update(4.0, 0.3, 0);
        baseline.update(5.0, 0.3, 1);
        baseline.update(6.0, 0.3, 2);
        baseline.update(5.0, 0.3, 3);
        baseline.update(5.0, 0.3, 4);

        // Rate near the mean should not trigger
        assert!(!baseline.is_burst(7.0, 3.0, 0.5));

        // Large spike should trigger
        assert!(baseline.is_burst(50.0, 3.0, 0.5));
    }

    #[test]
    fn test_feature_vector_baseline() {
        let mut baseline = FeatureVectorBaseline::new();

        let mut f1 = HashMap::new();
        f1.insert("cpu".to_string(), 0.5);
        f1.insert("memory".to_string(), 0.4);
        baseline.update(&f1);

        let mut f2 = HashMap::new();
        f2.insert("cpu".to_string(), 0.51);
        f2.insert("memory".to_string(), 0.41);
        baseline.update(&f2);

        // Normal point should have low distance
        let normal_dist = baseline.distance(&f1);

        // Anomalous point should have higher distance
        let mut f_anom = HashMap::new();
        f_anom.insert("cpu".to_string(), 2.0);
        f_anom.insert("memory".to_string(), 2.0);
        let anom_dist = baseline.distance(&f_anom);

        assert!(anom_dist > normal_dist);
    }
}

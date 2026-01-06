// locald/baseline/baseline_query.rs
// Query baselines for detection decisions

use super::types::HostBaseline;

pub struct BaselineQuery;

impl BaselineQuery {
    /// Check if a remote IP is new for a given exe
    /// Returns (is_new, total_count)
    pub fn is_new_remote_ip(
        baseline: &HostBaseline,
        exe_key: &str,
        remote_ip: &str,
    ) -> (bool, usize) {
        if let Some(ips) = baseline.first_seen.remote_ips_per_exe.get(exe_key) {
            let is_new = !ips.contains(remote_ip);
            (is_new, ips.len())
        } else {
            (true, 0)
        }
    }

    /// Check if a parent→child relationship is novel
    pub fn is_new_parent_child(baseline: &HostBaseline, parent_exe: &str, child_exe: &str) -> bool {
        if let Some(children) = baseline.first_seen.child_exes.get(parent_exe) {
            !children.contains(child_exe)
        } else {
            true
        }
    }

    /// Check if activity from an identity is novel
    /// Returns (is_new_tag, total_tags_for_identity)
    pub fn is_new_identity_activity(
        baseline: &HostBaseline,
        identity_key: &str,
        tag: &str,
    ) -> (bool, usize) {
        if let Some(tags) = baseline
            .first_seen
            .activity_tags_per_identity
            .get(identity_key)
        {
            let is_new = !tags.contains(tag);
            (is_new, tags.len())
        } else {
            (true, 0)
        }
    }

    /// Check if file path is a novel prefix for exe
    pub fn is_new_file_prefix(baseline: &HostBaseline, exe_key: &str, file_prefix: &str) -> bool {
        if let Some(prefixes) = baseline.first_seen.file_prefixes_per_exe.get(exe_key) {
            !prefixes.contains(file_prefix)
        } else {
            true
        }
    }

    /// Check if rate is anomalous for a metric
    /// Returns (is_burst, threshold)
    pub fn is_burst(
        baseline: &HostBaseline,
        metric_name: &str,
        observed_rate: f64,
        threshold_k: f64,
        min_floor: f64,
    ) -> (bool, f64) {
        if let Some(rate_baseline) = baseline.rate_baselines.get(metric_name) {
            let is_burst = rate_baseline.is_burst(observed_rate, threshold_k, min_floor);
            let threshold =
                (rate_baseline.ema + threshold_k * rate_baseline.ema_var.sqrt()).max(min_floor);
            (is_burst, threshold)
        } else {
            // No baseline yet; be conservative
            (false, min_floor)
        }
    }

    /// Get EMA for a metric (for logging/debugging)
    pub fn get_ema(baseline: &HostBaseline, metric_name: &str) -> Option<f64> {
        baseline.rate_baselines.get(metric_name).map(|rb| rb.ema)
    }

    /// Check if feature vector is anomalous using Mahalanobis-like distance
    /// Returns (distance, is_anomalous)
    pub fn is_feature_vector_anomalous(
        baseline: &HostBaseline,
        vector_type: &str,
        features: &std::collections::HashMap<String, f64>,
        threshold: f64,
    ) -> (f64, bool) {
        if let Some(fv_baseline) = baseline.feature_vector_baselines.get(vector_type) {
            let distance = fv_baseline.distance(features);
            let is_anomalous = distance > threshold;
            (distance, is_anomalous)
        } else {
            // No baseline yet
            (0.0, false)
        }
    }

    /// Get feature vector baseline statistics (for logging/debugging)
    pub fn get_feature_vector_stats(
        baseline: &HostBaseline,
        vector_type: &str,
    ) -> Option<(f64, f64, u32)> {
        baseline
            .feature_vector_baselines
            .get(vector_type)
            .map(|fv| {
                let mean_mean = fv.means.values().sum::<f64>() / (fv.means.len() as f64 + 1e-6);
                let mean_var =
                    fv.variances.values().sum::<f64>() / (fv.variances.len() as f64 + 1e-6);
                (mean_mean, mean_var, fv.sample_count)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_new_remote_ip() {
        let mut baseline = HostBaseline::new("test_host".to_string());
        baseline.first_seen.remote_ips_per_exe.insert(
            "exe1".to_string(),
            ["192.168.1.1", "192.168.1.2"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );

        let (is_new, count) = BaselineQuery::is_new_remote_ip(&baseline, "exe1", "192.168.1.1");
        assert!(!is_new);
        assert_eq!(count, 2);

        let (is_new, count) = BaselineQuery::is_new_remote_ip(&baseline, "exe1", "192.168.1.3");
        assert!(is_new);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_is_new_parent_child() {
        let mut baseline = HostBaseline::new("test_host".to_string());
        baseline.first_seen.child_exes.insert(
            "parent".to_string(),
            ["child1", "child2"].iter().map(|s| s.to_string()).collect(),
        );

        assert!(!BaselineQuery::is_new_parent_child(
            &baseline, "parent", "child1"
        ));
        assert!(BaselineQuery::is_new_parent_child(
            &baseline, "parent", "child3"
        ));
        assert!(BaselineQuery::is_new_parent_child(
            &baseline,
            "unknown_parent",
            "child1"
        ));
    }

    #[test]
    fn test_is_burst() {
        let mut baseline = HostBaseline::new("test_host".to_string());

        // Manually add a rate baseline with some variance
        let mut rate_bl = crate::baseline::types::RateBaseline::new();
        rate_bl.update(4.0, 0.3, 0);
        rate_bl.update(5.0, 0.3, 1);
        rate_bl.update(6.0, 0.3, 2);
        rate_bl.update(5.0, 0.3, 3);
        baseline
            .rate_baselines
            .insert("metric1".to_string(), rate_bl);

        // Rate near the mean should not trigger burst
        let (is_burst, _threshold) = BaselineQuery::is_burst(&baseline, "metric1", 7.0, 3.0, 0.5);
        assert!(!is_burst);

        // Large spike should trigger burst
        let (is_burst, _threshold) = BaselineQuery::is_burst(&baseline, "metric1", 50.0, 3.0, 0.5);
        assert!(is_burst);
    }
}

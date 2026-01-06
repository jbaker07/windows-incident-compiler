// locald/baseline/baseline_update.rs
// Update baselines from canonical events

use super::types::HostBaseline;
use edr_core::Event;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct BaselineUpdater;

impl BaselineUpdater {
    /// Update first-seen sets from a canonical event
    pub fn update_first_seen(baseline: &mut HostBaseline, event: &Event) {
        // Extract relevant fields from event
        let exe_key = event.proc_key.clone();
        let identity_key = event.identity_key.clone();
        let remote_ip = event.fields.get("dest_ip").and_then(|v| v.as_str());
        let parent_exe = event.fields.get("parent_exe").and_then(|v| v.as_str());
        let child_exe = event.fields.get("child_exe").and_then(|v| v.as_str());
        let file_path = event.fields.get("file_path").and_then(|v| v.as_str());

        // Track remote IPs per exe
        if let (Some(exe), Some(ip)) = (&exe_key, remote_ip) {
            baseline
                .first_seen
                .remote_ips_per_exe
                .entry(exe.clone())
                .or_default()
                .insert(ip.to_string());
        }

        // Track exes per identity
        if let (Some(identity), Some(exe)) = (&identity_key, &exe_key) {
            baseline
                .first_seen
                .exes_per_identity
                .entry(identity.clone())
                .or_default()
                .insert(exe.clone());
        }

        // Track parent→child relationships
        if let (Some(parent), Some(child)) = (parent_exe, child_exe) {
            baseline
                .first_seen
                .parent_exes
                .entry(parent.to_string())
                .or_default()
                .insert(parent.to_string());

            baseline
                .first_seen
                .child_exes
                .entry(parent.to_string())
                .or_default()
                .insert(child.to_string());
        }

        // Track file path prefixes
        if let (Some(exe), Some(path)) = (&exe_key, file_path) {
            let prefix = Self::extract_prefix(path);
            baseline
                .first_seen
                .file_prefixes_per_exe
                .entry(exe.clone())
                .or_default()
                .insert(prefix);
        }

        // Track activity tags per identity
        if let Some(identity) = &identity_key {
            for tag in &event.tags {
                baseline
                    .first_seen
                    .activity_tags_per_identity
                    .entry(identity.clone())
                    .or_default()
                    .insert(tag.clone());
            }
        }

        // Update timestamp
        baseline.last_updated_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
    }

    /// Update rate baselines from a canonical event
    pub fn update_rates(baseline: &mut HostBaseline, _event: &Event, metric_name: &str, rate: f64) {
        let now_min = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 60) as i64;

        let rate_baseline = baseline
            .rate_baselines
            .entry(metric_name.to_string())
            .or_default();

        // Use alpha=0.1 for EMA smoothing
        rate_baseline.update(rate, 0.1, now_min);
    }

    /// Update feature vector baselines from a canonical event
    pub fn update_feature_vector(
        baseline: &mut HostBaseline,
        vector_type: &str,
        features: &std::collections::HashMap<String, f64>,
    ) {
        let fv_baseline = baseline
            .feature_vector_baselines
            .entry(vector_type.to_string())
            .or_default();

        fv_baseline.update(features);
    }

    /// Extract a path prefix (first 2 levels)
    fn extract_prefix(path: &str) -> String {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();

        if parts.len() >= 2 {
            format!("/{}/{}", parts[0], parts[1])
        } else if !parts.is_empty() {
            format!("/{}", parts[0])
        } else {
            "/".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_extract_prefix() {
        assert_eq!(BaselineUpdater::extract_prefix("/usr/bin/ls"), "/usr/bin");
        assert_eq!(
            BaselineUpdater::extract_prefix("/home/user/file.txt"),
            "/home/user"
        );
        assert_eq!(BaselineUpdater::extract_prefix("/tmp"), "/tmp");
    }

    #[test]
    fn test_update_first_seen() {
        let mut baseline = HostBaseline::new("test_host".to_string());

        let mut event = Event {
            ts_ms: 0,
            host: "test_host".to_string(),
            tags: vec!["process".to_string()],
            proc_key: Some("proc_123".to_string()),
            file_key: None,
            identity_key: Some("user1".to_string()),
            evidence_ptr: Some(edr_core::EvidencePtr {
                stream_id: "test".to_string(),
                segment_id: 1,
                record_index: 1,
            }),
            fields: BTreeMap::new(),
        };

        event
            .fields
            .insert("dest_ip".to_string(), serde_json::json!("192.168.1.1"));

        BaselineUpdater::update_first_seen(&mut baseline, &event);

        assert!(baseline
            .first_seen
            .remote_ips_per_exe
            .get("proc_123")
            .is_some_and(|ips| ips.contains("192.168.1.1")));
    }
}

//! VendorAlertFact: Ingested third-party alerts as canonical facts
//!
//! VendorAlertFact extends the FactType enum with a new variant for
//! alerts/events from external systems (Wazuh, Zeek, Suricata, osquery, etc.)

use crate::hypothesis::{EvidencePtr, Fact, FactType, ScopeKey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Provenance indicator for facts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactProvenance {
    /// Hard provenance: directly observed by our sensors
    Hard,
    /// Soft provenance: ingested from third-party source
    Soft,
}

/// VendorAlertFact: A fact derived from an external alert/event source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorAlertFact {
    /// Vendor/source identifier (e.g., "wazuh", "zeek", "suricata")
    pub vendor: String,

    /// Source identifier within vendor (e.g., "alerts", "eve", "dns")
    pub source: String,

    /// Original event ID from the vendor (for dedup/correlation)
    pub original_event_id: Option<String>,

    /// Alert/rule name or ID
    pub alert_name: Option<String>,

    /// Alert severity from vendor
    pub vendor_severity: Option<String>,

    /// Timestamp from vendor
    pub vendor_ts: DateTime<Utc>,

    /// Host identifier (if present in vendor event)
    pub host_hint: Option<String>,

    /// IP address indicators
    pub ip_indicators: Vec<IpIndicator>,

    /// Process hints (for correlation)
    pub process_hints: Option<ProcessHint>,

    /// File hints (for correlation)
    pub file_hints: Option<FileHint>,

    /// DNS query (for network enrichment)
    pub dns_query: Option<String>,

    /// URL or domain indicators
    pub url_indicators: Vec<String>,

    /// MITRE ATT&CK tags if present
    pub mitre_tags: Vec<String>,

    /// Raw vendor event (truncated for storage)
    pub raw_event_summary: Option<String>,

    /// Provenance marker (always Soft for ingested)
    pub provenance: FactProvenance,
}

/// IP address indicator from vendor event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpIndicator {
    pub ip: String,
    pub port: Option<u16>,
    pub direction: IpDirection,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpDirection {
    Source,
    Destination,
    Unknown,
}

/// Process hints from vendor event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessHint {
    pub pid: Option<u32>,
    pub exe_path: Option<String>,
    pub exe_hash: Option<String>,
    pub cmdline: Option<String>,
    pub user: Option<String>,
}

/// File hints from vendor event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHint {
    pub path: Option<String>,
    pub hash_sha256: Option<String>,
    pub hash_md5: Option<String>,
}

impl VendorAlertFact {
    /// Create a new VendorAlertFact
    pub fn new(
        vendor: impl Into<String>,
        source: impl Into<String>,
        vendor_ts: DateTime<Utc>,
    ) -> Self {
        Self {
            vendor: vendor.into(),
            source: source.into(),
            original_event_id: None,
            alert_name: None,
            vendor_severity: None,
            vendor_ts,
            host_hint: None,
            ip_indicators: Vec::new(),
            process_hints: None,
            file_hints: None,
            dns_query: None,
            url_indicators: Vec::new(),
            mitre_tags: Vec::new(),
            raw_event_summary: None,
            provenance: FactProvenance::Soft,
        }
    }

    /// Compute deterministic scope key for this vendor alert
    ///
    /// Formula: hash(vendor + host_hint_or_ip + time_bucket_minutes)
    /// This ensures:
    /// 1. Same alert from same source at same time → same scope key
    /// 2. Different alerts → different scope keys
    /// 3. Deterministic across replays
    pub fn compute_scope_key(&self, time_bucket_minutes: i64) -> ScopeKey {
        let mut hasher = Sha256::new();

        // Vendor + source
        hasher.update(self.vendor.as_bytes());
        hasher.update(b":");
        hasher.update(self.source.as_bytes());
        hasher.update(b":");

        // Host or primary IP
        let host_component = self.host_hint.clone().unwrap_or_else(|| {
            self.ip_indicators
                .first()
                .map(|i| i.ip.clone())
                .unwrap_or_else(|| "unknown".to_string())
        });
        hasher.update(host_component.as_bytes());
        hasher.update(b":");

        // Time bucket
        let bucket = self.vendor_ts.timestamp() / (time_bucket_minutes * 60);
        hasher.update(bucket.to_le_bytes());

        // Optional: include original_event_id for uniqueness
        if let Some(ref event_id) = self.original_event_id {
            hasher.update(b":");
            hasher.update(event_id.as_bytes());
        }

        let hash = hex::encode(&hasher.finalize()[..16]);
        ScopeKey::Campaign {
            key: format!("vendor_alert:{}", hash),
        }
    }

    /// Convert to canonical Fact with Unknown FactType (for now)
    ///
    /// Note: We use FactType::Unknown because VendorAlert is not in the
    /// canonical FactType enum. This is intentional - vendor alerts are
    /// soft-provenance enrichment, not primary facts.
    pub fn to_fact(&self, host_id: &str, time_bucket_minutes: i64) -> Fact {
        let scope_key = self.compute_scope_key(time_bucket_minutes);

        // Build extra fields map
        let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
        fields.insert("vendor".to_string(), serde_json::json!(self.vendor));
        fields.insert("source".to_string(), serde_json::json!(self.source));
        fields.insert("provenance".to_string(), serde_json::json!("soft"));

        if let Some(ref alert_name) = self.alert_name {
            fields.insert("alert_name".to_string(), serde_json::json!(alert_name));
        }
        if let Some(ref severity) = self.vendor_severity {
            fields.insert("vendor_severity".to_string(), serde_json::json!(severity));
        }
        if !self.ip_indicators.is_empty() {
            fields.insert(
                "ip_indicators".to_string(),
                serde_json::json!(self.ip_indicators),
            );
        }
        if let Some(ref dns) = self.dns_query {
            fields.insert("dns_query".to_string(), serde_json::json!(dns));
        }
        if !self.mitre_tags.is_empty() {
            fields.insert("mitre_tags".to_string(), serde_json::json!(self.mitre_tags));
        }
        if let Some(ref raw) = self.raw_event_summary {
            fields.insert("raw_event_summary".to_string(), serde_json::json!(raw));
        }

        // Create evidence pointer (synthetic for ingested events)
        let evidence_ptr = EvidencePtr::new(
            format!("vendor:{}", self.vendor),
            self.original_event_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            0,
        )
        .with_timestamp(self.vendor_ts);

        let fact_type = FactType::Unknown {
            raw_type: format!("vendor_alert:{}", self.vendor),
            fields,
        };

        let host = self
            .host_hint
            .clone()
            .unwrap_or_else(|| host_id.to_string());
        Fact::new(host, scope_key, fact_type, vec![evidence_ptr])
    }

    /// Check if this alert can soft-join with a network event
    pub fn can_join_by_ip(&self, ip: &str, ts: DateTime<Utc>, window_seconds: i64) -> bool {
        // Check IP match
        let ip_match = self.ip_indicators.iter().any(|ind| ind.ip == ip);
        if !ip_match {
            return false;
        }

        // Check time window
        let delta = (self.vendor_ts - ts).num_seconds().abs();
        delta <= window_seconds
    }

    /// Check if this alert can soft-join with a process event
    pub fn can_join_by_exe(&self, exe_hash: &str) -> bool {
        self.process_hints
            .as_ref()
            .and_then(|h| h.exe_hash.as_ref())
            .map(|h| h == exe_hash)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vendor_alert_scope_key_determinism() {
        let ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let alert1 = VendorAlertFact {
            vendor: "wazuh".to_string(),
            source: "alerts".to_string(),
            original_event_id: Some("12345".to_string()),
            vendor_ts: ts,
            host_hint: Some("host1".to_string()),
            ..VendorAlertFact::new("wazuh", "alerts", ts)
        };

        let alert2 = VendorAlertFact {
            vendor: "wazuh".to_string(),
            source: "alerts".to_string(),
            original_event_id: Some("12345".to_string()),
            vendor_ts: ts,
            host_hint: Some("host1".to_string()),
            ..VendorAlertFact::new("wazuh", "alerts", ts)
        };

        let key1 = alert1.compute_scope_key(5);
        let key2 = alert2.compute_scope_key(5);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_vendor_alert_to_fact() {
        let ts = Utc::now();
        let mut alert = VendorAlertFact::new("zeek", "dns", ts);
        alert.dns_query = Some("evil.com".to_string());
        alert.ip_indicators.push(IpIndicator {
            ip: "1.2.3.4".to_string(),
            port: Some(53),
            direction: IpDirection::Destination,
            protocol: Some("udp".to_string()),
        });

        let fact = alert.to_fact("host1", 5);

        assert!(!fact.fact_id.is_empty());
        assert!(matches!(fact.scope_key, ScopeKey::Campaign { .. }));
    }

    #[test]
    fn test_ip_join() {
        let ts = Utc::now();
        let mut alert = VendorAlertFact::new("zeek", "conn", ts);
        alert.ip_indicators.push(IpIndicator {
            ip: "93.184.216.34".to_string(),
            port: Some(443),
            direction: IpDirection::Destination,
            protocol: Some("tcp".to_string()),
        });

        // Same time, same IP → should join
        assert!(alert.can_join_by_ip("93.184.216.34", ts, 300));

        // Different IP → should not join
        assert!(!alert.can_join_by_ip("1.2.3.4", ts, 300));

        // Same IP, outside window → should not join
        let old_ts = ts - chrono::Duration::seconds(600);
        assert!(!alert.can_join_by_ip("93.184.216.34", old_ts, 300));
    }
}

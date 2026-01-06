//! Ingest: Third-party alerts → VendorAlertFact
//!
//! Ingests alerts/events from external sources (Wazuh, Zeek, Suricata)
//! and converts them to VendorAlertFact for enrichment via soft joins.

use crate::hypothesis::Fact;
use crate::integrations::config::{IngestSourceConfig, IngestSourceType};
use crate::integrations::vendor_alert::{IpDirection, IpIndicator, ProcessHint, VendorAlertFact};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Ingest source trait
pub trait IngestSource: Send {
    /// Poll for new events, return parsed VendorAlertFacts
    fn poll(&mut self) -> Result<Vec<VendorAlertFact>, String>;

    /// Get source stats
    fn stats(&self) -> IngestStats;
}

/// Ingester statistics
#[derive(Debug, Clone, Default)]
pub struct IngestStats {
    pub events_read: u64,
    pub events_parsed: u64,
    pub parse_errors: u64,
    pub facts_created: u64,
}

/// VendorAlert ingester - manages multiple sources
pub struct VendorAlertIngester {
    sources: Vec<Box<dyn IngestSource>>,
    facts_buffer: VecDeque<Fact>,
    join_window_seconds: u64,
    time_bucket_minutes: i64,
    default_host: String,
}

impl VendorAlertIngester {
    pub fn new(default_host: &str) -> Self {
        Self {
            sources: Vec::new(),
            facts_buffer: VecDeque::new(),
            join_window_seconds: 300,
            time_bucket_minutes: 5,
            default_host: default_host.to_string(),
        }
    }

    /// Add a source from config
    pub fn add_source_from_config(&mut self, config: &IngestSourceConfig) -> Result<(), String> {
        let source: Box<dyn IngestSource> = match config.source_type {
            IngestSourceType::JsonlFile => {
                let path = config
                    .input_path
                    .clone()
                    .ok_or("JSONL source requires input_path")?;
                Box::new(JsonlFileSource::new(
                    &path,
                    &config.vendor,
                    &config.source_id,
                )?)
            }
            IngestSourceType::WazuhAlerts => {
                let path = config
                    .input_path
                    .clone()
                    .ok_or("Wazuh source requires input_path")?;
                Box::new(WazuhAlertsSource::new(&path)?)
            }
            IngestSourceType::ZeekEve => {
                let path = config
                    .input_path
                    .clone()
                    .ok_or("Zeek source requires input_path")?;
                Box::new(ZeekEveSource::new(&path)?)
            }
            IngestSourceType::SyslogUdp => {
                let addr = config
                    .listen_addr
                    .clone()
                    .ok_or("Syslog source requires listen_addr")?;
                Box::new(SyslogUdpSource::new(&addr, &config.vendor)?)
            }
        };

        self.sources.push(source);
        self.join_window_seconds = config.join_window_seconds;

        Ok(())
    }

    /// Poll all sources and collect facts
    pub fn poll(&mut self) -> Result<Vec<Fact>, String> {
        let mut all_facts = Vec::new();

        for source in &mut self.sources {
            match source.poll() {
                Ok(alerts) => {
                    for alert in alerts {
                        let fact = alert.to_fact(&self.default_host, self.time_bucket_minutes);
                        all_facts.push(fact);
                    }
                }
                Err(e) => {
                    eprintln!("[ingest] Source poll error: {}", e);
                }
            }
        }

        // Buffer facts for potential joins
        for fact in &all_facts {
            self.facts_buffer.push_back(fact.clone());
        }

        // Trim buffer to reasonable size
        while self.facts_buffer.len() > 10000 {
            self.facts_buffer.pop_front();
        }

        Ok(all_facts)
    }

    /// Find vendor alerts that can soft-join with a network event
    pub fn find_joinable_by_ip(&self, ip: &str, ts: DateTime<Utc>) -> Vec<&Fact> {
        self.facts_buffer
            .iter()
            .filter(|fact| {
                // Check if this is a vendor alert fact
                if let crate::hypothesis::FactType::Unknown { raw_type, fields } = &fact.fact_type {
                    if raw_type.starts_with("vendor_alert:") {
                        // Check IP indicators
                        if let Some(Value::Array(indicators)) = fields.get("ip_indicators") {
                            for ind in indicators {
                                if let Some(ind_ip) = ind.get("ip").and_then(|v| v.as_str()) {
                                    if ind_ip == ip {
                                        // Check time window
                                        let delta = (fact.ts - ts).num_seconds().abs();
                                        if delta <= self.join_window_seconds as i64 {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                false
            })
            .collect()
    }

    /// Get aggregate stats
    pub fn stats(&self) -> IngestStats {
        let mut total = IngestStats::default();
        for source in &self.sources {
            let s = source.stats();
            total.events_read += s.events_read;
            total.events_parsed += s.events_parsed;
            total.parse_errors += s.parse_errors;
            total.facts_created += s.facts_created;
        }
        total
    }
}

// ============================================================================
// Parsing Helpers (free functions to avoid borrow conflicts)
// ============================================================================

/// Parse a generic JSON alert into VendorAlertFact
fn parse_generic_json(json: &Value, vendor: &str, source_id: &str) -> Option<VendorAlertFact> {
    let ts = json
        .get("timestamp")
        .or_else(|| json.get("@timestamp"))
        .or_else(|| json.get("ts"))
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let event_id = json
        .get("id")
        .or_else(|| json.get("event_id"))
        .or_else(|| json.get("uid"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut alert = VendorAlertFact::new(vendor, source_id, ts);
    alert.original_event_id = event_id;

    // Extract host hint
    alert.host_hint = json
        .get("host")
        .or_else(|| json.get("hostname"))
        .or_else(|| json.get("agent").and_then(|a| a.get("name")))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    alert.alert_name = json
        .get("rule")
        .and_then(|r| r.get("description"))
        .or_else(|| json.get("alert"))
        .or_else(|| json.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Extract IP indicators
    for (src_field, direction) in [
        ("src_ip", IpDirection::Source),
        ("source_ip", IpDirection::Source),
        ("srcip", IpDirection::Source),
        ("dst_ip", IpDirection::Destination),
        ("dest_ip", IpDirection::Destination),
        ("dstip", IpDirection::Destination),
    ] {
        if let Some(ip) = json.get(src_field).and_then(|v| v.as_str()) {
            let port_field = if direction == IpDirection::Source {
                "src_port"
            } else {
                "dst_port"
            };
            let port = json
                .get(port_field)
                .and_then(|v| v.as_u64())
                .map(|p| p as u16);

            alert.ip_indicators.push(IpIndicator {
                ip: ip.to_string(),
                port,
                direction,
                protocol: json
                    .get("proto")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            });
        }
    }

    // Store raw summary (truncated)
    alert.raw_event_summary = Some(
        serde_json::to_string(json)
            .unwrap_or_default()
            .chars()
            .take(500)
            .collect(),
    );

    Some(alert)
}

/// Parse Wazuh alert JSON
fn parse_wazuh_alert(json: &Value, source_id: &str) -> Option<VendorAlertFact> {
    let ts = json
        .get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let rule_id = json
        .get("rule")
        .and_then(|r| r.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("0");

    let full_log_id = json
        .get("full_log")
        .and_then(|v| v.as_str())
        .map(|s| {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            s.hash(&mut hasher);
            hasher.finish()
        })
        .unwrap_or(0);

    let event_id = format!("wazuh_{}_{}", rule_id, full_log_id);

    let mut alert = VendorAlertFact::new("wazuh", source_id, ts);
    alert.original_event_id = Some(event_id);

    // Host from agent
    alert.host_hint = json
        .get("agent")
        .and_then(|a| a.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Alert name from rule description
    alert.alert_name = json
        .get("rule")
        .and_then(|r| r.get("description"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Severity from rule level
    alert.vendor_severity = json
        .get("rule")
        .and_then(|r| r.get("level"))
        .and_then(|v| v.as_u64())
        .map(|l| match l {
            0..=3 => "low".to_string(),
            4..=7 => "medium".to_string(),
            8..=11 => "high".to_string(),
            _ => "critical".to_string(),
        });

    // IP from agent
    if let Some(ip) = json
        .get("agent")
        .and_then(|a| a.get("ip"))
        .and_then(|v| v.as_str())
    {
        alert.ip_indicators.push(IpIndicator {
            ip: ip.to_string(),
            port: None,
            direction: IpDirection::Source,
            protocol: None,
        });
    }

    // MITRE tags
    if let Some(mitre) = json.get("rule").and_then(|r| r.get("mitre")) {
        if let Some(ids) = mitre.get("id").and_then(|v| v.as_array()) {
            for id in ids {
                if let Some(s) = id.as_str() {
                    alert.mitre_tags.push(s.to_string());
                }
            }
        }
    }

    // Process hints from Windows event data
    if let Some(data) = json.get("data").and_then(|d| d.get("win")) {
        let pid = data
            .get("system")
            .and_then(|s| s.get("processId"))
            .and_then(|v| v.as_u64())
            .map(|p| p as u32);

        let exe_path = data
            .get("system")
            .and_then(|s| s.get("image"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if pid.is_some() || exe_path.is_some() {
            alert.process_hints = Some(ProcessHint {
                pid,
                exe_path,
                exe_hash: None,
                cmdline: None,
                user: None,
            });
        }
    }

    // Store raw summary
    alert.raw_event_summary = Some(
        serde_json::to_string(json)
            .unwrap_or_default()
            .chars()
            .take(500)
            .collect(),
    );

    Some(alert)
}

/// Parse Zeek/Suricata EVE JSON
fn parse_zeek_eve(json: &Value, source_id: &str) -> Option<VendorAlertFact> {
    let ts = json
        .get("ts")
        .or_else(|| json.get("timestamp"))
        .and_then(|v| {
            // Zeek uses epoch float, Suricata uses ISO
            if let Some(epoch) = v.as_f64() {
                DateTime::from_timestamp(epoch as i64, ((epoch.fract()) * 1e9) as u32)
            } else if let Some(s) = v.as_str() {
                DateTime::parse_from_rfc3339(s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            } else {
                None
            }
        })
        .unwrap_or_else(Utc::now);

    let event_id = json
        .get("uid")
        .or_else(|| json.get("flow_id"))
        .and_then(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        });

    let mut alert = VendorAlertFact::new("zeek", source_id, ts);
    alert.original_event_id = event_id;

    // Source IP
    if let Some(orig_h) = json
        .get("id.orig_h")
        .or_else(|| json.get("src_ip"))
        .and_then(|v| v.as_str())
    {
        let port = json
            .get("id.orig_p")
            .or_else(|| json.get("src_port"))
            .and_then(|v| v.as_u64())
            .map(|p| p as u16);

        alert.ip_indicators.push(IpIndicator {
            ip: orig_h.to_string(),
            port,
            direction: IpDirection::Source,
            protocol: json
                .get("proto")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        });
    }

    // Destination IP
    if let Some(resp_h) = json
        .get("id.resp_h")
        .or_else(|| json.get("dest_ip"))
        .and_then(|v| v.as_str())
    {
        let port = json
            .get("id.resp_p")
            .or_else(|| json.get("dest_port"))
            .and_then(|v| v.as_u64())
            .map(|p| p as u16);

        alert.ip_indicators.push(IpIndicator {
            ip: resp_h.to_string(),
            port,
            direction: IpDirection::Destination,
            protocol: json
                .get("proto")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        });
    }

    // DNS query (critical for Zeek enrichment)
    alert.dns_query = json
        .get("query")
        .or_else(|| json.get("dns").and_then(|d| d.get("query")))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Event type as alert name
    alert.alert_name = json
        .get("event_type")
        .or_else(|| json.get("_path"))
        .and_then(|v| v.as_str())
        .map(|s| format!("zeek_{}", s));

    // Store raw summary
    alert.raw_event_summary = Some(
        serde_json::to_string(json)
            .unwrap_or_default()
            .chars()
            .take(500)
            .collect(),
    );

    Some(alert)
}

// ============================================================================
// JSONL File Source (Generic)
// ============================================================================

/// Generic JSONL file source (tail -f style)
pub struct JsonlFileSource {
    path: PathBuf,
    vendor: String,
    source_id: String,
    reader: Option<BufReader<File>>,
    position: u64,
    stats: IngestStats,
}

impl JsonlFileSource {
    pub fn new(path: &Path, vendor: &str, source_id: &str) -> Result<Self, String> {
        Ok(Self {
            path: path.to_path_buf(),
            vendor: vendor.to_string(),
            source_id: source_id.to_string(),
            reader: None,
            position: 0,
            stats: IngestStats::default(),
        })
    }

    fn ensure_reader(&mut self) -> Result<(), String> {
        if self.reader.is_none() && self.path.exists() {
            let file = File::open(&self.path)
                .map_err(|e| format!("Failed to open {}: {}", self.path.display(), e))?;
            let mut reader = BufReader::new(file);

            // Seek to last position
            reader
                .seek(SeekFrom::Start(self.position))
                .map_err(|e| format!("Seek failed: {}", e))?;

            self.reader = Some(reader);
        }
        Ok(())
    }
}

impl IngestSource for JsonlFileSource {
    fn poll(&mut self) -> Result<Vec<VendorAlertFact>, String> {
        self.ensure_reader()?;

        let mut alerts = Vec::new();
        let vendor = self.vendor.clone();
        let source_id = self.source_id.clone();

        if let Some(ref mut reader) = self.reader {
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        self.position += n as u64;
                        self.stats.events_read += 1;

                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        match serde_json::from_str::<Value>(trimmed) {
                            Ok(json) => {
                                self.stats.events_parsed += 1;
                                if let Some(alert) = parse_generic_json(&json, &vendor, &source_id)
                                {
                                    self.stats.facts_created += 1;
                                    alerts.push(alert);
                                }
                            }
                            Err(_) => {
                                self.stats.parse_errors += 1;
                            }
                        }
                    }
                    Err(e) => {
                        return Err(format!("Read error: {}", e));
                    }
                }
            }
        }

        Ok(alerts)
    }

    fn stats(&self) -> IngestStats {
        self.stats.clone()
    }
}

// ============================================================================
// Wazuh Alerts Source
// ============================================================================

/// Wazuh alerts.json source
pub struct WazuhAlertsSource {
    inner: JsonlFileSource,
}

impl WazuhAlertsSource {
    pub fn new(path: &Path) -> Result<Self, String> {
        Ok(Self {
            inner: JsonlFileSource::new(path, "wazuh", "wazuh_alerts")?,
        })
    }
}

impl IngestSource for WazuhAlertsSource {
    fn poll(&mut self) -> Result<Vec<VendorAlertFact>, String> {
        // Use inner source's reader management
        self.inner.ensure_reader()?;

        let mut alerts = Vec::new();
        let source_id = self.inner.source_id.clone();

        if let Some(ref mut reader) = self.inner.reader {
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(n) => {
                        self.inner.position += n as u64;
                        self.inner.stats.events_read += 1;

                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        match serde_json::from_str::<Value>(trimmed) {
                            Ok(json) => {
                                self.inner.stats.events_parsed += 1;
                                if let Some(alert) = parse_wazuh_alert(&json, &source_id) {
                                    self.inner.stats.facts_created += 1;
                                    alerts.push(alert);
                                }
                            }
                            Err(_) => {
                                self.inner.stats.parse_errors += 1;
                            }
                        }
                    }
                    Err(e) => return Err(format!("Read error: {}", e)),
                }
            }
        }

        Ok(alerts)
    }

    fn stats(&self) -> IngestStats {
        self.inner.stats.clone()
    }
}

// ============================================================================
// Zeek EVE JSON Source
// ============================================================================

/// Zeek/Suricata EVE JSON source (conn.log, dns.log, etc.)
pub struct ZeekEveSource {
    inner: JsonlFileSource,
}

impl ZeekEveSource {
    pub fn new(path: &Path) -> Result<Self, String> {
        Ok(Self {
            inner: JsonlFileSource::new(path, "zeek", "zeek_eve")?,
        })
    }
}

impl IngestSource for ZeekEveSource {
    fn poll(&mut self) -> Result<Vec<VendorAlertFact>, String> {
        self.inner.ensure_reader()?;

        let mut alerts = Vec::new();
        let source_id = self.inner.source_id.clone();

        if let Some(ref mut reader) = self.inner.reader {
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(n) => {
                        self.inner.position += n as u64;
                        self.inner.stats.events_read += 1;

                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        match serde_json::from_str::<Value>(trimmed) {
                            Ok(json) => {
                                self.inner.stats.events_parsed += 1;
                                if let Some(alert) = parse_zeek_eve(&json, &source_id) {
                                    self.inner.stats.facts_created += 1;
                                    alerts.push(alert);
                                }
                            }
                            Err(_) => {
                                self.inner.stats.parse_errors += 1;
                            }
                        }
                    }
                    Err(e) => return Err(format!("Read error: {}", e)),
                }
            }
        }

        Ok(alerts)
    }

    fn stats(&self) -> IngestStats {
        self.inner.stats.clone()
    }
}

// ============================================================================
// Syslog UDP Source (Placeholder)
// ============================================================================

/// Syslog UDP source (for CEF/LEEF/plain syslog)
#[allow(dead_code)]
pub struct SyslogUdpSource {
    addr: String,
    vendor: String,
    stats: IngestStats,
    // In production, this would use tokio UDP socket
}

impl SyslogUdpSource {
    pub fn new(addr: &str, vendor: &str) -> Result<Self, String> {
        Ok(Self {
            addr: addr.to_string(),
            vendor: vendor.to_string(),
            stats: IngestStats::default(),
        })
    }
}

impl IngestSource for SyslogUdpSource {
    fn poll(&mut self) -> Result<Vec<VendorAlertFact>, String> {
        // Placeholder - would need async UDP listener
        Ok(Vec::new())
    }

    fn stats(&self) -> IngestStats {
        self.stats.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::config::{IngestSourceConfig, IngestSourceType, JoinStrategy};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_wazuh_alert_parse() {
        let wazuh_json = r#"{"timestamp":"2024-01-01T00:00:00Z","agent":{"name":"host1"},"rule":{"id":"5501","description":"SSH auth failure","level":5,"mitre":{"id":["T1110"]}},"data":{"srcip":"192.168.1.100","dstip":"10.0.0.1"}}"#;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", wazuh_json).unwrap();

        let path = file.path().to_path_buf();
        let mut source = WazuhAlertsSource::new(&path).unwrap();
        let alerts = source.poll().unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].vendor, "wazuh");
        assert_eq!(alerts[0].host_hint, Some("host1".to_string()));
        assert!(alerts[0].mitre_tags.contains(&"T1110".to_string()));
    }

    #[test]
    fn test_zeek_eve_parse() {
        let zeek_json = r#"{"ts":1704067200.0,"uid":"CYrBQ54YlDl66cEhO3","id.orig_h":"192.168.1.1","id.orig_p":54321,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","query":"evil.com"}"#;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", zeek_json).unwrap();

        let path = file.path().to_path_buf();
        let mut source = ZeekEveSource::new(&path).unwrap();
        let alerts = source.poll().unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].vendor, "zeek");
        assert_eq!(alerts[0].dns_query, Some("evil.com".to_string()));
        assert_eq!(alerts[0].ip_indicators.len(), 2);
    }

    #[test]
    fn test_vendor_alert_scope_key_stability() {
        let ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let mut alert = VendorAlertFact::new("wazuh", "alerts", ts);
        alert.host_hint = Some("host1".to_string());
        alert.original_event_id = Some("12345".to_string());

        let key1 = alert.compute_scope_key(5);
        let key2 = alert.compute_scope_key(5);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_ingester_poll() {
        let json1 = r#"{"timestamp":"2024-01-01T00:00:00Z","host":"h1","src_ip":"1.2.3.4"}"#;
        let json2 = r#"{"timestamp":"2024-01-01T00:01:00Z","host":"h2","dst_ip":"5.6.7.8"}"#;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", json1).unwrap();
        writeln!(file, "{}", json2).unwrap();

        let config = IngestSourceConfig {
            source_id: "test".to_string(),
            source_type: IngestSourceType::JsonlFile,
            input_path: Some(file.path().to_path_buf()),
            listen_addr: None,
            vendor: "test".to_string(),
            join_strategy: JoinStrategy::IpTimeWindow,
            join_window_seconds: 300,
            poll_interval_ms: 1000,
        };

        let mut ingester = VendorAlertIngester::new("default_host");
        ingester.add_source_from_config(&config).unwrap();

        let facts = ingester.poll().unwrap();

        assert_eq!(facts.len(), 2);
    }
}

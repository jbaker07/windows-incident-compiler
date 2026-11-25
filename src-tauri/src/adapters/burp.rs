//! Burp Suite adapter: the XML that Burp exports
//!
//! - HTTP history and site map items ("Save items", root `<items>`): one
//!   `http_request` event per item, with the response status, length and MIME
//!   type. Request and response bodies stay in the bundle file, not the event.
//! - Scanner issues ("Report issues" as XML, root `<issues>`): one
//!   `web_vulnerability` event per issue, named like the ZAP adapter's events.

use crate::adapters::{generate_event_id, Adapter, ParseResult};
use crate::import_types::*;
use chrono::{DateTime, NaiveDateTime, Utc};
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;
use std::collections::HashMap;
use std::path::Path;

#[derive(Default)]
pub struct BurpAdapter;

impl BurpAdapter {
    pub fn new() -> Self {
        Self
    }
}

/// Burp writes times as `Mon Jan 01 00:00:05 UTC 2024`, in the zone of the
/// machine that ran it. UTC and GMT are exact, other zone names are kept as
/// an estimate because the offset is not in the file.
fn parse_burp_time(s: &str) -> Option<(DateTime<Utc>, TimestampQuality)> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    let without_zone = format!(
        "{} {} {} {} {}",
        parts[0], parts[1], parts[2], parts[3], parts[5]
    );
    let naive = NaiveDateTime::parse_from_str(&without_zone, "%a %b %d %H:%M:%S %Y").ok()?;
    let quality = if matches!(parts[4], "UTC" | "GMT") {
        TimestampQuality::Precise
    } else {
        TimestampQuality::Estimated
    };
    Some((naive.and_utc(), quality))
}

/// One `<item>` or `<issue>`: text of each child element, and the `ip`
/// attribute of `<host>`
#[derive(Default)]
struct Record {
    values: HashMap<String, String>,
    host_ip: Option<String>,
    index: u64,
}

impl Adapter for BurpAdapter {
    fn name(&self) -> &'static str {
        "burp"
    }

    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::BurpXml)
    }

    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read Burp XML: {}", e))?;
        let mut reader = Reader::from_str(&content);
        reader.config_mut().trim_text(true);

        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;

        let mut export_time: Option<(DateTime<Utc>, TimestampQuality)> = None;
        let mut current: Option<Record> = None;
        let mut child: Option<String> = None;
        let mut items_seen = 0u64;
        let mut issues_seen = 0u64;

        loop {
            let event = reader
                .read_event()
                .map_err(|e| format!("XML error at byte {}: {}", reader.buffer_position(), e))?;
            match event {
                XmlEvent::Start(e) | XmlEvent::Empty(e) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match tag.as_str() {
                        "items" | "issues" => {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"exportTime" {
                                    let v = attr
                                        .unescape_value()
                                        .map(|v| v.into_owned())
                                        .unwrap_or_default();
                                    export_time = parse_burp_time(&v);
                                }
                            }
                        }
                        "item" | "issue" => {
                            let index = if tag == "item" {
                                items_seen
                            } else {
                                issues_seen
                            };
                            current = Some(Record {
                                index,
                                ..Default::default()
                            });
                        }
                        _ => {
                            if let Some(rec) = current.as_mut() {
                                if tag == "host" {
                                    for attr in e.attributes().flatten() {
                                        if attr.key.as_ref() == b"ip" {
                                            rec.host_ip =
                                                attr.unescape_value().ok().map(|v| v.into_owned());
                                        }
                                    }
                                }
                                child = Some(tag);
                            }
                        }
                    }
                }
                XmlEvent::Text(t) => {
                    if let (Some(rec), Some(name)) = (current.as_mut(), child.as_ref()) {
                        let text = t.unescape().map(|v| v.into_owned()).unwrap_or_default();
                        rec.values.entry(name.clone()).or_default().push_str(&text);
                    }
                }
                XmlEvent::CData(c) => {
                    if let (Some(rec), Some(name)) = (current.as_mut(), child.as_ref()) {
                        let text = String::from_utf8_lossy(&c.into_inner()).to_string();
                        rec.values.entry(name.clone()).or_default().push_str(&text);
                    }
                }
                XmlEvent::End(e) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match tag.as_str() {
                        "item" | "issue" => {
                            let Some(rec) = current.take() else { continue };
                            if tag == "item" {
                                items_seen += 1;
                            } else {
                                issues_seen += 1;
                            }
                            if entries_processed >= limits.max_lines_per_file {
                                warnings.push("Event limit reached".to_string());
                                continue;
                            }
                            let event = if tag == "item" {
                                item_event(&rec, file, bundle_id, entries_processed)
                            } else {
                                issue_event(
                                    &rec,
                                    export_time.clone(),
                                    file,
                                    bundle_id,
                                    entries_processed,
                                )
                            };
                            events.push(event);
                            entries_processed += 1;
                        }
                        _ => {
                            if current.is_some() {
                                child = None;
                            }
                        }
                    }
                }
                XmlEvent::Eof => break,
                _ => {}
            }
        }

        if items_seen == 0 && issues_seen == 0 {
            warnings.push("No <item> or <issue> elements, not a Burp export".to_string());
        }

        Ok(ParseResult {
            events,
            warnings,
            entries_processed,
            entries_skipped: 0,
        })
    }
}

fn evidence(file: &ManifestFile, bundle_id: &str, json_path: String) -> ImportEvidencePtr {
    ImportEvidencePtr {
        bundle_id: bundle_id.to_string(),
        rel_path: file.rel_path.clone(),
        line_no: None,
        json_path: Some(json_path),
        byte_offset: None,
    }
}

fn number(s: Option<&String>) -> Option<i64> {
    s.and_then(|v| v.trim().parse().ok())
}

/// HTTP history item as an `http_request` event
fn item_event(rec: &Record, file: &ManifestFile, bundle_id: &str, n: u64) -> ImportEvent {
    let v = &rec.values;
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    for (src, dst) in [
        ("url", "url"),
        ("host", "domain"),
        ("protocol", "protocol"),
        ("method", "method"),
        ("path", "path"),
        ("mimetype", "mime_type"),
        ("comment", "comment"),
    ] {
        if let Some(text) = v
            .get(src)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && *s != "null")
        {
            fields.insert(dst.to_string(), serde_json::json!(text));
        }
    }
    if let Some(port) = number(v.get("port")) {
        fields.insert("port".to_string(), serde_json::json!(port));
    }
    if let Some(status) = number(v.get("status")) {
        fields.insert("status".to_string(), serde_json::json!(status));
    }
    if let Some(len) = number(v.get("responselength")) {
        fields.insert("response_size".to_string(), serde_json::json!(len));
    }
    if let Some(ip) = rec.host_ip.as_deref().filter(|s| !s.is_empty()) {
        fields.insert("server_ip".to_string(), serde_json::json!(ip));
    }
    let (timestamp, timestamp_quality) = v
        .get("time")
        .and_then(|t| parse_burp_time(t))
        .unwrap_or((Utc::now(), TimestampQuality::Unknown));

    let mut tags = vec!["burp".to_string(), "http".to_string(), "web".to_string()];
    if let Some(m) = v.get("method") {
        tags.push(format!("http_{}", m.trim().to_lowercase()));
    }
    ImportEvent {
        event_id: generate_event_id(bundle_id, &file.rel_path, n),
        timestamp,
        timestamp_quality,
        event_type: "http_request".to_string(),
        source_file: file.rel_path.clone(),
        source_line: None,
        fields,
        evidence_ptr: evidence(file, bundle_id, format!("/items/item[{}]", rec.index + 1)),
        tags,
    }
}

/// Scanner issue as a `web_vulnerability` event
fn issue_event(
    rec: &Record,
    export_time: Option<(DateTime<Utc>, TimestampQuality)>,
    file: &ManifestFile,
    bundle_id: &str,
    n: u64,
) -> ImportEvent {
    let v = &rec.values;
    let text = |k: &str| {
        v.get(k)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
    for (src, dst) in [
        ("name", "alert_name"),
        ("host", "site"),
        ("path", "path"),
        ("location", "location"),
        ("severity", "risk_level"),
        ("confidence", "confidence"),
        ("type", "burp_issue_type"),
        ("serialNumber", "serial_number"),
    ] {
        if let Some(t) = text(src) {
            fields.insert(dst.to_string(), serde_json::json!(t));
        }
    }
    if let Some(ip) = rec.host_ip.as_deref().filter(|s| !s.is_empty()) {
        fields.insert("server_ip".to_string(), serde_json::json!(ip));
    }
    // CWE IDs from the classification links, as the ZAP adapter writes them
    if let Some(classes) = text("vulnerabilityClassifications") {
        let mut cwes: Vec<String> = Vec::new();
        let mut rest = classes.as_str();
        while let Some(pos) = rest.find("CWE-") {
            let digits: String = rest[pos + 4..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if !digits.is_empty() {
                let id = format!("CWE-{}", digits);
                if !cwes.contains(&id) {
                    cwes.push(id);
                }
            }
            rest = &rest[pos + 4..];
        }
        if let Some(first) = cwes.first() {
            fields.insert("cwe_id".to_string(), serde_json::json!(first));
            fields.insert("cwe_ids".to_string(), serde_json::json!(cwes));
        }
    }

    // The report time, the nearest thing to a finding time the file has
    let (timestamp, timestamp_quality) = match export_time {
        Some((t, _)) => (t, TimestampQuality::Estimated),
        None => (Utc::now(), TimestampQuality::Unknown),
    };
    let severity = text("severity").unwrap_or_default().to_lowercase();
    let mut tags = vec![
        "burp".to_string(),
        "web_scan".to_string(),
        "vulnerability".to_string(),
    ];
    if matches!(severity.as_str(), "high" | "medium" | "low" | "information") {
        tags.push(format!("{}_risk", severity));
    }
    ImportEvent {
        event_id: generate_event_id(bundle_id, &file.rel_path, n),
        timestamp,
        timestamp_quality,
        event_type: "web_vulnerability".to_string(),
        source_file: file.rel_path.clone(),
        source_line: None,
        fields,
        evidence_ptr: evidence(file, bundle_id, format!("/issues/issue[{}]", rec.index + 1)),
        tags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burp_times_parse() {
        let (t, q) = parse_burp_time("Mon Jan 01 00:00:05 UTC 2024").unwrap();
        assert_eq!(t.to_rfc3339(), "2024-01-01T00:00:05+00:00");
        assert_eq!(q, TimestampQuality::Precise);
        let (_, q) = parse_burp_time("Mon Jan 01 00:00:05 CST 2024").unwrap();
        assert_eq!(q, TimestampQuality::Estimated);
        assert!(parse_burp_time("yesterday").is_none());
    }
}

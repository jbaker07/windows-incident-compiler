//! Nmap XML Adapter - Parse Nmap scan results
//!
//! Parses nmap -oX output and produces canonical events:
//! - host discovered
//! - port open
//! - service banner
//! - script output summary

use crate::adapters::{Adapter, ParseResult, generate_event_id};
use crate::import_types::*;
use std::collections::HashMap;
use std::path::Path;
use std::io::BufReader;
use std::fs::File;
use chrono::{DateTime, Utc, TimeZone};
use quick_xml::Reader;
use quick_xml::events::Event as XmlEvent;

pub struct NmapAdapter;

impl NmapAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for NmapAdapter {
    fn name(&self) -> &'static str {
        "nmap"
    }
    
    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::NmapXml)
    }
    
    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        _limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let f = File::open(file_path)
            .map_err(|e| format!("Failed to open Nmap XML: {}", e))?;
        let reader = BufReader::new(f);
        
        let mut xml_reader = Reader::from_reader(reader);
        xml_reader.trim_text(true);
        
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut buf = Vec::new();
        
        // Parse state
        let mut scan_start: Option<DateTime<Utc>> = None;
        let mut current_host: Option<HostInfo> = None;
        let mut current_port: Option<PortInfo> = None;
        let mut event_index = 0u64;
        
        loop {
            match xml_reader.read_event_into(&mut buf) {
                Ok(XmlEvent::Start(ref e)) | Ok(XmlEvent::Empty(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let attrs = parse_attrs(e);
                    
                    match tag.as_str() {
                        "nmaprun" => {
                            // Extract scan start time
                            if let Some(start) = attrs.get("start") {
                                if let Ok(ts) = start.parse::<i64>() {
                                    scan_start = Utc.timestamp_opt(ts, 0).single();
                                }
                            }
                        }
                        "host" => {
                            current_host = Some(HostInfo::default());
                        }
                        "address" => {
                            if let Some(ref mut host) = current_host {
                                let addr_type = attrs.get("addrtype").map(|s| s.as_str()).unwrap_or("");
                                let addr = attrs.get("addr").cloned().unwrap_or_default();
                                
                                match addr_type {
                                    "ipv4" | "ipv6" => host.ip = Some(addr),
                                    "mac" => host.mac = Some(addr),
                                    _ => {}
                                }
                            }
                        }
                        "hostname" => {
                            if let Some(ref mut host) = current_host {
                                if let Some(name) = attrs.get("name") {
                                    host.hostnames.push(name.clone());
                                }
                            }
                        }
                        "status" => {
                            if let Some(ref mut host) = current_host {
                                host.status = attrs.get("state").cloned().unwrap_or_default();
                            }
                        }
                        "port" => {
                            let portid = attrs.get("portid")
                                .and_then(|p| p.parse::<u16>().ok())
                                .unwrap_or(0);
                            let protocol = attrs.get("protocol").cloned().unwrap_or_default();
                            
                            current_port = Some(PortInfo {
                                port: portid,
                                protocol,
                                state: String::new(),
                                service: String::new(),
                                version: String::new(),
                                scripts: Vec::new(),
                            });
                        }
                        "state" => {
                            if let Some(ref mut port) = current_port {
                                port.state = attrs.get("state").cloned().unwrap_or_default();
                            }
                        }
                        "service" => {
                            if let Some(ref mut port) = current_port {
                                port.service = attrs.get("name").cloned().unwrap_or_default();
                                
                                // Build version string
                                let product = attrs.get("product").cloned().unwrap_or_default();
                                let version = attrs.get("version").cloned().unwrap_or_default();
                                let extra = attrs.get("extrainfo").cloned().unwrap_or_default();
                                
                                let version_parts: Vec<&str> = [
                                    product.as_str(),
                                    version.as_str(),
                                    extra.as_str(),
                                ].iter().filter(|s| !s.is_empty()).copied().collect();
                                
                                port.version = version_parts.join(" ");
                            }
                        }
                        "script" => {
                            if let Some(ref mut port) = current_port {
                                let id = attrs.get("id").cloned().unwrap_or_default();
                                let output = attrs.get("output").cloned().unwrap_or_default();
                                if !id.is_empty() {
                                    port.scripts.push((id, output));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(XmlEvent::End(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    
                    match tag.as_str() {
                        "host" => {
                            if let Some(host) = current_host.take() {
                                // Emit host discovered event
                                let timestamp = scan_start.unwrap_or_else(Utc::now);
                                
                                let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
                                if let Some(ref ip) = host.ip {
                                    fields.insert("ip".to_string(), serde_json::json!(ip));
                                }
                                if let Some(ref mac) = host.mac {
                                    fields.insert("mac".to_string(), serde_json::json!(mac));
                                }
                                if !host.hostnames.is_empty() {
                                    fields.insert("hostnames".to_string(), serde_json::json!(host.hostnames));
                                }
                                fields.insert("status".to_string(), serde_json::json!(host.status));
                                fields.insert("ports_count".to_string(), serde_json::json!(host.ports.len()));
                                
                                let ip_display = host.ip.as_deref().unwrap_or("unknown");
                                
                                events.push(ImportEvent {
                                    event_id: generate_event_id(bundle_id, &file.rel_path, event_index),
                                    timestamp,
                                    timestamp_quality: if scan_start.is_some() {
                                        TimestampQuality::Precise
                                    } else {
                                        TimestampQuality::Unknown
                                    },
                                    event_type: "host_discovered".to_string(),
                                    source_file: file.rel_path.clone(),
                                    source_line: None,
                                    fields: fields.clone(),
                                    evidence_ptr: ImportEvidencePtr {
                                        bundle_id: bundle_id.to_string(),
                                        rel_path: file.rel_path.clone(),
                                        line_no: None,
                                        json_path: Some(format!("//host[address/@addr='{}']", ip_display)),
                                        byte_offset: None,
                                    },
                                    tags: vec!["nmap".to_string(), "recon".to_string(), "host_discovery".to_string()],
                                });
                                event_index += 1;
                                
                                // Emit port events
                                for port_info in &host.ports {
                                    let mut port_fields: HashMap<String, serde_json::Value> = HashMap::new();
                                    port_fields.insert("ip".to_string(), serde_json::json!(ip_display));
                                    port_fields.insert("port".to_string(), serde_json::json!(port_info.port));
                                    port_fields.insert("protocol".to_string(), serde_json::json!(port_info.protocol));
                                    port_fields.insert("state".to_string(), serde_json::json!(port_info.state));
                                    port_fields.insert("service".to_string(), serde_json::json!(port_info.service));
                                    if !port_info.version.is_empty() {
                                        port_fields.insert("version".to_string(), serde_json::json!(port_info.version));
                                    }
                                    
                                    let mut tags = vec!["nmap".to_string(), "recon".to_string(), "port_scan".to_string()];
                                    
                                    // Add service-specific tags
                                    match port_info.service.as_str() {
                                        "http" | "https" | "http-proxy" => tags.push("web".to_string()),
                                        "ssh" => tags.push("ssh".to_string()),
                                        "ftp" => tags.push("ftp".to_string()),
                                        "smb" | "microsoft-ds" | "netbios-ssn" => tags.push("smb".to_string()),
                                        "rdp" | "ms-wbt-server" => tags.push("rdp".to_string()),
                                        "mysql" | "postgresql" | "mssql" | "oracle" => tags.push("database".to_string()),
                                        _ => {}
                                    }
                                    
                                    if port_info.state == "open" {
                                        tags.push("open_port".to_string());
                                    }
                                    
                                    events.push(ImportEvent {
                                        event_id: generate_event_id(bundle_id, &file.rel_path, event_index),
                                        timestamp,
                                        timestamp_quality: if scan_start.is_some() {
                                            TimestampQuality::Precise
                                        } else {
                                            TimestampQuality::Unknown
                                        },
                                        event_type: "port_discovered".to_string(),
                                        source_file: file.rel_path.clone(),
                                        source_line: None,
                                        fields: port_fields,
                                        evidence_ptr: ImportEvidencePtr {
                                            bundle_id: bundle_id.to_string(),
                                            rel_path: file.rel_path.clone(),
                                            line_no: None,
                                            json_path: Some(format!(
                                                "//host[address/@addr='{}']/ports/port[@portid='{}']",
                                                ip_display, port_info.port
                                            )),
                                            byte_offset: None,
                                        },
                                        tags,
                                    });
                                    event_index += 1;
                                    
                                    // Emit script output events
                                    for (script_id, output) in &port_info.scripts {
                                        let mut script_fields: HashMap<String, serde_json::Value> = HashMap::new();
                                        script_fields.insert("ip".to_string(), serde_json::json!(ip_display));
                                        script_fields.insert("port".to_string(), serde_json::json!(port_info.port));
                                        script_fields.insert("script_id".to_string(), serde_json::json!(script_id));
                                        script_fields.insert("output".to_string(), serde_json::json!(output));
                                        
                                        events.push(ImportEvent {
                                            event_id: generate_event_id(bundle_id, &file.rel_path, event_index),
                                            timestamp,
                                            timestamp_quality: if scan_start.is_some() {
                                                TimestampQuality::Precise
                                            } else {
                                                TimestampQuality::Unknown
                                            },
                                            event_type: "nmap_script".to_string(),
                                            source_file: file.rel_path.clone(),
                                            source_line: None,
                                            fields: script_fields,
                                            evidence_ptr: ImportEvidencePtr {
                                                bundle_id: bundle_id.to_string(),
                                                rel_path: file.rel_path.clone(),
                                                line_no: None,
                                                json_path: Some(format!(
                                                    "//host[address/@addr='{}']/ports/port[@portid='{}']/script[@id='{}']",
                                                    ip_display, port_info.port, script_id
                                                )),
                                                byte_offset: None,
                                            },
                                            tags: vec!["nmap".to_string(), "nse_script".to_string(), script_id.clone()],
                                        });
                                        event_index += 1;
                                    }
                                }
                            }
                        }
                        "port" => {
                            if let (Some(ref mut host), Some(port)) = (&mut current_host, current_port.take()) {
                                host.ports.push(port);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(XmlEvent::Eof) => break,
                Err(e) => {
                    warnings.push(format!("XML parse error: {}", e));
                    break;
                }
                _ => {}
            }
            buf.clear();
        }
        
        Ok(ParseResult {
            events,
            warnings,
            entries_processed: event_index,
            entries_skipped: 0,
        })
    }
}

#[derive(Default)]
struct HostInfo {
    ip: Option<String>,
    mac: Option<String>,
    hostnames: Vec<String>,
    status: String,
    ports: Vec<PortInfo>,
}

struct PortInfo {
    port: u16,
    protocol: String,
    state: String,
    service: String,
    version: String,
    scripts: Vec<(String, String)>,
}

fn parse_attrs(e: &quick_xml::events::BytesStart) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    for attr in e.attributes().filter_map(Result::ok) {
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        let value = String::from_utf8_lossy(&attr.value).to_string();
        attrs.insert(key, value);
    }
    attrs
}

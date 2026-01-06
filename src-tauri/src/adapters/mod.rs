//! Adapter Framework - Parse imported files into canonical events
//!
//! This module provides a pluggable adapter system for parsing various file formats
//! (JSONL, HAR, Zeek logs, etc.) into a common ImportEvent structure.
//!
//! ## Supported Formats
//! 
//! ### Network & Web
//! - **JSONL** - Generic JSON lines (Elastic, Splunk exports)
//! - **HAR** - HTTP Archive (browser dev tools, Burp, ZAP)
//! - **Zeek** - Zeek/Bro TSV logs (conn, dns, http, ssl, etc.)
//! - **Suricata** - EVE JSON (alerts, dns, http, flow)
//! - **Nmap** - XML scan results
//! - **OWASP ZAP** - JSON scan reports
//!
//! ### Endpoint
//! - **osquery** - Query result JSON
//! - **Velociraptor** - Hunt/collection exports (JSON/CSV)
//! - **EVTX JSON** - Windows Event Logs (via evtx_dump)
//! - **PowerShell Transcript** - PS session recordings
//!
//! ### Threat Detection
//! - **YARA** - Scan results (JSON and text)
//! - **Atomic Red Team** - Test execution logs
//!
//! ### Plaintext & Recon
//! - **Shell History** - bash_history, zsh_history
//! - **Gobuster** - Directory enumeration output
//! - **ffuf** - Fuzzing results (JSON and text)

pub mod jsonl;
pub mod har;
pub mod zeek;
pub mod nmap;
pub mod suricata;
pub mod osquery;
pub mod velociraptor;
pub mod yara;
pub mod zap;
pub mod evtx_json;
pub mod atomic;
pub mod plaintext;

use crate::import_types::*;
use std::path::Path;

// ============================================================================
// ADAPTER TRAIT
// ============================================================================

/// Adapter trait for parsing imported files
pub trait Adapter: Send + Sync {
    /// Adapter name for logging/manifest
    fn name(&self) -> &'static str;
    
    /// Check if this adapter can handle the given file
    fn can_handle(&self, file: &ManifestFile) -> bool;
    
    /// Parse the file and return events
    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String>;
}

/// Result of parsing a file
#[derive(Debug, Clone)]
pub struct ParseResult {
    /// Events extracted from the file
    pub events: Vec<ImportEvent>,
    /// Warnings during parsing
    pub warnings: Vec<String>,
    /// Number of lines/entries processed
    pub entries_processed: u64,
    /// Number of lines/entries skipped
    pub entries_skipped: u64,
}

impl ParseResult {
    pub fn empty() -> Self {
        Self {
            events: Vec::new(),
            warnings: Vec::new(),
            entries_processed: 0,
            entries_skipped: 0,
        }
    }
}

// ============================================================================
// ADAPTER REGISTRY
// ============================================================================

/// Registry of all available adapters
pub struct AdapterRegistry {
    adapters: Vec<Box<dyn Adapter>>,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AdapterRegistry {
    /// Create a new registry with all built-in adapters
    pub fn new() -> Self {
        Self {
            adapters: vec![
                // Core adapters
                Box::new(jsonl::JsonlAdapter::new()),
                Box::new(har::HarAdapter::new()),
                Box::new(zeek::ZeekAdapter::new()),
                
                // Network & security tools
                Box::new(nmap::NmapAdapter::new()),
                Box::new(suricata::SuricataAdapter::new()),
                Box::new(zap::ZapAdapter::new()),
                
                // Endpoint tools
                Box::new(osquery::OsqueryAdapter::new()),
                Box::new(velociraptor::VelociraptorAdapter::new()),
                Box::new(evtx_json::EvtxJsonAdapter::new()),
                
                // Threat detection
                Box::new(yara::YaraAdapter::new()),
                Box::new(atomic::AtomicAdapter::new()),
                
                // Plaintext & recon (handles multiple types)
                Box::new(plaintext::PlaintextAdapter::new()),
            ],
        }
    }
    
    /// Find adapter that can handle a file
    pub fn find_adapter(&self, file: &ManifestFile) -> Option<&dyn Adapter> {
        self.adapters.iter()
            .find(|a| a.can_handle(file))
            .map(|a| a.as_ref())
    }
    
    /// Parse all files in a manifest
    pub fn parse_manifest(
        &self,
        manifest: &mut ImportManifest,
        files_dir: &Path,
    ) -> Result<Vec<ImportEvent>, String> {
        let mut all_events = Vec::new();
        let limits = manifest.limits.clone();
        
        for file in &mut manifest.files {
            if !file.kind.is_parseable() {
                continue;
            }
            
            if let Some(adapter) = self.find_adapter(file) {
                let file_path = files_dir.join(&file.rel_path);
                
                match adapter.parse(file, &file_path, &manifest.bundle_id, &limits) {
                    Ok(result) => {
                        file.parsed = true;
                        file.parser = Some(adapter.name().to_string());
                        file.warnings = result.warnings;
                        file.events_extracted = Some(result.events.len() as u64);
                        
                        all_events.extend(result.events);
                    }
                    Err(e) => {
                        file.parsed = false;
                        file.warnings.push(format!("Parse error: {}", e));
                    }
                }
            }
        }
        
        // Update manifest summary
        manifest.summary.parsed_files = manifest.files.iter().filter(|f| f.parsed).count() as u64;
        manifest.summary.events_extracted = all_events.len() as u64;
        
        Ok(all_events)
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Generate a unique event ID
pub fn generate_event_id(bundle_id: &str, file_path: &str, index: u64) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bundle_id.hash(&mut hasher);
    file_path.hash(&mut hasher);
    index.hash(&mut hasher);
    format!("evt_{:016x}", hasher.finish())
}

/// Parse a timestamp string with multiple format attempts
pub fn parse_timestamp(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{DateTime, NaiveDateTime, Utc, TimeZone};
    
    // Try RFC3339 first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    
    // Try ISO 8601 without timezone
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(Utc.from_utc_datetime(&naive));
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(Utc.from_utc_datetime(&naive));
    }
    
    // Try common formats
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return Some(Utc.from_utc_datetime(&naive));
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(Utc.from_utc_datetime(&naive));
    }
    
    // Try Unix timestamp (seconds or milliseconds)
    if let Ok(ts) = s.parse::<i64>() {
        if ts > 1_000_000_000_000 {
            // Milliseconds
            return Utc.timestamp_millis_opt(ts).single();
        } else {
            // Seconds
            return Utc.timestamp_opt(ts, 0).single();
        }
    }
    
    // Try Unix timestamp as float
    if let Ok(ts) = s.parse::<f64>() {
        let secs = ts.trunc() as i64;
        let nanos = ((ts.fract()) * 1_000_000_000.0) as u32;
        return Utc.timestamp_opt(secs, nanos).single();
    }
    
    None
}

/// Extract timestamp from a JSON value
pub fn extract_timestamp(
    value: &serde_json::Value,
    fields: &[&str],
) -> (chrono::DateTime<chrono::Utc>, TimestampQuality) {
    for field in fields {
        if let Some(ts_value) = value.get(*field) {
            if let Some(s) = ts_value.as_str() {
                if let Some(dt) = parse_timestamp(s) {
                    return (dt, TimestampQuality::Precise);
                }
            }
            if let Some(n) = ts_value.as_i64() {
                if let Some(dt) = parse_timestamp(&n.to_string()) {
                    return (dt, TimestampQuality::Precise);
                }
            }
            if let Some(n) = ts_value.as_f64() {
                if let Some(dt) = parse_timestamp(&n.to_string()) {
                    return (dt, TimestampQuality::Precise);
                }
            }
        }
    }
    
    // No timestamp found, use now
    (chrono::Utc::now(), TimestampQuality::Unknown)
}

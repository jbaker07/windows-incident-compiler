// windows/sensors/evtx_collector.rs
// EVTX event log collection - reads Windows Event Logs
// On Windows: uses EvtOpenLog, EvtQuery, EvtNext APIs
// Cross-platform: provides stub for compilation

use serde::{Deserialize, Serialize};

/// Represents a parsed Windows Event Log record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvtxRecord {
    pub event_id: u32,
    pub level: String,
    pub provider: String,
    pub message: String,
}

impl EvtxRecord {
    pub fn new(event_id: u32, level: &str, provider: &str, message: &str) -> Self {
        Self {
            event_id,
            level: level.to_string(),
            provider: provider.to_string(),
            message: message.to_string(),
        }
    }
}

/// Windows Event Log collector
/// Provides access to Windows Event Logs (Security, System, Sysmon, etc.)
#[derive(Debug)]
pub struct EvtxCollector {
    /// List of log channels to poll
    channels: Vec<String>,
    /// Bookmark positions for each channel (event record ID)
    bookmarks: std::collections::HashMap<String, u64>,
}

impl Default for EvtxCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl EvtxCollector {
    pub fn new() -> Self {
        Self {
            channels: Self::default_channels(),
            bookmarks: std::collections::HashMap::new(),
        }
    }

    /// Create with specific channels
    pub fn with_channels(channels: Vec<String>) -> Self {
        Self {
            channels,
            bookmarks: std::collections::HashMap::new(),
        }
    }

    fn default_channels() -> Vec<String> {
        vec![
            "Microsoft-Windows-Sysmon/Operational".to_string(),
            "Security".to_string(),
            "System".to_string(),
            "Microsoft-Windows-PowerShell/Operational".to_string(),
            "Microsoft-Windows-Windows Defender/Operational".to_string(),
            "Microsoft-Windows-WMI-Activity/Operational".to_string(),
            "Microsoft-Windows-TaskScheduler/Operational".to_string(),
        ]
    }

    /// Returns list of enabled log channels
    pub fn enabled_logs(&self) -> Vec<&str> {
        self.channels.iter().map(|s| s.as_str()).collect()
    }

    /// Poll a specific log channel for new events
    #[cfg(target_os = "windows")]
    pub fn poll(&mut self, log: &str) -> anyhow::Result<Vec<EvtxRecord>> {
        // Windows implementation would use:
        // - EvtOpenLog to open the channel
        // - EvtQuery with bookmark to get new events
        // - EvtNext to iterate results
        // - EvtRender to get event XML
        // For now, return empty (real impl requires windows-rs bindings)
        let _ = log;
        Ok(vec![])
    }

    #[cfg(not(target_os = "windows"))]
    pub fn poll(&mut self, log: &str) -> anyhow::Result<Vec<EvtxRecord>> {
        // Non-Windows: no event logs available
        let _ = log;
        Ok(vec![])
    }

    /// Poll all configured channels
    pub fn poll_all(&mut self) -> anyhow::Result<Vec<EvtxRecord>> {
        let mut all_records = Vec::new();
        let channels = self.channels.clone();

        for channel in &channels {
            match self.poll(channel) {
                Ok(records) => all_records.extend(records),
                Err(e) => {
                    // Log error but continue with other channels
                    eprintln!("Error polling {}: {}", channel, e);
                }
            }
        }

        Ok(all_records)
    }

    /// Update bookmark for a channel after processing
    pub fn set_bookmark(&mut self, channel: &str, record_id: u64) {
        self.bookmarks.insert(channel.to_string(), record_id);
    }

    /// Get current bookmark for a channel
    pub fn get_bookmark(&self, channel: &str) -> Option<u64> {
        self.bookmarks.get(channel).copied()
    }

    /// Parse event XML into EvtxRecord (helper for Windows impl)
    #[allow(dead_code)]
    fn parse_event_xml(xml: &str) -> Option<EvtxRecord> {
        // Simplified XML parsing - real impl would use proper XML parser
        let event_id = Self::extract_xml_value(xml, "EventID")?;
        let level = Self::extract_xml_value(xml, "Level").unwrap_or_else(|| "0".to_string());
        let provider = Self::extract_xml_value(xml, "Provider Name").unwrap_or_default();

        // Convert level number to string
        let level_str = match level.as_str() {
            "0" => "LogAlways",
            "1" => "Critical",
            "2" => "Error",
            "3" => "Warning",
            "4" => "Information",
            "5" => "Verbose",
            _ => "Unknown",
        };

        Some(EvtxRecord {
            event_id: event_id.parse().ok()?,
            level: level_str.to_string(),
            provider,
            message: xml.to_string(), // Store full XML as message
        })
    }

    fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
        let start_tag = format!("<{}", tag);
        let start = xml.find(&start_tag)?;
        let after_tag = &xml[start..];
        let content_start = after_tag.find('>')? + 1;
        let end_tag = format!("</{}", tag.split_whitespace().next()?);
        let content_end = after_tag.find(&end_tag)?;
        Some(after_tag[content_start..content_end].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evtx_collector_new() {
        let collector = EvtxCollector::new();
        assert!(!collector.enabled_logs().is_empty());
        assert!(collector
            .enabled_logs()
            .iter()
            .any(|l| l.contains("Sysmon")));
    }

    #[test]
    fn test_evtx_record_creation() {
        let record = EvtxRecord::new(
            4688,
            "Information",
            "Microsoft-Windows-Security-Auditing",
            "A new process has been created.",
        );
        assert_eq!(record.event_id, 4688);
        assert_eq!(record.level, "Information");
    }

    #[test]
    fn test_bookmark_management() {
        let mut collector = EvtxCollector::new();
        assert!(collector.get_bookmark("Security").is_none());

        collector.set_bookmark("Security", 12345);
        assert_eq!(collector.get_bookmark("Security"), Some(12345));
    }

    #[test]
    fn test_poll_returns_empty_on_non_windows() {
        let mut collector = EvtxCollector::new();
        let result = collector.poll("Security");
        assert!(result.is_ok());
        // On non-Windows, should return empty
        #[cfg(not(target_os = "windows"))]
        assert!(result.unwrap().is_empty());
    }
}

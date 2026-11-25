//! YAML and CSV adapters: generic structured records
//!
//! Each YAML document, each item of a top level YAML list, and each CSV row
//! becomes one event, built the same way as a JSON record (see `jsonl`):
//! nested fields flattened to dotted names, the event type taken from the
//! record (`event_type`, `type`, `action` and similar), and process, user,
//! host and address entities named once. CSV files written by Invoke-AtomicTest
//! or Velociraptor are recognized by name and go to those adapters instead.

use crate::adapters::jsonl::JsonlAdapter;
use crate::adapters::{Adapter, ParseResult};
use crate::import_types::*;
use serde::Deserialize;
use std::path::Path;

/// YAML files (`.yaml`, `.yml`), one or more documents
#[derive(Default)]
pub struct YamlAdapter;

impl YamlAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for YamlAdapter {
    fn name(&self) -> &'static str {
        "yaml"
    }

    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::Yaml)
    }

    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read YAML file: {}", e))?;
        let records = JsonlAdapter::new();

        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let mut entries_skipped = 0u64;

        for (doc_idx, document) in serde_yaml::Deserializer::from_str(&content).enumerate() {
            let value = match serde_yaml::Value::deserialize(document) {
                Ok(v) => v,
                Err(e) => {
                    warnings.push(format!("Document {}: {}", doc_idx + 1, e));
                    entries_skipped += 1;
                    continue;
                }
            };
            let json = match serde_json::to_value(&value) {
                Ok(j) => j,
                Err(e) => {
                    warnings.push(format!(
                        "Document {}: not representable as JSON: {}",
                        doc_idx + 1,
                        e
                    ));
                    entries_skipped += 1;
                    continue;
                }
            };

            // A top level list of mappings is a list of records, as in
            // exported alert or inventory files
            let items: Vec<(serde_json::Value, String)> = match json {
                serde_json::Value::Array(list) => list
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| (v, format!("doc[{}][{}]", doc_idx, i)))
                    .collect(),
                serde_json::Value::Null => Vec::new(),
                other => vec![(other, format!("doc[{}]", doc_idx))],
            };

            for (item, path) in items {
                if entries_processed >= limits.max_lines_per_file {
                    warnings.push("Event limit reached".to_string());
                    break;
                }
                match records.record_to_event(
                    &item,
                    file,
                    bundle_id,
                    entries_processed,
                    None,
                    Some(path),
                ) {
                    Some(event) => {
                        events.push(event);
                        entries_processed += 1;
                    }
                    None => entries_skipped += 1, // a scalar, not a record
                }
            }
        }

        Ok(ParseResult {
            events,
            warnings,
            entries_processed,
            entries_skipped,
        })
    }
}

/// CSV files with a header row
#[derive(Default)]
pub struct CsvAdapter;

impl CsvAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for CsvAdapter {
    fn name(&self) -> &'static str {
        "csv"
    }

    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::Csv)
    }

    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let mut rdr = csv::ReaderBuilder::new()
            .flexible(true)
            .from_path(file_path)
            .map_err(|e| format!("Failed to open CSV: {}", e))?;
        let headers: Vec<String> = rdr
            .headers()
            .map_err(|e| format!("Failed to read CSV header: {}", e))?
            .iter()
            .map(|h| h.trim().trim_start_matches('\u{feff}').to_string())
            .collect();
        let records = JsonlAdapter::new();

        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;
        let mut entries_skipped = 0u64;

        for (idx, row) in rdr.records().enumerate() {
            if entries_processed >= limits.max_lines_per_file {
                warnings.push("Event limit reached".to_string());
                break;
            }
            let row = match row {
                Ok(r) => r,
                Err(e) => {
                    warnings.push(format!("Row {}: {}", idx + 2, e));
                    entries_skipped += 1;
                    continue;
                }
            };
            if row.len() != headers.len() {
                warnings.push(format!(
                    "Row {}: {} values for {} columns",
                    idx + 2,
                    row.len(),
                    headers.len()
                ));
            }

            let mut obj = serde_json::Map::new();
            for (header, value) in headers.iter().zip(row.iter()) {
                let value = value.trim();
                if header.is_empty() || value.is_empty() {
                    continue;
                }
                obj.insert(header.clone(), csv_value(value));
            }

            let line_no = row.position().map(|p| p.line()).unwrap_or(idx as u64 + 2);
            match records.record_to_event(
                &serde_json::Value::Object(obj),
                file,
                bundle_id,
                entries_processed,
                Some(line_no),
                None,
            ) {
                Some(event) => {
                    events.push(event);
                    entries_processed += 1;
                }
                None => entries_skipped += 1,
            }
        }

        Ok(ParseResult {
            events,
            warnings,
            entries_processed,
            entries_skipped,
        })
    }
}

/// Numbers and booleans as such, everything else as text
fn csv_value(value: &str) -> serde_json::Value {
    if let Ok(n) = value.parse::<i64>() {
        return serde_json::json!(n);
    }
    if let Ok(f) = value.parse::<f64>() {
        if f.is_finite() {
            return serde_json::json!(f);
        }
    }
    match value.to_ascii_lowercase().as_str() {
        "true" => serde_json::json!(true),
        "false" => serde_json::json!(false),
        _ => serde_json::json!(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_values_are_typed() {
        assert_eq!(csv_value("443"), serde_json::json!(443));
        assert_eq!(csv_value("1.5"), serde_json::json!(1.5));
        assert_eq!(csv_value("TRUE"), serde_json::json!(true));
        assert_eq!(csv_value("10.0.0.5"), serde_json::json!("10.0.0.5"));
    }
}

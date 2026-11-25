//! Atomic Red Team Adapter - Parse Atomic test execution outputs
//!
//! Parses outputs from Atomic Red Team test executions:
//! - the Invoke-AtomicTest execution log (the default CSV logger)
//! - JSON records with a technique ID (flat or {"technique": {"id": ...}})
//! - text logs that mention technique IDs
//!
//! Technique names and tactics follow ATT&CK v20.1.

use crate::adapters::{generate_event_id, Adapter, ParseResult};
use crate::import_types::*;
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Default)]
pub struct AtomicAdapter;

impl AtomicAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for AtomicAdapter {
    fn name(&self) -> &'static str {
        "atomic"
    }

    fn can_handle(&self, file: &ManifestFile) -> bool {
        matches!(file.kind, FileKind::AtomicOutput)
    }

    fn parse(
        &self,
        file: &ManifestFile,
        file_path: &Path,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read Atomic file: {}", e))?;

        // Try JSON first
        if content.trim().starts_with('{') || content.trim().starts_with('[') {
            return self.parse_json(file, &content, bundle_id, limits);
        }

        // The Invoke-AtomicTest CSV execution log
        let header = content.lines().next().unwrap_or("");
        if header.contains("Technique") && header.contains("Test Name") && header.contains(',') {
            return self.parse_execution_log_csv(file, &content, bundle_id, limits);
        }

        // Fall back to text parsing
        self.parse_text(file, &content, bundle_id, limits)
    }
}

impl AtomicAdapter {
    fn parse_json(
        &self,
        file: &ManifestFile,
        content: &str,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;

        let records: Vec<serde_json::Value> = if content.trim().starts_with('[') {
            serde_json::from_str(content)
                .map_err(|e| format!("Failed to parse JSON array: {}", e))?
        } else {
            // Single object or line-delimited
            let reader = BufReader::new(content.as_bytes());
            let mut results = Vec::new();
            for line in reader.lines().map_while(Result::ok) {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                    results.push(val);
                }
            }
            if results.is_empty() {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
                    results.push(val);
                }
            }
            results
        };

        for (idx, record) in records.iter().enumerate() {
            if entries_processed >= limits.max_lines_per_file {
                warnings.push("Event limit reached".to_string());
                break;
            }

            // Extract Atomic test information
            let technique_id = record
                .get("Technique")
                .or_else(|| record.get("technique_id"))
                .or_else(|| record.get("attack_technique"))
                .or_else(|| record.get("technique"))
                .and_then(|v| {
                    v.as_str()
                        .or_else(|| v.get("id").and_then(|id| id.as_str()))
                })
                .unwrap_or("");

            let test_name = record
                .get("TestName")
                .or_else(|| record.get("test_name"))
                .or_else(|| record.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // TestNumber is a number in Invoke-AtomicTest output and a string elsewhere
            let test_number: String = record
                .get("TestNumber")
                .or_else(|| record.get("test_number"))
                .or_else(|| record.get("auto_generated_guid"))
                .and_then(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .or_else(|| v.as_u64().map(|n| n.to_string()))
                })
                .unwrap_or_default();

            let hostname = record
                .get("Hostname")
                .or_else(|| record.get("hostname"))
                .or_else(|| record.get("host"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let execution_time = record
                .get("ExecutionTime")
                .or_else(|| record.get("execution_time"))
                .or_else(|| record.get("timestamp"))
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);

            let exit_code = record
                .get("ExitCode")
                .or_else(|| record.get("exit_code"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);

            let output = record
                .get("Output")
                .or_else(|| record.get("output"))
                .or_else(|| record.get("stdout"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let error_output = record
                .get("ErrorOutput")
                .or_else(|| record.get("error_output"))
                .or_else(|| record.get("stderr"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            fields.insert("technique_id".to_string(), serde_json::json!(technique_id));
            fields.insert("test_name".to_string(), serde_json::json!(test_name));
            if !test_number.is_empty() {
                fields.insert("test_number".to_string(), serde_json::json!(test_number));
            }
            if !hostname.is_empty() {
                fields.insert("hostname".to_string(), serde_json::json!(hostname));
            }
            fields.insert("exit_code".to_string(), serde_json::json!(exit_code));
            if !output.is_empty() {
                // Truncate long output
                let truncated = if output.len() > 2000 {
                    format!("{}...[truncated]", &output[..2000])
                } else {
                    output.to_string()
                };
                fields.insert("output".to_string(), serde_json::json!(truncated));
            }
            if !error_output.is_empty() {
                let truncated = if error_output.len() > 1000 {
                    format!("{}...[truncated]", &error_output[..1000])
                } else {
                    error_output.to_string()
                };
                fields.insert("error_output".to_string(), serde_json::json!(truncated));
            }

            let success = exit_code == 0;
            fields.insert("success".to_string(), serde_json::json!(success));

            // Map technique to MITRE ATT&CK
            let mitre_info = map_technique_id(technique_id);
            if let Some(info) = &mitre_info {
                insert_technique_fields(&mut fields, info);
            }

            let mut tags = vec![
                "atomic".to_string(),
                "red_team".to_string(),
                "attack_simulation".to_string(),
            ];

            if !technique_id.is_empty() {
                tags.push(technique_id.to_string());
            }

            if let Some(info) = &mitre_info {
                for tactic in info.tactics {
                    tags.push(tactic.to_lowercase().replace(' ', "_"));
                }
            }

            if success {
                tags.push("test_success".to_string());
            } else {
                tags.push("test_failed".to_string());
            }

            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp: execution_time,
                timestamp_quality: TimestampQuality::Precise,
                event_type: "technique_executed".to_string(),
                source_file: file.rel_path.clone(),
                source_line: None,
                fields,
                evidence_ptr: ImportEvidencePtr {
                    bundle_id: bundle_id.to_string(),
                    rel_path: file.rel_path.clone(),
                    line_no: None,
                    json_path: Some(format!("[{}]", idx)),
                    byte_offset: None,
                },
                tags,
            });

            entries_processed += 1;
        }

        Ok(ParseResult {
            events,
            warnings,
            entries_processed,
            entries_skipped: 0,
        })
    }

    /// The CSV log Invoke-AtomicTest writes by default, one row per test run:
    /// "Execution Time (UTC)","Execution Time (Local)","Technique","Test Number",
    /// "Test Name","Hostname","IP Address","Username","GUID","ProcessId","ExitCode"
    fn parse_execution_log_csv(
        &self,
        file: &ManifestFile,
        content: &str,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let mut rdr = csv::Reader::from_reader(content.as_bytes());
        let headers: Vec<String> = rdr
            .headers()
            .map_err(|e| format!("Failed to read CSV header: {}", e))?
            .iter()
            .map(|h| h.trim().to_string())
            .collect();

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
            let col = |name: &str| -> Option<&str> {
                headers
                    .iter()
                    .position(|h| h == name)
                    .and_then(|i| row.get(i))
                    .map(|v| v.trim())
                    .filter(|v| !v.is_empty())
            };

            let technique_id = col("Technique").unwrap_or("").to_uppercase();
            let ts = col("Execution Time (UTC)").and_then(crate::adapters::parse_timestamp);
            let exit_code = col("ExitCode").and_then(|v| v.parse::<i64>().ok());

            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            fields.insert("technique_id".to_string(), serde_json::json!(technique_id));
            for (name, key) in [
                ("Test Number", "test_number"),
                ("Test Name", "test_name"),
                ("Hostname", "hostname"),
                ("IP Address", "ip_address"),
                ("Username", "username"),
                ("GUID", "test_guid"),
                ("ProcessId", "process_id"),
            ] {
                if let Some(v) = col(name) {
                    fields.insert(key.to_string(), serde_json::json!(v));
                }
            }
            if let Some(code) = exit_code {
                fields.insert("exit_code".to_string(), serde_json::json!(code));
                fields.insert("success".to_string(), serde_json::json!(code == 0));
            }

            let mut tags = vec![
                "atomic".to_string(),
                "red_team".to_string(),
                "attack_simulation".to_string(),
            ];
            if !technique_id.is_empty() {
                tags.push(technique_id.clone());
            }
            if let Some(info) = map_technique_id(&technique_id) {
                insert_technique_fields(&mut fields, &info);
                for tactic in info.tactics {
                    tags.push(tactic.to_lowercase().replace(' ', "_"));
                }
            }

            let line_no = idx as u64 + 2; // header is line 1
            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp: ts.unwrap_or_else(Utc::now),
                timestamp_quality: if ts.is_some() {
                    TimestampQuality::Precise
                } else {
                    TimestampQuality::Unknown
                },
                event_type: "technique_executed".to_string(),
                source_file: file.rel_path.clone(),
                source_line: Some(line_no),
                fields,
                evidence_ptr: ImportEvidencePtr {
                    bundle_id: bundle_id.to_string(),
                    rel_path: file.rel_path.clone(),
                    line_no: Some(line_no),
                    json_path: None,
                    byte_offset: None,
                },
                tags,
            });
            entries_processed += 1;
        }

        Ok(ParseResult {
            events,
            warnings,
            entries_processed,
            entries_skipped,
        })
    }

    fn parse_text(
        &self,
        file: &ManifestFile,
        content: &str,
        bundle_id: &str,
        limits: &ImportLimits,
    ) -> Result<ParseResult, String> {
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        let mut entries_processed = 0u64;

        // Regex patterns for Atomic output
        let technique_re =
            Regex::new(r"(?i)(T\d{4}(?:\.\d{3})?)").map_err(|e| format!("Regex error: {}", e))?;
        let test_re = Regex::new(r"(?i)(?:Executing|Running|Test(?:ing)?)\s*[:\-]?\s*(.+)")
            .map_err(|e| format!("Regex error: {}", e))?;
        let result_re = Regex::new(r"(?i)(?:Result|Status|Exit\s*Code)\s*[:\-]?\s*(\w+|\d+)")
            .map_err(|e| format!("Regex error: {}", e))?;

        let timestamp = Utc::now();
        let mut current_technique: Option<String> = None;
        let mut current_test: Option<String> = None;
        let mut current_output = String::new();
        let mut last_result: Option<String> = None;
        let mut start_line = 0;

        for (line_no, line) in content.lines().enumerate() {
            if entries_processed >= limits.max_lines_per_file {
                warnings.push(format!("Event limit reached at line {}", line_no + 1));
                break;
            }

            // Check for technique ID
            if let Some(cap) = technique_re.captures(line) {
                // If we have a pending event, emit it
                if let Some(ref tech) = current_technique {
                    let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
                    fields.insert("technique_id".to_string(), serde_json::json!(tech));
                    if let Some(ref test) = current_test {
                        fields.insert("test_name".to_string(), serde_json::json!(test));
                    }
                    if !current_output.is_empty() {
                        fields.insert(
                            "output".to_string(),
                            serde_json::json!(current_output.trim()),
                        );
                    }
                    if let Some(ref result) = last_result {
                        fields.insert("result".to_string(), serde_json::json!(result));
                    }

                    if let Some(info) = map_technique_id(tech) {
                        insert_technique_fields(&mut fields, &info);
                    }

                    let tags = vec!["atomic".to_string(), "red_team".to_string(), tech.clone()];

                    events.push(ImportEvent {
                        event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                        timestamp,
                        timestamp_quality: TimestampQuality::Unknown,
                        event_type: "technique_executed".to_string(),
                        source_file: file.rel_path.clone(),
                        source_line: Some(start_line),
                        fields,
                        evidence_ptr: ImportEvidencePtr {
                            bundle_id: bundle_id.to_string(),
                            rel_path: file.rel_path.clone(),
                            line_no: Some(start_line),
                            json_path: None,
                            byte_offset: None,
                        },
                        tags,
                    });

                    entries_processed += 1;
                    current_output.clear();
                    current_test = None;
                    last_result = None;
                }

                current_technique = Some(cap.get(1).unwrap().as_str().to_uppercase());
                start_line = line_no as u64 + 1;
            }

            // Check for test name
            if let Some(cap) = test_re.captures(line) {
                current_test = Some(cap.get(1).unwrap().as_str().trim().to_string());
            }

            // Check for result
            if let Some(cap) = result_re.captures(line) {
                last_result = Some(cap.get(1).unwrap().as_str().to_string());
            }

            // Accumulate output
            if current_technique.is_some() && current_output.len() < 2000 {
                current_output.push_str(line);
                current_output.push('\n');
            }
        }

        // Emit final pending event
        if let Some(tech) = current_technique {
            let mut fields: HashMap<String, serde_json::Value> = HashMap::new();
            fields.insert("technique_id".to_string(), serde_json::json!(tech));
            if let Some(test) = current_test {
                fields.insert("test_name".to_string(), serde_json::json!(test));
            }
            if !current_output.is_empty() {
                fields.insert(
                    "output".to_string(),
                    serde_json::json!(current_output.trim()),
                );
            }
            if let Some(result) = last_result {
                fields.insert("result".to_string(), serde_json::json!(result));
            }

            if let Some(info) = map_technique_id(&tech) {
                insert_technique_fields(&mut fields, &info);
            }

            events.push(ImportEvent {
                event_id: generate_event_id(bundle_id, &file.rel_path, entries_processed),
                timestamp,
                timestamp_quality: TimestampQuality::Unknown,
                event_type: "technique_executed".to_string(),
                source_file: file.rel_path.clone(),
                source_line: Some(start_line),
                fields: fields.clone(),
                evidence_ptr: ImportEvidencePtr {
                    bundle_id: bundle_id.to_string(),
                    rel_path: file.rel_path.clone(),
                    line_no: Some(start_line),
                    json_path: None,
                    byte_offset: None,
                },
                tags: vec!["atomic".to_string(), "red_team".to_string(), tech],
            });

            entries_processed += 1;
        }

        Ok(ParseResult {
            events,
            warnings,
            entries_processed,
            entries_skipped: 0,
        })
    }
}

struct TechniqueInfo {
    name: &'static str,
    tactics: &'static [&'static str],
    /// The current ID when MITRE revoked this one
    replaced_by: Option<&'static str>,
}

/// Technique name, tactics (all of them, as ATT&CK lists them) and the
/// replacement for a revoked ID.
fn insert_technique_fields(fields: &mut HashMap<String, serde_json::Value>, info: &TechniqueInfo) {
    fields.insert("technique_name".to_string(), serde_json::json!(info.name));
    fields.insert(
        "tactic".to_string(),
        serde_json::json!(info.tactics.first().copied().unwrap_or("")),
    );
    fields.insert("tactics".to_string(), serde_json::json!(info.tactics));
    fields.insert("attack_version".to_string(), serde_json::json!("20.1"));
    if let Some(current) = info.replaced_by {
        fields.insert(
            "technique_replaced_by".to_string(),
            serde_json::json!(current),
        );
    }
}

/// Map ATT&CK technique IDs to names and tactics (ATT&CK v20.1). Atomic Red
/// Team still names some tests by IDs MITRE has revoked, such as T1070.001.
fn map_technique_id(technique_id: &str) -> Option<TechniqueInfo> {
    let id = technique_id.to_uppercase();

    match id.as_str() {
        "T1059" => Some(TechniqueInfo {
            name: "Command and Scripting Interpreter",
            tactics: &["Execution"],
            replaced_by: None,
        }),
        "T1059.001" => Some(TechniqueInfo {
            name: "Command and Scripting Interpreter: PowerShell",
            tactics: &["Execution"],
            replaced_by: None,
        }),
        "T1059.003" => Some(TechniqueInfo {
            name: "Command and Scripting Interpreter: Windows Command Shell",
            tactics: &["Execution"],
            replaced_by: None,
        }),
        "T1059.005" => Some(TechniqueInfo {
            name: "Command and Scripting Interpreter: Visual Basic",
            tactics: &["Execution"],
            replaced_by: None,
        }),
        "T1059.006" => Some(TechniqueInfo {
            name: "Command and Scripting Interpreter: Python",
            tactics: &["Execution"],
            replaced_by: None,
        }),
        "T1003" => Some(TechniqueInfo {
            name: "OS Credential Dumping",
            tactics: &["Credential Access"],
            replaced_by: None,
        }),
        "T1003.001" => Some(TechniqueInfo {
            name: "OS Credential Dumping: LSASS Memory",
            tactics: &["Credential Access"],
            replaced_by: None,
        }),
        "T1003.002" => Some(TechniqueInfo {
            name: "OS Credential Dumping: Security Account Manager",
            tactics: &["Credential Access"],
            replaced_by: None,
        }),
        "T1003.003" => Some(TechniqueInfo {
            name: "OS Credential Dumping: NTDS",
            tactics: &["Credential Access"],
            replaced_by: None,
        }),
        "T1547" => Some(TechniqueInfo {
            name: "Boot or Logon Autostart Execution",
            tactics: &["Persistence", "Privilege Escalation"],
            replaced_by: None,
        }),
        "T1547.001" => Some(TechniqueInfo {
            name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            tactics: &["Persistence", "Privilege Escalation"],
            replaced_by: None,
        }),
        "T1053" => Some(TechniqueInfo {
            name: "Scheduled Task/Job",
            tactics: &["Execution", "Persistence", "Privilege Escalation"],
            replaced_by: None,
        }),
        "T1053.005" => Some(TechniqueInfo {
            name: "Scheduled Task/Job: Scheduled Task",
            tactics: &["Execution", "Persistence", "Privilege Escalation"],
            replaced_by: None,
        }),
        "T1055" => Some(TechniqueInfo {
            name: "Process Injection",
            tactics: &["Stealth", "Privilege Escalation"],
            replaced_by: None,
        }),
        "T1055.001" => Some(TechniqueInfo {
            name: "Process Injection: Dynamic-link Library Injection",
            tactics: &["Stealth", "Privilege Escalation"],
            replaced_by: None,
        }),
        "T1055.012" => Some(TechniqueInfo {
            name: "Process Injection: Process Hollowing",
            tactics: &["Stealth", "Privilege Escalation"],
            replaced_by: None,
        }),
        "T1021" => Some(TechniqueInfo {
            name: "Remote Services",
            tactics: &["Lateral Movement"],
            replaced_by: None,
        }),
        "T1021.001" => Some(TechniqueInfo {
            name: "Remote Services: Remote Desktop Protocol",
            tactics: &["Lateral Movement"],
            replaced_by: None,
        }),
        "T1021.002" => Some(TechniqueInfo {
            name: "Remote Services: SMB/Windows Admin Shares",
            tactics: &["Lateral Movement"],
            replaced_by: None,
        }),
        "T1021.003" => Some(TechniqueInfo {
            name: "Remote Services: Distributed Component Object Model",
            tactics: &["Lateral Movement"],
            replaced_by: None,
        }),
        "T1021.006" => Some(TechniqueInfo {
            name: "Remote Services: Windows Remote Management",
            tactics: &["Lateral Movement"],
            replaced_by: None,
        }),
        "T1018" => Some(TechniqueInfo {
            name: "Remote System Discovery",
            tactics: &["Discovery"],
            replaced_by: None,
        }),
        "T1016" => Some(TechniqueInfo {
            name: "System Network Configuration Discovery",
            tactics: &["Discovery"],
            replaced_by: None,
        }),
        "T1033" => Some(TechniqueInfo {
            name: "System Owner/User Discovery",
            tactics: &["Discovery"],
            replaced_by: None,
        }),
        "T1057" => Some(TechniqueInfo {
            name: "Process Discovery",
            tactics: &["Discovery"],
            replaced_by: None,
        }),
        "T1069" => Some(TechniqueInfo {
            name: "Permission Groups Discovery",
            tactics: &["Discovery"],
            replaced_by: None,
        }),
        "T1082" => Some(TechniqueInfo {
            name: "System Information Discovery",
            tactics: &["Discovery"],
            replaced_by: None,
        }),
        "T1083" => Some(TechniqueInfo {
            name: "File and Directory Discovery",
            tactics: &["Discovery"],
            replaced_by: None,
        }),
        "T1087" => Some(TechniqueInfo {
            name: "Account Discovery",
            tactics: &["Discovery"],
            replaced_by: None,
        }),
        "T1070" => Some(TechniqueInfo {
            name: "Indicator Removal",
            tactics: &["Stealth"],
            replaced_by: None,
        }),
        "T1070.001" => Some(TechniqueInfo {
            name: "Disable or Modify Tools: Clear Windows Event Logs",
            tactics: &["Defense Impairment"],
            replaced_by: Some("T1685.005"),
        }),
        "T1685.005" => Some(TechniqueInfo {
            name: "Disable or Modify Tools: Clear Windows Event Logs",
            tactics: &["Defense Impairment"],
            replaced_by: None,
        }),
        "T1070.004" => Some(TechniqueInfo {
            name: "Indicator Removal: File Deletion",
            tactics: &["Stealth"],
            replaced_by: None,
        }),
        "T1566" => Some(TechniqueInfo {
            name: "Phishing",
            tactics: &["Initial Access"],
            replaced_by: None,
        }),
        "T1566.001" => Some(TechniqueInfo {
            name: "Phishing: Spearphishing Attachment",
            tactics: &["Initial Access"],
            replaced_by: None,
        }),
        "T1566.002" => Some(TechniqueInfo {
            name: "Phishing: Spearphishing Link",
            tactics: &["Initial Access"],
            replaced_by: None,
        }),
        "T1071" => Some(TechniqueInfo {
            name: "Application Layer Protocol",
            tactics: &["Command and Control"],
            replaced_by: None,
        }),
        "T1071.001" => Some(TechniqueInfo {
            name: "Application Layer Protocol: Web Protocols",
            tactics: &["Command and Control"],
            replaced_by: None,
        }),
        "T1486" => Some(TechniqueInfo {
            name: "Data Encrypted for Impact",
            tactics: &["Impact"],
            replaced_by: None,
        }),
        "T1490" => Some(TechniqueInfo {
            name: "Inhibit System Recovery",
            tactics: &["Impact"],
            replaced_by: None,
        }),
        _ => None,
    }
}

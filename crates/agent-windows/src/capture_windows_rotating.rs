// windows/sensors/capture_windows_rotating.rs
// Windows event log capture binary (JSONL segments + index, heartbeat)
// Analogous to linux/capture_linux_rotating.rs
// Polls Windows Event Logs (Sysmon, Security, System, etc.) with bounded work

#![cfg(target_os = "windows")]

use chrono::{DateTime, Utc};
use edr_core::{Event, EvidencePtr, event_keys};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct CaptureHeartbeat {
    pub ts: DateTime<Utc>,
    pub transport: String,
    pub source: String,
    pub events_read_total: u64,
    pub events_read_delta: u64,
    pub parse_failed_total: u64,
    pub parse_failed_delta: u64,
    pub last_event_ts: Option<DateTime<Utc>>,
    pub status: String,
    // Canonical event counters (9 types + 2 breakdown)
    pub credential_access_count: u64,
    pub discovery_count: u64,
    pub exfiltration_count: u64,
    pub network_connection_count: u64,
    pub persistence_change_count: u64,
    pub defense_evasion_count: u64,
    pub process_injection_count: u64,
    pub auth_event_count: u64,
    pub script_exec_count: u64,
    pub archive_tool_exec_count: u64,
    pub staging_write_count: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SegmentIndex {
    pub schema_version: u32,
    pub next_seq: u64,
    pub segments: Vec<SegmentMetadata>,
    pub last_updated_ts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_index_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SegmentMetadata {
    pub seq: u64,
    pub segment_id: String,
    pub rel_path: String,
    pub ts_first: u64,
    pub ts_last: u64,
    pub records: u32,
    pub size_bytes: u64,
    pub sha256_segment: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeartbeatMetrics {
    pub source: String,
    pub events_read_total: u64,
    pub events_read_delta: u64,
    pub parse_failed_total: u64,
    pub parse_failed_delta: u64,
    pub last_event_ts: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct WindowsCaptureConfig {
    pub root_dir: PathBuf,          // segments directory (telemetry_root/segments)
    pub telemetry_root: PathBuf,    // parent directory for index.json
    pub segment_rotation_records: u64,
    pub heartbeat_interval_secs: u64,
}

pub struct WindowsEventCapture {
    config: WindowsCaptureConfig,
    segment_count: u64,
    event_count: u64,
    collector: crate::sensors::EvtxCollector,
    metrics: BTreeMap<String, HeartbeatMetrics>,
    // Attack surface event counters
    proc_exec_count: u64,
    priv_escalation_count: u64,
    proc_access_count: u64,
    asr_block_count: u64,
    wmi_persistence_count: u64,
    persistence_service_count: u64,
    persistence_task_count: u64,
    log_clear_count: u64,
    remote_logon_rdp_count: u64,
    remote_winrm_count: u64,
    decode_failed_count: u64,
    // Primitive counters - Original 4 types
    cred_access_count: u64,
    discovery_exec_count: u64,
    archive_tool_exec_count: u64,
    staging_write_count: u64,
    net_connect_prim_count: u64,
    // Extended 3 canonical primitives (Windows parity)
    persistence_change_count: u64,
    defense_evasion_count: u64,
    script_exec_count: u64,
}

impl WindowsEventCapture {
    pub fn new(segments_dir: PathBuf) -> Self {
        fs::create_dir_all(&segments_dir).ok();

        // Derive telemetry_root as parent of segments directory
        let telemetry_root = segments_dir.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| segments_dir.clone());

        Self {
            config: WindowsCaptureConfig {
                root_dir: segments_dir,
                telemetry_root,
                segment_rotation_records: 10000,
                heartbeat_interval_secs: 5,
            },
            segment_count: 0,
            event_count: 0,
            collector: crate::sensors::EvtxCollector::new(),
            metrics: BTreeMap::new(),
            proc_exec_count: 0,
            priv_escalation_count: 0,
            proc_access_count: 0,
            asr_block_count: 0,
            wmi_persistence_count: 0,
            persistence_service_count: 0,
            persistence_task_count: 0,
            log_clear_count: 0,
            remote_logon_rdp_count: 0,
            remote_winrm_count: 0,
            decode_failed_count: 0,
            cred_access_count: 0,
            discovery_exec_count: 0,
            archive_tool_exec_count: 0,
            staging_write_count: 0,
            net_connect_prim_count: 0,
            persistence_change_count: 0,
            defense_evasion_count: 0,
            script_exec_count: 0,
        }
    }

    /// Create capture with mock JSONL events
    pub fn with_mock_events(segments_dir: PathBuf, fixture_path: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(&segments_dir)?;

        // Derive telemetry_root as parent of segments directory
        let telemetry_root = segments_dir.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| segments_dir.clone());

        eprintln!(
            "[capture_windows] Mock mode: reading JSONL events from {:?}",
            fixture_path
        );

        // Load events from JSONL fixture
        let content = std::fs::read_to_string(fixture_path)?;
        let mut events: Vec<Event> = Vec::new();
        let mut skipped = 0usize;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Event>(line) {
                Ok(evt) => events.push(evt),
                Err(_) => skipped += 1,
            }
        }
        eprintln!(
            "[capture_windows] Mock loaded {} events (skipped {})",
            events.len(),
            skipped
        );

        // Write segment with mock events
        let segment_id = "windows_000000";
        let segment_path = segments_dir.join(format!("{}.jsonl", segment_id));
        let events_count = events.len();

        let mut segment_content = String::new();
        for evt in &events {
            if let Ok(json_str) = serde_json::to_string(&evt) {
                segment_content.push_str(&json_str);
                segment_content.push('\n');
            }
        }

        fs::write(&segment_path, segment_content)?;

        // Write heartbeat
        let heartbeat = serde_json::json!({
            "ts": Utc::now(),
            "transport": "mock",
            "events_read_total": events_count,
            "parse_failed_total": skipped,
            "status": "complete"
        });
        fs::write(
            segments_dir.join("heartbeat.json"),
            serde_json::to_string(&heartbeat)?,
        )?;

        eprintln!("[capture_windows] Mock capture complete");

        Ok(Self {
            config: WindowsCaptureConfig {
                root_dir: segments_dir,
                telemetry_root,
                segment_rotation_records: 10000,
                heartbeat_interval_secs: 5,
            },
            segment_count: 1,
            event_count: events.len() as u64,
            collector: crate::sensors::EvtxCollector::new(),
            metrics: BTreeMap::new(),
            proc_exec_count: 0,
            priv_escalation_count: 0,
            proc_access_count: 0,
            asr_block_count: 0,
            wmi_persistence_count: 0,
            persistence_service_count: 0,
            persistence_task_count: 0,
            log_clear_count: 0,
            remote_logon_rdp_count: 0,
            remote_winrm_count: 0,
            decode_failed_count: 0,
            cred_access_count: 0,
            discovery_exec_count: 0,
            archive_tool_exec_count: 0,
            staging_write_count: 0,
            net_connect_prim_count: 0,
            persistence_change_count: 0,
            defense_evasion_count: 0,
            script_exec_count: 0,
        })
    }

    /// Poll all enabled event log sources and write segments
    /// CRITICAL: Derives primitives → dedup → EvidencePtr assignment → write
    pub fn poll_and_write(&mut self) -> anyhow::Result<()> {
        let host = crate::host::HostCtx::new();
        let segment_id = format!("evtx_{:06}", self.segment_count);
        let segment_path = self.config.root_dir.join(format!("{}.jsonl", segment_id));

        // Call unified collector that handles all sources + gating
        // Returns events with None evidence_ptr
        let mut all_events = crate::sensors::collect::collect_all(&host);

        // STEP 1: Derive canonical primitives from base events (process, network, file)
        let mut derived_events = Vec::new();
        for event in &all_events {
            let primitives = crate::sensors::primitives::derive_primitive_events(event);
            derived_events.extend(primitives);
        }

        // Merge derived primitives into events
        all_events.extend(derived_events);

        // STEP 2: Sort deterministically (by timestamp + type + pid)
        sort_events(&mut all_events);

        // STEP 3: Dedup derived primitives (same primitive from same source shouldn't repeat)
        let mut seen_derived = std::collections::HashSet::new();
        let mut deduped_events = Vec::new();

        for event in all_events {
            // Check if this is a derived primitive by tags (all 9 canonical types)
            let is_derived = event.tags.contains(&"credential_access".to_string())
                || event.tags.contains(&"discovery".to_string())
                || event.tags.contains(&"exfiltration".to_string())
                || event.tags.contains(&"network_connection".to_string())
                || event.tags.contains(&"persistence_change".to_string())
                || event.tags.contains(&"defense_evasion".to_string())
                || event.tags.contains(&"process_injection".to_string())
                || event.tags.contains(&"auth_event".to_string())
                || event.tags.contains(&"script_exec".to_string());

            if is_derived {
                // Generate dedup key for derived primitives
                let dedup_key = generate_dedup_key(&event);

                if seen_derived.contains(&dedup_key) {
                    // Skip duplicate derived primitive from this poll window
                    continue;
                }
                seen_derived.insert(dedup_key);
            }

            deduped_events.push(event);
        }

        let mut all_events = deduped_events;

        // Count attack surface events before EvidencePtr assignment
        for event in &all_events {
            match event
                .fields
                .get(event_keys::EVENT_KIND)
                .and_then(|v: &Value| v.as_str())
            {
                Some("proc_exec") => self.proc_exec_count += 1,
                Some("priv_escalation") => self.priv_escalation_count += 1,
                Some("proc_access") => self.proc_access_count += 1,
                Some("asr_block") => self.asr_block_count += 1,
                Some("wmi_persistence") => self.wmi_persistence_count += 1,
                Some("persistence_service") => self.persistence_service_count += 1,
                Some("persistence_task") => self.persistence_task_count += 1,
                Some("log_clear") => self.log_clear_count += 1,
                Some("remote_logon_rdp") => self.remote_logon_rdp_count += 1,
                Some("remote_winrm") => self.remote_winrm_count += 1,
                _ => {}
            }

            // Count primitive types
            if event.tags.contains(&"credential_access".to_string()) {
                self.cred_access_count += 1;
            } else if event.tags.contains(&"discovery".to_string()) {
                self.discovery_exec_count += 1;
            } else if event.tags.contains(&"exfiltration".to_string()) {
                if event
                    .fields
                    .contains_key(event_keys::ARCHIVE_TOOL)
                {
                    self.archive_tool_exec_count += 1;
                } else if event
                    .fields
                    .contains_key(event_keys::FILE_PATH)
                {
                    self.staging_write_count += 1;
                }
            } else if event.tags.contains(&"network_connection".to_string()) {
                self.net_connect_prim_count += 1;
            } else if event.tags.contains(&"persistence_change".to_string()) {
                self.persistence_change_count += 1;
            } else if event.tags.contains(&"defense_evasion".to_string()) {
                self.defense_evasion_count += 1;
            } else if event.tags.contains(&"script_exec".to_string()) {
                self.script_exec_count += 1;
            }
        }

        // STEP 4: ASSIGN EvidencePtr HERE ONLY - uses segment state
        let mut all_events = self.assign_evidence_ptrs_with_state(all_events, self.segment_count);

        // STEP 5: Validate canonical primitives contract
        for event in &all_events {
            if event.tags.contains(&"credential_access".to_string())
                || event.tags.contains(&"discovery".to_string())
                || event.tags.contains(&"exfiltration".to_string())
                || event.tags.contains(&"network_connection".to_string())
                || event.tags.contains(&"persistence_change".to_string())
                || event.tags.contains(&"defense_evasion".to_string())
                || event.tags.contains(&"process_injection".to_string())
                || event.tags.contains(&"auth_event".to_string())
                || event.tags.contains(&"script_exec".to_string())
            {
                if let Err(e) = event.validate_canonical_primitive() {
                    eprintln!(
                        "[capture_windows] VALIDATION ERROR: primitive event failed contract: {}",
                        e
                    );
                    eprintln!("[capture_windows] Event: {:?}", event);
                }
            }
        }

        // Write segment if events present
        if !all_events.is_empty() {
            let mut segment_file = fs::File::create(&segment_path)?;
            use std::io::Write;
            for evt in &all_events {
                if let Ok(json_str) = serde_json::to_string(evt) {
                    writeln!(segment_file, "{}", json_str)?;
                }
            }
            segment_file.sync_all()?;

            // Compute segment hash
            let segment_data = fs::read(&segment_path).unwrap_or_default();
            let sha256_segment = {
                let mut hasher = Sha256::new();
                hasher.update(&segment_data);
                format!("{:x}", hasher.finalize())
            };

            // Update index.json at telemetry_root level
            let index_path = self.config.telemetry_root.join("index.json");
            let ts_now = Utc::now().timestamp_millis() as u64;
            if let Err(e) = update_index_atomic(
                &index_path,
                &segment_id,
                format!("segments/{}.jsonl", segment_id),  // relative to telemetry_root
                ts_now,
                ts_now,
                all_events.len() as u32,
                segment_data.len() as u64,
                sha256_segment,
            ) {
                eprintln!("[capture_windows] WARNING: Failed to update index.json: {}", e);
            }
        }

        self.event_count += all_events.len() as u64;

        // Rotate if needed
        if self.event_count >= self.config.segment_rotation_records {
            self.rotate_segment()?;
        }

        Ok(())
    }

    /// Assign EvidencePtr to events using capture writer state (segment seq + record counter)
    /// NEVER uses WEVTAPI record_id - that's internal Windows state not for evidence paths
    ///
    /// Guard assertion: incoming events must have evidence_ptr == None
    /// If any event already has Some(evidence_ptr), treat as architectural bug
    fn assign_evidence_ptrs_with_state(
        &self,
        mut events: Vec<Event>,
        segment_seq: u64,
    ) -> Vec<Event> {
        let mut record_index = 0u32;

        for event in &mut events {
            // GUARD: Incoming event must NOT have evidence_ptr already set
            if event.evidence_ptr.is_some() {
                debug_assert!(false, "[capture] BUG: incoming event already has evidence_ptr set - this violates architecture");
                eprintln!("[capture] ERROR: incoming event from collect already has evidence_ptr - dropping event as bug indicator");
                // Drop this event - it's a sign of architectural violation
                continue;
            }

            // Extract channel for stream_id
            let stream_id = event
                .fields
                .get("windows.channel")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            // Create EvidencePtr from capture writer state only
            event.evidence_ptr = Some(EvidencePtr {
                stream_id,
                segment_id: segment_seq,
                record_index,
            });

            record_index = record_index.saturating_add(1);
        }

        // Filter out any events that triggered the guard (should be none in normal operation)
        events.retain(|e| e.evidence_ptr.is_some());

        events
    }

    /// Start capture loop
    pub fn run(&mut self) -> anyhow::Result<()> {
        // Spawn heartbeat thread
        let root = self.config.root_dir.clone();
        let interval = self.config.heartbeat_interval_secs;
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(interval));
            let heartbeat = serde_json::json!({
                "ts": Utc::now(),
                "transport": "evtx",
                "status": "running"
            });
            let hb_path = root.join("heartbeat.json");
            let _ = fs::write(hb_path, serde_json::to_string_pretty(&heartbeat).unwrap());
        });

        // Main capture loop
        loop {
            self.poll_and_write()?;
            self.write_heartbeat()?;
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn rotate_segment(&mut self) -> anyhow::Result<()> {
        self.segment_count += 1;
        self.event_count = 0;
        Ok(())
    }

    /// Write heartbeat with attack surface counters and primitive counters
    pub fn write_heartbeat(&self) -> anyhow::Result<()> {
        let heartbeat = serde_json::json!({
            "ts": Utc::now(),
            "pid": std::process::id(),
            "segment_id": self.segment_count,
            "schema_version": 1,
            "transport": "wevtapi",
            "proc_exec_count": self.proc_exec_count,
            "priv_escalation_count": self.priv_escalation_count,
            "proc_access_count": self.proc_access_count,
            "asr_block_count": self.asr_block_count,
            "wmi_persistence_count": self.wmi_persistence_count,
            "persistence_service_count": self.persistence_service_count,
            "persistence_task_count": self.persistence_task_count,
            "log_clear_count": self.log_clear_count,
            "remote_logon_rdp_count": self.remote_logon_rdp_count,
            "remote_winrm_count": self.remote_winrm_count,
            "decode_failed_count": self.decode_failed_count,
            "cred_access_count": self.cred_access_count,
            "discovery_exec_count": self.discovery_exec_count,
            "archive_tool_exec_count": self.archive_tool_exec_count,
            "staging_write_count": self.staging_write_count,
            "net_connect_prim_count": self.net_connect_prim_count,
            "persistence_change_count": self.persistence_change_count,
            "defense_evasion_count": self.defense_evasion_count,
            "script_exec_count": self.script_exec_count,
        });
        let hb_path = self.config.root_dir.join("capture_heartbeat.json");
        let temp_path = self.config.root_dir.join("capture_heartbeat.json.tmp");
        fs::write(&temp_path, serde_json::to_string_pretty(&heartbeat)?)?;
        fs::rename(&temp_path, &hb_path)?;
        Ok(())
    }
}

/// Sort events deterministically
fn sort_events(events: &mut Vec<Event>) {
    events.sort_by(|a, b| {
        // Sort by ts_ms primarily, then by event_kind, then by pid
        match a.ts_ms.cmp(&b.ts_ms) {
            std::cmp::Ordering::Equal => {
                let a_kind = a
                    .fields
                    .get("event_kind")
                    .and_then(|v: &Value| v.as_str())
                    .unwrap_or("");
                let b_kind = b
                    .fields
                    .get("event_kind")
                    .and_then(|v: &Value| v.as_str())
                    .unwrap_or("");
                match a_kind.cmp(b_kind) {
                    std::cmp::Ordering::Equal => {
                        let a_pid = a.fields.get("pid").and_then(|v: &Value| v.as_u64()).unwrap_or(0);
                        let b_pid = b.fields.get("pid").and_then(|v: &Value| v.as_u64()).unwrap_or(0);
                        a_pid.cmp(&b_pid)
                    }
                    other => other,
                }
            }
            other => other,
        }
    });
}

/// Generate dedup key for derived primitive events
/// Key is: event_kind + ts_ms + pid + (discriminator field for event type)
fn generate_dedup_key(event: &Event) -> String {
    let kind = event
        .fields
        .get("event_kind")
        .and_then(|v: &Value| v.as_str())
        .unwrap_or("unknown");
    let ts = event.ts_ms;
    let pid = event
        .fields
        .get("pid")
        .and_then(|v: &Value| v.as_u64())
        .unwrap_or(0);

    // Add type-specific discriminators for all 9 canonical types
    let discriminator = if event.tags.contains(&"credential_access".to_string()) {
        event
            .fields
            .get("target_user")
            .and_then(|v: &Value| v.as_str())
            .unwrap_or("")
    } else if event.tags.contains(&"discovery".to_string()) {
        event
            .fields
            .get("discovery_type")
            .and_then(|v: &Value| v.as_str())
            .unwrap_or("")
    } else if event.tags.contains(&"exfiltration".to_string()) {
        event
            .fields
            .get(event_keys::FILE_PATH)
            .and_then(|v: &Value| v.as_str())
            .unwrap_or(
                event
                    .fields
                    .get(event_keys::ARCHIVE_TOOL)
                    .and_then(|v: &Value| v.as_str())
                    .unwrap_or(""),
            )
    } else if event.tags.contains(&"network_connection".to_string()) {
        event
            .fields
            .get("remote_ip")
            .and_then(|v: &Value| v.as_str())
            .unwrap_or("")
    } else if event.tags.contains(&"persistence_change".to_string()) {
        event
            .fields
            .get(event_keys::PERSIST_LOCATION)
            .and_then(|v: &Value| v.as_str())
            .unwrap_or("")
    } else if event.tags.contains(&"defense_evasion".to_string()) {
        event
            .fields
            .get(event_keys::EVASION_TARGET)
            .and_then(|v: &Value| v.as_str())
            .unwrap_or("")
    } else if event.tags.contains(&"process_injection".to_string()) {
        event
            .fields
            .get(event_keys::INJECT_METHOD)
            .and_then(|v: &Value| v.as_str())
            .unwrap_or("")
    } else if event.tags.contains(&"auth_event".to_string()) {
        event
            .fields
            .get(event_keys::AUTH_USER)
            .and_then(|v: &Value| v.as_str())
            .unwrap_or("")
    } else if event.tags.contains(&"script_exec".to_string()) {
        event
            .fields
            .get(event_keys::SCRIPT_INTERPRETER)
            .and_then(|v: &Value| v.as_str())
            .unwrap_or("")
    } else {
        ""
    };

    format!("{}:{}:{}:{}", kind, ts, pid, discriminator)
}

/// Atomically update index.json with new segment metadata
fn update_index_atomic(
    index_path: &std::path::Path,
    segment_id: &str,
    rel_path: String,
    ts_first: u64,
    ts_last: u64,
    records: u32,
    size_bytes: u64,
    sha256_segment: String,
) -> Result<(), String> {
    // Load existing index or create new
    let mut index = if index_path.exists() {
        let content = fs::read_to_string(index_path)
            .map_err(|e| format!("Failed to read index: {}", e))?;
        serde_json::from_str(&content).unwrap_or_else(|_| SegmentIndex {
            schema_version: 1,
            next_seq: 0,
            segments: Vec::new(),
            last_updated_ts: 0,
            index_hash: None,
            prev_index_hash: None,
        })
    } else {
        SegmentIndex {
            schema_version: 1,
            next_seq: 0,
            segments: Vec::new(),
            last_updated_ts: 0,
            index_hash: None,
            prev_index_hash: None,
        }
    };

    // Assign monotonic seq to new segment
    let seq = index.next_seq;
    index.next_seq += 1;

    // Add/update segment metadata
    if let Some(existing) = index.segments.iter_mut().find(|s| s.segment_id == segment_id) {
        existing.ts_last = ts_last;
        existing.records = records;
        existing.size_bytes = size_bytes;
        existing.sha256_segment = sha256_segment;
    } else {
        index.segments.push(SegmentMetadata {
            seq,
            segment_id: segment_id.to_string(),
            rel_path,
            ts_first,
            ts_last,
            records,
            size_bytes,
            sha256_segment,
        });
    }

    index.last_updated_ts = Utc::now().timestamp_millis() as u64;

    // Store previous hash
    index.prev_index_hash = index.index_hash.clone();

    // Compute current index hash
    let json_str = serde_json::to_string_pretty(&index)
        .map_err(|e| format!("Failed to serialize index: {}", e))?;
    
    let index_hash = {
        let mut hasher = Sha256::new();
        hasher.update(json_str.as_bytes());
        format!("{:x}", hasher.finalize())
    };
    index.index_hash = Some(index_hash);

    let final_json = serde_json::to_string_pretty(&index)
        .map_err(|e| format!("Failed to serialize final index: {}", e))?;

    // Write to temp file first
    let temp_path = index_path.with_extension("json.tmp");
    fs::write(&temp_path, &final_json)
        .map_err(|e| format!("Failed to write temp index: {}", e))?;

    // Atomic rename
    fs::rename(&temp_path, index_path)
        .map_err(|e| format!("Failed to rename index: {}", e))?;

    // Write backup
    let bak_path = index_path.with_extension("json.bak");
    let _ = fs::write(&bak_path, final_json);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_new() {
        let tmpdir = std::env::temp_dir();
        let capture = WindowsEventCapture::new(tmpdir);
        assert_eq!(capture.segment_count, 0);
    }
}

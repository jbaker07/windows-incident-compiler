# Import Pipeline Map

This document clarifies the **two distinct import systems** in this project and when to use each.

---

## Overview: Two Import Pipelines

| Aspect | UI Import (Tauri Desktop) | Backend Import (locald integrations) |
|--------|---------------------------|--------------------------------------|
| **Purpose** | Import evidence bundles from external tools (YARA, Nmap, etc.) | Ingest live third-party alerts (Wazuh, Zeek) |
| **Entry Point** | `import_bundle` CLI (the `SafeImporter` library). The desktop app lists imported bundles but has no import command yet | locald daemon integration sources |
| **Code Location** | `src-tauri/src/adapters/` | `crates/locald/src/integrations/` |
| **Output** | `imports/<bundle_id>/manifest.json` + `events.json` | Facts in hypothesis engine |
| **Event Flow** | Files → Adapters → ImportEvents → Playbooks → Signals | Live stream → VendorAlertFact → Signals |

---

## UI Import (Tauri Desktop App)

**When to use**: Importing static evidence bundles from external tools (pentests, IR artifacts, scan results).

### Code Locations

| Component | Path |
|-----------|------|
| Adapters | `src-tauri/src/adapters/*.rs` |
| Import types | `src-tauri/src/import_types.rs` |
| SafeImporter | `src-tauri/src/importer.rs` |
| Grounded gates | `src-tauri/src/grounded_gates.rs` |
| Playbooks | `playbooks/import/*.yaml` |

### Adapters Available

| Adapter | File | Event Types |
|---------|------|-------------|
| atomic | `atomic.rs` | `technique_executed` (ATT&CK v20.1 names and tactics) |
| burp | `burp.rs` | `http_request` (Burp "Save items" XML), `web_vulnerability` (Burp scanner issues XML) |
| evtx_json | `evtx_json.rs` | `process_create`, `logon_success`, `logon_failure`, `service_installed`, `scheduled_task_created`, `log_cleared`, Sysmon and PowerShell types, `windows_event` |
| har | `har.rs` | `http_request`, `security_pattern` |
| jsonl | `jsonl.rs` | The record's own type, or `process_creation`, `network_connection`, `http_request`, `dns_query`, `auth_event`, `generic` |
| nmap | `nmap.rs` | `host_discovered`, `port_discovered`, `nmap_script` |
| osquery | `osquery.rs` | `process_info`, `user_info`, `listening_port`, `file_event`, `active_session`, `process_exec`, `socket_event`, `table_row` |
| plaintext | `plaintext.rs` | `shell_command`, `powershell_command`, `directory_found`, `fuzz_result`, `log_line` |
| suricata | `suricata.rs` | `net_alert`, `dns_query`, `http_txn`, `tls_handshake`, `netflow` |
| velociraptor | `velociraptor.rs` | `process_info`, `network_connection`, `mft_entry`, `file_info`, `registry_entry`, `prefetch_entry`, `scheduled_task`, `service_info`, `user_info`, `vr_artifact` |
| yara | `yara.rs` | `yara_match` |
| zap | `zap.rs` | `web_vulnerability` |
| zeek | `zeek.rs` | `netflow`, `dns_query`, `http_txn`, `tls_handshake`, `file_transfer`, `zeek_log` |
| yaml | `structured.rs` | One event per YAML document or list item, typed like a JSON record |
| csv | `structured.rs` | One event per CSV row, typed like a JSON record |

The importer runs `AdapterRegistry::parse_manifest` at the end of every import,
writes the events to `events.json` (a JSON array) and records `parsed`, `parser`,
`warnings` and `events_extracted` per file in `manifest.json`.

### Data Flow

```
Evidence Folder/ZIP
       ↓
   SafeImporter (validates limits: 2GB, 50K files)
       ↓
   FileKind::detect() classifies each file
       ↓
   AdapterRegistry matches FileKind → Adapter
       ↓
   Adapter.parse() → Vec<ImportEvent>
       ↓
   Events written to imports/<bundle_id>/events.json
       ↓
   Import playbooks (playbooks/import/*.yaml): defined, not evaluated yet
       ↓
   ImportEvents and the bundle manifest are the output
```

### Key Types

```rust
// src-tauri/src/import_types.rs
pub struct ImportEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub timestamp_quality: TimestampQuality, // precise, estimated or unknown
    pub event_type: String,
    pub source_file: String,
    pub source_line: Option<u64>,
    pub fields: HashMap<String, serde_json::Value>,
    pub evidence_ptr: ImportEvidencePtr, // bundle, file, line or JSON path
    pub tags: Vec<String>,
}
```

---

## Backend Import (locald Integrations)

**When to use**: Continuous ingestion of live alerts from deployed security tools.

### Code Locations

| Component | Path |
|-----------|------|
| Integration module | `crates/locald/src/integrations/mod.rs` |
| Ingest sources | `crates/locald/src/integrations/ingest.rs` |
| Export sinks | `crates/locald/src/integrations/export.rs` |
| Vendor alert types | `crates/locald/src/integrations/vendor_alert.rs` |
| Integration profiles | `crates/locald/src/integrations/profile.rs` |

### Supported Integrations

| Integration | Direction | Format |
|-------------|-----------|--------|
| Wazuh | Ingest | JSONL file watch |
| Zeek EVE | Ingest | JSONL file watch |
| SIEM export | Export | JSONL incidents |

### Data Flow

```
Third-party tool (Wazuh/Zeek)
       ↓
   Writes JSONL to monitored path
       ↓
   IngestSource reads new lines
       ↓
   Parse into VendorAlertFact
       ↓
   VendorAlertFact → Hypothesis engine
       ↓
   Correlates with live telemetry
       ↓
   Signals emitted
```

### Key Types

```rust
// crates/locald/src/integrations/vendor_alert.rs
pub struct VendorAlertFact {
    pub alert_id: String,
    pub vendor: String,
    pub timestamp: DateTime<Utc>,
    pub severity: AlertSeverity,
    pub title: String,
    pub ip_indicators: Vec<IpIndicator>,
    pub process_hints: Vec<ProcessHint>,
    pub file_hints: Vec<FileHint>,
}
```

---

## Shared Concepts

### Entity Keys (used by both pipelines)

| Key | Format | Purpose |
|-----|--------|---------|
| `host_key` | `{ip}` or `{hostname}` (lowercase) | Host correlation |
| `proc_key` | `{hostname}:{pid}:{name}` | Process correlation |
| `file_key` | `{hostname}:{path}` | File correlation |
| `identity_key` | `{domain}\\{user}` or `{user}` | User correlation |
| `net_key` | `{src_ip}:{src_port}->{dest_ip}:{dest_port}` | Connection correlation |

### CanonicalEventType (shared enum)

Both pipelines produce events that map to the same canonical types:
- Process events: `process_create`, `process_exit`, `process_exec`
- File events: `file_create`, `file_read`, `file_write`, `file_delete`
- Network events: `dns_query`, `http_txn`, `net_alert`, `ssl_handshake`
- Auth events: `logon_success`, `logon_failure`, `privilege_change`

---

## Quick Reference: Which Pipeline?

| Scenario | Pipeline | Why |
|----------|----------|-----|
| HTB/THM session artifacts | UI Import | Static evidence bundle |
| Nmap scan results | UI Import | Static XML file |
| YARA scan output | UI Import | Static JSON file |
| Live Wazuh alerts | Backend | Continuous monitoring |
| Zeek logs during capture | Backend | Live correlation |
| IR evidence package | UI Import | Static bundle |
| Atomic Red Team results | UI Import | Test output files |
| Suricata alerts (file) | UI Import | Offline analysis |
| Suricata alerts (live) | Backend | Real-time monitoring |

---

## Reader Test Answers

1. **Where do UI import adapters live?**
   → `src-tauri/src/adapters/*.rs`

2. **Where do backend integration adapters live?**
   → `crates/locald/src/integrations/`

3. **Which runs on an evidence folder or ZIP?**
   → UI Import (`import_bundle` CLI → SafeImporter → Adapters)

4. **Which runs when Wazuh writes alerts to a file?**
   → Backend Import (IngestSource → VendorAlertFact)

5. **Where are import playbooks?**
   → `playbooks/import/*.yaml` (templates only, no code evaluates them yet)

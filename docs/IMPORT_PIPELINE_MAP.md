# Import Pipeline Map

This document clarifies the **two distinct import systems** in this project and when to use each.

---

## Overview: Two Import Pipelines

| Aspect | UI Import (Tauri Desktop) | Backend Import (locald integrations) |
|--------|---------------------------|--------------------------------------|
| **Purpose** | Import evidence bundles from external tools (YARA, Nmap, etc.) | Ingest live third-party alerts (Wazuh, Zeek) |
| **Entry Point** | Desktop app drag-and-drop, or `import_bundle` CLI | locald daemon integration sources |
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
| atomic | `atomic.rs` | `technique_executed` |
| evtx_json | `evtx_json.rs` | Windows event types |
| har | `har.rs` | `http_request`, `http_response` |
| jsonl | `jsonl.rs` | Passthrough |
| nmap | `nmap.rs` | `host_discovered`, `port_discovered` |
| osquery | `osquery.rs` | `process_info`, `user_info`, `listening_port` |
| plaintext | `plaintext.rs` | `shell_command`, `directory_found`, `fuzz_result` |
| suricata | `suricata.rs` | `net_alert`, `dns_query`, `http_txn` |
| velociraptor | `velociraptor.rs` | Various |
| yara | `yara.rs` | `yara_match` |
| zap | `zap.rs` | `web_vulnerability` |
| zeek | `zeek.rs` | `dns_query`, `http_txn`, `ssl_handshake` |

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
   Import playbooks (playbooks/import/*.yaml) evaluate
       ↓
   Signals emitted to timeline
```

### Key Types

```rust
// src-tauri/src/import_types.rs
pub struct ImportEvent {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub source_adapter: String,
    pub evidence_ptr: EvidencePtr,
    pub fields: HashMap<String, serde_json::Value>,
    // Entity keys for correlation
    pub host_key: Option<String>,
    pub proc_key: Option<String>,
    pub file_key: Option<String>,
    pub identity_key: Option<String>,
    pub net_key: Option<String>,
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

3. **Which runs when I drag-and-drop a folder?**
   → UI Import (Tauri SafeImporter → Adapters)

4. **Which runs when Wazuh writes alerts to a file?**
   → Backend Import (IngestSource → VendorAlertFact)

5. **Where are import playbooks?**
   → `playbooks/import/*.yaml` (evaluated by UI import pipeline)

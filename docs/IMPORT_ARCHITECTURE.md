# Import Bundle Architecture - AGENT 0

## Overview

The Import Bundle workflow allows users to analyze external telemetry bundles (folders/zips) 
without executing any imported content. All imported files are treated as untrusted bytes.

## Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  IMPORT UI (ui/index.html)                                                       │
│  - Drag/drop or choose folder/zip                                                │
│  - Show manifest summary                                                         │
│  - View timeline + entities                                                      │
│  - Export case bundle                                                            │
└─────────────────┬───────────────────────────────────────────────────────────────┘
                  │ Tauri Commands
                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  IMPORT SERVICE (src-tauri/src/importer.rs)                                      │
│  - Safe extraction (zip bombs, path traversal protection)                        │
│  - SHA256 hashing for all files                                                  │
│  - Generate manifest.json                                                        │
│  - Type allowlist filtering                                                      │
└─────────────────┬───────────────────────────────────────────────────────────────┘
                  │ ManifestFile[]
                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  ADAPTER REGISTRY (src-tauri/src/adapters/mod.rs)                                │
│  - JsonlAdapter → parse JSONL lines                                              │
│  - HarAdapter → parse HAR requests/responses                                     │
│  - ZeekAdapter → parse conn.log, dns.log, http.log                               │
└─────────────────┬───────────────────────────────────────────────────────────────┘
                  │ ImportEvent[]
                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  FACT CONVERSION (reuse existing fact_extractor)                                 │
│  - ImportEvent → Fact with EvidencePtr                                           │
│  - EvidencePtr: {bundle_id, rel_path, line_no/index}                             │
└─────────────────┬───────────────────────────────────────────────────────────────┘
                  │ Fact[]
                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  PLAYBOOK MATCHING (crates/locald SlotMatcher)                                   │
│  - Existing playbooks + new import-specific playbooks                            │
│  - Generate HypothesisState → Signals                                            │
└─────────────────┬───────────────────────────────────────────────────────────────┘
                  │ Signal[]
                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  EXPLAINABILITY (ExplanationBundle, NarrativeDoc)                                │
│  - Fill slots with matched facts                                                 │
│  - EvidencePtr dereferencing into imported files                                 │
└─────────────────┬───────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  STORAGE (workbench.db + run_dir)                                                │
│  - signals table                                                                 │
│  - signal_explanations table                                                     │
│  - imports/{bundle_id}/manifest.json, files/                                     │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
%LOCALAPPDATA%\windows-incident-compiler\
├── runs/
│   └── <run_id>/
│       ├── imports/
│       │   └── <bundle_id>/
│       │       ├── manifest.json      # File inventory + hashes
│       │       ├── files/             # Extracted files (flat or preserved structure)
│       │       └── parsed/            # Adapter output (optional cache)
│       ├── case/
│       │   ├── timeline.json          # Aggregated events
│       │   ├── entities.json          # Entity index
│       │   ├── signals.json           # Detected signals
│       │   └── explanations/          # Per-signal explain bundles
│       ├── metrics/
│       │   └── metrics_<timestamp>.json
│       └── logs/
└── workbench.db
```

## File Touch List & Ownership

### AGENT 1 - SAFE-IMPORT
- **NEW**: `src-tauri/src/importer.rs` - Safe extraction + manifest generation
- **NEW**: `src-tauri/src/import_types.rs` - Shared import types
- **MOD**: `src-tauri/src/main.rs` - Add Tauri commands
- **MOD**: `src-tauri/src/lib.rs` - Register modules

### AGENT 2 - ADAPTER-JSONL
- **NEW**: `src-tauri/src/adapters/mod.rs` - Adapter trait + registry
- **NEW**: `src-tauri/src/adapters/jsonl.rs` - JSONL parser

### AGENT 3 - ADAPTER-HAR
- **NEW**: `src-tauri/src/adapters/har.rs` - HAR parser

### AGENT 4 - ADAPTER-ZEEK
- **NEW**: `src-tauri/src/adapters/zeek.rs` - Zeek log parser

### AGENT 5 - PLAYBOOKS
- **NEW**: `playbooks/import/signal_web_brute_force.yaml`
- **NEW**: `playbooks/import/signal_suspicious_download.yaml`
- **NEW**: `playbooks/import/signal_dns_tunneling.yaml`
- **NEW**: `playbooks/import/signal_beaconing.yaml`
- **NEW**: `playbooks/import/signal_credential_stuffing.yaml`
- **NEW**: `playbooks/import/*.yaml` (~10 playbooks)

### AGENT 6 - UI/UX
- **MOD**: `ui/index.html` - Import panel, cases view, export
- **MOD**: `ui/app.js` - Import handlers (if separate)

### AGENT 7 - METRICS/GATES
- **MOD**: `src-tauri/src/grounded_gates.rs` - Extend for imports

## Core Types (in src-tauri/src/import_types.rs)

```rust
// Import manifest entry
pub struct ManifestFile {
    pub rel_path: String,
    pub sha256: String,
    pub bytes: u64,
    pub kind: FileKind,
    pub parsed: bool,
    pub parser: Option<String>,
    pub warnings: Vec<String>,
}

// Import event (adapter output)
pub struct ImportEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub timestamp_quality: TimestampQuality,
    pub event_type: String,
    pub source_file: String,
    pub source_line: Option<u64>,
    pub fields: HashMap<String, Value>,
    pub evidence_ptr: ImportEvidencePtr,
}

// Evidence pointer for imports
pub struct ImportEvidencePtr {
    pub bundle_id: String,
    pub rel_path: String,
    pub line_no: Option<u64>,
    pub json_path: Option<String>,
}
```

## Security Model

1. **Path Traversal Protection**
   - Reject paths with `..`, absolute paths, drive letters, UNC paths
   - Normalize and validate all paths before extraction

2. **Zip Bomb Protection**
   - Max total uncompressed: 2GB (configurable)
   - Max files: 50,000
   - Max depth: 16 levels
   - Max single file: 200MB
   - Max compression ratio: 200:1

3. **No Execution**
   - Never shell out to paths in imported content
   - No dynamic code loading from imports
   - Parse only - read bytes, extract structure

4. **Type Allowlist**
   - Parsed: json, jsonl, yaml, yml, txt, csv, har, log, conn.log, dns.log, http.log
   - Stored (not parsed): pcap, pcapng, evtx
   - Everything else: rejected or stored as "unknown"

## Integration Points

### EvidencePtr Reuse
The existing `EvidencePtr` in `crates/core/src/evidence_ptr.rs` uses:
- `stream_id` → for imports: `import:<bundle_id>`
- `segment_id` → for imports: hash of rel_path
- `record_index` → for imports: line number or entry index

### ExplanationBundle Integration
Existing explain flow works unchanged - EvidencePtr derefs by:
1. Check if stream_id starts with "import:"
2. Extract bundle_id, look up manifest
3. Read file, extract line/entry
4. Return excerpt for display

### Metrics v3.x Gates
Extended to handle import runs:
- Gate 1 (Telemetry) → imported_files_total, parsed_files_total
- Gate 2 (Extraction) → events_count, facts_count
- Gate 3 (Detection) → signals_count, playbooks_matched
- Gate 4 (Explainability) → explain_valid_rate, evidence_deref_rate

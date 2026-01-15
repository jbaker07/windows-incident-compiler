# LocInt System Explanation (Part 1/3): Real Telemetry → Canonical Events

> **Audience:** Engineers, SOC analysts. Evidence-first, no hand-waving.  
> **Last Updated:** 2026-01-13  
> **Scope:** Architecture, WEVTAPI polling, attack surface normalization, canonical event writing.

---

## Source of Truth Pointers

This document references the following authoritative files. When in doubt, these are the ground truth:

| Topic | Authoritative File |
|-------|-------------------|
| WEVTAPI polling + dedupe | `crates/agent-windows/src/wevt_reader.rs` |
| Bookmark persistence | `crates/agent-windows/src/wevt_bookmarks.rs` |
| Attack surface routing | `crates/agent-windows/src/sensors/attack_surface.rs` |
| Coverage mapping | `docs/WINDOWS_V1_COVERAGE_MAP.md` |
| Safe validation triggers | `VALIDATION_RUN.md` |
| API routes | `docs/parity/routes_snapshot.json` |
| API contract | `docs/parity/contract_snapshot.json` |

---

## 1. Product Overview

**LocInt** (Local Incident Compiler) is a local-first, evidence-first incident detection system for Windows. It:

- Polls **real Windows Event Logs** via WEVTAPI (no simulated telemetry, no invented evidence)
- Normalizes events into canonical format
- Compiles evidence into deterministic findings (signals) with full explainability
- Runs entirely on-host with no cloud dependency

### What is a "Run"?

A **run** is a time-bounded telemetry capture session:

1. The capture binary polls Windows Event Logs and writes JSONL segment files
2. The compiler watches for new segments and transforms them into facts → hypotheses → signals
3. Results are stored in a local SQLite database
4. The UI queries the database via HTTP API

Each run produces an immutable evidence trail: segment files, an index manifest, and a run database.

A run is bounded by explicit start/stop commands (via UI or API). There is no automatic duration limit unless configured externally.

---

## 2. Components / Binaries

| Binary | Responsibility |
|--------|----------------|
| `capture_windows_rotating.exe` | WEVTAPI polling, event normalization, JSONL segment writing |
| `edr-locald.exe` | Segment compiler: canonical events → facts → signals, playbook evaluation |
| `locint.exe` | HTTP API server, UI serving, real-time capability probing |

### Output Artifacts

```
<telemetry_root>/
├── index.json                 # Segment manifest (written by capture)
├── segments/
│   ├── 000001.jsonl           # JSONL: one canonical event per line
│   ├── 000002.jsonl
│   └── ...
├── heartbeat.json             # Capture health metrics
├── run_meta.json              # Run metadata + capability snapshot
└── workbench.db               # SQLite: signals, explanations, rollup tables
```

**Immutability note:** Segment JSONL files are append-only during capture—once written, records are not modified. The `workbench.db` database is derived from segments and is modified during compilation (inserts/updates). Evidence integrity depends on segment file preservation.

---

## 3. Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         WINDOWS HOST                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────┐                                                 │
│  │ Windows Event Logs  │                                                 │
│  │  • Security         │                                                 │
│  │  • System           │                                                 │
│  │  • Sysmon/Op        │                                                 │
│  │  • PowerShell/Op    │                                                 │
│  │  • WMI-Activity/Op  │                                                 │
│  │  • TaskScheduler/Op │                                                 │
│  │  • WinRM/Op         │                                                 │
│  └─────────┬───────────┘                                                 │
│            │                                                             │
│            │ EvtQuery + EvtNext (WEVTAPI)                                │
│            ▼                                                             │
│  ┌─────────────────────────────────────────┐                             │
│  │ capture_windows_rotating.exe            │                             │
│  │                                         │                             │
│  │  wevt_reader.rs:                        │                             │
│  │   • poll() each enabled channel         │                             │
│  │   • Per-channel dedupe (HashSet + LRU)  │                             │
│  │   • Bookmark resumption (if configured) │                             │
│  │                                         │                             │
│  │  attack_surface.rs:                     │                             │
│  │   • normalize_to_attack_surface()       │                             │
│  │   • Route by (channel, event_id)        │                             │
│  │   • parse_* → canonical event tags      │                             │
│  │                                         │                             │
│  │  capture_windows_rotating.rs:           │                             │
│  │   • Assign EvidencePtr (segment:offset) │                             │
│  │   • Write JSONL segment + update index  │                             │
│  └─────────┬───────────────────────────────┘                             │
│            │                                                             │
│            ▼ segments/*.jsonl + index.json                               │
│  ┌─────────────────────────────────────────┐                             │
│  │ <telemetry_root>/segments/              │                             │
│  │                                         │                             │
│  │ Each line is a canonical edr_core::Event│                             │
│  │ with evidence_ptr assigned              │                             │
│  └─────────────────────────────────────────┘                             │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Real Telemetry Ingestion (WEVTAPI)

### 4.1 Channels Polled

`capture_windows_rotating.exe` uses `wevt_reader.rs` to poll these Windows Event Log channels:

| Channel | Purpose | Prerequisites |
|---------|---------|---------------|
| `Security` | Auth (4624), process creation (4688), log clear (1102), tasks (4698) | **Admin required** |
| `System` | Service install (7045), log clear (104) | None |
| `Microsoft-Windows-Sysmon/Operational` | Process (1), network (3), registry (12–14), WMI (19–21), file (11), process access (10) | **Sysmon installed** |
| `Microsoft-Windows-PowerShell/Operational` | Script block logging (4103, 4104) | PowerShell logging enabled |
| `Microsoft-Windows-WMI-Activity/Operational` | WMI activity | None |
| `Microsoft-Windows-TaskScheduler/Operational` | Task registration (106) | None |
| `Microsoft-Windows-WinRM/Operational` | Remote management (91) | None |

> **Source:** `wevt_reader.rs` → `WevtReader::new()` defines the channel list.

### 4.2 "Channel Accessible" Meaning

A channel is **accessible** if WEVTAPI `EvtQuery` succeeds. Common failure reasons:

| Error Code | Meaning | Typical Cause |
|------------|---------|---------------|
| `0x80070005` | `ACCESS_DENIED` | Not running as Administrator |
| `0x80070003` | `CHANNEL_NOT_FOUND` | Sysmon not installed, or channel name invalid |
| `0x00001069` | `CHANNEL_DISABLED` | Channel disabled via GPO or `wevtutil` |

The `/api/capability/status` endpoint probes each channel and reports `accessible: true/false` with a `reason` field for failures.

### 4.3 Per-Channel Dedupe

**Location:** `wevt_reader.rs` → `WevtReader::is_duplicate()`

**Mechanism:**

1. Each channel maintains a `(HashSet<u64>, VecDeque<u64>)` tuple
2. The `HashSet` provides O(1) membership check by `source_record_id`
3. The `VecDeque` provides LRU eviction (keeps last 1000 record IDs per channel)
4. On poll, each event's `source_record_id` is checked; duplicates are skipped

**What this guarantees:**
- Tail overlap protection: if the capture binary restarts and re-queries recent events, the HashSet rejects already-seen record IDs
- Bounded memory: only the last 1000 record IDs per channel are tracked

**What this does NOT guarantee:**
- Full restart idempotency across long downtime (records may have scrolled past the 1000-entry window)

### 4.4 Bookmark Persistence

**Location:** `wevt_bookmarks.rs` → `WevtBookmarkManager`

The bookmark manager persists per-channel WEVTAPI bookmark XML to `wevt_bookmarks.json`. This allows resumption from the last-read position on restart.

**Behavior:**
- Bookmarks are loaded at startup if the file exists
- After processing events, bookmarks are updated and persisted atomically (write to `.tmp`, then rename)
- Each channel entry stores: `bookmark_xml`, `last_event_ts`, `last_source_record_id`, `total_events_processed`

> **Caution:** Bookmark behavior depends on `use_bookmarks` config flag per channel. See `wevt_reader.rs` for exact semantics.

### 4.5 Missing or Blocked Channels

| Scenario | Behavior |
|----------|----------|
| Channel not installed (e.g., Sysmon) | `EvtQuery` fails; channel marked `accessible: false`; zero events from that channel |
| Channel blocked (ACCESS_DENIED) | Same as above; `/api/capability/status` reports `reason: "ACCESS_DENIED"` |
| Channel exists but empty | No events returned; not an error |

**Impact:**
- Security log blocked → near-zero auth/persistence facts
- Sysmon missing → no process command lines, network connections, or file hashes

---

## 5. Attack Surface Normalization

### 5.1 Location

`crates/agent-windows/src/sensors/attack_surface.rs`

### 5.2 Routing Model

The function `normalize_to_attack_surface(event: &Event) -> Vec<Event>` routes by `(channel, event_id, provider)`:

```rust
match (channel, event_id, provider) {
    // Process Execution
    ("Microsoft-Windows-Sysmon/Operational", 1, _) => parse_proc_exec(event),
    ("Security", 4688, _) => parse_proc_exec(event),
    
    // Network
    ("Microsoft-Windows-Sysmon/Operational", 3, _) => parse_network_connect(event),
    
    // Persistence
    ("System", 7045, _) | ("Security", 4697, _) => parse_persistence_service(event),
    ("Security", 4698, _) | ("Security", 4702, _) => parse_persistence_task(event),
    
    // ... and so on
    _ => {} // Unrouted events produce no canonical output
}
```

Each `parse_*` function:
1. Extracts relevant fields from the raw event
2. Builds a new canonical event with appropriate tags (e.g., `["windows", "process_exec"]`)
3. Preserves evidence fields (`windows.channel`, `windows.event_id`, etc.)

### 5.3 Windows v1 Required Surfaces (Summary)

The v1 definition requires coverage for:

| Surface | Primary Sources |
|---------|-----------------|
| Process Execution | Sysmon 1, Security 4688 |
| Network Egress | Sysmon 3 |
| Credential/Process Access | Sysmon 10 |
| Persistence (Service) | System 7045, Security 4697 |
| Persistence (Task) | Security 4698/4702, TaskScheduler 106 |
| Persistence (Registry) | Sysmon 12/13/14, Security 4657 |
| PowerShell Execution | PowerShell 4103/4104 |
| Log Tampering | Security 1102, System 104 |

> **Full mapping:** See `docs/WINDOWS_V1_COVERAGE_MAP.md` for the complete matrix including prerequisites and parser functions.

---

## 6. Canonical Events + Evidence Pointers

### 6.1 What is a Canonical Event?

A **canonical event** (`edr_core::Event`) is a platform-agnostic, normalized representation of a security-relevant activity:

```rust
pub struct Event {
    pub ts_ms: i64,                              // Unix timestamp (ms)
    pub host: String,                            // Hostname
    pub tags: Vec<String>,                       // e.g., ["windows", "process_exec"]
    pub proc_key: Option<String>,                // Process identity key
    pub file_key: Option<String>,                // File identity key
    pub identity_key: Option<String>,            // User identity key
    pub evidence_ptr: Option<EvidencePtr>,       // Pointer to segment record
    pub fields: BTreeMap<String, Value>,         // Structured fields
}
```

**Purpose:** Decouples detection logic from platform-specific event formats. Playbooks match on canonical tags, not raw Windows XML.

### 6.2 Evidence Fields

Every canonical event carries these evidence fields in `fields`:

| Field Key | Source | Purpose |
|-----------|--------|---------|
| `windows.channel` | WEVTAPI | Which log channel (e.g., "Security") |
| `windows.provider` | WEVTAPI | Event provider name |
| `windows.event_id` | WEVTAPI | Windows Event ID (e.g., 4688) |
| `windows.source_record_id` | WEVTAPI | Channel-local record ID (for dedupe/debug) |
| `windows.computer` | WEVTAPI | Source computer name |

### 6.3 EvidencePtr Structure

```rust
pub struct EvidencePtr {
    pub stream_id: String,    // Stream identifier (e.g., "windows_evtx")
    pub segment_id: u64,      // Segment sequence number
    pub record_index: u32,    // 0-based line offset in segment JSONL
}
```

**Semantics:**
- `stream_id` identifies the telemetry stream (not the channel name)
- `segment_id` references the segment file sequence number
- `record_index` is a **0-based line offset**—to dereference, read the segment file and retrieve the line at that index

**Assignment:** `EvidencePtr` is assigned in the capture binary when writing to segment JSONL. The `wevt_reader.rs` output has `evidence_ptr: None`—this ensures evidence pointers are tied to immutable segment records.

**Dereferencing:** To retrieve the raw event from an `EvidencePtr`:
1. Locate `segments/{segment_id}.jsonl`
2. Read line at 0-based offset `record_index`
3. Parse JSON to get the full event with all fields

> **Source of truth:** `crates/server/src/services/evidence.rs` → `dereference_evidence()`

---

## 7. Segment Writing

### 7.1 Segment Format

Each segment file is newline-delimited JSON (JSONL):

```json
{"ts_ms":1736784000000,"host":"WORKSTATION01","tags":["windows","process_exec"],"evidence_ptr":{"stream_id":"Security","segment_id":1,"record_index":0},"fields":{...}}
{"ts_ms":1736784001000,"host":"WORKSTATION01","tags":["windows","network_connect"],"evidence_ptr":{"stream_id":"Microsoft-Windows-Sysmon/Operational","segment_id":1,"record_index":1},"fields":{...}}
```

### 7.2 Index Manifest

`index.json` tracks all segments:

```json
{
  "schema_version": 1,
  "next_seq": 3,
  "segments": [
    {"seq": 1, "segment_id": "000001", "rel_path": "segments/000001.jsonl", ...},
    {"seq": 2, "segment_id": "000002", "rel_path": "segments/000002.jsonl", ...}
  ],
  "last_updated_ts": 1736784000000
}
```

The compiler (`edr-locald.exe`) watches this file for new segment entries.

### 7.3 Heartbeat

`heartbeat.json` provides capture health metrics:

```json
{
  "ts": "2026-01-13T10:00:00Z",
  "transport": "wevtapi",
  "source": "windows_evtx",
  "events_read_total": 1500,
  "events_read_delta": 50,
  "status": "running"
}
```

---

## 8. Summary: Part 1 Scope

This part covered:

- ✅ What LocInt is and what a "run" means
- ✅ The three binaries and their responsibilities
- ✅ Data flow from Windows Event Logs through WEVTAPI to JSONL segments
- ✅ Channel accessibility, dedupe mechanism, and bookmark persistence
- ✅ Attack surface normalization routing model
- ✅ Canonical event structure and evidence pointer semantics

**Next:** Part 2 covers the full Windows v1 coverage matrix, cross-source overlap policy, and validation hooks.

---

*This document describes the system as implemented. If behavior differs, consult the authoritative source files listed at the top.*

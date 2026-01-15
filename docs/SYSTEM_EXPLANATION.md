# LocInt System Explanation: End-to-End Data Flow

> **Audience:** Engineers, SOC analysts. Evidence-first, no hand-waving.
> **Last Updated:** 2026-01-13

---

## 1. Product Overview

**LocInt** (Local Incident Compiler) is a local-first, evidence-first incident detection system for Windows. It compiles real telemetry from Windows Event Logs into deterministic findings (signals) with full explainability. A **"run"** is a time-bounded telemetry capture session: the capture binary polls Windows Event Logs, writes JSONL segments, and the compiler transforms those segments into facts, hypotheses, and finally signals stored in SQLite. The UI queries this database via HTTP API. There is no cloud dependency, no simulated telemetry, and no invented evidence.

---

## 2. Binaries and Responsibilities

| Binary | Location | Responsibility | Inputs | Outputs |
|--------|----------|----------------|--------|---------|
| `capture_windows_rotating.exe` | `target/release/` | WEVTAPI polling, event normalization, segment writing | Windows Event Logs (7 channels) | `segments/*.jsonl`, `index.json`, `heartbeat.json` |
| `edr-locald.exe` | `target/release/` | Segment compiler: events → facts → signals, playbook evaluation | `index.json`, `segments/*.jsonl`, `playbooks/*.yaml` | `workbench.db` (signals, explanations, rollup tables) |
| `locint.exe` | `target/release/` | HTTP API server, UI serving, capability probing | `workbench.db`, real-time channel probes | HTTP JSON responses on port 3000 (default) |

### Output Artifacts

```
<telemetry_root>/
├── index.json                 # Segment manifest (written by capture)
├── segments/
│   ├── 000001.jsonl           # JSONL: one line per canonical event
│   ├── 000002.jsonl
│   └── ...
├── heartbeat.json             # Capture health metrics
├── run_meta.json              # Run metadata + capability snapshot
└── workbench.db               # SQLite: signals, explanations, rollup tables
```

---

## 3. Data Flow Diagram (ASCII)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            WINDOWS HOST                                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌────────────────────┐                                                          │
│  │ Windows Event Logs │                                                          │
│  │  • Security        │                                                          │
│  │  • System          │                                                          │
│  │  • Sysmon/Op       │                                                          │
│  │  • PowerShell/Op   │                                                          │
│  │  • WMI-Activity/Op │                                                          │
│  │  • TaskScheduler   │                                                          │
│  │  • WinRM/Op        │                                                          │
│  └────────┬───────────┘                                                          │
│           │ EvtQuery + EvtNext (WEVTAPI)                                         │
│           ▼                                                                      │
│  ┌────────────────────────────────────────┐                                      │
│  │ capture_windows_rotating.exe           │                                      │
│  │  • wevt_reader.rs: poll()              │                                      │
│  │  • Per-channel dedupe (HashSet + LRU)  │                                      │
│  │  • attack_surface.rs: normalize()      │                                      │
│  │  • Assign EvidencePtr (segment:record) │                                      │
│  └────────┬───────────────────────────────┘                                      │
│           │                                                                      │
│           ▼ JSONL segments + index.json                                          │
│  ┌────────────────────────────────────────┐                                      │
│  │ <telemetry_root>/segments/*.jsonl      │                                      │
│  │  {"ts_ms":..,"host":..,"tags":[..],    │                                      │
│  │   "fields":{..},"evidence_ptr":{..}}   │                                      │
│  └────────┬───────────────────────────────┘                                      │
│           │                                                                      │
│           ▼ Reads via index.json watch                                           │
│  ┌────────────────────────────────────────┐                                      │
│  │ edr-locald.exe                         │                                      │
│  │  • Parse segment JSONL                 │                                      │
│  │  • extract_facts() → Fact structs      │                                      │
│  │  • HypothesisController.ingest_fact()  │                                      │
│  │  • Playbook slot matching              │                                      │
│  │  • Incident promotion                  │                                      │
│  │  • ExplanationBundle construction      │                                      │
│  └────────┬───────────────────────────────┘                                      │
│           │                                                                      │
│           ▼ SQLite writes (WAL mode)                                             │
│  ┌────────────────────────────────────────┐                                      │
│  │ workbench.db                           │                                      │
│  │  • signals                             │                                      │
│  │  • signal_explanations                 │                                      │
│  │  • coverage_rollup                     │                                      │
│  │  • entity_rollup                       │                                      │
│  │  • playbook_eval_rollup                │                                      │
│  │  • segments                            │                                      │
│  └────────┬───────────────────────────────┘                                      │
│           │                                                                      │
│           ▼ HTTP queries                                                         │
│  ┌────────────────────────────────────────┐                                      │
│  │ locint.exe (HTTP :3000)                │                                      │
│  │  GET /api/runs                         │                                      │
│  │  GET /api/signals                      │                                      │
│  │  GET /api/signals/:id/explain          │                                      │
│  │  GET /api/capability/status            │                                      │
│  └────────┬───────────────────────────────┘                                      │
│           │                                                                      │
│           ▼ JSON responses                                                       │
│  ┌────────────────────────────────────────┐                                      │
│  │ UI (browser)                           │                                      │
│  │  • Runs list                           │                                      │
│  │  • Signal details + explanations       │                                      │
│  │  • Coverage checklist                  │                                      │
│  │  • Capability gaps                     │                                      │
│  └────────────────────────────────────────┘                                      │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Real Telemetry Ingestion (WEVTAPI)

### 4.1 Channels Polled

`capture_windows_rotating.exe` uses `wevt_reader.rs` to poll these Windows Event Log channels:

| Channel | Purpose | Admin Required | Sysmon Required |
|---------|---------|----------------|-----------------|
| `Security` | Auth events (4624, 4625), process creation (4688), log clear (1102), task creation (4698) | **Yes** | No |
| `System` | Service installation (7045), log clear (104) | No | No |
| `Microsoft-Windows-Sysmon/Operational` | Process (1), network (3), registry (12-14), WMI (19-21), file (11), process access (10) | No | **Yes** |
| `Microsoft-Windows-PowerShell/Operational` | Script block logging (4103, 4104) | No | No |
| `Microsoft-Windows-WMI-Activity/Operational` | WMI activity (future use) | No | No |
| `Microsoft-Windows-TaskScheduler/Operational` | Task registration (106) | No | No |
| `Microsoft-Windows-WinRM/Operational` | Remote management (91) | No | No |

### 4.2 "Channel Accessible" Meaning

A channel is **accessible** if WEVTAPI `EvtQuery` succeeds. Common failures:

| Error Code | Meaning | Cause |
|------------|---------|-------|
| `0x80070005` | `ACCESS_DENIED` | Not running as admin; Security log blocked |
| `0x80070003` | `CHANNEL_NOT_FOUND` | Sysmon not installed, or channel name typo |
| `0x00001069` | `CHANNEL_DISABLED` | Channel disabled via GPO or wevtutil |

The `/api/capability/status` endpoint probes each channel and reports `accessible: true/false` with `reason` for failures.

### 4.3 Per-Channel Dedupe

**Location:** [wevt_reader.rs](../crates/agent-windows/src/wevt_reader.rs) → `WevtReader::is_duplicate()`

**Mechanism:**
- Each channel maintains a `(HashSet<u64>, VecDeque<u64>)` tuple.
- The `HashSet` provides O(1) membership check by `source_record_id`.
- The `VecDeque` provides LRU eviction (keeps last 1000 record IDs per channel).
- On poll, each event's `source_record_id` is checked; duplicates are skipped.
- This prevents re-ingesting events if the capture binary restarts.

**Why it prevents duplicates:**
- Windows Event Logs assign monotonically increasing `EventRecordID` per channel.
- On restart, the reader may re-query recent events; the HashSet membership check rejects them.

### 4.4 Missing or Blocked Channels

| Scenario | Behavior |
|----------|----------|
| Channel not installed (e.g., Sysmon) | `EvtQuery` fails; channel marked `accessible: false`; zero events from that channel |
| Channel blocked (ACCESS_DENIED) | Same as above; `/api/capability/status` reports `reason: "ACCESS_DENIED"` |
| Channel exists but empty | No events returned; not an error |

**Impact:** If Security log is blocked, you get near-zero authentication/persistence facts. If Sysmon is missing, you lose process command lines, network connections, and file hashes.

---

## 5. Canonical Events + Evidence (`edr_core::Event`)

### 5.1 What is a Canonical Event?

A **canonical event** is a platform-agnostic, normalized representation of a security-relevant activity. It abstracts Windows-specific XML into a consistent structure with:

```rust
pub struct Event {
    pub ts_ms: i64,              // Unix timestamp (milliseconds)
    pub host: String,            // Hostname
    pub tags: Vec<String>,       // e.g., ["windows", "process_exec"]
    pub proc_key: Option<String>,
    pub file_key: Option<String>,
    pub identity_key: Option<String>,
    pub evidence_ptr: Option<EvidencePtr>,  // Pointer to raw segment record
    pub fields: BTreeMap<String, Value>,    // Structured fields
}
```

**Purpose:** Decouples detection logic from platform-specific event formats. Playbooks match on canonical event tags, not raw XML.

### 5.2 Evidence Fields

Every canonical event carries these evidence fields in `fields`:

| Field Key | Source | Purpose |
|-----------|--------|---------|
| `windows.channel` | WEVTAPI | Which log channel (e.g., "Security") |
| `windows.provider` | WEVTAPI | Event provider GUID/name |
| `windows.event_id` | WEVTAPI | Windows Event ID (e.g., 4688) |
| `windows.source_record_id` | WEVTAPI | Channel-local record ID (for dedupe/debug) |
| `windows.computer` | WEVTAPI | Source computer name |

### 5.3 EvidencePtr Structure

```rust
pub struct EvidencePtr {
    pub stream_id: String,    // e.g., "windows_evtx"
    pub segment_id: u64,      // Segment sequence number
    pub record_index: u32,    // Line number within segment JSONL
}
```

**Assignment:** `EvidencePtr` is assigned **only** in `capture_windows_rotating.rs` when writing to segment JSONL. The `wevt_reader.rs` output has `evidence_ptr: None`—this is intentional to ensure evidence pointers are tied to immutable segment records.

**Dereferencing:** To retrieve the raw event from an `EvidencePtr`:
1. Open `segments/{segment_id}.jsonl`
2. Read line `record_index`
3. Parse JSON to get full event with all fields

---

## 6. Attack Surface Parsing (`attack_surface.rs`)

### 6.1 Location

[crates/agent-windows/src/sensors/attack_surface.rs](../crates/agent-windows/src/sensors/attack_surface.rs)

### 6.2 Routing Model

The function `normalize_to_attack_surface(event: &Event) -> Vec<Event>` routes by `(channel, event_id, provider)`:

```rust
match (channel, event_id, provider) {
    ("Microsoft-Windows-Sysmon/Operational", 1, _) | ("Security", 4688, _) => parse_proc_exec(event),
    ("Microsoft-Windows-Sysmon/Operational", 3, _) => parse_network_connect(event),
    ("Microsoft-Windows-Sysmon/Operational", 10, _) => parse_proc_access(event),
    ("System", 7045, _) | ("Security", 4697, _) => parse_persistence_service(event),
    // ... etc
}
```

### 6.3 Sensor Monitor Modules

Some codebase files may reference "sensor monitors" (e.g., `registry_monitor.rs`). These are **delegators, not pollers**. They do not directly read from Windows Event Logs. All real polling happens in `wevt_reader.rs`. The monitors may provide tag enrichment or field normalization but are not the source of events.

### 6.4 v1 Coverage Matrix

| Attack Surface | Channel(s) | Event ID(s) | Parser Function | Canonical Tag | Prerequisites |
|----------------|------------|-------------|-----------------|---------------|---------------|
| **Process Execution** | Sysmon | 1 | `parse_proc_exec` | `process_exec` | Sysmon |
| | Security | 4688 | `parse_proc_exec` | `process_exec` | Admin + Audit Policy |
| **Network Egress** | Sysmon | 3 | `parse_network_connect` | `network_connect` | Sysmon |
| **Process Access (LSASS)** | Sysmon | 10 | `parse_proc_access` | `proc_access` | Sysmon |
| **Persistence: Service** | System | 7045 | `parse_persistence_service` | `persistence_service` | None |
| | Security | 4697 | `parse_persistence_service` | `persistence_service` | Admin |
| **Persistence: Task** | Security | 4698, 4702 | `parse_persistence_task` | `persistence_task` | Admin |
| | TaskScheduler | 106 | `parse_persistence_task_operational` | `persistence_task` | None |
| **Persistence: Registry** | Sysmon | 12, 13, 14 | `parse_registry_mod` | `registry_mod` | Sysmon |
| | Security | 4657 | `parse_registry_mod` | `registry_mod` | Admin + Audit Policy |
| **Persistence: WMI** | Sysmon | 19, 20, 21 | `parse_wmi_persistence` | `wmi_persistence` | Sysmon |
| **PowerShell Execution** | PowerShell | 4103, 4104 | `parse_powershell_exec` | `powershell_exec` | ScriptBlock Logging |
| **Log Tampering** | Security | 1102 | `parse_log_clear` | `log_clear` | Admin |
| | System | 104 | `parse_log_clear` | `log_clear` | None |
| **Lateral Movement: RDP** | Security | 4624 (Type=10) | `parse_remote_logon_rdp` | `remote_logon_rdp` | Admin |
| **Lateral Movement: WinRM** | WinRM | 91 | `parse_remote_winrm` | `remote_winrm` | None |
| **Privilege Escalation** | Security | 4672 | `parse_priv_escalation` | `priv_elevation` | Admin |
| **File Creation** | Sysmon | 11 | `parse_file_create` | `file_create` | Sysmon |
| **Defense Prevention** | Defender | 1121 | `parse_asr_block` | `asr_block` | Defender ASR |

---

## 7. Compilation: Events → Facts → Signals → Incidents

### 7.1 Where the Compiler Reads From

`edr-locald.exe` watches `<telemetry_root>/index.json` for new segment entries. When a new segment appears, it reads the corresponding JSONL file from `segments/`.

### 7.2 Facts

A **Fact** is a normalized assertion about an observed activity. Examples:

| Fact Type | Description |
|-----------|-------------|
| `ProcSpawn` | Process A spawned process B |
| `Exec` | Process executed at path X |
| `OutboundConnect` | Process connected to IP:port |
| `RegistryMod` | Registry key modified |
| `AuthEvent` | User authentication event |
| `LogTamper` | Security log cleared |

Facts are extracted by `extract_facts()` in [crates/locald/src/os/windows/fact_extractor.rs](../crates/locald/src/os/windows/fact_extractor.rs).

### 7.3 Signals

A **Signal** is a fired detection result. Signals come from:
- **Playbook-based:** `HypothesisController` promotes hypotheses to incidents when all playbook slots match.
- **Rule-based:** Direct pattern matching (legacy `WindowsSignalEngine`).

Signals are stored in `workbench.db` with:
- `signal_id`: Unique identifier
- `signal_type`: e.g., `playbook:lolbin_execution`
- `severity`: `Low | Medium | High | Critical`
- `evidence_ptrs`: Array of `EvidencePtr` pointing to source events

### 7.4 Incidents

An **Incident** is a promoted hypothesis that satisfied all playbook slots. It includes:
- `incident_id`: Derived from playbook + scope
- `family`: Detection category (e.g., "credential_access")
- `mitre_techniques`: ATT&CK technique IDs
- `evidence_ptrs_summary`: Evidence pointers from matched facts

### 7.5 workbench.db Tables

| Table | Purpose | UI Consumer |
|-------|---------|-------------|
| `signals` | All fired signals with metadata | `/api/signals`, `/api/runs/:id` |
| `signal_explanations` | ExplanationBundle JSON per signal | `/api/signals/:id/explain` |
| `coverage_rollup` | Fact type/signal counts per minute | Coverage checklist |
| `entity_rollup` | Top-N entities (process, user, network, file) per run | Entity pivot view |
| `playbook_eval_rollup` | Per-playbook slot progress and status | Playbook status page |
| `segments` | Processed segment metadata | Run stats |
| `locald_checkpoint` | Resume state (seen segments) | Internal |

---

## 8. Capability Model: Configured vs Active vs Observed

### 8.1 Definitions

| Term | Meaning |
|------|---------|
| **Configured** | The system is set up to attempt this capability. The channel is in `wevt_reader.rs` channel list, parsers exist in `attack_surface.rs`. |
| **Active / Accessible** | WEVTAPI can read the channel **right now**. Probed via `wevtutil qe <channel> /c:1`. |
| **Observed** | Matching events were **actually seen** during this run window. Requires telemetry to have flowed. |

### 8.2 Status Codes for UI

| Status | UI Representation | Cause |
|--------|-------------------|-------|
| `ACCESSIBLE` | ✅ Green | Channel readable, parsers present |
| `BLOCKED` | ❌ Red + "Admin required" | `ACCESS_DENIED` (0x80070005) |
| `NOT_INSTALLED` | ⚠️ Amber + "Sysmon required" | `CHANNEL_NOT_FOUND` (Sysmon missing) |
| `DISABLED` | ⚠️ Amber | Channel disabled via GPO |
| `UNSUPPORTED` | 🔒 Gray | No parser in `attack_surface.rs` |
| `NOT_OBSERVED` | ○ Empty | Channel accessible but no events this run |
| `FEATURE_LOCKED` | 🔒 Pro/Team badge | Tier-gated feature (e.g., diff, baseline) |

### 8.3 API Response Example

`GET /api/capability/status`:

```json
{
  "is_admin": true,
  "sysmon_installed": true,
  "security_log_accessible": true,
  "overall_status": "full",
  "channels": [
    {
      "name": "Security",
      "accessible": true,
      "reason": null,
      "supported": true,
      "supported_event_ids": [1102, 4624, 4657, 4672, 4688, 4697, 4698, 4702]
    },
    {
      "name": "Microsoft-Windows-Sysmon/Operational",
      "accessible": true,
      "reason": null,
      "supported": true,
      "supported_event_ids": [1, 3, 10, 11, 12, 13, 14, 19, 20, 21]
    }
  ]
}
```

---

## 9. HTTP API → UI Wiring

### 9.1 Router Architecture

`locint.exe` is a thin Axum router. All business logic lives in service modules:

| Module | Path | Purpose |
|--------|------|---------|
| `services/run_control.rs` | `/api/runs/*` | Run CRUD, status, metrics |
| `services/signals.rs` | `/api/signals/*` | Signal list, detail, explain |
| `services/capability.rs` | `/api/capability/*` | Capability probes, detection plan |
| `services/evidence.rs` | `/api/evidence/deref` | Evidence pointer dereferencing |
| `services/packs.rs` | `/api/packs/*`, `/api/playbooks/*` | Playbook catalog |
| `services/meta.rs` | `/api/meta/*`, `/api/features` | Routes, contracts, features |
| `services/export_import.rs` | `/api/export/*`, `/api/import/*` | Bundle export/import |
| `team/cases.rs` | `/api/team/cases/*` | Team case management (Team tier) |
| `team/store.rs` | `/api/team/store/*` | Team store configuration (Team tier) |

### 9.2 Key Endpoints

| Endpoint | Method | Description | Tier |
|----------|--------|-------------|------|
| `/api/selfcheck` | GET | System health + capability snapshot | Free |
| `/api/runs` | GET | List all runs | Free |
| `/api/runs/:run_id` | GET | Run details + signal summary | Free |
| `/api/runs/:run_id/coverage` | GET | Coverage rollup for run | Free |
| `/api/signals` | GET | List signals (filterable) | Free |
| `/api/signals/:id` | GET | Signal detail | Free |
| `/api/signals/:id/explain` | GET | ExplanationBundle for signal | Free |
| `/api/capability/status` | GET | Real-time capability probe | Free |
| `/api/capability/gaps` | GET | Missing capabilities (Dev only) | Dev |
| `/api/runs/:run_id/baseline` | POST | Set baseline for diffing | Pro |
| `/api/runs/:run_id/diff` | GET | Delta vs baseline | Pro |
| `/api/team/cases` | GET/POST | Team case management | Team |

### 9.3 Tier Gating

Tier-gated endpoints return `403 Forbidden` with:

```json
{
  "error": "FEATURE_LOCKED",
  "required_tier": "Pro",
  "message": "This feature requires a Pro license"
}
```

The UI renders this as a locked badge with upgrade prompt.

### 9.4 Coverage Checklist Computation

The UI's "Coverage Checklist" in debug mode is computed from:

1. **Capability snapshot** (`/api/capability/status`): What channels are accessible now
2. **coverage_rollup table** (via `/api/runs/:id/coverage`): What fact types were observed

The checklist shows:
- ✅ Configured AND Accessible AND Observed
- ⚠️ Configured AND Accessible but NOT Observed
- ❌ Configured but NOT Accessible

**No inflated claims:** If a fact type was never observed, it shows as "Not Observed" even if the channel is accessible.

---

## 10. Operator Walkthrough: "What You Should See"

### 10.1 Start Capture (Admin Recommended)

```powershell
# Open Admin PowerShell
cd C:\path\to\windows-incident-compiler
.\target\release\capture_windows_rotating.exe
```

**Expected:**
- `heartbeat.json` appears in telemetry root
- `segments/*.jsonl` files begin populating
- Console shows: `[poll] Security: 5 events, Sysmon: 12 events, ...`

### 10.2 Start Compiler

```powershell
# In another Admin PowerShell
.\target\release\edr-locald.exe
```

**Expected:**
- `workbench.db` is created/updated
- Console shows: `[ingest] Processing: segments/000001.jsonl`
- Facts extracted: `[fact] Affected 2 hypotheses`
- Signals fired: `[persisted] playbook:lolbin_execution → severity=Medium`

### 10.3 Start Server + Open UI

```powershell
.\target\release\locint.exe --port 3000
```

**Expected:**
- `Listening on 0.0.0.0:3000`
- Open browser to `http://localhost:3000/ui/`

**UI Shows:**
- Runs list with your current run
- Capability status: `overall_status: "full"` (if admin + Sysmon)
- Channels: All 7 channels show `accessible: true`

### 10.4 Generate Safe Test Events

From [VALIDATION_RUN.md](../VALIDATION_RUN.md):

```powershell
# Process Execution (Sysmon 1 / Security 4688)
whoami.exe /all

# Network Connection (Sysmon 3)
Resolve-DnsName -Name "example.com" -Type A

# PowerShell Script Block (4104)
Write-Host "Test script block"
```

**Expected:**
- Within 2-5 seconds, new segments appear
- locald processes them, extracts facts
- If playbook matches, signal appears in UI

### 10.5 Log Clear Test (🔴 LAB ONLY - DESTRUCTIVE)

```powershell
# WARNING: This clears the Application log!
wevtutil cl Application
```

This should trigger:
- System Event ID 104
- `log_clear` canonical event
- `LogTamper` fact
- Potential signal if playbook matches

---

## 11. Failure Modes and Truthful Messaging

### 11.1 Security Log Blocked (0x80070005)

**Symptom:** `/api/capability/status` shows `Security.accessible: false, reason: "ACCESS_DENIED"`

**Impact:**
- No Security events (4688, 4624, 4672, 4697, 4698, 1102)
- Near-zero authentication/privilege facts
- Persistence detection limited to System 7045 only

**UI Message:** "Security log blocked — run as Administrator for full coverage"

### 11.2 Sysmon Not Installed

**Symptom:** `/api/capability/status` shows `Sysmon.accessible: false, reason: "CHANNEL_NOT_FOUND"`

**Impact:**
- No process command lines
- No network connections (Sysmon 3)
- No registry modifications (Sysmon 12-14)
- No WMI persistence (Sysmon 19-21)
- Fallback: Security 4688 (if audit policy enables command line logging)

**UI Message:** "Sysmon not installed — reduced detection fidelity"

### 11.3 PowerShell Logging Not Enabled

**Symptom:** PowerShell channel accessible but no 4104/4103 events observed

**Impact:** No script block content for PowerShell-based attacks

**Detection:** `coverage_rollup` shows zero `ScriptExec` facts

**UI Message:** "PowerShell script block logging not enabled"

### 11.4 No Matching Events

**Symptom:** Run completes with zero signals

**Behavior:**
- `Observed` stays `false` for all fact types
- No incidents invented
- UI shows empty signal list (not an error)

**Truthful Message:** "No security-relevant events detected in this run window"

### 11.5 Duplicate Ingestion Symptoms

**Detection:**
- Check `wevt_reader.rs` stats: `events_read_total` vs segment record count
- If stats >> segment records, dedupe may be failing
- Check `source_record_id` continuity in segment JSONL

**Fix:** Restart capture; dedupe HashSet will rebuild on resume.

---

## 12. Where to Look in Code

| Purpose | File | Key Functions/Structs |
|---------|------|-----------------------|
| WEVTAPI polling | [crates/agent-windows/src/wevt_reader.rs](../crates/agent-windows/src/wevt_reader.rs) | `WevtReader::poll()`, `is_duplicate()` |
| Attack surface parsing | [crates/agent-windows/src/sensors/attack_surface.rs](../crates/agent-windows/src/sensors/attack_surface.rs) | `normalize_to_attack_surface()`, `parse_*` functions |
| Segment writing | [crates/agent-windows/src/capture_windows_rotating.rs](../crates/agent-windows/src/capture_windows_rotating.rs) | `WindowsEventCapture::run()` |
| Fact extraction | [crates/locald/src/os/windows/fact_extractor.rs](../crates/locald/src/os/windows/fact_extractor.rs) | `extract_facts()` |
| Hypothesis engine | [crates/locald/src/hypothesis_controller.rs](../crates/locald/src/hypothesis_controller.rs) | `HypothesisController`, `ingest_fact()` |
| Signal persistence | [crates/locald/src/main.rs](../crates/locald/src/main.rs) | `persist_signal()`, `build_explanation_with_reason()` |
| HTTP router | [crates/server/src/bin/locint.rs](../crates/server/src/bin/locint.rs) | `build_locint_router()` |
| Capability service | [crates/server/src/services/capability.rs](../crates/server/src/services/capability.rs) | `get_capability_status()`, `probe_channel()` |
| Signal service | [crates/server/src/services/signals.rs](../crates/server/src/services/signals.rs) | Signal CRUD, explain endpoint |
| Team features | [crates/server/src/team/](../crates/server/src/team/) | `cases.rs`, `store.rs`, `publish.rs` |
| Contract snapshots | [docs/parity/](../docs/parity/) | `contract_snapshot.json`, `routes_snapshot.json` |
| Validation triggers | [VALIDATION_RUN.md](../VALIDATION_RUN.md) | Safe PowerShell commands |
| Coverage map | [docs/WINDOWS_V1_COVERAGE_MAP.md](../docs/WINDOWS_V1_COVERAGE_MAP.md) | Channel → parser → fact mapping |

---

## Appendix: Canonical Event Schema

```json
{
  "ts_ms": 1736784000000,
  "host": "WORKSTATION01",
  "tags": ["windows", "process_exec"],
  "proc_key": "sha256:abc123...",
  "file_key": null,
  "identity_key": "DOMAIN\\user",
  "evidence_ptr": {
    "stream_id": "windows_evtx",
    "segment_id": 42,
    "record_index": 17
  },
  "fields": {
    "windows.channel": "Microsoft-Windows-Sysmon/Operational",
    "windows.event_id": 1,
    "windows.provider": "Microsoft-Windows-Sysmon",
    "windows.source_record_id": 12345,
    "windows.computer": "WORKSTATION01",
    "proc.exe": "C:\\Windows\\System32\\cmd.exe",
    "proc.cmdline": "cmd.exe /c whoami",
    "proc.parent_exe": "C:\\Windows\\explorer.exe"
  }
}
```

---

*This document describes the system as implemented. If behavior differs, file a bug.*

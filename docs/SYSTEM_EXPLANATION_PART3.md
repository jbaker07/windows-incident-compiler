# LocInt System Explanation (Part 3/3): Compiler → workbench.db → API → UI

> **Audience:** Engineers, SOC analysts. Evidence-first, no hand-waving.  
> **Last Updated:** 2026-01-13  
> **Scope:** Compiler stage, database schema, HTTP API wiring, UI behavior, failure modes.

---

## Source of Truth Pointers

| Topic | Authoritative File |
|-------|-------------------|
| API routes | `docs/parity/routes_snapshot.json` |
| API contract wrapper | `docs/parity/contract_snapshot.json` |
| Server binary | `crates/server/src/bin/locint.rs` |
| Per-run DB access | `crates/server/src/run_db.rs` |
| Evidence deref | `crates/server/src/services/evidence.rs` |
| UI entry point | `ui/app.js` |

---

## 1. The Compiler Stage: edr-locald.exe

### 1.1 Purpose

`edr-locald.exe` compiles raw segments into structured analysis:

```
Input:   segments/seg_*.jsonl (canonical events + evidence pointers)
Output:  workbench.db (SQLite database with signals, facts, rollups)
```

### 1.2 Database Initialization

When locald starts a run, it creates `{run_dir}/workbench.db`:

```rust
// crates/locald/src/main.rs
let db_path = telemetry_root.join("workbench.db");
```

**Schema tables (verified):**

| Table | Purpose | Written By |
|-------|---------|------------|
| `signals` | Detected findings (matched patterns) | locald |
| `signal_explanations` | Explanations for each signal | locald |
| `coverage_rollup` | Fact counts per tag | locald |
| `locald_checkpoint` | Compiler progress tracking | locald |

Rollups are updated during compilation as events are processed.

> **Source of truth:** Schema initialization is defined in `crates/locald/src/main.rs`. For exact column definitions, inspect the init functions or run `.schema` on an existing `workbench.db` file.

### 1.3 Signal Generation Flow

```
canonical event (from segment)
        ↓
pattern matching (playbook rules)
        ↓
signal generated (with evidence pointers)
        ↓
INSERT INTO signals
        ↓
INSERT INTO signal_explanations (async)
```

**Signal record fields:**
- `id` — Unique signal identifier
- `rule_id` — Playbook rule that fired
- `severity` — critical / high / medium / low / info
- `summary` — Human-readable summary
- `evidence` — JSON array of `EvidencePtr` objects
- `timestamp` — When signal was generated
- `run_id` — Parent run identifier

### 1.4 Coverage Rollup

As events are processed, locald updates `coverage_rollup` with fact counts per canonical tag. This enables the UI to show the "coverage checklist" without re-scanning all signals.

> **Source of truth:** See `crates/locald/src/main.rs` for the rollup update logic and exact column definitions.

---

## 2. The Server: locint.exe

### 2.1 Purpose

`locint.exe` is the HTTP API server that:
- Manages runs (start/stop/list)
- Queries per-run `workbench.db` files
- Serves the UI (SPA at `/`)
- Exposes all `/api/*` endpoints

### 2.2 Database Architecture

LocInt uses **two SQLite databases**:

| Database | Location | Purpose |
|----------|----------|---------|
| **Master DB** | `{config.data_dir}/workbench.db` (defaults to `%LOCALAPPDATA%/attack-workbench/`) | Run registry, sessions, global state |
| **Per-run DB** | `{run_dir}/workbench.db` | Signals, explanations, coverage for that run |

**Pattern:** Most `/api/runs/:run_id/*` endpoints query the per-run DB, not the master DB.

> **Source of truth:** `crates/server/src/bin/locint.rs` (master DB path via `config.data_dir`), `crates/server/src/run_db.rs` (per-run DB access)

### 2.3 Per-Run DB Access

```rust
// crates/server/src/services/run_control.rs
pub fn open_run_db(db: &Database, run_id: &str) -> Result<RunDbHandle, RunDbError> {
    // 1. Look up run in master database
    let run = db.get_run(run_id)?;
    
    // 2. Get run_dir from run record
    let run_dir = run.run_dir.ok_or(RunDbError::NoRunDir)?;
    
    // 3. Open {run_dir}/workbench.db
    let db_path = run_dir.join("workbench.db");
    let conn = Connection::open(&db_path)?;
    
    Ok(RunDbHandle { conn, run_dir, run })
}
```

---

## 3. HTTP API: Key Endpoints

> **Authoritative source:** `docs/parity/routes_snapshot.json`
>
> The tables below list commonly-used endpoints. This is **not exhaustive**—the full route catalog (40+ endpoints) is defined in the snapshot file.

### 3.1 Run Management

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/run/start` | POST | Start a new capture run |
| `/api/run/stop` | POST | Stop active run |
| `/api/run/status` | GET | Get current run status |
| `/api/run/metrics` | GET | Get live metrics (events, facts, signals) |
| `/api/runs` | GET | List all runs |
| `/api/runs/:run_id` | GET | Get single run details |

### 3.2 Signal Queries

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/signals` | GET | List signals (requires `?run_id=`) |
| `/api/signals/:id` | GET | Get single signal |
| `/api/signals/:id/explain` | GET | Get signal explanation |
| `/api/signals/stats` | GET | Get signal statistics |

**Query parameters for `/api/signals`:**
- `run_id` — Required: which run to query
- `severity` — Filter by severity
- `limit` — Max results (default: 100)

### 3.3 Coverage & Analysis

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/runs/:run_id/coverage` | GET | Facts and coverage checklist |
| `/api/runs/:run_id/playbooks` | GET | Playbook status (matched/unmatched) |
| `/api/runs/:run_id/diff` | GET | Diff against baseline |
| `/api/runs/:run_id/state` | GET | System state summary |
| `/api/runs/:run_id/next_steps` | GET | Workflow guidance |

### 3.4 Evidence Dereferencing

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/evidence/deref` | GET | Resolve EvidencePtr to source record |

**Query parameters:**
- `stream_id` — Stream ID from EvidencePtr
- `segment_id` — Segment ID from EvidencePtr
- `record_index` — 0-based line offset in segment JSONL

**Semantics:** The endpoint locates the segment file by `segment_id`, reads the file, and returns the JSON record at line index `record_index` (0-indexed).

> **Source of truth:** `crates/server/src/services/evidence.rs` → `dereference_evidence()`
>
> For the complete parameter list, see `docs/parity/routes_snapshot.json`.

### 3.5 Capability & Health

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/capability/status` | GET | Sensor inventory and status |
| `/api/capability/detection_plan` | GET | Detection plan with dependencies |
| `/api/selfcheck` | GET | System readiness check |
| `/health` | GET | Health check (root) |
| `/api/health` | GET | Health check |

### 3.6 Import/Export

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/export/bundle` | POST | Export run as ZIP bundle |
| `/api/import/bundle` | POST | Import ZIP bundle |
| `/api/import/validate` | POST | Validate bundle before import |

---

## 4. API Response Contract

> **Authoritative source:** `docs/parity/contract_snapshot.json`
>
> All API responses follow the wrapper format defined in the contract snapshot. The examples below are representative; see the snapshot for the complete specification.

### 4.1 Success Response

```json
{
  "success": true,
  "data": { /* endpoint-specific payload */ }
}
```

### 4.2 Error Response

```json
{
  "success": false,
  "error": "Human-readable error message",
  "code": "STRUCTURED_ERROR_CODE"
}
```

### 4.3 Common Error Codes

| Code | Meaning |
|------|---------|
| `RUN_NOT_FOUND` | Run ID doesn't exist |
| `SIGNAL_NOT_FOUND` | Signal ID doesn't exist |
| `DB_NOT_FOUND` | Per-run workbench.db missing |
| `FEATURE_LOCKED` | Feature requires higher tier |
| `EVIDENCE_NOT_FOUND` | Evidence pointer cannot be resolved |

> **Reference:** See `docs/parity/contract_snapshot.json` for complete error code list.

---

## 5. UI Behavior

### 5.1 Architecture

The UI is a single-page application served from `/`:
- Entry point: `ui/index.html`
- Application logic: `ui/app.js`
- No framework (vanilla JS)

### 5.2 API Consumption Pattern

```javascript
// ui/app.js
async function api(endpoint, options = {}) {
    const response = await fetch(endpoint, options);
    const json = await response.json();
    
    if (!json.success) {
        throw new Error(json.error || 'API error');
    }
    
    return json.data;
}
```

### 5.3 Key UI Flows

#### Run Management
1. User clicks "Start Run" → `POST /api/run/start`
2. UI polls `GET /api/run/status` for state updates
3. Metrics displayed via `GET /api/run/metrics`
4. User clicks "Stop Run" → `POST /api/run/stop`

#### Signal Display
1. Run selected → `GET /api/signals?run_id={id}`
2. Signal clicked → `GET /api/signals/{id}`
3. Explain requested → `GET /api/signals/{id}/explain`

#### Evidence Inspection
1. User clicks evidence link in signal
2. UI calls `GET /api/evidence/deref?stream_id=...&segment_id=...&record_index=...`
3. Raw event record displayed in modal

#### Coverage Checklist
1. Run selected → `GET /api/runs/{id}/coverage`
2. UI displays coverage matrix with fact counts

### 5.4 Capability Status Display

The UI shows sensor status via `/api/capability/status`:

| UI State | Meaning |
|----------|---------|
| ✅ Available | Sensor detected and accessible |
| ⚠️ Missing | Sensor not installed (e.g., Sysmon) |
| 🔒 Requires Admin | Sensor requires elevated privileges |
| ❌ Error | Sensor check failed |

---

## 6. Capability Checklist Logic

### 6.1 How Capability Status Works

```rust
// crates/server/src/services/capability.rs (simplified)
pub fn get_capability_status() -> CapabilityStatus {
    let mut sensors = vec![];
    
    // Check each channel
    for channel in CHANNELS {
        let status = match check_channel_access(channel) {
            Ok(_) => SensorStatus::Available,
            Err(e) if e.is_not_found() => SensorStatus::Missing,
            Err(e) if e.is_permission() => SensorStatus::RequiresAdmin,
            Err(e) => SensorStatus::Error(e.to_string()),
        };
        sensors.push(Sensor { channel, status });
    }
    
    CapabilityStatus { sensors }
}
```

### 6.2 Coverage Checklist vs Capability Status

| Concept | Source | Question Answered |
|---------|--------|-------------------|
| **Capability Status** | `/api/capability/status` | "Can we read from this channel?" |
| **Coverage Checklist** | `/api/runs/:id/coverage` | "Did we see events from this surface?" |

Capability status is **pre-run** (can you capture?).  
Coverage checklist is **post-run** (did you capture?).

---

## 7. Operator Walkthrough

### 7.1 Starting a Capture

```powershell
# 1. Start locint server
locint.exe --port 9220

# 2. Open UI in browser
Start-Process "http://localhost:9220"

# 3. Check capability status (UI: Settings → Capability)
# Verify Sysmon shows ✅ (or install if missing)

# 4. Click "Start Run" in UI
# Or via API:
Invoke-RestMethod -Uri "http://localhost:9220/api/run/start" -Method POST
```

> **Note:** Run `locint.exe --help` to see all available CLI flags.

### 7.2 Generating Activity

```powershell
# Execute commands to generate telemetry
whoami /all                    # process_exec
ping 8.8.8.8                   # network_connect
schtasks /query                # scheduled task access

# Or run validation triggers from Part 2
```

### 7.3 Stopping and Reviewing

```powershell
# 1. Click "Stop Run" in UI
# Or via API:
Invoke-RestMethod -Uri "http://localhost:9220/api/run/stop" -Method POST

# 2. UI automatically shows signals list
# 3. Click any signal to see explanation
# 4. Click evidence pointer to see raw event
```

### 7.4 Exporting Results

```powershell
# Export run as bundle (UI: Run → Export)
# Or via API:
$body = @{ run_id = "run_20250113_123456" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:9220/api/export/bundle" `
    -Method POST -Body $body -ContentType "application/json" `
    -OutFile "export.zip"
```

---

## 8. Failure Modes

### 8.1 No Signals After Run

**Symptom:** Run completes but signals list is empty.

**Diagnosis:**
1. Check `/api/run/metrics` → Are `events_total` > 0?
2. Check `/api/runs/:id/coverage` → Are any facts present?
3. Check `{run_dir}/workbench.db` exists?

**Common Causes:**
- No telemetry sources available (Sysmon not installed, no admin rights)
- locald crashed during compilation
- Run was too short (no events captured)

### 8.2 Evidence Deref Fails

**Symptom:** Clicking evidence pointer returns error.

**Diagnosis:**
1. Check if `segments/` directory exists in run
2. Check if segment file (`seg_{segment_id}.jsonl`) exists
3. Check if record_index is within file bounds

**Common Causes:**
- Segments deleted or moved
- Bundle imported without segments
- Segment file corruption

### 8.3 Database Locked

**Symptom:** API returns "database is locked" errors.

**Diagnosis:**
1. Is locald still running? (writer contention)
2. Multiple server instances?
3. Database file on network share?

**Solution:**
- Wait for locald to complete
- Ensure only one locint instance per data directory
- Use local storage, not network shares

### 8.4 Capability Shows Missing But Log Exists

**Symptom:** Capability status shows channel as missing, but you know the log exists.

**Diagnosis:**
1. Run as Administrator? (Security channel requires admin)
2. Is the channel name exact? (case-sensitive)
3. Is the log enabled in Event Viewer?

**Common Causes:**
- Permission denied (not admin)
- Channel disabled by policy
- Provider not registered

---

## 9. Data Flow Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Complete Data Flow                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Windows Event Logs                                                         │
│  ├── Security                                                               │
│  ├── Sysmon                                                                 │
│  ├── PowerShell                                                             │
│  └── ...                                                                    │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────────┐                                                   │
│  │   edr-agent.exe     │  WEVTAPI polling + bookmark persistence           │
│  │   (capture)         │  Dedup: HashSet + LRU per channel                 │
│  └─────────────────────┘                                                   │
│           │                                                                 │
│           ▼                                                                 │
│  segments/seg_*.jsonl                                                       │
│  ├── Line 0: { "tag": "process_exec", "evidence": {...} }                   │
│  ├── Line 1: { "tag": "network_connect", "evidence": {...} }                │
│  └── ...                                                                    │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────────┐                                                   │
│  │   edr-locald.exe    │  Pattern matching, signal generation              │
│  │   (compile)         │  Creates workbench.db                             │
│  └─────────────────────┘                                                   │
│           │                                                                 │
│           ▼                                                                 │
│  {run_dir}/workbench.db                                                    │
│  ├── signals                                                                │
│  ├── signal_explanations                                                    │
│  └── coverage_rollup                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────────┐                                                   │
│  │   locint.exe        │  HTTP API server                                  │
│  │   (serve)           │  Queries per-run workbench.db                     │
│  └─────────────────────┘                                                   │
│           │                                                                 │
│           ▼                                                                 │
│  /api/signals?run_id=...                                                    │
│  /api/signals/:id/explain                                                   │
│  /api/evidence/deref?...                                                    │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────────┐                                                   │
│  │   UI (browser)      │  Single-page app                                  │
│  │   (display)         │  Signals, explanations, evidence viewer           │
│  └─────────────────────┘                                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Summary: Part 3 Scope

This part covered:

- ✅ Compiler stage (edr-locald.exe) and workbench.db schema
- ✅ Server (locint.exe) database architecture
- ✅ Full HTTP API endpoint catalog with routes_snapshot.json alignment
- ✅ API response contract
- ✅ UI architecture and consumption patterns
- ✅ Capability checklist vs coverage checklist distinction
- ✅ Operator walkthrough
- ✅ Failure modes and diagnosis

---

## Cross-Reference: All Three Parts

| Part | File | Coverage |
|------|------|----------|
| 1 | `SYSTEM_EXPLANATION_PART1.md` | Architecture, real telemetry → canonical events |
| 2 | `SYSTEM_EXPLANATION_PART2.md` | Windows v1 coverage matrix, routing, validation |
| 3 | `SYSTEM_EXPLANATION_PART3.md` | Compiler → DB → API → UI |

---

*This document describes the system as implemented. For authoritative route definitions, see `docs/parity/routes_snapshot.json`.*

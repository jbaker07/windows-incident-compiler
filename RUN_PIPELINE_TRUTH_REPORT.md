# RUN_PIPELINE_TRUTH_REPORT.md

> **Date:** 2026-01-27  
> **Purpose:** Repo-accurate mental model of how runs, facts, signals, evidence refs, playbooks, chains, and UI tabs work TODAY.  
> **Rule:** No new features, no deletions. Cite file paths + line ranges. Say "not found" if something cannot be proven.

---

## ASCII Pipeline Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            RUN PIPELINE OVERVIEW                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

USER
  │
  ▼ [Click "Start Run"]
┌───────────────────────────────────────────────────────────────────────────────┐
│  locint.rs:867  run_start_handler()                                           │
│    → services::run_control::build_start_config()                              │
│    → supervisor.start(config)                                                 │
│    → db.insert_run(RunRecord)                             [SERVER DB: runs]   │
│    → Spawns: capture_windows_rotating.exe + edr-locald.exe                    │
│    → Returns: run_id, run_dir, PIDs, playbook_scope                           │
└───────────────────────────────────────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  capture_windows_rotating.exe                                                 │
│    → ETW Consumers (Process, File, Network, Registry)                         │
│    → Writes: {run_dir}/segments/*.jsonl (rotating files)                      │
└───────────────────────────────────────────────────────────────────────────────┘
                │
                ▼  (reads segments)
┌───────────────────────────────────────────────────────────────────────────────┐
│  edr-locald.exe (locald/main.rs)                                              │
│    → Opens: {run_dir}/workbench.db                                            │
│    → Creates tables: signals, facts_sample, coverage_rollup, segments, etc.   │
│    → For each segment:                                                        │
│        1. Parse JSON lines into Event structs                                 │
│        2. Extract Facts (via fact_extraction)                                 │
│        3. Evaluate Playbooks (HypothesisController)                           │
│        4. If playbook fires → INSERT INTO signals                             │
│        5. INSERT INTO facts_sample (sampled subset)                           │
│        6. UPDATE coverage_rollup                                              │
└───────────────────────────────────────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  {run_dir}/workbench.db (PER-RUN DATABASE)                                    │
│    Tables:                                                                    │
│      signals         - Fired playbook detections + evidence_ptrs              │
│      facts_sample    - Sampled facts (200/type cap, discovery categories)     │
│      coverage_rollup - Per-minute telemetry coverage                          │
│      segments        - Processed segment metadata                             │
│      entity_rollup   - Top-N entities by fact count                           │
│      playbook_eval_rollup - Per-playbook slot progress                        │
└───────────────────────────────────────────────────────────────────────────────┘
                │
USER            ▼ [Click "Stop Run"]
┌───────────────────────────────────────────────────────────────────────────────┐
│  locint.rs:917  run_stop_handler()                                            │
│    → supervisor.stop_and_finalize()                                           │
│        Phase 1: Mark as finalizing                                            │
│        Phase 2: Stop capture (SIGTERM)                                        │
│        Phase 3: Wait 300ms for segment flush                                  │
│        Phase 4: Drain locald (up to 2s)                                       │
│        Phase 5: Query final counts from {run_dir}/workbench.db                │
│        Phase 6: Write {run_dir}/run_meta.json (finalized=true)                │
│    → db.finalize_run(run_id, stopped_at, metrics)         [SERVER DB: runs]   │
│    → Returns: stopped, finalized, events_total, facts_extracted, signals_fired│
└───────────────────────────────────────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  UI / API Access                                                              │
│    → /api/runs/:run_id/facts          (queries facts_sample table)            │
│    → /api/runs/:run_id/signals        (queries signals table)                 │
│    → /api/runs/:run_id/events         (queries canonical_events or facts)     │
│    → /api/runs/:run_id/playbooks/eval (evaluates playbooks against facts)     │
│    → /api/runs/:run_id/step_status    (computes chain step satisfaction)      │
│    → /api/runs/:run_id/facts/resolve  (resolves EvidenceRef → fact)           │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## Section 1: Run Lifecycle (Authoritative)

### 1.1 Start Flow

| Step | Location | What Happens |
|------|----------|--------------|
| 1 | [locint.rs#L867-L913](crates/server/src/bin/locint.rs#L867-L913) | `run_start_handler()` builds config via `build_start_config()` |
| 2 | [run_control.rs#L651-L685](crates/server/src/services/run_control.rs#L651-L685) | `create_run_record()` builds `RunRecord` struct |
| 3 | [supervisor.rs#L777](crates/server/src/supervisor.rs#L777) | `supervisor.start()` spawns capture + locald |
| 4 | [db.rs#L883-L918](crates/server/src/db.rs#L883-L918) | `db.insert_run()` persists to `runs` table |

**RunRecord struct** ([db.rs#L35-L58](crates/server/src/db.rs#L35-L58)):
```rust
pub struct RunRecord {
    pub run_id: String,
    pub name: Option<String>,
    pub profile: Option<String>,
    pub started_at: String,
    pub stopped_at: Option<String>,
    pub run_dir: Option<String>,
    pub events_total: u64,
    pub segments_count: u32,
    pub facts_extracted: u64,
    pub signals_fired: u64,
    pub bytes_written: u64,
    pub status: String,           // "running" | "stopping" | "stopped"
    pub baseline_scope: Option<String>,
    pub baseline_enabled: bool,
    pub baseline_set_at: Option<String>,
    pub chain_ids: Option<Vec<String>>,  // INVESTIGATE_CHAINS-1
}
```

### 1.2 Stop Flow

| Step | Location | What Happens |
|------|----------|--------------|
| 1 | [locint.rs#L917-L959](crates/server/src/bin/locint.rs#L917-L959) | `run_stop_handler()` calls `supervisor.stop_and_finalize()` |
| 2 | [supervisor.rs#L777-L900](crates/server/src/supervisor.rs#L777-L900) | 6-phase finalization (stop capture → drain → query counts → write meta) |
| 3 | [db.rs#L920-L945](crates/server/src/db.rs#L920-L945) | `db.finalize_run()` updates `stopped_at`, `status='stopped'`, final metrics |

### 1.3 Run Status Values

| Status | Meaning |
|--------|---------|
| `running` | Capture and locald active |
| `stopping` | Stop initiated, draining |
| `stopped` | Finalized, metrics frozen |
| `capturing` | Legacy alias for `running` |
| `active` | Legacy alias for `running` |

---

## Section 2: Data Surfaces (Events, Facts, Signals, Segments)

### 2.1 Segments

**Writer:** `capture_windows_rotating.exe`  
**Location:** `{run_dir}/segments/*.jsonl`  
**Format:** Newline-delimited JSON, one event per line

**Schema** (per segment file):
```json
{"ts": 1706123456000, "eventType": "Exec", "host": "...", "rawFields": {...}}
```

**Tracking table** ([main.rs#L658-L669](crates/locald/src/main.rs#L658-L669)):
```sql
CREATE TABLE IF NOT EXISTS segments (
    segment_id TEXT NOT NULL UNIQUE,
    segment_path TEXT NOT NULL,
    records INTEGER NOT NULL DEFAULT 0,
    facts INTEGER NOT NULL DEFAULT 0,
    signals INTEGER NOT NULL DEFAULT 0,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### 2.2 Events

**Not persisted as table.** Events are raw JSON lines in segments.

**Endpoint:** `GET /api/runs/:run_id/events` ([locint.rs#L2534-L2680](crates/server/src/bin/locint.rs#L2534-L2680))  
**Source:** 
- If `canonical_events` table exists (newer runs): query it
- Fallback: synthesize from `facts_sample` as proxy

### 2.3 Facts

**Table:** `facts_sample` in `{run_dir}/workbench.db`  
**Writer:** `edr-locald.exe` ([main.rs#L411-L420](crates/locald/src/main.rs#L411-L420))  
**Sampling:** 200 per `fact_type`, discovery categories always kept

**Schema** ([main.rs#L711-L727](crates/locald/src/main.rs#L711-L727)):
```sql
CREATE TABLE IF NOT EXISTS facts_sample (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fact_id TEXT NOT NULL UNIQUE,
    ts INTEGER NOT NULL,
    fact_type TEXT NOT NULL,
    category TEXT NOT NULL,
    host TEXT NOT NULL,
    entity_key TEXT,
    details_json TEXT NOT NULL,
    fact_json TEXT,
    evidence_ptrs TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Endpoint:** `GET /api/runs/:run_id/facts` ([locint.rs#L1621-L1900](crates/server/src/bin/locint.rs#L1621-L1900))  
**Query params:** `fact_type`, `host`, `category`, `search`, `limit`, `offset`

### 2.4 Signals

**Table:** `signals` in `{run_dir}/workbench.db`  
**Writer:** `edr-locald.exe` ([main.rs#L603-L625](crates/locald/src/main.rs#L603-L625))

**Schema:**
```sql
CREATE TABLE IF NOT EXISTS signals (
    signal_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL DEFAULT 'unknown',
    signal_type TEXT NOT NULL,      -- "playbook:{playbook_id}"
    severity TEXT NOT NULL,
    host TEXT NOT NULL,
    ts INTEGER NOT NULL,
    ts_start INTEGER NOT NULL,
    ts_end INTEGER NOT NULL,
    proc_key TEXT,
    file_key TEXT,
    identity_key TEXT,
    metadata TEXT NOT NULL,         -- JSON blob
    evidence_ptrs TEXT NOT NULL,    -- JSON array of EvidenceRef
    dropped_evidence_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
```

**Endpoint:** `GET /api/runs/:run_id/signals` ([locint.rs#L2760-L2930](crates/server/src/bin/locint.rs#L2760-L2930))

---

## Section 3: EvidenceRef + Resolve Loop

### 3.1 EvidenceRef Definition

**Location:** [playbook_scope.rs#L375-L392](crates/server/src/playbook_scope.rs#L375-L392)

```rust
pub struct EvidenceRef {
    pub fact_id: Option<String>,      // Primary key in facts_sample (PREFERRED)
    pub segment_id: Option<String>,   // Segment file reference
    pub record_index: Option<u32>,    // Line within segment
    pub fact_type: Option<String>,    // Fallback: fact_type + ts
    pub ts: Option<i64>,              // Timestamp (epoch ms)
}
```

**Resolvability check** ([playbook_scope.rs#L393-L398](crates/server/src/playbook_scope.rs#L393-L398)):
```rust
pub fn is_resolvable(&self) -> bool {
    self.fact_id.is_some() 
        || (self.segment_id.is_some() && self.record_index.is_some())
        || (self.fact_type.is_some() && self.ts.is_some())
}
```

### 3.2 Resolution Endpoint

**Endpoint:** `POST /api/runs/:run_id/facts/resolve` ([locint.rs#L1961-L2110](crates/server/src/bin/locint.rs#L1961-L2110))

**Resolution Priority:**
1. `fact_id` alone → primary key lookup ([locint.rs#L2118-L2148](crates/server/src/bin/locint.rs#L2118-L2148))
2. `segment_id` + `record_index` → evidence_ptrs LIKE match ([locint.rs#L2150-L2182](crates/server/src/bin/locint.rs#L2150-L2182))
3. `fact_type` + `ts` → approximate match ±1000ms ([locint.rs#L2185-L2220](crates/server/src/bin/locint.rs#L2185-L2220))

**Error codes:**
- `RUN_NOT_FOUND` - Run ID does not exist
- `MISSING_DB` - workbench.db not present
- `NO_FACTS_SAMPLE_TABLE` - DB exists but no facts_sample
- `TOO_MANY_REFS` - More than 200 refs requested
- `NOT_FOUND` - Ref resolvable but no matching fact
- `INSUFFICIENT_FIELDS` - Ref missing required fields

### 3.3 Evidence Flow

```
Signal fired (locald)
  │
  ├─► evidence_ptrs stored in signals table (JSON array of EvidenceRef)
  │
  ▼
UI calls /api/runs/:id/signals
  │
  ├─► Gets signal with evidence_ptrs
  │
  ▼
UI calls POST /api/runs/:id/facts/resolve {refs: evidence_ptrs}
  │
  ├─► Backend resolves refs to full fact records
  │
  ▼
UI renders evidence panel with fact details
```

---

## Section 4: Playbooks Evaluation Flow

### 4.1 At Run Time (Locald)

**Location:** [main.rs#L750-L810](crates/locald/src/main.rs#L750-L810)

1. Playbooks loaded via `PlaybookManager`
2. `HypothesisController` tracks slot satisfaction per playbook
3. When all required slots satisfied → signal inserted

### 4.2 At Query Time (Server)

**Endpoint:** `GET /api/runs/:run_id/playbooks/eval` ([locint.rs#L6420-L6700](crates/server/src/bin/locint.rs#L6420-L6700))

**Response shape:**
```json
{
  "success": true,
  "data": {
    "run_id": "...",
    "available": true,
    "playbook_scope": { "mode": "general_discovery", "effective_playbook_ids": [...] },
    "visibility": { "sensors_present": [...], "sensors_missing": [...] },
    "evaluations": [
      {
        "playbook_id": "...",
        "status": "fired|candidate|no_match|blocked|skipped",
        "in_scope": true,
        "reason_code": "ALL_SLOTS_SATISFIED",
        "slots": [
          {
            "slot_id": "...",
            "status": "matched|missing|blocked|skipped",
            "match_count": N,
            "match_trace": { "evidence_refs": [...] },
            "search_hints": { "fact_types": [...], "query_terms": [...] }
          }
        ]
      }
    ]
  }
}
```

### 4.3 Status Values

**Playbook status:**
| Status | Meaning |
|--------|---------|
| `fired` | All required slots satisfied, signal emitted |
| `candidate` | Some slots matched, not all required |
| `no_match` | No slots matched |
| `blocked` | Missing required telemetry |
| `skipped` | Out of scope for this run |

**Slot status** ([playbook_scope.rs#L291-L303](crates/server/src/playbook_scope.rs#L291-L303)):
| Status | Meaning |
|--------|---------|
| `matched` | Slot matched facts |
| `missing` | No facts matched |
| `blocked` | Visibility issue |
| `skipped` | Out of scope |

---

## Section 5: Chains Compilation + Step Status

### 5.1 Chain Definitions

**Location:** [chains.rs#L120-L400](crates/server/src/services/chains.rs#L120-L400) (static registry)

**Chain structure:**
```rust
pub struct MicroChain {
    pub id: String,
    pub title: String,
    pub description: String,
    pub steps: Vec<ChainStep>,
    pub match_rules: MatchRules,
    pub requirements: Vec<String>,  // e.g., ["sysmon", "is_admin"]
}
```

### 5.2 Chain Compilation

**Endpoint:** `POST /api/chains/compile` ([locint.rs#L7593-L7700](crates/server/src/bin/locint.rs#L7593-L7700))

**Request:** `{ chain_ids: ["process-injection", "credential-dump"] }`

**Response:**
```json
{
  "success": true,
  "baseline": {
    "type": "chain_stack",
    "chains": [{ "chain_id": "...", "compiled_playbook_ids": [...], "step_to_playbooks": {...} }],
    "baseline_playbook_ids": [...]
  }
}
```

### 5.3 Step Status (Backend-Canonical)

**Endpoint:** `GET /api/runs/:run_id/step_status?chain_ids=...` ([locint.rs#L7723-L7850](crates/server/src/bin/locint.rs#L7723-L7850))

**Core logic:** [chains.rs#L545-L680](crates/server/src/services/chains.rs#L545-L680) `compute_step_status()`

**Step states:**
| State | Meaning |
|-------|---------|
| `blocked` | Chain requires unavailable telemetry |
| `unverified` | Partial telemetry (may miss detections) |
| `satisfied` | Signal fired for this step |
| `candidate` | Playbooks matched, no signal |
| `not_observed` | No relevant data |

**Response:**
```json
{
  "success": true,
  "run_id": "...",
  "is_live": false,
  "chains": [
    {
      "chain_id": "process-injection",
      "steps": [
        { "step_id": "alloc", "state": "satisfied", "evidence_refs_count": 3, "matched_playbooks": [...] }
      ]
    }
  ]
}
```

---

## Section 6: Capability / Snapshot Semantics

### 6.1 Live Capability Check

**Endpoint:** `GET /api/capability/status` ([locint.rs#L5467](crates/server/src/bin/locint.rs#L5467))  
**Function:** [capability.rs#L160-L260](crates/server/src/services/capability.rs#L160-L260) `get_capability_status()`

Returns CURRENT system state:
- `is_admin` - Running with elevation
- `sysmon_installed` - Sysmon present
- `security_log_accessible` - Can read Security event log
- `channels` - Per-channel probe results

### 6.2 Per-Run Snapshot

**Stored in:** `{run_dir}/run_meta.json` field `readiness_snapshot.capability_snapshot`  
**Access:** [capability.rs#L357-L420](crates/server/src/services/capability.rs#L357-L420) `get_capability_snapshot_from_meta()`

**IMPORTANT:** This is the snapshot AT RUN TIME, not current system state.

### 6.3 CapabilitySnapshot (for chains)

**Struct:** [chains.rs#L519-L525](crates/server/src/services/chains.rs#L519-L525)

```rust
pub struct CapabilitySnapshot {
    pub sysmon_installed: bool,
    pub is_admin: bool,
    pub security_log_accessible: bool,
    pub channels: HashMap<String, bool>,
}
```

---

## Section 7: UI Composition Map

### 7.1 UI Tabs (Run Detail View)

| Tab | Internal Name | Data Source |
|-----|---------------|-------------|
| Overview | `overview` | `/api/runs/:id/coverage` |
| Investigate | `investigate` | `/api/runs/:id/playbooks/eval`, `/api/runs/:id/step_status` |
| Evidence | `facts` | `/api/runs/:id/facts`, `/api/runs/:id/evidence_summary` |
| Structure | `structure` | `/api/runs/:id/discovery_summary` |
| Signals | `signals` | `/api/runs/:id/signals` |
| Timeline | `timeline` | `/api/runs/:id/events` |

### 7.2 Key UI State Objects

**Location:** [app.js#L380-L520](ui/app.js#L380-L520)

```javascript
state = {
  selectedRun: null,           // Current run object
  selectedRunCoverage: null,   // /api/runs/:id/coverage response
  investigateEval: null,       // /api/runs/:id/playbooks/eval response
  chainStackData: null,        // /api/runs/:id/step_status response
  outcome: {
    chains: [],                // Compiled chain definitions
    baselinePlaybookIds: [],   // Union of all playbook IDs
    stepStatus: {}             // Per-step satisfaction
  },
  evidenceTab: {
    mode: 'summary',           // 'summary' | 'grouped' | 'raw'
    selectedFactType: null,
    currentPage: 1
  }
}
```

### 7.3 Key UI → API Mappings

| UI Function | Location | API Call |
|-------------|----------|----------|
| `fetchChainDefinitions()` | [app.js#L1725](ui/app.js#L1725) | `GET /api/chains` |
| `compileChainStackViaBackend()` | [app.js#L1749](ui/app.js#L1749) | `POST /api/chains/compile` |
| `fetchStepStatusFromBackend()` | [app.js#L1777](ui/app.js#L1777) | `GET /api/runs/:id/step_status` |
| `loadCapabilitySnapshotForRun()` | [app.js#L13103](ui/app.js#L13103) | via `/api/runs/:id/coverage` (embedded) |
| Evidence tab load | [app.js#L500](ui/app.js#L500) | `GET /api/runs/:id/facts`, `GET /api/runs/:id/evidence_summary` |

---

## Section 8: Inconsistencies / Unknowns

### 8.1 Known Inconsistencies

| Issue | Location | Impact |
|-------|----------|--------|
| `signals_fired` metric source | [supervisor.rs#L863](crates/server/src/supervisor.rs#L863) | Queries `{run_dir}/workbench.db`, not server DB |
| Event count source varies | [locint.rs#L2580-L2600](crates/server/src/bin/locint.rs#L2580-L2600) | Uses `coverage_rollup.event_count` OR `segments.records` |
| Dual status check for "is live" | [locint.rs#L7755](crates/server/src/bin/locint.rs#L7755) | Checks both `"capturing"` and `"active"` |

### 8.2 Unknowns / Not Found

| Question | Status |
|----------|--------|
| Where is `canonical_events` table created? | Not found in locald - appears to be optional/newer feature |
| Who creates `signal_explanations`? | Table created by locald but INSERT logic not confirmed |
| Is `entity_rollup` ever queried by server? | Not found - appears unused |

### 8.3 Schema Drift Risk

The following tables are created by `edr-locald` but queried by `locint`:
- `signals` - schema must match between [main.rs#L603](crates/locald/src/main.rs#L603) and query expectations
- `facts_sample` - schema must match between [main.rs#L711](crates/locald/src/main.rs#L711) and [locint.rs#L1782](crates/server/src/bin/locint.rs#L1782)

---

## 5 Constraints for New Endpoints

### Constraint 1: Per-Run DB Isolation

Any endpoint reading run data MUST:
1. Resolve `run_dir` via `services::run_control::resolve_run_dir()`
2. Open `{run_dir}/workbench.db` (NOT server DB for run-scoped data)
3. Return structured error if DB missing: `{ success: false, error: "MISSING_DB" }`

### Constraint 2: EvidenceRef Format

Any endpoint returning evidence pointers MUST use canonical `EvidenceRef` shape:
```json
{
  "fact_id": "string|null",
  "segment_id": "string|null",
  "record_index": "number|null",
  "fact_type": "string|null",
  "ts": "number|null"
}
```

At least one of: `fact_id` OR (`segment_id` + `record_index`) OR (`fact_type` + `ts`) must be present.

### Constraint 3: Playbook Scope Respect

Endpoints evaluating playbooks MUST:
1. Read `playbook_scope` from `run_meta.json`
2. Only evaluate `effective_playbook_ids` (NOT all playbooks in catalog)
3. Return `in_scope: false` for playbooks outside scope

### Constraint 4: Capability Snapshot Source

When determining capability for a run:
- **CORRECT:** Use `get_capability_snapshot_from_meta(run_meta.json)` - what was true AT run time
- **WRONG:** Use `get_capability_status()` - what is true NOW

### Constraint 5: Signal Type Format

Signal `signal_type` is stored as `"playbook:{playbook_id}"`.  
When matching signals to playbooks, strip the `"playbook:"` prefix:
```rust
let playbook_id = signal_type.strip_prefix("playbook:").unwrap_or(&signal_type);
```

---

## Route Inventory (Run-Scoped)

| Route | Handler | Line |
|-------|---------|------|
| `/api/runs/:run_id` | `get_run_handler` | [locint.rs#L420](crates/server/src/bin/locint.rs#L420) |
| `/api/runs/:run_id/coverage` | `run_coverage_handler` | [locint.rs#L424](crates/server/src/bin/locint.rs#L424) |
| `/api/runs/:run_id/facts` | `run_facts_handler` | [locint.rs#L425](crates/server/src/bin/locint.rs#L425) |
| `/api/runs/:run_id/facts/resolve` | `facts_resolve_handler` | [locint.rs#L426](crates/server/src/bin/locint.rs#L426) |
| `/api/runs/:run_id/evidence_summary` | `run_evidence_summary_handler` | [locint.rs#L427](crates/server/src/bin/locint.rs#L427) |
| `/api/runs/:run_id/brief` | `run_brief_handler` | [locint.rs#L428](crates/server/src/bin/locint.rs#L428) |
| `/api/runs/:run_id/events` | `run_events_handler` | [locint.rs#L430](crates/server/src/bin/locint.rs#L430) |
| `/api/runs/:run_id/signals` | `run_signals_handler` | [locint.rs#L431](crates/server/src/bin/locint.rs#L431) |
| `/api/runs/:run_id/segments` | `run_segments_handler` | [locint.rs#L432](crates/server/src/bin/locint.rs#L432) |
| `/api/runs/:run_id/playbooks` | `run_playbooks_handler` | [locint.rs#L436](crates/server/src/bin/locint.rs#L436) |
| `/api/runs/:run_id/playbooks/eval` | `run_playbooks_eval_handler` | [locint.rs#L437](crates/server/src/bin/locint.rs#L437) |
| `/api/runs/:run_id/step_status` | `run_step_status_handler` | [locint.rs#L466](crates/server/src/bin/locint.rs#L466) |

---

## Observed Lens: `/api/runs/:run_id/brief` Response

**BUILD-ID**: 2026-01-27-RUN_BRIEF-1

This endpoint provides a playbook-independent view of what actually happened during a run.
It aggregates data from per-run tables without requiring chain/playbook selection.

### Response Shape

```json
{
  "available": true,
  "totals": {
    "events_total": 12345,        // From coverage_rollup SUM(event_count)
    "facts_total": 8901,          // From coverage_rollup SUM(fact_count) 
    "signals_fired": 23,          // From signals table COUNT
    "segments_count": 5           // From segments table COUNT
  },
  "coverage": {
    "snapshot_present": true,     // From run_meta.json capability_snapshot
    "sysmon": true,
    "is_admin": true,
    "security_log_accessible": false,
    "gaps": ["PowerShellLogging"]
  },
  "timeline": [
    { "start_ts": 1706000000000, "end_ts": 1706000060000, "count": 234 }
  ],
  "top_entities": {
    "processes": [{ "entity": "powershell.exe", "count": 150 }],
    "destinations": [],
    "registry": [],
    "files": []
  },
  "notable_findings": [
    {
      "signal_id": "exec_obfuscated_command",
      "playbook_id": "persistence",
      "severity": "high",
      "ts_start": 1706000030000,
      "ts_end": 1706000045000,
      "evidence_refs_count": 3,
      "evidence_ptrs": [
        { "seg": "...", "row": 42, "ts": 1706000032000 }
      ]
    }
  ],
  "episodes": [
    {
      "episode_id": "ep_1706000030",
      "start_ts": 1706000030000,
      "end_ts": 1706000120000,
      "primary_entity": "powershell.exe → cmd.exe",
      "labels": ["Exec", "ScriptBlock"],
      "evidence_ptrs": [...]
    }
  ],
  "unmapped_activity": {
    "fact_type_counts": {
      "NetworkConnect": 45,
      "FileCreate": 23
    }
  }
}
```

### Data Sources

| Field | Source | Note |
|-------|--------|------|
| `totals.events_total` | `coverage_rollup` SUM | NOT sampled |
| `totals.facts_total` | `coverage_rollup` SUM | NOT sampled |
| `totals.signals_fired` | `signals` COUNT | All fired signals |
| `coverage.*` | `run_meta.json` → `capability_snapshot` | Constraint 4 |
| `top_entities.*` | `entity_rollup` OR `facts_sample` fallback | entity_rollup preferred |
| `notable_findings` | `signals` table | With evidence_ptrs from signal data |
| `episodes` | Clustered signals + facts | 60s window clustering |
| `unmapped_activity` | `facts_sample` minus signal-covered types | Shows gaps |

---

## Database Summary

### Server Database (`locint_data/locint.db`)

| Table | Purpose |
|-------|---------|
| `runs` | Run records (metadata, status, final metrics) |
| `baselines` | Baseline configurations |
| `team_cases` | Team tier case storage |

### Per-Run Database (`{run_dir}/workbench.db`)

| Table | Writer | Purpose |
|-------|--------|---------|
| `signals` | locald | Fired playbook detections |
| `signal_explanations` | locald | Signal explanations |
| `facts_sample` | locald | Sampled facts (200/type) |
| `coverage_rollup` | locald | Per-minute telemetry coverage |
| `segments` | locald | Processed segment metadata |
| `entity_rollup` | locald | Top-N entities by fact count |
| `playbook_eval_rollup` | locald | Per-playbook slot progress |
| `canonical_events` | (optional) | Raw events table |

---

*End of report.*

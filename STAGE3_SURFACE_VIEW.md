# STAGE 3 SURFACE VIEW: edr-server + UI Read Model Audit

**Generated:** 2026-01-11  
**Scope:** Full audit of edr-server Stage 3 - the ONLY user-facing entrypoint  
**Method:** Source code tracing with line-level grep-backed evidence

---

## A) STAGE 3 CONTRACTS (Authoritative Sources)

### 1. Run Directory Structure (run_dir)

**Source of Truth:** `run_control.rs:192-198`

```rust
let run_dir = self.telemetry_root.join("runs").join(&run_id);
let segments_dir = run_dir.join("segments");
let logs_dir = run_dir.join("logs");
```

**run_dir Layout:**
```
$EDR_TELEMETRY_ROOT/runs/<run_id>/
├── segments/               # JSONL event files
│   └── evtx_NNNNNN.jsonl
├── logs/
│   ├── capture.log        # capture_windows_rotating stdout/stderr
│   └── locald.log         # edr-locald stdout/stderr
├── workbench.db           # Per-run SQLite (signals, signal_explanations, coverage_rollup)
├── run.pid                # Server PID at run creation
└── index.json             # (if written by capture) segment inventory
```

### 2. Database Files

| DB File | Creator | Location | Schema Tables | Status |
|---------|---------|----------|--------------|--------|
| **workbench.db** | edr-server | `%LOCALAPPDATA%/attack-workbench/workbench.db` | documents, sessions, signals, runs, narratives, mission_specs, narrative_actions | ✅ ACTIVE - Server master DB |
| **workbench.db** | edr-locald | `$run_dir/workbench.db` | signals, signal_explanations, coverage_rollup, locald_checkpoint | ✅ ACTIVE - Per-run analysis DB |
| **analysis.db** | (legacy) | `$run_dir/analysis.db` | Same as workbench.db | ⚠️ FALLBACK ONLY |
| **signals.db** | (never created) | N/A | N/A | ❌ **BUG REFERENCE** |

**Evidence for Server DB Path:**
```rust
// main.rs:2577-2579
let db_path = data_dir.join("workbench.db");
tracing::info!("📁 Database: {:?}", db_path);
let db = Database::open(&db_path).expect("Failed to open database");
```

**Evidence for Per-Run DB Path:**
```rust
// locald/main.rs:247-249
let db_path = telemetry_root.join("workbench.db");
let db = match Connection::open(&db_path) {
```

**Evidence for Legacy Fallback:**
```rust
// run_coverage.rs:184-190
let workbench_path = run_dir.join("workbench.db");
let analysis_path = run_dir.join("analysis.db");

let db_path = if workbench_path.exists() {
    workbench_path
} else if analysis_path.exists() {
    analysis_path
```

### 3. Segment/Index Paths

| Artifact | Location | Producer | Consumer |
|----------|----------|----------|----------|
| Segments | `$run_dir/segments/*.jsonl` | capture_windows_rotating | edr-locald |
| Index | `$run_dir/segments/index.json` or `$run_dir/index.json` | capture_windows_rotating | UI (optional) |
| Logs | `$run_dir/logs/{capture,locald}.log` | capture/locald | Diagnostics |

### 4. API Endpoint → Data Source Mapping

| Endpoint | Handler | Reads From | DB/File |
|----------|---------|------------|---------|
| `GET /api/runs` | `list_runs_endpoint()` | **Server DB** | workbench.db → `runs` table |
| `GET /api/runs/:run_id/coverage` | `run_coverage::get_run_coverage()` | **Per-Run DB** | run_dir/workbench.db → `coverage_rollup` |
| `GET /api/signals` | `list_signals()` | **Server DB** | workbench.db → `signals` table |
| `GET /api/signals/:id` | `get_signal()` | **Server DB** | workbench.db → `signals` table |
| `GET /api/signals/:id/explain` | `get_signal_explanation()` | **Server DB** | workbench.db → `signal_explanations` table |
| `GET /api/signals/:id/narrative` | `get_signal_narrative()` | **Server DB** | workbench.db → `narratives` table |
| `GET /api/run/metrics` | `run_metrics()` | **Per-Run Dir** | Scans `run_dir/segments/`, opens `run_dir/signals.db` (**BUG!**) |
| `GET /api/diff` | `diff_endpoint()` | **Server DB** | workbench.db → `signals` table |
| `POST /api/export/bundle` | `export_bundle()` | In-memory | Uses report bundle from state |
| `POST /api/import/bundle` | `import_bundle_endpoint()` | ZIP bytes | Parses incoming bundle |

---

## B) STAGE 3 DATA MODEL

### 1. Runs Table Schema

**Location:** `db.rs:128-143`

```sql
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    profile TEXT,
    started_at TEXT NOT NULL,
    stopped_at TEXT,
    run_dir TEXT,                    -- ✅ Persisted artifact location
    events_total INTEGER NOT NULL DEFAULT 0,
    segments_count INTEGER NOT NULL DEFAULT 0,
    facts_extracted INTEGER NOT NULL DEFAULT 0,
    signals_fired INTEGER NOT NULL DEFAULT 0,
    bytes_written INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',
    created_at TEXT NOT NULL
);
```

**RunRecord Struct:** `db.rs:31-44`
```rust
pub struct RunRecord {
    pub run_id: String,
    pub profile: Option<String>,
    pub started_at: String,
    pub stopped_at: Option<String>,
    pub run_dir: Option<String>,    // ✅ Artifact location persisted
    pub events_total: u64,
    pub segments_count: u32,
    pub facts_extracted: u64,
    pub signals_fired: u64,
    pub bytes_written: u64,
    pub status: String,
}
```

### 2. Signals Storage

**Server DB Schema:** `db.rs:94-116`
```sql
CREATE TABLE IF NOT EXISTS signals (
    signal_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL DEFAULT 'unknown',  -- ✅ Links signal to run
    signal_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    host TEXT NOT NULL,
    ts INTEGER NOT NULL,
    ts_start INTEGER NOT NULL,
    ts_end INTEGER NOT NULL,
    proc_key TEXT,
    file_key TEXT,
    identity_key TEXT,
    detector_id TEXT NOT NULL DEFAULT 'unknown',
    detector_version TEXT NOT NULL DEFAULT '0.0.0',
    source_sensor TEXT NOT NULL DEFAULT 'unknown',
    metadata TEXT NOT NULL,
    evidence_ptrs TEXT NOT NULL,
    dropped_evidence_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
```

**Per-Run DB Schema (locald):** `locald/main.rs:252-274`
- Same schema as server, but written by locald during run
- Contains `signal_explanations` table linked by `signal_id`

### 3. Signal Explanations

**Server DB:** `db.rs:173-177` (lazily created)
```sql
CREATE TABLE IF NOT EXISTS signal_explanations (
    signal_id TEXT PRIMARY KEY,
    explanation_json TEXT NOT NULL,
    created_at TEXT NOT NULL
)
```

**Per-Run DB (locald):** `locald/main.rs:275-281`
```sql
CREATE TABLE IF NOT EXISTS signal_explanations (
    signal_id TEXT PRIMARY KEY,
    explanation_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (signal_id) REFERENCES signals(signal_id)
);
```

### 4. Coverage Rollup

**Per-Run DB (locald):** `locald/main.rs:287-299`
```sql
CREATE TABLE IF NOT EXISTS coverage_rollup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_minute INTEGER NOT NULL,
    host TEXT NOT NULL,
    sensor_mode TEXT,
    fact_type TEXT,
    fact_count INTEGER DEFAULT 0,
    signal_type TEXT,
    signal_count INTEGER DEFAULT 0,
    enabled_capabilities TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ts_minute, host, sensor_mode, fact_type, signal_type)
);
```

### 5. run_id Propagation (End-to-End)

| Stage | Source | Evidence |
|-------|--------|----------|
| **1. Server generates** | `run_control.rs:181-185` | `run_id = format!("run_{}_{}", timestamp, label)` |
| **2. Server passes to locald** | `run_control.rs:307` | `.env("EDR_RUN_ID", run_id)` |
| **3. Locald reads** | `locald/main.rs:222-228` | `std::env::var("EDR_RUN_ID")` |
| **4. Locald stamps signals** | `locald/main.rs` | Writes `run_id` column to signals table |
| **5. Server inserts run record** | `db.rs:503-522` | `insert_run()` with run_id |
| **6. API filters by run_id** | `db.rs:400-445` | `WHERE run_id = ?` in list_signals |
| **7. Coverage filters** | `run_coverage.rs:354-359` | `WHERE run_id = ?1` |

---

## C) RUNTIME READ PATHS vs WRITE PATHS

### Path 1: Start Run

```
POST /api/run/start
  └── main.rs:run_start()
        └── run_controller.start(req)
              ├── Create run_dir: runs/<run_id>/
              ├── Create segments/ and logs/
              ├── Write run.pid
              ├── start_capture() → spawn capture_windows_rotating.exe
              │     env: EDR_TELEMETRY_ROOT=run_dir, EDR_SEGMENTS_DIR=segments/
              └── start_locald() → spawn edr-locald.exe
                    env: EDR_TELEMETRY_ROOT=run_dir, EDR_RUN_ID=run_id
```

**WRITE PATH:** Server spawns capture + locald with env vars

### Path 2: Stop Run

```
POST /api/run/stop
  └── main.rs:run_stop()
        └── run_controller.stop()
              ├── Kill capture process
              ├── Kill locald process
              └── Clear run state (but NO DB finalization!)
```

**⚠️ ISSUE:** `run_control.rs:338-351` does NOT call `db.finalize_run()` or persist to runs table.

**Expected (not implemented):**
```rust
// Should call:
state.db.finalize_run(&run_id, &stopped_at, &metrics)?;
```

### Path 3: Runs List

```
GET /api/runs
  └── main.rs:list_runs_endpoint()
        └── diff_api::list_runs_response(&state.db)
              └── list_runs_from_db(db)
                    ├── First: db.list_runs(100) → runs table
                    └── Fallback: discover run_ids from signals table
```

**Evidence:** `diff_api.rs:93-176`

### Path 4: Signals List

```
GET /api/signals?run_id=X
  └── main.rs:list_signals()
        └── state.db.list_signals(run_id, host, type, severity, limit, offset)
              └── SELECT FROM signals WHERE run_id = ?
```

**READS FROM:** Server's workbench.db (NOT per-run DB)

**Evidence:** `main.rs:520-537`, `db.rs:400-450`

### Path 5: Explain (Signal Explanation)

```
GET /api/signals/:id/explain
  └── main.rs:get_signal_explanation()
        ├── state.db.get_signal(&id)
        └── state.db.get_signal_explanation(&id)
              └── SELECT FROM signal_explanations WHERE signal_id = ?
```

**READS FROM:** Server's workbench.db signal_explanations table

**Evidence:** `main.rs:551-592`

### Path 6: Coverage

```
GET /api/runs/:run_id/coverage
  └── run_coverage::get_run_coverage()
        ├── state.db.get_run(&run_id)  → Get run_dir from runs table
        ├── Check run_dir exists
        └── load_run_coverage(&run_dir, &run_id)
              ├── Open run_dir/workbench.db (or analysis.db fallback)
              └── SELECT FROM coverage_rollup
```

**READS FROM:** **Per-Run DB** (workbench.db in run_dir)

**Evidence:** `run_coverage.rs:580-700`

### Path 7: Export

```
POST /api/export/bundle
  └── main.rs:export_bundle()
        └── build_incident_bundle() → Creates in-memory bundle
              └── export_to_zip() → Returns ZIP bytes
```

**READS FROM:** In-memory state (not directly from per-run artifacts)

**Evidence:** `main.rs:1392-1480`, `bundle_exchange.rs`

### Path 8: Import

```
POST /api/import/bundle
  └── main.rs:import_bundle_endpoint()
        ├── import_bundle(&body) → Parse ZIP
        ├── validate_bundle()
        ├── mark_as_imported() → Add namespace isolation
        └── Update state (mode, preset)
```

**WRITES TO:** In-memory state, session metadata

**Evidence:** `main.rs:1487-1560`

---

## D) MISMATCH DETECTION (Bugs and Drift)

### 🐛 BUG 1: `signals.db` Reference (CONFIRMED)

**File:** `run_control.rs:401`
```rust
let signals_fired = if let Some(ref dir) = run_dir {
    count_signals_in_db(&dir.join("signals.db"))  // ❌ WRONG
} else {
    0
};
```

**Problem:** Locald writes to `workbench.db`, not `signals.db`. This file never exists.

**Correct:** Should be `workbench.db`

**Impact:** `GET /api/run/metrics` always returns `signals_fired: 0`

**Fix:**
```rust
count_signals_in_db(&dir.join("workbench.db"))
```

### 🐛 BUG 2: Run Finalization Not Wired

**File:** `run_control.rs:338-351`

**Problem:** `stop()` method kills processes but does NOT:
1. Call `db.finalize_run()` to persist stopped_at and final metrics
2. Update the runs table at all

**Evidence:** 
- `db.rs:527-544` defines `finalize_run()` method
- No caller in `run_control.rs`

**Impact:**
- Runs never get `stopped_at` timestamp
- `status` stays as "running" forever
- `signals_fired`, `events_total` etc. never updated

**Fix Required:** Call `finalize_run()` from stop endpoint or from controller

### 🐛 BUG 3: Signals Query Goes to Server DB, Not Per-Run DB

**File:** `main.rs:520-537`

**Problem:** `/api/signals?run_id=X` queries `state.db` (server's workbench.db), but signals are written by locald to `run_dir/workbench.db`.

**Impact:** If signals aren't copied/synced from per-run DB to server DB, API returns empty results.

**Analysis:** 
- Locald writes to `$run_dir/workbench.db`
- Server reads from `%LOCALAPPDATA%/attack-workbench/workbench.db`
- These are DIFFERENT files!

**Expected Behavior:** 
Option A: Sync signals from per-run DB to server DB on run stop
Option B: `/api/signals?run_id=X` should open `run_dir/workbench.db` dynamically

### 🐛 BUG 4: analysis.db in Error Messages

**File:** `run_coverage.rs:675, 688, 754`

```rust
expected_path: Some(run_dir.join("analysis.db").display().to_string()),
```

**Problem:** Error messages reference `analysis.db` when the code tries `workbench.db` first.

**Impact:** Confusing error messages

**Fix:** Update to show `workbench.db` or both in error messages

### ⚠️ ISSUE 5: Mixed DB Locations

**Finding:** The system has TWO workbench.db files with different schemas:

| Location | Contents | Issue |
|----------|----------|-------|
| Server DB | documents, sessions, runs, narratives, signals | UI reads here |
| Per-Run DB | signals, signal_explanations, coverage_rollup | locald writes here |

**Problem:** Signals written by locald to per-run DB are NOT automatically visible to server API.

### ⚠️ ISSUE 6: Run Record Not Inserted on Start

**File:** `run_control.rs:169-240`

**Problem:** `start()` spawns processes but does NOT call `db.insert_run()`.

**Impact:** New runs don't appear in `/api/runs` until... (unclear when)

**Evidence:** Search for `insert_run` in run_control.rs - 0 matches

---

## E) HANGING IMPLEMENTATION LIST

### BROKEN (Wrong filename/path/table)

| Item | File:Line | Severity | Issue | Fix |
|------|-----------|----------|-------|-----|
| signals.db reference | run_control.rs:401 | **High** | File never exists | Change to `workbench.db` |
| analysis.db in error | run_coverage.rs:675,688,754 | Low | Misleading message | Update message |

### MISSING (Endpoint/UI expects field not produced)

| Item | File:Line | Severity | Issue | Fix |
|------|-----------|----------|-------|-----|
| Run insert on start | run_control.rs | **High** | Runs not persisted | Call `db.insert_run()` in `start()` |
| Run finalize on stop | run_control.rs:338 | **High** | Runs not finalized | Call `db.finalize_run()` in `stop()` |
| Signal sync | N/A | **High** | Per-run signals not in server DB | Add sync or dynamic query |

### INCOMPLETE (Implemented but not wired to UI)

| Item | File:Line | Severity | Issue | Fix |
|------|-----------|----------|-------|-----|
| Per-run signal explanations | Per-run DB | Medium | Server queries wrong DB for explain | Query per-run DB |
| Facts extracted | run_control.rs:411 | Low | Parsed from log, not DB | Consider using coverage_rollup |

### REDUNDANT/DUPLICATE

| Item | Files | Severity | Issue | Fix |
|------|-------|----------|-------|-----|
| Two workbench.db schemas | db.rs, locald/main.rs | Medium | Divergent schemas possible | Unify or document |
| signals in both DBs | Server + per-run | Medium | Unclear source of truth | Define canonical source |

---

## FIX PLAN (Minimal Changes)

### Priority 1: Fix Wrong Artifact References

#### Fix 1.1: signals.db → workbench.db
**File:** `crates/server/src/run_control.rs:401`
```rust
// BEFORE:
count_signals_in_db(&dir.join("signals.db"))

// AFTER:
count_signals_in_db(&dir.join("workbench.db"))
```

### Priority 2: Run Completion Produces Queryable Artifacts

#### Fix 2.1: Insert Run on Start
**File:** `crates/server/src/run_control.rs`, in `start()` method, after line 240

Add call to persist run record:
```rust
// After spawning processes, persist run record
let run_record = db::RunRecord {
    run_id: run_id.clone(),
    profile: req.profile.clone(),
    started_at: now.to_rfc3339(),
    stopped_at: None,
    run_dir: Some(run_dir.display().to_string()),
    events_total: 0,
    segments_count: 0,
    facts_extracted: 0,
    signals_fired: 0,
    bytes_written: 0,
    status: "running".to_string(),
};
// Need to pass db reference to RunController or call from endpoint
```

#### Fix 2.2: Finalize Run on Stop
**File:** `crates/server/src/run_control.rs`, in `stop()` method

Add call to finalize run record:
```rust
// Before clearing state, finalize run
let metrics = self.metrics().await;
let now = chrono::Utc::now().to_rfc3339();
// Need to pass db reference or call from endpoint
db.finalize_run(&run_id, &now, &db::RunMetrics {
    events_total: metrics.events_total,
    segments_count: metrics.segments_count,
    facts_extracted: metrics.facts_extracted,
    signals_fired: metrics.signals_fired,
    bytes_written: metrics.bytes_written,
})?;
```

### Priority 3: UI Has Consistent Read Model After Stop

#### Fix 3.1: Signal Sync on Stop

Option A: Copy signals from per-run DB to server DB
```rust
// After run stop, sync signals
fn sync_signals_to_server_db(run_dir: &Path, server_db: &Database) {
    let run_db_path = run_dir.join("workbench.db");
    if run_db_path.exists() {
        let run_conn = Connection::open(&run_db_path)?;
        // Query signals and explanations
        // Insert into server DB
    }
}
```

Option B: Dynamic per-run DB query (less intrusive)
```rust
// In get_signal_explanation(), check per-run DB if not in server DB
let explanation = state.db.get_signal_explanation(&id)?;
if explanation.is_none() {
    // Try per-run DB based on signal's run_id
    if let Ok(Some(run)) = state.db.get_run(&signal.run_id) {
        if let Some(run_dir) = run.run_dir {
            let run_db = open_run_db(&run_dir)?;
            explanation = query_explanation_from(&run_db, &id)?;
        }
    }
}
```

### Priority 4: Remove/Hide Non-Real Sensors

Already documented in SENSOR_USAGE_AUDIT.md:
- All monitors return `vec![]` (stubs)
- Adapters (Sysmon, Defender, ETW) only used in tests

**Recommendation:** Do not advertise these as "sensors" in UI/marketing. They're architectural placeholders.

---

## STAGE 3 TRUTH CHECKLIST

### After Stop Verification

| Check | Expected | How to Verify |
|-------|----------|---------------|
| `/api/runs` shows run | Run appears with correct `run_dir` | `curl localhost:3000/api/runs \| jq '.data[0].run_dir'` |
| Run has `stopped_at` | Non-null timestamp | `curl localhost:3000/api/runs \| jq '.data[0].stopped_at'` |
| Run has `status: stopped` | "stopped" | `curl localhost:3000/api/runs \| jq '.data[0].status'` |

### Signals Verification

| Check | Expected | How to Verify |
|-------|----------|---------------|
| `/api/signals?run_id=X` returns signals | Non-empty list if locald ran | `curl 'localhost:3000/api/signals?run_id=run_...'` |
| Signal has valid `run_id` | Matches run | `jq '.data[0].run_id'` |
| Signal has `detector_id` | Non-"unknown" | `jq '.data[0].detector_id'` |

### Coverage Verification

| Check | Expected | How to Verify |
|-------|----------|---------------|
| `/api/runs/:id/coverage` returns data | `available: true` or structured `available: false` | `curl localhost:3000/api/runs/run_.../coverage` |
| Coverage has `facts_total > 0` | Facts extracted | `jq '.facts_total'` |
| Coverage has `coverage_minutes > 0` | Time tracked | `jq '.pipeline_diagnostics.coverage_minutes'` |

### Metrics Verification

| Check | Expected | How to Verify |
|-------|----------|---------------|
| `/api/run/metrics` signals_fired | Matches signals in per-run DB | Compare with `SELECT COUNT(*) FROM signals` in `run_dir/workbench.db` |
| Segments count accurate | Matches actual JSONL files | `ls $run_dir/segments/*.jsonl \| wc -l` |

### No Stale References

| Check | Expected | How to Verify |
|-------|----------|---------------|
| No code references `signals.db` | 0 runtime usages | `rg "signals\.db" crates/server/src/` |
| Per-run DB is `workbench.db` | File exists | `ls $run_dir/workbench.db` |

---

## SUMMARY

### Critical Bugs (3)
1. **run_control.rs:401** references `signals.db` (file never created) → signals_fired always 0
2. **Run start** doesn't insert run record → new runs not queryable
3. **Run stop** doesn't finalize → status stuck as "running", no final metrics

### Architectural Issues (2)
1. **Two workbench.db files** (server vs per-run) with different data
2. **Signals not synced** from per-run DB to server DB

### Documentation Mismatches (1)
1. Error messages reference `analysis.db` but code tries `workbench.db` first

### Minimal Fix Priority
1. Change `signals.db` → `workbench.db` in run_control.rs:401
2. Add `insert_run()` call on run start
3. Add `finalize_run()` call on run stop
4. Add signal sync from per-run DB to server DB on stop

---

**END OF STAGE 3 SURFACE VIEW**

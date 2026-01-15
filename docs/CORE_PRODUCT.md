# CORE PRODUCT CONSTITUTION

This document defines the **Core Loop** - the minimal, reliable functionality that must work 100% before any other features are enabled. Non-core features are gated behind Cargo features and compile only when explicitly requested.

---

## 1. Core Loop Definition

The core product is a single-session Windows telemetry capture and signal detection tool:

```
Start App → Start Run → Capture + Detect → Stop Run → Review → Export/Import
```

### 1.1 Core Binaries

| Binary | Description | Required |
|--------|-------------|----------|
| `locint.exe` | Primary GUI entry point (desktop double-click) | YES |
| `edr-server.exe` | Headless CLI server (automation use) | YES |
| `edr-locald.exe` | Detection daemon | YES |
| `capture_windows_rotating.exe` | Telemetry capture agent | YES |

### 1.2 Core Artifacts (per run)

Every run creates a `run_dir` with exactly these files:

| Artifact | Description | Written By |
|----------|-------------|------------|
| `run_meta.json` | Run metadata (started_at, stopped_at, finalized, profile) | locint/server |
| `segments/*.jsonl` | Raw telemetry records | capture agent |
| `workbench.db` | Signals, explanations, coverage_rollup, facts | locald |
| `logs/capture.log` | Capture agent stdout/stderr | process redirect |
| `logs/locald.log` | Locald stdout/stderr | process redirect |

### 1.3 Core Database Schema

The `workbench.db` SQLite database must contain:

```sql
-- Detected signals
CREATE TABLE signals (
  id TEXT PRIMARY KEY,
  signal_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  ts_ms INTEGER,
  host TEXT,
  json_blob TEXT,
  explanation_json TEXT,
  mitre_technique TEXT,
  mitre_tactic TEXT,
  created_at TEXT
);

-- MITRE coverage rollup
CREATE TABLE coverage_rollup (
  technique_id TEXT PRIMARY KEY,
  tactic TEXT,
  technique_name TEXT,
  signal_count INTEGER DEFAULT 0,
  first_seen TEXT,
  last_seen TEXT
);

-- Extracted facts (optional for core, but locald writes them)
CREATE TABLE facts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fact_type TEXT NOT NULL,
  key TEXT,
  value TEXT,
  ts_ms INTEGER,
  host TEXT,
  created_at TEXT
);
```

---

## 2. Core Endpoints

These endpoints are required for the core loop and must be present in every build:

### 2.1 Health & Lifecycle

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check, returns `{status: "ok"}` |
| `/api/run/start` | POST | Start capture + locald, creates run_dir |
| `/api/run/stop` | POST | Stop capture + locald, finalize run_meta.json |
| `/api/run/status` | GET | Current run state (running, run_id, elapsed) |
| `/api/run/metrics` | GET | Live metrics (events, segments, signals) |

### 2.2 Run Review

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/runs` | GET | List all runs |
| `/api/runs/:id/coverage` | GET | Coverage data (facts, types, hosts, diagnostics) |
| `/api/runs/:id/signals` | GET | Signals for run (with query params) |

### 2.3 Signals & Explainability

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/signals` | GET | Query signals (with run isolation) |
| `/api/signals/:id` | GET | Get single signal |
| `/api/signals/:id/explain` | GET | Get signal explanation |

### 2.4 Export/Import

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/export/bundle` | POST | Export run to ZIP (blocked while running) |
| `/api/import/bundle` | POST | Import ZIP bundle (read-only mode) |

### 2.5 UI & Config

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/features` | GET | Feature flags status |
| `/api/capture/profiles` | GET | Available capture profiles |
| `/api/app/state` | GET | App state for UI |
| `/api/selfcheck` | GET | Readiness/self-check |
| `/ui/*` | GET | Static UI files |

### 2.6 Detection Plan & Playbook Catalog

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/playbooks/catalog` | GET | System-wide playbook catalog with telemetry status |
| `/api/runs/:id/playbooks` | GET | Per-run playbook evaluation with why_not_fired |

---

## 2.5 Detection Plan Concept

The **Detection Plan** shows users what the system CAN and CANNOT detect based on current telemetry availability.

### Contract:
- Lists ALL available playbooks (enabled and blocked)
- Shows `telemetry_blocked: true/false` per playbook
- Explains blocking reasons (e.g., "Sysmon not installed")
- Provides `slots_summary` with human-readable slot intents
- Displays in Settings tab as "Detection Plan" panel

### Implementation:
- Endpoint: `/api/playbooks/catalog`
- Checks: `check_sysmon_installed()`, `check_security_log_accessible()`
- UI: Detection Plan panel in Settings with searchable playbook list

---

## 2.6 Explainability Invariants

**CRITICAL INVARIANTS** - These must be enforced at all times:

### Invariant 1: Every RUN has a Run Story
Every run MUST have a Run Story explanation (state + coverage + playbook progress/near-miss), even if it produced 0 signals.

**Elements:**
- Run state: started_at, stopped_at, duration, finalized
- Coverage summary: techniques seen, facts collected
- Playbook progress: fired, near-miss (partial slot fill), not-fired

### Invariant 2: Every SIGNAL has an ExplainResponse
Every signal MUST return an `ExplainResponse` object with `available: true/false`, regardless of whether it came from a playbook-based or hardcoded detector.

**Response Schema:**
```json
// When explanation IS available:
{
  "success": true,
  "data": {
    "signal_id": "...",
    "available": true,
    "explanation": { /* full ExplanationBundle */ }
  }
}

// When explanation is NOT available:
{
  "success": true,
  "data": {
    "signal_id": "...",
    "available": false,
    "reason_code": "EXPLANATION_NOT_FOUND | SIGNAL_NOT_FOUND | HYPOTHESIS_NOT_FOUND",
    "message": "Human-readable reason",
    "partial_context": {
      "signal_type": "...",
      "severity": "...",
      "ts": ...,
      "host": "...",
      "metadata": { /* real signal metadata */ },
      "evidence_ptrs": [ /* real evidence pointers */ ],
      "playbook_eval": { /* if available */ }
    }
  }
}
```

### Invariant 3: Never Invent/Synthesize Signals or Explanations
- NEVER create signals to satisfy explainability
- NEVER generate synthetic `why_fired` narrative without real slot data
- Narrative generation requires: `status=fired` AND `filled_slots > 0` AND evidence exists
- If conditions not met, return `available: false` with `partial_context` only

### UI Contract:
- When `available: true`: Show full explanation with narrative
- When `available: false`: Show "⚠️ Explanation unavailable: {reason_code}" with partial context if available

---

## 2.7 Why-Fired Narrative Generation

Each explanation includes a **deterministic 2-4 sentence narrative** explaining why the detection fired.

### Pre-conditions (must ALL be true):
- Signal status = fired (playbook threshold met)
- At least one slot has `status = Filled`
- Evidence pointers exist for matched slots

If pre-conditions not met, no narrative is generated. The explanation will show:
`"Detection triggered but slot evidence not available for narrative generation."`

### Template Structure (when pre-conditions met):
1. **Sentence 1**: What was detected (required)
   - "The 'X' detector identified a {category} pattern."
2. **Sentence 2**: What slots matched
   - "Evidence matched 'A' and 'B' criteria."
3. **Sentence 3**: Slot completion status
   - "All N required slots were satisfied."
4. **Sentence 4**: Category context
   - "This activity falls under the 'persistence' threat category."

### Implementation:
- Function: `generate_why_fired_narrative()` in `explanation_builder.rs`
- Uses: `playbook.title`, `playbook.family`, slot names, filled count

---

## 3. Core UI

### 3.1 Main Tabs (Core)

| Tab | Description | Required |
|-----|-------------|----------|
| Mission | Start/stop run, live metrics | YES |
| Runs | List runs, select for review | YES |
| Import/Export | Import bundle, export bundle | YES |
| Settings | Health check, connection info | YES |

### 3.2 Run Detail Tabs (Core)

| Tab | Description | Required |
|-----|-------------|----------|
| Overview | Run summary, data sources | YES |
| Findings | Signals list with severity filter | YES |
| Facts | Extracted facts by type/host | YES |
| Explain | Signal explanation (select signal first) | YES |

### 3.3 Non-Core UI (Feature-Gated)

These tabs require feature flags:

| Tab | Feature | Description |
|-----|---------|-------------|
| Changes | `diff` | Diff between runs |
| Playbooks | `playbook_debug` | Playbook diagnostics |
| Timeline | `timeline` | Event timeline view |
| Raw JSON | Always shown (debug) | Raw signal JSON |
| Narrative | `narrative` | Natural language narrative |

---

## 4. Feature Flags

### 4.1 Cargo Features

```toml
[features]
default = ["core"]
core = []                    # Always enabled, core loop only
pro = ["diff", "narrative", "watermark"]
diff = []                    # Delta reports between runs
narrative = []               # Natural language narratives
watermark = []               # Report watermarking
golden_bundle = []           # Golden bundle CI testing
support_bundle = []          # Support bundle generation
integrations = []            # SIEM/vendor integrations
workbench_api = []           # Attack documentation workbench API
```

### 4.2 Runtime Checks

Code uses `#[cfg(feature = "X")]` for compile-time gating:

```rust
#[cfg(feature = "diff")]
mod diff_api;

#[cfg(feature = "diff")]
.route("/api/diff", get(diff_handler))
```

---

## 5. Core Loop Truth Checks

A build passes the core loop if ALL of these pass:

### 5.1 Start Run
- [ ] `POST /api/run/start` returns `{run_id, started_at}`
- [ ] `capture_windows_rotating.exe` process starts
- [ ] `edr-locald.exe` process starts
- [ ] `run_meta.json` created with `started_at`

### 5.2 Live Metrics
- [ ] `GET /api/run/status` returns `{running: true}`
- [ ] `GET /api/run/metrics` returns increasing `segments_count`
- [ ] `segments/*.jsonl` files appear in run_dir

### 5.3 Stop Run
- [ ] `POST /api/run/stop` returns `{stopped: true, finalized: true}`
- [ ] Both processes terminate
- [ ] `run_meta.json` updated with `stopped_at`, `finalized: true`
- [ ] Final stats written (`events_total`, `signals_fired`, etc.)

### 5.4 Review Run
- [ ] `GET /api/runs` lists the run
- [ ] `GET /api/runs/:id/coverage` returns coverage data
- [ ] `GET /api/signals?run_id=X` returns signals (may be empty)
- [ ] UI displays run in Runs tab

### 5.5 Export/Import
- [ ] `POST /api/export/bundle` while running returns error
- [ ] `POST /api/export/bundle` after stop returns ZIP
- [ ] `POST /api/import/bundle` creates imported namespace
- [ ] Imported run is read-only

---

## 6. Excluded from Core

These modules/features are NOT part of core and must be feature-gated:

| Module | Reason |
|--------|--------|
| `diff.rs`, `diff_api.rs` | Pro feature: delta reports |
| `narrative.rs` | Pro feature: NLP narratives |
| `watermark.rs` | Pro feature: report watermarks |
| `golden_bundle.rs` | CI testing only |
| `support_bundle.rs` | Debugging only |
| `integration_api.rs` | Enterprise: SIEM integrations |
| `license_gen` binary | Internal tooling only |
| `golden-cli` binary | CI tooling only |
| `workbench` crate | Attack documentation (separate product) |

---

## 7. Dead Code Quarantine

These files are deprecated and should be gated or removed:

| File | Status | Action |
|------|--------|--------|
| `crates/server/src/main.rs` | Deprecated (use locint.rs) | Gate behind `legacy_server` |
| `crates/agent-windows/src/main.rs` | Deprecated | Remove (not in binaries) |
| `crates/locald/src/bin/proof_run.rs` | Dev utility | Gate behind `dev_utils` |
| `crates/locald/src/bin/metrics_run.rs` | Dev utility | Gate behind `dev_utils` |
| `crates/locald/src/bin/explain_harness.rs` | Dev utility | Gate behind `dev_utils` |

---

## 8. Response Format Contract

All core endpoints use consistent response format:

### Success
```json
{
  "success": true,
  "data": { ... }
}
```

### Error
```json
{
  "success": false,
  "error": "Human-readable message",
  "code": "MACHINE_CODE"
}
```

### Error Codes (Core)
- `RUN_ALREADY_ACTIVE` - Cannot start: run in progress
- `NO_ACTIVE_RUN` - Cannot stop: no run active
- `EXPORT_BLOCKED_RUNNING` - Cannot export while running
- `RUN_NOT_FOUND` - Run ID not found
- `SIGNAL_NOT_FOUND` - Signal ID not found
- `INVALID_BUNDLE` - Import bundle validation failed

---

## 9. Verification

Run `cargo run --bin wi_run_all --release` to verify core loop:

```
Exit 0 = Core loop passes
Exit 1 = Setup failure
Exit 2 = Run lifecycle failure
Exit 3 = Database integrity failure
Exit 4 = API contract failure
```

---

*Document created: Core Product Constitution v1.0*
*Purpose: Define and enforce the reliable core loop*

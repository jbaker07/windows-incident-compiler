# Reliability Defects Fixed (RD-1 through RD-5)

This document summarizes the fixes applied to address the 5 reliability defects identified in the core loop debugging session.

**Last Updated**: 2025-01-11 (FINISH LINE update)

---

## RD-1: Tickers Not Updating Reliably

**Problem**: Metrics endpoint was using `bytes_written / 500` estimate for event count instead of querying the database.

**Root Cause**: `run_metrics_handler` calculated `events: bytes_written / 500` which was an unreliable estimate. Also `parse_locald_facts()` was parsing log files with regex.

**Fix Applied** in [run_control.rs](../crates/server/src/run_control.rs):
- **REMOVED**: `parse_locald_facts()` function - no more log regex parsing
- **REMOVED**: `bytes_written / 500` estimation
- **ADDED**: `query_facts_from_db()` - queries workbench.db coverage_rollup for fact_count sum
- **ADDED**: `query_events_from_db()` - queries workbench.db coverage_rollup for event_count sum
- Returns `Option<u64>` - `None` if DB unavailable or query fails
- UI shows "—" for null values (truthful "unknown" state)

**Contract**:
```rust
// /api/run/metrics response - ALL values from DB, NOT estimates
{
    "events_total": u64 | null,     // null = unknown, 0 = genuinely zero
    "segments_count": u32,          // from fs::read_dir
    "facts_extracted": u64 | null,  // from DB SUM(fact_count)
    "signals_fired": usize | null   // from DB COUNT(*)
}
```

---

## RD-2: Findings Showing 0 on Runs That Produced Signals

**Problem**: Run list and detail views showed `signal_count: 0` even when signals existed.

**Root Cause**: Query timing - signals were being queried before locald finished writing to workbench.db.

**Fix Applied**:
- `run_stop_handler` now implements proper finalization phases (see RD-5)
- `read_run_stats()` correctly queries `SELECT COUNT(*) FROM signals` table
- `list_runs_handler` reads from run_meta.json which has final counts after finalization

**Verification**: After stop, check that `run_meta.json` contains `finalized: true` and accurate counts.

---

## RD-3: Playbooks API Returns Network Error When Not Configured

**Problem**: When playbooks directory wasn't found, the API returned inconsistent error responses.

**Root Cause**: Error responses were using `reason` instead of `reason_code`, and missing required fields. Also responses weren't wrapped in `{success, data}`.

**Fix Applied** in `run_playbooks_handler` ([locint.rs](../crates/server/src/bin/locint.rs)):
- All responses now use standard wrapper: `{success: true/false, data: {...}}`
- When `available: false`, response now includes:
  - `reason_code`: "PLAYBOOKS_DISABLED" | "PLAYBOOKS_NOT_FOUND" | "DB_ERROR"
  - `message`: Human-readable explanation
  - `searched_paths`: Directories that were checked
  - `loaded_count`, `fired_count`, `skipped_count`, `skipped_by_reason` (all 0 or {})

**Contract**:
```json
// When playbooks unavailable
{
    "success": true,
    "data": {
        "available": false,
        "reason_code": "PLAYBOOKS_NOT_FOUND",
        "message": "Playbooks directory not found",
        "searched_paths": ["playbooks/windows", "LocInt/playbooks/windows"],
        "run_id": "run_...",
        "loaded_count": 0,
        "fired_count": 0,
        "skipped_count": 0,
        "skipped_by_reason": {}
    }
}

// When playbooks available
{
    "success": true,
    "data": {
        "available": true,
        "loaded_count": 5,
        "loaded_playbooks": ["credential_access", "persistence"],
        "fired_count": 2,
        "fired_playbooks": ["credential_access", "persistence"],
        "skipped_count": 3,
        "skipped_by_reason": {"no_matching_events": 3}
    }
}
```

---

## RD-4: Export Triggering Memory Injection Signals

**Problem**: When exporting a bundle, the export process itself (reading files, creating ZIP) was triggering memory injection false positives. Also export was allowed while run was active.

**Root Cause**: LocInt's own processes weren't excluded from fact extraction; export didn't check run phase.

**Fixes Applied**:

### 1. Export Blocked While Running OR Finalizing
In `export_bundle_handler` ([locint.rs](../crates/server/src/bin/locint.rs)):
```rust
// Check Supervisor phase - ONLY allow export when Idle or Completed
let phase = state.supervisor.current_phase().await;
if phase != RunPhase::Idle && phase != RunPhase::Completed {
    return 409 Conflict with code "RUN_ACTIVE"
}

// Fallback: Also check process-level with tasklist
```

**Export blocking phases**:
- `Starting` - Block (run initializing)
- `Running` - Block (capture active)
- `DrainingLocald` - Block (locald still processing)
- `Finalizing` - Block (run_meta.json being written)
- `Idle` - **Allow** (no run active)
- `Completed` - **Allow** (run finished)

### 2. Self-Process Allowlist
In fact_extractor.rs:

```rust
/// Check if a process path is one of our own binaries (should be ignored)
fn is_self_process(proc_path: &str) -> bool {
    let lower = proc_path.to_lowercase();
    lower.ends_with("locint.exe")
        || lower.ends_with("edr-server.exe")
        || lower.ends_with("edr-locald.exe")
        || lower.ends_with("capture_windows_rotating.exe")
}
```

---

## RD-5: Runs Not Persisting Final Counts

**Problem**: After stopping a run, `run_meta.json` didn't have `finalized: true` or accurate final counts.

**Root Cause**: `run_stop_handler` wasn't properly waiting for processes to terminate and flush data.

**Fix Applied** - Supervisor pattern in [supervisor.rs](../crates/server/src/supervisor.rs):

The Supervisor manages run lifecycle with proper phase transitions:

```rust
pub enum RunPhase {
    Idle,            // No run active
    Starting,        // Processes launching
    Running,         // Capture + locald active
    DrainingLocald,  // Capture stopped, locald draining
    Finalizing,      // Writing final metadata
    Completed,       // Run complete
}
```

**`stop_and_finalize()` flow**:
1. Set phase to `DrainingLocald`
2. Stop capture process first
3. Wait for capture to exit
4. Stop locald process
5. Wait for locald to exit
6. Set phase to `Finalizing`
7. Write finalized run_meta.json with all counts
8. Set phase to `Completed`

**Final run_meta.json structure**:
```json
{
    "run_id": "run_...",
    "started_at": "2025-01-10T12:00:00Z",
    "stopped_at": "2025-01-10T12:05:00Z",
    "status": "completed",
    "phase": "completed",
    "finalized": true,
    "profile": "extended",
    "events_total": 1500,
    "segments_count": 15,
    "facts_extracted": 200,
    "signals_fired": 3
}
```

---

## Endpoint Response Consistency (Task F)

All core endpoints now use the standard wrapper format:

**Success**:
```json
{
    "success": true,
    "data": { ... }
}
```

**Error**:
```json
{
    "success": false,
    "error": "Human-readable message",
    "code": "MACHINE_CODE"
}
```

**Endpoints updated for consistency**:
- `run_coverage_handler` - now wraps response
- `run_changes_handler` - now wraps response
- `signals_handler` - now wraps response (returns `{signals: [...]}` in data)
- `signal_explain_handler` - now wraps response
- `selfcheck_handler` - now wraps response
- `run_playbooks_handler` - now wraps response

---

## Verification Checklist

After deploying these fixes:

1. **Start 3 runs, stop each, verify**:
   - [ ] `run_meta.json` has `finalized: true`
   - [ ] `run_meta.json` has accurate `events_total`, `signals_fired`
   - [ ] `/api/runs` shows correct signal counts

2. **While run is active**:
   - [ ] `/api/run/metrics` returns DB-queried values (not estimates)
   - [ ] UI updates counters every 1 second
   - [ ] `/api/export/bundle` returns 409 with `RUN_ACTIVE`

3. **While run is finalizing**:
   - [ ] `/api/run/status` shows `phase: "finalizing"` or `phase: "draining_locald"`
   - [ ] `/api/export/bundle` returns 409 with `RUN_ACTIVE`

4. **Playbooks edge cases**:
   - [ ] Without playbooks dir: returns `available: false` with `reason_code`
   - [ ] With LOCINT_PLAYBOOKS=off: returns `PLAYBOOKS_DISABLED`
   - [ ] With playbooks: shows `loaded_count`, `fired_count`, `skipped_count`

5. **Self-process filtering**:
   - [ ] Export doesn't trigger memory injection signals
   - [ ] LocInt's own processes don't appear in findings

6. **Response consistency**:
   - [ ] All endpoints return `{success, data}` or `{success, error, code}`
   - [ ] No bare JSON responses

---

*Document created: 2025-01-10*
*Last updated: 2025-01-11 (FINISH LINE)*
*Fixes: RD-1 through RD-5*

# Authoritative Route Map from Code

**Generated from**: `crates/server/src/bin/locint.rs` lines 164-189  
**UI Source**: `ui/app.js`  
**Last Updated**: 2026-01-11

---

## Route Registry (locint.rs build_locint_router)

| Method | Path | Handler | Response Schema | UI Caller (app.js) |
|--------|------|---------|-----------------|-------------------|
| GET | `/` | redirect → `/ui/` | 302 Redirect | (browser navigation) |
| GET | `/health` | `health_handler` | `{success, data: {status, version, binary}}` | — |
| GET | `/api/health` | `health_handler` | `{success, data: {status, version, binary}}` | line 591 `checkHealth()` |
| POST | `/api/run/start` | `run_start_handler` | `{run_id, run_dir, capture_pid, locald_pid, started_at, playbooks_enabled, playbooks_dir}` | line 840 `startRun()` |
| POST | `/api/run/stop` | `run_stop_handler` | `{stopped, run_id?, stopped_at, finalized?, events_total?, ...}` | line 917 `stopRun()` |
| GET | `/api/run/status` | `run_status_handler` | `{running, run_id?, started_at?, elapsed_seconds?, capture_running, locald_running, is_admin}` | line 673 `fetchRunStatus()` |
| GET | `/api/run/metrics` | `run_metrics_handler` | `{success, data: {running, run_id, segments_count, events_total, facts_extracted, signals_fired, bytes_written, elapsed_seconds, ...noise_stats}}` | line 714 `fetchRunMetrics()` |
| GET | `/api/runs` | `list_runs_handler` | `{success, data: [{run_id, signal_count, earliest_ts, latest_ts, started_at, stopped_at, status, ...}]}` | line 943 `fetchRuns()` |
| GET | `/api/runs/:run_id/coverage` | `run_coverage_handler` | `{available, run_id, coverage_rows?, signals_count?, reason?}` | line 1592 `loadRunCoverage()` |
| GET | `/api/runs/:run_id/changes` | `run_changes_handler` | `{available, run_id, highlights, changes, categories, stats}` | line 2011 `loadRunChanges()` |
| GET | `/api/runs/:run_id/playbooks` | `run_playbooks_handler` | `{available, run_id, playbooks_enabled, loaded_count, fired_count, matches, mitre_techniques, ...}` | line 2145 `loadRunPlaybooks()` |
| GET | `/api/signals` | `signals_handler` | `[{signal_id, signal_type, severity, ts, host}]` | line 1043 `fetchSignalsForRun()` |
| GET | `/api/signals/stats` | `signal_stats_handler` | `{success, data: {total, by_type, by_severity}}` | line 1138 `fetchSignalStats()` |
| GET | `/api/signals/:id` | `get_signal_handler` | `{success, data: {signal_id, signal_type, severity, ts, host, raw}}` | line 1071 `fetchSignalDetail()` |
| GET | `/api/signals/:id/explain` | `signal_explain_handler` | `{signal_id, explanation?, note?}` | line 1091 `fetchSignalExplanation()` |
| GET | `/api/app/state` | `app_state_handler` | `{success, data: {initialized, binary, version, is_admin}}` | — (not used) |
| GET | `/api/selfcheck` | `selfcheck_handler` | `{verdict, is_admin, issues[], resources{}}` | line 617 `checkReadiness()` |
| GET | `/api/features` | `features_handler` | `{success, features: {core, diff, narrative, ...}}` | — (used on boot) |
| GET | `/api/capture/profiles` | `capture_profiles_handler` | `{success, profiles: [{id, description, sensors_count, ...}]}` | — |
| POST | `/api/export/bundle` | `export_bundle_handler` | `{success, size}` or `409 {success:false, error, code}` | line 1162 `exportBundle()` |

---

## Endpoint-UI Mapping Details

### Mission Tab Endpoints
| Endpoint | UI Function | Line | Purpose |
|----------|-------------|------|---------|
| `GET /api/health` | `checkHealth()` | 591 | Server online badge |
| `GET /api/selfcheck` | `checkReadiness()` | 617 | Readiness state (healthy/blocked) |
| `GET /api/run/status` | `fetchRunStatus()` | 673 | Running state, run_id, elapsed |
| `GET /api/run/metrics` | `fetchRunMetrics()` | 714 | Live counters (events, facts, signals) |
| `POST /api/run/start` | `startRun()` | 840 | Start capture + locald |
| `POST /api/run/stop` | `stopRun()` | 917 | Stop and finalize run |

### Runs Tab Endpoints
| Endpoint | UI Function | Line | Purpose |
|----------|-------------|------|---------|
| `GET /api/runs` | `fetchRuns()` | 943 | List all runs |
| `GET /api/runs/:id/coverage` | `loadRunCoverage()` | 1592 | Facts, types, hosts, diagnostics |
| `GET /api/runs/:id/changes` | `loadRunChanges()` | 2011 | Changes tab data |
| `GET /api/runs/:id/playbooks` | `loadRunPlaybooks()` | 2145 | Playbooks tab data |
| `GET /api/signals?run_id=X` | `fetchSignalsForRun()` | 1043 | Findings for run |
| `GET /api/signals/:id` | `fetchSignalDetail()` | 1071 | Single signal detail |
| `GET /api/signals/:id/explain` | `fetchSignalExplanation()` | 1091 | Explanation bundle |
| `POST /api/export/bundle` | `exportBundle()` | 1162 | Export run as bundle |

---

## Missing/Unused Endpoints

### UI Calls Endpoint That Doesn't Exist
| Endpoint | UI Line | Status |
|----------|---------|--------|
| `GET /api/signals/:id/narrative` | 1114 | **NOT IMPLEMENTED** - returns 404 |
| `GET /api/runs/:id/signals` | — | Not in router; UI uses `/api/signals?run_id=X` |

### Server Has Endpoint UI Doesn't Use
| Endpoint | Handler | Notes |
|----------|---------|-------|
| `/api/app/state` | `app_state_handler` | Unused - could be removed |
| `/api/capture/profiles` | `capture_profiles_handler` | Unused - could be removed |

---

## Response Wrapper Contract

**Per Truth Rule #6**, all endpoints MUST use:

```json
// Success
{ "success": true, "data": ... }

// Error
{ "success": false, "error": "message", "code": "ERROR_CODE" }
```

### Current Compliance Status

| Endpoint | Compliant | Notes |
|----------|-----------|-------|
| `/api/health` | ✅ | Returns `{success, data}` |
| `/api/run/metrics` | ✅ | Returns `{success, data}` |
| `/api/runs` | ✅ | Returns `{success, data}` |
| `/api/signals/stats` | ✅ | Returns `{success, data}` |
| `/api/signals/:id` | ✅ | Returns `{success, data}` |
| `/api/run/start` | ⚠️ | Returns raw object (no wrapper) |
| `/api/run/stop` | ⚠️ | Returns raw object (no wrapper) |
| `/api/run/status` | ⚠️ | Returns raw object (no wrapper) |
| `/api/runs/:id/coverage` | ⚠️ | Returns `{available}` not `{success}` |
| `/api/runs/:id/changes` | ⚠️ | Returns `{available}` not `{success}` |
| `/api/runs/:id/playbooks` | ⚠️ | Returns `{available}` not `{success}` |
| `/api/signals` | ❌ | Returns raw array |
| `/api/export/bundle` | ⚠️ | Partial - 409 has code but not wrapped |

---

## Known Issues Status (RD-1 through RD-5)

### RD-1: Metrics Truthfulness
- **Location**: `run_metrics_handler` + `query_events_from_db()`
- **Problem**: `events_total` was estimated as `bytes_written / 500`
- **Status**: ✅ FIXED
- **Fix**: Added `query_events_from_db()` and `query_facts_from_db()` that query workbench.db
  - Checks `coverage_rollup.event_count` first
  - Falls back to `COUNT(*)` from segments
  - Returns `Option<u64>` - UI shows "—" for null

### RD-2: Zero Findings When Facts Exist
- **Location**: `list_runs_handler` + `run_stop_handler`
- **Problem**: Signals queried before locald finished writing
- **Status**: ✅ FIXED (via RD-5 finalization)
- **Fix**: Proper finalization phases ensure DB is complete before counts read

### RD-3: Playbooks "Network Error"
- **Location**: `run_playbooks_handler`
- **Problem**: Inconsistent error responses when playbooks unavailable
- **Status**: ✅ FIXED
- **Fix**: Returns structured response with:
  - `available: false`
  - `reason_code`: "PLAYBOOKS_DISABLED" | "PLAYBOOKS_NOT_FOUND" | "DB_ERROR"
  - `message`, `searched_paths`, `loaded_count`, `fired_count`, `skipped_count`, `skipped_by_reason`

### RD-4: Export Triggers Memory Injection
- **Location**: `export_bundle_handler` + `crates/locald/src/os/windows/fact_extractor.rs`
- **Problem**: Export while running creates ETW events that trip detectors
- **Status**: ✅ FIXED
- **Fixes**:
  1. Export blocked while running (returns 409 with code "RUN_ACTIVE")
  2. Self-process allowlist in `fact_extractor.rs`:
     - locint.exe, edr-server.exe, edr-locald.exe, capture_windows_rotating.exe
     - Events from these processes filtered out in `extract_facts()`

### RD-5: Runs Don't Persist Final Counts
- **Location**: `run_stop_handler` + `run_status_handler`
- **Problem**: stop killed processes without finalize phase
- **Status**: ✅ FIXED
- **Fix**: 7-phase stop handler:
  1. Mark run as "finalizing"
  2. Stop capture first
  3. Wait 300ms for segment flush
  4. Update phase to "draining_locald"
  5. Stop locald
  6. Poll for termination (up to 2s)
  7. Write finalized run_meta.json with final counts
- **Status handler**: Now includes `phase` field (running/draining_locald/completed)

---

## File Locations

| Component | Path |
|-----------|------|
| Server routes | `crates/server/src/bin/locint.rs` |
| UI JavaScript | `ui/app.js` |
| Locald daemon | `crates/locald/src/main.rs` |
| Fact extractor | `crates/locald/src/os/windows/fact_extractor.rs` |
| Capture binary | `crates/agent-windows/src/bin/capture_windows_rotating.rs` |
| Core Event type | `crates/core/src/event.rs` |
| RD Fixes Summary | `docs/RD_FIXES_SUMMARY.md` |

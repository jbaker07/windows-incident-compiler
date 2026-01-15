# Flakiness Playbook

**Purpose**: When "it doesn't work," diagnose in under 1 minute using the flight recorder and dataflow snapshot.

---

## OPERATOR CHECKLIST: If Findings Are Empty

**Open**: `http://127.0.0.1:3000/api/meta/dataflow_snapshot?debug=1`

Check these 6 fields in order:

| # | Field | Expected | If Wrong |
|---|-------|----------|----------|
| 1 | `diagnosis` | `["OK: No obvious dataflow issues detected"]` | Read the diagnosis! It tells you what's broken |
| 2 | `spawn_status.locald_running` | `true` (during run) | locald crashed - check `paths.logs_path/locald.log` |
| 3 | `segments_status.segments_count` | `> 0` after 5s | capture not writing - check `paths.logs_path/capture.log` |
| 4 | `segments_status.newest_segment.age_seconds` | `< 30` during run | capture stalled - restart run |
| 5 | `db_truth.tables[signals].rowcount` | `> 0` after 10s | locald not processing - check locald.log |
| 6 | `db_truth.can_read` | `true` | DB locked - another process has exclusive lock |

**If all 6 pass but still no signals**: 
- Check `active_run.run_id` matches the run you're viewing in UI
- Check UI is connected to correct port (see `instance.port`)

---

## Quick Start: When Updates Aren't Showing

1. **Open dataflow snapshot**: Click the port badge in UI header (e.g., `:3000`) or:
   ```
   http://127.0.0.1:3000/api/meta/dataflow_snapshot?debug=1
   ```

2. **Check the snapshot for these common issues** (see signatures below)

3. **Review flight log tail**: The snapshot includes the last 20 flight recorder events

---

## How to Read the Dataflow Snapshot

The snapshot provides a complete view of the system state:

```json
{
  "instance": {
    "pid": 12345,           // This server's process ID
    "port": 3000,           // Port the server is listening on
    "is_admin": false,      // Running as Administrator?
    "api_base": "http://127.0.0.1:3000/api",
    "data_dir": "C:\\Users\\...\\attack-workbench"
  },
  "active_run": {           // null if no run active
    "run_id": "run_20260112_143022",
    "run_dir": "...",
    "phase": "running",     // idle|starting|running|draining_locald|finalizing|completed
    "elapsed_seconds": 45
  },
  "paths": {
    "db_path_for_live_queries": "...\\workbench.db",  // The DB server reads
    "segments_path": "...\\segments",
    "flight_log": "...\\diagnostics\\flight_12345_3000.jsonl"
  },
  "spawn_status": {
    "capture_running": true,
    "capture_pid": 12346,
    "locald_running": true,
    "locald_pid": 12347
  },
  "db_truth": {
    "db_exists": true,
    "can_read": true,
    "journal_mode": "wal",
    "tables": [
      {"name": "signals", "rowcount": 5, "max_ts": 1736694622000},
      {"name": "coverage_rollup", "rowcount": 12, "max_ts": null},
      {"name": "segments", "rowcount": 3, "max_ts": null}
    ]
  },
  "recent_events": [...]    // Last 20 flight recorder events
}
```

---

## Failure Signature #1: Split-Brain (Two Instances)

**Symptom**: Updates appear inconsistent; sometimes work, sometimes don't.

**Snapshot Check**:
- You see flight event `instance_conflict` in recent events
- OR: You got an error at startup saying "Another instance is running"

**Root Cause**: Two LocInt instances running on different ports. UI connected to wrong one.

**Fix**:
1. Close all LocInt windows
2. Kill any orphan processes: `taskkill /F /IM locint.exe`
3. Restart LocInt (only one instance)

**Prevention**: The instance lock should prevent this. If you see this, report it.

---

## Failure Signature #2: Wrong Database Path

**Symptom**: Run starts, but signals never appear.

**Snapshot Check**:
```json
"db_truth": {
  "db_path": "C:\\path\\to\\wrong\\workbench.db",
  "can_read": true,
  "tables": [{"name": "signals", "rowcount": 0}]
}
```
- `db_path` doesn't match `active_run.run_dir + "/workbench.db"`

**Root Cause**: Server is querying a different workbench.db than locald is writing.

**Fix**:
1. Check the `paths.db_path_for_live_queries` in snapshot
2. Should be: `{active_run.run_dir}/workbench.db`
3. If mismatched, restart LocInt

---

## Failure Signature #3: Locald Not Running

**Symptom**: Capture running, but no signals/facts appear.

**Snapshot Check**:
```json
"spawn_status": {
  "capture_running": true,
  "locald_running": false,   // <-- Problem!
  "locald_pid": null
}
```

**Root Cause**: locald crashed or failed to spawn.

**Investigation**:
1. Check `{run_dir}/logs/locald.log` for crash reason
2. Look for `spawn_fail` events in `recent_events`
3. Common causes:
   - Missing `edr-locald.exe` binary
   - Binary incompatibility
   - Segfault in playbook processing

**Fix**:
1. Stop the run
2. Check locald.log for errors
3. Rebuild locald: `cargo build --release -p locald --bin edr-locald`
4. Start new run

---

## Failure Signature #4: Capture Not Running

**Symptom**: Run shows "running" but no segments appear.

**Snapshot Check**:
```json
"spawn_status": {
  "capture_running": false,  // <-- Problem!
  "locald_running": true
}
```
OR:
```json
"db_truth": {
  "tables": [{"name": "segments", "rowcount": 0}]
}
```

**Root Cause**: Capture process crashed or never started.

**Investigation**:
1. Check `{run_dir}/logs/capture.log`
2. Look for `spawn_fail` events
3. Common causes:
   - Not running as Administrator (for ETW)
   - Missing capture binary

**Fix**:
1. Run as Administrator for full telemetry
2. Check capture.log for specific error
3. Rebuild: `cargo build --release -p agent-windows --bin capture_windows_rotating`

---

## Failure Signature #5: Database Locked

**Symptom**: Updates stop mid-run; "database is locked" in logs.

**Snapshot Check**:
```json
"db_truth": {
  "can_read": false,
  "error": "database is locked"
}
```

**Root Cause**: SQLite contention between reader (server) and writer (locald).

**Investigation**:
1. Check `journal_mode` - should be `wal` for concurrent access
2. Check for orphan connections

**Fix**:
1. Stop the run
2. Delete any `.db-shm` and `.db-wal` files in run_dir
3. Start new run

**Prevention**: Both server and locald should use WAL mode. If this happens frequently, report it.

---

## Failure Signature #6: No Segments Written

**Symptom**: Run active, capture running, but rowcount=0 for segments.

**Snapshot Check**:
```json
"spawn_status": {
  "capture_running": true
},
"db_truth": {
  "tables": [{"name": "segments", "rowcount": 0}]
}
```

**Root Cause**: Capture is running but not writing segments to the expected directory.

**Investigation**:
1. Check `paths.segments_path`
2. Manually list files: `ls "{segments_path}"`
3. If files exist but rowcount=0, locald isn't ingesting

**Fix**:
1. Verify `EDR_SEGMENTS_DIR` env var passed to capture matches `paths.segments_path`
2. Check capture.log for write errors

---

## Failure Signature #7: Not Running as Administrator

**Symptom**: "Limited telemetry" warning; Security log events missing.

**Snapshot Check**:
```json
"instance": {
  "is_admin": false
}
```

**Root Cause**: LocInt needs Administrator for full ETW access.

**Fix**:
1. Close LocInt
2. Right-click → Run as Administrator
3. Or use the "Restart as Admin" button in Settings

---

## Failure Signature #8: Readiness Timeout

**Symptom**: Run starts but phase stuck at "starting".

**Snapshot Check**: Look in `recent_events` for:
```json
{
  "event": "readiness_timeout",
  "fields": {
    "gate": "locald_ready",
    "waited_ms": 3000,
    "reason": "timeout waiting for locald DB"
  }
}
```

**Root Cause**: Locald didn't create workbench.db within expected time.

**Investigation**:
1. Check locald.log for startup errors
2. Check if segments exist (locald needs input)
3. May indicate slow disk or very large backlog

**Fix**:
1. Wait longer (locald may still be processing)
2. If stuck, stop run and check logs

---

## Using the Flight Log

The flight recorder writes to: `{data_dir}/diagnostics/flight_{pid}_{port}.jsonl`

Each line is a JSON event:
```json
{"ts_ms":1736694622000,"ts_iso":"2026-01-12T14:30:22Z","level":"info","component":"supervisor","event":"run_start","seq":42,"fields":{"run_id":"run_20260112_143022",...}}
```

### Key Events to Search For

| Event | Meaning |
|-------|---------|
| `boot` | Server started |
| `run_start` | Run initiated |
| `spawn` | Process spawned successfully |
| `spawn_fail` | Process failed to spawn (check fields.error) |
| `phase_change` | Run phase transition |
| `readiness_check` | Gate check (passed/failed) |
| `readiness_timeout` | Gate timed out |
| `db_open` | Database opened |
| `db_error` | Database error |
| `instance_lock` | Instance lock acquired |
| `instance_conflict` | Another instance detected |
| `run_stop` | Run stopped/finalized |

### Quick Search Commands

```powershell
# Find all errors
Select-String -Path "diagnostics\flight_*.jsonl" -Pattern '"level":"error"'

# Find spawn failures
Select-String -Path "diagnostics\flight_*.jsonl" -Pattern "spawn_fail"

# Find phase changes for a run
Select-String -Path "diagnostics\flight_*.jsonl" -Pattern "phase_change" | Select-String "run_20260112"

# Tail latest events
Get-Content "diagnostics\flight_12345_3000.jsonl" -Tail 50
```

---

## Escalation Checklist

If the playbook doesn't resolve the issue:

1. **Collect artifacts**:
   - Flight log: `{data_dir}/diagnostics/flight_*.jsonl`
   - Run logs: `{run_dir}/logs/*.log`
   - Dataflow snapshot JSON

2. **Note the exact steps** to reproduce

3. **Check for known issues** in CHANGELOG.md

4. **File issue** with:
   - Snapshot JSON
   - Flight log tail (last 100 lines)
   - Process list (`tasklist | Select-String "locint|edr-|capture"`)
   - Windows version and admin status

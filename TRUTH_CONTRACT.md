# TRUTH_CONTRACT.md

> **Ship Pass Invariants**: 10 post-run conditions that must hold for a valid release.
> **Verified by**: `wi_run_all` smoke test harness (hard-fail on any violation)

---

## The 10 Invariants

### 1. Run Record Persisted on Start

**Condition**: When `/api/run/start` returns success, a `runs` table row exists with:
- `run_id` matches response
- `status = 'running'`
- `started_at` is set
- `run_dir` points to valid directory

**Verification**: `SELECT * FROM runs WHERE run_id = ? AND status = 'running'`

---

### 2. Run Record Finalized on Stop

**Condition**: When `/api/run/stop` returns success, the run record has:
- `status = 'stopped'`
- `stopped_at` is set
- `events_total`, `facts_extracted`, `signals_fired` reflect final counts

**Verification**: `SELECT * FROM runs WHERE run_id = ? AND stopped_at IS NOT NULL`

---

### 3. Per-Run Database Created

**Condition**: After a run produces artifacts, `{run_dir}/workbench.db` exists and contains:
- `signals` table (may be empty)
- `signal_explanations` table (may be empty)

**Verification**: `os.path.exists(run_dir + "/workbench.db")` and valid SQLite schema

---

### 4. No signals.db References

**Condition**: The string `signals.db` does not appear in any runtime code path.
All signal storage uses `workbench.db`.

**Verification**: `grep -r "signals.db" crates/` returns 0 matches (excluding comments/docs)

---

### 5. Run-Scoped Endpoints Require run_id

**Condition**: When `run_id` query param is provided to `/api/signals` or `/api/signals/:id/explain`:
- Endpoint queries `{run_dir}/workbench.db` (not server DB)
- Returns error if run not found (no silent fallback)

**Verification**: 
- `GET /api/signals?run_id=invalid` returns 404/error
- `GET /api/signals?run_id=valid` returns data from per-run DB

---

### 6. Coverage Reflects Observed Reality

**Condition**: `/api/selfcheck` returns per-channel status with:
- `configured`: whether channel is in capture config
- `observed`: whether events were received
- `last_seen_ts`: actual timestamp or null
- `missing_reason`: explanation if no events

**Verification**: Response contains `streams[]` with truthful `last_seen_ts` values

---

### 7. Metrics Match Database

**Condition**: `/api/run/metrics` returns counts that match database queries:
- `signals_fired` = `SELECT COUNT(*) FROM signals` in per-run DB
- `segments_count` = count of `.jsonl` files in `{run_dir}/segments/`

**Verification**: Cross-check metrics response against filesystem/DB

---

### 8. UI Passes run_id on Signals Requests

**Condition**: When viewing a completed run, the UI passes `run_id` to:
- `/api/signals?run_id=X`
- `/api/signals/:id/explain?run_id=X`

**Verification**: Network tab shows `run_id` query param in requests

---

### 9. Explain Endpoint Returns Canonical Shape

**Condition**: `/api/signals/:id/explain` always returns consistent shape:
```json
{
  "signal_id": "...",
  "signal_type": "...",
  "entities": {...},
  "evidence": [...],
  "scoring": {...},
  "playbook_id": "..."
}
```
Fields may be empty objects/arrays but must be present.

**Verification**: Response validates against ExplainResponse schema

---

### 10. No Orphan Code Trees

**Condition**: These paths do not exist:
- `locald/` at workspace root (deprecated duplicate)
- `locald/scoring/` (duplicate of `crates/locald/src/scoring/`)
- `locald/baseline/` (duplicate of `crates/locald/src/baseline/`)

**Verification**: `test ! -d locald/` returns success

---

## Verification Commands

```powershell
# Run full smoke test with invariant checks
cargo run --bin wi_run_all --release

# Manual verification
# 1. Run record
sqlite3 data/workbench.db "SELECT run_id, status, started_at, stopped_at FROM runs ORDER BY started_at DESC LIMIT 1"

# 2. Per-run DB
dir runs\run_*\workbench.db

# 3. No signals.db
findstr /S /I "signals.db" crates\**\*.rs

# 4. Coverage endpoint
curl http://localhost:3000/api/selfcheck | jq '.streams'

# 5. Orphan code check
if (Test-Path locald) { Write-Error "FAIL: locald/ exists" }
```

---

## wi_run_all Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All invariants pass |
| 1 | Setup failure (server didn't start) |
| 2 | Run lifecycle failure (invariants 1-2) |
| 3 | Database integrity failure (invariants 3-4) |
| 4 | API contract failure (invariants 5-9) |
| 5 | Code hygiene failure (invariant 10) |

---

## Capability Model Truth Contract

The Capability Model provides always-on visibility into sensor status and detection coverage.
It MUST adhere to the following truthfulness guarantees:

### Sensor Status Truth

| Status | Guarantee |
|--------|-----------|
| `active` | Sensor IS producing events NOW. Never claim active when blocked/missing. |
| `configured` | Sensor installed but channel may be disabled. |
| `missing` | Sensor NOT installed. Must have `reason_code` and `message`. |
| `blocked` | Sensor exists but access denied. Must have `reason_code` and `message`. |

### Attack Surface Truth

| Status | Guarantee |
|--------|-----------|
| `covered` | All sensors for this surface are active. |
| `partial` | Some sensors active, some missing/blocked. |
| `blocked` | No sensors active. Must have `blocked_reason`. |

### Playbook Derived Status Truth

| Status | Guarantee |
|--------|-----------|
| `enabled` | All requirements met. YAML enabled + sensors available. |
| `blocked_by_telemetry` | Missing sensors. Must have `blocked_by` + `reasons`. |
| `disabled_by_config` | YAML has `enabled: false`. |
| `skipped_invalid` | YAML parse error. Must have reason. |

**NEVER CLAIM**:
- Sensor `active` when it's blocked or missing
- Surface `covered` when required sensors are unavailable
- Playbook `enabled` when telemetry requirements not met

**ALWAYS INCLUDE**:
- `reason_code` and `message` for any blocked/missing state
- `blocked_by` list for blocked playbooks
- `captured_at` timestamp in capability snapshots

### Capability Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /api/capability/status` | Current sensor inventory and capability status |
| `GET /api/capability/detection_plan` | Detection plan with playbook dependencies |
| `run_meta.json.readiness_snapshot.capability_snapshot` | Snapshot at run start |

---

*Last updated: 2026-01-12 (Capability Model)*

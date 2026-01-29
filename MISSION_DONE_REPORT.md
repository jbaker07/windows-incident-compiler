# MISSION_DONE Report
**Build Stamp:** `2026-01-27-MISSION_DONE-1`
**Date:** 2026-01-27

## Summary

Mission is now ship-grade with **backend-canonical step satisfaction**. Frontend no longer guesses step status - it queries the backend for truthful satisfaction based on actual run evidence.

## What Was Done

### Part A: Backend Step Status Endpoint
- **Endpoint:** `GET /api/runs/:run_id/step_status?chain_ids=process-injection,credential-dump`
- **Location:** [locint.rs](crates/server/src/bin/locint.rs) - handler `run_step_status_handler`
- **Service:** [chains.rs](crates/server/src/services/chains.rs) - `compute_step_status()` function

**Response shape:**
```json
{
  "success": true,
  "run_id": "run_12345",
  "chains": [
    {
      "chain_id": "process-injection",
      "title": "Process Injection",
      "icon": "💉",
      "steps": [
        {
          "step_id": "alloc",
          "title": "Memory Allocation",
          "icon": "🧠",
          "state": "satisfied",
          "evidence_refs_count": 3,
          "matched_playbooks": ["pb-injection-001"],
          "matched_signals": [
            {
              "signal_id": "sig-xxx",
              "playbook_id": "pb-injection-001",
              "severity": "high",
              "evidence_count": 3
            }
          ],
          "why": null,
          "coverage_gaps": []
        }
      ]
    }
  ],
  "is_live": true,
  "generated_at": "2026-01-27T18:00:00Z"
}
```

### Part B: Step States
Five canonical states:

| State | Meaning | Icon |
|-------|---------|------|
| `not_observed` | No evidence observed for this step | ⚪ |
| `candidate` | Some matching data but insufficient to satisfy | 🟡 |
| `satisfied` | Step satisfied with backing evidence (signals + evidence_refs) | ✅ |
| `blocked` | Step cannot be evaluated (missing telemetry requirements) | ⛔ |
| `unverified` | Step has partial telemetry (can evaluate but may miss detections) | ❓ |

**Satisfaction Rule:** A step is `satisfied` only when:
1. At least one signal fired for a playbook in the step's mapping
2. The signal has non-empty `evidence_refs` array

### Part C: is_live Flag
- `is_live: true` = Run is still capturing (status = "capturing" or "active")
- `is_live: false` = Run has stopped, can compute final satisfaction
- Frontend polls step_status during live runs (every signal poll cycle)
- Frontend fetches step_status once when selecting a historical run

### Part D: Frontend Wiring
**New functions in app.js:**
- `fetchStepStatusFromBackend(runId, chainIds)` - Calls backend endpoint
- `updateStepStatusFromBackend()` - Converts response to frontend state format

**Integration points:**
1. `pollLiveSignals()` - Calls `updateStepStatusFromBackend()` during live capture
2. `loadSignalsForRun()` - Calls `updateStepStatusFromBackend()` when selecting a run
3. `state.outcome.stepStatus` - Now populated from backend, not frontend guesswork

### Part E: Tests
Added to [chains.rs](crates/server/src/services/chains.rs):
- `test_step_status_not_observed` - No signals → all steps not_observed
- `test_step_status_satisfied_with_evidence` - Signal + evidence → satisfied
- `test_step_status_candidate_no_evidence` - Signal but no evidence_refs → candidate
- `test_step_status_blocked_no_sysmon` - Missing requirement → blocked
- `test_step_state_serialization` - State enum serializes correctly

All 11 tests pass.

## Startup Verification
When locint starts, it now logs:
```
[CHAINS] Registry loaded N chains
[STEP_STATUS] Backend-canonical step satisfaction enabled (GET /api/runs/:run_id/step_status)
```

## Files Modified

### Backend
1. `crates/server/src/services/chains.rs`
   - Added `StepState` enum
   - Added `StepStatus`, `StepStatusResult`, `ChainStatus` structs
   - Added `RunSignal`, `CapabilitySnapshot` structs
   - Added `compute_step_status()` function
   - Added helper functions: `check_chain_requirements()`, `check_chain_partial_telemetry()`
   - Added 5 tests for step status

2. `crates/server/src/bin/locint.rs`
   - Added route: `/api/runs/:run_id/step_status`
   - Added handler: `run_step_status_handler`
   - Added helpers: `query_run_signals_for_step_status()`, `get_capability_snapshot_from_run()`
   - Added startup log for step_status

### Frontend
1. `ui/app.js`
   - Updated BUILD_STAMP to `2026-01-27-MISSION_DONE-1`
   - Added `fetchStepStatusFromBackend()` function
   - Added `updateStepStatusFromBackend()` function
   - Modified `pollLiveSignals()` to call step status update
   - Modified `loadSignalsForRun()` to call step status update
   - Updated header comment with MISSION v2026-01-27 documentation

## QA Verification Checklist

### Pre-flight
- [ ] Kill any running locint.exe
- [ ] Run `cargo build --package edr-server --bin locint --release`
- [ ] Copy UI files: `Copy-Item ui\*.js,ui\*.html target\release\ui\ -Force`

### Test Cases
- [ ] Start locint, verify "[STEP_STATUS] enabled" in logs
- [ ] Open Mission tab, select a chain (e.g., process-injection)
- [ ] Start a run → steps should show ⚪ (not_observed)
- [ ] Trigger a detection that fires a signal → step should become ✅ (satisfied)
- [ ] Stop run, select it from history → step status should load correctly
- [ ] Select chain requiring Sysmon when Sysmon not installed → steps should show ⛔ (blocked)

## Architecture Truth

This implementation follows the Truth Contract:
- **Backend is canonical** for step satisfaction computation
- **Frontend displays** what backend tells it, does not compute satisfaction
- **Evidence is required** for satisfaction (not just signal presence)
- **is_live flag** enables honest polling behavior

---

*Build completed: 2026-01-27-MISSION_DONE-1*

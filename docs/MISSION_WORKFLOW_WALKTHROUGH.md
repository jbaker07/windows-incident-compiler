# Mission Workflow UI Walkthrough

This document describes the end-to-end Mission Workflow in EDR Desktop.

## Overview

The Mission Workflow provides a structured approach to running detection validation:
1. **Select a Mission Profile** - Choose what type of activity to capture
2. **Run the Mission** - Execute commands, capture telemetry
3. **View Quality Gates** - See pass/warn/skip/fail for each gate
4. **Export Artifacts** - Get run_summary.json and quality_report.json

---

## UI Flow (Text Walkthrough)

### Step 1: Launch & Readiness Check

```
┌─────────────────────────────────────────────────────────────────┐
│  🔬 EDR Desktop                                                 │
├─────────────────────────────────────────────────────────────────┤
│  System Readiness                                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ [SKIP] Admin: No                                         │   │
│  │ [SKIP] Sysmon: Not Installed                            │   │
│  │ [  OK] Process Auditing: N/A (limited mode)             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Overall: ⚠️ Limited Capability Mode                           │
│  Missions will run with reduced telemetry coverage.            │
└─────────────────────────────────────────────────────────────────┘
```

**Key Behavior**: Quality gates show `Skip` (not `Fail`) when capabilities are missing.
This allows the workflow to proceed with appropriate expectations.

---

### Step 2: Mission Profile Selection

```
┌─────────────────────────────────────────────────────────────────┐
│  Select Mission Profile                                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  🔍 DISCOVERY                                                   │
│  ┌─────────────────────┐  ┌─────────────────────┐              │
│  │ Benign Admin       │  │ Developer Workflow  │              │
│  │ Normal sysadmin    │  │ git, cargo, node    │              │
│  │ tasks (should be   │  │ commands (should    │              │
│  │ quiet)             │  │ not alert)          │              │
│  │ [5 steps, ~30s]    │  │ [3 steps, ~15s]     │              │
│  └─────────────────────┘  └─────────────────────┘              │
│                                                                 │
│  🎯 ADVERSARY SIMULATION                                        │
│  ┌─────────────────────┐  ┌─────────────────────┐              │
│  │ LOLBin Tier A      │  │ LOLBin Tier B       │              │
│  │ whoami, net user,  │  │ Registry, schtasks, │              │
│  │ systeminfo...      │  │ WMIC queries        │              │
│  │ [T1033, T1082...]  │  │ [T1012, T1053...]   │              │
│  └─────────────────────┘  └─────────────────────┘              │
│                                                                 │
│  Duration: [1 min ▼]  [5 min] [15 min] [30 min]                │
│                                                                 │
│           [ Start Mission ]                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

### Step 3: Mission Running

```
┌─────────────────────────────────────────────────────────────────┐
│  Mission: Benign Admin Activity                      🟢 RUNNING │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Elapsed: 00:23 / 01:00                                        │
│  ▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░ 38%                        │
│                                                                 │
│  Live Metrics                                                   │
│  ┌────────────┬────────────┬────────────┬────────────┐         │
│  │ Events     │ Facts      │ Signals    │ Incidents  │         │
│  │    1,247   │     891    │      0     │     0      │         │
│  │ captured   │ extracted  │ emitted    │ promoted   │         │
│  └────────────┴────────────┴────────────┴────────────┘         │
│                                                                 │
│  Scenario Progress                                              │
│  [OK] hostname         - 30ms, hash: 7bb35b45...               │
│  [OK] ipconfig /all    - 38ms, hash: b803f389...               │
│  [OK] whoami /all      - 72ms, hash: 5ca3c962...               │
│  [...] systeminfo      - running...                             │
│                                                                 │
│                    [ Stop Mission ]                             │
└─────────────────────────────────────────────────────────────────┘
```

**Key Behavior**: Each step execution is audit-logged with:
- `step_id` - Unique identifier
- `command` - Full command line
- `exit_code` - Process exit code
- `stdout_hash` - SHA256 hash of stdout (first 16 hex chars)
- `stderr_hash` - SHA256 hash of stderr
- `timestamp` - ISO8601 execution time

---

### Step 4: Quality Gates Scoreboard

```
┌─────────────────────────────────────────────────────────────────┐
│  Quality Gates Scoreboard                    Overall: ✅ PASS   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Gate             Status    Score    Message                    │
│  ─────────────────────────────────────────────────────────────  │
│  Readiness        ⏭️ Skip    40/100  Limited mode - not admin   │
│  Telemetry        ✅ Pass    85/100  1,247 events, 1 segment    │
│  Extraction       ✅ Pass    90/100  891 facts extracted        │
│  Detection        ✅ Pass   100/100  0 signals (expected)       │
│  Explainability   ⏭️ Skip   100/100  No signals to explain      │
│  Performance      ✅ Pass    95/100  Peak RSS: 50MB             │
│  Benign Noise     ✅ Pass   100/100  0 signals (max: 5)         │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ ✅ Discovery mission passed: benign activity produced   │   │
│  │    minimal noise. This validates noise suppression.     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  [ Export Run Summary ]  [ Export Quality Report ]              │
└─────────────────────────────────────────────────────────────────┘
```

**Key Behavior**: 
- Gates show `Skip` (⏭️) when capabilities are missing, NOT `Fail` (❌)
- This allows runs to succeed in limited environments
- Discovery missions expect 0 signals (noise validation)
- Adversary missions expect specific detections

---

## Run Artifacts

### run_summary.json

Location: `%LOCALAPPDATA%\edr-desktop\runs\<run_id>\run_summary.json`

```json
{
  "schema_version": "1.0.0",
  "run_id": "e2e_test_20260109_170637",
  "mission": {
    "type": "discovery",
    "profile": "discovery_benign_admin",
    "duration_requested_sec": 60
  },
  "timing": {
    "started_at": "2026-01-09T17:06:37.123Z",
    "ended_at": "2026-01-09T17:07:41.582Z",
    "duration_actual_sec": 64
  },
  "environment": {
    "is_admin": false,
    "sysmon_installed": false,
    "readiness_level": "Limited"
  },
  "capture": {
    "events_read": 10,
    "segments_written": 1
  },
  "compiler": {
    "facts_extracted": 5,
    "signals_emitted": 0
  },
  "scenario_audit": [
    {
      "step_id": "hostname",
      "command": "hostname.exe",
      "exit_code": 0,
      "stdout_hash": "7bb35b4516d5f18d",
      "timestamp": "2026-01-09T17:06:37.200Z",
      "duration_ms": 30
    }
  ]
}
```

### quality_report.json

Location: `%LOCALAPPDATA%\edr-desktop\runs\<run_id>\quality_report.json`

```json
{
  "schema_version": "1.0.0",
  "run_id": "e2e_test_20260109_170637",
  "generated_at": "2026-01-09T17:07:42.000Z",
  "gates": {
    "readiness": { "status": "skip", "score": 40, "message": "Limited mode" },
    "telemetry": { "status": "pass", "score": 85 },
    "extraction": { "status": "pass", "score": 90 },
    "detection": { "status": "pass", "score": 100 },
    "explainability": { "status": "skip", "score": 100 },
    "performance": { "status": "pass", "score": 95 }
  },
  "overall_verdict": "pass",
  "verdict_summary": "Discovery mission passed: benign activity produced minimal noise"
}
```

---

## Invoking from JavaScript (Tauri)

```javascript
// Get mission profiles
const profiles = await invoke('get_mission_profiles');

// Start a mission
const result = await invoke('start_mission', {
  profile_id: 'discovery_benign_admin',
  duration_override_minutes: 1
});

// Get live metrics
const metrics = await invoke('get_mission_metrics');

// Get quality scoreboard
const scoreboard = await invoke('get_quality_scoreboard');

// Stop mission
const stopResult = await invoke('stop_mission');

// Compare runs for regression
const comparison = await invoke('compare_runs', {
  current_run_path: 'C:\\...\\run_123',
  baseline_run_path: 'C:\\...\\run_baseline'
});
```

---

## Summary

The Mission Workflow delivers:

1. ✅ **Windows-only scenario execution** via `cfg(windows)` module
2. ✅ **Audit logging** with step_id, command, exit_code, stdout/stderr hash
3. ✅ **Capability-aware** metrics and quality gates
4. ✅ **Skip (not Fail)** for missing capabilities
5. ✅ **E2E proof run** with valid JSON artifacts
6. ✅ **Deterministic schemas** for run_summary and quality_report

The workflow is ready for validation testing against real Windows telemetry.

# EDR Verification Runbook

**Date**: 2026-01-05  
**Status**: Verified Working  

---

## Prerequisites

- Windows machine with PowerShell
- Rust toolchain installed (`cargo`)
- Administrator access recommended (for full event log capture)

---

## Step 1: Build

```powershell
cd path\to\windows-incident-compiler
cargo build --release
```

**Expected**: `Finished release profile [optimized]` with warnings only (no errors)

**Built binaries**:
- `target\release\edr-server.exe` (~8MB)
- `target\release\edr-locald.exe` (~4MB)
- `target\release\capture_windows_rotating.exe` (~900KB)

---

## Step 2: Environment Setup

```powershell
$env:EDR_TELEMETRY_ROOT = "C:\ProgramData\edr"

# Create required directories
@(
    "$env:EDR_TELEMETRY_ROOT",
    "$env:EDR_TELEMETRY_ROOT\segments",
    "$env:EDR_TELEMETRY_ROOT\playbooks\windows"
) | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force -ErrorAction SilentlyContinue }

# Copy playbooks
Copy-Item "playbooks\windows\*" "$env:EDR_TELEMETRY_ROOT\playbooks\windows" -Recurse -Force -ErrorAction SilentlyContinue
```

---

## Step 3: Start Stack (3 terminals or background)

### Terminal 1 - Capture Agent
```powershell
$env:EDR_TELEMETRY_ROOT = "C:\ProgramData\edr"
cd path\to\windows-incident-compiler
.\target\release\capture_windows_rotating.exe
```
**Expected output**: `Beginning Windows Event Log capture loop ...`, then a
`[capture_windows] Wrote evtx_NNNNNN (N records, N total)` line each time new
events are written (at most once a second). Ctrl-C, or creating
`C:\ProgramData\edr\capture.stop`, stops it after the last write.

### Terminal 2 - Locald (Signal Detector)
```powershell
$env:EDR_TELEMETRY_ROOT = "C:\ProgramData\edr"
cd path\to\windows-incident-compiler
.\target\release\edr-locald.exe
```
**Expected output**:
```
edr-locald starting (YAML playbook engine)
TELEMETRY_ROOT: C:\ProgramData\edr
Loaded 30 Windows playbooks (131 rules) from 30 files
Watching: C:\ProgramData\edr\index.json
```

### Terminal 3 - Server (API)
```powershell
$env:EDR_TELEMETRY_ROOT = "C:\ProgramData\edr"
cd path\to\windows-incident-compiler
.\target\release\edr-server.exe
```
**Expected output**: `Attack Documentation Workbench running at http://127.0.0.1:3000`.
The server listens on loopback only. Set `EDR_SERVER_BIND=0.0.0.0` to open it
to the network (for example inside a container), knowing the API has no
authentication.

---

## Step 4: Verify Health

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/health" -TimeoutSec 5
```

**Expected output**:
```
service                        status version
-------                        ------ -------
Attack Documentation Workbench ok     0.1.0
```

---

## Step 5: Generate Test Activity

Triggers detection playbooks by generating Windows events:

```powershell
# Process execution (triggers if 4688 auditing enabled)
whoami.exe /all
hostname.exe
systeminfo.exe

# If admin: more privileged events
sc.exe query type= service state= all
```

Wait 30 seconds for capture → locald → signals pipeline.

---

## Step 6: Verify Signals Exist

```powershell
$signals = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/signals" -TimeoutSec 10
Write-Host "Signal count: $($signals.data.Count)"
$signals.data | Select-Object -First 3 | ForEach-Object {
    Write-Host "  [$($_.severity)] $($_.signal_type) - $($_.signal_id)"
}
```

**Expected**: At least 1 signal (may require Security/Sysmon auditing for real detections)

**Sample output**:
```
Signal count: 4
  [CRITICAL] playbook:signal_log_tamper_detection - sig_5c0f8f1e2b7d4a6c9e3b1a0d7f2c4e81
  [HIGH] playbook:signal_service_persistence - sig_0c622e4eedd25af33c20bee475eec659
```

---

## Step 7: Verify Explanation with Evidence

```powershell
# Get first signal ID
$signals = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/signals" -TimeoutSec 10
$sigId = $signals.data[0].signal_id

# Get explanation
$explain = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/signals/$sigId/explain" -TimeoutSec 10
$explain.data | ConvertTo-Json -Depth 5
```

**Expected**: ExplanationBundle with:
- `playbook_id`: e.g., "signal_task_persistence"
- `slots`: Array with at least 1 filled slot
- `evidence`: Array with dereferenced excerpts
- `counters.required_slots_filled >= 1`

**Sample output structure**:
```json
{
  "playbook_id": "signal_task_persistence",
  "playbook_title": "Windows Task Scheduler Persistence",
  "family": "persistence",
  "slots": [
    {
      "slot_id": "step1",
      "status": "filled",
      "required": true,
      "matched_facts": [...]
    }
  ],
  "evidence": [
    {
      "ptr": { "stream_id": "...", "segment_id": 0, "record_index": 1 },
      "excerpt": "ts=1767485093325 host=WINDOWS-HLP8O87 tags=[windows,event_log,system]",
      "ts_ms": 1767485093325
    }
  ],
  "counters": {
    "required_slots_filled": 1,
    "required_slots_total": 1,
    "facts_emitted": 1
  }
}
```

---

## Step 8: Manual Evidence Deref (Optional Deep Verify)

```powershell
# From explanation, get evidence pointer
$ptr = $explain.data.evidence[0].ptr

# Read the segment file (capture names segments evtx_NNNNNN.jsonl)
$segmentPath = "$env:EDR_TELEMETRY_ROOT\segments\$($ptr.segment_id).jsonl"
if (-not (Test-Path $segmentPath)) {
    $segmentPath = "$env:EDR_TELEMETRY_ROOT\segments\evtx_{0:D6}.jsonl" -f [int]$ptr.segment_id
}
if (Test-Path $segmentPath) {
    $lines = Get-Content $segmentPath
    $record = $lines[$ptr.record_index] | ConvertFrom-Json
    Write-Host "Dereferenced record:"
    $record | ConvertTo-Json -Depth 3
} else {
    Write-Host "Segment file not found (may be synthetic test data)"
}
```

---

## Shutdown

```powershell
Get-Process edr-server, edr-locald, capture_windows_rotating -ErrorAction SilentlyContinue | Stop-Process -Force
```

---

## Golden Bundle Definition

A minimal bundle that **reliably triggers** a signal:

**Option A: Replay the end to end test fixture (any OS)**

`test_e2e/` holds only an `index.json` from a capture run, without its segment files, so
copying it does not trigger a signal. The end to end test builds a small telemetry folder
(Security log cleared, a service installed from a temp folder, a shadow copy deletion) and
runs `edr-locald --once` on it:
```powershell
cargo test -p edr-locald --test locald_yaml_e2e
```

**Option B: Generate fresh (requires admin)**
1. Start full stack (Steps 3)
2. Clear Security log (Event ID 1102 fires `signal_log_tamper_detection` and `signal_defense_evasion`)
   ```powershell
   # CAUTION: Only in test environments!
   wevtutil cl Security
   ```
3. Wait 30s for detection

---

## Troubleshooting

### No signals detected
- Check `C:\ProgramData\edr\segments\*.jsonl` exists
- Check `C:\ProgramData\edr\index.json` lists segments
- Verify locald stderr shows `[ingest] Processing: ...`
- For real detections, enable Security auditing (4688 process creation)

### Explanation missing
- Signal was created before explanation persistence was added
- Check `signal_explanations` table in `workbench.db`:
  ```powershell
  sqlite3 "$env:EDR_TELEMETRY_ROOT\workbench.db" "SELECT signal_id FROM signal_explanations"
  ```

### Server won't start
- Check port 3000 not in use: `netstat -an | findstr 3000`
- Check database exists: `Test-Path "$env:EDR_TELEMETRY_ROOT\workbench.db"`

---

## Summary

| Check | Expected |
|-------|----------|
| `cargo build --release` | Finishes with warnings only |
| `/api/health` | `status: ok` |
| `/api/signals` | `data.length >= 1` |
| `/api/signals/:id/explain` | Has `slots`, `evidence`, `counters` |
| Evidence excerpt | Contains `ts=`, `host=`, `tags=` |

**DONE** when all checks pass.

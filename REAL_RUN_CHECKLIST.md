# REAL RUN CHECKLIST

**Purpose:** Validate a production run using real Windows telemetry. No simulation, no smoke assumptions.

**When to use:** Before shipping, after major changes, or when validating a new deployment environment.

---

## Prerequisites

- [ ] Windows 10/11 or Server 2019+ with **Administrator privileges**
- [ ] Sysmon installed and running *(recommended, not required)*
- [ ] Server built: `cargo build --release -p edr-server` (or `locint` for GUI binary)
- [ ] At least 60 seconds of capture time for meaningful coverage

> **Note:** Without Sysmon, some fact types (ProcessCreate, FileCreate, NetworkConnect) and playbooks may not trigger. This is acceptable if `coverage_rollup` shows Security or System facts.

---

## Binary Options

| Binary | Use Case | Starts Browser |
|--------|----------|----------------|
| `edr-server.exe` | Development, headless | Manual |
| `locint.exe` | End-user distribution, standalone | Auto-opens |

**locint.exe** is a thin wrapper around edr-server that:
- Expects resources bundled in exe-relative paths (`ui/`, `playbooks/`, `locald.exe`, `capture.exe`)
- Shows Windows MessageBox errors for missing resources or port conflicts
- Auto-opens browser on startup

---

## 1. Execute a Real Capture Run

```powershell
# Option A: Development server
.\target\release\edr-server.exe

# Option B: Standalone GUI binary (auto-opens browser)
.\target\release\locint.exe

# In browser: http://127.0.0.1:3000/ui/
# 1. Click "Start" to begin capture
# 2. Generate some activity (open apps, run commands, browse files)
# 3. Wait at least 60 seconds
# 4. Click "Stop" to finalize
# 5. Note the run_id from the Runs list (e.g., run_1736600000000)
```

Set environment variables for subsequent checks:
```powershell
# Telemetry root: use EDR_TELEMETRY_ROOT if set, else default
$ROOT = if ($env:EDR_TELEMETRY_ROOT) { $env:EDR_TELEMETRY_ROOT } else { Join-Path $env:LOCALAPPDATA "attack-workbench" }

$RUN_ID = "run_1736600000000"  # Replace with actual run_id from UI
$RUN_DIR = Join-Path $ROOT "runs\$RUN_ID"

Write-Host "Telemetry root: $ROOT"
Write-Host "Run directory:  $RUN_DIR"
```

---

## 2. Filesystem Artifact Checks

### 2.1 Run Directory Structure

```powershell
# Verify run directory exists
Test-Path $RUN_DIR
# Expected: True

# List contents
Get-ChildItem $RUN_DIR -Recurse | Select-Object FullName, Length
```

**Required artifacts:**

| Path | Description | Fail if missing? |
|------|-------------|------------------|
| `<run_dir>/workbench.db` | Per-run signals + coverage | ✅ FAIL |
| `<run_dir>/segments/` | Raw event segments directory | ✅ FAIL |
| `<run_dir>/segments/*.jsonl` | At least one segment file | ✅ FAIL |
| `<run_dir>/logs/capture.log` | Capture process log | ✅ FAIL |
| `<run_dir>/logs/locald.log` | Detection daemon log | ✅ FAIL |

**Optional artifacts:**

| Path | Description |
|------|-------------|
| `<run_dir>/index.json` | Segment index (if capture writes it) |
| `<run_dir>/meta.json` | Run metadata |

### 2.2 Segment File Validation

```powershell
# Count segment files
$segments = Get-ChildItem (Join-Path $RUN_DIR "segments\*.jsonl") -ErrorAction SilentlyContinue
Write-Host "Segment files: $($segments.Count)"
# Expected: >= 1

# Check segment has content
if ($segments.Count -gt 0) {
    $firstSegment = $segments[0]
    $lineCount = (Get-Content $firstSegment.FullName | Measure-Object -Line).Lines
    Write-Host "Lines in first segment: $lineCount"
    # Expected: > 0
}
```

### 2.3 Workbench Database Exists and Has Size

```powershell
$dbPath = Join-Path $RUN_DIR "workbench.db"
if (Test-Path $dbPath) {
    $dbSize = (Get-Item $dbPath).Length
    Write-Host "workbench.db size: $dbSize bytes"
    # Expected: > 4096 (more than just schema)
} else {
    Write-Host "FAIL: workbench.db not found at $dbPath"
}
```

### 2.4 Log Files Exist

```powershell
$captureLog = Join-Path $RUN_DIR "logs\capture.log"
$localdLog = Join-Path $RUN_DIR "logs\locald.log"

Write-Host "capture.log exists: $(Test-Path $captureLog)"
Write-Host "locald.log exists:  $(Test-Path $localdLog)"
# Expected: Both True
```

---

## 3. SQLite Database Validation

### 3.1 Open Database

```powershell
# Using sqlite3 CLI (install via: winget install SQLite.SQLite)
$dbPath = Join-Path $RUN_DIR "workbench.db"
sqlite3 $dbPath
```

### 3.2 Validate Schema Tables Exist

```sql
-- List all tables
.tables

-- Required tables (per-run workbench.db):
--   signals
--   signal_explanations
--   coverage_rollup
--   locald_checkpoint

-- Optional tables (may or may not exist):
--   facts
--   runs
```

### 3.3 Validate coverage_rollup Has Data

```sql
-- Check coverage_rollup row count
SELECT COUNT(*) AS coverage_rows FROM coverage_rollup;
-- Expected: >= 1

-- View coverage breakdown by fact type
SELECT 
    fact_type,
    SUM(fact_count) AS total_facts
FROM coverage_rollup
GROUP BY fact_type
ORDER BY total_facts DESC;

-- View coverage by sensor mode
SELECT 
    sensor_mode,
    COUNT(*) AS row_count,
    SUM(fact_count) AS total_facts
FROM coverage_rollup
GROUP BY sensor_mode;
```

**Expected fact types (depends on channels):**

| Fact Type | Source | Expected if... |
|-----------|--------|----------------|
| ProcessCreate | Sysmon 1 or Security 4688 | Sysmon OR audit policy |
| NetworkConnect | Sysmon 3 | Sysmon installed |
| FileCreate | Sysmon 11 | Sysmon installed |
| LogonEvent | Security 4624 | Logon auditing enabled |
| ServiceInstall | System 7045 | A service was installed |

### 3.4 Validate signals Table

```sql
-- Count signals
SELECT COUNT(*) AS signal_count FROM signals;
-- Expected: >= 0 (may be 0 if no detections fired)

-- View signals if any
SELECT 
    signal_id,
    signal_type,
    severity,
    ts,
    host
FROM signals
ORDER BY ts DESC
LIMIT 10;

-- Signals by type
SELECT 
    signal_type,
    COUNT(*) AS n
FROM signals
GROUP BY signal_type
ORDER BY n DESC;
```

### 3.5 Validate signal_explanations Table

```sql
-- Check explanations exist for signals
SELECT COUNT(*) AS explanation_count FROM signal_explanations;
-- Expected: same as signals count (1:1 relationship)
```

### 3.6 Validate locald_checkpoint Table

```sql
-- Check checkpoint exists (proves locald ran)
SELECT * FROM locald_checkpoint;
-- Expected: at least one row with last processed position
```

---

## 4. UI Verification Steps

Open http://127.0.0.1:3000/ui/ in browser with DevTools Network tab open.

### 4.1 Runs List

| Step | Action | Expected Result | API Call |
|------|--------|-----------------|----------|
| 1 | Load UI | Runs list visible in sidebar | `GET /api/runs` |
| 2 | Find run | Run with your `run_id` appears | - |
| 3 | Check status | Status shows "Completed" or "Stopped" | - |

### 4.2 Coverage View

| Step | Action | Expected Result | API Call |
|------|--------|-----------------|----------|
| 1 | Click run in list | Coverage panel loads | `GET /api/runs/<run_id>/coverage` |
| 2 | Check facts_total | Number > 0 | - |
| 3 | Check sensors | At least one sensor shows "Active" | - |
| 4 | Check pipeline_diagnostics | playbooks_loaded > 0 | - |

### 4.3 Signals View

| Step | Action | Expected Result | API Call |
|------|--------|-----------------|----------|
| 1 | Click "Signals" tab | Signals list loads | `GET /api/signals?run_id=<run_id>` |
| 2 | Check response | Array returned (may be empty) | - |
| 3 | If signals exist | Click one to expand | - |

### 4.4 Explain View

| Step | Action | Expected Result | API Call |
|------|--------|-----------------|----------|
| 1 | Click signal (if any) | Detail panel opens | `GET /api/signals/<id>/explain?run_id=<run_id>` |
| 2 | Check response shape | Has: signal_id, playbook_id, evidence[], scoring | - |
| 3 | Evidence array | At least one evidence pointer | - |

### 4.5 Export Bundle

| Step | Action | Expected Result | API Call |
|------|--------|-----------------|----------|
| 1 | Click "Export" | Download initiates | `POST /api/export/bundle` |
| 2 | Check file | ZIP with signals + evidence | - |

---

## 5. Stage 3 Truth Check: DB vs API Consistency

This validates that the per-run database is correctly wired to the API.

```powershell
# 1. Get signal count from database
$dbPath = Join-Path $RUN_DIR "workbench.db"
$dbCount = sqlite3 $dbPath "SELECT COUNT(*) FROM signals;"
Write-Host "DB signal count: $dbCount"

# 2. Get signal count from API
$apiResponse = Invoke-RestMethod "http://127.0.0.1:3000/api/signals?run_id=$RUN_ID"
$apiCount = $apiResponse.Count
Write-Host "API signal count: $apiCount"

# 3. Compare
if ($dbCount -eq $apiCount) {
    Write-Host "✅ PASS: DB and API counts match ($dbCount)"
} else {
    Write-Host "❌ FAIL: DB has $dbCount signals but API returned $apiCount"
    Write-Host "   → Stage 3 wiring is broken. Check run_id propagation in API handlers."
}
```

**Interpretation:**
- If DB count > 0 but API returns empty array: run_id not being passed or query filtering wrong
- If DB count = 0 and API returns empty: no signals fired (acceptable)
- Counts should always match when run_id is correct

---

## 6. Troubleshooting: coverage_rollup = 0

If `SELECT COUNT(*) FROM coverage_rollup` returns 0:

### 6.1 Diagnostic Tree

```
coverage_rollup = 0
├── No events captured at all?
│   ├── Check: Did capture actually run? (logs/capture.log exists and has content)
│   ├── Check: Is capture_windows_rotating process visible in Task Manager?
│   └── Check: logs/capture.log for errors
│
├── Events captured but not processed?
│   ├── Check: segments/*.jsonl has content (lines > 0)
│   ├── Check: logs/locald.log exists and has processing entries
│   └── Check: logs/locald.log for parsing errors
│
└── Channel-specific issues (see 6.2)
```

### 6.2 Channel-Specific Causes

| Missing Channel | Likely Cause | Fix |
|-----------------|--------------|-----|
| **Security** (all) | Not running as Admin | Run server as Administrator |
| **Security** 4688 | Process audit disabled | `auditpol /set /subcategory:"Process Creation" /success:enable` |
| **Security** 4624 | Logon audit disabled | `auditpol /set /subcategory:"Logon" /success:enable` |
| **Security** 5156 | Firewall audit disabled | `auditpol /set /subcategory:"Filtering Platform Connection" /success:enable` |
| **Sysmon** (all) | Sysmon not installed | Install from Sysinternals (optional) |
| **Sysmon** (all) | Sysmon service stopped | `sc start Sysmon64` |
| **Sysmon** specific | Sysmon config excludes events | Check Sysmon config XML |
| **System** 7045 | No services installed during capture | Normal - this is rare |

### 6.3 Permission Checks

```powershell
# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Running as Admin: $isAdmin"
# Expected: True

# Check Sysmon status (optional)
$sysmon = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($sysmon) {
    Write-Host "Sysmon status: $($sysmon.Status)"
} else {
    Write-Host "Sysmon not installed (optional)"
}

# Check audit policies
auditpol /get /subcategory:"Process Creation"
auditpol /get /subcategory:"Logon"
# Expected: Success auditing enabled
```

### 6.4 Quick Diagnostic Endpoint

```powershell
# Use selfcheck endpoint for automated diagnosis
$selfcheck = Invoke-RestMethod http://127.0.0.1:3000/api/selfcheck
$selfcheck | ConvertTo-Json -Depth 5
```

Check response for:
- `verdict`: Should be "healthy" or "degraded" (not "blocked")
- `streams[].status`: Each stream's configured vs observed state
- `issues[]`: Any blocking issues listed

**Configured vs Observed:**
- A stream may be "configured" (we try to read it) but show 0 events if:
  - Audit policy not enabled
  - No relevant activity during capture
  - Permission denied (not Admin)

---

## 7. Pass/Fail Criteria

### PASS Requirements (all must be true)

- [ ] `<run_dir>/workbench.db` exists and size > 4KB
- [ ] `<run_dir>/segments/` contains at least one `.jsonl` file with content
- [ ] `<run_dir>/logs/capture.log` exists
- [ ] `<run_dir>/logs/locald.log` exists
- [ ] `SELECT COUNT(*) FROM coverage_rollup` > 0
- [ ] At least one fact type observed (Security OR Sysmon OR System)
- [ ] UI loads without console errors
- [ ] `GET /api/runs/<run_id>/coverage` returns `available: true`
- [ ] `GET /api/signals?run_id=<run_id>` returns valid JSON array
- [ ] Stage 3 truth check passes (DB count = API count)

### FAIL Conditions

- [ ] workbench.db missing or empty (0 bytes)
- [ ] No segment files created
- [ ] logs/capture.log or logs/locald.log missing
- [ ] coverage_rollup table empty AND run duration > 30s
- [ ] UI shows "blocked" verdict in selfcheck
- [ ] API returns 500 errors
- [ ] DB signal count ≠ API signal count (Stage 3 wiring broken)

### ACCEPTABLE (not failures)

- [ ] signals table empty (no detections fired - depends on activity)
- [ ] Sysmon not installed (Security/System coverage is sufficient)
- [ ] Some fact types show 0 (depends on audit policy and activity)
- [ ] Warnings in selfcheck (degraded but not blocked)

---

## 8. Sign-Off

| Check | Result | Verified By | Date |
|-------|--------|-------------|------|
| Filesystem artifacts present | ☐ Pass / ☐ Fail | | |
| Log files exist | ☐ Pass / ☐ Fail | | |
| workbench.db has coverage_rollup | ☐ Pass / ☐ Fail | | |
| At least one fact type observed | ☐ Pass / ☐ Fail | | |
| UI workflow completes | ☐ Pass / ☐ Fail | | |
| Stage 3 truth check (DB = API) | ☐ Pass / ☐ Fail | | |
| No blocking issues in selfcheck | ☐ Pass / ☐ Fail | | |

**Overall:** ☐ **SHIP READY** / ☐ **BLOCKED**

---

*Last updated: 2026-01-11 (Ship Pass)*

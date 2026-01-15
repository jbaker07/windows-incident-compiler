# LocInt Gap Report

**Generated:** 2026-01-11  
**Last Updated:** 2026-01-11 (Timestamp hardening + Noise diagnostics)
**Purpose:** Detailed analysis of what locint.exe has vs what it needs to be feature-complete

---

## Executive Summary

**locint.exe** is a standalone GUI wrapper designed for end-user distribution. It should work without needing Cargo, VS Code, or development dependencies.

**Current Status:** ✅ **READY** - All core endpoints implemented, UI workflow supported.

---

## Recent Changes (2026-01-11)

### Timestamp Hardening
- `/api/runs` now reads timestamps from `run_meta.json` (authoritative source)
- `run_id` parsing is ONLY used as backwards-compatibility fallback
- `/api/run/stop` writes `stopped_at` to `run_meta.json`
- Unit tests verify: `run_meta_json_takes_priority_over_run_id_parsing`

### Noise Diagnostics
- `/api/run/metrics` now includes:
  - `top_playbook`: Most frequent signal type (from signals table)
  - `top_entity`: Most frequent entity (process/file/host)
  - `collapsed_count`: Dedupe collapse estimate
- UI shows "—" instead of "N/A" when no signals yet

---

## 1. Endpoint Parity Analysis

### ✅ locint HAS (19 endpoints)

| Endpoint | Method | Status |
|----------|--------|--------|
| `/` | GET | ✅ Redirect to /ui/ |
| `/health` | GET | ✅ Health check |
| `/api/health` | GET | ✅ Health check |
| `/api/run/start` | POST | ✅ Start capture |
| `/api/run/stop` | POST | ✅ Stop capture |
| `/api/run/status` | GET | ✅ Process status |
| `/api/run/metrics` | GET | ✅ Live metrics |
| `/api/runs` | GET | ✅ List runs |
| `/api/runs/:run_id/coverage` | GET | ✅ Coverage data |
| `/api/signals` | GET | ✅ List signals |
| `/api/signals/stats` | GET | ✅ **NEW** Signal statistics |
| `/api/signals/:id` | GET | ✅ **NEW** Get single signal |
| `/api/signals/:id/explain` | GET | ✅ Signal explanation |
| `/api/app/state` | GET | ✅ **NEW** App state |
| `/api/selfcheck` | GET | ✅ Resource validation |
| `/api/features` | GET | ✅ Feature flags |
| `/api/capture/profiles` | GET | ✅ Capture profiles |
| `/api/export/bundle` | POST | ✅ **NEW** Export bundle |
| `/ui/*` | GET | ✅ Static UI files |

### ❌ locint MISSING (edr-server only, NOT needed)

#### Advanced features (not needed for basic operation)

| Endpoint | Reason to Omit |
|----------|----------------|
| `/api/documents/*` | Document editor (advanced) |
| `/api/session/*` | Legacy session API |
| `/api/import/bundle` | Import feature |
| `/api/diff` | Pro feature |
| `/api/missions/*` | Mission mode (advanced) |
| `/api/report/pdf` | Pro feature |
| `/api/support/bundle` | Dev support |
| `/api/verify/*` | Dev verification |
| `/api/techniques/*` | MITRE lookup |
| `/api/narratives/*` | Narrative actions |
| `/api/integrations/*` | Integration metadata |
| `/api/capabilities` | Integration capabilities |
| `/api/eval/metrics` | Eval metrics |

---

## 2. Resource Layout Requirements

locint expects this exact layout relative to the .exe:

```
LocInt/
├── locint.exe                          ← Main executable
├── capture_windows_rotating.exe        ← Capture binary (REQUIRED)
├── edr-locald.exe                      ← Detection daemon (REQUIRED)
├── ui/                                 ← UI static files (REQUIRED)
│   ├── index.html
│   ├── assets/
│   └── ...
└── playbooks/
    └── windows/                        ← Playbooks (REQUIRED)
        ├── signal_*.yaml
        └── ...
```

### Validation Checklist

```powershell
# Run from LocInt directory
$exe = ".\locint.exe"
$exeDir = Split-Path $exe -Parent

# Check all required files
$required = @(
    "$exeDir\capture_windows_rotating.exe",
    "$exeDir\edr-locald.exe",
    "$exeDir\ui\index.html",
    "$exeDir\playbooks\windows"
)

$missing = $required | Where-Object { -not (Test-Path $_) }
if ($missing) {
    Write-Host "❌ MISSING:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "✅ All resources present" -ForegroundColor Green
}
```

---

## 3. Data Directory

locint writes data to:
```
%LOCALAPPDATA%\attack-workbench\
├── workbench.db            ← Main database (legacy, server-level)
└── runs\
    └── run_YYYYMMDD_HHMMSS\
        ├── workbench.db    ← Per-run database (signals, coverage)
        ├── segments\       ← Raw event JSONL files
        │   └── *.jsonl
        └── logs\
            ├── capture.log
            └── locald.log
```

---

## 4. What's Needed to Ship

### ✅ All Critical Items Fixed

| Item | Status |
|------|--------|
| `/api/signals/:id` | ✅ Added |
| `/api/signals/stats` | ✅ Added |
| `/api/export/bundle` | ✅ Added |
| `/api/app/state` | ✅ Added |
| `/api/run/metrics` | ✅ Added |

### Ready for Testing

Run the full UI workflow to verify all endpoints work together.

---

## 5. Build & Package Instructions

### Build locint

```powershell
cd "c:\Users\Jermaine B\src\windows-incident-compiler"
cargo build --release --bin locint
```

### Create Distribution Package

```powershell
$dist = ".\dist\LocInt"
New-Item -ItemType Directory -Force -Path $dist

# Copy binaries
Copy-Item ".\target\release\locint.exe" $dist
Copy-Item ".\target\release\capture_windows_rotating.exe" $dist -ErrorAction SilentlyContinue
Copy-Item ".\target\release\edr-locald.exe" $dist -ErrorAction SilentlyContinue

# Copy UI
Copy-Item ".\ui\dist\*" "$dist\ui\" -Recurse -Force

# Copy playbooks
Copy-Item ".\playbooks\windows" "$dist\playbooks\windows" -Recurse -Force
```

### Build All Binaries

```powershell
# Build all required binaries
cargo build --release -p edr-server --bin locint
cargo build --release -p agent-windows --bin capture_windows_rotating
cargo build --release -p locald --bin edr-locald

# Verify
Get-ChildItem ".\target\release\*.exe" | Select-Object Name
```

---

## 6. Runtime Requirements

| Requirement | Notes |
|-------------|-------|
| **Windows 10/11** | Or Server 2019+ |
| **Administrator** | Required for event log access |
| **Port 3000** | Must be available (or set EDR_SERVER_PORT) |
| **.NET** | NOT required |
| **Rust** | NOT required (statically linked) |

---

## 7. Error Handling

locint shows Windows MessageBox dialogs for:

| Error | MessageBox Title | When |
|-------|------------------|------|
| Missing binaries | "Missing Resources" | Startup |
| Missing UI | "Missing Resources" | Startup |
| Port in use | "Port Conflict" | Startup |
| Child spawn fail | "Process Error" | Run start |

---

## 8. Testing locint

### Quick Smoke Test

```powershell
# From LocInt directory, as Administrator
.\locint.exe

# Should:
# 1. Open browser to http://127.0.0.1:3000/ui/
# 2. UI loads without errors
# 3. Click "Start" - capture begins
# 4. Wait 30 seconds
# 5. Click "Stop" - run completes
# 6. Run appears in list with coverage data
```

### API Test

```powershell
# Health check
Invoke-RestMethod http://127.0.0.1:3000/api/health

# Selfcheck (shows resource status)
Invoke-RestMethod http://127.0.0.1:3000/api/selfcheck | ConvertTo-Json

# Metrics (during run)
Invoke-RestMethod http://127.0.0.1:3000/api/run/metrics | ConvertTo-Json
```

---

## 9. Recommended Next Steps

1. **Add missing `/api/signals/:id` endpoint** (30 min)
2. **Add `/api/export/bundle` endpoint** (1 hr)
3. **Test full UI workflow end-to-end** (30 min)
4. **Create installer/zip package script** (1 hr)
5. **Add code signing for Windows** (optional)

---

## 10. Current locint.rs Line Count

| Section | Lines |
|---------|-------|
| Imports & setup | ~80 |
| main() | ~50 |
| run_server() | ~50 |
| build_locint_router() | ~25 |
| Handlers | ~400 |
| Platform helpers | ~100 |
| Tests | ~30 |
| **Total** | **~735** |

This is acceptable for a thin wrapper. Most logic is in handlers that could be shared with edr-server in the future.

---

*Report generated by gap analysis of locint.rs vs main.rs router*

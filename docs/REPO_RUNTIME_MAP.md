# Repository Runtime Map

> **Generated**: 2026-01-28 (UI_SYNC_HARDENED-1)
> **Purpose**: Repo-accurate map of runtime components, optional modules, and stale paths

---

## A) Runtime Components (REQUIRED to run end-to-end)

### Binaries

| Binary | Source Path | Output Path | Purpose | Status |
|--------|-------------|-------------|---------|--------|
| `locint.exe` | `crates/server/src/bin/locint.rs` | `target/release/locint.exe` | HTTP server, serves /ui + /api | **REQUIRED** |
| `capture_windows_rotating.exe` | `crates/agent-windows/src/bin/capture_windows_rotating.rs` | `target/release/capture_windows_rotating.exe` | ETW capture → segments/*.jsonl | **REQUIRED** |
| `edr-locald.exe` | `crates/locald/src/main.rs` | `target/release/edr-locald.exe` | Fact extraction → workbench.db | **REQUIRED** |

### Runtime Data Directories

| Path | Created By | Purpose | Status |
|------|------------|---------|--------|
| `runs/<run_id>/` | locint | Per-run data directory | **REQUIRED** |
| `runs/<run_id>/segments/` | capture_windows_rotating | Raw telemetry JSONL files | **REQUIRED** |
| `runs/<run_id>/workbench.db` | edr-locald | SQLite with signals, facts, coverage | **REQUIRED** |
| `runs/<run_id>/run_meta.json` | locint | Run metadata snapshot | **REQUIRED** |
| `playbooks/windows/` | Static | Signal detection playbooks | **REQUIRED** |
| `ui/` | Static | Web UI assets (app.js, index.html, loading.html) | **REQUIRED** |

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `LOCINT_DEV_UI` | unset | If "1", serve from repo `ui/` instead of `target/release/ui/` |
| `LOCINT_UI_DIR` | exe_dir/ui | Override UI assets directory |
| `EDR_UI_DIR` | (fallback) | Legacy: same as LOCINT_UI_DIR |
| `EDR_PLAYBOOKS_DIR` | playbooks/windows | Override playbooks directory |
| `LOCINT_PORT` | 3000 | HTTP server port |
| `LOCINT_DATA_DIR` | ./locint_data | State directory (runs, settings) |

---

## B) Backend Services / Modules

### Core Services (REQUIRED for core loop)

| Module | Path | Purpose | Key Endpoints |
|--------|------|---------|---------------|
| `run_control` | `crates/server/src/services/run_control.rs` | Run lifecycle (start/stop/status/metrics) | `/api/run/start`, `/api/run/stop`, `/api/run/status`, `/api/run/metrics` |
| `supervisor` | `crates/server/src/supervisor.rs` | Process orchestration (capture + locald) | Internal: spawns binaries |
| `db` | `crates/server/src/db.rs` | SQLite connection pool + schema | Internal: all data access |
| `capability` | `crates/server/src/services/capability.rs` | Detection plan, readiness checks | `/api/capability/status`, `/api/capability/detection_plan` |
| `signals` | `crates/server/src/services/signals.rs` | Signal queries, explainability | `/api/signals`, `/api/signals/:id/explain` |
| `evidence` | `crates/server/src/services/evidence.rs` | Evidence dereference, segment access | `/api/evidence/deref` |
| `run_coverage` | `crates/server/src/run_coverage.rs` | Coverage rollup computation | `/api/runs/:run_id/coverage` |
| `playbook_scope` | `crates/server/src/playbook_scope.rs` | Playbook matching and scope computation | Used by run_brief, playbooks/eval |

### Investigation Services (REQUIRED for Investigate tab)

| Module | Path | Purpose | Key Endpoints |
|--------|------|---------|---------------|
| `chains` | `crates/server/src/services/chains.rs` | Micro chains registry + compilation | `/api/chains`, `/api/chains/compile` |
| `run_brief` | `crates/server/src/services/run_brief.rs` | Run brief orchestrator | `/api/runs/:run_id/brief` |
| `run_brief_repo` | `crates/server/src/services/run_brief_repo.rs` | Database queries for run brief | Internal |
| `evidence_ptrs` | `crates/server/src/services/evidence_ptrs.rs` | Evidence pointer parsing | Internal |
| `episodes` | `crates/server/src/services/episodes.rs` | Episode clustering | Used by run_brief |

### Additional Services

| Module | Path | Purpose | Key Endpoints | Status |
|--------|------|---------|---------------|--------|
| `diff` | `crates/server/src/services/diff.rs` | Diff v2 (phase/baseline/marker) | `/api/runs/:run_id/diff` | Pro tier |
| `baseline` | `crates/server/src/services/baseline.rs` | Baseline management | `/api/baselines` | Pro tier |
| `export_import` | `crates/server/src/services/export_import.rs` | Bundle export/import | `/api/export/bundle`, `/api/import/bundle` | Community |
| `meta` | `crates/server/src/services/meta.rs` | Route registry, features, dataflow | `/api/meta/routes`, `/api/meta/ui_dir` | Community |
| `packs` | `crates/server/src/services/packs.rs` | Content pack discovery | `/api/packs` | Community |
| `team/*` | `crates/server/src/team/` | Team Case Store | `/api/team/*` | Team tier |

---

## C) Per-Run Data Model

### Run Directory Structure

```
runs/<run_id>/
├── segments/
│   ├── security_<ts>.jsonl      # Security events
│   ├── process_<ts>.jsonl       # Process events  
│   └── ...
├── workbench.db                  # SQLite: facts, signals, coverage
└── run_meta.json                 # Snapshot of run config + stats
```

### workbench.db Tables (Created by edr-locald)

| Table | Purpose | Status |
|-------|---------|--------|
| `signals` | Detected signals with severity, playbook_id | **REQUIRED** |
| `signal_facts` | Facts associated with each signal | **REQUIRED** |
| `coverage_rollup` | Playbook coverage counts | **REQUIRED** |
| `episodes` | Episode clustering for signals | **REQUIRED** |
| `telemetry_events` | Raw telemetry (optional, can be large) | Optional |
| `canonical_events` | Normalized events for queries | Optional |
| `segment_metadata` | Segment file tracking | **REQUIRED** |
| `locald_checkpoint` | Processing checkpoint | Internal |
| `incidents` | Legacy incident grouping | Optional |
| `metrics_rollup` | Runtime metrics | Optional |

### segments/*.jsonl Format

Each line is a JSON object with:
- `ts`: Unix timestamp (ms)
- `provider`: ETW provider name
- `event_id`: Windows event ID
- `data`: Event-specific fields

### run_meta.json Schema

```json
{
  "run_id": "run_20260128_...",
  "started_at": "2026-01-28T10:00:00Z",
  "stopped_at": "2026-01-28T10:05:00Z",
  "duration_secs": 300,
  "preset": "default",
  "playbooks": ["signal_credential_access", ...],
  "stats": {
    "segments": 42,
    "events": 15000,
    "facts": 3500,
    "signals": 12
  }
}
```

---

## D) Frontend Surfaces

### UI Tab → Endpoint Mapping

| Tab | Primary Endpoints | State Keys |
|-----|-------------------|------------|
| **Mission** | `/api/capability/status`, `/api/capability/detection_plan`, `/api/run/start`, `/api/run/stop` | `isRunning`, `counters`, `readiness` |
| **Runs / Overview** | `/api/runs`, `/api/runs/:run_id/coverage`, `/api/runs/:run_id/brief` | `runs`, `selectedRunId`, `coverage` |
| **Runs / Findings** | `/api/signals`, `/api/signals/:id/explain` | `signals`, `selectedSignal` |
| **Investigate** | `/api/runs/:run_id/brief`, `/api/runs/:run_id/step_status`, `/api/runs/:run_id/playbooks/eval` | `briefData`, `stepStatus` |
| **Evidence** | `/api/runs/:run_id/evidence_summary`, `/api/runs/:run_id/facts`, `/api/runs/:run_id/facts/resolve` | `evidenceSummary`, `facts` |
| **Team** | `/api/team/store/status`, `/api/team/cases` | `teamStore`, `teamCases` |

### Build Stamp System

| Location | Variable | Purpose |
|----------|----------|---------|
| `ui/app.js:76` | `const BUILD_STAMP = '...'` | Single source of truth |
| `ui/app.js:77` | `BUILD_VERSION = BUILD_STAMP` | Alias for compatibility |
| `ui/index.html:1110` | `<div id="uiBuildBadge">UI BUILD: ...</div>` | Visible badge (top-right) |
| `ui/index.html:4` | `<!-- BUILD_STAMP: ... -->` | HTML comment marker |
| `<script src>` | `app.js?v=...` | Cache-busting query param |

### UI Sync Check

On load, `checkUiSync()` in app.js:
1. Fetches `/api/meta/ui_dir`
2. Compares `ui_app_js_sha256` vs `source_ui_app_js_sha256`
3. If mismatch and not dev mode, shows red `#uiMismatchBanner`

---

## E) Stale/Duplicate/Packaging Paths

### DO NOT DELETE - Just Label

| Path | Purpose | Used In | Status |
|------|---------|---------|--------|
| `LocInt/` | **Release distribution folder** - pre-built binaries + playbooks + UI | Release packaging, user downloads | **ACTIVE (packaging)** |
| `LocInt/ui/` | Bundled UI assets for release | Release packaging | **ACTIVE (packaging)** |
| `LocInt/playbooks/` | Bundled playbooks for release | Release packaging | **ACTIVE (packaging)** |
| `LocInt/*.exe` | Pre-built release binaries | Release packaging | **ACTIVE (packaging)** |
| `target/release/ui/` | Build-time UI copy (optional) | Legacy: some builds copy here | **Stale** - use LOCINT_DEV_UI=1 instead |
| `ui/` | **Source UI assets** - edit here | Development | **ACTIVE (source)** |
| `src-tauri/` | Tauri desktop wrapper (optional) | Desktop app packaging | **Optional** - not required for web UI |
| `src-tauri/src/` | Tauri Rust source | Desktop app | Optional |
| `playbooks/windows/` | **Source playbooks** - edit here | Development, runtime | **ACTIVE (source + runtime)** |

### File Tracking Notes

- `LocInt/*.exe` are tracked in git (intentional for release distribution)
- `target/` is NOT tracked (correctly excluded by .gitignore)
- `ui/` changes should be synced to `LocInt/ui/` before release
- `playbooks/windows/` changes should be synced to `LocInt/playbooks/windows/` before release

---

## F) How to Run

### Development Mode (RECOMMENDED)

```powershell
# 1. Build all binaries
cargo build --release

# 2. Set dev UI mode (serves from repo ui/)
$env:LOCINT_DEV_UI = "1"

# 3. Run locint
.\target\release\locint.exe

# UI at http://localhost:3000/ui/
# Changes to ui/app.js reflect immediately on refresh
```

### Release Mode (for distribution)

```powershell
# 1. Build release binaries
cargo build --release

# 2. Sync UI to release folder (manual step)
Copy-Item ui\* target\release\ui\ -Recurse -Force

# 3. Sync playbooks
Copy-Item playbooks\windows\* target\release\playbooks\windows\ -Recurse -Force

# 4. Run from target/release
cd target\release
.\locint.exe
```

### LocInt Distribution Package

The `LocInt/` folder is the pre-packaged distribution:

```powershell
# Run from LocInt folder directly
cd LocInt
.\locint.exe

# All dependencies are co-located:
# - locint.exe (server)
# - capture_windows_rotating.exe (capture)
# - edr-locald.exe (fact extraction)
# - ui/ (web assets)
# - playbooks/windows/ (detection rules)
```

### Verify UI Serving

```powershell
# Check what UI is being served
Invoke-RestMethod http://localhost:3000/api/meta/ui_dir | ConvertTo-Json

# Expected output includes:
# - dev_mode: true/false
# - ui_dir: path being served
# - ui_app_js_sha256: hash of served app.js
# - source_ui_app_js_sha256: hash of repo ui/app.js (if dev mode)
```

---

## G) Verification Checklist

Before pushing:

- [ ] `cargo build --release -p edr-server --bin locint` succeeds
- [ ] `cargo test -p edr-server --test router_parity_tests --test explain_api_tests` passes
- [ ] `git status` shows no untracked files that should be ignored
- [ ] UI BUILD_STAMP matches between `ui/app.js` and `ui/index.html`
- [ ] `/api/meta/ui_dir` returns expected paths

---

## H) Unknown / To Investigate

| Item | Status | How Checked |
|------|--------|-------------|
| `src-tauri/` integration status | Unknown - appears optional | Listed in workspace but not required for web UI |
| `LocInt/query` file | Unknown purpose | Untracked file in LocInt/, possibly debug artifact |
| `LocInt/*.txt` files | Debug artifacts | `build_output.txt`, `stderr.txt`, `stdout.txt` - should not be committed |

---

*Last updated: 2026-01-28 by UI_SYNC_HARDENED-1*

# UI Sync Runbook (UI_SYNC_HARDENED-1)

## Problem

When editing `ui/index.html` or `ui/app.js`, the served UI may not reflect changes because:
- The server serves from `target/release/ui/` (build output)
- Source files in `ui/` are not automatically copied

## Solution A: Dev Mode Serving (Recommended for Development)

Set `LOCINT_DEV_UI=1` to serve directly from the repo's `ui/` directory:

```powershell
# Start locint with dev UI mode
$env:LOCINT_DEV_UI = "1"
.\target\release\locint.exe

# Or inline
$env:LOCINT_DEV_UI = "1"; .\target\release\locint.exe
```

**What happens:**
- Server logs: `[UI] DEV MODE: Serving from source ui/`
- Changes to `ui/app.js` or `ui/index.html` are immediately reflected on browser refresh
- No sync scripts needed

## Solution B: Manual Sync (For Testing Release Builds)

If you need to test the actual release UI behavior:

```powershell
.\scripts\sync_ui.ps1
```

This copies `ui/*` to `target/release/ui/`.

## Verifying UI Version Changed

### Method 1: Check the UI Badge
The top-right badge shows `UI BUILD: YYYY-MM-DD-BUILD_NAME-N`

### Method 2: Browser Console
Open DevTools (F12) → Console. Look for:
```
[BOOT] app.js loaded BUILD_STAMP=2026-01-28-UI_SYNC_HARDENED-1
[UI BUILD] 2026-01-28-UI_SYNC_HARDENED-1
```

### Method 3: API Endpoint
```powershell
Invoke-RestMethod http://localhost:3000/api/meta/ui_dir | ConvertTo-Json -Depth 5
```

Check:
- `data.ui_dir` - Where files are served from
- `data.dev_mode` - Whether dev mode is active
- `data.ui_app_js_sha256` - SHA of served app.js
- `data.source_ui_app_js_sha256` - SHA of source app.js

If these SHAs differ and `dev_mode` is false, the UI is stale.

## Mismatch Warning Banner

If source and served UI differ (and not in dev mode), you'll see a red banner:

> ⚠️ **UI STALE:** Served files don't match source. Run `scripts/sync_ui.ps1` or set `LOCINT_DEV_UI=1` to serve from source.

Click ✕ to dismiss, or fix with one of the solutions above.

## Workflow Summary

| Scenario | Command |
|----------|---------|
| Development | `$env:LOCINT_DEV_UI = "1"; .\target\release\locint.exe` |
| Test release build | `.\scripts\sync_ui.ps1; .\target\release\locint.exe` |
| Override UI path | `$env:LOCINT_UI_DIR = "C:\custom\ui"; .\target\release\locint.exe` |

## Files Changed (UI_SYNC_HARDENED-1)

- `crates/server/src/bin/locint.rs`:
  - `LOCINT_DEV_UI=1` env var support
  - `find_repo_root()` helper function
  - `/api/meta/ui_dir` returns `dev_mode`, `source_ui_dir`, `source_ui_app_js_sha256`

- `ui/app.js`:
  - Unified `BUILD_STAMP` (single source of truth)
  - `BUILD_VERSION` now references `BUILD_STAMP`
  - `checkUiSync()` fetches `/api/meta/ui_dir` and shows warning if mismatched

- `ui/index.html`:
  - `#uiMismatchBanner` red warning element
  - Updated `#uiBuildBadge` to new version

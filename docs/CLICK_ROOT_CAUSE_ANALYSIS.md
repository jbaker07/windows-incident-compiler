# Click Non-Registration Root Cause Analysis

**Date:** 2026-01-22  
**Status:** ✅ ROOT CAUSE IDENTIFIED AND FIXED

---

## Executive Summary

**The "clicks not registering" issue was NOT a click interception, overlay, z-index, or pointer-events problem.**

**Root Cause:** The server was serving **stale UI files from a different directory** than the one being edited.

| Location | Contents |
|----------|----------|
| `ui/` (workspace root) | Updated files with all fixes (18,426 lines) |
| `target/release/ui/` (server serves this) | **STALE** old version (14,474 lines) |

---

## Phase 0: Environment Verification

### 0.1 Which UI folder is served?

**Server Configuration Evidence:**

```rust
// crates/server/src/server_core.rs:93
ui_dir: exe_dir.join("ui")
```

```rust  
// crates/server/src/bin/locint.rs:447
.nest_service("/ui", ServeDir::new(&config.ui_dir))
```

The `locint.exe` binary serves from `{exe_directory}/ui/`, which for release builds is:
```
target/release/ui/
```

**NOT** from the workspace root `ui/` folder.

### 0.2 Evidence of Version Mismatch

| Property | Workspace `ui/app.js` | Served `app.js` |
|----------|----------------------|-----------------|
| BUILD_STAMP | `2026-01-22-FORENSIC-V2` | `2026-01-10-SHIP` |
| Line count | 18,426 | 14,474 |
| Click handlers | ✅ Present | ⚠️ Old version |

**Proof Command:**
```powershell
# This showed the WRONG build stamp
$resp = Invoke-WebRequest -Uri "http://localhost:3000/ui/app.js"
$resp.Content -match "BUILD_STAMP = '([^']+)'"
# Output: 2026-01-10-SHIP (WRONG!)
```

### 0.3 Service Worker Check

**Result:** No service worker registered. The HTML does not register any SW.

---

## Phase 1-3: Why Previous "Fixes" Didn't Work

All previous edits to:
- `ui/app.js` 
- `ui/index.html`

Were made to the **workspace root** files, but the server was serving from `target/release/ui/`.

The click handlers, debug instrumentation, and fixes were never actually deployed.

---

## Phase 4: The Fix

### 4.1 Immediate Fix

Copy workspace UI files to the served location:

```powershell
Copy-Item -Path "ui\*" -Destination "target\release\ui\" -Force -Recurse
```

### 4.2 Verification

```powershell
$resp = Invoke-WebRequest -Uri "http://localhost:3000/ui/app.js"
$resp.Content -match "BUILD_STAMP = '([^']+)'"
# Output: 2026-01-22-FORENSIC-V3 (CORRECT!)
```

### 4.3 Permanent Solution

Created `scripts/sync_ui.ps1` to sync UI files:

```powershell
# After editing UI files, run:
.\scripts\sync_ui.ps1

# Or for automatic sync during development:
.\scripts\sync_ui.ps1 -Watch
```

---

## Phase 5: Post-Fix Verification

### Forensic Tools Added (gated behind `?debug=1`)

| Function | Purpose |
|----------|---------|
| `window.probeHitTest()` | Sample 20 points across viewport to detect overlays |
| `window.checkOverlays()` | List all fixed/absolute positioned elements |
| `window.diagnoseClicks()` | Full diagnostic: DOM check, hit test, overlay scan |

### Console Logs on Click (with `?debug=1`)

```
[FORENSIC POINTERDOWN] {
  type: "pointerdown",
  target: "BUTTON#btnStartRun.btn-primary",
  topElementAtPoint: "BUTTON#btnStartRun.btn-primary",
  INTERCEPTED: false,
  ...
}
[DEBUG] btnStartRun CLICKED!
```

**Proof:** `target` === `topElementAtPoint` means no interception.

---

## Lessons Learned

1. **Always verify which files are being served** before debugging click issues
2. **Add a BUILD_STAMP** to JS files for instant verification
3. **The release binary uses exe-relative paths**, not workspace-relative paths
4. **Copy UI files after each edit** or use a watch script

---

## Files Changed

| File | Change |
|------|--------|
| `ui/app.js` | Added forensic instrumentation (gated behind DEBUG_MODE) |
| `ui/index.html` | Updated cache buster `?v=20260122-forensic` |
| `scripts/sync_ui.ps1` | NEW: Script to sync UI files to target/release/ui |
| `target/release/ui/*` | Copied from workspace ui/ |

---

## Diagnostic Commands

### Check which version is served
```powershell
$resp = Invoke-WebRequest -Uri "http://localhost:3000/ui/app.js"
$resp.Content -match "BUILD_STAMP = '([^']+)'"
$matches[1]
```

### Sync UI files
```powershell
Copy-Item -Path "ui\*" -Destination "target\release\ui\" -Force -Recurse
```

### Browser Console Diagnostics
```javascript
// With ?debug=1 in URL:
window.diagnoseClicks()  // Full diagnostic
window.probeHitTest()    // Check for overlays
window.checkOverlays()   // List fixed/absolute elements
```

---

## Conclusion

The root cause was **file path confusion**, not a CSS/DOM/event issue. The workspace has two `ui/` folders:
- `ui/` at workspace root (what we edit)
- `target/release/ui/` (what server serves)

All edits must be synced to `target/release/ui/` for the running server to pick them up.

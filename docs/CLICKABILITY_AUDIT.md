# LocInt UI Clickability + Wiring Audit

**Audit Date:** 2026-01-22  
**Build Stamp:** `2026-01-22-CLICKAUDIT`  
**Status:** ✅ Complete

---

## Executive Summary

Systematic audit of all interactive controls across all tabs (Mission, Runs, Import/Export, Settings, Team) plus global navigation. Found and fixed **4 issues**, added keyboard accessibility throughout.

---

## Issues Found & Fixed

| # | Tab | Element | Issue | Root Cause | Fix |
|---|-----|---------|-------|------------|-----|
| 1 | Mission | `#btnStartRun` | Click didn't trigger `startRun()` | Inline `onclick` in HTML conflicted with `addEventListener` binding | Removed inline onclick, added `data-action="startRun"` |
| 2 | Settings | `#settingsIntegrations` | Looked clickable (hover state) but no action | Missing click handler | Added click → `showUpgradePrompt()` |
| 3 | Settings | `#settingsCompare` | Looked clickable (hover state) but no action | Missing click handler | Added click → `showUpgradePrompt()` |
| 4 | Settings | `#settingsLicense` | Looked clickable (hover state) but no action | Missing click handler | Added click → `showLicenseModal()` |

---

## Code Changes

### File: `ui/index.html`

**Line 823** - Removed inline onclick from Start Run button:
```html
<!-- BEFORE -->
<button id="btnStartRun" class="btn-primary" onclick="console.log('INLINE ONCLICK FIRED!'); alert('Button clicked!');">

<!-- AFTER -->
<button id="btnStartRun" class="btn-primary" data-action="startRun">
```

### File: `ui/app.js`

**Lines 38-68** - Added Phase 1 click probe (DEBUG_MODE only):
```javascript
if (DEBUG_MODE) {
  document.addEventListener('click', (e) => {
    // Logs click target, elementFromPoint, interception detection
    // Warns if click blocked by z-index/pointer-events issues
  }, true);
}
```

**Lines 17843-17912** - Added Settings row click handlers with keyboard accessibility:
```javascript
// settingsIntegrations → showUpgradePrompt('Adapters & Integrations')
// settingsCompare → showUpgradePrompt('Baseline Compare')  
// settingsLicense → showLicenseModal()
// All: tabindex=0, role=button, Enter/Space handlers
```

**Lines 17914-17929** - Added global keyboard accessibility:
```javascript
document.querySelectorAll('[data-action], .btn-primary, .btn-secondary, .btn-danger, .tab, .run-tab, .path-chip, .playbook-filter-chip')
  .forEach(el => { /* Add tabindex, role, keydown handler */ });
```

**Lines 17932-17938** - Added `showLicenseModal()` helper function.

**Lines 18093-18240** - Added `window.uiSelfTest()` diagnostic function.

---

## Interactive Control Inventory

### Tab A: Mission

| Selector | Label | Binding | Status |
|----------|-------|---------|--------|
| `#btnStartRun` | Start Run | addEventListener → startRun() | ✅ Fixed |
| `#btnStopRun` | Stop Run | addEventListener → stopRun() | ✅ OK |
| `.path-chip` | Path of Work | addEventListener → togglePathOfWork() | ✅ OK |
| `#playbookPresetSelect` | Preset Dropdown | addEventListener change → applyPlaybookPreset() | ✅ OK |
| `#btnTogglePlaybookList` | Toggle Playbooks | addEventListener → togglePlaybookList() | ✅ OK |
| `#btnSelectAllRunnable` | Select Runnable | addEventListener → selectRunnablePlaybooks() | ✅ OK |
| `#btnClearPlaybooks` | Clear Selection | addEventListener → clearPlaybookSelection() | ✅ OK |
| `.playbook-filter-chip` | Filter Chips | addEventListener → toggleFilterChip() | ✅ OK |
| `#durationSelect` | Duration | Native select | ✅ OK |
| `#btnMissionRerunReadiness` | Re-check | addEventListener → retryReadinessCheck() | ✅ OK |

### Tab B: Runs

| Selector | Label | Binding | Status |
|----------|-------|---------|--------|
| `.run-item` | Run List Items | addEventListener → selectRun() | ✅ OK |
| `.run-tab` | Detail Tabs | addEventListener → switchRunTab() | ✅ OK |
| `#btnViewFindings` | View Findings | addEventListener → viewFindings() | ✅ OK |
| `#btnPrimaryInvestigate` | Investigate | addEventListener → investigateFinding() | ✅ OK |
| `#btnPrimaryEvidence` | Evidence | addEventListener → showEvidencePanel() | ✅ OK |
| `#btnPrimaryExport` | Export | addEventListener → exportFindings() | ✅ OK |
| `#btnExportRunHeader` | Export (header) | addEventListener → exportRun() | ✅ OK |
| `#btnGoToMission` | Go to Mission | addEventListener → switchTab('mission') | ✅ OK |
| `#findingsSeverityFilter` | Severity Filter | Native select | ✅ OK |
| `#btnExpandAllFindings` | Expand All | addEventListener → expandAllFindings() | ✅ OK |
| `#btnCollapseAllFindings` | Collapse All | addEventListener → collapseAllFindings() | ✅ OK |

### Tab C: Import/Export

| Selector | Label | Binding | Status |
|----------|-------|---------|--------|
| `#importDropZone` | Drop Zone | addEventListener dragover/dragleave/drop | ✅ OK |
| `#importFileInput` | File Input | addEventListener change → handleImportFiles() | ✅ OK |
| `#btnExportBundle` | Export Bundle | addEventListener → exportBundle() | ✅ OK |
| `#exportSegments` | Segments Checkbox | Native checkbox | ✅ OK |
| `#exportSignals` | Signals Checkbox | Native checkbox | ✅ OK |
| `#exportFacts` | Facts Checkbox | Native checkbox | ✅ OK |

### Tab D: Settings

| Selector | Label | Binding | Status |
|----------|-------|---------|--------|
| `#settingsDiagnostics` | Diagnostics | inline onclick → goToMissionDiagnostics() | ✅ OK |
| `#settingsIntegrations` | Integrations | addEventListener → showUpgradePrompt() | ✅ Added |
| `#settingsCompare` | Compare | addEventListener → showUpgradePrompt() | ✅ Added |
| `#settingsLicense` | License | addEventListener → showLicenseModal() | ✅ Added |

### Tab E: Team

| Selector | Label | Binding | Status |
|----------|-------|---------|--------|
| `#btnConfigureStore` | Configure Store | addEventListener | ✅ OK |
| `#btnRefreshStore` | Refresh Store | addEventListener | ✅ OK |
| `#btnCreateCase` | Create Case | addEventListener | ✅ OK |
| `.team-case-tab` | Case Tabs | addEventListener | ✅ OK |
| `#btnAddCaseNote` | Add Note | addEventListener | ✅ OK |
| `#btnPublishRunToCase` | Publish Run | addEventListener | ✅ OK |

### Global Navigation

| Selector | Label | Binding | Status |
|----------|-------|---------|--------|
| `.tab[data-tab]` | Main Tabs | addEventListener → switchTab() | ✅ OK |
| `#settingsGear` | Settings Gear | addEventListener → switchTab('settings') | ✅ OK |
| `#errorBannerDismiss` | Error Dismiss | addEventListener | ✅ OK |

---

## Debug Tools Added

### 1. Click Probe (DEBUG_MODE only)

Enable with `?debug=1` in URL. Logs every click with:
- Target element
- Element at click coordinates (elementFromPoint)
- Interception detection
- Event path
- pointer-events value

### 2. uiSelfTest() Function

Run in browser console:
```javascript
window.uiSelfTest()
```

Returns object with:
- `passed`: Count of verified controls
- `failed`: Count of missing required controls
- `warnings`: Count of optional/styling issues
- `details`: Array of per-control results

---

## Manual QA Script

1. **Load UI with debug mode**: `http://localhost:3000/?debug=1`

2. **Open browser DevTools console** (F12 → Console)

3. **Run automated test**:
   ```javascript
   window.uiSelfTest()
   ```
   Verify: 0 failures

4. **Mission Tab**:
   - [ ] Click "Start Run" → console shows `[CLICK PROBE] target: BUTTON#btnStartRun`
   - [ ] Click Path chips → chips toggle visual state
   - [ ] Click "Show Playbooks" → list expands
   - [ ] Change Duration dropdown → value persists

5. **Runs Tab**:
   - [ ] Click run in list → detail panel updates
   - [ ] Click sub-tabs (Summary/Findings/Raw) → content switches
   - [ ] Click "View Findings" → findings panel opens

6. **Import/Export Tab**:
   - [ ] Click drop zone → file picker opens
   - [ ] Drag file over drop zone → border highlights
   - [ ] Click "Export Bundle" → download initiates

7. **Settings Tab**:
   - [ ] Click "Diagnostics" → switches to Mission diagnostics section
   - [ ] Click "Integrations" → shows upgrade prompt
   - [ ] Click "Compare" → shows upgrade prompt
   - [ ] Click "License" → shows license modal

8. **Team Tab**:
   - [ ] Click "Configure Store" → modal opens
   - [ ] Click case tabs → content switches

9. **Keyboard Navigation**:
   - [ ] Tab through all controls → focus ring visible
   - [ ] Press Enter on focused button → action fires
   - [ ] Press Space on focused button → action fires

---

## Conclusion

All interactive controls now have proper bindings. The key root cause was an inline onclick handler on `#btnStartRun` that was added during debugging but conflicted with the IIFE's addEventListener binding. Settings rows had visual affordances (hover states, arrows) but no actual click handlers until now.

The DEBUG_MODE click probe and `uiSelfTest()` function provide ongoing verification tools for future UI changes.

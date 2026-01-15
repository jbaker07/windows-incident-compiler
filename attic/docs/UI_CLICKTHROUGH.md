# UI Clickthrough Test Script

This document provides a manual test script to verify all clickable elements in the Incident Compiler UI work as expected.

## Prerequisites

1. Start the app with `cargo tauri dev`
2. Backend should be running (check status bar)
3. Have some test telemetry data or use the verification pack

## Test Sequence

### 1. Initial Load & Wizard

- [ ] App loads showing welcome wizard
- [ ] Wizard title shows "Welcome to Incident Compiler"
- [ ] EDR platform buttons (Defender, Sysmon, Falcon, etc.) are clickable
- [ ] Preset buttons (HTB, Atomic, TryHackMe, Generic) are clickable
- [ ] Focus window buttons work
- [ ] "Load verification pack" checkbox is functional
- [ ] Next/Back buttons navigate wizard steps
- [ ] "Start" button completes wizard

### 2. Header Elements

- [ ] Header shows "Incident Compiler" title
- [ ] Mode badge shows (live/imported/verification)
- [ ] Stats counters update: events, findings, nodes, edges, bpf_drops
- [ ] "📤 Export Bundle" button opens export dialog
- [ ] "📥 Import Bundle" button opens file picker
- [ ] "🆘 Export Support Bundle" button works
- [ ] "Graph Evidence" link opens graph.html

### 3. Main Navigation Tabs

- [ ] **📋 Runs** tab - activates screenDash (default view)
- [ ] **🎯 New Run** tab - activates screenMission
- [ ] **📦 Import** tab - activates screenImport
- [ ] **🔌 Adapters** tab - activates screenIntegrations
- [ ] **🔀 Diff** tab - activates screenCompare
- [ ] **🔑 License** tab - activates screenLicense

### 4. Runs Tab (Dashboard)

#### Run Control Panel (Desktop only)
- [ ] Start Run button starts capture
- [ ] Stop Run button stops capture
- [ ] Duration dropdown works
- [ ] Playbook selector checkboxes work
- [ ] 🧪 Scenarios button opens scenario runner
- [ ] 🔧 Readiness button opens readiness check
- [ ] 📁 History button opens run history
- [ ] 📊 Metrics button shows metrics

#### Mission Control Panel
- [ ] "New Run →" button navigates to New Run tab

#### Findings Table
- [ ] Search/filter input works
- [ ] Severity dropdown filters
- [ ] Row click selects finding
- [ ] Selected finding shows in JSON panel

#### Cases Panel
- [ ] Cases list renders
- [ ] Case click expands details

#### Findings Panel
- [ ] Refresh button reloads findings
- [ ] Finding row has Explain button
- [ ] Finding row has Narrative button

#### Diagnostics Drawer (Advanced)
- [ ] Drawer opens/closes on click
- [ ] **Investigation Panel:**
  - [ ] Focus Window inputs work
  - [ ] Set Focus button works
  - [ ] Checkpoint label input works
  - [ ] Create Checkpoint button works
  - [ ] Checkpoint dropdown populates
  - [ ] Restore button works
  - [ ] Show Changes button works
  - [ ] Pivot dropdown works
  - [ ] Apply Pivot button works
- [ ] **Run Settings Panel:**
  - [ ] Telemetry profile dropdown works
  - [ ] Apply Profile button works
  - [ ] Throttle mode dropdown works
  - [ ] Reset Counters button works
- [ ] **Run Metrics Panel:**
  - [ ] Refresh button works
  - [ ] Load File button opens file picker
  - [ ] Detailed Results accordion opens
- [ ] **Pivot & Search Panel:**
  - [ ] Quick search input works
  - [ ] Events/Findings/Facts buttons work
  - [ ] Pivot by Entity dropdown works
  - [ ] Pivot button works

### 5. New Run Tab

- [ ] Run Profile dropdown populates
- [ ] Duration dropdown works
- [ ] Baseline dropdown populates
- [ ] ▶️ Start Mission button starts run
- [ ] ⏹️ Stop Mission button (when running)
- [ ] Mark Baseline button (after run)
- [ ] Compare to Baseline button (after run)
- [ ] Show Provenance button works
- [ ] 📋 Baselines button opens manager

### 6. Readiness Tab (Capability Exhaust)

#### Header Summary
- [ ] Readiness Score badge shows (Excellent/Good/Limited/Minimal/Blocked)
- [ ] Score percentage displays correctly
- [ ] Last check timestamp shows

#### Safe Probes Section
- [ ] **Run Probes** button triggers capability exhaust
- [ ] **Refresh** button (btnRefreshReadiness) reloads report
- [ ] Probe cards display for each probe type:
  - [ ] Process Creation probe card
  - [ ] DNS Lookup probe card
  - [ ] File Write probe card
  - [ ] PowerShell probe card
- [ ] Each probe card shows:
  - [ ] **Status icon**: ✅ Verified | ⚙️ ConfiguredOnly | ❌ NotObserved | ⚠️ ExecutionFailed | ⏭️ Skipped
  - [ ] **Command executed** with full path
  - [ ] **Expected providers** list
  - [ ] **Time window** searched (start → end)
  - [ ] **Matched count** with observed/expected IDs
  - [ ] **Evidence excerpt** (when Verified)
  - [ ] **Latency** in milliseconds

#### Channel Status Section
- [ ] Security channel shows enabled/accessible status
- [ ] Sysmon channel shows enabled/accessible status
- [ ] PowerShell channel shows enabled/accessible status
- [ ] Event count estimates display

#### Audit Policy Section
- [ ] Process Creation audit status
- [ ] Logon/Logoff audit status
- [ ] Command line in events checkbox status

#### Recommendations Section
- [ ] Priority-sorted recommendations display
- [ ] Each recommendation shows:
  - [ ] Priority badge (P0-P3)
  - [ ] Title and description
  - [ ] Admin requirement indicator
  - [ ] Impact score

#### View JSON Button
- [ ] Opens readiness report JSON in modal

### 7. Delta Report Flow

#### Delta Summary Header
- [ ] **Headline** shows change summary (e.g., "📈 3 new findings detected")
- [ ] **Significance badge** shows: None | Low | Medium | High | Critical
- [ ] **Key changes** list displays top 3 changes

#### Findings Delta Section
- [ ] **Added findings** list with severity indicators
- [ ] **Removed findings** list (resolved)
- [ ] **Changed findings** with field-level diffs
- [ ] Unchanged count displays

#### Noise Control Indicators
- [ ] Suppressed count shows (filtered by min_confidence, severity)
- [ ] Dedup count shows (stable key deduplication)
- [ ] Noise control config expandable (confidence threshold, suppressed severities)

#### Entities Delta Section
- [ ] New processes list
- [ ] New files list
- [ ] New network connections list
- [ ] New users list
- [ ] Removed entities in each category

#### MITRE Delta Section
- [ ] New techniques with tactic mapping
- [ ] Removed techniques list
- [ ] New/removed tactics summary

### 8. Import Tab

- [ ] Drop zone accepts files
- [ ] File picker button works
- [ ] Folder picker button works
- [ ] Imported cases list renders
- [ ] Case click shows details
- [ ] Delete Case button works
- [ ] Reprocess Case button works
- [ ] Export Case button works
- [ ] Generate Narrative button works

### 9. Adapters Tab

- [ ] Mode filter dropdown works
- [ ] 🔄 Refresh button reloads
- [ ] + Add Adapter button opens dialog
- [ ] Adapter row actions work (test, edit, delete)
- [ ] Capabilities Matrix loads
- [ ] Show Collectors checkbox works
- [ ] Join Key Support section loads

### 10. Diff Tab (Pro Feature)

- [ ] Pro banner shows if unlicensed
- [ ] "Get Pro" link works
- [ ] Left run dropdown populates
- [ ] Right run dropdown populates
- [ ] Run Diff button works (if licensed)

### 11. License Tab

- [ ] Install ID shows
- [ ] Copy button copies to clipboard
- [ ] License drop zone accepts files
- [ ] Install License button works
- [ ] License status displays correctly

### 12. Modals & Dialogs

- [ ] Signal Explanation Modal opens/closes
- [ ] Narrative Modal opens/closes
- [ ] Baseline Manager Modal opens/closes
- [ ] JSON Viewer Modal opens/closes
- [ ] Readiness JSON Modal opens/closes
- [ ] All modal × close buttons work
- [ ] All modal backdrop clicks close

### 13. Toast Notifications

- [ ] Errors show red toast
- [ ] Warnings show amber toast
- [ ] Success shows green toast
- [ ] Info shows slate toast
- [ ] Toasts auto-dismiss

### 14. Graph View (graph.html)

- [ ] Page loads with title "Evidence Graph"
- [ ] Pause/Resume button toggles
- [ ] Relayout button works
- [ ] Risk lens slider adjusts
- [ ] R-GCN toggle works
- [ ] Search input finds nodes
- [ ] Download JSON button exports
- [ ] Node hover shows tooltip
- [ ] Node click selects
- [ ] Zoom/pan works

### 15. Compiler-First Header (New)

- [ ] Run status indicator shows (●/⏸ icons with label)
- [ ] Findings count badge updates after compilation
- [ ] Readiness score displays percentage
- [ ] **Diagnostics drawer** toggle button works
- [ ] Diagnostics drawer shows live counters:
  - [ ] Events count
  - [ ] Nodes count
  - [ ] Edges count
  - [ ] BPF drops count

## Verification Checklist

After completing the clickthrough:

1. [ ] No console errors during test
2. [ ] All buttons gave feedback (visual/toast)
3. [ ] No dead buttons found
4. [ ] Pro features properly gated
5. [ ] All tab switches work
6. [ ] All modals open/close properly

## Notes

- Record any issues found during testing
- Note any elements that feel broken or unresponsive
- Check browser console for JS errors during each action

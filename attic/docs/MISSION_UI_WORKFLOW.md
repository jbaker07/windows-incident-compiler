# Mission Control UI Workflow

## Overview

The Mission Control UI provides a **terminal-free** workflow for running structured telemetry capture missions with quality gates, baselines, and provenance tracking.

**The promise: Users click buttons; they never think about Tauri commands or scripts.**

## Accessing Mission Control

### Option 1: Quick Access Banner (Dashboard)
When running in Tauri desktop mode, a purple banner appears at the top of the Dashboard:

```
🎯 Mission Control Available
   Run structured telemetry workflows with quality gates and baselines
   [Open Mission Control →]
```

Click **"Open Mission Control →"** to switch to the Mission tab.

### Option 2: Navigation Tab
Click the **"🎯 Mission"** tab in the top navigation bar.

---

## Mission Workflow (Click-by-Click)

### Step 1: Configure Mission
1. **Select Profile**: Choose a mission profile (e.g., "Default", "Network-focused", "Process-focused")
2. **Set Duration**: Pick capture duration (1, 2, 5, 10, or 15 minutes)
3. **Choose Baseline** (optional): Select a previous run to compare against

### Step 2: Run Mission
1. Click **"▶️ Start Mission"**
2. The Status Panel appears showing:
   - Progress bar with time remaining
   - Live counters (Events, Segments, Facts, Signals)
   - Real-time polling every 1.5 seconds
3. Wait for completion or click **"⏹️ Stop Mission"** to end early

### Step 3: View Results
After mission completes, the Results Panel shows:
- **Verdict**: ✅ or ⚠️ with summary
- **Quality Gates**: Grid of pass/fail gates
- **Final Stats**: Events, Segments, Facts, Signals captured
- **Baseline Comparison** (if baseline was selected): Deltas and regressions

### Step 4: Mark as Baseline (Optional)
1. Click **"⭐ Mark as Baseline"**
2. Enter a description (e.g., "First successful adversary detection run")
3. Check "Set as default baseline" if desired
4. Click **"Mark Baseline"**

### Step 5: Compare Against Baseline
1. Click **"🔀 Compare to Baseline"**
2. View delta metrics and any regressions

### Step 6: View Provenance
1. Click **"🔍 Provenance"**
2. See the evidence chain from captured segments → facts → signals

---

## UI Components

### Mission Control Tab (`screenMission`)
The main Mission Control interface with:
- Configuration dropdowns (profile, duration, baseline)
- Control buttons (Start, Stop, Mark Baseline, Compare, Provenance, Manage Baselines)
- Status Panel with live counters
- Results Panel with quality gates and comparison

### Quick Access Banner (`missionControlPanel`)
Shown on Dashboard in Tauri mode - links to Mission tab.

### Modals
- **Baseline Manager**: List all baselines, set default, clear
- **Mark Baseline**: Create new baseline from current run
- **Provenance**: View evidence chain
- **JSON Viewer**: View raw `run_summary.json` or `quality_report.json`

---

## Live Counters (Requirement #3)

During an active mission, counters poll every **1.5 seconds**:
- **Events**: Total events captured + rate per second
- **Segments**: Segments written + bytes
- **Facts**: Facts extracted from segments
- **Signals**: Signals emitted by playbooks

---

## Quality Gates & Run Artifacts (Requirement #4)

After mission completes:
1. UI calls `get_mission_metrics(runId)` for summary stats
2. UI loads `quality_report.json` via `read_run_artifact` for quality gates
3. Quality gates displayed in a grid (✓ pass / ✗ fail)
4. Click **"📄 View run_summary.json"** or **"📋 View quality_report.json"** for raw data

---

## Baseline Manager (Requirement #5)

The Baseline Manager (`📋 Manage Baselines` button) allows:
- View all marked baselines
- See which is the default (⭐)
- Set a different baseline as default
- Clear the default baseline

Baselines also appear in the "Recent Baselines" quick list at the bottom of the Mission tab.

---

## UX States (Requirement #6)

### While Running
- **Start button**: Hidden
- **Stop button**: Visible
- **Mark/Compare/Provenance buttons**: Disabled
- **Progress bar**: Animating with time remaining

### After Completion
- **Start button**: Visible
- **Stop button**: Hidden
- **Mark/Compare/Provenance buttons**: Enabled
- **Results panel**: Visible with stats and quality gates

### Error States
- Errors display in mission error box
- Specific error messages for permissions issues (402/403)
- Button states reset on error

---

## Tauri Commands Used

| UI Action | Tauri Command |
|-----------|---------------|
| Start Mission | `start_mission` |
| Stop Mission | `stop_mission` |
| Poll Counters | `get_pipeline_counters` |
| Get Metrics | `get_mission_metrics` |
| Read Artifact | `read_run_artifact` |
| Mark Baseline | `mark_run_as_baseline` |
| Compare Baseline | `compare_against_baseline` |
| Get Baselines | `get_baselines` |
| Set Default | `set_default_baseline` |
| Provenance | `prove_signal_origins` |
| Open Folder | `open_folder` |

---

## Complete Click-Flow

```
Open App
  │
  ├── Dashboard shows "Mission Control Available" banner
  │     └── Click "Open Mission Control →"
  │
  └── OR click "🎯 Mission" tab
        │
        ▼
Mission Control Tab
  │
  ├── Select Profile (dropdown)
  ├── Select Duration (dropdown)
  ├── Select Baseline (optional dropdown)
  │
  └── Click "▶️ Start Mission"
        │
        ▼
Mission Running
  │
  ├── Watch live counters (Events/Segments/Facts/Signals)
  ├── Watch progress bar countdown
  │
  └── Mission auto-completes OR click "⏹️ Stop Mission"
        │
        ▼
Mission Complete
  │
  ├── View verdict (✅/⚠️)
  ├── View quality gates grid
  ├── View final stats
  │
  ├── Click "⭐ Mark as Baseline" → Fill form → Confirm
  ├── Click "🔀 Compare to Baseline" → View deltas/regressions
  ├── Click "🔍 Provenance" → View evidence chain
  ├── Click "📄 View run_summary.json" → Modal with JSON
  ├── Click "📋 View quality_report.json" → Modal with JSON
  └── Click "📂 Open Run Folder" → Opens explorer
```

---

## Files Modified

- `ui/index.html`: Added Mission tab, screenMission section, modals
- `ui/app.js`: Added Mission Control module with all button handlers and polling

## Backend Commands Required

Ensure these Tauri commands are implemented:
- `start_mission`
- `stop_mission`
- `get_pipeline_counters`
- `get_mission_metrics`
- `read_run_artifact`
- `mark_run_as_baseline`
- `compare_against_baseline`
- `get_baselines`
- `set_default_baseline`
- `prove_signal_origins`
- `open_folder`
- `get_mission_profiles` (optional, provides fallback defaults)

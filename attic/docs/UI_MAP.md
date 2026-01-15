# UI Map - Incident Compiler

This document maps the navigation structure and screen architecture of the Incident Compiler UI.

## Navigation Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          INCIDENT COMPILER                               │
│  ┌──────┐ ┌────────┐ ┌────────┐ ┌──────────┐ ┌──────┐ ┌─────────┐      │
│  │ Runs │ │New Run │ │ Import │ │ Adapters │ │ Diff │ │ License │      │
│  └──┬───┘ └────┬───┘ └────┬───┘ └────┬─────┘ └──┬───┘ └────┬────┘      │
└─────┼──────────┼──────────┼──────────┼──────────┼──────────┼────────────┘
      │          │          │          │          │          │
      ▼          ▼          ▼          ▼          ▼          ▼
┌──────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐ ┌─────────┐
│screenDash│ │screenMis│ │screenImp│ │screenInt│ │screenCo│ │screenLic│
│          │ │sion     │ │ort      │ │egrations│ │mpare   │ │ense     │
└──────────┘ └─────────┘ └─────────┘ └─────────┘ └────────┘ └─────────┘
```

## Screen Details

### 1. Runs (screenDash) - Default View

The main operational view for monitoring telemetry capture runs.

**Layout:**
```
┌────────────────────────────────────────────────────────────────┐
│ Run Control Panel (Desktop only)                                │
│ [Start/Stop] [Duration] [Playbooks] [Scenarios] [Readiness]    │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ New Run Quick Access Panel                                      │
│ [New Run →]                                                    │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ ┌────────────────────────┐ ┌─────────────────────────────────┐ │
│ │ Findings Table         │ │ Timeline Chart                  │ │
│ │ [filter] [severity▼]   │ │ (canvas)                       │ │
│ │ ─────────────────────  │ │                                 │ │
│ │ time | sev | event     │ └─────────────────────────────────┘ │
│ │                        │ ┌─────────────────────────────────┐ │
│ │                        │ │ Cases                           │ │
│ │                        │ │ (compiled findings)             │ │
│ └────────────────────────┘ └─────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ Findings Panel                                                  │
│ [Explain] [Narrative] for each finding                         │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ ▸ Advanced / Diagnostics (collapsible)                         │
│   ┌────────────────────────────────────────────────────────┐   │
│   │ Investigation Panel                                     │   │
│   │ Focus Window | Checkpoints | Diff View | Disambiguation │   │
│   └────────────────────────────────────────────────────────┘   │
│   ┌────────────────────────────────────────────────────────┐   │
│   │ Run Settings Panel                                      │   │
│   │ Telemetry Profile | Throttle Config                     │   │
│   └────────────────────────────────────────────────────────┘   │
│   ┌────────────────────────────────────────────────────────┐   │
│   │ Run Metrics Panel                                       │   │
│   │ Events | Signals | Facts | Verdict                      │   │
│   └────────────────────────────────────────────────────────┘   │
│   ┌────────────────────────────────────────────────────────┐   │
│   │ Pivot & Search Panel                                    │   │
│   │ Quick Search | Pivot by Entity | Results               │   │
│   └────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ Selected Finding (JSON)                                        │
│ <pre>                                                          │
└────────────────────────────────────────────────────────────────┘
```

### 2. New Run (screenMission)

Configure and launch a telemetry capture mission.

**Layout:**
```
┌────────────────────────────────────────────────────────────────┐
│ 🎯 New Run                                                     │
│ Configure and start a telemetry capture run.                   │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ Run Configuration                                               │
│ ┌─────────────┐ ┌──────────────┐ ┌───────────────────┐        │
│ │ Run Profile │ │ Duration     │ │ Baseline          │        │
│ └─────────────┘ └──────────────┘ └───────────────────┘        │
│ [▶️ Start Mission] [⏹️ Stop] [Mark Baseline] [Compare]         │
│ [Show Provenance] [📋 Baselines]                               │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ Mission Results (after completion)                              │
│ Quality Gates | Stats | Baseline Comparison                    │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ Available Baselines                                            │
│ (list of saved baseline runs)                                  │
└────────────────────────────────────────────────────────────────┘
```

### 3. Import (screenImport)

Import evidence bundles and manage cases.

**Layout:**
```
┌──────────────────────────────┐ ┌─────────────────────────────┐
│ Import Zone                   │ │ Case Details               │
│ ┌──────────────────────────┐ │ │ ┌─────────────────────────┐│
│ │      Drop files here     │ │ │ │ Case Header             ││
│ │  or click to browse      │ │ │ │ [Delete][Reprocess]     ││
│ └──────────────────────────┘ │ │ │ [Export][Narrative]     ││
│ [📂 Folder]                   │ │ └─────────────────────────┘│
│                               │ │ ┌─────────────────────────┐│
│ 📁 Imported Cases             │ │ │ Case Tabs:              ││
│ ┌──────────────────────────┐ │ │ │ Timeline|Signals|Entities││
│ │ case_001                 │ │ │ │ Manifest|Narrative      ││
│ │ case_002                 │ │ │ └─────────────────────────┘│
│ │ ...                      │ │ │                            │
│ └──────────────────────────┘ │ │                            │
└──────────────────────────────┘ └─────────────────────────────┘
```

### 4. Adapters (screenIntegrations)

Manage telemetry adapters for data import/export.

**Layout:**
```
┌────────────────────────────────────────────────────────────────┐
│ Import Adapters                                                 │
│ [Mode▼] [🔄 Refresh] [+ Add Adapter]                           │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ Adapter Profiles Table                                          │
│ Status | Name | Type | Mode | EPS | Errors | Facts | Actions  │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ 📊 Capabilities Matrix                                          │
│ HARD/SOFT telemetry coverage by adapter                        │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ 🔗 Join Key Support                                             │
│ Entity correlation capabilities                                │
└────────────────────────────────────────────────────────────────┘
```

### 5. Diff (screenCompare) - Pro Feature

Compare findings between runs.

**Layout:**
```
┌────────────────────────────────────────────────────────────────┐
│ 🔀 Diff Runs (Pro Feature)                                     │
│ ⚠️ Pro license required                                        │
│ [Get Pro →]                                                    │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ Compare Findings Between Runs                                   │
│ ┌────────────────┐   ┌────────────────┐                       │
│ │ Left Run ▼     │   │ Right Run ▼    │   [Run Diff]          │
│ └────────────────┘   └────────────────┘                       │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ Diff Results                                                    │
│ Added | Removed | Changed findings                             │
└────────────────────────────────────────────────────────────────┘
```

### 6. License (screenLicense)

Manage product licensing.

**Layout:**
```
┌────────────────────────────────────────────────────────────────┐
│ 🔑 License                                                      │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ Installation ID                                                 │
│ [install-id-here]                               [📋 Copy]      │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ License Status                                                  │
│ ✅ Pro Licensed  or  ⚠️ Free Tier                              │
│ Features: [list]                                               │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│ Install License                                                 │
│ Drop .lic file here or click to browse                        │
│ [Install License]                                              │
└────────────────────────────────────────────────────────────────┘
```

## Modals

| Modal | ID | Trigger |
|-------|-----|---------|
| Welcome Wizard | `wizardModal` | App start (first run) |
| Signal Explanation | `explainModal` | Explain button on finding |
| Narrative | `narrativeModal` | Narrative button on finding |
| Baseline Manager | `baselineManagerModal` | 📋 Baselines button |
| JSON Viewer | `jsonViewerModal` | View JSON buttons |
| Add Adapter | `addIntegrationDlg` | + Add Adapter button |
| Sample Events | `sampleEventModal` | Sample Events buttons |
| Metrics | `metricsModal` | 📊 Metrics button |
| E2E Results | `e2eModal` | E2E test completion |
| Readiness | `readinessModal` | 🔧 Readiness button |
| Scenario Runner | `scenarioRunnerModal` | 🧪 Scenarios button |
| Run History | `runHistoryModal` | 📁 History button |

## Element ID Reference

### Tabs
- `tabDash` → Runs
- `tabMission` → New Run
- `tabImport` → Import
- `tabIntegrations` → Adapters
- `tabCompare` → Diff
- `tabLicense` → License

### Screens
- `screenDash` - Main runs/findings view
- `screenMission` - New run configuration
- `screenImport` - Import cases
- `screenIntegrations` - Adapter management
- `screenCompare` - Diff comparison
- `screenLicense` - License management

### Key Panels
- `runControlPanel` - Desktop run controls
- `missionControlPanel` - Quick access to new run
- `runResultsPanel` - Post-run results
- `signalsPanel` - Findings list
- `diagnosticsDrawer` - Advanced controls (collapsible)
- `analystWorkflow` - Investigation tools
- `captureControlPanel` - Run settings
- `runMetricsPanel` - Metrics display
- `pivotSearchPanel` - Search/pivot tools

## Terminology Mapping

| Old Term | New Term | Context |
|----------|----------|---------|
| EDR Demo | Incident Compiler | App title |
| Alerts | Findings | Detection results |
| Incidents | Cases | Compiled findings |
| Signals | Findings | Playbook matches |
| Dashboard | Runs | Main tab |
| Mission | New Run | Tab name |
| Integrations | Adapters | Tab name |
| Compare Runs | Diff | Tab name |
| Live Graph | Evidence Graph | graph.html title |

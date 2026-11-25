# UI Workflow Guide

This document describes the detection engineer workflow in the EDR Dashboard UI.

## Overview

The UI provides a unified view for:
1. Monitoring live telemetry and alerts
2. Viewing playbook signals and explanations
3. Running evaluations and reviewing metrics
4. Pivoting and searching across events, signals, and facts

## Panels

### Dashboard (Main View)

#### Alerts Panel
- Real-time alerts from the detection pipeline (`/alerts`, one per signal)
- Filter by severity (low/medium/high/critical)
- Search by process name, command line, or tags
- Click any alert to open its explanation

#### Timeline
- Visual timeline of alert frequency
- Helps identify attack bursts and patterns

#### Incidents (Rollups)
- Signals grouped per host and hour (`/incidents/stream`)
- Shows the playbooks, techniques and highest severity in each group

### Playbook Signals Panel
- Shows signals from playbook-based detection
- Click "Explain" to see slot fills and evidence
- Signals are linked to specific playbooks and rules (e.g., `playbook:signal_credential_access`, rule "LSASS Process Access")

### Run Metrics Panel

Location: Below Capture Control panel

Features:
- **Load File**: Load a metrics JSON from `eval_windows.ps1` output
- **Refresh**: Poll server for latest metrics

Displays:
- Run ID, timestamp, duration, status
- Detection counts: signals, explained, playbooks hit, false positives
- Telemetry stats: events, segments, channels, EPS
- Pass/Fail verdicts:
  - Telemetry flowing
  - Detections fired
  - Explanations valid
  - No fake detections

### Pivot & Search Panel

Location: Below Run Metrics panel

Features:
- **Quick Search**: Search by process name, hash, IP, user
  - Search Events: Filter timeline/telemetry
  - Search Signals: Query playbook signals
  - Search Facts: Query canonical facts

- **Pivot by Entity**: Select entity type and value to pivot
  - Process, File, Network, User, Registry

### Capture Control Panel

Manage telemetry capture:
- **Capture Profile**: Core/Extended/Forensic
- **Throttle Stats**: Accepted/Dropped events
- **Active Sensors**: Currently enabled sensors
- **Visibility Status**: Degraded reasons if any

## Workflows

### Basic Detection Validation

1. Start the stack:
   ```powershell
   .\scripts\run_stack_windows.ps1
   ```

2. Open UI at http://127.0.0.1:3000

3. Monitor Alerts panel for incoming events

4. Check Playbook Signals for detection hits

5. Click "Explain" on any signal to see evidence

### Running Evaluation

1. On a throwaway VM, run the live evaluation and leave edr-server running. It clears
   the Security and System logs and changes the audit policy:
   ```powershell
   .\scripts\eval_windows.ps1 -ScenarioSet basic -DisposableHost -KeepRunning
   ```

2. Open http://127.0.0.1:3000 and go to the Run Metrics panel

3. Click "Refresh" or "Load File" to view results

4. Check all verdicts pass

### Investigating an Incident

1. Click an incident in the Incidents panel

2. Review the hypothesis explanation

3. Use Pivot & Search to find related events:
   - Enter process name from alert
   - Click "Search Signals" to find all related signals
   - Use "Pivot by Entity" to follow process tree

4. Check Evidence Pointers for raw telemetry locations

5. Use Focus Window to narrow time range

### Exporting Results

- **Export Bundle**: Download current investigation as ZIP
- **Export Support Bundle**: Redacted diagnostic package

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` | Focus search input |
| `Esc` | Close modal dialogs |
| `r` | Refresh current view |

## Status Indicators

| Badge | Meaning |
|-------|---------|
| `live` (green) | Real-time telemetry active |
| `verification` (yellow) | Synthetic test data loaded |
| `degraded` (red) | Visibility issues detected |

## Troubleshooting

### No Events Appearing
1. Check capture_windows_rotating.exe is running
2. Run `enable_advanced_telemetry.ps1 -AutoFix`
3. Check Capture Control panel for throttle stats

### Signals Not Firing
1. Verify telemetry channels are enabled
2. Check the Playbook Signals panel for hits
3. Review playbook requirements in [playbooks_windows_coverage.md](playbooks_windows_coverage.md)

### UI Not Loading
1. Verify edr-server.exe is running on port 3000
2. Check browser console for errors
3. Try the http://127.0.0.1:3000/health endpoint

## See Also

- [Playbook Coverage](playbooks_windows_coverage.md)
- [Facts Reference](facts_windows.md)
- [README](../README.md)

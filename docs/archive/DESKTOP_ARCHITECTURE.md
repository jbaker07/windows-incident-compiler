# EDR Desktop Architecture

## Overview

The EDR Desktop application is a production-ready Windows desktop app built with Tauri v2 that provides:
- One-click run workflow for telemetry capture and detection
- Per-run directory structure for organized telemetry storage
- Readiness checks for system capabilities
- Scenario runner for safe test activity generation
- Metrics v2 with per-playbook statistics
- Full explainability via ExplanationBundle

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                      EDR Desktop (Tauri v2)                         │
├─────────────────────────────────────────────────────────────────────┤
│  UI Layer (index.html + JavaScript)                                 │
│  ├── Run Control Panel (Start/Stop/Duration)                        │
│  ├── Readiness Modal (Admin/Sysmon/Audit checks)                    │
│  ├── Scenario Runner (Tier A/B/C safe activities)                   │
│  ├── Run History (Previous runs with metrics)                       │
│  ├── Metrics Modal (Per-playbook stats, validation)                 │
│  └── Signal Explain Modal (ExplanationBundle viewer)                │
├─────────────────────────────────────────────────────────────────────┤
│  Rust Backend (src-tauri/)                                          │
│  ├── Supervisor (process management, per-run dirs)                  │
│  ├── Readiness Checks (admin, security log, sysmon, audit)          │
│  ├── Run History (list_runs, get_run_metrics)                       │
│  └── Activity Commands (whitelisted exe execution)                  │
├─────────────────────────────────────────────────────────────────────┤
│  Supervised Processes                                               │
│  ├── capture_windows_rotating.exe (telemetry capture)               │
│  ├── edr-locald.exe (fact extraction, playbook matching)            │
│  └── edr-server.exe (HTTP API on port 3000)                         │
└─────────────────────────────────────────────────────────────────────┘
```

## Per-Run Directory Structure

Each run creates an isolated directory under:
```
%LOCALAPPDATA%\windows-incident-compiler\telemetry\runs\<run_id>\
├── segments/       # JSONL telemetry segments
├── logs/           # Process logs (capture.log, locald.log, server.log)
├── metrics/        # Metrics v2 JSON artifact
├── incidents/      # Promoted incidents
└── exports/        # Exported bundles
```

## Tauri Commands

### Run Management
| Command | Description |
|---------|-------------|
| `start_run(duration_minutes, selected_playbooks)` | Start a timed capture run |
| `stop_all()` | Stop all processes and write metrics |
| `get_status()` | Get current stack status including run stats |

### Readiness
| Command | Description |
|---------|-------------|
| `get_readiness()` | Check admin, security log, sysmon, audit policy |
| `apply_telemetry_fix(fix_id)` | Apply a recommended fix (requires admin) |

### History & Metrics
| Command | Description |
|---------|-------------|
| `list_runs()` | List all previous runs with summary |
| `get_run_metrics(run_id)` | Get Metrics v2 for a specific run |
| `open_run_folder(run_id)` | Open run folder in Explorer |

### Activity Generation
| Command | Description |
|---------|-------------|
| `run_activity_command(exe, args)` | Run whitelisted command for telemetry |

## Metrics v2 Schema

```json
{
  "schema_version": "2.0",
  "run_id": "run_20250101_120000",
  "timestamp": "2025-01-01T12:10:00+00:00",
  "host": "WORKSTATION",
  "os": "Windows",
  "os_version": "Microsoft Windows [Version 10.0.22631.xxxx]",
  
  "environment": {
    "is_admin": true,
    "limited_mode": false,
    "port": 3000,
    "run_dir": "...\telemetry\runs\run_20250101_120000"
  },
  
  "config": {
    "duration_minutes": 10,
    "selected_playbooks": null
  },
  
  "telemetry": {
    "segments_count": 42
  },
  
  "pipeline": {
    "signals_count": 5,
    "signals_by_playbook": {
      "windows_lolbin_abuse": 2,
      "windows_log_tamper_clear": 1
    },
    "signals_by_severity": {
      "high": 2,
      "medium": 3
    }
  },
  
  "timing": {
    "elapsed_seconds": 600,
    "events_per_second": 70.0
  },
  
  "validation": {
    "has_signals": true,
    "has_segments": true,
    "pipeline_working": true
  }
}
```

## Readiness Check Structure

```json
{
  "is_admin": true,
  "can_read_security_log": true,
  "sysmon_installed": true,
  "sysmon_version": "15.0",
  "audit_policy_state": {
    "process_creation": true,
    "command_line_logging": true,
    "logon_events": true
  },
  "powershell_logging_enabled": true,
  "overall_readiness": "Full",
  "recommended_fixes": []
}
```

### Readiness Levels
| Level | Criteria |
|-------|----------|
| **Full** | Admin + Security Log + Sysmon + Audit OK |
| **Good** | Admin + Security Log, missing enhancements |
| **Limited** | Non-admin, basic telemetry only |
| **Blocked** | Cannot capture meaningful telemetry |

## Scenario Tiers

| Tier | Risk | Examples |
|------|------|----------|
| **A** | Safe | whoami, hostname, Get-ComputerInfo |
| **B** | Moderate | reg query, schtasks /Query, wmic process list |
| **C** | Advanced | net user, net localgroup, nltest |

## Signal Pipeline (No Fake Signals)

```
Windows Events → capture_windows_rotating.exe
     ↓ (JSONL segments)
edr-locald.exe
     ↓ fact_extractor.rs: Event → Fact
     ↓ playbook_loader.rs: Load YAML playbooks
     ↓ signal_engine.rs: Facts × Playbooks → Signals
     ↓ explanation_builder.rs: Signal → ExplanationBundle
edr-server.exe
     ↓ GET /api/signals
     ↓ GET /api/signals/:id/explain
UI displays with ExplanationBundle viewer
```

## Key Implementation Files

| File | Purpose |
|------|---------|
| `src-tauri/src/supervisor.rs` | Process lifecycle, per-run dirs, readiness checks |
| `src-tauri/src/main.rs` | Tauri commands |
| `ui/index.html` | Desktop UI with modals and panels |
| `crates/locald/src/os/windows/fact_extractor.rs` | Event → Fact mapping |
| `crates/locald/src/os/windows/signal_engine.rs` | Signal detection |
| `crates/core/src/explain.rs` | ExplanationBundle structure |

## User Workflow

1. **Open App** → Readiness check runs automatically
2. **Review Readiness** → Apply fixes if needed (admin)
3. **Select Duration** → 2-60 minutes
4. **Click "Start Run"** → Processes launch, telemetry flows
5. **Optionally Run Scenarios** → Generate detectable activity
6. **View Signals Panel** → Real signals from playbooks
7. **Click "Explain"** → See ExplanationBundle with evidence
8. **Run Completes** → Metrics v2 written to run folder
9. **Review History** → Compare runs, export metrics

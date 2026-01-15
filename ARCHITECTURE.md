# Windows Incident Compiler - Architecture Documentation

This document provides a file-by-file breakdown of the entire codebase with explanations of what each file does.

---

## Project Overview

**windows-incident-compiler** is a Windows EDR (Endpoint Detection and Response) signal analysis platform. It captures Windows telemetry (via ETW, Sysmon, Event Logs), runs detection playbooks against the telemetry, and produces a forensic-quality report with MITRE ATT&CK mappings.

### Core Binaries

| Binary | Description |
|--------|-------------|
| `locint.exe` | Main GUI binary (Tauri desktop app) - primary user-facing product |
| `edr-server.exe` | Headless HTTP server for CLI/automation use |
| `edr-locald.exe` | Detection daemon (processes telemetry, fires signals) |
| `capture_windows_rotating.exe` | Telemetry capture agent (ETW/Sysmon/Event Logs) |
| `wi_run_all.exe` | Smoke test harness (CI verification tool) |

---

## Root Files

| File | Description |
|------|-------------|
| `Cargo.toml` | Workspace manifest defining all crates |
| `BUILD.md` | Build instructions |
| `README.md` | Project overview and quick-start |
| `CHANGELOG.md` | Version history |
| `LICENSE` | License file |
| `TRUTH_CONTRACT.md` | Hard invariants enforced by CI (smoke tests fail if violated) |
| `RELEASE_NOTES.md` | Release notes for current version |
| `REAL_RUN_CHECKLIST.md` | Pre-flight checklist for production runs |
| `CLEANUP_PLAN.md` | Technical debt cleanup tracking |
| `CLEANUP_INVENTORY.txt` | Inventory of files to clean up |
| `REPO_FILE_AUDIT.md` | Audit of repository files |
| `SENSOR_USAGE_AUDIT.md` | Audit of sensor usage across codebase |
| `LOCINT_GAP_REPORT.md` | Gap analysis report |
| `STAGE3_SURFACE_VIEW.md` | Stage 3 surface view documentation |
| `warnings.txt` | Compilation warnings log |

---

## crates/core/src/ - Core Types Library

The foundational types shared across all crates.

| File | Description |
|------|-------------|
| `lib.rs` | Module exports and re-exports for edr_core |
| `event.rs` | Canonical `Event` struct - the normalized telemetry record all agents produce |
| `event_keys.rs` | Key generation for events (proc_key, file_key, identity_key) |
| `event_validation_test.rs` | Unit tests for event validation |
| `evidence_ptr.rs` | `EvidencePtr` struct - links signals back to source telemetry (stream_id, segment_id, record_index) |
| `explain.rs` | Core explainability types for signal explanations |
| `explain_api.rs` | API types for explainability endpoints (`SignalExplanation`, `ConfidenceDetail`) |
| `severity.rs` | `Severity` enum (Info, Low, Medium, High, Critical) for signals |
| `signal_result.rs` | `SignalResult` struct - represents a detected signal with all metadata |
| `license.rs` | License types and structs |
| `license_manager.rs` | License validation and feature gating |
| `license_protection.rs` | License protection and anti-tampering |
| `machine_fingerprint.rs` | Hardware fingerprinting for license binding |
| `install_id.rs` | Installation ID generation and persistence |
| `diff.rs` | Diff types for delta reports (Pro feature) |
| `narrative.rs` | Narrative generation types (Pro feature) |
| `watermark.rs` | Report watermarking (Pro feature) |
| `error.rs` | Shared error types |

---

## crates/locald/src/ - Detection Daemon

The signal detection engine that processes telemetry and fires detection rules.

### Root Files

| File | Description |
|------|-------------|
| `lib.rs` | Module exports, architecture diagram in doc comments |
| `pipeline.rs` | Event processing pipeline - converts `TelemetryInput` → `Event` → `SignalResult` |
| `signal_orchestrator.rs` | Routes events to platform-specific engines (Windows/macOS/Linux) |
| `signal_result.rs` | Local signal result types |
| `signal_persistence.rs` | Persists signals to `signals.jsonl` file |
| `playbook_loader.rs` | Loads YAML playbooks from disk |
| `playbook_manager.rs` | Manages playbook lifecycle, tag mappings, enables/disables playbooks |
| `slot_matcher.rs` | Playbook slot matching engine - matches events against playbook conditions |
| `slot_matcher_tests.rs` | Unit tests for slot matcher |
| `e2e_playbook_test.rs` | End-to-end tests for YAML playbook loading and firing |
| `baseline.rs` | Baseline/whitelist management for reducing false positives |
| `scoring.rs` | Signal scoring and confidence calculation |
| `evidence.rs` | Evidence system with path safety |

### locald/src/os/ - Platform-Specific Engines

| File | Description |
|------|-------------|
| `mod.rs` | Platform module exports |

#### locald/src/os/windows/

| File | Description |
|------|-------------|
| `mod.rs` | Windows module exports |
| `signal_engine.rs` | `WindowsSignalEngine` - main detection engine, includes `is_self_process()` allowlist |
| `signals_windows.rs` | Windows-specific signal definitions |
| `signal_result.rs` | Windows-specific signal result types |
| `fact_extractor.rs` | Extracts facts from Windows telemetry (proc_tree, file ops, registry, etc.) |
| `playbooks.rs` | Windows playbook loading and management |

#### locald/src/os/linux/

| File | Description |
|------|-------------|
| `mod.rs` | Linux module exports |
| `signal_engine.rs` | `LinuxSignalEngine` - Linux detection engine (stub, not primary platform) |

#### locald/src/os/macos/

| File | Description |
|------|-------------|
| `mod.rs` | macOS module exports |
| `signal_engine.rs` | `MacOSSignalEngine` - macOS detection engine (stub, not primary platform) |

### locald/src/integrations/ - External Integrations

| File | Description |
|------|-------------|
| `mod.rs` | Integration module exports |
| `config.rs` | Integration configuration types |
| `export.rs` | Export adapters for external systems |
| `ingest.rs` | `VendorAlertIngester` - ingests alerts from SIEMs |
| `metrics.rs` | Metrics collection and export |
| `profile.rs` | Integration profiles |
| `vendor_alert.rs` | Vendor alert types and parsing |

---

## crates/server/src/ - HTTP Server

The HTTP API layer serving the UI and programmatic clients.

### Root Files

| File | Description |
|------|-------------|
| `lib.rs` | Module exports, re-exports key types for tests |
| `main.rs` | Server entrypoint (NOT USED - see bin/locint.rs) |
| `server_core.rs` | Shared router construction used by both edr-server and locint |
| `db.rs` | Database utilities |
| `run_db.rs` | Run-specific database (`workbench.db`) with signals, coverage_rollup tables |
| `run_control.rs` | Run lifecycle management (start, stop, finalize) |
| `run_coverage.rs` | MITRE ATT&CK coverage calculation |
| `bundle_exchange.rs` | Import/export bundle functionality |
| `golden_bundle.rs` | Golden bundle generation and verification for CI |
| `health.rs` | Health check endpoints (`/api/v1/health`) |
| `capture_control.rs` | Capture agent control endpoints |
| `explain_normalize.rs` | Normalizes signal explanations for API response |
| `report.rs` | Report generation (PDF, JSON) |
| `diagnostics.rs` | Diagnostic endpoints |
| `diff_api.rs` | Delta report API (Pro feature) |
| `integration_api.rs` | Integration profile API |
| `license_api.rs` | License management API |
| `probe.rs` | Probe endpoints for testing |
| `query_isolation.rs` | Query isolation for imported vs live data |
| `write_isolation.rs` | Write isolation to prevent cross-run contamination |
| `support_bundle.rs` | Support bundle generation for debugging |
| `verification_pack.rs` | Verification pack generation |

### server/src/bin/ - Binary Entrypoints

| File | Description |
|------|-------------|
| `locint.rs` | **MAIN BINARY** - GUI server with all HTTP handlers, Tauri hooks |
| `golden_cli.rs` | CLI for golden bundle operations |
| `license_gen.rs` | License generation tool (internal use) |

---

## crates/agent-windows/src/ - Windows Capture Agent

Captures Windows telemetry via ETW, Sysmon, and Event Logs.

### Root Files

| File | Description |
|------|-------------|
| `lib.rs` | Module exports |
| `main.rs` | Agent entrypoint (NOT USED - see bin/) |
| `capture_windows_rotating.rs` | **MAIN CAPTURE LOGIC** - rotating JSONL capture with segment management |
| `config.rs` | Capture configuration (paths, rotation settings) |
| `telemetry.rs` | Telemetry collection orchestration |
| `telemetry_types.rs` | Telemetry record types |
| `host.rs` | Host information gathering |
| `wevt_reader.rs` | Windows Event Log reader (via Windows API) |
| `wevt_bookmarks.rs` | Event Log bookmarks for incremental reads |
| `bookmark_manager.rs` | Manages bookmarks across restarts |
| `evtlog_state.rs` | Event Log state tracking |
| `self_test.rs` | Self-test for capture agent |

### agent-windows/src/bin/

| File | Description |
|------|-------------|
| (capture_windows_rotating.rs is typically built as binary) | Main capture binary |

### agent-windows/src/sensors/ - Telemetry Sensors

| File | Description |
|------|-------------|
| `mod.rs` | Sensor module exports and registration |
| `collect.rs` | Sensor collection orchestration |
| `sysmon_adapter.rs` | Sysmon event parsing (process create, network, file, registry) |
| `sysmon_adapter_ext.rs` | Extended Sysmon event types |
| `etw_adapter.rs` | ETW (Event Tracing for Windows) adapter |
| `evtx_collector.rs` | EVTX file collector |
| `registry_monitor.rs` | Registry change monitoring |
| `service_monitor.rs` | Windows service monitoring |
| `powershell_monitor.rs` | PowerShell script block logging |
| `wmi_monitor.rs` | WMI event monitoring |
| `task_scheduler_monitor.rs` | Scheduled task monitoring |
| `lateral_movement_monitor.rs` | Lateral movement detection (RDP, PsExec, etc.) |
| `log_tamper_monitor.rs` | Log tampering detection |
| `attack_surface.rs` | Attack surface enumeration |
| `defender_adapter.rs` | Windows Defender event parsing |
| `evidence_deref_example.rs` | Example for evidence dereferencing |

### agent-windows/src/sensors/primitives/

Low-level sensor primitives (likely contains raw Windows API wrappers).

---

## crates/workbench/src/ - Attack Documentation Workbench

Document-centric workbench for attack documentation with MITRE ATT&CK integration.

| File | Description |
|------|-------------|
| `lib.rs` | Module exports, MITRE technique types |
| `api.rs` | Workbench API endpoints |
| `document.rs` | Document types and management |
| `session.rs` | Session management |
| `export.rs` | Export functionality |

---

## crates/wi-run-all/src/ - Smoke Test Harness

CI/dev verification tool that validates TRUTH_CONTRACT.md invariants.

| File | Description |
|------|-------------|
| `main.rs` | **SMOKE TEST HARNESS** - starts server, runs API tests, verifies invariants, exits with status code |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All invariants pass |
| 1 | Setup failure (server didn't start) |
| 2 | Run lifecycle failure (invariants 1-2) |
| 3 | Database integrity failure (invariants 3-4) |
| 4 | API contract failure (invariants 5-9) |
| 5 | Code hygiene failure (invariant 10) |

---

## src-tauri/src/ - Tauri Desktop Application

The Tauri-based desktop application wrapper.

### Root Files

| File | Description |
|------|-------------|
| `lib.rs` | Module exports, Tauri app setup |
| `main.rs` | Tauri entrypoint |
| `backend.rs` | Backend communication bridge |
| `supervisor.rs` | **CRITICAL** - Manages lifecycle of capture/locald/server processes |
| `grounded_gates.rs` | Grounded quality gates (evidence-backed assertions) |
| `quality_gates.rs` | Quality gate definitions and checks |
| `health_gates.rs` | Health-based quality gates |
| `missions.rs` | Mission definitions (guided workflows) |
| `mission_commands.rs` | Mission-related Tauri commands |
| `importer.rs` | Telemetry import handling |
| `import_types.rs` | Import type definitions |
| `baseline.rs` | Baseline management |
| `delta_report.rs` | Delta report generation |
| `pipeline_counters.rs` | Pipeline statistics counters |
| `run_metrics.rs` | Run metrics collection |
| `scenario_profiles.rs` | Scenario profile definitions |
| `capability_exhaust.rs` | Capability exhaustion tracking |
| `logging.rs` | Logging setup |
| `port.rs` | Port management |

### src-tauri/src/adapters/ - Import Adapters

Adapters for importing telemetry from various formats.

| File | Description |
|------|-------------|
| `mod.rs` | Adapter module exports |
| `jsonl.rs` | JSONL file import |
| `evtx_json.rs` | EVTX JSON import |
| `plaintext.rs` | Plaintext log import |
| `atomic.rs` | Atomic Red Team import |
| `har.rs` | HAR (HTTP Archive) import |
| `nmap.rs` | Nmap XML import |
| `osquery.rs` | osquery JSON import |
| `suricata.rs` | Suricata EVE JSON import |
| `velociraptor.rs` | Velociraptor artifact import |
| `yara.rs` | YARA scan results import |
| `zap.rs` | OWASP ZAP import |
| `zeek.rs` | Zeek/Bro log import |

### src-tauri/src/scenario_packs/

Pre-built scenario packs for demonstrations.

---

## ui/ - Web UI

Single-page application served by the HTTP server.

| File | Description |
|------|-------------|
| `index.html` | Main HTML shell |
| `app.js` | **MAIN UI** - Single-file JavaScript application with all UI logic |
| `loading.html` | Loading screen shown during startup |

---

## playbooks/windows/ - Detection Playbooks

YAML-based detection rules. Each playbook defines conditions for signal detection.

| File | Description |
|------|-------------|
| `signal_bitsadmin_abuse.yaml` | Detects BITSADMIN abuse (T1197) |
| `signal_certutil_abuse.yaml` | Detects certutil abuse for download/decode |
| `signal_credential_access.yaml` | Detects credential access attempts |
| `signal_defense_evasion.yaml` | Detects defense evasion techniques |
| `signal_discovery_burst.yaml` | Detects discovery command bursts |
| `signal_dll_side_loading.yaml` | Detects DLL side-loading |
| `signal_encoded_powershell.yaml` | Detects encoded PowerShell execution |
| `signal_file_staging.yaml` | Detects file staging for exfiltration |
| `signal_group_membership_change.yaml` | Detects group membership changes |
| `signal_lateral_movement_detection.yaml` | Detects lateral movement |
| `signal_logon_anomaly.yaml` | Detects logon anomalies |
| `signal_log_tampering.yaml` | Detects log tampering |
| `signal_log_tamper_detection.yaml` | Detects log tamper attempts |
| `signal_lolbin_abuse.yaml` | Detects Living-off-the-Land binary abuse |
| `signal_mshta_abuse.yaml` | Detects mshta.exe abuse |
| `signal_net_command_abuse.yaml` | Detects net.exe command abuse |
| `signal_office_child_process.yaml` | Detects suspicious Office child processes |
| `signal_persistence_windows.yaml` | Detects persistence mechanisms |
| `signal_powershell_download.yaml` | Detects PowerShell download cradles |
| `signal_process_injection.yaml` | Detects process injection |
| `signal_registry_persistence.yaml` | Detects registry-based persistence |
| `signal_regsvr32_abuse.yaml` | Detects regsvr32.exe abuse |
| `signal_rundll32_abuse.yaml` | Detects rundll32.exe abuse |
| `signal_schtasks_abuse.yaml` | Detects schtasks.exe abuse |
| `signal_sc_abuse.yaml` | Detects sc.exe abuse |
| `signal_security_tool_disable.yaml` | Detects security tool disabling |
| `signal_service_persistence.yaml` | Detects service-based persistence |
| `signal_task_persistence.yaml` | Detects task-based persistence |
| `signal_wmic_abuse.yaml` | Detects WMIC abuse |
| `signal_wscript_cscript_abuse.yaml` | Detects wscript/cscript abuse |

### playbooks/windows/unsupported/

Playbooks that are not yet production-ready.

---

## scripts/ - Utility Scripts

PowerShell scripts for development and operations.

| File | Description |
|------|-------------|
| `run_stack_windows.ps1` | Starts the full stack (capture + locald + server) |
| `smoke_stack.ps1` | Runs smoke tests against running stack |
| `smoke_explainability.ps1` | Tests explainability API endpoints |
| `verify_explainability.ps1` | Verifies explainability contract |
| `e2e_explainability_verify.ps1` | End-to-end explainability verification |
| `quick_explain_check.ps1` | Quick check of explain endpoints |
| `diagnose_import.ps1` | Diagnoses import issues |
| `eval_windows.ps1` | Evaluates Windows detection |
| `enable_advanced_telemetry.ps1` | Enables advanced telemetry sources |
| `ship.ps1` | Build and package for shipping |

### scripts/archive/

Archived/deprecated scripts.

---

## docs/ - Documentation

| File | Description |
|------|-------------|
| `DATA_FLOW_MAP.md` | Data flow diagram and pipeline documentation |
| `ENDPOINT_CONTRACTS.md` | HTTP endpoint contracts |
| `RELIABILITY_DIAGNOSIS.md` | Reliability audit and fix tracking |
| `ARCHITECTURE_AUDIT.txt` | Architecture audit notes |
| `EXPLAINABILITY_API.md` | Explainability API documentation |
| `EXPLAINABILITY_ENDPOINTS.md` | Explainability endpoint reference |
| `IMPORT_ARCHITECTURE.md` | Import pipeline architecture |
| `IMPORT_PIPELINE_MAP.md` | Import pipeline flow diagram |
| `IMPORT_TROUBLESHOOTING.md` | Import troubleshooting guide |
| `UI_MAP.md` | UI component map |
| `UI_VERIFICATION_CHECKLIST.md` | UI verification test cases |
| `UI_CLICKTHROUGH.md` | UI clickthrough guide |
| `ui_workflow.md` | UI workflow documentation |
| `DEV_ORIGIN.md` | Development origin notes |
| `DEV_UI_DEBUG.md` | UI debugging guide |
| `LICENSING.md` | License documentation |
| `SHIPPING.md` | Shipping process |
| `SMOKE_CHECKLIST_LICENSING.md` | Smoke test checklist for licensing |
| `SYSTEM_STORY_SURFACE_VIEW.md` | System story documentation |
| `facts_windows.md` | Windows facts documentation |
| `playbooks_windows_coverage.md` | Playbook coverage report |
| `MISSION_REAL_TELEMETRY.md` | Real telemetry mission guide |
| `MISSION_UI_WORKFLOW.md` | UI workflow mission |
| `MISSION_WORKFLOW_WALKTHROUGH.md` | Workflow walkthrough |

### docs/archive/

Archived documentation.

### docs/schemas/

| File | Description |
|------|-------------|
| `EXPLAIN_API_SCHEMA.md` | Explainability API schema |
| `quality_report.schema.json` | Quality report JSON schema |

---

## packaging/

| File | Description |
|------|-------------|
| `allowlist.json` | Allowlist for packaging |
| `allowlist.schema.json` | Allowlist JSON schema |
| `validate_allowlist.ps1` | Validates allowlist |

---

## Test Directories

### testdata/imports/

Test data for import testing.

### test_e2e/

End-to-end test data with segments.

### test_telemetry/

Test telemetry data with segments.

---

## Artifacts

### artifacts/

| File | Description |
|------|-------------|
| `smoke_report.json` | Output from smoke test runs |

---

## NOT USED / UNCLEAR Status

Files that may be unused or have unclear purpose:

| File | Status |
|------|--------|
| `crates/server/src/main.rs` | **NOT USED** - Server entrypoint superseded by bin/locint.rs |
| `crates/agent-windows/src/main.rs` | **NOT USED** - Agent entrypoint superseded by capture_windows_rotating.rs binary |
| `CLEANUP_INVENTORY.txt` | Meta/tracking file |
| `STAGE3_SURFACE_VIEW.md` | Unclear purpose - may be outdated |
| `LOCINT_GAP_REPORT.md` | Audit artifact |

---

## Data Flow Summary

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        USER INTERACTION                                  │
│                                                                          │
│   Browser UI (app.js)  ←──HTTP──→  locint.exe (server)                  │
│         │                                │                               │
│         └── Start Run ──────────────────→│                               │
│                                          │                               │
│                                          ▼                               │
│   ┌──────────────────────────────────────────────────────────────┐      │
│   │                     SUPERVISOR                                │      │
│   │                                                               │      │
│   │   ┌─────────────────┐   ┌─────────────────┐                  │      │
│   │   │ capture_windows │   │    edr-locald   │                  │      │
│   │   │   _rotating     │   │                 │                  │      │
│   │   │                 │   │   ┌──────────┐  │                  │      │
│   │   │ ETW ──┐         │   │   │ Pipeline │  │                  │      │
│   │   │ Sysmon├──→JSONL─┼───┼──→│          │  │                  │      │
│   │   │ EvtLog┘         │   │   └────┬─────┘  │                  │      │
│   │   │                 │   │        │        │                  │      │
│   │   └─────────────────┘   │        ▼        │                  │      │
│   │                         │   ┌──────────┐  │                  │      │
│   │                         │   │Orchestr- │  │                  │      │
│   │                         │   │   ator   │  │                  │      │
│   │                         │   └────┬─────┘  │                  │      │
│   │                         │        │        │                  │      │
│   │                         │        ▼        │                  │      │
│   │                         │   ┌──────────┐  │                  │      │
│   │                         │   │ Windows  │  │                  │      │
│   │                         │   │  Engine  │  │                  │      │
│   │                         │   └────┬─────┘  │                  │      │
│   │                         │        │        │                  │      │
│   │                         └────────┼────────┘                  │      │
│   │                                  │                           │      │
│   └──────────────────────────────────┼───────────────────────────┘      │
│                                      │                                   │
│                                      ▼                                   │
│                            ┌─────────────────┐                          │
│                            │  workbench.db   │                          │
│                            │  (signals,      │                          │
│                            │   coverage,     │                          │
│                            │   facts)        │                          │
│                            └────────┬────────┘                          │
│                                     │                                    │
│                                     ▼                                    │
│                            ┌─────────────────┐                          │
│                            │   Report Gen    │                          │
│                            │   (PDF/JSON)    │                          │
│                            └─────────────────┘                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Key Concepts

### TelemetryInput → Event → SignalResult

1. **TelemetryInput**: Raw telemetry from capture agent (ETW/Sysmon/EvtLog)
2. **Event**: Normalized canonical event (platform-agnostic)
3. **SignalResult**: Detected signal with MITRE mapping, severity, evidence

### Evidence Chain

Every signal has an `EvidencePtr` pointing back to source telemetry:
- `stream_id`: Telemetry stream identifier
- `segment_id`: JSONL segment file
- `record_index`: Line number in segment

### YAML Playbooks

Detection logic defined in YAML with:
- `slots`: Conditions to match (event types, field patterns)
- `mitre_technique`: ATT&CK technique ID
- `severity`: Signal severity level
- `confidence`: Detection confidence

---

*Generated: Architecture audit for windows-incident-compiler*

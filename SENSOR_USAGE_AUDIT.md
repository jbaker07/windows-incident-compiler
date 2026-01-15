# SENSOR USAGE AUDIT: windows-incident-compiler

**Generated:** 2026-01-11  
**Scope:** Truthful audit of which sensors actually emit telemetry at runtime  
**Method:** Call chain tracing from `capture_windows_rotating` binary entry point

---

## EXECUTIVE SUMMARY

### Truth Table

| Level | Description | Count |
|-------|-------------|-------|
| **LEVEL 1: Compiled** | Module declared and builds | 28 |
| **LEVEL 2: Invoked at Runtime** | Called from main capture path | 15 |
| **LEVEL 3: Emits Telemetry** | Produces records in segment JSONL | 12 |

### Critical Findings

1. **13 sensor modules are COMPILED but NOT INVOKED** at runtime
2. **3 sensor modules are INVOKED but emit EMPTY vec![]** (stubs)
3. **All adapters (Sysmon, Defender, ETW) are ONLY used in tests**, not runtime path
4. **Monitor modules are ALL STUBS** returning `vec![]`

---

## CALL CHAIN ANALYSIS

### Actual Runtime Path

```
capture_windows_rotating.rs::main()
  └── WindowsEventCapture::poll_and_write()
        ├── sensors::collect::collect_all()
        │     ├── collect_evtx_events()
        │     │     └── wevt_reader::WevtReader::poll()   ✅ EMITS TELEMETRY
        │     │           └── attack_surface::normalize_to_attack_surface()  ✅ EMITS
        │     └── collect_monitors()
        │           ├── registry_monitor::RegistryMonitor::collect()      → vec![] STUB
        │           ├── service_monitor::ServiceMonitor::collect()        → vec![] STUB
        │           ├── task_scheduler_monitor::collect()                 → vec![] STUB
        │           ├── log_tamper_monitor::LogTamperMonitor::collect()   → vec![] STUB
        │           ├── lateral_movement_monitor::collect()               → vec![] STUB
        │           ├── powershell_monitor::PowerShellMonitor::collect()  → vec![] STUB
        │           └── wmi_monitor::WmiMonitor::collect()                → vec![] STUB
        └── primitives::derive_primitive_events()                         ✅ EMITS TELEMETRY
              ├── credential_access::detect_cred_access()                 ✅
              ├── discovery_exec::detect_discovery_exec()                 ✅
              ├── archive_tool_exec::detect_archive_tool_exec()           ✅
              ├── process_injection::detect_process_injection()           ✅
              ├── auth_event::detect_auth_event()                         ✅
              ├── defense_evasion::detect_defense_evasion_*()             ✅
              ├── script_exec::detect_script_exec()                       ✅
              ├── persistence_change::detect_persistence_*()              ✅
              ├── network_connection::detect_network_connection()         ✅
              ├── staging_write::detect_staging_write()                   ✅
              └── composite_detectors::*()                                ✅
```

---

## LEVEL 1-2-3 AUDIT: sensors/ (17 files)

### Core Collection (USED)

| File | Compiled? | Invoked? | Emits? | Evidence |
|------|-----------|----------|--------|----------|
| **mod.rs** | ✅ Yes | ✅ Yes | N/A | Module root, declares all submodules |
| **collect.rs** | ✅ Yes | ✅ Yes | ✅ Yes | Called by `poll_and_write()` at L267 |
| **evtx_collector.rs** | ✅ Yes | ✅ Yes | ⚠️ Partial | Types used; actual poll via `wevt_reader` |
| **attack_surface.rs** | ✅ Yes | ✅ Yes | ✅ Yes | Called at collect.rs:52; parses 11 event types |

### Adapters (COMPILED ONLY - NOT RUNTIME)

| File | Compiled? | Invoked? | Emits? | Evidence |
|------|-----------|----------|--------|----------|
| **sysmon_adapter.rs** | ✅ Yes | ❌ No | ❌ No | Only used in `#[cfg(test)]` blocks |
| **sysmon_adapter_ext.rs** | ✅ Yes | ❌ No | ❌ No | Only used in tests; no runtime caller |
| **defender_adapter.rs** | ✅ Yes | ❌ No | ❌ No | Only used in `#[cfg(test)]` blocks |
| **etw_adapter.rs** | ✅ Yes | ❌ No | ❌ No | Only used in `#[cfg(test)]` blocks |

### Monitors (STUB IMPLEMENTATIONS)

| File | Compiled? | Invoked? | Emits? | Evidence |
|------|-----------|----------|--------|----------|
| **registry_monitor.rs** | ✅ Yes | ✅ Yes | ❌ No | `collect()` returns `vec![]` - comment: "STUB" |
| **service_monitor.rs** | ✅ Yes | ✅ Yes | ❌ No | `collect()` returns `vec![]` - comment: "STUB" |
| **task_scheduler_monitor.rs** | ✅ Yes | ✅ Yes | ❌ No | `collect()` returns `vec![]` - comment: "STUB" |
| **log_tamper_monitor.rs** | ✅ Yes | ✅ Yes | ❌ No | `collect()` returns `vec![]` - comment: "STUB" |
| **lateral_movement_monitor.rs** | ✅ Yes | ✅ Yes | ❌ No | `collect()` returns `vec![]` - comment: "STUB" |
| **powershell_monitor.rs** | ✅ Yes | ✅ Yes | ❌ No | `collect()` returns `vec![]` - comment: "STUB" |
| **wmi_monitor.rs** | ✅ Yes | ✅ Yes | ❌ No | `collect()` returns `vec![]` - comment: "STUB" |

**Note on Monitors:** All 7 monitor modules contain a comment like:
```rust
// For now: [EventType] events are included in wevt_reader polling
// This module is a STUB - all [type] detection flows through main event log reader
```

This means the monitors delegate to `wevt_reader` and `attack_surface.rs` for actual event capture.

---

## LEVEL 1-2-3 AUDIT: sensors/primitives/ (12 files)

All primitives are **INVOKED AT RUNTIME** via `primitives::derive_primitive_events()` called at `capture_windows_rotating.rs:272`.

| File | Compiled? | Invoked? | Emits? | Evidence |
|------|-----------|----------|--------|----------|
| **mod.rs** | ✅ Yes | ✅ Yes | ✅ Yes | `derive_primitive_events()` called at L272 |
| **credential_access.rs** | ✅ Yes | ✅ Yes | ✅ Yes | `detect_cred_access()` at mod.rs:29 |
| **discovery_exec.rs** | ✅ Yes | ✅ Yes | ✅ Yes | `detect_discovery_exec()` at mod.rs:33 |
| **archive_tool_exec.rs** | ✅ Yes | ✅ Yes | ✅ Yes | `detect_archive_tool_exec()` at mod.rs:37 |
| **staging_write.rs** | ✅ Yes | ✅ Yes | ✅ Yes | `detect_staging_write()` at mod.rs:69 |
| **network_connection.rs** | ✅ Yes | ✅ Yes | ✅ Yes | `detect_network_connection()` at mod.rs:92 |
| **persistence_change.rs** | ✅ Yes | ✅ Yes | ✅ Yes | `detect_persistence_*()` at mod.rs:73,127,136 |
| **defense_evasion.rs** | ✅ Yes | ✅ Yes | ✅ Yes | `detect_defense_evasion_*()` at mod.rs:50,77,148,152 |
| **process_injection.rs** | ✅ Yes | ✅ Yes | ✅ Yes | `detect_process_injection*()` at mod.rs:41,109 |
| **auth_event.rs** | ✅ Yes | ✅ Yes | ✅ Yes | `detect_auth_event*()` at mod.rs:45,119 |
| **script_exec.rs** | ✅ Yes | ✅ Yes | ✅ Yes | `detect_script_exec()` + `detect_lolbin_exec()` at mod.rs:54,58 |
| **composite_detectors.rs** | ✅ Yes | ✅ Yes | ✅ Yes | 4 detectors called at mod.rs:165-188 |

---

## TELEMETRY OUTPUT VERIFICATION

### What Actually Ends Up in Segments

The capture binary writes events to `segments/*.jsonl`. Events come from:

| Source | Output Path | Event Tags |
|--------|-------------|------------|
| `wevt_reader` | segments/evtx_NNNNNN.jsonl | `["windows", "event_log", "<channel>"]` |
| `attack_surface` | segments/evtx_NNNNNN.jsonl | `["windows", "<event_kind>"]` |
| `primitives` | segments/evtx_NNNNNN.jsonl | `["<canonical_type>"]` + inherited |

### Canonical Primitive Types Emitted

| Tag | Detector | Description |
|-----|----------|-------------|
| `credential_access` | credential_access.rs | LSASS access, procdump, mimikatz |
| `discovery` | discovery_exec.rs | tasklist, wmic, ipconfig, whoami |
| `persistence_change` | persistence_change.rs | Registry Run keys, services, tasks |
| `defense_evasion` | defense_evasion.rs | Log clear, audit disable, file delete |
| `process_injection` | process_injection.rs | CreateRemoteThread, ProcessAccess |
| `auth_event` | auth_event.rs | 4624, 4625, Kerberos, NTLM |
| `script_exec` | script_exec.rs | PowerShell, cmd, wscript, mshta |
| `network_connection` | network_connection.rs | Sysmon 3, Security 5156 |
| `exfiltration` (archive) | archive_tool_exec.rs | 7z, tar, Compress-Archive |
| `exfiltration` (staging) | staging_write.rs | %TEMP%, Downloads staging |

---

## DB FILES AND LOCATIONS (CORRECTED)

### CORRECTION to REPO_FILE_AUDIT.md

The previous audit incorrectly listed `signals.db` as a separate file. Here is the **truthful** breakdown:

| DB File | Creator | Location | Schema | Status |
|---------|---------|----------|--------|--------|
| **workbench.db** | edr-server | `%LOCALAPPDATA%/attack-workbench/workbench.db` | documents, sessions | ✅ ACTIVE |
| **workbench.db** | edr-locald | `$EDR_TELEMETRY_ROOT/workbench.db` | signals, signal_explanations, coverage_rollup, locald_checkpoint | ✅ ACTIVE |
| **analysis.db** | (legacy) | `$run_dir/analysis.db` | Same as workbench.db | ⚠️ FALLBACK ONLY |

### Evidence for `workbench.db` as sole per-run DB

```rust
// crates/locald/src/main.rs:249
let db_path = telemetry_root.join("workbench.db");
let db = match Connection::open(&db_path) {
```

### Evidence for `analysis.db` fallback

```rust
// crates/server/src/run_coverage.rs:184-188
// Try workbench.db first (used by current locald), then analysis.db (legacy)
let workbench_path = run_dir.join("workbench.db");
let analysis_path = run_dir.join("analysis.db");

let db_path = if workbench_path.exists() {
    workbench_path
} else if analysis_path.exists() {
    analysis_path
```

### `signals.db` Reference in run_control.rs

```rust
// crates/server/src/run_control.rs:401
count_signals_in_db(&dir.join("signals.db"))
```

**This is a BUG** - the function looks for `signals.db` but locald writes to `workbench.db`. This path may never find signals if the file doesn't exist.

---

## SENSORS NOT INVOKED AT RUNTIME (Hide from Marketing/UI)

These modules compile and export types but are **not called during actual capture**:

| Module | Reason | Recommendation |
|--------|--------|----------------|
| `sysmon_adapter.rs` | Test-only; real Sysmon events via wevt_reader | Keep for tests; don't advertise |
| `sysmon_adapter_ext.rs` | Test-only | Keep for tests; don't advertise |
| `defender_adapter.rs` | Test-only; Defender events via wevt_reader | Keep for tests; don't advertise |
| `etw_adapter.rs` | Test-only; ETW not implemented | Keep; feature-gated future work |

---

## STUB MONITORS (Invoked but Return Empty)

These modules are **invoked** by `collect_monitors()` but always return `vec![]`:

| Module | Comment in Code | Actual Detection Via |
|--------|-----------------|----------------------|
| `registry_monitor.rs` | "Sysmon events included in wevt_reader" | attack_surface.rs Sysmon 12-14 |
| `service_monitor.rs` | "Service events included in wevt_reader" | attack_surface.rs System 7045, Security 4697 |
| `task_scheduler_monitor.rs` | "Task events included in wevt_reader" | attack_surface.rs Security 4698/4702 |
| `log_tamper_monitor.rs` | "Log tamper events detected by wevt_reader" | attack_surface.rs Security 1102 |
| `lateral_movement_monitor.rs` | "Logon events included in wevt_reader" | attack_surface.rs Security 4624 |
| `powershell_monitor.rs` | "PowerShell events included in wevt_reader" | attack_surface.rs PowerShell channel |
| `wmi_monitor.rs` | "WMI events included in wevt_reader" | attack_surface.rs Sysmon 19-21 |

**Recommendation:** These modules are architectural placeholders. The actual detection happens in:
1. `wevt_reader.rs` - Reads events from Windows Event Log
2. `attack_surface.rs` - Normalizes to canonical event kinds
3. `primitives/` - Derives higher-level detections

---

## SUMMARY: ACTUAL TELEMETRY EMITTERS

### Sensors That Actually Produce Segment Records

| Component | Emits? | Output |
|-----------|--------|--------|
| `wevt_reader.rs` | ✅ Yes | Raw Windows events with channel, event_id, XML |
| `attack_surface.rs` | ✅ Yes | Normalized attack surface events (proc_exec, log_clear, etc.) |
| `primitives/credential_access.rs` | ✅ Yes | LSASS/credential harvesting events |
| `primitives/discovery_exec.rs` | ✅ Yes | Reconnaissance command events |
| `primitives/archive_tool_exec.rs` | ✅ Yes | Data staging/compression events |
| `primitives/staging_write.rs` | ✅ Yes | File staging write events |
| `primitives/network_connection.rs` | ✅ Yes | Network connection events |
| `primitives/persistence_change.rs` | ✅ Yes | Persistence mechanism events |
| `primitives/defense_evasion.rs` | ✅ Yes | Anti-forensics events |
| `primitives/process_injection.rs` | ✅ Yes | Injection detection events |
| `primitives/auth_event.rs` | ✅ Yes | Authentication events |
| `primitives/script_exec.rs` | ✅ Yes | Script/LOLBin execution events |
| `primitives/composite_detectors.rs` | ✅ Yes | Multi-signal composite detections |

### Sensors That Do NOT Produce Records

| Component | Status | Reason |
|-----------|--------|--------|
| `sysmon_adapter.rs` | ❌ Test-only | Not called at runtime |
| `sysmon_adapter_ext.rs` | ❌ Test-only | Not called at runtime |
| `defender_adapter.rs` | ❌ Test-only | Not called at runtime |
| `etw_adapter.rs` | ❌ Test-only | Not called at runtime |
| `registry_monitor.rs` | ❌ Stub | Returns vec![] |
| `service_monitor.rs` | ❌ Stub | Returns vec![] |
| `task_scheduler_monitor.rs` | ❌ Stub | Returns vec![] |
| `log_tamper_monitor.rs` | ❌ Stub | Returns vec![] |
| `lateral_movement_monitor.rs` | ❌ Stub | Returns vec![] |
| `powershell_monitor.rs` | ❌ Stub | Returns vec![] |
| `wmi_monitor.rs` | ❌ Stub | Returns vec![] |

---

## CORRECTIONS TO REPO_FILE_AUDIT.md

### Section 5) DB / STORAGE - CORRECTED

Replace the previous DB section with:

| DB | Used By | Location | Status |
|----|---------|----------|--------|
| workbench.db | edr-server | `%LOCALAPPDATA%/attack-workbench/` | ✅ Active (sessions, documents) |
| workbench.db | edr-locald | `$EDR_TELEMETRY_ROOT/` (per-run) | ✅ Active (signals, explanations, coverage) |
| analysis.db | edr-server | `$run_dir/` (legacy fallback) | ⚠️ Fallback only (not created by current code) |
| signals.db | (bug reference) | run_control.rs:401 | ❌ **BUG** - file never created |

### Bug to Fix

`crates/server/src/run_control.rs:401` references `signals.db` but locald creates `workbench.db`. This should be fixed:

```rust
// BEFORE (bug):
count_signals_in_db(&dir.join("signals.db"))

// AFTER (correct):
count_signals_in_db(&dir.join("workbench.db"))
```

---

**END OF SENSOR USAGE AUDIT**

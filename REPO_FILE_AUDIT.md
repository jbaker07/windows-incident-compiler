# REPO FILE AUDIT: windows-incident-compiler

**Generated:** 2026-01-11  
**Scope:** Complete file-by-file inventory with evidence-backed usage verification  
**Method:** grep/rg module tracing, Cargo.toml analysis, runtime path verification

---

## A) HIGH-LEVEL MAP: CRATES AND BINARIES

### Workspace Members (from root Cargo.toml)

| Crate | Path | Purpose |
|-------|------|---------|
| `edr-core` | crates/core | Shared types: Event, EvidencePtr, License, Severity, Narrative, Diff |
| `workbench` | crates/workbench | Document editing, session management, export |
| `edr-server` | crates/server | HTTP API server, PDF reports, golden bundles |
| `edr-locald` | crates/locald | Signal detection daemon, playbook engine, hypothesis system |
| `agent-windows` | crates/agent-windows | Windows telemetry capture via WEVTAPI/Sysmon/ETW |
| `wi-run-all` | crates/wi-run-all | CI/smoke test harness |

### Binary Entrypoints

| Binary | Crate | Main Path | Purpose |
|--------|-------|-----------|---------|
| `edr-server` | edr-server | crates/server/src/main.rs | **PRODUCT** - HTTP API server |
| `golden-cli` | edr-server | crates/server/src/bin/golden_cli.rs | Golden bundle verification CLI |
| `license_gen` | edr-server | crates/server/src/bin/license_gen.rs | License file generator (internal) |
| `edr-locald` | edr-locald | crates/locald/src/main.rs | **PRODUCT** - Detection daemon |
| `proof_run` | edr-locald | crates/locald/src/bin/proof_run.rs | CI verification harness |
| `metrics_run` | edr-locald | crates/locald/src/bin/metrics_run.rs | E2E metrics generation |
| `explain_harness` | edr-locald | crates/locald/src/bin/explain_harness.rs | ExplanationBundle validator |
| `capture_windows_rotating` | agent-windows | crates/agent-windows/src/bin/capture_windows_rotating.rs | **PRODUCT** - Windows event capture |
| `wevt_smoke` | agent-windows | crates/agent-windows/src/bin/wevt_smoke.rs | WEVTAPI diagnostic tool |
| `wi_run_all` | wi-run-all | crates/wi-run-all/src/main.rs | **CI** - Smoke test harness |

### Standalone Crate (Not in Workspace)

| Crate | Path | Purpose |
|-------|------|---------|
| `edr-desktop` | src-tauri | Tauri desktop app with Mission Workflow Harness |

---

## B) FILE INVENTORY BY DIRECTORY

### crates/server/src/ (21 files)

| Path | Type | Purpose | Used? | Used By | Evidence | Action |
|------|------|---------|-------|---------|----------|--------|
| lib.rs | Rust | Library entry point with 8 public modules | Yes | Crate library | Cargo.toml `[lib]` | Keep |
| main.rs | Rust | HTTP server with 2770 lines, all API routes | Yes | `edr-server` binary | Cargo.toml `[[bin]]` | Keep |
| bundle_exchange.rs | Rust | Bundle export/import with SHA-256, ZIP safety | Yes | lib + main | `pub mod` in lib.rs | Keep |
| capture_control.rs | Rust | Capture profiles, rate limiting, backpressure | Yes | main.rs only | `mod` in main.rs | Keep |
| db.rs | Rust | SQLite persistence (signals, runs, documents) | Yes | main.rs only | `mod` in main.rs | Keep |
| diagnostics.rs | Rust | Self-check v2 with structured remediation | Yes | main.rs only | `mod` in main.rs | Keep |
| diff_api.rs | Rust | Pro: `/api/diff` snapshot comparison | Yes | main.rs only | `mod` in main.rs | Keep |
| explain_normalize.rs | Rust | Normalize legacy signals to ExplainResponse | Yes | main.rs only | `mod` in main.rs | Keep |
| golden_bundle.rs | Rust | Golden bundle verification, deterministic fixtures | Yes | lib + main | `pub mod` in lib.rs | Keep |
| health.rs | Rust | `/health` endpoint with build info, verdicts | Yes | lib + main | `pub mod` in lib.rs | Keep |
| integration_api.rs | Rust | `/api/integrations` REST endpoints | Yes | lib + main | `pub mod` in lib.rs | Keep |
| license_api.rs | Rust | License status and management API | Yes | main.rs only | `mod` in main.rs | Keep |
| probe.rs | Rust | Harmless probe runner for pipeline testing | Yes | main.rs only | `mod` in main.rs | Keep |
| query_isolation.rs | Rust | Namespace isolation for imported vs live data | Yes | lib + main | `pub mod` in lib.rs | Keep |
| report.rs | Rust | PDF report generation with genpdf | Yes | lib + main | `pub mod` in lib.rs | Keep |
| run_control.rs | Rust | RunController: start/stop capture/locald | Yes | main.rs only | `mod` in main.rs | Keep |
| run_coverage.rs | Rust | `/api/runs/:id/coverage` API | Yes | main.rs only | `mod` in main.rs | Keep |
| support_bundle.rs | Rust | Support pack ZIP generation | Yes | lib + main | `pub mod` in lib.rs | Keep |
| verification_pack.rs | Rust | First-run sample data generation | Yes | main.rs only | `mod` in main.rs | Keep |
| write_isolation.rs | Rust | Bundle write sandboxing | Yes | lib + main | `pub mod` in lib.rs | Keep |
| bin/golden_cli.rs | Rust | Golden bundle CLI | Yes | `golden-cli` binary | Cargo.toml `[[bin]]` | Keep |
| bin/license_gen.rs | Rust | License generator | Yes | `license_gen` binary | Cargo.toml `[[bin]]` | Keep |

### crates/locald/src/ (71 files total)

#### Root Files (17 files)

| Path | Type | Purpose | Used? | Evidence | Action |
|------|------|---------|-------|----------|--------|
| lib.rs | Rust | Library entry point, declares all modules | Yes | Crate root | Keep |
| main.rs | Rust | edr-locald daemon entry point | Yes | Cargo.toml `[[bin]]` | Keep |
| pipeline.rs | Rust | Event processing pipeline | Yes | `pub mod` in lib.rs | Keep |
| signal_orchestrator.rs | Rust | Routes events through signal engines | Yes | `pub mod` in lib.rs | Keep |
| signal_result.rs | Rust | SignalResult, EvidenceRef types | Yes | `pub mod` in lib.rs | Keep |
| playbook_loader.rs | Rust | Platform-scoped playbook loading | Yes | `pub mod` in lib.rs | Keep |
| playbook_manager.rs | Rust | Central playbook YAML loading (~1180 lines) | Yes | `pub mod` in lib.rs | Keep |
| slot_matcher.rs | Rust | Playbook slot matching engine | Yes | `pub mod` in lib.rs | Keep |
| slot_matcher_tests.rs | Rust | Slot matcher tests | Yes | `#[cfg(test)]` in lib.rs | Keep |
| signal_persistence.rs | Rust | JSONL signal persistence | Yes | `pub mod` in lib.rs | Keep |
| evidence_deref.rs | Rust | Evidence dereference helper | Yes | `pub mod` in lib.rs | Keep |
| explanation_builder.rs | Rust | ExplanationBundle builder | Yes | `pub mod` in lib.rs | Keep |
| narrative_builder.rs | Rust | NarrativeDoc builder | Yes | `pub mod` in lib.rs | Keep |
| safety.rs | Rust | Path/namespace/ZIP safety | Yes | `pub mod` in lib.rs | Keep |
| hypothesis_controller.rs | Rust | Incident compiler runtime | Yes | `pub mod` in lib.rs | Keep |
| e2e_playbook_test.rs | Rust | E2E playbook integration tests | Yes | `#[cfg(test)]` in lib.rs | Keep |
| **edr_locald.rs** | Rust | **LEGACY daemon code** | **No** | Commented out in lib.rs | **Remove** |

#### bin/ (3 files)

| Path | Type | Purpose | Used? | Evidence | Action |
|------|------|---------|-------|----------|--------|
| bin/proof_run.rs | Rust | CI verification harness | Yes | Cargo.toml `[[bin]]` | Keep |
| bin/metrics_run.rs | Rust | Metrics generation | Yes | Cargo.toml `[[bin]]` | Keep |
| bin/explain_harness.rs | Rust | Explanation validator | Yes | Cargo.toml `[[bin]]` | Keep |

#### baseline/ (5 files) - All Used

| Path | Purpose | Action |
|------|---------|--------|
| baseline/mod.rs | Module root | Keep |
| baseline/types.rs | HostBaseline type | Keep |
| baseline/baseline_query.rs | Query baselines | Keep |
| baseline/baseline_store.rs | Persist baselines | Keep |
| baseline/baseline_update.rs | Update baselines | Keep |

#### canonical/ (3 files) - **ALL ORPHANED**

| Path | Type | Purpose | Used? | Evidence | Action |
|------|------|---------|-------|----------|--------|
| **canonical/event.rs** | Rust | OS-agnostic event model | **No** | No mod.rs, not declared | **Remove** |
| **canonical/fact.rs** | Rust | Fact model (duplicate) | **No** | Superseded by hypothesis/canonical_fact.rs | **Remove** |
| **canonical/scope.rs** | Rust | Scope keys | **No** | Superseded by hypothesis/scope_keys.rs | **Remove** |

#### evidence/ (5 files) - All Used

| Path | Purpose | Action |
|------|---------|--------|
| evidence/mod.rs | Module root | Keep |
| evidence/evidence_ptr.rs | EvidencePtr stable refs | Keep |
| evidence/evidence_store.rs | Evidence storage | Keep |
| evidence/deref.rs | Evidence dereference | Keep |
| evidence/path_safety.rs | Path validation | Keep |

#### hypothesis/ (24 files) - All Used

All files in `hypothesis/` are declared via `pub mod hypothesis` in lib.rs and the submodule's mod.rs. Keep all.

#### integrations/ (7 files) - All Used

All files in `integrations/` are declared via `pub mod integrations` in lib.rs. Keep all.

#### os/ (10 files)

| Path | Type | Purpose | Used? | Evidence | Action |
|------|------|---------|-------|----------|--------|
| os/mod.rs | Rust | OS detection module root | Yes | `pub mod os` in lib.rs | Keep |
| os/linux/mod.rs | Rust | Linux module root | Yes | Declared in os/mod.rs | Keep |
| os/linux/signal_engine.rs | Rust | Linux detection engine | Yes | Declared in linux/mod.rs | Keep |
| os/macos/mod.rs | Rust | macOS module root | Yes | Declared in os/mod.rs | Keep |
| os/macos/signal_engine.rs | Rust | macOS detection engine | Yes | Declared in macos/mod.rs | Keep |
| os/windows/mod.rs | Rust | Windows module root | Yes | Declared in os/mod.rs | Keep |
| os/windows/signal_engine.rs | Rust | Windows detection | Yes | Declared in windows/mod.rs | Keep |
| os/windows/fact_extractor.rs | Rust | Fact extraction | Yes | Declared in windows/mod.rs | Keep |
| os/windows/playbooks.rs | Rust | Windows playbook defs | Yes | Declared in windows/mod.rs | Keep |
| os/windows/signals_windows.rs | Rust | Windows patterns | Yes | Declared in windows/mod.rs | Keep |
| **os/windows/signal_result.rs** | Rust | **DUPLICATE** | **No** | Not declared in windows/mod.rs | **Remove** |

#### scoring/ (9 files)

| Path | Type | Purpose | Used? | Evidence | Action |
|------|------|---------|-------|----------|--------|
| scoring/mod.rs | Rust | Module root | Yes | `pub mod scoring` in lib.rs | Keep |
| scoring/scored_signal.rs | Rust | ScoredSignal type | Yes | Declared in mod.rs | Keep |
| scoring/scoring_engine.rs | Rust | Orchestrates scoring | Yes | Declared in mod.rs | Keep |
| scoring/mahalanobis.rs | Rust | Distance-based scoring | Yes | Declared in mod.rs | Keep |
| scoring/elliptic_envelope_lite.rs | Rust | Anomaly detection | Yes | Declared in mod.rs | Keep |
| scoring/krim_lite.rs | Rust | Entropy-based scoring | Yes | Declared in mod.rs | Keep |
| **scoring/elliptic_envelope.rs** | Rust | **OLD VERSION** | **No** | Not declared, replaced by _lite | **Remove** |
| **scoring/engine.rs** | Rust | **OLD VERSION** | **No** | Not declared, replaced by scoring_engine.rs | **Remove** |
| **scoring/krim.rs** | Rust | **OLD VERSION** | **No** | Not declared, replaced by _lite | **Remove** |

### crates/core/src/ (18 files) - All Used

All files declared in lib.rs. No orphans. Keep all.

### crates/workbench/src/ (6 files)

| Path | Type | Purpose | Used? | Evidence | Action |
|------|------|---------|-------|----------|--------|
| lib.rs | Rust | Crate entry point | Yes | Crate root | Keep |
| api.rs | Rust | REST types | Yes | `pub mod` in lib.rs | Keep |
| document.rs | Rust | Document model | Yes | `pub mod` in lib.rs | Keep |
| export.rs | Rust | Export functionality | Yes | `pub mod` in lib.rs | Keep |
| session.rs | Rust | Session management | Yes | `pub mod` in lib.rs | Keep |
| **mod.rs** | Rust | **DUPLICATE** | **No** | Orphan - lib.rs is entry point | **Remove** |

### crates/agent-windows/src/ (43 files)

#### Root (12 files) - All Used

All files declared in lib.rs. Keep all.

#### bin/ (2 files) - All Used

| Path | Purpose | Action |
|------|---------|--------|
| bin/capture_windows_rotating.rs | Capture binary | Keep |
| bin/wevt_smoke.rs | WEVTAPI diagnostic | Keep |

#### sensors/ (17 files)

| Path | Type | Purpose | Used? | Evidence | Action |
|------|------|---------|-------|----------|--------|
| sensors/mod.rs | Rust | Sensor module root | Yes | `pub mod sensors` in lib.rs | Keep |
| sensors/attack_surface.rs | Rust | Event normalization | Yes | Declared in mod.rs | Keep |
| sensors/collect.rs | Rust | Collection orchestration | Yes | Declared in mod.rs | Keep |
| sensors/defender_adapter.rs | Rust | Defender adapter | Yes | Declared in mod.rs | Keep |
| sensors/etw_adapter.rs | Rust | ETW adapter | Yes | Declared in mod.rs | Keep |
| sensors/evtx_collector.rs | Rust | EVTX collection types | Yes | Declared in mod.rs | Keep |
| sensors/lateral_movement_monitor.rs | Rust | Lateral movement (stub) | Yes | Declared in mod.rs | Keep |
| sensors/log_tamper_monitor.rs | Rust | Log tampering (stub) | Yes | Declared in mod.rs | Keep |
| sensors/powershell_monitor.rs | Rust | PowerShell (stub) | Yes | Declared in mod.rs | Keep |
| sensors/registry_monitor.rs | Rust | Registry (stub) | Yes | Declared in mod.rs | Keep |
| sensors/service_monitor.rs | Rust | Service (stub) | Yes | Declared in mod.rs | Keep |
| sensors/sysmon_adapter.rs | Rust | Sysmon adapter | Yes | Declared in mod.rs | Keep |
| sensors/sysmon_adapter_ext.rs | Rust | Extended Sysmon | Yes | Declared in mod.rs | Keep |
| sensors/task_scheduler_monitor.rs | Rust | Task scheduler (stub) | Yes | Declared in mod.rs | Keep |
| sensors/wmi_monitor.rs | Rust | WMI (stub) | Yes | Declared in mod.rs | Keep |
| **sensors/evidence_deref_example.rs** | Rust | **ORPHANED** | **No** | Not declared, dead test code | **Remove** |

#### sensors/primitives/ (12 files) - All Used

All files declared in primitives/mod.rs. Keep all.

### crates/wi-run-all/src/ (1 file)

| Path | Type | Purpose | Used? | Evidence | Action |
|------|------|---------|-------|----------|--------|
| main.rs | Rust | Smoke test harness (946 lines) | Yes | Cargo.toml `[[bin]]` | Keep |

---

## C) SPECIAL ATTENTION SECTIONS

### 1) DUPLICATES

#### Root locald/ vs crates/locald/src/ - **CRITICAL**

The `locald/` folder at workspace root is **DEPRECATED** and **FULLY ORPHANED**.

| Finding | Details |
|---------|---------|
| Evidence | `locald/DEPRECATED.md` states folder is deprecated |
| `#[path]` hacks | None remain - already removed from lib.rs |
| Compilation | `edr-locald` compiles without any reference to root locald/ |
| File comparison | All 24 `hypothesis/` files are byte-identical; rest are older versions |

**Files in root locald/ (49 total):**

| Subdirectory | Status | Action |
|--------------|--------|--------|
| DEPRECATED.md | Marker doc | Remove (with folder) |
| mod.rs | Self-referential orphan | Remove |
| edr_locald.rs | Legacy daemon (older version) | Remove |
| evidence_deref_example.rs | Example code | Remove |
| playbook_loader.rs | Older version | Remove |
| signal_orchestrator.rs | Older version | Remove |
| signal_persistence.rs | Older version | Remove |
| baseline/ (5 files) | All older versions | Remove |
| hypothesis/ (24 files) | All **IDENTICAL** to crates/locald/src/hypothesis/ | Remove |
| os/ (7 files) | Stubs + older versions | Remove |
| scoring/ (6 files) | All older versions | Remove |

**Safe Removal Command:**
```powershell
Remove-Item -Recurse -Force "c:\Users\Jermaine B\src\windows-incident-compiler\locald"
```

### 2) DEAD CODE / LEGACY

| File | Type | Evidence | Safe to Remove? |
|------|------|----------|-----------------|
| crates/locald/src/edr_locald.rs | Legacy daemon | Commented out in lib.rs | ✅ Yes |
| crates/locald/src/canonical/ (3 files) | Orphan directory | No mod.rs, no declaration | ✅ Yes |
| crates/locald/src/scoring/elliptic_envelope.rs | Old version | Replaced by _lite variant | ✅ Yes |
| crates/locald/src/scoring/engine.rs | Old version | Replaced by scoring_engine.rs | ✅ Yes |
| crates/locald/src/scoring/krim.rs | Old version | Replaced by _lite variant | ✅ Yes |
| crates/locald/src/os/windows/signal_result.rs | Duplicate | Not declared in mod.rs | ✅ Yes |
| crates/workbench/src/mod.rs | Orphan | lib.rs is entry point | ✅ Yes |
| crates/agent-windows/src/sensors/evidence_deref_example.rs | Dead test | Not declared anywhere | ✅ Yes |

**Total dead files: 13**

### 3) PLAYBOOKS

#### playbooks/windows/ (30 files)

| Status | Count | Description |
|--------|-------|-------------|
| ✅ **LOADS_AND_FIRES** | 18 | Has `input_facts` with fact_type AND rules with fact_type conditions |
| ⚠️ **LOADS_VIA_TAG_FALLBACK** | 6 | Uses `tag:` conditions mapped via `tag_to_slot_predicate()` |
| ⚠️ **LOADS_VIA_DETECTION** | 1 | Uses `detection:` block with signal types |
| ⚠️ **LOADS_BUT_INERT** | 2 | Has detection block but no rules/slots |
| ⚠️ **PARTIALLY_INERT** | 2 | Mixed slot sources with some unmapped conditions |
| ⏸️ **SKIPPED** | 1 | signal_lolbin_abuse.yaml - uses `detection.signal` singular schema |

**Detailed Playbook Status:**

| Playbook | Status | Reason |
|----------|--------|--------|
| signal_bitsadmin_abuse.yaml | ✅ Fires | fact_type: Exec |
| signal_certutil_abuse.yaml | ✅ Fires | fact_type: Exec |
| signal_credential_access.yaml | ✅ Fires | fact_type: Exec |
| signal_defense_evasion.yaml | ✅ Fires | fact_type: PersistArtifact |
| signal_discovery_burst.yaml | ✅ Fires | fact_type: Exec |
| signal_dll_side_loading.yaml | ✅ Fires | fact_type: Exec |
| signal_encoded_powershell.yaml | ✅ Fires | fact_type: Exec |
| signal_file_staging.yaml | ✅ Fires | fact_type: FileOp |
| signal_group_membership_change.yaml | ⚠️ Tag fallback | tag: admin_group → Auth |
| signal_lateral_movement_detection.yaml | ⚠️ Tag fallback | tag: psexec → Auth |
| signal_lolbin_abuse.yaml | ⏸️ **SKIPPED** | Uses different schema |
| signal_log_tamper_detection.yaml | ⚠️ Tag fallback | tag: log_clear → Exec |
| signal_log_tampering.yaml | ⚠️ Tag fallback | tag: log_tamper → Exec |
| signal_logon_anomaly.yaml | ✅ Fires | fact_type: AuthEvent |
| signal_mshta_abuse.yaml | ✅ Fires | fact_type: Exec |
| signal_net_command_abuse.yaml | ✅ Fires | fact_type: Exec |
| signal_office_child_process.yaml | ✅ Fires | fact_type: Exec |
| signal_persistence_windows.yaml | ⚠️ Detection block only | **INERT** - no slots |
| signal_powershell_download.yaml | ✅ Fires | fact_type: Exec |
| signal_process_injection.yaml | ⚠️ Partially inert | Mixed sources |
| signal_registry_persistence.yaml | ⚠️ Tag fallback | tag: registry → PersistArtifact |
| signal_regsvr32_abuse.yaml | ✅ Fires | fact_type: Exec |
| signal_rundll32_abuse.yaml | ✅ Fires | fact_type: Exec |
| signal_schtasks_abuse.yaml | ✅ Fires | fact_type: Exec |
| signal_sc_abuse.yaml | ✅ Fires | fact_type: Exec |
| signal_security_tool_disable.yaml | ⚠️ Detection block only | **INERT** - no rules |
| signal_service_persistence.yaml | ⚠️ Tag fallback | tag: service_install → PersistArtifact |
| signal_task_persistence.yaml | ⚠️ Tag fallback | tag: task_create → PersistArtifact |
| signal_wmic_abuse.yaml | ✅ Fires | fact_type: Exec |
| signal_wscript_cscript_abuse.yaml | ✅ Fires | fact_type: Exec |

#### playbooks/windows/unsupported/ (1 file)

| File | Purpose | Action |
|------|---------|--------|
| README.md | Documents why tag-based playbooks were quarantined (now outdated) | Keep as documentation |

#### playbooks/import/ (14 files)

| Status | Description |
|--------|-------------|
| ⏸️ **NOT_FOR_LOCALD** | All 14 files use different architecture (trigger/correlation/signal_template) designed for UI import pipeline, NOT PlaybookManager |

These playbooks work with the Tauri desktop import workflow documented in `docs/IMPORT_ARCHITECTURE.md`.

### 4) UI FILES

| Path | Type | Purpose | Served? | Evidence |
|------|------|---------|---------|----------|
| ui/index.html | HTML | Main UI (956 lines) | ✅ Yes | ServeDir at `/ui` serves ui/ directory |
| ui/app.js | JS | UI application (2520 lines) | ✅ Yes | Referenced by index.html |
| ui/loading.html | HTML | Tauri loading screen (147 lines) | ⚠️ Tauri only | Used by src-tauri, not edr-server |

**Serving Evidence:**
```rust
// crates/server/src/main.rs:2612-2629
let ui_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent().unwrap().parent().unwrap().join("ui");
// ...
.nest_service("/ui", ServeDir::new(&ui_dir))
```

**Cache-bust behavior:** BUILD_STAMP in both index.html and app.js: `2026-01-10T23:00:00Z_SHIP`

**Unused UI files:** None detected.

### 5) DB / STORAGE

#### Schema Locations

| Component | Location | Purpose |
|-----------|----------|---------|
| Server DB schema | crates/server/src/db.rs | workbench.db: signals, runs, documents |
| Locald signals schema | crates/locald/src/main.rs | signals table with run_id, signal_type, evidence, etc. |
| Hypothesis storage | crates/locald/src/hypothesis/storage.rs | Incident/hypothesis persistence |

#### Database Files

| DB | Used By | Location | Status |
|----|---------|----------|--------|
| workbench.db | edr-server | `%APPDATA%/edr-workbench/` | ✅ Active |
| signals.db | edr-locald | Per-run directory | ✅ Active |
| analysis.db | (none) | Legacy reference only | ❌ **DEAD** |

**analysis.db references:** Only in old documentation, not in current code paths.

---

## D) src-tauri/ AUDIT (Standalone Crate)

### Module Status

| Category | Count | Details |
|----------|-------|---------|
| Declared in lib.rs | 15 | All core modules |
| Orphaned | 1 | backend.rs (superseded by supervisor.rs) |
| adapters/ | 13 | **NOT WIRED** - complete implementations but no `pub mod adapters` |

### adapters/ - Not Integrated

The entire `src-tauri/src/adapters/` directory (13 files) is **complete but not wired**:

| File | Purpose |
|------|---------|
| mod.rs | Adapter trait, file type detection |
| atomic.rs | Atomic Red Team results |
| evtx_json.rs | Windows Event Logs |
| har.rs | HTTP Archive |
| jsonl.rs | JSON Lines |
| nmap.rs | Nmap XML |
| osquery.rs | osquery JSON |
| plaintext.rs | Text logs |
| suricata.rs | Suricata EVE |
| velociraptor.rs | Velociraptor |
| yara.rs | YARA results |
| zap.rs | OWASP ZAP |
| zeek.rs | Zeek/Bro logs |

**Status:** `import_types.rs` defines `FileKind` variants for all adapters, but `importer.rs` doesn't invoke them. Planned but incomplete integration.

**Recommended Action:** Either wire adapters into import flow or document as planned/future.

---

## E) SUMMARY: REMOVAL CANDIDATES

### Confirmed Dead Files (16 total)

| Path | Reason |
|------|--------|
| **locald/** (entire directory, ~49 files) | Deprecated, no `#[path]` references remain |
| crates/locald/src/edr_locald.rs | Commented out in lib.rs |
| crates/locald/src/canonical/event.rs | No mod.rs, not declared |
| crates/locald/src/canonical/fact.rs | Superseded |
| crates/locald/src/canonical/scope.rs | Superseded |
| crates/locald/src/scoring/elliptic_envelope.rs | Replaced by _lite |
| crates/locald/src/scoring/engine.rs | Replaced |
| crates/locald/src/scoring/krim.rs | Replaced by _lite |
| crates/locald/src/os/windows/signal_result.rs | Duplicate, not declared |
| crates/workbench/src/mod.rs | Orphan |
| crates/agent-windows/src/sensors/evidence_deref_example.rs | Dead test code |

### Uncertain Files (14 total)

| Path | Reason |
|------|--------|
| src-tauri/src/backend.rs | May be superseded by supervisor.rs |
| src-tauri/src/adapters/ (13 files) | Complete but not wired |

---

## F) VERIFICATION COMMANDS

### Verify No Root locald/ References
```bash
rg -l "locald/" --glob '!locald/**' --glob '!target/**' | head -20
rg '#\[path.*locald' --glob '!locald/**'
```

### Verify Crate Compiles Without Orphans
```bash
cargo check -p edr-locald
cargo check -p edr-server
cargo check -p agent-windows
cargo check -p workbench
cargo check -p wi-run-all
```

### List All Undeclared .rs Files
```bash
# Should return empty after cleanup
find crates -name '*.rs' -exec grep -L 'pub mod\|mod\|use' {} \;
```

---

## G) RECOMMENDED CLEANUP ORDER

1. **Phase 1: Safe Removals** (no code changes needed)
   - Delete entire `locald/` directory at workspace root
   - Delete `crates/locald/src/edr_locald.rs`
   - Delete `crates/locald/src/canonical/` directory
   - Delete old scoring files: `elliptic_envelope.rs`, `engine.rs`, `krim.rs`
   - Delete `crates/locald/src/os/windows/signal_result.rs`
   - Delete `crates/workbench/src/mod.rs`
   - Delete `crates/agent-windows/src/sensors/evidence_deref_example.rs`

2. **Phase 2: Verification**
   - Run `cargo check --workspace`
   - Run `cargo test --workspace`
   - Run `wi_run_all` smoke test

3. **Phase 3: Decision Required**
   - src-tauri/src/backend.rs - confirm superseded
   - src-tauri/src/adapters/ - wire in or document as future

---

**END OF AUDIT**

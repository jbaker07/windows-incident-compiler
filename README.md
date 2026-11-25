# windows-incident-compiler

EDR (Endpoint Detection and Response) incident compiler pipeline for Windows telemetry. The engine
builds and tests on Windows, macOS and Linux. Live capture runs only on Windows.

---

## Build & Test Status

The detection engine (5 crates: `edr-core`, `workbench`, `edr-server`, `edr-locald`,
`agent-windows`) builds and tests **clean on Windows, macOS, and Linux**.

Last verified on Linux aarch64 with rustc 1.100.0 (clippy and rustfmt from the same toolchain):

```bash
cargo build --workspace                 # OK (all 5 crates, incl. agent-windows)
cargo build --workspace --features pro  # OK
cargo test  --workspace                 # OK, 749 passed, 0 failed, 3 ignored
cargo test  --workspace --features pro  # OK, 749 passed, 0 failed, 3 ignored
cargo clippy --workspace --all-targets -- -D warnings  # OK (CI gate)
cargo fmt --all -- --check                             # OK

# Windows only code, checked from Linux or macOS (rustup target and MinGW installed)
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings  # OK, also with --features pro
```

The default-members build (`cargo build` / `cargo test`, which excludes the
`agent-windows` agent) reports **710 passed, 0 failed, 3 ignored**. The 3 ignored are
two documentation examples and `test_e2e_live_server` in `crates/server/tests/pdf_report_tests.rs`,
which needs a running edr-server. The `windows-live-e2e` CI job runs that test against the
server of the live run. Live capture, the PowerShell scripts and the Windows test run happen
in that job on windows-latest (see Continuous Integration below).

**Platform notes:**

- The `agent-windows` crate compiles cross-platform: the real WEVTAPI capture path is
  `#[cfg(target_os = "windows")]`-gated and falls back to a stub `main`/empty collection
  off Windows, so `--workspace` is green everywhere. Live Windows event-log capture only
  runs *on* Windows.
- The **Tauri desktop app** (`src-tauri/`) is intentionally **not** a workspace member.
  It needs WebView2 (Windows) and is built separately (`cd src-tauri && cargo run`). A
  missing system WebView toolchain does not affect the core engine build/tests above.

---

## Desktop App (Recommended)

The easiest way to use EDR is the **Tauri Desktop App**. It needs no scripts.

### Prerequisites

1. **Rust toolchain**: `rustup` with stable toolchain
2. **WebView2 Runtime**: Pre-installed on Windows 10/11, or download from Microsoft
3. **Visual Studio Build Tools**: For Windows compilation
4. (Optional) **Administrator rights**: For full telemetry access

### Build & Run Desktop App

```powershell
# 1. Build all binaries
cargo build --release --bins

# 2. Build and run the desktop app
cd src-tauri
cargo run
```

### One-Click Workflow

1. **Launch the app**: it creates the telemetry directories and copies the YAML playbooks
2. **Select capture duration** (default: 10 minutes)
3. **Optionally select playbooks**: the app passes the selection to `edr-locald` in
   `EDR_SELECTED_PLAYBOOKS` and only those YAML playbooks load. With no selection all 30 load.
4. **Click "Start Run"**: the app
   - Starts capture, locald, and server processes
   - Monitors telemetry ingestion
   - Auto-stops after the time window
   - Writes metrics artifact to `%LOCALAPPDATA%\windows-incident-compiler\telemetry\metrics\`
5. **View Detections**: signals appear in the UI with Explain/Narrative buttons
6. **Generate Activity**: click **Scenarios** to run safe test commands. The Discovery Burst
   scenario fires `signal_discovery_burst`. The other scenarios run benign commands and check
   that telemetry and fact extraction work, so they are expected to produce no signals.
7. **E2E Check**: the E2E Self Check dialog validates the full pipeline (health, signals, explain)
8. **View Metrics**: click **Metrics** for run statistics and telemetry counts

### Desktop App Features

| Feature | Description |
|---------|-------------|
| **Start/Stop Run** | One-click process lifecycle management |
| **Time Window** | 2-60 minute capture durations |
| **Playbook Selection** | Multi-select YAML playbooks. `edr-locald` loads only the selected ones |
| **Live Status** | Segments, signals, remaining time |
| **Admin Detection** | Shows banner in limited mode |
| **Crash Detection** | Surfaces last error from crashed process |
| **Generate Activity** | Safe LOLBin commands for testing |
| **E2E Self Check** | Validates segments, API, signals, explain |
| **Explainability** | View slot fills, evidence pointers, narrative |
| **Metrics Export** | JSON artifact with run statistics |

### Known Limitations

| Limitation | Impact | Workaround |
|------------|--------|------------|
| **Not Admin** | Limited telemetry (System log only). Security events, Sysmon, PowerShell logging unavailable. | Run app as Administrator |
| **No Sysmon** | Missing network, file, registry events | Install Sysmon with recommended config |
| **Audit policy not set** | Missing process creation (4688), logon (4624) events | Run `enable_advanced_telemetry.ps1 -AutoFix` |
| **Port 3000 in use** | App shows error with PID holding port | Stop conflicting process |

### Telemetry Location

- **Default**: `%LOCALAPPDATA%\windows-incident-compiler\telemetry\`
- **Override**: Set `EDR_TELEMETRY_ROOT` environment variable

---

## CLI / Scripts (Dev/CI Only)

The following scripts are for **development and CI**. Normal users should use the desktop app.

### Quick Start (CLI)

```powershell
# Build all binaries
cargo build --release --bins

# Start the full stack (dev mode)
.\scripts\run_stack_windows.ps1

# Or with E2E verification
.\scripts\run_stack_windows.ps1 -Verify -Explain -Metrics
```

### Enable Telemetry (CLI)

```powershell
# Check telemetry state
.\scripts\enable_advanced_telemetry.ps1

# Auto-fix missing channels (requires admin)
.\scripts\enable_advanced_telemetry.ps1 -AutoFix
```

---

## Windows E2E: One Command (Dev/CI)

Run the complete end-to-end verification with a single command:

```powershell
.\scripts\run_stack_windows.ps1 -Verify -Explain -Metrics -OpenUI
```

This authoritative command:
1. **Builds** all binaries (skip with `-NoBuild`)
2. **Starts** capture → locald → server stack with process supervision
3. **Generates** real Windows OS activity (process exec, PowerShell, file ops, DNS)
4. **Reports** the detections from real telemetry and warns when there are none (the
   hard checks by playbook id are in `eval_windows.ps1`)
5. **Validates** ExplanationBundle integrity (slots, evidence, playbook references)
6. **Writes** metrics artifact JSON to `$EDR_TELEMETRY_ROOT\metrics\`
7. **Opens** the UI in default browser
8. **Exits** `PASS` (0) or `FAIL` (1) with actionable logs

### Flags

| Flag | Description |
|------|-------------|
| `-NoBuild` | Skip `cargo build`, use pre-built binaries |
| `-Verify` | Run E2E verification (generate activity, check signals, exit) |
| `-Explain` | Validate ExplanationBundle for each signal |
| `-Metrics` | Write metrics JSON artifact |
| `-OpenUI` | Open browser to http://127.0.0.1:3000 |
| `-KeepRunning` | Don't shut down after verification |

### Expected Output (PASS)

```
═══════════════════════════════════════════════════════════════════
  RESULT: PASS
═══════════════════════════════════════════════════════════════════

Artifacts:
  Segments:   C:\ProgramData\edr\segments\
  Logs:       C:\ProgramData\edr\logs\
  Metrics:    C:\ProgramData\edr\metrics\run_20250101_120000.json
  UI:         http://127.0.0.1:3000
```

### Known Limitations

| Issue | Mitigation |
|-------|------------|
| **No signals detected** | Windows audit policy must have Process Creation (4688), PowerShell logging (4103/4104), or Sysmon installed. Run `enable_advanced_telemetry.ps1 -AutoFix` as admin. |
| **Security log access denied** | Run script as Administrator for full capture. Without admin, only System log is accessible. |
| **Sysmon not installed** | Install Sysmon for network/file/registry events. See installation section below. |

### Quick Verification Commands

```powershell
# Full E2E (recommended)
.\scripts\run_stack_windows.ps1 -Verify -Explain -Metrics -OpenUI

# Quick smoke test (pre-built binaries)
.\scripts\run_stack_windows.ps1 -NoBuild -Verify

# Interactive mode (keep running for manual testing)
.\scripts\run_stack_windows.ps1 -OpenUI

# Debug mode (keep running after verification)
.\scripts\run_stack_windows.ps1 -Verify -KeepRunning
```

---

## Windows Telemetry Prerequisites

The detection pipeline requires specific Windows event channels to be enabled.

### Required Channels

| Channel | Purpose | How to Enable |
|---------|---------|---------------|
| Security | Auth, process (4624, 4688, 1102) | Default enabled |
| System | Services (7045) | Default enabled |
| PowerShell Operational | Script block logging | Enable via GPO |
| Sysmon | Process, network, file events | Install Sysmon |

### Enable Script

```powershell
# Check current state
.\scripts\enable_advanced_telemetry.ps1

# Auto-fix (admin required)
.\scripts\enable_advanced_telemetry.ps1 -AutoFix
```

The script checks:
- Event channel accessibility
- Sysmon installation
- Audit policy settings
- PowerShell script block logging
- Command line in process creation events

### Sysmon Installation

For best detection coverage, install Sysmon:

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile Sysmon64.exe

# Install with SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile sysmonconfig.xml
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

## Running Evaluations

### Live Detection Evaluation

`scripts/eval_windows.ps1` runs attack-like activity on the machine, captures it live
through WEVTAPI, runs `edr-locald --once` over the capture and checks by playbook id
that the expected playbooks fired. It then checks that every signal has an explanation
with slots and evidence, and writes the metrics file the UI Metrics tab reads. Nothing
is injected.

The activity changes the host: it clears the Security and System logs, turns on the
audit policy, makes six failed logons, and in the full set creates and then deletes a
scheduled task, a service and a local administrator account. Run it only on a throwaway
VM or a CI runner. It needs PowerShell 7, an elevated session and `-DisposableHost`.

| Scenario set | Expected playbooks |
|--------------|--------------------|
| `basic` | `signal_encoded_powershell`, `signal_discovery_burst`, `signal_certutil_abuse`, `signal_logon_anomaly`, `signal_log_tamper_detection` |
| `full` (default) | basic plus `signal_schtasks_abuse`, `signal_task_persistence`, `signal_sc_abuse`, `signal_service_persistence`, `signal_net_command_abuse`, `signal_group_membership_change` |

```powershell
# Full set, build first
.\scripts\eval_windows.ps1 -DisposableHost

# Pre-built binaries, leave edr-server running for other scripts
.\scripts\eval_windows.ps1 -SkipBuild -DisposableHost -KeepRunning

# Checks only, on segments that are already captured (any OS, no admin)
pwsh scripts/eval_windows.ps1 -CheckOnly -TelemetryRoot <root> -BinDir target/debug
```

The `windows_eval_replay` test in `crates/locald/tests/` replays the events the full set
writes on Windows and checks the same eleven playbooks on every OS. With
`EDR_EVAL_REPLAY_DIR` set it also writes that telemetry root, for `-CheckOnly`.

### Metrics Output

Evaluation metrics are written to:
```
<TelemetryRoot>\metrics\run_<id>_metrics.json   (default C:\ProgramData\edr_eval)
```

View in UI: Open Run Metrics panel, click "Refresh" or "Load File"

### Verification Constraints

All evaluations enforce:
- **No fake detections**: all signals come from real telemetry
- **Explanations valid**: every signal has evidence pointers
- **Telemetry flowing**: events are captured from channels
- **Detections fired**: playbooks matched real events

## Playbook Coverage

The 30 YAML files in `playbooks/windows/` are the detection logic. `edr-locald` loads them at
startup, rejects any file with an unknown key, a bad regex, a field or fact type the engine does
not know, or a revoked ATT&CK ID, and runs every fact through the rules that remain. A match is
written to the `signals` table as `playbook:<id>` with its rule, severity, ATT&CK techniques and
tactics, plus an ExplanationBundle that points back to the segment records.

- 30 playbooks, 131 rules: 119 single event, 10 count and 2 sequence rules
- 68 ATT&CK technique IDs (45 parent techniques) across 12 tactics, mapped to ATT&CK v20.1
- 139 fixture cases that must fire and 80 near misses that must not, one named test per playbook

The Primary column counts each playbook once, by its `family`, so it sums to 30. The Listed
column counts every playbook that lists the tactic. ATT&CK v19 split Defense Evasion into
Stealth (TA0005) and Defense Impairment (TA0112).

| Tactic | Primary | Listed | Examples |
|--------|---------|--------|----------|
| Initial Access | 0 | 2 | Office child process, RDP from a public IP |
| Execution | 4 | 12 | Encoded PowerShell, Office child process, WMIC abuse |
| Persistence | 7 | 10 | Services, scheduled tasks, Run keys, WMI subscriptions |
| Privilege Escalation | 0 | 9 | Group membership change, IFEO debugger, process injection |
| Stealth | 6 | 13 | Mshta, regsvr32 and rundll32 proxy execution, DLL side-loading |
| Defense Impairment | 4 | 6 | Log clearing, audit policy and Defender disabled |
| Credential Access | 2 | 4 | LSASS dumping, SAM and NTDS theft, Kerberoasting, password spraying |
| Discovery | 2 | 2 | Discovery command burst, net command abuse |
| Lateral Movement | 1 | 3 | RDP, admin shares, PsExec, WMI and WinRM remote execution |
| Collection | 1 | 1 | Archive staging |
| Command and Control | 3 | 3 | BITSAdmin, certutil and PowerShell downloads |
| Impact | 0 | 1 | Shadow copy deletion |

`edr-locald` looks for playbooks in `EDR_PLAYBOOKS_DIR`, then the older `EDR_PLAYBOOK_DIR`,
then `<EDR_TELEMETRY_ROOT>/playbooks/windows`, then `playbooks/windows` next to the binary or
under the current directory. It writes the result to `playbooks_loaded.json` in the telemetry
root. `edr-locald --once` processes the current `index.json` and exits, which replays a
captured folder on any OS.

See [docs/playbooks_windows_coverage.md](docs/playbooks_windows_coverage.md) for the per rule
mapping, the playbook format and the v20.1 migration notes. That file is generated from the
YAML files.

---

## Evidence Import

Import evidence bundles from external tools for correlation and analysis.

### Supported Formats

| Category | Format | Adapter | Output |
|----------|--------|---------|--------|
| **Network** | Zeek TSV (`conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`) | `zeek` | netflow, dns_query, http_txn, tls_handshake, file_transfer |
| | Suricata EVE JSON (`eve.json`) | `suricata` | net_alert, dns_query, http_txn, tls_handshake, netflow |
| | Nmap XML | `nmap` | host_discovered, port_discovered, nmap_script |
| | HAR (HTTP Archive) | `har` | http_request (one per entry, with the response status), security_pattern |
| **Endpoint** | osquery (osqueryi `--json`, daemon results log, snapshots) | `osquery` | process_info, user_info, listening_port, file_event, active_session, process_exec, socket_event |
| | Velociraptor (JSON or CSV, file named after the artifact) | `velociraptor` | process_info, network_connection, mft_entry, file_info, registry_entry, prefetch_entry, scheduled_task, service_info, user_info |
| | EVTX JSON (`evtx_dump -o jsonl`, or flat records with `EventID`) | `evtx_json` | process_create, logon_success, logon_failure, service_installed, scheduled_task_created, log_cleared and other Windows event types |
| **Web Scanning** | OWASP ZAP JSON report | `zap` | web_vulnerability |
| | Burp Suite XML ("Save items" HTTP history, scanner issues report) | `burp` | http_request (with status, server IP and comment), web_vulnerability (with severity, confidence and CWE IDs) |
| | Burp Suite HAR export | `har` | http_request |
| **Threat Detection** | YARA (CLI text with `-s` or `-g`, JSON list of matches) | `yara` | yara_match |
| | Atomic Red Team (Invoke-AtomicTest CSV log, JSON records) | `atomic` | technique_executed |
| **Recon & Logs** | Shell history (bash, zsh extended history) | `plaintext` | shell_command |
| | PowerShell transcript | `plaintext` | powershell_command |
| | Gobuster output | `plaintext` | directory_found |
| | ffuf output (JSON or text) | `plaintext` | fuzz_result |
| | Other `.txt` and `.log` files | `plaintext` | log_line |
| **Artifacts** | PCAP | (stored) | Not parsed. Use Zeek logs for detection |
| | Generic JSON and JSONL | `jsonl` | The record's own event type, nested fields flattened to dotted names, plus process_name, command_line, user_name, hostname, src_ip, dest_ip and dest_port |
| | Generic YAML (one or more documents) | `yaml` | One event per document or top level list item, built like a JSON record |
| | Generic CSV with a header row | `csv` | One event per row, columns as fields (numbers stay numbers), built like a JSON record |

Files are recognized by name first: the Zeek log names, `eve.json`, and names that
contain `nmap`, `osquery`, `velociraptor`, `yara`, `zap`, `atomic`, `transcript`,
`history`, `gobuster`, `ffuf` or `burp` (with `.xml`). Otherwise the extension decides
(`.json`, `.jsonl`, `.yaml`, `.yml`, `.csv`, `.har`, `.txt`, `.log`, `.pcap`). Each event keeps a pointer to its file and line or
JSON path, and a timestamp quality: precise (from the record), estimated (from the
report or run time) or unknown (the format has no time, such as bash history).
`testdata/import_formats/` has one sample per row, and
`src-tauri/tests/import_formats_test.rs` checks what each one produces.

### How to Import

1. **CLI**: `cd src-tauri && cargo run --bin import_bundle -- --input <path> --out <telemetry root>\runs\<run>`
   imports a folder or ZIP into `imports\<bundle_id>\` with a `manifest.json`.
2. **UI**: the Import screen lists the imported bundles and shows each manifest. It does
   not upload files itself.
3. **Check a bundle**: `.\scripts\diagnose_import.ps1 -BundleId <bundle_id>`

### Import Workflow

```
Evidence Folder/ZIP
       ↓
   SafeImporter (2GB/50K files limit)
       ↓
   File Detection (FileKind)
       ↓
   Adapter Parsing → ImportEvents
       ↓
   Import Playbooks → Signals   (defined, not evaluated, see below)
       ↓
   Timeline + Entities + Evidence Pointers
```

### Import Playbooks

| Playbook | Trigger | Signal Type |
|----------|---------|-------------|
| `recon_attack_surface` | Nmap + Gobuster | Attack surface enumeration |
| `network_alert_correlation` | Suricata/Zeek alerts | Network security alerts |
| `yara_malware_detection` | YARA matches | Malware detection |
| `web_vulnerability_summary` | ZAP findings | Web vulnerabilities |
| `atomic_technique_coverage` | Atomic RT tests | Detection gap analysis |
| `windows_security_events` | EVTX logons/processes | Windows security signals |
| `endpoint_inventory` | osquery/Velociraptor | Asset inventory |

These definitions are YAML files in `playbooks/import/`. No code in this repository evaluates
them. The importer and `import_bundle` stop at ImportEvents and the bundle manifest.

### HTB/TryHackMe Session Import

Drop your session artifacts folder:
```
htb-machine-name/
├── nmap.xml              # → host/port discovery
├── gobuster.txt          # → directory enumeration
├── ffuf.json             # → fuzz results
├── .bash_history         # → command timeline
├── burp.har              # → HTTP transactions
└── notes.md              # (stored, not parsed)
```

The importer detects each file's type from its name and parses it into events.

### Safety Guarantees

- **No execution**: Imported files are NEVER executed
- **No fake signals**: All signals require real evidence
- **Size limits**: 2GB total, 50K files, 16 depth max
- **Extension block**: .exe, .dll, .ps1, etc. blocked from parsing
- **Evidence grounded**: Every signal points to source artifacts

---

## Quick Start (Build From Source)

### Prerequisites
- Rust toolchain (`rustup`)
- Windows: Visual Studio Build Tools with C++ workload
- macOS: Xcode Command Line Tools
- Linux: `build-essential`, `pkg-config`, `libssl-dev`

macOS and Linux can build and test the engine. This repository has no macOS or Linux
capture agent, so the stack runs on Windows.

### Build

```bash
cargo build --release --bins
```

### Run Stack (Windows)

PowerShell, may need admin for capture:
```powershell
.\scripts\run_stack_windows.ps1
```

### Verify (Windows)

```powershell
# Full verification (Admin PowerShell recommended)
.\scripts\run_stack_windows.ps1 -Verify

# Endpoint smoke check against a running stack
.\scripts\smoke_stack.ps1
```

### UI

Once the stack is running, open: **http://127.0.0.1:3000**

edr-server listens on 127.0.0.1 only and answers browser requests only from its own UI
and the desktop app, because the API has no authentication. `EDR_SERVER_BIND=0.0.0.0`
opens it to the network, for example inside a container.

Features:
- Real-time alerts and timeline
- Playbook signals with explanations
- Run metrics panel
- Pivot & search controls
- Export bundle for sharing

## Architecture

```
capture_windows_rotating → segments/*.jsonl → edr-locald → signals → edr-server (API + UI)
                                    ↓
                              workbench.db
                                    ↓
                           metrics/*.json
```

| Component | Description |
|-----------|-------------|
| `capture_windows_rotating` | Windows Event Log capture through WEVTAPI into rotating JSONL segments |
| `edr-locald` | Detection engine: Windows event XML to facts, YAML playbook rules, signals with explanations |
| `edr-server` | HTTP API + UI server (127.0.0.1:3000) |
| `eval_windows.ps1` | Live detection evaluation on a disposable Windows host |

### Continuous Integration

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Runner | What it checks |
|-----|--------|----------------|
| `build-and-test` | windows-latest | fmt, clippy (core and pro), release builds, tests (core and pro) |
| `build-linux` | ubuntu-latest | build and tests of the platform independent crates |
| `desktop-linux` | ubuntu-latest | rustfmt check, clippy and tests of the desktop crate (`src-tauri`), including one import per supported evidence format |
| `security-scan` | windows-latest | no signing key material in the shipped binaries |
| `artifact-allowlist` | windows-latest | the binaries in `packaging/allowlist.json` are built |
| `windows-live-e2e` | windows-latest | release build and tests, a parse of every PowerShell script, `wevt_smoke.exe`, `enable_advanced_telemetry.ps1 -AutoFix`, `eval_windows.ps1` (live capture, the eleven playbooks by id, explanations), `smoke_stack.ps1`, `quick_explain_check.ps1`, `verify_explainability.ps1`, `verify_narration.ps1`, `/api/eval/metrics` and the PDF report test against the live server, `run_stack_windows.ps1 -Verify -Explain -Metrics`, `diagnose_import.ps1` on `testdata/import_bundles` and `packaging/validate_allowlist.ps1` on a release layout |

## Documentation

- [docs/playbooks_windows_coverage.md](docs/playbooks_windows_coverage.md): playbook format, rules and ATT&CK mapping
- [docs/facts_windows.md](docs/facts_windows.md): event ID to fact type mapping
- [docs/ui_workflow.md](docs/ui_workflow.md): UI usage guide
- [docs/DESKTOP_ARCHITECTURE.md](docs/DESKTOP_ARCHITECTURE.md): desktop app architecture
- [docs/IMPORT_PIPELINE_MAP.md](docs/IMPORT_PIPELINE_MAP.md): evidence import pipeline
- [docs/LICENSING.md](docs/LICENSING.md): Pro licensing

## Third Party

| Component | Where | License |
|-----------|-------|---------|
| Liberation fonts 2.1.5 (Sans, Serif, Mono) | `crates/server/fonts/`. Liberation Sans is built into `edr-server` for PDF reports | SIL Open Font License 1.1, text in [crates/server/fonts/LICENSE](crates/server/fonts/LICENSE) (from the upstream 2.1.5 release). Release builds include it as `LIBERATION-FONTS-LICENSE.txt` |

Rust crate dependencies are listed in `Cargo.lock`, and each crate states its license on crates.io.

## License

MIT. See [LICENSE](LICENSE).

# EDR Incident Compiler

EDR (Endpoint Detection and Response) incident compiler pipeline with cross-platform telemetry capture.

---

## 🚀 Run the Product (One Command)

After building, start the app with a **single command**:

```powershell
# GUI mode (opens browser automatically)
.\target\release\locint.exe

# CLI/headless mode (no browser)
.\target\release\edr-server.exe
```

**That's it.** The UI opens at `http://127.0.0.1:3000/ui/`

> ⚠️ **Never run the helper binaries directly.** The supervisor automatically spawns
> `capture_windows_rotating.exe` and `edr-locald.exe` when you click "Start Run".

### What You Can Do in the UI

1. **Click "Start Run"** → Supervisor spawns capture + locald automatically
2. **View live metrics** → Watch events, segments, and signals accumulate (real DB counts, no estimates)
3. **Click "Stop Run"** → Supervisor stops processes and finalizes the run
4. **View Detections** → Signals appear with Explain/Narrative buttons
5. **Generate Activity** → Click 🧪 to trigger test commands for playbook matches
6. **Export/Import** → Share incident bundles

### If "Start Run" Shows Missing Binaries (HTTP 412)

The UI will display the exact build commands needed. Run them once:

```powershell
cargo build --release -p agent-windows --bin capture_windows_rotating
cargo build --release -p edr-locald --bin edr-locald
```

Then click "Start Run" again. The supervisor searches for binaries in:
1. Same directory as the main executable
2. `./bin/` subdirectory (packaged deployment)
3. `target/release/` (dev builds)

### To Stop the Server

Press `Ctrl+C` in the terminal where locint/edr-server is running. The supervisor automatically terminates any running capture and locald processes.

---

## 📋 Prerequisites

1. **Rust toolchain**: `rustup` with stable toolchain
2. **Visual Studio Build Tools**: For Windows compilation
3. (Optional) **Administrator rights**: For full telemetry access

### Build Everything

```powershell
cargo build --release --bins
```

This builds all required binaries:
- `locint.exe` — GUI server (recommended entry point)
- `edr-server.exe` — CLI/headless server  
- `capture_windows_rotating.exe` — Telemetry capture (auto-spawned)
- `edr-locald.exe` — Incident compiler (auto-spawned)

---

## ✅ Verify the Build (Optional)

Run the smoke test harness to verify all APIs work:

```powershell
cargo run --bin wi_run_all --release --
```

⚠️ **Note:** This is a verification tool, not how you run the product. It starts a temporary server, runs automated tests, and exits. For normal use, run `edr-server.exe` directly as shown above.

---

## 🖥️ Desktop App (Alternative)

The Tauri Desktop App is an alternative way to use EDR.

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

1. **Launch the app** — It auto-initializes directories and copies playbooks
2. **Select capture duration** (default: 10 minutes)
3. **Optionally select playbooks** (empty = run all available)
4. **Click "Start Run"** — The app:
   - Starts capture, locald, and server processes
   - Monitors telemetry ingestion
   - Auto-stops after the time window
   - Writes metrics artifact to `%LOCALAPPDATA%\windows-incident-compiler\telemetry\metrics\`
5. **View Detections** — Signals appear in the UI with Explain/Narrative buttons
6. **Generate Activity** — Click 🧪 to trigger safe test commands for playbook matches
7. **E2E Check** — Click 🔍 to validate the full pipeline (health, signals, explain)
8. **View Metrics** — 📊 shows run statistics and telemetry counts

### Desktop App Features

| Feature | Description |
|---------|-------------|
| **Start/Stop Run** | One-click process lifecycle management |
| **Time Window** | 2-60 minute capture durations |
| **Playbook Selection** | Multi-select or run all |
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

### Playbooks (Detection Rules)

Playbooks are **enabled by default**. The built-in starter pack ships with the binary and is automatically discovered.

**Discovery Order** (first found wins):
1. `<binary_dir>/playbooks/` — Next to the executable
2. `%LOCALAPPDATA%/LocInt/playbooks/` — User data folder
3. `EDR_PLAYBOOKS_DIR` environment variable — Custom location

**Configuration:**
| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `LOCINT_PLAYBOOKS` | `on`, `off` | `on` | Enable/disable playbook evaluation |

To disable playbooks entirely:
```powershell
$env:LOCINT_PLAYBOOKS = "off"
.\target\release\locint.exe
```

When playbooks are enabled and loaded, they produce real signals from matched telemetry events. Each signal includes:
- Evidence pointers to source events
- MITRE ATT&CK technique mapping
- Explainability metadata (slots, narrative)

---

## 📜 CLI / Scripts (Dev/CI Only)

The following scripts are for **development and CI** — normal users should use the desktop app.

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

## 🦀 Smoke Test Harness (CI/Dev Only)

⚠️ **This is NOT how you run the product.** See "Run the Product" section above.

The smoke test is a verification tool for CI and development:

```bash
cargo run --bin wi_run_all --release --
```

What it does:
1. Starts a **temporary** server instance
2. Runs automated API tests (12 steps)
3. **Shuts down** when complete

This is useful for:
   - Health endpoint (`/api/health`)
   - Selfcheck endpoint (`/api/selfcheck`)
   - Start run (`POST /api/run/start`)
   - Poll status (`/api/run/status`)
   - Metrics (`/api/run/metrics`)
   - Stop run (`POST /api/run/stop`)
   - List runs (`/api/runs`)
   - Signals API with run_id filter (`/api/signals?run_id=<id>`)
   - Pagination bounds (default=200, max=1000)
   - Explain endpoint (`/api/signals/<id>/explain`)
   - Export/Import round-trip (`/api/export_bundle`, `/api/import_bundle`)
5. **Shutdown**: Clean server termination
6. **Report**: JSON artifact saved to `./artifacts/smoke_report.json`

### Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | All smoke tests passed |
| `1`  | One or more tests failed |

### Artifacts

```
./artifacts/
├── smoke_report.json    # Step-by-step results
├── bundle.zip           # Exported bundle (if export succeeded)
└── server.log           # Server stdout/stderr (if available)
```

### Why Rust Instead of PowerShell?

- **Cross-platform**: Same binary runs on Linux CI
- **No shell escaping issues**: No quoting, no `-ExecutionPolicy` headaches
- **Atomic**: Single `cargo run` invocation
- **Timeout-aware**: Built-in deadlines for each step
- **Clean shutdown**: Server killed even on Ctrl+C or panic

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
4. **Asserts** detections ≥ 1 from real telemetry (no fake signals)
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
| `-OpenUI` | Open browser to http://localhost:3000 |
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
  UI:         http://localhost:3000
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

### Full E2E Evaluation

```powershell
# Run basic scenario set
.\scripts\eval_windows.ps1 -ScenarioSet basic

# Run full scenario set (more comprehensive)
.\scripts\eval_windows.ps1 -ScenarioSet full

# Keep stack running after evaluation
.\scripts\eval_windows.ps1 -KeepRunning
```

### Metrics Output

Evaluation metrics are written to:
```
$env:EDR_TELEMETRY_ROOT\metrics\run_<id>_metrics.json
```

View in UI: Open Run Metrics panel, click "Refresh" or "Load File"

### Verification Constraints

All evaluations enforce:
- ✅ **No fake detections** - All signals from real telemetry
- ✅ **Explanations valid** - Every signal has evidence pointers
- ✅ **Telemetry flowing** - Events captured from channels
- ✅ **Detections fired** - Playbooks matched real events

## Playbook Coverage

21 detection playbooks covering:

| Category | Count | Examples |
|----------|-------|----------|
| Execution | 4 | PowerShell download, Office child process |
| Credential Access | 2 | LSASS access, ProcDump |
| Persistence | 5 | Service install, scheduled task, WMI |
| Defense Evasion | 4 | Log clear, Defender disable |
| Lateral Movement | 3 | RDP, admin share, WinRM |
| Discovery | 2 | Network enum, domain enum |
| Collection | 1 | Archive staging |

See [docs/playbooks_windows_coverage.md](docs/playbooks_windows_coverage.md) for full details.

---

## 📦 Evidence Import

Import evidence bundles from external tools for correlation and analysis.

### Supported Formats

| Category | Format | Adapter | Output |
|----------|--------|---------|--------|
| **Network** | Zeek TSV | `zeek` | dns_query, http_txn, ssl_handshake, netflow |
| | Suricata EVE JSON | `suricata` | net_alert, dns_query, http_txn, tls_handshake |
| | Nmap XML | `nmap` | host_discovered, port_discovered, nmap_script |
| | HAR (HTTP Archive) | `har` | http_request, http_response |
| **Endpoint** | osquery JSON | `osquery` | process_info, user_info, listening_port, file_event |
| | Velociraptor | `velociraptor` | process_info, mft_entry, registry_entry, etc. |
| | EVTX JSON | `evtx_json` | Windows events (logon, process, service, etc.) |
| **Web Scanning** | OWASP ZAP JSON | `zap` | web_vulnerability |
| | Burp Suite | `har` | Use HAR export from Burp |
| **Threat Detection** | YARA Results | `yara` | yara_match |
| | Atomic Red Team | `atomic` | technique_executed |
| **Recon & Logs** | Shell History | `plaintext` | shell_command |
| | PowerShell Transcript | `plaintext` | powershell_command |
| | Gobuster Output | `plaintext` | directory_found |
| | ffuf Output | `plaintext` | fuzz_result |
| **Artifacts** | PCAP | (stored) | Not parsed—use Zeek logs for detection |
| | Generic JSONL | `jsonl` | Passthrough with entity extraction |

### How to Import

1. **Desktop App**: Drag & drop folder or ZIP into Import tab
2. **Dev CLI** (Windows): `cargo run --bin import_bundle -- --input <path>`

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
   Import Playbooks → Signals
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

The importer auto-detects file types and correlates findings.

### Safety Guarantees

- ✅ **No execution**: Imported files are NEVER executed
- ✅ **No fake signals**: All signals require real evidence
- ✅ **Size limits**: 2GB total, 50K files, 16 depth max
- ✅ **Extension block**: .exe, .dll, .ps1, etc. blocked from parsing
- ✅ **Evidence grounded**: Every signal points to source artifacts

---

## Quick Start (Cross-Platform)

### Prerequisites
- Rust toolchain (`rustup`)
- macOS: Xcode Command Line Tools
- Linux: `build-essential`, `pkg-config`, `libssl-dev`, kernel headers (for eBPF)
- Windows: Visual Studio Build Tools with C++ workload

### Build

```bash
cargo build --release --bins
```

### Run Stack

**macOS** (requires sudo for capture):
```bash
./scripts/run_stack_macos.sh
```

**Linux** (requires sudo for eBPF):
```bash
./scripts/run_stack_linux.sh
```

**Windows** (PowerShell, may need admin for capture):
```powershell
.\scripts\run_stack_windows.ps1
```

### Verify

```bash
# macOS/Linux
./scripts/smoke_stack.sh

# Windows (Admin PowerShell - recommended)
.\scripts\run_stack_windows.ps1 -Verify
```

### UI

Once the stack is running, open: **http://localhost:3000**

Features:
- Real-time alerts and timeline
- Playbook signals with explanations
- Run metrics panel
- Pivot & search controls
- Export bundle for sharing

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  locint.exe / edr-server.exe                                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  SUPERVISOR                                               │  │
│  │  - Spawns/stops capture + locald on Start/Stop Run        │  │
│  │  - Tracks PIDs, polls liveness                            │  │
│  │  - Finalizes run_meta.json on stop                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│         ↓ spawn                        ↓ spawn                  │
│  capture_windows_rotating.exe    edr-locald.exe                 │
│         ↓ writes                       ↓ reads                  │
│     segments/*.jsonl  ──────────→  workbench.db                 │
│                                        ↓                        │
│                                   signals + facts               │
│                                        ↓                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  HTTP API + UI (port 3000)                                │  │
│  │  /api/run/start, /stop, /status, /metrics                 │  │
│  │  /api/signals, /api/signals/<id>/explain                  │  │
│  │  /ui/ → static UI files                                   │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

| Component | Description |
|-----------|-------------|
| `locint.exe` | **Entry point (GUI)** — HTTP API + UI + Supervisor |
| `edr-server.exe` | **Entry point (CLI)** — Same as locint, no auto-browser |
| `Supervisor` | Process manager — spawns/stops capture + locald automatically |
| `capture_windows_rotating` | Windows ETW telemetry capture (auto-spawned) |
| `edr-locald` | Incident compiler: fact extraction, playbook matching (auto-spawned) |

### Supervisor Behavior

| API Call | Supervisor Action |
|----------|-------------------|
| `POST /api/run/start` | Spawn capture + locald, track PIDs, return `run_id` |
| `GET /api/run/status` | Return phase (idle/running/finalizing), PIDs, liveness |
| `GET /api/run/metrics` | Query DB for real segment/signal counts |
| `POST /api/run/stop` | Stop capture → drain locald → finalize run_meta.json |

### Error Codes

| HTTP | Code | Meaning |
|------|------|---------|
| 412 | `BINARY_NOT_FOUND` | Helper binary missing — build it first |
| 409 | `RUN_ALREADY_ACTIVE` | A run is already in progress |
| 409 | `NO_ACTIVE_RUN` | No run to stop (already idle) |
| 500 | `SPAWN_FAILED` | Process failed to start (check permissions) |

## Documentation

- [docs/VALIDATION_RUN.md](docs/VALIDATION_RUN.md) - **End-to-end validation workflow** (known-fire test)
- [docs/playbooks_windows_coverage.md](docs/playbooks_windows_coverage.md) - Playbook → MITRE mapping
- [docs/facts_windows.md](docs/facts_windows.md) - Event ID → Fact type mapping
- [docs/ui_workflow.md](docs/ui_workflow.md) - UI usage guide
- [docs/LICENSING.md](docs/LICENSING.md) - Licensing documentation
- [docs/SHIPPING.md](docs/SHIPPING.md) - Release process
- [docs/IMPORT_ARCHITECTURE.md](docs/IMPORT_ARCHITECTURE.md) - Import bundle system
- [docs/MISSION_UI_WORKFLOW.md](docs/MISSION_UI_WORKFLOW.md) - Mission Control workflow

## License

MIT - see [LICENSE](LICENSE)

# RELEASE NOTES

**Version:** 1.0.0-ship  
**Date:** 2026-01-11  
**Build:** `cargo build --release --workspace`

---

## What Ships

Windows Incident Compiler is a local-first endpoint detection system that:

1. **Captures** Windows Event Log telemetry (Security, System, Sysmon)
2. **Analyzes** events against threat playbooks (ATT&CK-mapped)
3. **Scores** signals using evidence-based detection logic
4. **Explains** why signals fired with full evidence chains

### Binaries

| Binary | Description |
|--------|-------------|
| `locint` | **Product entrypoint** — double-click GUI, no console |
| `edr-server` | Developer server (CLI mode) |
| `edr-locald` | Detection daemon (lifecycle managed by server) |
| `capture_windows_rotating` | Telemetry capture with rotation |
| `wi_run_all` | Smoke test + invariant verification |

### End-User Experience

**For end users:** Double-click `locint.exe` — browser opens automatically, no terminal.

```
LocInt/
  locint.exe                        # Double-click this!
  edr-locald.exe                    
  capture_windows_rotating.exe      
  ui/                               
  playbooks/windows/                
```

All paths are resolved relative to the executable, so the folder can live anywhere.

### UI Workflow

1. **Settings** → Verify telemetry sources are healthy
2. **Start** → Begin capture run
3. **Stop** → End capture, finalize analysis
4. **Select Run** → View coverage + signals
5. **Signal Detail** → See evidence + explanation

---

## Key Changes (This Release)

### Stabilization

- **Run lifecycle is canonical:** `insert_run()` on start, `finalize_run()` on stop
- **Per-run database:** Each run writes to `{run_dir}/workbench.db` (no drift)
- **Run ID propagation:** UI passes `run_id` to all signals endpoints
- **Explanation shape:** Canonical JSON schema for `/api/signals/:id/explain`

### Cleanup

- Removed orphan `locald/` directory (duplicate of `crates/locald/src/`)
- Stale references in docs flagged (non-runtime, documentation debt)

### Verification

- `TRUTH_CONTRACT.md` defines 10 post-run invariants
- `wi_run_all` checks invariants and returns categorized exit codes:
  - `0` = All pass
  - `1` = Setup failure
  - `2` = Lifecycle invariant broken
  - `3` = Database invariant broken
  - `4` = API invariant broken
  - `5` = Code hygiene violation

---

## Supported Telemetry Sources

### Enabled by Default

| Source | Coverage |
|--------|----------|
| **Security** | Logon (4624/4625), Process (4688), Audit clear (1102), Tasks (4698), Policy (4719), Firewall (5156) |
| **System** | Service install (7045) |
| **Sysmon** | Full (Events 1-26) — Requires Sysmon installed |

### Available (Disabled)

| Source | Why Disabled |
|--------|--------------|
| PowerShell Operational | Requires policy: Script Block Logging |
| WMI-Activity | Verbose, optional enrichment |
| TaskScheduler | Covered by Security 4698 |

---

## Playbook Coverage

| Category | Playbooks | Top TTPs |
|----------|-----------|----------|
| Execution | 6 | T1059.001, T1059.003, T1053.005 |
| Defense Evasion | 4 | T1070.001, T1112, T1562.001 |
| Persistence | 3 | T1543.003, T1547.001, T1053.005 |
| Credential Access | 2 | T1003.001, T1558.003 |
| Discovery | 2 | T1016, T1082 |

Total: **17 playbooks** covering **24 ATT&CK techniques**.

---

## System Requirements

- **OS:** Windows 10 20H2+ / Windows 11 / Windows Server 2019+
- **Arch:** x64
- **Privileges:** Administrator (for event log capture)
- **Disk:** 500MB + ~100MB per capture run
- **Memory:** 512MB minimum, 2GB recommended

### Dependencies (Bundled)

- Rust runtime (statically linked)
- SQLite (embedded via rusqlite)
- Web UI (static files in binary)

### External (Optional but Recommended)

- **Sysmon** — Install for process/network/file visibility
- **Audit policies** — Configure for credential/logon events

---

## Known Limitations

1. **Windows-only** — Linux companion project exists separately
2. **Local capture only** — No remote collection
3. **Single run context** — One active run at a time
4. **No persistence across server restarts** — Runs stored in filesystem

---

## Verification Checklist

Before shipping:

```powershell
# Run smoke test
cargo run --bin wi_run_all --release

# Expected output: "Smoke test completed successfully" + exit code 0

# Run full test suite
cargo test --workspace

# Verify invariants
# See TRUTH_CONTRACT.md for manual verification steps
```

---

## File Inventory (What Gets Deployed)

```
windows-incident-compiler/
├── target/release/
│   ├── edr-server.exe        # Main binary
│   ├── edr-locald.exe        # Detection daemon
│   └── capture_windows_rotating.exe
├── playbooks/windows/        # Detection rules
├── data/                     # Created at runtime
└── runs/                     # Created at runtime
```

---

## Contact / Support

This is a demonstration/research tool. No warranty implied.

See `TRUTH_CONTRACT.md` for invariant definitions and `BUILD.md` for setup instructions.

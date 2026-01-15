# BUILD.md

## Quick Start

**One command to run:**

```powershell
# Build and start the server
cargo build --release -p edr-server && .\target\release\edr-server.exe
```

Then open http://127.0.0.1:3000/ui/ in your browser.

---

## Prerequisites

- **Windows 10/11** (x64)
- **Rust 1.70+** with `x86_64-pc-windows-msvc` target
- **Visual Studio Build Tools** (for MSVC linker)
- **Administrator privileges** for capture (recommended)

## Full Build

```powershell
# Clone and build
git clone <repo-url>
cd windows-incident-compiler

# Build all binaries (release mode)
cargo build --release --workspace

# Run smoke test to verify everything works
cargo run --bin wi_run_all --release
```

## Binaries Produced

| Binary | Purpose | Location |
|--------|---------|----------|
| `locint.exe` | **Product entrypoint** (GUI, no console) | `target/release/locint.exe` |
| `edr-server.exe` | Developer server (CLI) | `target/release/edr-server.exe` |
| `edr-locald.exe` | Detection daemon | `target/release/edr-locald.exe` |
| `capture_windows_rotating.exe` | Telemetry capture | `target/release/capture_windows_rotating.exe` |
| `wi_run_all.exe` | Smoke test harness | `target/release/wi_run_all.exe` |

---

## Shipping Layout (End-User Distribution)

For end-user deployment, ship the `LocInt/` folder below. Users double-click `locint.exe` and the browser opens automatically - no terminal interaction required.

```
LocInt/
  locint.exe                        # Main entrypoint (double-click me!)
  edr-locald.exe                    # Detection daemon (spawned automatically)
  capture_windows_rotating.exe      # Telemetry capture (spawned automatically)
  ui/                               # Web UI (served by locint.exe)
    index.html
    app.js
    loading.html
  playbooks/                        # Detection playbooks
    windows/
      *.yaml
```

### Building the Shipping Folder

```powershell
# Build release binaries
cargo build --release --workspace

# Create shipping folder
$ship = "LocInt"
New-Item -ItemType Directory -Force -Path $ship
New-Item -ItemType Directory -Force -Path "$ship\ui"
New-Item -ItemType Directory -Force -Path "$ship\playbooks\windows"

# Copy binaries
Copy-Item target\release\locint.exe $ship\
Copy-Item target\release\edr-locald.exe $ship\
Copy-Item target\release\capture_windows_rotating.exe $ship\

# Copy UI
Copy-Item ui\* $ship\ui\ -Recurse

# Copy playbooks
Copy-Item playbooks\windows\*.yaml $ship\playbooks\windows\

Write-Host "✅ Shipping folder ready: $ship"
Write-Host "   Double-click LocInt\locint.exe to launch"
```

### What locint.exe Does Differently

| Aspect | `edr-server.exe` (dev) | `locint.exe` (product) |
|--------|------------------------|------------------------|
| Console | Visible | Hidden (GUI subsystem) |
| Paths | Relative to repo/cwd | Relative to exe directory |
| Browser | Manual open | Auto-opens UI |
| Errors | Logs to console | MessageBox dialog |
| Data | `data/` in cwd | `%LOCALAPPDATA%\attack-workbench\` |

## Data Directories

| Path | Contents |
|------|----------|
| `data/` | Server workbench.db, config |
| `runs/run_*/` | Per-run telemetry + artifacts |
| `runs/run_*/workbench.db` | Per-run signals + explanations |
| `runs/run_*/segments/` | Raw event segments (.jsonl) |
| `playbooks/windows/` | Detection playbooks (.yaml) |

## Verification

After starting the server:

1. Open http://127.0.0.1:3000/ui/
2. Click **Settings** → **Run checks** to verify telemetry sources
3. Click **Start** to begin capture
4. After ~30s, click **Stop**
5. Click the run in the **Runs** list to view coverage and findings

---

## Telemetry Sources (Default)

The following Windows Event Log channels are enabled by default:

| Channel | Status | Event IDs |
|---------|--------|-----------|
| Security | ✅ Enabled | 4624, 4625, 4688, 1102, 4698, 4719, 5156 |
| System | ✅ Enabled | 7045 |
| Microsoft-Windows-Sysmon/Operational | ✅ Enabled | 1-26 |
| PowerShell Operational | ❌ Disabled | 4103, 4104 |
| WMI-Activity Operational | ❌ Disabled | - |
| TaskScheduler Operational | ❌ Disabled | 106, 141 |

### Enabling Additional Sources

To enable PowerShell script block logging:

```powershell
# Enable PowerShell module and script block logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name EnableModuleLogging -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Force
```

## Windows Policies for Best Results

### Sysmon (Highly Recommended)

Install Sysmon from Sysinternals for comprehensive process, file, and network visibility:

```powershell
# Download and install Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath Sysmon
.\Sysmon\Sysmon64.exe -accepteula -i
```

### Audit Policies

Enable these audit policies via Group Policy or `auditpol`:

```powershell
# Process creation with command line
auditpol /set /category:"Detailed Tracking" /subcategory:"Process Creation" /success:enable /failure:enable

# Logon events
auditpol /set /category:"Logon/Logoff" /subcategory:"Logon" /success:enable /failure:enable

# Object access (for registry/file auditing)
auditpol /set /category:"Object Access" /subcategory:"Registry" /success:enable
```

### Command Line Logging

Enable process command line auditing:

```powershell
# Enable command line logging in process creation events
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord -Force
```

---

## Troubleshooting

### No events captured?

1. Run as Administrator
2. Verify Sysmon is installed: `sc query Sysmon64`
3. Check audit policies: `auditpol /get /category:*`
4. Try the selfcheck endpoint: http://127.0.0.1:3000/api/selfcheck

### Server won't start?

```powershell
# Check if port 3000 is in use
netstat -ano | findstr :3000

# Kill existing process if needed
taskkill /PID <pid> /F
```

### Build errors?

```powershell
# Ensure Rust is up to date
rustup update stable

# Clean and rebuild
cargo clean
cargo build --release --workspace
```

---

*Last updated: 2026-01-11 (Ship Pass)*

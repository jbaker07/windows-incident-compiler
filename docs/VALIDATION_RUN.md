# Validation Run: Known-Fire Detection Test

This document provides a **deterministic, safe** procedure to validate the entire detection pipeline on a properly instrumented Windows machine.

**Purpose**: Confirm that live findings are captured, facts are extracted, signals fire, and the explain feature populates — end-to-end.

---

## Prerequisites

| Requirement | Check Command | Expected |
|-------------|---------------|----------|
| **Admin privileges** | Run PowerShell as Administrator | Window title shows "Administrator" |
| **Sysmon installed** | `Get-Service Sysmon64 -ErrorAction SilentlyContinue` | Status: Running |
| **Security log accessible** | `wevtutil qe Security /c:1 /f:text` | Returns event data (no "Access denied") |
| **Audit Process Creation enabled** | `auditpol /get /subcategory:"Process Creation"` | Success: "Success and Failure" or "Success" |

### Quick Prerequisites Check

```powershell
# Run this as Administrator to verify readiness:
$checks = @{
    "Admin" = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    "Sysmon" = (Get-Service Sysmon64 -ErrorAction SilentlyContinue).Status -eq 'Running'
    "SecurityLog" = try { wevtutil qe Security /c:1 /f:text 2>$null; $true } catch { $false }
}
$checks | Format-Table -AutoSize
```

If any check fails, fix it before proceeding.

---

## The Test: Encoded PowerShell Detection

We use **Encoded PowerShell** as the validation signal because:
- ✅ PowerShell is always present on Windows
- ✅ The command is completely benign (`whoami` encoded)
- ✅ Sysmon Event ID 1 reliably captures it
- ✅ No network access required
- ✅ The playbook `signal_encoded_powershell.yaml` is enabled by default

### The Trigger Command

```powershell
powershell.exe -NoProfile -EncodedCommand dwBoAG8AYQBtAGkA
```

This runs `whoami` (base64-encoded as UTF-16LE). It:
- Creates a detectable Sysmon Event ID 1 (Process Create)
- Matches the `-EncodedCommand` pattern in the playbook
- Is completely safe — just prints your username

---

## Step-by-Step Validation

### 1. Start LocInt as Administrator

```powershell
# From project directory, as Admin:
.\target\release\locint.exe
```

The UI opens at `http://127.0.0.1:3000/ui/`

### 2. Verify System Health

In the **Settings** tab, click **"Run Checks"**. Confirm:
- `admin_mode`: ✅ (green)
- `sysmon_available`: ✅ (green)  
- `security_log_access`: ✅ (green)

If any are red, fix before proceeding.

### 3. Start a Capture Run

1. Go to the **Mission** tab
2. Set Profile: **Extended** (or Core)
3. Set Duration: **5 min** (sufficient for testing)
4. Click **"▶ Start Run"**
5. Wait for status to show **"Capturing"** with process PIDs

### 4. Execute the Trigger Command

In a **separate** Administrator PowerShell window, run:

```powershell
powershell.exe -NoProfile -EncodedCommand dwBoAG8AYQBtAGkA
```

You should see your username printed (e.g., `DOMAIN\username`).

### 5. Wait for Processing

The pipeline processes events in near real-time:
1. **capture_windows** writes Sysmon events to segment files
2. **locald** reads segments, extracts facts, evaluates playbooks
3. **server** serves updated counts via `/api/run/status`

Wait ~5-10 seconds for the event to flow through.

### 6. Verify Detection

**In the Mission tab**, check the live counters:
- `facts_total` should increase (at least +1 for the Exec fact)
- `signals_rows` should increase (at least +1 for encoded PowerShell)

**In the Findings panel** (right side), you should see:
- A new finding with title containing "Encoded" or "PowerShell"
- Severity: HIGH
- MITRE: T1059.001 (PowerShell)

### 7. Test Explainability

1. Click on the finding row to select it
2. Click **"Explain"** button
3. Verify the explain panel shows:
   - Signal metadata (playbook ID, severity)
   - Matched facts with timestamps
   - Evidence chain linking to raw events

### 8. Stop and Finalize

1. Click **"⏹ Stop Run"**
2. Wait for status to show **"Completed"**
3. The run is now finalized and can be reviewed in the **Runs** tab

---

## Expected Outcomes

| Metric | Before Trigger | After Trigger |
|--------|----------------|---------------|
| `facts_total` | N | N + 1 (minimum) |
| `signals_rows` | M | M + 1 (minimum) |
| Findings list | Empty or prior | New "Encoded PowerShell" finding |
| Explain panel | Empty | Populated with signal chain |

---

## Troubleshooting

### No facts_total increase

1. Check dataflow: `http://127.0.0.1:3000/api/meta/dataflow_snapshot?debug=1`
2. Verify `spawn_status.capture_running` is `true`
3. Verify `segments_status.segments_count` is increasing
4. Check `diagnosis` array for issues

### No signals_rows increase

1. Facts are arriving but playbook not matching
2. Verify playbook is enabled: check `playbooks/windows/signal_encoded_powershell.yaml` has `enabled: true`
3. Check fact extraction logs in the flight recorder

### Explain shows "No data"

1. Signal fired but explain endpoint issue
2. Check `/api/signals/{id}/explain` returns data
3. Verify the signal has `evidence_json` populated

---

## Debug Mode

Access the UI with `?debug=1` to enable:
- Diagnosis banner (shows dataflow issues)
- **"Copy Validation Cmd"** button (copies trigger command to clipboard)
- Extra console logging

Example: `http://127.0.0.1:3000/ui/?debug=1`

---

## Alternative Trigger Commands

If encoded PowerShell doesn't fire (rare), try these alternatives:

### CertUtil Decode (signal_certutil_abuse.yaml)
```powershell
# Create test file, then decode it (benign)
echo "dGVzdA==" > $env:TEMP\test.b64
certutil -decode $env:TEMP\test.b64 $env:TEMP\test.txt
del $env:TEMP\test.b64, $env:TEMP\test.txt
```

### Net Commands (signal_net_command_abuse.yaml)
```powershell
# Benign user enumeration
net user
net localgroup administrators
```

---

## Attack Surface Validation Triggers

This section provides **safe, benign triggers** for each major attack surface.
Each trigger is designed to generate detectable telemetry without causing harm.

### Prerequisites by Surface

| Surface | Required Sensors | Required Privileges |
|---------|------------------|---------------------|
| Process Execution | Sysmon OR Audit Process Creation | Standard |
| Persistence | Security Log + System Log | Administrator |
| Credential Access | Sysmon 10 (Process Access) | Administrator |
| Defense Evasion | Security Log + Sysmon | Administrator |
| Lateral Movement | Security Log (4624, 5140) | Administrator |
| Network | Sysmon 3 (Network Connect) | Standard |

---

### 1. Process Execution (Baseline)

**Playbook**: `signal_encoded_powershell.yaml`  
**Expected Fact**: `Exec` with `-EncodedCommand` in cmdline  
**Expected Signal**: `windows_encoded_powershell_001`

```powershell
# SAFE: Runs encoded "whoami" (completely benign)
powershell.exe -NoProfile -EncodedCommand dwBoAG8AYQBtAGkA
```

**Verification**:
- `facts_total` increases (Exec fact created)
- Signal appears in Findings with severity HIGH
- MITRE: T1059.001

---

### 2. Persistence - Scheduled Task

**Playbook**: `signal_schtasks_abuse.yaml`, `signal_task_persistence.yaml`  
**Expected Fact**: `PersistArtifact` (type: ScheduledTask)  
**Expected Signal**: `windows_schtasks_001`

```powershell
# SAFE: Create and immediately delete a harmless scheduled task
$taskName = "LocInt_Validation_Test_$(Get-Date -Format 'HHmmss')"
schtasks /create /tn $taskName /tr "cmd.exe /c echo test" /sc once /st 23:59 /f
Start-Sleep -Seconds 5  # Allow event to be captured
schtasks /delete /tn $taskName /f
Write-Host "Task $taskName created and deleted for validation"
```

**Verification**:
- Security Event 4698 (task created) captured
- PersistArtifact fact with ScheduledTask type
- Signal fires if task path looks suspicious

---

### 3. Persistence - Service

**Playbook**: `signal_service_persistence.yaml`, `signal_sc_abuse.yaml`  
**Expected Fact**: `PersistArtifact` (type: Service)  
**Expected Signal**: `windows_service_persistence_001`

```powershell
# SAFE: Create a disabled test service and delete it
# This generates System Event 7045 without starting any service
$svcName = "LocIntValidationSvc"
sc.exe create $svcName binPath= "cmd.exe /c exit" start= disabled
Start-Sleep -Seconds 5
sc.exe delete $svcName
Write-Host "Service $svcName created and deleted for validation"
```

**Verification**:
- System Event 7045 captured
- PersistArtifact fact with Service type
- Signal severity HIGH (temp path patterns not present in this benign test)

**⚠️ Note**: Service creation requires Administrator privileges.

---

### 4. Persistence - Registry Run Key

**Playbook**: `signal_registry_persistence.yaml`  
**Expected Fact**: `RegistryMod` with Run key path  
**Expected Signal**: `windows_registry_persistence_001`

```powershell
# SAFE: Set and remove a harmless HKCU Run key
$keyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$valueName = "LocIntValidationTest"
New-ItemProperty -Path $keyPath -Name $valueName -Value "notepad.exe" -PropertyType String -Force
Start-Sleep -Seconds 5
Remove-ItemProperty -Path $keyPath -Name $valueName -Force
Write-Host "Run key '$valueName' set and removed for validation"
```

**Verification**:
- Sysmon Event 13 (registry value set) captured
- RegistryMod fact with key containing "\Run"
- Signal fires for Run key modification

**⚠️ Note**: Requires Sysmon for full registry monitoring.

---

### 5. Credential Access Detection

**Playbook**: `signal_credential_access.yaml`  
**Expected Fact**: `ProcessAccess` (Sysmon 10) or `Exec` with dump tool patterns  
**Expected Signal**: `windows_credential_access_001`

#### Prerequisites (CRITICAL)

| Requirement | Why | How to Check |
|-------------|-----|--------------|
| **Sysmon installed** | ProcessAccess requires Sysmon Event ID 10 | `Get-Service Sysmon64` |
| **Sysmon Event 10 enabled** | Must have ProcessAccess logging in config | Check Sysmon XML config |

**⚠️ WARNING**: Without Sysmon, ProcessAccess facts CANNOT be generated. The playbook will be marked `blocked_by_telemetry` in `/api/capability/gaps`.

#### Validation Option A: Command-Line Patterns (Safe, No Sysmon Required)

```powershell
# SAFE: Command pattern that LOOKS like a dump tool but is harmless
# This fires the command-line pattern detection WITHOUT actually dumping
powershell.exe -NoProfile -Command "Write-Host 'Validation: procdump test pattern'"
```

**Verification**:
- Exec fact with "procdump" in output triggers pattern match
- Signal fires if command matches credential tool patterns
- Does NOT generate ProcessAccess fact (that requires Sysmon 10)

#### Validation Option B: ProcessAccess Facts (Requires Sysmon)

**DO NOT** attempt to trigger real LSASS access for validation. Instead:

1. Verify Sysmon Event 10 is working:
   ```powershell
   # Check if Sysmon 10 events exist
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | 
     Where-Object { $_.Id -eq 10 } | Format-List TimeCreated, Message
   ```

2. Expected behavior with Sysmon 10 enabled:
   - ProcessAccess facts appear in `/api/runs/{run_id}/coverage` with `fact_type: "ProcessAccess"`
   - Facts include `target_image`, `granted_access`, `source_proc_key`, `target_proc_key`
   - Signal fires when target_image contains "lsass"

#### Success Criteria

| Scenario | Expected Facts | Expected Signals |
|----------|----------------|------------------|
| Without Sysmon | Exec (cmdline patterns only) | Fires on dump tool patterns |
| With Sysmon | ProcessAccess + Exec | Fires on LSASS access OR patterns |

**⚠️ Truth Contract**:
- ProcessAccess is NOT a proxy for MemAlloc
- ProcessAccess specifically maps to Sysmon Event ID 10
- If Sysmon is missing, `/api/capability/gaps` reports `credential_access` as blocked

---

### 6. Defense Evasion - Encoded PowerShell (Cross-Surface)

Already covered in Section 1 above.

---

### 7. Defense Evasion - Security Tool Disable Pattern

**Playbook**: `signal_security_tool_disable.yaml`  
**Expected Fact**: `Exec` with disable patterns  
**Expected Signal**: `windows_security_disable_001`

```powershell
# SAFE: Echo commands that LOOK like security disable but don't execute
# The command pattern is captured even though it's just an echo
cmd.exe /c "echo Set-MpPreference -DisableRealtimeMonitoring $true"
```

**Verification**:
- Exec fact captured with disable pattern in cmdline
- Signal may fire based on pattern matching

**⚠️ Note**: Some patterns require actual execution to trigger (don't actually disable security tools!).

---

### 8. Lateral Movement - RDP Logon

**Playbook**: `signal_lateral_movement_detection.yaml`, `signal_logon_anomaly.yaml`  
**Expected Fact**: `AuthEvent` (type: RemoteInteractive, logon type 10)  
**Expected Signal**: `windows_lateral_movement_001`

**Lab-Only Validation**:
```powershell
# Requires a second machine in your lab network
# From the remote machine, RDP to the validation target
# This generates Security Event 4624 with LogonType 10
mstsc /v:<target_hostname>
```

**Verification**:
- Security Event 4624 with LogonType 10
- AuthEvent fact with type RemoteInteractive
- Signal fires for remote RDP logon

**⚠️ Note**: 
- Only perform in isolated lab environments
- Requires two machines (source and target)
- Network-based validation is complex; skip if no lab available

---

### 9. Network - Outbound Connection

**Playbook**: Lateral movement detection (network indicators)  
**Expected Fact**: `OutboundConnect`  
**Expected Signal**: None (direct network facts are informational)

```powershell
# SAFE: Trigger a network connection to a benign target
# Uses Invoke-WebRequest which Sysmon 3 can capture
powershell.exe -NoProfile -Command "Invoke-WebRequest -Uri 'https://www.microsoft.com' -Method Head -TimeoutSec 5 | Out-Null"
```

**Verification**:
- Sysmon Event 3 (Network Connect) captured
- OutboundConnect fact with dst_ip and dst_port
- No signal expected (outbound to known-good IP)

**⚠️ Note**: 
- Requires Sysmon with NetworkConnect rule enabled
- Destination should be a benign, known-good IP
- Signal detection depends on destination reputation

---

## Log Clearing Validation

**⚠️ WARNING**: DO NOT clear production Security logs!

**Playbook**: `signal_log_tampering.yaml`  
**Expected Fact**: `LogTamper` (action: Clear)  
**Expected Signal**: `windows_log_tamper_001`

**Safe Alternative**: Import a pre-recorded event log containing Event 1102:
```powershell
# If you have a captured .evtx with log clear events:
wevtutil epl Security exported_security.evtx /q:"*[System[(EventID=1102)]]"
# Then import into the validation target via the import pipeline
```

**Do NOT run in production**:
```powershell
# THIS CLEARS LOGS - ONLY FOR ISOLATED LAB
# wevtutil cl Application  # Clears Application log (generates 104)
```

---

## Validation Checklist by Surface

| Surface | Trigger Executed | Fact Observed | Signal Fired | Pass/Fail |
|---------|------------------|---------------|--------------|-----------|
| Process Execution | ☐ | ☐ | ☐ | |
| Sched Task Persist | ☐ | ☐ | ☐ | |
| Service Persist | ☐ | ☐ | ☐ | |
| Registry Persist | ☐ | ☐ | ☐ | |
| Credential Access | ☐ | ☐ | ☐ | |
| Security Disable | ☐ | ☐ | ☐ | |
| RDP/Lateral | ☐ | ☐ | ☐ | |
| Network Connect | ☐ | ☐ | ☐ | |

---

## Phase 2: Enhanced Explanation Validation

For the 5 core playbooks with template-based explanations, verify the following fields are present when signals fire:

### Expected Explanation Fields by Playbook

#### 1. Encoded PowerShell (`windows_encoded_powershell_001`)

| Field | Present | Expected Content |
|-------|---------|------------------|
| `reasons` | ✅ | Array with `code: "POWERSHELL_ENCODED_COMMAND"` |
| `key_fields.cmdline` | ✅ | Command line containing `-enc` |
| `key_fields.proc_key` | ✅ | PowerShell.exe path |
| `why_fired` | ✅ | Template narrative mentioning encoded command |
| `detector_version` | ✅ | e.g., "2.0" |
| `evidence_ptrs_count` | ≥1 | At least one evidence pointer |

**Reason Codes**: `POWERSHELL_ENCODED_COMMAND`, `POWERSHELL_BYPASS_POLICY`, `POWERSHELL_HIDDEN_WINDOW`, `POWERSHELL_DOWNLOAD_CRADLE`

#### 2. Schtasks Abuse (`windows_schtasks_abuse_001`)

| Field | Present | Expected Content |
|-------|---------|------------------|
| `reasons` | ✅ | Array with `code: "TASK_CREATED"` or `"TASK_CREATED_SYSTEM"` |
| `key_fields.cmdline` | ✅ | Command line with `/create` |
| `key_fields.proc_key` | ✅ | schtasks.exe path |
| `why_fired` | ✅ | Template narrative mentioning scheduled task |

**Reason Codes**: `TASK_CREATED`, `TASK_CREATED_SYSTEM`, `TASK_CREATED_REMOTE`, `TASK_HIDDEN`

#### 3. Service Persistence (`windows_service_persistence_001`)

| Field | Present | Expected Content |
|-------|---------|------------------|
| `reasons` | ✅ | Array with `code: "SERVICE_INSTALLED"` |
| `key_fields.service_name` | When available | Service name from event |
| `key_fields.binary_path` | When available | Service binary path |
| `why_fired` | ✅ | Template narrative mentioning service installation |

**Reason Codes**: `SERVICE_INSTALLED`, `SERVICE_SUSPICIOUS_PATH`, `SERVICE_REGISTRY_MODIFIED`

#### 4. Registry Persistence (`windows_registry_persistence_001`)

| Field | Present | Expected Content |
|-------|---------|------------------|
| `reasons` | ✅ | Array with `code: "REGISTRY_RUN_KEY_MODIFIED"` |
| `key_fields.registry_key` | ✅ | Registry path containing "Run" |
| `key_fields.registry_value` | When available | Value name or data |
| `why_fired` | ✅ | Template narrative mentioning registry persistence |

**Reason Codes**: `REGISTRY_RUN_KEY_MODIFIED`, `REGISTRY_IFEO_DEBUGGER`, `REGISTRY_WINLOGON_SHELL`, `REGISTRY_SERVICES_MODIFIED`

#### 5. Credential Access (`windows_credential_access_001`)

| Field | Present | Expected Content |
|-------|---------|------------------|
| `reasons` | ✅ | `PROCESS_ACCESS_LSASS` (Sysmon) or `CREDENTIAL_DUMP_TOOL` (cmdline) |
| `key_fields.source_proc` | When Sysmon | Source process accessing LSASS |
| `key_fields.target_image` | When Sysmon | "lsass.exe" |
| `key_fields.granted_access` | When Sysmon | Hex access mask |
| `key_fields.cmdline` | When pattern | Command line with dump tool pattern |
| `why_fired` | ✅ | Template narrative mentioning credential access |

**Reason Codes**: `PROCESS_ACCESS_LSASS`, `CREDENTIAL_DUMP_TOOL`, `SAM_REGISTRY_EXPORT`, `NTDS_ACCESS`, `COMSVCS_DUMP`

**⚠️ Note**: ProcessAccess fields (source_proc, target_image, granted_access) require Sysmon Event 10.

### API Verification

Fetch explanation for a signal:
```bash
curl "http://localhost:5175/api/signals/{signal_id}/explain?run_id={run_id}"
```

Expected structure when `available: true`:
```json
{
  "success": true,
  "data": {
    "available": true,
    "narrative": "PowerShell process detected with encoded command flag...",
    "reasons": [
      {"code": "POWERSHELL_ENCODED_COMMAND", "label": "Encoded PowerShell Command", "detail": "..."}
    ],
    "key_fields": {
      "cmdline": "powershell.exe -enc ...",
      "proc_key": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    },
    "evidence_ptrs_count": 1,
    "source": {"kind": "playbook", "id": "windows_encoded_powershell_001", "version": "2.0"}
  }
}
```

### Explanation Checklist

| Playbook | Signal Fired | reasons[] Present | key_fields Present | why_fired Present | Pass |
|----------|--------------|-------------------|-------------------|-------------------|------|
| encoded_powershell | ☐ | ☐ | ☐ | ☐ | ☐ |
| schtasks_abuse | ☐ | ☐ | ☐ | ☐ | ☐ |
| service_persistence | ☐ | ☐ | ☐ | ☐ | ☐ |
| registry_persistence | ☐ | ☐ | ☐ | ☐ | ☐ |
| credential_access | ☐ | ☐ | ☐ | ☐ | ☐ |

---

## Summary

This validation confirms:
1. ✅ Telemetry capture is working (Sysmon → segments)
2. ✅ Fact extraction is working (segments → facts)
3. ✅ Signal evaluation is working (facts → signals)
4. ✅ UI rendering is working (signals → findings)
5. ✅ Explainability is working (signals → evidence chain)

If all checks pass, the system is **production-ready** for real incident response.

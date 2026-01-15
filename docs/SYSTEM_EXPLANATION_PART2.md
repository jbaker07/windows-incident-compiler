# LocInt System Explanation (Part 2/3): Windows v1 Coverage + Routing

> **Audience:** Engineers, SOC analysts. Evidence-first, no hand-waving.  
> **Last Updated:** 2026-01-13  
> **Scope:** Windows v1 attack surface coverage matrix, cross-source overlap, validation hooks.

---

## Source of Truth Pointers

| Topic | Authoritative File |
|-------|-------------------|
| Coverage mapping | `docs/WINDOWS_V1_COVERAGE_MAP.md` |
| Attack surface routing | `crates/agent-windows/src/sensors/attack_surface.rs` |
| Channel configuration | `crates/agent-windows/src/wevt_reader.rs` |
| Safe validation triggers | `VALIDATION_RUN.md` |

---

## 1. Windows v1 Coverage Matrix (Required)

The following surfaces are **required for v1 completeness**. Each must have routing in `attack_surface.rs` and parsers that emit canonical events.

### 1.1 Process Execution

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Microsoft-Windows-Sysmon/Operational` | 1 | `parse_proc_exec` | `process_exec` | Sysmon installed |
| `Security` | 4688 | `parse_proc_exec` | `process_exec` | Admin + "Audit Process Creation" policy |

**Notes:**
- Sysmon 1 provides command line, hashes, parent process details
- Security 4688 requires audit policy; command line logging requires additional GPO setting
- Both sources produce the same canonical tag; see §2 for overlap handling

### 1.2 Network Egress

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Microsoft-Windows-Sysmon/Operational` | 3 | `parse_network_connect` | `network_connect` | Sysmon installed |

**Notes:**
- No Security event fallback for network connections
- Sysmon 3 captures outbound TCP/UDP with process context

### 1.3 Credential / Process Access (LSASS)

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Microsoft-Windows-Sysmon/Operational` | 10 | `parse_proc_access` | `proc_access` | Sysmon installed |

**Notes:**
- Primarily used to detect LSASS access (credential dumping)
- Requires Sysmon with ProcessAccess logging enabled

### 1.4 Persistence: Services

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `System` | 7045 | `parse_persistence_service` | `persistence_service` | None |
| `Security` | 4697 | `parse_persistence_service` | `persistence_service` | Admin |

**Notes:**
- System 7045 fires for new service installation (always available)
- Security 4697 requires audit policy but provides more detail

### 1.5 Persistence: Scheduled Tasks

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Security` | 4698 | `parse_persistence_task` | `persistence_task` | Admin |
| `Security` | 4702 | `parse_persistence_task` | `persistence_task` | Admin |
| `Microsoft-Windows-TaskScheduler/Operational` | 106 | `parse_persistence_task_operational` | `persistence_task` | None |

**Notes:**
- Security 4698 = task created, 4702 = task updated
- TaskScheduler 106 provides a non-admin fallback for task registration

### 1.6 Persistence: Registry

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Microsoft-Windows-Sysmon/Operational` | 12 | `parse_registry_mod` | `registry_mod` | Sysmon |
| `Microsoft-Windows-Sysmon/Operational` | 13 | `parse_registry_mod` | `registry_mod` | Sysmon |
| `Microsoft-Windows-Sysmon/Operational` | 14 | `parse_registry_mod` | `registry_mod` | Sysmon |
| `Security` | 4657 | `parse_registry_mod` | `registry_mod` | Admin + audit policy |

**Notes:**
- Sysmon 12 = key/value create/delete, 13 = value set, 14 = rename
- Security 4657 requires "Audit Registry" policy; rarely enabled by default

### 1.7 PowerShell Execution

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Microsoft-Windows-PowerShell/Operational` | 4103 | `parse_powershell_exec` | `powershell_exec` | Module logging enabled |
| `Microsoft-Windows-PowerShell/Operational` | 4104 | `parse_powershell_exec` | `powershell_exec` | Script block logging enabled |

**Notes:**
- 4104 captures full script block content (most valuable)
- Requires GPO or registry settings to enable logging

### 1.8 Log Tampering / Defense Evasion

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Security` | 1102 | `parse_log_clear` | `log_clear` | Admin |
| `System` | 104 | `parse_log_clear` | `log_clear` | None |

**Notes:**
- Security 1102 = Security log cleared
- System 104 = any log cleared (Application, System, etc.)

---

## 2. Additional Supported Events (Non-v1 / Optional)

These events are routed in `attack_surface.rs` but are **not required for v1 completeness**:

### 2.1 WMI Persistence

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Microsoft-Windows-Sysmon/Operational` | 19 | `parse_wmi_persistence` | `wmi_persistence` | Sysmon |
| `Microsoft-Windows-Sysmon/Operational` | 20 | `parse_wmi_persistence` | `wmi_persistence` | Sysmon |
| `Microsoft-Windows-Sysmon/Operational` | 21 | `parse_wmi_persistence` | `wmi_persistence` | Sysmon |

**Status:** Routed but optional. Sysmon 19/20/21 = WMI filter/consumer/binding events.

### 2.2 Lateral Movement: RDP

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Security` | 4624 (LogonType=10) | `parse_remote_logon_rdp` | `remote_logon_rdp` | Admin |

**Status:** Routed but optional. Only LogonType=10 (RDP) is extracted; other logon types are not currently emitted.

### 2.3 Lateral Movement: WinRM

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Microsoft-Windows-WinRM/Operational` | 91 | `parse_remote_winrm` | `remote_winrm` | None |

**Status:** Routed but optional. Event 91 = WinRM shell started.

### 2.4 Privilege Escalation

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Security` | 4672 | `parse_priv_escalation` | `priv_elevation` | Admin |

**Status:** Routed but optional. Special privileges assigned to new logon.

### 2.5 File Creation

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Microsoft-Windows-Sysmon/Operational` | 11 | `parse_file_create` | `file_create` | Sysmon |

**Status:** Routed but optional. High-volume event; filtering recommended.

### 2.6 Defense Prevention (ASR)

| Channel | Event ID | Parser Function | Canonical Tag | Prerequisites |
|---------|----------|-----------------|---------------|---------------|
| `Microsoft-Windows-Windows Defender/Operational` | 1121 | `parse_asr_block` | `asr_block` | Defender + ASR rules |

**Status:** Routed but optional. Requires Windows Defender with ASR enabled.

---

## 3. Cross-Source Overlap Policy

### 3.1 Sysmon vs Security for Process Execution

Both Sysmon 1 and Security 4688 can fire for the same process creation:

| Behavior | Current Implementation |
|----------|------------------------|
| Both events routed? | **Yes** — both produce separate canonical events |
| Same canonical tag? | **Yes** — both emit `process_exec` |
| Evidence pointers? | **Separate** — each points to its own segment record |
| Cross-source merge? | **Not implemented** — no automatic dedup at fact level |

**Implication:** If both channels are accessible, you may see two canonical events for the same process spawn, each with different evidence pointers. The compiler does not currently merge them.

> **Verification note:** No cross-source merge logic was found in `crates/locald/` as of 2026-01-13. If merge behavior is added, update this section.

### 3.2 Dedup Guarantees

- **Per-channel dedup:** Guaranteed by `wevt_reader.rs` (HashSet + LRU)
- **Cross-channel dedup:** Not implemented (same logical event from different channels = separate records)

---

## 4. Regression Test Posture

### 4.1 Attack Surface Routing Tests

`attack_surface.rs` includes unit tests that verify:

| Test Category | What It Guarantees |
|---------------|-------------------|
| Routing correctness | Each (channel, event_id) tuple routes to the expected parser |
| Tag emission | Parser outputs include the expected canonical tags |
| Field extraction | Required fields are present in output events |

**Test commands:**
```powershell
cargo test -p agent-windows -- attack_surface
```

### 4.2 Parity Contract Tests

`crates/server/tests/parity_routes_contract.rs` verifies:

- API routes match `routes_snapshot.json`
- Contract version is stable
- No unintended route additions/removals

**Test commands:**
```powershell
cargo test -p edr-server --test parity_routes_contract
```

---

## 5. Validation Hooks (Operator Safe Triggers)

These commands generate **real Windows events** that flow through the pipeline. Use them to verify coverage.

> **Full reference:** See `VALIDATION_RUN.md` for complete trigger list with expected outputs.

### 5.1 Process Execution

```powershell
# Sysmon 1 / Security 4688
whoami.exe /all
```
**Expected:** `process_exec` canonical event

### 5.2 Network Connection

```powershell
# Sysmon 3 — Force TCP connection (preferred)
curl.exe -s -o NUL "http://example.com" 2>$null
# Or using PowerShell:
Invoke-WebRequest -Uri "http://example.com" -UseBasicParsing -TimeoutSec 5 | Out-Null
```

**Expected:** `network_connect` canonical event

> **Note:** `Resolve-DnsName` uses UDP and typically does not trigger Sysmon Event ID 3 (which captures TCP/UDP connects with process context). Use HTTP requests to guarantee a TCP connect event.

### 5.3 File Creation

```powershell
# Sysmon 11
$testFile = "$env:TEMP\validation_test_$(Get-Random).txt"
"test" | Out-File -FilePath $testFile
Remove-Item $testFile -ErrorAction SilentlyContinue
```
**Expected:** `file_create` canonical event

### 5.4 Registry Modification

```powershell
# Sysmon 13 (no admin required for HKCU)
$key = "HKCU:\Software\ValidationTest_$(Get-Random)"
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name "TestValue" -Value "validation"
Remove-Item -Path $key -Recurse -Force
```
**Expected:** `registry_mod` canonical event

### 5.5 PowerShell Execution

```powershell
# PowerShell 4104 (requires script block logging)
Write-Host "Validation: PowerShell script block test"
```
**Expected:** `powershell_exec` canonical event

### 5.6 Service Installation

```powershell
# System 7045 (requires admin)
$svcName = "ValidationTestSvc"
sc.exe create $svcName binPath= "C:\Windows\System32\cmd.exe" start= disabled | Out-Null
sc.exe delete $svcName | Out-Null
```
**Expected:** `persistence_service` canonical event

### 5.7 Scheduled Task

```powershell
# Security 4698 / TaskScheduler 106
$taskName = "ValidationTask_$(Get-Random)"
schtasks /create /tn $taskName /tr "cmd.exe /c echo test" /sc once /st 23:59 /f | Out-Null
schtasks /delete /tn $taskName /f | Out-Null
```
**Expected:** `persistence_task` canonical event

### 5.8 Log Clear (🔴 LAB ONLY - DESTRUCTIVE)

```powershell
# System 104 — DESTRUCTIVE: clears Application log
wevtutil cl Application
```
**Expected:** `log_clear` canonical event

> ⚠️ **WARNING:** This clears the Application event log. Only run in lab environments.

---

## 6. Summary: Part 2 Scope

This part covered:

- ✅ Full Windows v1 required coverage matrix with prerequisites
- ✅ Additional supported events (non-v1 / optional)
- ✅ Cross-source overlap policy (Sysmon vs Security)
- ✅ Regression test posture
- ✅ Safe validation triggers for each surface

**Next:** Part 3 covers the compiler stage, workbench.db, HTTP API wiring, and UI behavior.

---

*This document describes the system as implemented. For the authoritative coverage mapping, see `docs/WINDOWS_V1_COVERAGE_MAP.md`.*

# Windows Telemetry Coverage Validation

This document provides safe trigger commands to validate that the attack surface coverage is wired correctly. All commands generate **real Windows events** that flow through the unified WEVTAPI pipeline.

> **⚠️ Run these commands in an Admin PowerShell session for full coverage.**

---

## Prerequisites

1. **Admin privileges** — Required for Security log access
2. **Sysmon installed** — Required for process/network/registry events ([download](https://learn.microsoft.com/sysinternals/downloads/sysmon))
3. **PowerShell script block logging enabled** (optional but recommended):
   ```powershell
   # Enable via GPO or registry:
   New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force
   ```

---

## 1. Process Execution (Sysmon 1 / Security 4688)

```powershell
# Trigger process creation event
whoami.exe /all
```

**Expected Event:**
- Sysmon 1: ProcessCreate
- Attack Surface: `process_exec`

---

## 2. Network Connection (Sysmon 3)

```powershell
# TCP connection to trigger Sysmon 3 (NetworkConnect)
# Note: Resolve-DnsName uses UDP which may NOT trigger Sysmon 3
# Use curl.exe or Invoke-WebRequest for reliable TCP-based trigger
curl.exe -s https://example.com -o $null 2>$null
# Alternative: Invoke-WebRequest -Uri "https://example.com" -UseBasicParsing | Out-Null
```

**Expected Event:**
- Sysmon 3: NetworkConnect (requires TCP connection, not DNS/UDP)
- Attack Surface: `network_connect`

---

## 3. File Creation (Sysmon 11)

```powershell
# Create a temporary file
$testFile = "$env:TEMP\validation_test_$(Get-Random).txt"
"validation test" | Out-File -FilePath $testFile
Remove-Item -Path $testFile -ErrorAction SilentlyContinue
```

**Expected Event:**
- Sysmon 11: FileCreate
- Attack Surface: `file_create`

---

## 4. Registry Modification (Sysmon 12/13/14 or Security 4657)

```powershell
# Safe registry write to user hive (does not require admin)
$key = "HKCU:\Software\ValidationTest_$(Get-Random)"
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name "TestValue" -Value "validation"
Remove-Item -Path $key -Recurse -Force
```

**Expected Event:**
- Sysmon 13: RegistryValue Set
- Attack Surface: `registry_mod`

---

## 5. PowerShell Execution (PowerShell 4103/4104)

```powershell
# Script block logging captures this
Write-Host "Validation: PowerShell script block logging test"
Get-Process | Select-Object -First 1
```

**Expected Event:**
- PowerShell 4104: ScriptBlockLogging
- Attack Surface: `powershell_exec`

---

## 6. Service Installation (System 7045 / Security 4697)

```powershell
# Create and remove a test service (requires admin)
$svcName = "ValidationTestSvc"
sc.exe create $svcName binPath= "C:\Windows\System32\cmd.exe" start= disabled | Out-Null
sc.exe delete $svcName | Out-Null
```

**Expected Event:**
- System 7045: ServiceInstalled
- Attack Surface: `persistence_service`

---

## 7. Scheduled Task Creation (Security 4698 / TaskScheduler 106)

```powershell
# Create and remove a scheduled task (requires admin)
$taskName = "ValidationTestTask"
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo test"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(10)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force | Out-Null
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
```

**Expected Event:**
- Security 4698: ScheduledTaskCreated
- TaskScheduler/Operational 106: Task registered
- Attack Surface: `persistence_task`

---

## 8. Logon Event (Security 4624)

```powershell
# Local logon already occurred when you logged in
# Check existing events:
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 1 | Format-List
```

**Expected Event:**
- Security 4624: LogonSuccess
- Attack Surface: `remote_logon_rdp` (if LogonType=10)

---

## 9. Privilege Elevation (Security 4672)

```powershell
# Running elevated already triggers this
# Check existing events:
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4672]]" -MaxEvents 1 | Format-List
```

**Expected Event:**
- Security 4672: SpecialPrivilegesAssigned
- Attack Surface: `priv_elevation`

---

## 10. Log Clear Detection (Security 1102 / System 104)

> **🔴 LAB ONLY - DESTRUCTIVE: This clears an event log. Do NOT run in production.**

```powershell
# Clear a low-value diagnostic log to generate System 104
# LAB ONLY - this destroys log data
wevtutil cl "Microsoft-Windows-Diagnosis-Scheduled/Operational"
```

**Expected Event:**
- System 104: LogCleared
- Attack Surface: `log_clear`

---

## Validation Checklist

Run `locint` and then check `/api/capability/status` to verify channel accessibility:

```powershell
# Check capability status
Invoke-RestMethod -Uri "http://localhost:8442/api/capability/status" | ConvertTo-Json -Depth 5
```

Expected output includes:
- `is_admin: true`
- `sysmon_installed: true`
- `channels`: Array with accessibility status for each channel
- `overall_status: "full"`

---

## Attack Surface Coverage Matrix

| Attack Surface     | Primary Source          | Fallback Source     | Parser Function                |
|--------------------|-------------------------|---------------------|--------------------------------|
| process_exec       | Sysmon 1                | Security 4688       | `parse_process_exec`           |
| network_connect    | Sysmon 3                | —                   | `parse_network_connect`        |
| file_create        | Sysmon 11               | —                   | `parse_file_create`            |
| registry_mod       | Sysmon 12/13/14         | Security 4657       | `parse_registry_mod`           |
| powershell_exec    | PowerShell 4103/4104    | —                   | `parse_powershell_exec`        |
| persistence_service| System 7045             | Security 4697       | `parse_persistence_service`    |
| persistence_task   | Security 4698/4702      | TaskScheduler 106   | `parse_persistence_task[_operational]` |
| wmi_persistence    | Sysmon 19/20/21         | —                   | `parse_wmi_persistence`        |
| log_clear          | Security 1102           | System 104          | `parse_log_clear`              |
| remote_logon_rdp   | Security 4624 (Type=10) | —                   | `parse_remote_logon_rdp`       |
| remote_winrm       | WinRM 91                | —                   | `parse_remote_winrm`           |
| priv_elevation     | Security 4672           | —                   | `parse_priv_elevation`         |
| proc_access        | Sysmon 10               | —                   | `parse_proc_access`            |

---

## Channels Enabled by Default

| Channel                                          | Enabled | Attack Surface Events    |
|--------------------------------------------------|---------|--------------------------|
| Security                                         | ✅      | 4624, 4672, 4688, 4697, 4698, 1102, etc. |
| System                                           | ✅      | 7045, 104                |
| Microsoft-Windows-Sysmon/Operational             | ✅      | 1, 3, 10, 11, 12-14, 19-21 |
| Microsoft-Windows-PowerShell/Operational         | ✅      | 4103, 4104               |
| Microsoft-Windows-WMI-Activity/Operational       | ✅      | 5857-5861                |
| Microsoft-Windows-TaskScheduler/Operational      | ✅      | 106                      |
| Microsoft-Windows-WinRM/Operational              | ✅      | 91                       |

---

## Quick Verification Commands

```powershell
# 1. Check capability status (run locint first)
$cap = Invoke-RestMethod -Uri "http://localhost:8442/api/capability/status"
Write-Host "Admin: $($cap.is_admin) | Sysmon: $($cap.sysmon_installed) | Status: $($cap.overall_status)"

# 2. List supported channels with parser coverage
$cap.channels | ForEach-Object { 
    Write-Host "$($_.name): Accessible=$($_.accessible), Supported=$($_.supported), EventIDs=$($_.supported_event_ids -join ',')"
}

# 3. Check selfcheck endpoint
Invoke-RestMethod -Uri "http://localhost:8442/api/selfcheck" | ConvertTo-Json

# 4. Verify parity tests pass
cargo test -p edr-server --test parity_routes_contract
```

---

## v1 Coverage Completion Checklist

- [ ] `/api/capability/status` returns `overall_status: "full"` (admin + Sysmon)
- [ ] All channels show `accessible: true` and `supported: true`
- [ ] Process execution test generates `process_exec` event
- [ ] Network test generates `network_connect` event  
- [ ] Registry test generates `registry_mod` event
- [ ] Service test generates `persistence_service` event
- [ ] Task test generates `persistence_task` event
- [ ] PowerShell test generates `powershell_exec` event
- [ ] Parity tests pass: `cargo test -p edr-server --test parity_routes_contract`

---

*Last updated: 2026-01-13 (Windows v1 Full Attack Surface Coverage)*

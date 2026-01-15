# Windows Playbook Coverage

This document maps all Windows detection playbooks to their MITRE ATT&CK techniques and required telemetry sources.

## Playbook Inventory

### Execution (4 playbooks)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `execution_lolbin_rundll32` | Suspicious Rundll32 Execution | T1218.011 | Sysmon 1, Security 4688 |
| `execution_lolbin_powershell_download` | PowerShell Download Cradle | T1059.001 | PowerShell 4103/4104, Sysmon 1 |
| `execution_office_child_process` | Office Application Child Process | T1204.002 | Sysmon 1, Security 4688 |
| `execution_suspicious_script` | Suspicious Script Host Execution | T1059.005, T1059.007 | Sysmon 1, Security 4688 |

### Credential Access (2 playbooks)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `credential_lsass_access` | LSASS Memory Access | T1003.001 | Sysmon 10 |
| `credential_procdump` | Process Dump Tool Usage | T1003.001 | Sysmon 1, Sysmon 11 |

### Persistence (5 playbooks)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `persistence_service_install` | Malicious Service Installation | T1543.003 | System 7045, Sysmon 1 |
| `persistence_scheduled_task` | Scheduled Task Creation | T1053.005 | TaskScheduler 106/141, Security 4698 |
| `persistence_registry_run` | Registry Run Key Modification | T1547.001 | Sysmon 13, Security 4657 |
| `persistence_wmi_subscription` | WMI Event Subscription | T1546.003 | Sysmon 19/20/21 |
| `persistence_startup_folder` | Startup Folder Persistence | T1547.001 | Sysmon 11 |

### Defense Evasion (4 playbooks)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `log_tamper_clear` | Security Log Cleared | T1070.001 | Security 1102 |
| `log_tamper_utility` | Log Clearing Utility | T1070.001 | Sysmon 1, Security 4688 |
| `defense_evasion_audit_disable` | Audit Policy Modification | T1562.002 | Security 4719 |
| `defense_evasion_defender_disable` | Windows Defender Tampering | T1562.001 | Sysmon 1, Defender 5001 |

### Lateral Movement (3 playbooks)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `lateral_movement_rdp` | RDP Lateral Movement | T1021.001 | Security 4624 (Type 10), TerminalServices |
| `lateral_movement_admin_share` | Admin Share Access | T1021.002 | Security 5140/5145 |
| `lateral_movement_winrm` | WinRM Remote Execution | T1021.006 | Sysmon 1, WinRM 91 |

### Discovery (2 playbooks)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `discovery_network_enum` | Network Enumeration | T1018, T1016 | Sysmon 1, Sysmon 3 |
| `discovery_domain_enum` | Domain Enumeration | T1087.002, T1069 | Sysmon 1, Security 4661 |

### Collection (1 playbook)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `collection_archive_staging` | Data Archive for Exfil | T1560.001 | Sysmon 1, Sysmon 11 |

## Telemetry Requirements Summary

### Core Channels (Minimum Required)

| Channel | Event IDs | Playbooks Covered |
|---------|-----------|-------------------|
| Security | 4624, 4625, 4688, 1102, 4698, 4719 | 12 |
| System | 7045 | 1 |
| PowerShell Operational | 4103, 4104 | 2 |

### High-Value Channels (Recommended)

| Channel | Event IDs | Playbooks Covered |
|---------|-----------|-------------------|
| Sysmon | 1, 3, 10, 11, 13, 19-21 | 18 |
| TaskScheduler Operational | 106, 141 | 1 |

### Extended Channels (Full Coverage)

| Channel | Event IDs | Playbooks Covered |
|---------|-----------|-------------------|
| TerminalServices-LocalSessionManager | 21, 25 | 1 |
| WinRM Operational | 91 | 1 |
| Windows Defender | 5001, 5007 | 1 |

## MITRE ATT&CK Coverage Matrix

```
Tactic              | Techniques Covered
--------------------|-------------------
Execution           | T1059.001, T1059.005, T1059.007, T1204.002, T1218.011
Persistence         | T1053.005, T1543.003, T1546.003, T1547.001
Defense Evasion     | T1070.001, T1562.001, T1562.002
Credential Access   | T1003.001
Discovery           | T1016, T1018, T1069, T1087.002
Lateral Movement    | T1021.001, T1021.002, T1021.006
Collection          | T1560.001
```

## Enabling Telemetry

Run the provided script to enable all required telemetry sources:

```powershell
# Check current telemetry state
.\scripts\enable_advanced_telemetry.ps1

# Auto-fix missing channels (requires admin)
.\scripts\enable_advanced_telemetry.ps1 -AutoFix
```

See [docs/facts_windows.md](facts_windows.md) for the mapping from event IDs to fact types.

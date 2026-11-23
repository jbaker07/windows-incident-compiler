# Windows Playbook Coverage

This document maps the Windows detection playbooks to MITRE ATT&CK. The repository has two sets.

- **YAML playbooks**: 30 files in `playbooks/windows/`. Each file has a `mitre:` block with its
  tactics and technique IDs.
- **Compiled engine playbooks**: 21 definitions in `crates/locald/src/os/windows/playbooks.rs`.
  `edr-locald` registers these at startup and matches facts against them. No code in this
  repository parses the YAML files into the engine.

ATT&CK IDs and tactic names in both sets follow ATT&CK v18. ATT&CK v19 split Defense Evasion
into Stealth and Defense Impairment and moved some techniques to new IDs, for example
T1070.001 is now T1685.005.

## YAML Playbooks (playbooks/windows, 30 files)

The 30 files cover 56 distinct technique IDs.

### Count by Tactic

Primary counts each playbook once, by the first tactic it lists, so it sums to 30. Listed counts
every playbook that lists the tactic anywhere.

| Tactic | Primary | Listed | Examples |
|--------|---------|--------|----------|
| Initial Access | 0 | 2 | Office child process, logon anomaly |
| Execution | 4 | 13 | Encoded PowerShell, Office child process, WMIC abuse |
| Persistence | 7 | 10 | Service, scheduled task and registry persistence |
| Privilege Escalation | 0 | 8 | Process injection, group membership change |
| Defense Evasion | 11 | 17 | Log clearing, security tool disable, rundll32 and regsvr32 proxy execution |
| Credential Access | 2 | 2 | LSASS, SAM and NTDS access, brute force logons |
| Discovery | 2 | 3 | Discovery command burst, net command abuse |
| Lateral Movement | 1 | 3 | RDP, admin shares, PsExec and WMI remote execution |
| Collection | 1 | 1 | File staging |
| Command and Control | 2 | 3 | BITSAdmin, certutil and PowerShell downloads |
| Exfiltration | 0 | 1 | File staging |

### Playbook Inventory

| Playbook file | Tactics (first is primary) | Techniques |
|---------------|----------------------------|------------|
| `signal_bitsadmin_abuse.yaml` | Command and Control, Defense Evasion, Persistence | T1197, T1105 |
| `signal_certutil_abuse.yaml` | Defense Evasion, Command and Control | T1140, T1105, T1218 |
| `signal_credential_access.yaml` | Credential Access | T1003.001, T1003.002, T1003.003 |
| `signal_defense_evasion.yaml` | Defense Evasion | T1070.001, T1562, T1562.001, T1112 |
| `signal_discovery_burst.yaml` | Discovery | T1087, T1016, T1033, T1069, T1082, T1083 |
| `signal_dll_side_loading.yaml` | Defense Evasion, Persistence | T1574.001, T1574.002 |
| `signal_encoded_powershell.yaml` | Execution, Defense Evasion | T1059.001, T1027, T1140 |
| `signal_file_staging.yaml` | Collection, Exfiltration | T1560.001, T1074 |
| `signal_group_membership_change.yaml` | Persistence, Privilege Escalation | T1098, T1136 |
| `signal_lateral_movement_detection.yaml` | Lateral Movement, Execution, Defense Evasion | T1021, T1021.001, T1021.002, T1550.003, T1569.002, T1047 |
| `signal_log_tamper_detection.yaml` | Defense Evasion | T1070.001 |
| `signal_log_tampering.yaml` | Defense Evasion | T1070.001, T1562.002 |
| `signal_logon_anomaly.yaml` | Credential Access, Initial Access, Lateral Movement | T1110, T1078, T1021.001 |
| `signal_lolbin_abuse.yaml` | Defense Evasion, Execution | T1218, T1218.005, T1218.010, T1218.011, T1059.001 |
| `signal_mshta_abuse.yaml` | Defense Evasion, Execution | T1218.005 |
| `signal_net_command_abuse.yaml` | Discovery, Lateral Movement, Persistence | T1087, T1069, T1135, T1136 |
| `signal_office_child_process.yaml` | Execution, Initial Access | T1204.002, T1566.001, T1559.002 |
| `signal_persistence_windows.yaml` | Persistence, Privilege Escalation, Execution | T1543.003, T1053.005, T1547.001 |
| `signal_powershell_download.yaml` | Command and Control, Execution | T1059.001, T1105 |
| `signal_process_injection.yaml` | Defense Evasion, Privilege Escalation | T1055.001, T1055.002, T1055.003, T1055.004, T1055.012 |
| `signal_registry_persistence.yaml` | Persistence, Privilege Escalation | T1547.001, T1546.012, T1547.004, T1543.003 |
| `signal_regsvr32_abuse.yaml` | Defense Evasion, Execution | T1218.010 |
| `signal_rundll32_abuse.yaml` | Defense Evasion, Execution | T1218.011 |
| `signal_sc_abuse.yaml` | Persistence, Privilege Escalation, Defense Evasion | T1543.003, T1562.001 |
| `signal_schtasks_abuse.yaml` | Persistence, Execution, Privilege Escalation | T1053.005 |
| `signal_security_tool_disable.yaml` | Defense Evasion | T1562.001, T1562.004 |
| `signal_service_persistence.yaml` | Persistence, Privilege Escalation | T1543.003 |
| `signal_task_persistence.yaml` | Persistence, Execution, Privilege Escalation | T1053.005 |
| `signal_wmic_abuse.yaml` | Execution, Discovery, Defense Evasion | T1047, T1220, T1490 |
| `signal_wscript_cscript_abuse.yaml` | Execution, Defense Evasion | T1059.005, T1059.007 |

## Compiled Engine Playbooks (21)

These are the playbooks `edr-locald` runs. IDs are the `playbook_id` values in
`crates/locald/src/os/windows/playbooks.rs`.

### Execution (4 playbooks)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `windows_exec_lolbin_rundll32` | Suspicious Rundll32 Execution | T1218.011 | Sysmon 1, Security 4688 |
| `windows_exec_powershell_download` | PowerShell Download Cradle | T1059.001 | PowerShell 4103/4104, Sysmon 1 |
| `windows_exec_office_child` | Office Application Child Process | T1204.002 | Sysmon 1, Security 4688 |
| `windows_exec_script_host` | Suspicious Script Host Execution | T1059.005, T1059.007 | Sysmon 1, Security 4688 |

### Credential Access (2 playbooks)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `windows_credential_lsass` | LSASS Memory Access | T1003.001 | Sysmon 10 |
| `windows_credential_procdump` | Process Dump Tool Usage | T1003.001 | Sysmon 1, Sysmon 11 |

### Persistence (5 playbooks)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `windows_persist_service` | Malicious Service Installation | T1543.003 | System 7045, Sysmon 1 |
| `windows_persist_task` | Scheduled Task Creation | T1053.005 | TaskScheduler 106/141, Security 4698 |
| `windows_persist_registry_run` | Registry Run Key Modification | T1547.001 | Sysmon 13, Security 4657 |
| `windows_persist_wmi` | WMI Event Subscription | T1546.003 | Sysmon 19/20/21 |
| `windows_persist_startup` | Startup Folder Persistence | T1547.001 | Sysmon 11 |

### Defense Evasion (4 playbooks)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `windows_log_tamper_clear` | Security Log Cleared | T1070.001 | Security 1102 |
| `windows_log_tamper_utility` | Log Clearing Utility | T1070.001 | Sysmon 1, Security 4688 |
| `windows_evasion_audit_disable` | Audit Policy Modification | T1562.002 | Security 4719 |
| `windows_evasion_defender_disable` | Windows Defender Tampering | T1562.001 | Sysmon 1, Defender 5001 |

### Lateral Movement (3 playbooks)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `windows_lateral_rdp` | RDP Lateral Movement | T1021.001 | Security 4624 (Type 10), TerminalServices |
| `windows_lateral_share` | Admin Share Access | T1021.002 | Security 5140/5145 |
| `windows_lateral_winrm` | WinRM Remote Execution | T1021.006 | Sysmon 1, WinRM 91 |

### Discovery (2 playbooks)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `windows_discovery_network` | Network Enumeration | T1018, T1016 | Sysmon 1, Sysmon 3 |
| `windows_discovery_domain` | Domain Enumeration | T1087.002, T1069 | Sysmon 1, Security 4661 |

### Collection (1 playbook)

| Playbook ID | Name | MITRE Technique | Required Telemetry |
|------------|------|-----------------|-------------------|
| `windows_collection_archive` | Data Archive for Exfil | T1560.001 | Sysmon 1, Sysmon 11 |

## Telemetry Requirements Summary (Compiled Set)

### Core Channels (Minimum Required)

| Channel | Event IDs | Playbooks Covered |
|---------|-----------|-------------------|
| Security | 1102, 4624, 4657, 4661, 4688, 4698, 4719, 5140, 5145 | 11 |
| System | 7045 | 1 |
| PowerShell Operational | 4103, 4104 | 1 |

### High-Value Channels (Recommended)

| Channel | Event IDs | Playbooks Covered |
|---------|-----------|-------------------|
| Sysmon | 1, 3, 10, 11, 13, 19-21 | 16 |
| TaskScheduler Operational | 106, 141 | 1 |

### Extended Channels (Full Coverage)

| Channel | Event IDs | Playbooks Covered |
|---------|-----------|-------------------|
| TerminalServices-LocalSessionManager | 21, 25 | 1 |
| WinRM Operational | 91 | 1 |
| Windows Defender | 5001, 5007 | 1 |

## MITRE ATT&CK Coverage Matrix (Compiled Set)

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

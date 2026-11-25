# Windows Playbook Coverage

This file is generated from `playbooks/windows/*.yaml`. Those YAML files are the only
source of detection logic for `edr-locald`. At startup it loads them, checks every rule,
and runs every fact through them. Each match becomes a row in the `signals` table with
an ExplanationBundle in `signal_explanations`.

- Playbooks: 30
- Rules: 131
- ATT&CK technique IDs: 68 (45 distinct parent techniques)
- Tactics covered: 12 of the 15 Enterprise tactics
- ATT&CK release: v20.1 (Enterprise), checked against attack.mitre.org
- Fixture cases: 139 that must fire and 80 near misses that must not

## Count by Tactic

Primary counts each playbook once, by its `family` (the main tactic), so it sums to
30. Listed counts every playbook whose `mitre.tactics` includes the tactic.

| Tactic | Primary | Listed |
|--------|---------|--------|
| Initial Access (TA0001) | 0 | 2 |
| Execution (TA0002) | 4 | 12 |
| Persistence (TA0003) | 7 | 10 |
| Privilege Escalation (TA0004) | 0 | 9 |
| Stealth (TA0005) | 6 | 13 |
| Defense Impairment (TA0112) | 4 | 6 |
| Credential Access (TA0006) | 2 | 4 |
| Discovery (TA0007) | 2 | 2 |
| Lateral Movement (TA0008) | 1 | 3 |
| Collection (TA0009) | 1 | 1 |
| Command and Control (TA0011) | 3 | 3 |
| Impact (TA0040) | 0 | 1 |

## Playbook Inventory

| Playbook | Family | Rules | Tactics | Techniques |
|----------|--------|-------|---------|------------|
| `signal_bitsadmin_abuse` | Command and Control | 4 | Command and Control, Stealth, Persistence, Execution | T1105, T1197 |
| `signal_certutil_abuse` | Command and Control | 4 | Command and Control, Stealth | T1105, T1140, T1027.013, T1070.004 |
| `signal_credential_access` | Credential Access | 6 | Credential Access | T1003.001, T1003.002, T1003.003, T1555.004 |
| `signal_defense_evasion` | Defense Impairment | 4 | Defense Impairment | T1685, T1685.001, T1685.005, T1112 |
| `signal_discovery_burst` | Discovery | 4 | Discovery | T1033, T1087, T1069, T1016, T1049, T1482, T1615, T1082, T1057 |
| `signal_dll_side_loading` | Stealth | 2 | Stealth, Execution | T1574.001 |
| `signal_encoded_powershell` | Execution | 4 | Execution, Stealth | T1059.001, T1027.010, T1564.003, T1620 |
| `signal_file_staging` | Collection | 5 | Collection | T1560.001, T1074.001 |
| `signal_group_membership_change` | Persistence | 5 | Persistence, Privilege Escalation | T1098.007, T1136 |
| `signal_lateral_movement_detection` | Lateral Movement | 7 | Lateral Movement, Execution, Credential Access | T1021.001, T1021.002, T1021.006, T1569.002, T1047, T1558.003 |
| `signal_log_tamper_detection` | Defense Impairment | 3 | Defense Impairment | T1685.005 |
| `signal_log_tampering` | Defense Impairment | 4 | Defense Impairment | T1685.001 |
| `signal_logon_anomaly` | Credential Access | 5 | Credential Access, Initial Access | T1110.001, T1110.003, T1078, T1133 |
| `signal_lolbin_abuse` | Stealth | 4 | Stealth, Execution | T1218, T1218.005, T1218.010, T1218.011, T1059.001 |
| `signal_mshta_abuse` | Stealth | 3 | Stealth | T1218.005 |
| `signal_net_command_abuse` | Discovery | 7 | Discovery, Persistence, Privilege Escalation, Lateral Movement, Stealth | T1069.002, T1087.002, T1135, T1136.001, T1098.007, T1098, T1021.002, T1070.005 |
| `signal_office_child_process` | Execution | 4 | Execution, Initial Access | T1204.002, T1566.001 |
| `signal_persistence_windows` | Persistence | 4 | Persistence, Privilege Escalation | T1547.001, T1546.003 |
| `signal_powershell_download` | Command and Control | 6 | Command and Control, Execution, Stealth, Persistence | T1105, T1059.001, T1197 |
| `signal_process_injection` | Stealth | 4 | Stealth, Privilege Escalation | T1055, T1055.001, T1055.012 |
| `signal_registry_persistence` | Persistence | 4 | Persistence, Privilege Escalation | T1547.001, T1546.012, T1547.004, T1543.003 |
| `signal_regsvr32_abuse` | Stealth | 3 | Stealth | T1218.010 |
| `signal_rundll32_abuse` | Stealth | 4 | Stealth, Credential Access | T1218.011, T1003.001 |
| `signal_sc_abuse` | Persistence | 5 | Persistence, Privilege Escalation, Defense Impairment, Lateral Movement | T1543.003, T1685, T1685.001, T1021.002 |
| `signal_schtasks_abuse` | Persistence | 5 | Persistence, Execution, Privilege Escalation | T1053.005 |
| `signal_security_tool_disable` | Defense Impairment | 6 | Defense Impairment, Stealth | T1685, T1685.001, T1686.003, T1564.012 |
| `signal_service_persistence` | Persistence | 3 | Persistence, Privilege Escalation, Execution | T1543.003, T1569.002 |
| `signal_task_persistence` | Persistence | 3 | Persistence, Execution, Privilege Escalation | T1053.005 |
| `signal_wmic_abuse` | Execution | 5 | Execution, Stealth, Impact, Defense Impairment | T1047, T1220, T1490, T1685 |
| `signal_wscript_cscript_abuse` | Execution | 4 | Execution | T1059.005, T1059.007 |

## Techniques

| ID | Name (ATT&CK v20.1) | Playbooks |
|----|---------------------|-----------|
| T1003.001 | OS Credential Dumping: LSASS Memory | `signal_credential_access`, `signal_rundll32_abuse` |
| T1003.002 | OS Credential Dumping: Security Account Manager | `signal_credential_access` |
| T1003.003 | OS Credential Dumping: NTDS | `signal_credential_access` |
| T1016 | System Network Configuration Discovery | `signal_discovery_burst` |
| T1021.001 | Remote Services: Remote Desktop Protocol | `signal_lateral_movement_detection` |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | `signal_lateral_movement_detection`, `signal_net_command_abuse`, `signal_sc_abuse` |
| T1021.006 | Remote Services: Windows Remote Management | `signal_lateral_movement_detection` |
| T1027.010 | Obfuscated Files or Information: Command Obfuscation | `signal_encoded_powershell` |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | `signal_certutil_abuse` |
| T1033 | System Owner/User Discovery | `signal_discovery_burst` |
| T1047 | Windows Management Instrumentation | `signal_lateral_movement_detection`, `signal_wmic_abuse` |
| T1049 | System Network Connections Discovery | `signal_discovery_burst` |
| T1053.005 | Scheduled Task/Job: Scheduled Task | `signal_schtasks_abuse`, `signal_task_persistence` |
| T1055 | Process Injection | `signal_process_injection` |
| T1055.001 | Process Injection: Dynamic-link Library Injection | `signal_process_injection` |
| T1055.012 | Process Injection: Process Hollowing | `signal_process_injection` |
| T1057 | Process Discovery | `signal_discovery_burst` |
| T1059.001 | Command and Scripting Interpreter: PowerShell | `signal_encoded_powershell`, `signal_lolbin_abuse`, `signal_powershell_download` |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | `signal_wscript_cscript_abuse` |
| T1059.007 | Command and Scripting Interpreter: JavaScript | `signal_wscript_cscript_abuse` |
| T1069 | Permission Groups Discovery | `signal_discovery_burst` |
| T1069.002 | Permission Groups Discovery: Domain Groups | `signal_net_command_abuse` |
| T1070.004 | Indicator Removal: File Deletion | `signal_certutil_abuse` |
| T1070.005 | Indicator Removal: Network Share Connection Removal | `signal_net_command_abuse` |
| T1074.001 | Data Staged: Local Data Staging | `signal_file_staging` |
| T1078 | Valid Accounts | `signal_logon_anomaly` |
| T1082 | System Information Discovery | `signal_discovery_burst` |
| T1087 | Account Discovery | `signal_discovery_burst` |
| T1087.002 | Account Discovery: Domain Account | `signal_net_command_abuse` |
| T1098 | Account Manipulation | `signal_net_command_abuse` |
| T1098.007 | Account Manipulation: Additional Local or Domain Groups | `signal_group_membership_change`, `signal_net_command_abuse` |
| T1105 | Ingress Tool Transfer | `signal_bitsadmin_abuse`, `signal_certutil_abuse`, `signal_powershell_download` |
| T1110.001 | Brute Force: Password Guessing | `signal_logon_anomaly` |
| T1110.003 | Brute Force: Password Spraying | `signal_logon_anomaly` |
| T1112 | Modify Registry | `signal_defense_evasion` |
| T1133 | External Remote Services | `signal_logon_anomaly` |
| T1135 | Network Share Discovery | `signal_net_command_abuse` |
| T1136 | Create Account | `signal_group_membership_change` |
| T1136.001 | Create Account: Local Account | `signal_net_command_abuse` |
| T1140 | Deobfuscate/Decode Files or Information | `signal_certutil_abuse` |
| T1197 | BITS Jobs | `signal_bitsadmin_abuse`, `signal_powershell_download` |
| T1204.002 | User Execution: Malicious File | `signal_office_child_process` |
| T1218 | System Binary Proxy Execution | `signal_lolbin_abuse` |
| T1218.005 | System Binary Proxy Execution: Mshta | `signal_lolbin_abuse`, `signal_mshta_abuse` |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | `signal_lolbin_abuse`, `signal_regsvr32_abuse` |
| T1218.011 | System Binary Proxy Execution: Rundll32 | `signal_lolbin_abuse`, `signal_rundll32_abuse` |
| T1220 | XSL Script Processing | `signal_wmic_abuse` |
| T1482 | Domain Trust Discovery | `signal_discovery_burst` |
| T1490 | Inhibit System Recovery | `signal_wmic_abuse` |
| T1543.003 | Create or Modify System Process: Windows Service | `signal_registry_persistence`, `signal_sc_abuse`, `signal_service_persistence` |
| T1546.003 | Event Triggered Execution: Windows Management Instrumentation Event Subscription | `signal_persistence_windows` |
| T1546.012 | Event Triggered Execution: Image File Execution Options Injection | `signal_registry_persistence` |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | `signal_persistence_windows`, `signal_registry_persistence` |
| T1547.004 | Boot or Logon Autostart Execution: Winlogon Helper DLL | `signal_registry_persistence` |
| T1555.004 | Credentials from Password Stores: Windows Credential Manager | `signal_credential_access` |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | `signal_lateral_movement_detection` |
| T1560.001 | Archive Collected Data: Archive via Utility | `signal_file_staging` |
| T1564.003 | Hide Artifacts: Hidden Window | `signal_encoded_powershell` |
| T1564.012 | Hide Artifacts: File/Path Exclusions | `signal_security_tool_disable` |
| T1566.001 | Phishing: Spearphishing Attachment | `signal_office_child_process` |
| T1569.002 | System Services: Service Execution | `signal_lateral_movement_detection`, `signal_service_persistence` |
| T1574.001 | Hijack Execution Flow: DLL | `signal_dll_side_loading` |
| T1615 | Group Policy Discovery | `signal_discovery_burst` |
| T1620 | Reflective Code Loading | `signal_encoded_powershell` |
| T1685 | Disable or Modify Tools | `signal_defense_evasion`, `signal_sc_abuse`, `signal_security_tool_disable`, `signal_wmic_abuse` |
| T1685.001 | Disable or Modify Tools: Disable or Modify Windows Event Log | `signal_defense_evasion`, `signal_log_tampering`, `signal_sc_abuse`, `signal_security_tool_disable` |
| T1685.005 | Disable or Modify Tools: Clear Windows Event Logs | `signal_defense_evasion`, `signal_log_tamper_detection` |
| T1686.003 | Disable or Modify System Firewall: Windows Host Firewall | `signal_security_tool_disable` |

## Rules

Every rule below has at least one fixture in `testdata/playbooks/windows/` that makes
it fire, and every playbook has near miss fixtures that must not fire.

### BITSAdmin LOLBin Abuse (`signal_bitsadmin_abuse`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| BITSAdmin Download | HIGH | Exec | single event | T1197, T1105 |
| BITSAdmin Add File | MEDIUM | Exec | single event | T1197 |
| BITSAdmin Create Job | MEDIUM | Exec | single event | T1197 |
| BITSAdmin Notify Command | HIGH | Exec | single event | T1197 |

### CertUtil LOLBin Abuse (`signal_certutil_abuse`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| CertUtil Download | HIGH | Exec | single event | T1105 |
| CertUtil Decode Operation | MEDIUM | Exec | single event | T1140 |
| CertUtil Encode Operation | MEDIUM | Exec | single event | T1027.013 |
| CertUtil Cache Clear | HIGH | Exec | single event | T1070.004 |

### Credential Access Detection (`signal_credential_access`)

Telemetry:

- Security 4688 with command line, or Sysmon 1
- Sysmon 10 for LSASS access

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| LSASS Dump Tool | CRITICAL | Exec | single event | T1003.001 |
| Comsvcs LSASS Dump | CRITICAL | Exec | single event | T1003.001 |
| LSASS Process Access | CRITICAL | MemAlloc | single event | T1003.001 |
| SAM Registry Export | CRITICAL | Exec | single event | T1003.002 |
| NTDS Access | CRITICAL | Exec | single event | T1003.003 |
| Credential Manager Query | MEDIUM | Exec | count 3 in 60s | T1555.004 |

### Defense Impairment Detection (Windows) (`signal_defense_evasion`)

Telemetry:

- Security 1102
- Security 4688 with command line, or Sysmon 1
- Sysmon 13 and Sysmon 23 for registry and delete events

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Security Log Cleared | CRITICAL | LogTamper | single event | T1685.005 |
| Defender Disabled by Command | CRITICAL | Exec | single event | T1685 |
| Event Log Settings Changed | HIGH | RegistryMod | single event | T1685.001, T1112 |
| Event Log File Deleted | HIGH | DeletePath | single event | T1685.005 |

### Discovery Command Burst (`signal_discovery_burst`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| User Discovery Burst | HIGH | Exec | count 3 distinct cmdline in 60s | T1033, T1087, T1069 |
| Network Discovery Burst | MEDIUM | Exec | count 3 distinct cmdline in 60s | T1016, T1049 |
| Domain Discovery Burst | HIGH | Exec | count 2 distinct cmdline in 60s | T1087, T1069, T1482, T1615 |
| Combined Discovery Activity | CRITICAL | Exec | count 5 distinct image in 300s | T1082, T1033, T1016, T1057, T1087 |

### DLL Side-Loading Detection (`signal_dll_side_loading`)

Telemetry:

- Sysmon 7 (image load)

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| DLL Loaded from Temp Directory | HIGH | ModuleLoad | single event | T1574.001 |
| Unsigned DLL from User Writable Path | MEDIUM | ModuleLoad | single event | T1574.001 |

### Encoded PowerShell Execution (`signal_encoded_powershell`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Base64 Encoded Command | HIGH | Exec | single event | T1059.001, T1027.010 |
| Download Cradle Pattern | CRITICAL | Exec | single event | T1059.001 |
| Hidden Window With Encoded Command | CRITICAL | Exec | single event | T1059.001, T1564.003, T1027.010 |
| Reflection Assembly Load | CRITICAL | Exec | single event | T1059.001, T1620 |

### File Staging Detection (`signal_file_staging`)

Telemetry:

- Security 4688 with command line, or Sysmon 1
- Sysmon 11 for file creation

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Archive Utility Execution | MEDIUM | Exec | single event | T1560.001 |
| PowerShell Compress-Archive | MEDIUM | Exec | single event | T1560.001 |
| Archive Created in Temp | HIGH | Exec | single event | T1560.001, T1074.001 |
| Password Protected Archive | HIGH | Exec | single event | T1560.001 |
| Archive Written to Staging Folder | MEDIUM | CreatePath | single event | T1074.001 |

### Sensitive Group Membership Change (`signal_group_membership_change`)

Telemetry:

- Security 4720, 4728, 4732 and 4756 (account management auditing)

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Admin Group Member Added | CRITICAL | AuthEvent | single event | T1098.007 |
| Enterprise or Schema Admin Added | CRITICAL | AuthEvent | single event | T1098.007 |
| Remote Desktop Users Added | MEDIUM | AuthEvent | single event | T1098.007 |
| Backup Operators Added | HIGH | AuthEvent | single event | T1098.007 |
| User Account Created | MEDIUM | AuthEvent | single event | T1136 |

### Windows Lateral Movement Detection (`signal_lateral_movement_detection`)

Telemetry:

- Security 4624, 4769, 5140 and 5145
- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Remote RDP Logon | MEDIUM | AuthEvent | single event | T1021.001 |
| Administrative Share Access | HIGH | AuthEvent | single event | T1021.002 |
| Kerberoasting Ticket Burst | HIGH | AuthEvent | count 5 distinct ServiceName in 60s | T1558.003 |
| PsExec Service Execution | CRITICAL | Exec | single event | T1569.002, T1021.002 |
| WMI Remote Process Execution | HIGH | Exec | single event | T1047 |
| WinRM Remote Shell | HIGH | Exec | single event | T1021.006 |
| RDP Logon Followed by Shell | HIGH | AuthEvent then Exec | sequence, 300s | T1021.001 |

### Windows Event Log Clearing (`signal_log_tamper_detection`)

Telemetry:

- Security 1102
- System 104
- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Event Log Cleared | CRITICAL | LogTamper | single event | T1685.005 |
| Log Clear Command | CRITICAL | Exec | single event | T1685.005 |
| Shell Followed by Log Clear | CRITICAL | Exec then LogTamper | sequence, 300s | T1685.005 |

### Windows Event Logging Disabled (`signal_log_tampering`)

Telemetry:

- Security 4688 with command line, or Sysmon 1
- Security 4719 (policy change auditing)

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| EventLog Service Stopped or Disabled | HIGH | Exec | single event | T1685.001 |
| Event Log Channel Disabled | HIGH | Exec | single event | T1685.001 |
| Audit Policy Cleared or Disabled | CRITICAL | Exec | single event | T1685.001 |
| Audit Policy Changed | HIGH | SecurityToolDisable | single event | T1685.001 |

### Anomalous Logon Detection (`signal_logon_anomaly`)

Telemetry:

- Security 4624 and 4625 (logon auditing)

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Failed Logon Burst | HIGH | AuthEvent | count 5 in 300s | T1110.001 |
| Password Spray | HIGH | AuthEvent | count 5 distinct user in 300s | T1110.003 |
| Multiple Logon Sources | MEDIUM | AuthEvent | count 3 distinct source_ip in 3600s | T1078 |
| Service Account Interactive Logon | HIGH | AuthEvent | single event | T1078 |
| RDP From Public IP | CRITICAL | AuthEvent | single event | T1133, T1078 |

### LOLBin Abuse Detection (`signal_lolbin_abuse`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Mshta Proxy Execution | HIGH | ShellCommand | single event | T1218, T1218.005 |
| Regsvr32 Proxy Execution | HIGH | ShellCommand | single event | T1218, T1218.010 |
| Rundll32 Proxy Execution | HIGH | ShellCommand | single event | T1218, T1218.011 |
| PowerShell With Evasion Flags | HIGH | ShellCommand | single event | T1059.001 |

### MSHTA LOLBin Abuse (`signal_mshta_abuse`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| MSHTA Inline Script | CRITICAL | Exec | single event | T1218.005 |
| MSHTA Remote URL | CRITICAL | Exec | single event | T1218.005 |
| MSHTA About Protocol | HIGH | Exec | single event | T1218.005 |

### Net Command Abuse (`signal_net_command_abuse`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Net Domain Group Enumeration | MEDIUM | Exec | single event | T1069.002, T1087.002 |
| Net User Add | HIGH | Exec | single event | T1136.001 |
| Net Localgroup Add | HIGH | Exec | single event | T1098.007 |
| Net Share Enumeration | MEDIUM | Exec | count 2 distinct cmdline in 60s | T1135 |
| Net Use to Admin Share | HIGH | Exec | single event | T1021.002 |
| Net Session or Connection Delete | MEDIUM | Exec | single event | T1070.005 |
| Net User Password Reset | HIGH | Exec | single event | T1098 |

### Office Application Child Process (`signal_office_child_process`)

Telemetry:

- Sysmon 1, or Security 4688 with parent process name (Windows 10 and later)

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Office Spawns Shell | CRITICAL | Exec | single event | T1204.002, T1566.001 |
| Office Spawns Script Engine | CRITICAL | Exec | single event | T1204.002, T1566.001 |
| Office Spawns LOLBin | CRITICAL | Exec | single event | T1204.002, T1566.001 |
| Outlook Spawns Process | CRITICAL | Exec | single event | T1566.001 |

### Autostart Persistence (Windows) (`signal_persistence_windows`)

Telemetry:

- Sysmon 11, 13, 20 and 21

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Run Key Points to Script or Temp Path | HIGH | RegistryMod | single event | T1547.001 |
| File Dropped in Startup Folder | MEDIUM | CreatePath | single event | T1547.001 |
| WMI Event Consumer Created | HIGH | PersistArtifact | single event | T1546.003 |
| WMI Filter to Consumer Binding | HIGH | PersistArtifact | single event | T1546.003 |

### PowerShell Download Activity (`signal_powershell_download`)

Telemetry:

- Security 4688 with command line, or Sysmon 1
- PowerShell 4104 script block logging

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| PowerShell DownloadString | HIGH | Exec | single event | T1105, T1059.001 |
| PowerShell DownloadFile | HIGH | Exec | single event | T1105, T1059.001 |
| PowerShell Invoke-WebRequest | MEDIUM | Exec | single event | T1105, T1059.001 |
| PowerShell IEX Download Cradle | CRITICAL | Exec | single event | T1105, T1059.001 |
| PowerShell Start-BitsTransfer | HIGH | Exec | single event | T1105, T1197 |
| Script Block Download | HIGH | ScriptExec | single event | T1105, T1059.001 |

### Process Injection Detection (`signal_process_injection`)

Telemetry:

- Sysmon 8 and Sysmon 25

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Remote Thread Creation | HIGH | Injection | single event | T1055, T1055.001 |
| Injection into System Process | CRITICAL | Injection | single event | T1055, T1055.001 |
| Injection from User Writable Path | CRITICAL | Injection | single event | T1055, T1055.001 |
| Process Image Tampering | HIGH | Injection | single event | T1055.012 |

### Windows Registry Persistence (`signal_registry_persistence`)

Telemetry:

- Sysmon 12, 13 and 14, or Security 4657 with registry auditing

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Run or RunOnce Key Modified | HIGH | RegistryMod | single event | T1547.001 |
| IFEO Debugger Set | CRITICAL | RegistryMod | single event | T1546.012 |
| Winlogon Value Changed | CRITICAL | RegistryMod | single event | T1547.004 |
| Service Path Changed Outside the Service Manager | HIGH | RegistryMod | single event | T1543.003 |

### Regsvr32 LOLBin Abuse (`signal_regsvr32_abuse`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Regsvr32 Squiblydoo | CRITICAL | Exec | single event | T1218.010 |
| Regsvr32 Remote Scriptlet | CRITICAL | Exec | single event | T1218.010 |
| Regsvr32 From User Writable Path | HIGH | Exec | single event | T1218.010 |

### Rundll32 LOLBin Abuse (`signal_rundll32_abuse`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Rundll32 JavaScript Execution | CRITICAL | Exec | single event | T1218.011 |
| Rundll32 URL or Shell Handler | HIGH | Exec | single event | T1218.011 |
| Rundll32 Comsvcs MiniDump | CRITICAL | Exec | single event | T1218.011, T1003.001 |
| Rundll32 DLL From User Writable Path | HIGH | Exec | single event | T1218.011 |

### SC Service Manipulation (`signal_sc_abuse`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Service Creation | HIGH | Exec | single event | T1543.003 |
| Security Service Stopped or Disabled | CRITICAL | Exec | single event | T1685, T1685.001 |
| Service Binary Path Changed | HIGH | Exec | single event | T1543.003 |
| Remote Service Creation | CRITICAL | Exec | single event | T1543.003, T1021.002 |
| Service Binary in User Writable Path | CRITICAL | Exec | single event | T1543.003 |

### Schtasks Persistence Abuse (`signal_schtasks_abuse`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Task Created to Run as SYSTEM | HIGH | Exec | single event | T1053.005 |
| Remote Task Creation | CRITICAL | Exec | single event | T1053.005 |
| Logon or Startup Task Runs a Shell | HIGH | Exec | single event | T1053.005 |
| Task Running PowerShell | HIGH | Exec | single event | T1053.005 |
| Task Running from User Writable Path | CRITICAL | Exec | single event | T1053.005 |

### Security Tool Disable (`signal_security_tool_disable`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Disable Windows Defender | CRITICAL | Exec | single event | T1685 |
| Defender Exclusion Added | HIGH | Exec | single event | T1564.012 |
| Disable Windows Firewall | HIGH | Exec | single event | T1686.003 |
| Stop Event Log Service | CRITICAL | Exec | single event | T1685.001 |
| AMSI Bypass Attempt | CRITICAL | Exec | single event | T1685 |
| Security Process Killed | CRITICAL | Exec | single event | T1685 |

### Windows Service Installation (`signal_service_persistence`)

Telemetry:

- System 7045, or Security 4697 (security system extension auditing)

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Service With Shell Command Line | HIGH | PersistArtifact | single event | T1543.003 |
| Service Binary in User Writable Path | CRITICAL | PersistArtifact | single event | T1543.003 |
| Remote Admin Tool Service | HIGH | PersistArtifact | single event | T1543.003, T1569.002 |

### Windows Task Scheduler Persistence (`signal_task_persistence`)

Telemetry:

- Security 4698 and 4702 (other object access auditing)

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Scheduled Task Created With Suspicious Action | HIGH | PersistArtifact | single event | T1053.005 |
| Scheduled Task Updated With Suspicious Action | MEDIUM | PersistArtifact | single event | T1053.005 |
| Hidden Scheduled Task | HIGH | PersistArtifact | single event | T1053.005 |

### WMIC LOLBin Abuse (`signal_wmic_abuse`)

Telemetry:

- Security 4688 with command line, or Sysmon 1

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| WMIC Process Creation | HIGH | Exec | single event | T1047 |
| WMIC XSL Script Execution | CRITICAL | Exec | single event | T1220 |
| WMIC Shadow Copy Delete | CRITICAL | Exec | single event | T1490 |
| WMIC Remote Execution | HIGH | Exec | single event | T1047 |
| WMIC Product Uninstall | MEDIUM | Exec | single event | T1685 |

### Windows Script Host Abuse (`signal_wscript_cscript_abuse`)

Telemetry:

- Sysmon 1, or Security 4688 with command line and parent process name

| Rule | Severity | Fact | Shape | Techniques |
|------|----------|------|-------|------------|
| Script Host Spawned by Office | CRITICAL | Exec | single event | T1059.005, T1059.007 |
| Script From User Writable Path | HIGH | Exec | single event | T1059.005, T1059.007 |
| Script From URL or Network Share | MEDIUM | Exec | single event | T1059.005, T1059.007 |
| Script Engine Spawns PowerShell | HIGH | Exec | single event | T1059.005, T1059.007 |

## ATT&CK v20.1 Migration Notes

ATT&CK v19 split Defense Evasion (TA0005) into Stealth (TA0005, same ID) and Defense
Impairment (TA0112), and revoked several techniques. The loader rejects these old IDs and
names the replacement:

| Revoked ID | Replaced by | Name now |
|------------|-------------|----------|
| T1070.001 | T1685.005 | Disable or Modify Tools: Clear Windows Event Logs |
| T1562 | T1685 | Disable or Modify Tools |
| T1562.001 | T1685 | Disable or Modify Tools |
| T1562.002 | T1685.001 | Disable or Modify Tools: Disable or Modify Windows Event Log |
| T1562.004 | T1686 (this repo uses T1686.003) | Disable or Modify System Firewall: Windows Host Firewall |
| T1562.006 | T1685 | Disable or Modify Tools |
| T1574.002 | T1574.001 | Hijack Execution Flow: DLL |
| T1089 | T1685 | Disable or Modify Tools |
| T1084 | T1546.003 | Event Triggered Execution: Windows Management Instrumentation Event Subscription |

Other mapping fixes made during the migration:

- `signal_wmic_abuse` lists Impact, because shadow copy deletion is Inhibit System
  Recovery (T1490) and that technique sits only under Impact.
- `signal_mshta_abuse`, `signal_regsvr32_abuse` and `signal_rundll32_abuse` no longer
  list Execution. Their T1218 sub-techniques sit only under Stealth.
- `signal_sc_abuse` maps stopping security services to T1685 Disable or Modify Tools
  instead of the old T1562.001 and its retired name.
- The 4769 burst in `signal_lateral_movement_detection` is now a Kerberoasting rule
  (T1558.003, Credential Access): one account asking for RC4 tickets for many different
  services in a minute. Pass the Ticket (T1550.003) was dropped because no rule detects it.
- Each playbook now lists only tactics that one of its techniques maps to, and every
  technique has at least one of its tactics listed. A test enforces both.

## Retired Compiled Playbooks

Before this change `edr-locald` ran 21 playbooks compiled into the binary from
`crates/locald/src/os/windows/playbooks.rs` and never read the YAML. That file is gone.
Each compiled playbook is covered by a YAML rule:

| Old compiled ID | Now covered by |
|-----------------|----------------|
| `windows_exec_lolbin_rundll32` | signal_rundll32_abuse |
| `windows_exec_powershell_download` | signal_powershell_download (Script Block Download) |
| `windows_exec_office_child` | signal_office_child_process |
| `windows_exec_script_host` | signal_wscript_cscript_abuse, signal_mshta_abuse |
| `windows_credential_lsass` | signal_credential_access (LSASS Process Access) |
| `windows_credential_procdump` | signal_credential_access (LSASS Dump Tool) |
| `windows_persist_service` | signal_service_persistence |
| `windows_persist_task` | signal_task_persistence |
| `windows_persist_registry_run` | signal_registry_persistence |
| `windows_persist_wmi` | signal_persistence_windows (WMI rules) |
| `windows_persist_startup` | signal_persistence_windows (File Dropped in Startup Folder) |
| `windows_log_tamper_clear` | signal_log_tamper_detection (Event Log Cleared) |
| `windows_log_tamper_utility` | signal_log_tamper_detection (Log Clear Command) |
| `windows_evasion_audit_disable` | signal_log_tampering (Audit Policy Changed) |
| `windows_evasion_defender_disable` | signal_security_tool_disable |
| `windows_lateral_rdp` | signal_lateral_movement_detection (Remote RDP Logon) |
| `windows_lateral_share` | signal_lateral_movement_detection (Administrative Share Access) |
| `windows_lateral_winrm` | signal_lateral_movement_detection (WinRM Remote Shell) |
| `windows_discovery_network` | signal_discovery_burst (Network Discovery Burst) |
| `windows_discovery_domain` | signal_discovery_burst (Domain Discovery Burst) |
| `windows_collection_archive` | signal_file_staging |

Several compiled playbooks matched on the fact type alone (for example any process start,
or any logon), so they fired on ordinary activity. The YAML rules match on command lines,
paths, event IDs and fields, and the near miss fixtures prove that ordinary activity stays
quiet.

## Playbook Format

```yaml
id: signal_example            # must equal the file name without .yaml
title: 'Example'
family: execution             # main tactic, used for grouping in the UI
severity: HIGH                # default for rules without their own
cooldown_seconds: 60          # quiet time per rule and group after a match
requires: ['Security 4688 with command line, or Sysmon 1']   # informational
mitre:
  attack_version: "20.1"
  tactics: [execution]
  techniques:
    - id: T1059.001
      name: 'Command and Scripting Interpreter: PowerShell'
rules:
  - name: 'Encoded command'
    severity: HIGH
    fact: Exec                  # fact type from the Windows fact extractor
    match:                      # every condition must hold
      - field: image
        equals: powershell.exe
      - field: cmdline
        regex: '(?i)\s-enc\s+\S{40,}'
    any: []                     # optional, at least one must hold
    exclude: []                 # optional, none may hold
    techniques: [T1059.001]     # optional subset of the playbook techniques
```

Rule shapes:

- Single event: no `threshold` and no `then`. One matching fact fires the rule.
- Count: `threshold: N` and `window_seconds: W`. Fires when N matching facts (or N
  distinct values of the `distinct` field) arrive within W seconds for one group.
- Sequence: `then:` holds a second step. Fires when a fact matching the first step is
  followed within `window_seconds` by a fact matching `then` for the same group.

`group_by` is `host` (default), `user`, `process` or a field name. Groups are always
scoped to one host. User names are compared without the domain, so `CORP\alice` and
`alice@corp.local` are the same user.

Condition operators: `regex`, `not_regex`, `equals`, `not_equals`, `in`, `not_in`,
`exists`. Each condition uses exactly one. `equals` and `in` ignore case. A condition on
a field the fact does not have is false, except `exists: false`, so negative operators
never fire on events that lack the field.

Fields: lowercase names are a fixed view over the fact (`path`, `image`, `cmdline`,
`parent_image`, `user`, `auth_type`, `source_ip`, `logon_type`, `event_id`, `key`,
`details`, `service_path`, `task_content`, `target_image`, `script_text` and others listed
in `crates/locald/src/playbook/fields.rs`). Any other name is read from the raw Windows
event, for example `TargetUserName`, `ShareName` or `TicketEncryptionType`. The capture
agent stores event data as XML, and `edr-locald` copies each `<Data Name=...>` element
into a field before the rules run.

Time comes from event timestamps, not the wall clock, so replaying old segments gives the
same signals as live capture.

The loader rejects a file that has an unknown key, a misspelled field name, a bad regex,
a fact type the Windows extractor never produces, a tactic name that is not in ATT&CK
v20.1, a revoked technique ID, or an id that does not match its file name. The rejected
file is reported and the others still load.

Sections named `false_positives`, `response` and `remediation` are analyst guidance. They
are parsed so the file stays valid but nothing executes them.

## Loading and Selection

`edr-locald` picks the first of these directories:

1. `EDR_PLAYBOOKS_DIR` (the desktop app sets this)
2. `EDR_PLAYBOOK_DIR` (older name, still accepted)
3. `<EDR_TELEMETRY_ROOT>/playbooks/windows` (where the scripts copy playbooks)
4. `playbooks/windows` next to the executable
5. `playbooks/windows` under the current directory

`EDR_SELECTED_PLAYBOOKS` is a comma separated list of playbook ids. The desktop picker
sends the file names it lists, which are the ids. When it is unset every playbook loads.
After loading, `edr-locald` writes `playbooks_loaded.json` into the telemetry root with the
directory, the selection, the ids that loaded, the rule count and any load errors. The
desktop app reads its `count` for the run metrics.

## Testing

- `crates/locald/tests/yaml_playbooks.rs` has one named test per playbook. Each runs the
  playbook fixtures through the same path as `edr-locald` (XML flattening, fact
  extraction, the engine). Every rule must fire on its fixture and every near miss must
  stay quiet. Other tests in the file check that all 30 files load, that the ATT&CK
  mappings follow v20.1, that selection works, and that the fixtures still fire with all
  playbooks loaded together.
- `crates/locald/tests/locald_yaml_e2e.rs` runs the `edr-locald` binary with `--once`
  on a small telemetry folder and checks the signals, explanations, evidence excerpts,
  the selection variable and the status file.

See [docs/facts_windows.md](facts_windows.md) for the event ID to fact type mapping.

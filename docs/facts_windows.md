# Windows Facts Reference

This document maps Windows event IDs to their canonical Fact types used by the detection pipeline.

## Event ID → Fact Type Mapping

### Process Events (FactType: Exec)

| Event ID | Source | Description |
|----------|--------|-------------|
| 4688 | Security | Process Creation |
| 1 | Sysmon | Process Create |

### Authentication Events (FactType: AuthEvent)

| Event ID | Source | Description |
|----------|--------|-------------|
| 4624 | Security | Successful Logon |
| 4625 | Security | Failed Logon |
| 4648 | Security | Explicit Credential Logon |
| 4634 | Security | Logoff |
| 4647 | Security | User Initiated Logoff |
| 4672 | Security | Special Privileges Assigned |

### Network Events (FactType: NetConn)

| Event ID | Source | Description |
|----------|--------|-------------|
| 3 | Sysmon | Network Connection |
| 5156 | Security | WFP Connection |
| 5158 | Security | WFP Bind |

### File Events (FactType: FileOp)

| Event ID | Source | Description |
|----------|--------|-------------|
| 11 | Sysmon | File Create |
| 23 | Sysmon | File Delete |
| 26 | Sysmon | File Delete Logged |
| 4663 | Security | Object Access |

### Registry Events (FactType: RegOp)

| Event ID | Source | Description |
|----------|--------|-------------|
| 12 | Sysmon | Registry Object Added/Deleted |
| 13 | Sysmon | Registry Value Set |
| 14 | Sysmon | Registry Key/Value Rename |
| 4657 | Security | Registry Value Modified |

### Process Access Events (FactType: MemRead)

| Event ID | Source | Description |
|----------|--------|-------------|
| 10 | Sysmon | Process Access |

### Module Load Events (FactType: ModuleLoad)

| Event ID | Source | Description |
|----------|--------|-------------|
| 7 | Sysmon | Image Loaded |

### DNS Events (FactType: DnsQuery)

| Event ID | Source | Description |
|----------|--------|-------------|
| 22 | Sysmon | DNS Query |

### Persistence Events (FactType: PersistArtifact)

| Event ID | Source | Description |
|----------|--------|-------------|
| 7045 | System | Service Installed |
| 106 | TaskScheduler | Task Registered |
| 141 | TaskScheduler | Task Deleted |
| 4698 | Security | Scheduled Task Created |
| 4699 | Security | Scheduled Task Deleted |

### WMI Events (FactType: WmiOp)

| Event ID | Source | Description |
|----------|--------|-------------|
| 19 | Sysmon | WMI Filter |
| 20 | Sysmon | WMI Consumer |
| 21 | Sysmon | WMI Consumer Binding |

### Log Tamper Events (FactType: LogTamper)

| Event ID | Source | Description |
|----------|--------|-------------|
| 1102 | Security | Audit Log Cleared |
| 104 | System | Event Log Cleared |
| 1100 | Security | Event Logging Service Shutdown |

### Defense Evasion Events (FactType: DefenseEvasion)

| Event ID | Source | Description |
|----------|--------|-------------|
| 4719 | Security | System Audit Policy Changed |
| 5001 | Defender | Real-time Protection Disabled |
| 5007 | Defender | Configuration Changed |

### Account Management Events (FactType: AccountOp)

| Event ID | Source | Description |
|----------|--------|-------------|
| 4720 | Security | User Account Created |
| 4722 | Security | User Account Enabled |
| 4728 | Security | Member Added to Security Group |
| 4732 | Security | Member Added to Local Group |

### Remote Desktop Events (FactType: RdpSession)

| Event ID | Source | Description |
|----------|--------|-------------|
| 21 | TerminalServices-LocalSessionManager | RDP Session Connected |
| 25 | TerminalServices-LocalSessionManager | RDP Session Reconnected |
| 4778 | Security | Session Reconnected |
| 4779 | Security | Session Disconnected |

### PowerShell Events (FactType: ScriptExec)

| Event ID | Source | Description |
|----------|--------|-------------|
| 4103 | PowerShell Operational | Module Logging |
| 4104 | PowerShell Operational | Script Block Logging |

## Tag Enrichment

Events are enriched with tags based on their characteristics:

### Process Tags
- `mitre:execution` - Process execution events
- `mitre:defense-evasion` - Events involving defense evasion
- `lolbin` - Living-off-the-land binaries
- `powershell` - PowerShell-related events
- `cmdline:suspicious` - Suspicious command line patterns

### Network Tags
- `mitre:command-and-control` - C2-related network activity
- `mitre:exfiltration` - Data exfiltration indicators
- `network:outbound` - Outbound network connections

### File Tags
- `mitre:collection` - Data collection indicators
- `mitre:persistence` - Persistence mechanisms
- `file:temp` - Temporary file operations
- `file:executable` - Executable file operations

### Registry Tags
- `mitre:persistence` - Persistence via registry
- `registry:run` - Run key modifications
- `registry:services` - Service registry changes

## Fact Extraction Functions

The following extraction functions are available in `fact_extractor.rs`:

| Function | Input Events | Output FactType |
|----------|--------------|-----------------|
| `extract_process_fact()` | 4688, Sysmon 1 | Exec |
| `extract_auth_fact()` | 4624, 4625, etc. | AuthEvent |
| `extract_network_fact()` | Sysmon 3, 5156 | NetConn |
| `extract_file_create_fact()` | Sysmon 11 | FileOp |
| `extract_file_delete_fact()` | Sysmon 23, 26 | FileOp |
| `extract_registry_fact()` | Sysmon 12/13/14 | RegOp |
| `extract_lsass_access_fact()` | Sysmon 10 | MemRead |
| `extract_module_load_fact()` | Sysmon 7 | ModuleLoad |
| `extract_dns_fact()` | Sysmon 22 | DnsQuery |
| `extract_powershell_fact()` | 4103, 4104 | ScriptExec |
| `extract_rdp_fact()` | 21, 25, 4778, 4779 | RdpSession |
| `extract_account_fact()` | 4720, 4722, 4728 | AccountOp |
| `extract_injection_fact()` | Sysmon 8 | Injection |

## Usage Example

```rust
use fact_extractor::{extract_fact, enrich_tags_from_event_id};

// Parse a Windows event
let event = parse_event(raw_json)?;

// Extract canonical fact
let fact = extract_fact(&event)?;

// Enrich with MITRE tags
let mut tags = vec![];
enrich_tags_from_event_id(event.event_id, &mut tags);
```

## See Also

- [Playbook Coverage](playbooks_windows_coverage.md) - Maps playbooks to required telemetry
- [UI Workflow](ui_workflow.md) - Using the detection engineer UI

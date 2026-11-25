# Windows Facts Reference

This document maps Windows event IDs to the canonical facts that the YAML playbooks read. The
code is `crates/locald/src/os/windows/fact_extractor.rs` and
`crates/locald/src/os/windows/event_xml.rs`.

## How an Event Becomes Facts

1. `edr-locald` reads a segment record. The capture agent stores the channel, event ID and
   provider as fields and the rest of the event as XML in `windows.xml`.
2. `flatten_event_xml` copies every `<Data Name="X">value</Data>` element, and the simple
   elements under `<UserData>` (event 1102 uses these), into named fields such as
   `CommandLine` or `TargetUserName`. Fields that already exist are not overwritten.
3. `extract_facts` adds a routing tag from `windows.event_id` (and the channel, for Sysmon,
   PowerShell and Terminal Services events). Tags already on the event route the same way.
4. Each routing tag calls one extractor, which returns zero or one fact.
5. Any process event whose image is a LOLBin and whose command line has a known abuse pattern
   also produces a `ShellCommand` fact.

## Event ID to Fact Type

| Event ID | Channel | Routing tag | Fact type | Notes |
|----------|---------|-------------|-----------|-------|
| 4688 | Security | `process_creation` | Exec | path from NewProcessName, cmdline from CommandLine |
| 1 | Sysmon | `process_creation` | Exec | path from Image, parent from ParentImage |
| 4624, 4648 | Security | `logon` | AuthEvent | logon type 2, 3, 5, 7, 10, 11 map to auth types |
| 4625 | Security | `logon` | AuthEvent | success is false |
| 4769 | Security | `kerberos_ticket` | AuthEvent | auth type `kerberos_service_ticket`, success from Status |
| 5140, 5145 | Security | `share_access` | AuthEvent | only for shares whose name ends in `$` |
| 4720, 4722, 4728, 4732, 4756 | Security | `account_created`, `account_enabled`, `group_member_added` | AuthEvent | auth type `account_management` |
| 21, 22, 25, 1149 | TerminalServices | `rdp_session`, `rdp_connection` | AuthEvent | auth type `remote_interactive` |
| 1102 | Security | `log_cleared` | LogTamper | action `clear` |
| 104 | System | `log_cleared` | LogTamper | action `clear` |
| 4719, 4713 | Security | `audit_policy`, `policy_change` | SecurityToolDisable | tool `Windows Audit Policy` |
| 7045 | System | `service_installed` | PersistArtifact | type `service`, ServiceName and ImagePath |
| 4697 | Security | `service_installed` | PersistArtifact | type `service`, ServiceName and ServiceFileName |
| 4698 to 4702 | Security | `scheduled_task` | PersistArtifact | type `scheduled_task`, TaskName and TaskContent |
| 4657 | Security | `registry_mod` | RegistryMod | key from ObjectName |
| 12, 13, 14 | Sysmon | `registry_mod` | RegistryMod | key from TargetObject, value from Details |
| 19, 20, 21 | Sysmon | `wmi_persistence` | PersistArtifact | WmiEventFilter, WmiEventConsumer, WmiFilterToConsumerBinding |
| 3 | Sysmon | `network_connection` | OutboundConnect | DestinationIp, DestinationPort |
| 17, 18 | Sysmon | `pipe_event` | OutboundConnect | named pipe, dst_ip is `pipe` |
| 22 | Sysmon | `dns_query` | DnsResolve | QueryName, QueryResults |
| 6, 7 | Sysmon | `driver_load`, `image_load` | ModuleLoad | ImageLoaded, Signature, is_kernel for 6 |
| 8 | Sysmon | `remote_thread` | Injection | type `remote_thread` |
| 25 | Sysmon | `process_tamper` | Injection | type `process_hollowing` |
| 10 | Sysmon | `credential_access` | MemAlloc | only when TargetImage is lsass.exe |
| 11 | Sysmon | `file_create` | CreatePath | TargetFilename |
| 23, 26 | Sysmon | `file_delete` | DeletePath | TargetFilename |
| 4103, 4104 | PowerShell Operational | `script_block` | ScriptExec | ScriptBlockText is readable as `script_text` |

Events that get a tag but no extractor today: 4724 (`password_reset`), 4771
(`kerberos_preauth_failed`), 7036 (`service_state`), Sysmon 2 (`file_time_changed`) and Sysmon
15 (`file_stream`).

## LOLBin ShellCommand Facts

`extract_lolbin_fact` emits a `ShellCommand` fact for these patterns, which
`signal_lolbin_abuse` turns into signals:

| Binary | Command line patterns |
|--------|-----------------------|
| powershell.exe, pwsh.exe | `-enc`, `downloadstring`, `iex`, `-ep bypass`, `-w hidden` |
| certutil.exe | `-urlcache`, `-decode`, `-encode` |
| mshta.exe | `vbscript:`, `javascript:`, `http` |
| rundll32.exe | `javascript:`, `comsvcs`, `url.dll` |
| regsvr32.exe | `/i:http`, `scrobj` |
| wmic.exe | `process call create`, `/format:`, `shadowcopy delete` |
| schtasks.exe | `/create` with `/ru system` or `powershell` |
| sc.exe | `create` with `binpath`, or `stop` of windefend, eventlog or sense |

## Fields Playbooks Can Read

Rules name fields, not fact internals. Lowercase names are a fixed view over the fact, for
example `path`, `image`, `cmdline`, `parent_image`, `user`, `auth_type`, `source_ip`,
`logon_type`, `event_id`, `key`, `details`, `service_path`, `task_content`, `target_image`,
`granted_access` and `script_text`. The full list is `VIEW_FIELDS` in
`crates/locald/src/playbook/fields.rs`. Any other name is read from the raw event fields by
its Windows name, for example `TargetUserName`, `ShareName` or `TicketEncryptionType`.

## See Also

- [Playbook Coverage](playbooks_windows_coverage.md): the playbook format, every rule and its
  ATT&CK mapping
- [UI Workflow](ui_workflow.md): using the detection engineer UI

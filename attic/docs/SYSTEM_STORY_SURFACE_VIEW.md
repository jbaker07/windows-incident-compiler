# System Story Surface View

> **Audit Date**: 2024 | **Scope**: Evidence Graph Contract + Coverage Matrix  
> **Purpose**: Document what "evidence" we can reconstruct from real capture and what gaps remain

---

## 1. Evidence Graph Contract (MVP)

The Evidence Graph is the narrative structure we aim to reconstruct from raw telemetry. It defines **what happened**, **who did it**, **to what**, and **when**.

### 1.1 Entity Types (Nodes)

| Entity | Key Field | Description | Source Files |
|--------|-----------|-------------|--------------|
| **Process** | `proc_key` (exe+pid+start_ts) | An executing program | Sysmon 1, Security 4688 |
| **File** | `path` | A filesystem object | Sysmon 11/23/26, Security 4663 |
| **Network** | `dst_ip:dst_port` | A network endpoint | Sysmon 3, Security 5156 |
| **User** | `identity_key` (domain\\user) | An authenticated identity | Security 4624/4625 |
| **Host** | `host_id` | A machine/endpoint | All events |
| **Registry** | `key\\value` | Windows registry path | Sysmon 12-14, Security 4657 |
| **Service** | `service_name` | A Windows service | System 7045, Security 4697 |
| **Task** | `task_name` | A scheduled task | Security 4698, TaskScheduler 106 |

### 1.2 Edge Types (Relationships)

| Edge | From → To | FactType | Required Fields | Evidence |
|------|-----------|----------|-----------------|----------|
| **spawned** | Process → Process | `ProcSpawn` | parent_proc_key, child_proc_key | Sysmon 1 |
| **executed** | User → Process | `Exec` | identity_key, exe_path, cmdline | 4688, Sysmon 1 |
| **connected** | Process → Network | `OutboundConnect` | proc_key, dst_ip, dst_port, proto | Sysmon 3, 5156 |
| **accepted** | Network → Process | `InboundConnect` | src_ip, src_port, proc_key | Sysmon 3 |
| **resolved** | Process → DNS | `DnsResolve` | proc_key, query, responses | Sysmon 22 |
| **wrote** | Process → File | `WritePath` | proc_key, path, bytes | Sysmon 11 (create), inferred |
| **read** | Process → File | `ReadPath` | proc_key, path | Sysmon (no direct event) |
| **created** | Process → File | `CreatePath` | proc_key, path | Sysmon 11 |
| **deleted** | Process → File | `DeletePath` | proc_key, path | Sysmon 23/26 |
| **renamed** | Process → File | `RenamePath` | proc_key, old_path, new_path | (gap) |
| **loaded** | Process → Module | `ModuleLoad` | proc_key, dll_path, hash, signer | Sysmon 7 |
| **modified** | Process → Registry | `RegistryMod` | proc_key, key, value, operation | Sysmon 13, 4657 |
| **persisted** | Process → Artifact | `PersistArtifact` | proc_key, artifact_type, path_or_key | 7045, 4698, Sysmon 19-21 |
| **logged_on** | User → Host | `AuthEvent` | user, host, logon_type, success | 4624, 4625 |
| **injected** | Process → Process | `Injection` | source_proc_key, target_proc_key, type | Sysmon 8, 10 |
| **cleared** | Process → Log | `LogTamper` | proc_key, log_type, action | 1102, 104 |
| **ran_script** | Process → Script | `ScriptExec` | proc_key, interpreter, content_hash | 4103, 4104 |
| **ran_shell** | Process → Command | `ShellCommand` | proc_key, shell, command | cmdline patterns |

### 1.3 Required Fields Per FactType

```
ProcSpawn:      parent_proc_key, child_proc_key
Exec:           exe_path, cmdline*, hash*, signer*
OutboundConnect: dst_ip, dst_port, proto, sock_id*
InboundConnect:  src_ip, src_port, proto
DnsResolve:     query, responses
WritePath:      path, inode*, bytes*, entropy*
ReadPath:       path, inode*, bytes*
CreatePath:     path, inode*
DeletePath:     path, inode*
RenamePath:     old_path, new_path
PersistArtifact: artifact_type, path_or_key, enable_action
ModuleLoad:     path, hash*, signer*, is_kernel
Injection:      source_proc_key, target_proc_key, injection_type
RegistryMod:    key, value_name*, operation
AuthEvent:      auth_type, user, source*, success
LogTamper:      log_type, action
ScriptExec:     interpreter, script_path*, content_hash*
ShellCommand:   shell, command, is_encoded

(* = optional/enrichment field)
```

---

## 2. Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CAPTURE LAYER                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  wevt_reader.rs (agent-windows)                                              │
│  ├── Security (ENABLED)       → 4624, 4625, 4688, 1102, 4698, 4719, 5156... │
│  ├── System (ENABLED)         → 7045, 7036                                  │
│  ├── Sysmon (ENABLED)         → 1-26                                        │
│  ├── PowerShell (DISABLED)    → 4103, 4104                                  │
│  ├── WMI-Activity (DISABLED)  → WMI events                                  │
│  └── TaskScheduler (DISABLED) → 106, 141                                    │
│                                                                              │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NORMALIZATION LAYER                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  attack_surface.rs (sensors)                                                 │
│  ├── Event ID routing → CanonicalEvent types                                │
│  ├── Sysmon 1 / 4688  → proc_exec                                           │
│  ├── Security 4672    → priv_escalation                                     │
│  ├── Sysmon 10        → proc_access (credential_access)                     │
│  ├── Defender 1121    → asr_block                                           │
│  ├── Sysmon 19-21     → wmi_persistence                                     │
│  ├── 7045 / 4697      → persistence_service                                 │
│  ├── 4698 / 4702      → persistence_task                                    │
│  ├── 1102             → log_clear                                           │
│  └── 4624 (Type 3/10) → remote_logon                                        │
│                                                                              │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FACT EXTRACTION LAYER                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  fact_extractor.rs (locald/os/windows)                                       │
│  ├── enrich_tags_from_event_id() maps 50+ Event IDs → detection tags        │
│  │   Security: 1102→log_cleared, 4624→logon, 4625→logon_failed,            │
│  │             4688→process_creation, 4657→registry_mod, 4698→scheduled_task│
│  │   Sysmon:   1→process_creation, 3→network_connection, 7→image_load,     │
│  │             8→remote_thread, 10→credential_access, 11→file_create,      │
│  │             12-14→registry_mod, 22→dns_query, 23/26→file_delete         │
│  │                                                                          │
│  ├── Tag→Extractor routing:                                                 │
│  │   process_creation  → extract_process_fact()  → Exec                     │
│  │   network_connection→ extract_network_fact()  → OutboundConnect          │
│  │   logon             → extract_auth_fact()     → AuthEvent                │
│  │   log_cleared       → extract_log_tamper_fact()→ LogTamper               │
│  │   service_installed → extract_service_fact()  → PersistArtifact          │
│  │   scheduled_task    → extract_task_fact()     → PersistArtifact          │
│  │   registry_mod      → extract_registry_fact() → RegistryMod              │
│  │   wmi_persistence   → extract_wmi_fact()      → PersistArtifact          │
│  │   credential_access → extract_lsass_fact()    → Injection                │
│  │   script_block      → extract_powershell_fact()→ ScriptExec              │
│  │   file_create       → extract_file_create_fact()→ CreatePath             │
│  │   file_delete       → extract_file_delete_fact()→ DeletePath             │
│  │   dns_query         → extract_dns_fact()      → DnsResolve               │
│  │   image_load        → extract_module_load_fact()→ ModuleLoad             │
│  │   remote_thread     → extract_injection_fact()→ Injection                │
│  │   rdp_session       → extract_rdp_fact()      → AuthEvent                │
│  │   account_*         → extract_account_fact()  → (AccountOp - not in enum)│
│  │   pipe_event        → extract_pipe_fact()     → (custom)                 │
│  │                                                                          │
│  └── LOLBin secondary enrichment → ShellCommand                             │
│                                                                              │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PLAYBOOK MATCHING LAYER                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  slot_matcher.rs (locald)                                                    │
│  ├── PlaybookIndex: fact_type → [playbook_id] fast lookup                   │
│  ├── SlotMatcher: predicate evaluation (path_glob, exe_filter, port_range)  │
│  ├── CapabilityGate: Hard/Soft/Unavailable fact categorization              │
│  │   HARD: Exec, ProcSpawn, OutboundConnect, WritePath, ModuleLoad...       │
│  │   SOFT: DnsResolve, AuthEvent                                            │
│  │                                                                          │
│  └── Output: SignalResult with matched facts + evidence pointers            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Coverage Matrix

### 3.1 FactType → Event Source Coverage

| FactType | Sysmon | Security | System | PowerShell | Defender | TaskSched | RDP |
|----------|:------:|:--------:|:------:|:----------:|:--------:|:---------:|:---:|
| **ProcSpawn** | ✅ 1 | ⚠️ 4688* | - | - | - | - | - |
| **Exec** | ✅ 1 | ✅ 4688 | - | - | - | - | - |
| **OutboundConnect** | ✅ 3 | ✅ 5156 | - | - | - | - | - |
| **InboundConnect** | ✅ 3 | ✅ 5156 | - | - | - | - | - |
| **DnsResolve** | ✅ 22 | - | - | - | - | - | - |
| **WritePath** | ⚠️ 11† | - | - | - | - | - | - |
| **ReadPath** | ❌ | ⚠️ 4663‡ | - | - | - | - | - |
| **CreatePath** | ✅ 11 | - | - | - | - | - | - |
| **DeletePath** | ✅ 23,26 | - | - | - | - | - | - |
| **RenamePath** | ❌ | - | - | - | - | - | - |
| **PersistArtifact** | ✅ 19-21 | ✅ 4698 | ✅ 7045 | - | - | ⚠️ 106§ | - |
| **ModuleLoad** | ✅ 7 | - | - | - | - | - | - |
| **Injection** | ✅ 8 | - | - | - | - | - | - |
| **RegistryMod** | ✅ 12-14 | ✅ 4657 | - | - | - | - | - |
| **AuthEvent** | - | ✅ 4624/25 | - | - | - | - | ✅ 21,25 |
| **LogTamper** | - | ✅ 1102 | ✅ 104 | - | - | - | - |
| **ScriptExec** | - | - | - | ⚠️ 4103/04§ | - | - | - |
| **ShellCommand** | ⚠️¶ | ⚠️¶ | - | - | - | - | - |
| **PrivilegeBoundary** | - | ✅ 4672 | - | - | - | - | - |
| **MemWX** | ❌ | - | - | - | - | - | - |
| **MemAlloc** | ❌ | - | - | - | - | - | - |
| **SecurityToolDisable** | - | - | - | - | ⚠️ 5001§ | - | - |

**Legend:**
- ✅ = Fully mapped and extracted
- ⚠️ = Partial/conditional support
- ❌ = No source available
- § = Channel disabled by default in wevt_reader
- † = Sysmon 11 is file create, not write content
- ‡ = 4663 requires advanced audit policy
- ¶ = Derived from cmdline patterns, not direct event
- * = 4688 lacks parent_proc_key (only Sysmon 1 has it)

### 3.2 Channel Enable Status

| Channel | Default | Playbooks Needing |
|---------|:-------:|-------------------|
| Security | ✅ ON | 12+ playbooks |
| System | ✅ ON | persistence_service_install |
| Sysmon | ✅ ON | 18+ playbooks |
| **PowerShell Operational** | ❌ OFF | execution_lolbin_powershell_download, ScriptExec |
| **WMI-Activity** | ❌ OFF | wmi correlation |
| **TaskScheduler** | ❌ OFF | persistence_scheduled_task (fallback) |
| **TerminalServices** | ❌ OFF | lateral_movement_rdp |
| **Defender** | ❌ OFF | defense_evasion_defender_disable |

### 3.3 Playbook → Required Telemetry Gap Analysis

| Playbook | Required Sources | Current Status | Gap |
|----------|------------------|----------------|-----|
| `execution_lolbin_powershell_download` | PowerShell 4103/4104, Sysmon 1 | Sysmon ✅, PowerShell ❌ | **PowerShell OFF** |
| `persistence_scheduled_task` | TaskScheduler 106/141, Security 4698 | Security ✅, TaskSched ❌ | Works via 4698 fallback |
| `lateral_movement_rdp` | Security 4624 (Type 10), TerminalServices | Security ✅, TS ❌ | Partial (4624 works) |
| `defense_evasion_defender_disable` | Sysmon 1, Defender 5001 | Sysmon ✅, Defender ❌ | **Defender OFF** |
| `lateral_movement_winrm` | Sysmon 1, WinRM 91 | Sysmon ✅, WinRM ❌ | **WinRM OFF** |
| `credential_lsass_access` | Sysmon 10 | ✅ | OK |
| `persistence_wmi_subscription` | Sysmon 19/20/21 | ✅ | OK |
| `log_tamper_clear` | Security 1102 | ✅ | OK |

---

## 4. Top 10 Missing Edges (Priority Gaps)

### Critical (Breaks Story Reconstruction)

| # | Gap | Impact | Fix Complexity | Recommendation |
|---|-----|--------|----------------|----------------|
| 1 | **PowerShell channel disabled** | No ScriptExec facts for encoded PowerShell detection | Low | Enable PowerShell channel in wevt_reader defaults |
| 2 | **ReadPath has no source** | Cannot track data exfil reconnaissance (what files were read) | High | Would need ETW FileIO provider or Sysmon custom config |
| 3 | **RenamePath has no extractor** | Miss staging/obfuscation via rename | Medium | Sysmon file events can be extended |
| 4 | **MemWX/MemAlloc not mapped** | No memory protection change detection | High | Needs Sysmon/ETW memory events |

### High (Degrades Correlation Quality)

| # | Gap | Impact | Fix Complexity | Recommendation |
|---|-----|--------|----------------|----------------|
| 5 | **ProcSpawn missing parent from 4688** | Cannot build process tree from Security events alone | Medium | Require Sysmon 1 for full trees |
| 6 | **Defender channel disabled** | No ASR block / AV disable detection | Low | Enable Defender channel |
| 7 | **WinRM channel disabled** | No WinRM lateral movement detection | Low | Enable WinRM Operational |
| 8 | **AccountOp not in FactType enum** | Account mgmt facts extracted but not canonical | Low | Add AccountOp to FactType |

### Medium (Enrichment Gaps)

| # | Gap | Impact | Fix Complexity | Recommendation |
|---|-----|--------|----------------|----------------|
| 9 | **WritePath = CreatePath** | Cannot distinguish create vs modify vs overwrite | Medium | Sysmon config or 4663 audit |
| 10 | **DnsResolve SOFT capability** | DNS facts may not satisfy required slots | Low | Consider promoting to HARD if Sysmon 22 reliable |

---

## 5. Evidence Pointer Contract

### 5.1 EvidencePtr Structure

```rust
// crates/locald/src/hypothesis/canonical_event.rs
pub struct EvidencePtr {
    pub stream_id: String,      // e.g., "wevt_security", "sysmon"
    pub segment_id: String,     // segment file identifier
    pub record_index: u64,      // record number within segment
    pub ts: Option<DateTime<Utc>>,
    pub excerpt: Option<String>, // optional human-readable excerpt
}
```

### 5.2 Evidence Chain Integrity

For each Signal/Detection:
1. **Signal** → references **Fact[]** via `matched_facts`
2. **Fact** → references **EvidencePtr[]** via `evidence_ptrs`
3. **EvidencePtr** → locates **raw event** via `stream_id/segment_id/record_index`

Current gaps:
- EvidencePtr segment_id sometimes hard-coded to `"0"` in fact_extractor
- excerpt field rarely populated
- No back-link from raw event to derived facts

---

## 6. Example Narrative Template

Given the Contract, a complete incident narrative should populate:

```
INCIDENT: PowerShell Download + Service Persistence

TIMELINE:
[T1] AuthEvent(logon): User CORP\jdoe logged on to HOST-01 (Type 3, network)
     Evidence: Security 4624 @ stream:wevt_security/seg:0/rec:1234

[T2] Exec: powershell.exe launched by winword.exe
     Evidence: Sysmon 1 @ stream:sysmon/seg:0/rec:5678
     
[T3] OutboundConnect: powershell.exe → 185.234.x.x:443 (TCP)
     Evidence: Sysmon 3 @ stream:sysmon/seg:0/rec:5679

[T4] DnsResolve: malware[.]example[.]com → 185.234.x.x
     Evidence: Sysmon 22 @ stream:sysmon/seg:0/rec:5680

[T5] CreatePath: C:\Users\jdoe\AppData\Local\Temp\payload.exe
     Evidence: Sysmon 11 @ stream:sysmon/seg:0/rec:5681

[T6] Exec: payload.exe launched
     Evidence: Sysmon 1 @ stream:sysmon/seg:0/rec:5700

[T7] PersistArtifact(Service): "WindowsUpdateService" → payload.exe
     Evidence: System 7045 @ stream:wevt_system/seg:0/rec:100

GAPS:
- [T2→T3] No ScriptExec fact: PowerShell channel disabled
- [T5] WritePath unclear: Sysmon 11 = create, no content/bytes info
- [T6] No parent relationship in narrative (need ProcSpawn)

SIGNALS FIRED:
- execution_lolbin_powershell_download (PARTIAL: missing script block)
- persistence_service_install (FULL)
```

---

## 7. Recommendations Summary

### Immediate (Config Changes)

1. **Enable PowerShell channel** in `wevt_reader.rs:new()` - change enabled: false → true
2. **Enable Defender channel** for ASR/AV detection
3. **Add TerminalServices channel** for RDP visibility

### Short-Term (Code Changes)

4. Add `AccountOp` variant to `FactType` enum in `canonical_fact.rs`
5. Populate `excerpt` field in `EvidencePtr` for human-readable context
6. Fix segment_id hard-coding in `fact_extractor.rs`

### Medium-Term (Design Work)

7. Design `ReadPath` detection strategy (ETW or custom Sysmon rules)
8. Add `RenamePath` extractor for Sysmon file events
9. Document which playbooks require Sysmon vs work with Security-only

### Long-Term (Architecture)

10. Add memory protection change detection (`MemWX`, `MemAlloc`)
11. Build evidence excerpt auto-generator for explainability
12. Create "minimum viable telemetry" profile vs "full visibility" profile

---

## Appendix A: File References

| Component | Path | Purpose |
|-----------|------|---------|
| wevt_reader | `crates/agent-windows/src/wevt_reader.rs` | Windows Event Log polling, channel config |
| attack_surface | `crates/agent-windows/src/sensors/attack_surface.rs` | Event normalization |
| canonical_fact | `crates/locald/src/hypothesis/canonical_fact.rs` | FactType enum, Fact struct |
| fact_extractor | `crates/locald/src/os/windows/fact_extractor.rs` | Event ID → FactType mapping |
| slot_matcher | `crates/locald/src/slot_matcher.rs` | Playbook matching engine |
| facts_windows.md | `docs/facts_windows.md` | Event ID reference doc |
| playbooks_coverage | `docs/playbooks_windows_coverage.md` | Playbook telemetry requirements |

## Appendix B: FactType Enum (Complete)

From `crates/locald/src/hypothesis/canonical_fact.rs`:

```
ProcSpawn         - Process spawned another process
Exec              - Executable execution
OutboundConnect   - Outbound network connection
InboundConnect    - Inbound network connection (listen/accept)
DnsResolve        - DNS resolution
WritePath         - File write operation
ReadPath          - File read operation
CreatePath        - File creation
DeletePath        - File deletion
RenamePath        - File rename/move
PersistArtifact   - Persistence artifact created/modified
PrivilegeBoundary - Privilege boundary crossing
MemWX             - Memory WX violation (write+execute)
MemAlloc          - Memory allocation for code
ModuleLoad        - Module/library loaded
Injection         - Code injection into another process
RegistryMod       - Registry modification (Windows)
AuthEvent         - Authentication event
LogTamper         - Log tampering
SecurityToolDisable - Security tool disabled
ShellCommand      - Command execution via shell
ScriptExec        - Script execution
Unknown           - Unknown/custom fact type
```

---

*End of System Story Surface View Audit*

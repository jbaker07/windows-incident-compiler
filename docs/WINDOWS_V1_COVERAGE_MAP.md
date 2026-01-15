# Windows v1 Attack Surface Coverage Map

This document maps Windows event sources to parsers, canonical events, and fact types.

## Coverage Status Legend

| Status | Meaning |
|--------|---------|
| ✅ ROUTED | Parser exists in attack_surface.rs, routing enabled |
| ⚠️ PARTIAL | Parser exists but routing incomplete or conditional |
| ❌ GAP | No parser/routing - needs implementation |
| 🔄 FACT_ONLY | Routed via fact_extractor.rs tag enrichment only |

---

## v1 Full Attack Surface Coverage Matrix

### 1. Process Execution

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| Sysmon | 1 | `parse_proc_exec` | `process_exec` | ProcessStart | ✅ ROUTED |
| Security | 4688 | `parse_proc_exec` | `process_exec` | ProcessStart | ✅ ROUTED |

**Dedupe Notes:**
- Both Sysmon 1 and Security 4688 route to same parser
- Dedup at wevt_reader level by (channel, source_record_id)
- Cross-source dedupe at fact level needed for ProcessStart when both sources active

---

### 2. Network Egress

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| Sysmon | 3 | `parse_network_connect` | `network_connect` | NetworkConnection | ✅ ROUTED |

---

### 3. Credential / Process Access

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| Sysmon | 10 | `parse_proc_access` | `proc_access` | Injection (LSASS) | ✅ ROUTED |

---

### 4. Persistence

#### 4a. Services

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| System | 7045 | `parse_persistence_service` | `persistence_service` | Persistence::Service | ✅ ROUTED |
| Security | 4697 | `parse_persistence_service` | `persistence_service` | Persistence::Service | ✅ ROUTED |

#### 4b. Scheduled Tasks

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| Security | 4698 | `parse_persistence_task` | `persistence_task` | Persistence::ScheduledTask | ✅ ROUTED |
| Security | 4702 | `parse_persistence_task` | `persistence_task` | Persistence::ScheduledTask | ✅ ROUTED |
| TaskScheduler | 106 | `parse_persistence_task_operational` | `persistence_task` | Persistence::ScheduledTask | ✅ ROUTED |

#### 4c. Registry

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| Sysmon | 12 | `parse_registry_mod` | `registry_mod` | Persistence::Registry | ✅ ROUTED |
| Sysmon | 13 | `parse_registry_mod` | `registry_mod` | Persistence::Registry | ✅ ROUTED |
| Sysmon | 14 | `parse_registry_mod` | `registry_mod` | Persistence::Registry | ✅ ROUTED |
| Security | 4657 | `parse_registry_mod` | `registry_mod` | Persistence::Registry | ✅ ROUTED |

#### 4d. WMI Persistence

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| Sysmon | 19 | `parse_wmi_persistence` | `wmi_persistence` | Persistence::WMI | ✅ ROUTED |
| Sysmon | 20 | `parse_wmi_persistence` | `wmi_persistence` | Persistence::WMI | ✅ ROUTED |
| Sysmon | 21 | `parse_wmi_persistence` | `wmi_persistence` | Persistence::WMI | ✅ ROUTED |

---

### 5. PowerShell Execution

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| PowerShell | 4103 | `parse_powershell_exec` | `powershell_exec` | Execution::Script | ✅ ROUTED |
| PowerShell | 4104 | `parse_powershell_exec` | `powershell_exec` | Execution::Script | ✅ ROUTED |

---

### 6. Log Tampering / Defense Evasion

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| Security | 1102 | `parse_log_clear` | `log_clear` | LogTamper | ✅ ROUTED |
| System | 104 | `parse_log_clear` | `log_clear` | LogTamper | ✅ ROUTED |

---

### 7. Lateral Movement

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| Security | 4624 (Type=10) | `parse_remote_logon_rdp` | `remote_logon_rdp` | Auth (RDP) | ✅ ROUTED |
| WinRM | 91 | `parse_remote_winrm` | `remote_winrm` | Auth (WinRM) | ✅ ROUTED |

---

### 8. Privilege Escalation

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| Security | 4672 | `parse_priv_escalation` | `priv_elevation` | Auth (Privilege) | ✅ ROUTED |

---

### 9. File System Events

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| Sysmon | 11 | `parse_file_create` | `file_create` | FileCreate | ✅ ROUTED |

---

### 10. Defense Prevention

| Channel | Event ID | Parser Function | Canonical Event | Fact Type | Status |
|---------|----------|-----------------|-----------------|-----------|--------|
| Defender | 1121 | `parse_asr_block` | `asr_block` | DefensePrevention | ✅ ROUTED |

---

## Gap Analysis vs v1 Definition

### ❌ Missing from attack_surface.rs (but have fact enrichment)

| Channel | Event ID | Description | Impact | Priority |
|---------|----------|-------------|--------|----------|
| Security | 4625 | Failed logon | Brute force detection | Medium |
| WMI-Activity | 5857-5861 | WMI errors/queries | WMI abuse detection | Low |

### ⚠️ Routing exists but fact extraction may be incomplete

| Channel | Event ID | Issue |
|---------|----------|-------|
| Security | 4624 | Only LogonType=10 (RDP) extracted; Type=3 (Network) not emitted |

---

## Channels Polled by wevt_reader.rs

| Channel | Enabled | attack_surface.rs Support |
|---------|---------|---------------------------|
| Security | ✅ | ✅ Full (1102, 4624, 4672, 4688, 4697, 4698, 4702, 4657) |
| System | ✅ | ✅ Full (7045, 104) |
| Sysmon/Operational | ✅ | ✅ Full (1, 3, 10, 11, 12-14, 19-21) |
| PowerShell/Operational | ✅ | ✅ Full (4103, 4104) |
| WMI-Activity/Operational | ✅ | ❌ No parsers (only Sysmon WMI events) |
| TaskScheduler/Operational | ✅ | ✅ Partial (106 only) |
| WinRM/Operational | ✅ | ✅ Partial (91 only) |

---

## Dedupe Architecture

### Per-Channel Dedupe (wevt_reader.rs)
- Uses `(channel, source_record_id)` HashSet with LRU eviction (1000 entries)
- Prevents duplicate events on reader restart
- Location: `WevtReader::is_duplicate()`

### Cross-Source Merge (locald fact_extractor.rs)
- Both Sysmon 1 and Security 4688 emit ProcessStart facts
- **GAP**: No explicit cross-source dedup for ProcessStart facts
- Recommendation: Use proc_key hash as dedup key at fact insert

---

## Capability Model Fields

Current `/api/capability/status` returns:
- `is_admin` - Can access Security log
- `sysmon_installed` - Sysmon service running
- `security_log_accessible` - Can query Security channel
- `channels` - Per-channel probe results
- `channels_accessible` - Count of accessible channels

### Proposed Enhancements (no contract change)
Add to each channel entry:
- `supported` - Parser routes exist for this channel
- `observed` - Events seen this run (requires runtime tracking)

---

*Last updated: 2026-01-13*

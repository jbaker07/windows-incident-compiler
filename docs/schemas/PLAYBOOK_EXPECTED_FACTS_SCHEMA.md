# Playbook Expected Facts Schema

## Overview

Every playbook rule/step MUST define expected facts to enable:
1. **UI rendering** of "Expected Facts" column in Investigate → Steps table
2. **Evidence deep-linking** with correct lens/query/fact_types
3. **Variant support** for attacks with multiple possible indicators

## Schema

Each rule in `rules:` MUST have an `expected:` block:

```yaml
rules:
  - name: "Rule Name"
    conditions: [...]
    actions: [...]
    expected:
      # Human-readable facts (REQUIRED - at least one)
      facts:
        - "Process execution: certutil.exe with -urlcache flag"
        - "Command line contains remote URL (http:// or https://)"
      
      # Machine hints for Evidence deep-linking (REQUIRED)
      evidence:
        lens: "process"  # registry|process|script|network|file|auth
        fact_types: ["Exec"]  # Fact types in the system
        query_terms: ["certutil", "-urlcache"]  # Search terms
        event_ids: [4688, 1]  # Windows Event IDs (optional)
      
      # Attack variants (OPTIONAL - for OR conditions)
      variants:
        - label: "CertUtil URLCache Download"
          facts:
            - "certutil.exe -urlcache -split -f <URL>"
          evidence:
            query_terms: ["certutil", "-urlcache"]
        
        - label: "CertUtil Decode from Base64"
          facts:
            - "certutil.exe -decode <input> <output>"
          evidence:
            query_terms: ["certutil", "-decode"]
      
      # Visibility requirements (OPTIONAL - for blocked explanations)
      visibility_requires: ["security_log", "audit_proc_creation"]
```

## Evidence Lens Types

| Lens | Description | Typical Fact Types |
|------|-------------|-------------------|
| `process` | Process execution | Exec, ProcessAccess |
| `registry` | Registry modifications | RegistryMod |
| `script` | Script execution | ScriptExec, PowerShell |
| `network` | Network connections | NetworkConn, DnsQuery |
| `file` | File operations | FileCreate, FileAccess |
| `auth` | Authentication events | AuthEvent, LogonEvent |

## Rules

1. **Every step MUST have `expected.facts`** - Human-readable strings describing what to look for
2. **Every step MUST have `expected.evidence`** - Machine hints for Evidence tab deep-link
3. **Use `variants`** when an attack has multiple possible techniques (OR conditions)
4. **`fact_types` should match system fact types** - Exec, AuthEvent, RegistryMod, etc.
5. **`lens` determines Evidence tab filter** - Maps to UI lens dropdown

## Examples

### Simple Rule (Single Detection Pattern)

```yaml
- name: "BITSAdmin Download"
  conditions:
    - fact_type: Exec
    - field: path
      matches: "(?i)bitsadmin"
    - field: cmdline
      matches: "(?i)/transfer.*https?://"
  expected:
    facts:
      - "bitsadmin.exe execution with /transfer flag"
      - "Remote URL in command line (HTTP/HTTPS)"
    evidence:
      lens: "process"
      fact_types: ["Exec"]
      query_terms: ["bitsadmin", "/transfer"]
      event_ids: [4688, 1]
    visibility_requires: ["security_log"]
```

### Rule with Variants (Multiple Attack Techniques)

```yaml
- name: "LSASS Memory Dump"
  conditions:
    - fact_type: Exec
    - field: cmdline
      matches: "(?i)(procdump|mimikatz|comsvcs)"
  expected:
    facts:
      - "Process accessing LSASS memory"
      - "Known credential dumping tool execution"
    variants:
      - label: "Procdump LSASS"
        facts:
          - "procdump.exe -ma lsass.exe"
        evidence:
          query_terms: ["procdump", "lsass"]
      - label: "Mimikatz sekurlsa"
        facts:
          - "mimikatz.exe with sekurlsa::logonpasswords"
        evidence:
          query_terms: ["mimikatz", "sekurlsa"]
      - label: "Comsvcs MiniDump"
        facts:
          - "rundll32.exe comsvcs.dll MiniDump"
        evidence:
          query_terms: ["comsvcs", "MiniDump", "lsass"]
    evidence:
      lens: "process"
      fact_types: ["Exec", "ProcessAccess"]
      query_terms: ["lsass"]
      event_ids: [10, 4688]
    visibility_requires: ["sysmon"]
```

## Backend Contract

The `/api/runs/:id/playbooks/eval` endpoint MUST return for each step:

```json
{
  "step_id": "rule_0",
  "step_name": "LSASS Memory Dump",
  "status": "blocked",
  "reason": "Sysmon not installed",
  "expected_facts": [
    "Process accessing LSASS memory",
    "Known credential dumping tool execution"
  ],
  "expected_variants": [
    {
      "label": "Procdump LSASS",
      "facts": ["procdump.exe -ma lsass.exe"]
    },
    {
      "label": "Mimikatz sekurlsa",
      "facts": ["mimikatz.exe with sekurlsa::logonpasswords"]
    }
  ],
  "evidence_hints": {
    "lens": "process",
    "fact_types": ["Exec", "ProcessAccess"],
    "query_terms": ["lsass"]
  }
}
```

## UI Contract

The Investigate → Steps table MUST render:

| Step | Status | Reason | Expected Facts | Action |
|------|--------|--------|----------------|--------|
| LSASS Memory Dump | ⚫ Blocked | Sysmon not installed | • Process accessing LSASS memory<br>• Known credential dumping tool<br><br>**Variants:** Procdump, Mimikatz, Comsvcs | 🔍 Evidence |

Evidence button opens: `Runs → Evidence` with lens=process, query="lsass"

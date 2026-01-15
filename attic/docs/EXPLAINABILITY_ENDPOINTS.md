# Explainability Endpoints Map

BUILD_STAMP: 2026-01-10T20:00:00Z

This document maps all backend endpoints relevant to run explainability, findings, signals, and scoring.

---

## Core Run Endpoints (Confirmed Working)

| Method | Path | Purpose | Response Shape |
|--------|------|---------|----------------|
| GET | `/api/runs` | List available runs | `RunInfo[]` |
| GET | `/api/run/status` | Current run status | `RunStatus` |
| GET | `/api/run/metrics` | Live metrics | `RunMetrics` |
| POST | `/api/run/start` | Start capture | `StartRunResponse` |
| POST | `/api/run/stop` | Stop capture | `{ stopped: bool }` |

### RunInfo Shape
```json
{
  "run_id": "run_1736531400000",
  "signal_count": 42,
  "earliest_ts": 1736531400000,
  "latest_ts": 1736535000000,
  "hosts": ["WORKSTATION-1"]
}
```

---

## Signal Endpoints (Confirmed Working)

| Method | Path | Purpose | Response Shape |
|--------|------|---------|----------------|
| GET | `/api/signals` | List signals (findings) | `StoredSignal[]` |
| GET | `/api/signals?host=X&signal_type=Y&severity=Z&limit=N` | Filtered signals | `StoredSignal[]` |
| GET | `/api/signals/:id` | Get single signal | `StoredSignal` |
| GET | `/api/signals/stats` | Aggregate stats | `SignalStats` |
| GET | `/api/signals/:id/explain` | Explanation bundle | `ExplanationBundle` |
| GET | `/api/signals/:id/narrative` | Narrative text | `Narrative` |

### StoredSignal Shape
```json
{
  "signal_id": "sig_abc123",
  "signal_type": "RansomwareIndicator",
  "severity": "critical",
  "host": "WORKSTATION-1",
  "ts": 1736531500000,
  "ts_start": 1736531400000,
  "ts_end": 1736531500000,
  "proc_key": "chrome.exe|1234",
  "file_key": null,
  "identity_key": "DOMAIN\\user",
  "metadata": { ... },
  "evidence_ptrs": [ ... ],
  "dropped_evidence_count": 0
}
```

### SignalStats Shape
```json
{
  "total": 42,
  "by_severity": { "critical": 2, "high": 10, "medium": 20, "low": 10 },
  "by_host": { "WORKSTATION-1": 42 },
  "by_type": { "RansomwareIndicator": 2, "ProcessInjection": 5, ... }
}
```

### ExplanationBundle Shape (from `/api/signals/:id/explain`)
```json
{
  "signal_id": "sig_abc123",
  "hypothesis_name": "RansomwareIndicator",
  "matched_facts": [
    { "fact_type": "ProcessStart", "entity": "vssadmin.exe", "ts": 1736531400000 }
  ],
  "slots": {
    "target_process": "vssadmin.exe",
    "shadow_deleted": true
  },
  "scoring": {
    "base_severity": "critical",
    "risk_score": 0.95,
    "mahalanobis_distance": 3.2,
    "scoring_reasons": [
      { "reason": "shadow_copy_deletion", "weight": 0.4 },
      { "reason": "known_ransomware_tool", "weight": 0.3 }
    ]
  },
  "evidence_refs": [
    { "segment_id": "seg_001", "record_index": 42, "field": "CommandLine" }
  ],
  "playbook_id": "windows/ransomware_shadow_delete.yaml",
  "detector_version": "1.0.0"
}
```

### Narrative Shape (from `/api/signals/:id/narrative`)
```json
{
  "narrative_id": "narr_xyz789",
  "signal_id": "sig_abc123",
  "version": 1,
  "mode": "Discovery",
  "sentences": [
    {
      "sentence_id": "s1",
      "text": "At 10:30 AM, the process vssadmin.exe was observed deleting shadow copies.",
      "evidence_refs": [{ "segment_id": "seg_001", "record_index": 42 }],
      "confidence": 0.95
    }
  ],
  "entities": {
    "processes": ["vssadmin.exe"],
    "users": ["DOMAIN\\user"],
    "hosts": ["WORKSTATION-1"]
  },
  "generated_at": "2026-01-10T10:35:00Z"
}
```

---

## Mission & Narrative Endpoints

| Method | Path | Purpose | Response Shape |
|--------|------|---------|----------------|
| GET | `/api/mission` | Get mission mode | `MissionSpec` |
| GET | `/api/missions` | List missions | `MissionSpec[]` |
| GET | `/api/missions/:id` | Get specific mission | `MissionSpec` |
| GET | `/api/narratives/:id/actions` | Get narrative actions | `NarrativeAction[]` |

---

## Run Coverage Endpoint

| Method | Path | Purpose | Response Shape |
|--------|------|---------|----------------|
| GET | `/api/runs/:run_id/coverage` | Fact extraction statistics for a run | `CoverageAvailable` or `CoverageUnavailable` |

Returns structured coverage data showing what fact types were extracted during a run, active sensors, and diagnostics for "why no signals?" scenarios.

### CoverageAvailable Shape (when `available: true`)
```json
{
  "available": true,
  "run_id": "run_1736531400000",
  "facts_total": 1523,
  "fact_types": [
    { "fact_type": "ProcSpawn", "count": 850 },
    { "fact_type": "Exec", "count": 423 },
    { "fact_type": "WritePath", "count": 250 }
  ],
  "top_hosts": [
    { "host": "WORKSTATION-1", "count": 1523 }
  ],
  "sensor_modes": ["ETW"],
  "sensors": [
    {
      "sensor_name": "ETW",
      "status": "active",
      "fact_count": 1523,
      "capabilities": ["proc_exec", "file_ops", "netconnect", "registry"]
    }
  ],
  "pipeline_diagnostics": {
    "playbooks_loaded": 5,
    "playbook_names": ["encoded_powershell", "ransomware_indicator"],
    "scoring_enabled": true,
    "coverage_minutes": 15,
    "explanation": "1523 facts extracted, 5 playbook rules active. No signals were produced."
  }
}
```

### CoverageUnavailable Shape (when `available: false`)
```json
{
  "available": false,
  "reason_code": "MISSING_DB",
  "message": "No analysis database found for this run.",
  "run_id": "run_1736531400000",
  "debug": {
    "expected_path": "C:\\ProgramData\\edr\\runs\\run_1736531400000\\workbench.db",
    "run_status": "stopped"
  }
}
```

### Reason Codes
| Code | Meaning |
|------|---------|
| `MISSING_RUN_DIR` | Run directory does not exist on disk |
| `MISSING_DB` | Database file (workbench.db/analysis.db) not found |
| `MISSING_TABLE` | `coverage_rollup` table not found in database |
| `PIPELINE_NOT_FINALIZED` | Run is still in progress - stop to finalize |
| `RUN_NOT_FOUND` | No run record with this ID |
| `DATABASE_ERROR` | Error opening or querying database |

### Sensor Status Values
| Status | Meaning |
|--------|---------|
| `active` | Sensor is configured and producing events (fact_count > 0) |
| `configured` | Sensor is configured but produced no events |
| `missing` | Expected sensor not found |

---

## Run Changes Endpoint (Layer 1 Explainability)

| Method | Path | Purpose | Response Shape |
|--------|------|---------|----------------|
| GET | `/api/runs/:run_id/changes` | Categorized system changes from facts | `ChangesResponse` |

Returns categorized changes detected during a run, built from facts, coverage rollup, and signals tables. This is Layer 1 Explainability - always available when facts exist.

### ChangesResponse Shape (when `available: true`)
```json
{
  "available": true,
  "run_id": "run_1736531400000",
  "highlights": [
    {
      "change_id": "chg_001",
      "category": "Persistence",
      "title": "Service created",
      "summary": "malware.exe installed as service",
      "severity": "high",
      "severity_basis": "Persistence change (signal correlated)",
      "evidence": [{ "segment_id": "seg_001", "record_index": 42 }],
      "evidence_unavailable_reason": null
    }
  ],
  "changes": [
    {
      "change_id": "fact_abc123",
      "ts": 1736531500000,
      "category": "Process",
      "title": "Exec: ProcSpawn",
      "summary": "powershell.exe → cmd.exe",
      "entities": {
        "host": "WORKSTATION-1",
        "fact_type": "ProcSpawn",
        "domain": "process"
      },
      "evidence": [ /* EvidencePointer[] */ ],
      "evidence_unavailable_reason": "Aggregated from coverage_rollup",
      "supporting_facts_count": 1,
      "severity": "low",
      "severity_basis": "Process change"
    }
  ],
  "categories": {
    "Process": 45,
    "Files": 23,
    "Network": 12,
    "Persistence": 3,
    "Auth": 5
  },
  "stats": {
    "total_changes": 88,
    "fact_types": 7,
    "hosts": 1
  }
}
```

### ChangeItem Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `change_id` | string | Yes | Unique identifier for this change |
| `ts` | number | Yes | Timestamp in milliseconds |
| `category` | string | Yes | Change category (Process, Files, etc.) |
| `title` | string | Yes | Short title describing the change |
| `summary` | string | Yes | Human-readable summary |
| `entities` | object | Yes | Entity information (host, fact_type, domain) |
| `evidence` | array | Yes | Evidence pointers (may be empty) |
| `evidence_unavailable_reason` | string | If empty evidence | Explains why evidence is not available |
| `severity` | string | Yes | Deterministic severity: info, low, medium, high, critical |
| `severity_basis` | string | Yes | Human-readable explanation of severity |

### Severity Heuristic
Severity is computed deterministically from:
1. **Category weight**: Persistence/Evasion=3, Auth/Network=2, Process/Files=1
2. **Fact type bump**: +1 for ServiceCreate, SchedTask, RegOp, ProcessInject, etc.
3. **Signal correlation**: +1 if a signal matches this change
4. **Evidence count**: +1 if >5 evidence items

Score mapping: 1=info, 2=low, 3=medium, 4=high, 5+=critical

### Highlights Invariant
Items in `highlights[]` MUST have either:
- `evidence.length > 0`, OR
- `evidence_unavailable_reason` explaining why evidence is missing

### Change Categories
| Category | Mapped Fact Types |
|----------|-------------------|
| `Process` | Exec, ProcSpawn, ProcessCreate, ProcessExit, ModuleLoad, MemRead |
| `Files` | FileOp, FileCreate, FileDelete, FileModify, FileAccess |
| `Network` | NetConn, NetworkConnection, DnsQuery |
| `Persistence` | PersistArtifact, ServiceCreate, SchedTask, RegOp, WmiOp |
| `Auth` | AuthEvent, AuthLogon, Logon, Logoff, AuthFailure |
| `Evasion` | LogTamper, DefenseEvasion, SecurityEvasion |
| `Other` | All other fact types |

---

## Run Playbooks Endpoint (Layer 2 Explainability)

| Method | Path | Purpose | Response Shape |
|--------|------|---------|----------------|
| GET | `/api/runs/:run_id/playbooks` | Playbook evaluation status and matches | `PlaybooksResponse` |

Returns playbook evaluation results for a run. Layer 2 Explainability - uses automatic discovery with fallback chain.

### Playbooks Discovery Chain
The endpoint searches for playbooks in this order:
1. `<binary_dir>/playbooks` - Playbooks bundled with the binary
2. `%LOCALAPPDATA%/LocInt/playbooks` - User-local playbooks
3. `EDR_PLAYBOOKS_DIR` environment variable

### PlaybooksResponse Shape (when playbooks enabled)
```json
{
  "available": true,
  "run_id": "run_1736531400000",
  "playbooks_enabled": true,
  "playbooks_dir": "C:\\playbooks\\windows",
  "searched_paths": [
    "C:\\Program Files\\LocInt\\playbooks",
    "C:\\Users\\jsmith\\AppData\\Local\\LocInt\\playbooks"
  ],
  "not_found_reason": null,
  "loaded_count": 15,
  "loaded_playbooks": ["ransomware_shadow_delete", "process_injection", ...],
  "fired_count": 2,
  "fired_playbooks": ["ransomware_shadow_delete", "credential_dump"],
  "matches": [
    {
      "signal_id": "sig_abc123",
      "playbook": "ransomware_shadow_delete",
      "signal_type": "RansomwareIndicator",
      "severity": "critical",
      "ts": 1736531500000,
      "host": "WORKSTATION-1",
      "mitre_technique": "T1490",
      "mitre_tactic": "Impact",
      "description": "Shadow copy deletion detected"
    }
  ],
  "by_category": {
    "Impact": ["ransomware_shadow_delete"],
    "Credential Access": ["credential_dump"]
  },
  "mitre_techniques": ["T1490", "T1003"],
  "message": "Playbook matches found"
}
```

### PlaybooksResponse Shape (when playbooks not found)
```json
{
  "available": true,
  "run_id": "run_1736531400000",
  "playbooks_enabled": false,
  "playbooks_dir": null,
  "searched_paths": [
    "C:\\Program Files\\LocInt\\playbooks",
    "C:\\Users\\jsmith\\AppData\\Local\\LocInt\\playbooks"
  ],
  "not_found_reason": "No playbooks directory found. Searched: ... Set EDR_PLAYBOOKS_DIR or place playbooks in <binary_dir>/playbooks",
  "loaded_count": 0,
  "fired_count": 0,
  "matches": [],
  "mitre_techniques": [],
  "message": "No playbooks directory found..."
}
```

### MITRE Truthfulness Invariant
The `mitre_techniques` array ONLY contains MITRE technique IDs that are:
1. Explicitly specified in playbook metadata
2. Valid MITRE format (starts with "T", at least 4 characters)

If no MITRE IDs are found in playbook metadata, returns empty array `[]`. The UI should display "—" when empty.

### Playbooks vs Changes
| Layer | Endpoint | Always Available? | Purpose |
|-------|----------|-------------------|---------|
| Layer 1 | `/api/runs/:run_id/changes` | Yes (if facts exist) | What changed on the system |
| Layer 2 | `/api/runs/:run_id/playbooks` | No (requires config) | What attack chains match |

---

## Diagnostics Endpoints

| Method | Path | Purpose | Response Shape |
|--------|------|---------|----------------|
| GET | `/api/selfcheck` | Self-check v2 | `SelfCheckResponse` |
| GET | `/api/selfcheck/actions` | Recommended actions | `Action[]` |
| GET | `/api/capabilities` | Backend capabilities | `Capabilities` |

---

## Bundle Export/Import

| Method | Path | Purpose | Response Shape |
|--------|------|---------|----------------|
| POST | `/api/export/bundle` | Export bundle | Binary (ZIP) |
| POST | `/api/import/bundle` | Import bundle | `ImportBundleResponse` |

---

## UI Capability Probing

At boot, the UI probes these endpoints to determine which tabs/sections to enable:

1. `GET /api/runs` - If 200, Runs tab is functional
2. `GET /api/signals?limit=1` - If 200, Findings available
3. `GET /api/signals/stats` - If 200, Stats dashboard available
4. `GET /api/capabilities` - Returns feature flags

If an endpoint returns 404, the corresponding UI section shows:
> "Not available (missing: /api/endpoint)"

---

## Data Flow: Runs → Findings → Explain

```
[Runs List]                [Signal/Finding Detail]           [Explanation View]
GET /api/runs       →      GET /api/signals?run_id=X   →     GET /api/signals/:id/explain
                           GET /api/signals/:id              GET /api/signals/:id/narrative
```

Note: The current backend groups signals by time bucket into "runs". 
There is no explicit run_id filter on `/api/signals` yet - UI filters client-side by timestamp range.

---

## Scoring Fields (When Advanced Scoring Enabled)

From `ScoredSignal`:
- `mahalanobis_distance`: Distance from normal (higher = more anomalous)
- `elliptic_envelope_score`: Anomaly score [0.0, 1.0]
- `krim_score`: Entropy-based score [0.0, 1.0]
- `risk_score`: Combined weighted score [0.0, 1.0]

These appear in the explanation bundle under the `scoring` key when available.

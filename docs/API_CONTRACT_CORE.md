# API Contract - Core Endpoints

**Version**: 1.0.0  
**Last Updated**: 2026-01-12  
**Contract Hash**: `v1-core-202601`

This is the **single source of truth** for API response shapes. Both backend (locint.rs) and UI (app.js) MUST conform to this contract.

---

## Response Wrapper Convention

ALL endpoints use a consistent wrapper:

```json
// Success
{
  "success": true,
  "data": { ... }   // endpoint-specific payload
}

// Error
{
  "success": false,
  "error": "Human-readable message",
  "code": "ERROR_CODE"  // machine-readable code
}
```

### Tier-Gated Error Response (FEATURE_LOCKED)

Some endpoints require Pro tier or higher. When called on Free tier, they return HTTP 403 with:

```json
{
  "success": false,
  "error": "Baselines management requires Pro tier",
  "code": "FEATURE_LOCKED",
  "required_tier": "Pro",
  "current_tier": "Free",
  "upgrade_url": "https://locint.io/upgrade"
}
```

**Tier-Gated Endpoints:**

| Endpoint | Required Tier | Gating Condition |
|----------|---------------|------------------|
| `POST /api/runs/:id/baseline` | Pro | Always |
| `GET /api/baselines` | Pro | Always |
| `GET /api/runs/:id/case_summary` | Pro | Always |
| `GET /api/runs/:id/diff` | Pro | When `mode=baseline`, `mode=marker`, or `baseline_filter=true` |
| `GET /api/runs/:id/entities` | Pro | Always |
| `GET /api/runs/:id/pivot` | Pro | Always |
| `POST /api/runs/:id/export/case_pack` | Pro | Always |
| `GET /api/packs/:name` | Pro | When requesting custom (non-builtin) packs |
| `POST /api/packs/rescan` | Pro | Always |
| `GET /api/team/store/status` | Team | Always |
| `POST /api/team/store/configure` | Team | Always |
| `GET /api/team/cases` | Team | Always |
| `POST /api/team/cases` | Team | Always |
| `GET /api/team/cases/:id` | Team | Always |
| `GET /api/team/cases/:id/aggregate` | Team | Always |
| `POST /api/team/cases/:id/tags` | Team | Always |
| `POST /api/team/cases/:id/notes` | Team | Always |
| `POST /api/team/cases/:id/runs` | Team | Always |
| `POST /api/team/cases/:id/runs/:run_id/import` | Team | Always |

**Free Tier Core Loop (Always Available):**
- `GET /api/runs` - List runs
- `GET /api/runs/:id/coverage` - Run story
- `GET /api/runs/:id/diff` - Diff (phase mode only, no baseline_filter)
- `GET /api/signals` - List signals
- `GET /api/signals/:id/explain` - Explainability
- `GET /api/signals/:id/evidence` - Evidence dereference
- `GET /api/runs/:id/playbooks` - Builtin playbooks
- `POST /api/import` - Import bundles
- `POST /api/export` - Export bundles
- `GET /api/packs/builtin` - Builtin content pack

### List Endpoint Convention

For list endpoints, `data` is ALWAYS an **object with a named array field**, never a raw array.

| Endpoint | Array Field |
|----------|-------------|
| `GET /api/runs` | `data.runs` |
| `GET /api/signals` | `data.signals` |
| `GET /api/runs/:id/playbooks` | `data.playbooks` |

---

## Core Endpoints

### 1. GET /api/runs

List all past runs.

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "runs": [
      {
        "run_id": "run_20260112_143022",
        "name": "Test Run",           // nullable
        "signal_count": 5,
        "earliest_ts": 1736694622000,
        "latest_ts": 1736698222000,
        "hosts": [],
        "profile": "extended",
        "started_at": "2026-01-12T14:30:22Z",  // nullable
        "stopped_at": "2026-01-12T15:30:22Z",  // nullable
        "events_total": 15420,
        "segments_count": 12,
        "facts_extracted": 892,
        "status": "completed"          // "completed"|"running"|"unknown"
      }
    ],
    "count": 1
  }
}
```

**Required Fields**: `run_id`, `signal_count`, `status`  
**Nullable Fields**: `name`, `started_at`, `stopped_at`

---

### 2. GET /api/runs/:id/coverage

Run coverage and facts summary (Run Story).

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "available": true,
    "run_id": "run_20260112_143022",
    "facts_total": 892,
    "coverage_rows": 45,
    "signals_count": 5,
    "fact_types": [
      { "fact_type": "process_created", "count": 234 },
      { "fact_type": "network_connection", "count": 156 }
    ],
    "top_hosts": ["WORKSTATION-1"],
    "readiness_snapshot": { ... }      // nullable
  }
}

// When not available:
{
  "success": true,
  "data": {
    "available": false,
    "reason": "workbench.db not found",
    "run_id": "run_20260112_143022",
    "readiness_snapshot": null
  }
}
```

**Required Fields**: `available`, `run_id`  
**Conditional Fields**: When `available=true`: `facts_total`, `coverage_rows`, `signals_count`, `fact_types`, `top_hosts`

---

### 2a. GET /api/runs/:id/diff (Diff v2)

**NEW in v1.1** - Deterministic, evidence-backed diff with three comparison modes.

**Query Parameters:**
| Param | Required | Default | Description |
|-------|----------|---------|-------------|
| `mode` | No | `phase` | `baseline` \| `phase` \| `marker` |
| `baseline_run_id` | If mode=baseline | - | Run ID to compare against |
| `phase_minutes` | If mode=phase | `2` | Minutes for initial phase |
| `marker_ts` | If mode=marker | - | Timestamp (ms) to split on |
| `category` | No | - | Filter by category (comma-separated) |
| `direction` | No | - | Filter by direction (comma-separated) |

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "available": true,
    "run_id": "run_20260112_143022",
    "mode": "phase",
    "comparison": "First 2min vs Rest",
    
    // Capability alignment header
    "capability_snapshot_a": {
      "is_admin": true,
      "sysmon_installed": true,
      "security_log_accessible": true,
      "enabled_sensors": ["sysmon", "security"],
      "fact_types_observed": ["exec", "netconn", "authevent"]
    },
    "capability_snapshot_b": {
      "is_admin": true,
      "sysmon_installed": true,
      "security_log_accessible": true,
      "enabled_sensors": ["sysmon", "security"],
      "fact_types_observed": ["exec", "netconn", "authevent", "servicecreate"]
    },
    "telemetry_caveats": [
      "⚠️ Sysmon was missing in set A but present in set B - New detections may be from improved telemetry"
    ],
    
    // Diff results
    "highlights": [ /* top 5 DiffChange objects */ ],
    "changes": [
      {
        "change_id": "diff_add_abc123",
        "ts_ms": 1736694622000,
        "ts_end_ms": null,           // nullable, for aggregated changes
        "category": "persistence",   // process|persistence|auth|network|evasion|file|other
        "direction": "added",        // added|removed|increased|decreased|modified
        "title": "New Persistence activity",
        "summary": "Service 'SuspiciousSvc' detected",
        "entities": {
          "host": "WORKSTATION-1",
          "service_name": "SuspiciousSvc",
          "proc_key": null,
          "user": null,
          "ip": null,
          "port": null,
          "registry_path": null
        },
        "severity": "high",
        "severity_basis": "Significant Persistence added (score 6)",
        "evidence_ptrs": [
          { "segment_id": "seg_123", "record_index": 45 }
        ],
        "evidence_unavailable_reason": null,  // or "Aggregated data without per-event evidence"
        "supporting_facts_count": 1,
        "stable_key": "persistence:service:WORKSTATION-1:SuspiciousSvc"
      }
    ],
    
    // Stats
    "stats": {
      "total_changes": 12,
      "by_category": {
        "Persistence": 2,
        "Process": 5,
        "Network": 3,
        "Auth": 2
      },
      "by_direction": {
        "added": 8,
        "removed": 2,
        "increased": 1,
        "modified": 1
      },
      "keys_in_a": 45,
      "keys_in_b": 52
    }
  }
}

// When not available:
{
  "success": true,
  "data": {
    "available": false,
    "reason_code": "NO_DB",
    "message": "No workbench.db found for this run",
    "run_id": "run_20260112_143022",
    "mode": "phase"
  }
}

// Baseline not found:
{
  "success": false,
  "error": "Baseline run run_20260101_000000 not found",
  "code": "BASELINE_NOT_FOUND"
}
```

**Canonical Change Object Schema:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `change_id` | string | ✓ | Stable unique identifier |
| `ts_ms` | i64 | ✓ | Timestamp (ms) or window start |
| `ts_end_ms` | i64? | - | Window end for aggregated changes |
| `category` | enum | ✓ | `process`\|`persistence`\|`auth`\|`network`\|`evasion`\|`file`\|`other` |
| `direction` | enum | ✓ | `added`\|`removed`\|`increased`\|`decreased`\|`modified` |
| `title` | string | ✓ | Human-readable title |
| `summary` | string | ✓ | Detailed summary |
| `entities` | object | ✓ | Entities involved (host, proc_key, user, etc.) |
| `severity` | string | ✓ | `critical`\|`high`\|`medium`\|`low`\|`info` |
| `severity_basis` | string | ✓ | Explanation for severity |
| `evidence_ptrs` | array | ✓ | Evidence pointers (may be empty) |
| `evidence_unavailable_reason` | string? | - | Why evidence is unavailable |
| `supporting_facts_count` | i64 | ✓ | Number of facts supporting this change |
| `stable_key` | string | ✓ | Stable key used for diff matching |

**Stable Key Formats:**
- Persistence: `persistence:service:{host}:{service_name}` or `persistence:task:{host}:{task_name}` or `persistence:reg:{host}:{registry_path}`
- Process: `process:{host}:{proc_key}:{parent_proc_key}`
- Network: `network:{host}:{proc_key}:{remote_ip}:{port}`
- Auth: `auth:{host}:{user}:{logon_type}`
- File: `file:{host}:{file_path}:{operation}`
- Evasion: `evasion:{host}:{technique}:{target}`

**Telemetry Caveats Behavior:**
- Diff MUST include capability snapshots for both sets
- If Sysmon differs between sets, report caveat about Process/Network changes
- If Security log access differs, report caveat about Auth changes
- DO NOT report "removed" if baseline couldn't observe that surface

---

### 3. GET /api/runs/:id/playbooks

Playbook evaluation status for a run.

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "available": true,
    "run_id": "run_20260112_143022",
    "playbooks_enabled": true,
    "playbooks_dir": "C:\\path\\to\\playbooks\\windows",
    "searched_paths": ["./playbooks/windows", ...],
    "loaded_count": 12,
    "loaded_playbooks": ["encoded_powershell", "lateral_smb"],
    "fired_count": 2,
    "fired_playbooks": ["encoded_powershell"],
    "skipped_count": 3,
    "skipped_by_reason": {
      "missing_telemetry": 2,
      "below_threshold": 1
    },
    "playbooks": [
      {
        "playbook_id": "playbook:encoded_powershell",
        "playbook_name": "Encoded PowerShell",
        "status": "fired",           // "fired"|"not_fired"|"skipped"|"partial"
        "matched_slots": 3,
        "total_slots": 4,
        "matched_slot_names": "base64_pattern,powershell_execution",
        "evidence_ptrs_sample": "[{...}]",  // nullable
        "mitre_technique": "T1059.001"
      }
    ],
    "mitre_techniques": ["T1059.001"],
    "by_category": {
      "execution": ["encoded_powershell"]
    }
  }
}

// When playbooks unavailable:
{
  "success": true,
  "data": {
    "available": false,
    "reason_code": "PLAYBOOKS_NOT_FOUND",
    "message": "Playbooks directory not found",
    "searched_paths": [...],
    "run_id": "run_20260112_143022",
    "loaded_count": 0,
    "fired_count": 0,
    "skipped_count": 0,
    "skipped_by_reason": {}
  }
}
```

**Required Fields**: `available`, `run_id`  
**Conditional Fields**: When `available=true`: `playbooks_enabled`, `loaded_count`, `fired_count`, `playbooks`

---

### 3a. GET /api/runs/:id/next_steps

Deterministic workflow guidance based on observed run data. Computes next steps from capability snapshot, facts total, signals total, playbook near-misses, and top entities.

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "run_id": "run_20260112_143022",
    "scenario": "telemetry_blocked",  // "telemetry_blocked"|"limited_no_facts"|"no_findings"|"near_miss"|"findings_present"
    "summary": {
      "text": "Telemetry is blocked or limited. 2 issue(s) detected: Not running as Administrator; Sysmon not installed",
      "severity": "high"              // "info"|"low"|"medium"|"high"
    },
    "actions": [
      {
        "action_id": "restart_admin",
        "title": "Restart as Administrator",
        "rationale": "Security Event Log access requires Administrator privileges.",
        "blocking_reason": null,      // nullable - if blocked, explains why action unavailable
        "deep_link": {
          "tab": "Settings"
        },
        "requires": {
          "admin": true
        }
      },
      {
        "action_id": "view_detection_plan",
        "title": "View Detection Plan",
        "rationale": "See which playbooks are blocked by missing telemetry. 2 reason(s) detected.",
        "blocking_reason": null,
        "deep_link": {
          "tab": "Mission",
          "section": "detection_plan"
        },
        "requires": null
      }
    ],
    "evidence_basis": {
      "capability_snapshot": {...},   // from run_meta.json readiness_snapshot
      "overall_status": "blocked",    // "full"|"partial"|"limited"|"blocked"
      "facts_total": 0,
      "signals_total": 0,
      "top_near_misses": [
        {
          "playbook_id": "encoded_powershell",
          "playbook_name": "Encoded PowerShell Commands",
          "completion_ratio": 0.75,
          "missing_slots_count": 1
        }
      ],
      "top_entities": [
        { "type": "process", "key": "powershell.exe", "count": 42 }
      ],
      "blocked_reasons": ["Not running as Administrator", "Sysmon not installed"]
    }
  }
}
```

**Scenario Classification Rules (Deterministic):**
| Scenario | Condition |
|----------|-----------|
| `telemetry_blocked` | `overall_status == "blocked"` OR `overall_status == "limited"` |
| `limited_no_facts` | `facts_total == 0` AND sensors configured |
| `findings_present` | `signals_total > 0` |
| `near_miss` | `signals_total == 0` AND `top_near_misses` non-empty |
| `no_findings` | `facts_total > 0` AND `signals_total == 0` AND no near-misses |

**Action Types by Scenario:**
| Scenario | Actions |
|----------|---------|
| `telemetry_blocked` | `restart_admin`, `install_sysmon`, `view_detection_plan` |
| `limited_no_facts` | `review_capability`, `rerun_with_telemetry`, `validate_trigger` |
| `no_findings` | `review_top_entities`, `view_playbooks`, `rerun_extended_profile` |
| `near_miss` | `inspect_missing_slots`, `check_telemetry_blockers`, `rerun_after_prerequisites` |
| `findings_present` | `open_explain`, `review_all_findings`, `search_similar_in_run`, `export_bundle` |

**Deep Link Tabs:**
- `Mission` - Main Mission tab, optionally with `section: "detection_plan"|"capability"`
- `Runs` - Runs list, optionally with `run_id` to select
- `Facts` - Facts tab within run detail, optionally with `filter`
- `Playbooks` - Playbooks tab within run detail, optionally with `playbook_id`
- `Findings` - Findings tab within run detail
- `Explain` - Explain tab, optionally with `signal_id`
- `Export` - Export section of Import/Export tab
- `Settings` - Settings tab

**Required Fields**: `run_id`, `scenario`, `summary`, `actions`, `evidence_basis`

---

### 4. GET /api/signals?run_id=...&since_ts_ms=...

List signals for a run.

**Query Parameters:**
- `run_id` (required): Run to query
- `since_ts_ms` (optional): Cursor for incremental polling

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "signals": [
      {
        "signal_id": "sig_abc123",
        "signal_type": "playbook:encoded_powershell",
        "severity": "high",
        "ts": 1736694622000,         // ms timestamp (ts_ms)
        "host": "WORKSTATION-1"      // nullable
      }
    ],
    "run_id": "run_20260112_143022",
    "available": true,
    "next_since_ts_ms": 1736694622000
  }
}
```

**Required Fields**: `signals`, `run_id`, `available`  
**Nullable Fields**: `host` in each signal

---

### 4a. GET /api/signals/explainability_stats?run_id=...

Explainability availability statistics for a run.

**Query Parameters:**
- `run_id` (required): Run to query

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "run_id": "run_20260112_143022",
    "total_signals": 5,
    "explanations_available": 4,
    "explanations_unavailable": 1,
    "unavailable_by_reason": {
      "MISSING_HYPOTHESIS": 1
    },
    "structural_invariant": {
      "every_signal_has_explanation_row": true,
      "missing_rows": 0
    }
  }
}
```

**Required Fields**: `run_id`, `total_signals`, `explanations_available`, `explanations_unavailable`, `unavailable_by_reason`, `structural_invariant`

**Structural Invariant:**
- `every_signal_has_explanation_row`: MUST be `true` after any new run
- `missing_rows`: MUST be `0` after any new run
- If invariant fails, locald explanation write path has a bug

**Reason Codes in `unavailable_by_reason`:**
| Code | Meaning |
|------|---------|
| `MISSING_EXPLANATION_ROW` | Signal exists but no row in signal_explanations (legacy data) |
| `MISSING_HYPOTHESIS` | Hypothesis not found when building explanation |
| `MISSING_PLAYBOOK` | Playbook definition not found |
| `MISSING_FACTS_STORE` | Facts store was empty |
| `JSON_SERIALIZE_FAILED` | Serialization error |
```

**Required Fields**: `signals`, `run_id`, `available`  
**Nullable Fields**: `host` in each signal

---

### 5. GET /api/signals/:id/explain?run_id=...

Get explanation for a signal. **Canonical ExplainResponse schema**.

**Query Parameters:**
- `run_id` (required): Run context

**Response Shape (available=true):**
```json
{
  "success": true,
  "data": {
    "available": true,
    "signal": {
      "signal_id": "sig_abc123",
      "signal_type": "playbook:encoded_powershell",
      "ts_ms": 1736694622000,
      "severity": "high",
      "host": "WORKSTATION-1",       // nullable
      "run_id": "run_20260112_143022"
    },
    "source": {
      "kind": "playbook",            // "playbook"|"detector"|"unknown"
      "id": "playbook:encoded_powershell",
      "version": "1.0"               // nullable
    },
    "evidence_ptrs": [...],          // array, possibly empty
    "evidence_ptrs_count": 3,
    "confidence": 0.85,              // nullable
    "explanation": {
      "playbook_id": "playbook:encoded_powershell",
      "playbook": "encoded_powershell",
      "slots": [...],
      "matched_facts": [...],
      "summary": "...",
      "why_fired": "..."             // narrative
    },
    "matched_slots": {               // nullable, only for playbook-based
      "filled": 3,
      "total": 4,
      "names": ["base64_pattern", "powershell_execution"]
    },
    "narrative": "The 'Encoded PowerShell' detector identified...",  // nullable
    "reasons": [                     // nullable
      {
        "code": "SLOT_MATCH",
        "label": "Matched base64_pattern slot",
        "weight": 0.4,
        "detail": "..."              // nullable
      }
    ]
  }
}
```

**Response Shape (available=false):**
```json
{
  "success": true,
  "data": {
    "available": false,
    "reason_code": "EXPLANATION_NOT_FOUND",  // required when available=false
    "message": "Explanation bundle not found in signal_explanations table",
    "signal": {
      "signal_id": "sig_abc123",
      "signal_type": "playbook:encoded_powershell",
      "ts_ms": 1736694622000,
      "severity": "high",
      "host": "WORKSTATION-1",
      "run_id": "run_20260112_143022"
    },
    "source": {
      "kind": "unknown",
      "id": null,
      "version": null
    },
    "evidence_ptrs": [...],          // from signal metadata, possibly empty
    "evidence_ptrs_count": 0,
    "confidence": null,
    "partial_context": {             // minimal honest data only
      "signal_type": "...",
      "severity": "...",
      "ts": ...,
      "host": "...",
      "metadata": {...},
      "evidence_ptrs": [...],
      "playbook_eval": {...}         // nullable
    },
    "matched_slots": null,
    "narrative": null,
    "reasons": null
  }
}
```

**Reason Codes:**
| Code | Meaning |
|------|---------|
| `EXPLANATION_NOT_FOUND` | Signal exists but no explanation in signal_explanations table |
| `SIGNAL_NOT_FOUND` | Signal not found in database |
| `HYPOTHESIS_NOT_FOUND` | Playbook/hypothesis could not be resolved |

**Required Fields**: `available`, `signal`, `source`, `evidence_ptrs`, `evidence_ptrs_count`  
**Required when available=false**: `reason_code`, `message`  
**Never invented**: `narrative`, `matched_slots`, `reasons` when `available=false`

---

## Capability Model Endpoints

### Semantic Distinction: Configured vs Active

The Capability Model distinguishes between:
- **Configured**: Sensor/channel is accessible and properly set up (static check)
- **Active**: Facts have been observed from this sensor during a run (requires observed data)

Live endpoints (`/api/capability/status`) report **configured** status because they can only confirm accessibility, not that facts have been produced.

Run snapshot endpoints show **active** status only when facts from that sensor were actually observed during the run.

### GET /api/capability/status

Always-on sensor inventory and capability status. Shows what detection is possible with current system state.

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "overall_status": "partial",  // "full"|"partial"|"limited"|"blocked"
    "is_admin": false,
    "sensors": [
      {
        "sensor_name": "Sysmon (System Monitor)",
        "sensor_id": "sysmon",
        "status": "configured",       // "active"|"configured"|"missing"|"blocked"
        "status_label": "Configured (no events observed yet)",
        "reason_code": null,          // null when configured/active
        "message": null,
        "capabilities": ["PROC_CREATE", "NET_CONNECT", ...],
        "requires_admin": false,
        "requires_install": true
      },
      {
        "sensor_name": "Windows Security Event Log",
        "sensor_id": "security_log",
        "status": "blocked",
        "status_label": "Blocked",
        "reason_code": "REQUIRES_ADMIN",
        "message": "Security Event Log requires Administrator privileges",
        "capabilities": [],
        "requires_admin": true,
        "requires_install": false
      }
    ],
    "fact_types_possible": ["ProcSpawn", "Exec", "OutboundConnect", ...],
    "attack_surfaces": {
      "process": {
        "surface": "process",
        "status": "configured",       // "configured"|"partial"|"blocked"
        "status_label": "Configured (sensors accessible)",
        "configured_sensors": ["Sysmon (System Monitor)"],
        "missing_sensors": [],
        "blocked_reason": null
      },
      "auth": {
        "surface": "auth",
        "status": "blocked",
        "status_label": "Blocked (no sensors accessible)",
        "configured_sensors": [],
        "missing_sensors": ["Windows Security Event Log"],
        "blocked_reason": "Security Event Log requires Administrator privileges"
      }
    },
    "pipeline": {
      "components": [
        {
          "component_id": "capture_windows_rotating",
          "component_name": "capture_windows_rotating binary",
          "status": "configured",
          "status_label": "Present",
          "reason_code": null,
          "message": null,
          "path": "C:\\path\\to\\capture_windows_rotating.exe"
        },
        {
          "component_id": "edr-locald",
          "component_name": "edr-locald binary",
          "status": "configured",
          "status_label": "Present",
          "reason_code": null,
          "message": null,
          "path": "C:\\path\\to\\edr-locald.exe"
        },
        {
          "component_id": "data_dir",
          "component_name": "Data directory",
          "status": "configured",
          "status_label": "Writable",
          "reason_code": null,
          "message": null,
          "path": "C:\\data\\dir"
        },
        {
          "component_id": "workbench_db",
          "component_name": "Workbench database",
          "status": "configured",
          "status_label": "Writable",
          "reason_code": null,
          "message": null,
          "path": "C:\\data\\dir\\workbench.db"
        }
      ],
      "active_run": {            // null when no run active
        "run_id": "run_20260112_143022",
        "capture_running": true,
        "locald_running": true,
        "segments_count": 12,
        "events_total": 15420,
        "facts_extracted": 892,
        "signals_fired": 5
      }
    },
    "notes": ["Running without Administrator privileges - Security Event Log is not accessible"],
    "guidance": ["Run as Administrator to enable Security Event Log detections"]
  }
}
```

**Sensor Status Values**:
- `active`: Facts have been observed from this sensor (only in run snapshots)
- `configured`: Sensor accessible, no facts observed yet (live checks)
- `missing`: Sensor not installed or not present
- `blocked`: Sensor exists but access denied

**Attack Surfaces**: `process`, `auth`, `persistence`, `network`, `evasion`, `file`

**Pipeline Components**: Runtime infrastructure (binaries present, directories writable, active run metrics)

---

### GET /api/capability/detection_plan

Detection plan with playbook dependencies. Shows what playbooks are enabled vs blocked.

**Note**: Uses **configured** sensor status for dependency resolution - showing what playbooks CAN run with the current sensor configuration, not what HAS produced facts. This is intentional for planning.

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "capability": {
      "overall_status": "partial",
      "is_admin": false,
      "sensors": [...]  // Same structure as /api/capability/status
    },
    "playbooks": {
      "total": 42,
      "enabled": [
        {
          "playbook_id": "encoded_powershell",
          "playbook_name": "Encoded PowerShell Commands",
          "name": "Encoded PowerShell Commands",
          "description": "Detects PowerShell commands with Base64-encoded content",
          "category": "execution",
          "derived_status": "enabled",
          "attack_surfaces": ["process", "evasion"],
          "blocked_by": [],
          "reasons": [],
          "mitre_techniques": ["T1059.001"],
          "mitre_tactics": ["execution"],
          "how_it_fires": "Matches when PowerShell execution includes encoded command arguments (-enc, -e, -ec) with substantial Base64 content.",
          "prerequisites": {
            "requires_admin": false,
            "requires_sysmon": true,
            "requires_security_log": false,
            "sensors": ["sysmon"],
            "fact_types": ["Exec", "ShellCommand"]
          },
          "slots_ui": [
            {
              "slot_name": "base64_pattern",
              "intent": "Detects Base64-encoded command content",
              "required": true,
              "required_fields": ["cmdline"],
              "examples_hint": ["Looks for encoded patterns in command lines"],
              "telemetry_dependency": ["Sysmon 1", "Security 4688"]
            },
            {
              "slot_name": "powershell_execution",
              "intent": "Matches PowerShell process invocation",
              "required": true,
              "required_fields": ["image", "cmdline"],
              "examples_hint": ["PowerShell.exe with encoding flags"],
              "telemetry_dependency": ["Sysmon 1", "Security 4688"]
            }
          ],
          "validation_hint_id": "encoded_powershell_whoami"  // nullable - maps to UI validation triggers
        }
      ],
      "blocked_by_telemetry": [
        {
          "playbook_id": "suspicious_logon",
          "playbook_name": "Suspicious Logon Activity",
          "derived_status": "blocked_by_telemetry",
          "attack_surfaces": ["auth"],
          "blocked_by": ["security_log"],
          "reasons": ["Security Event Log requires Administrator privileges"]
        }
      ],
      "disabled_by_config": [...],
      "skipped_invalid": [...]
    },
    "coverage_by_surface": {
      "process": ["Encoded PowerShell Commands", "Suspicious Process Spawn", ...],
      "auth": [],
      "persistence": ["Registry Run Key", ...]
    },
    "user_guidance": ["Run as Administrator to enable Security Event Log detections"]
  }
}
```

**Playbook Derived Status**:
- `enabled`: All requirements met, playbook will evaluate
- `blocked_by_telemetry`: Missing sensors or fact types
- `disabled_by_config`: Playbook YAML has `enabled: false`
- `skipped_invalid`: Playbook YAML failed to parse

**Playbook Interactivity Fields (v1.1)**:

The following fields provide intent-level playbook information for UI display without exposing raw detection patterns:

| Field | Type | Description |
|-------|------|-------------|
| `how_it_fires` | `string` | Human-readable guidance on what triggers the playbook (no regex) |
| `prerequisites` | `object` | Sensor and fact type requirements |
| `slots_ui` | `array<SlotUIDefinition>` | Enhanced slot definitions with intent |
| `validation_hint_id` | `string?` | Maps to UI validation trigger registry (debug mode only) |

**SlotUIDefinition Schema:**
```json
{
  "slot_name": "base64_pattern",
  "intent": "Detects Base64-encoded command content",
  "required": true,
  "required_fields": ["cmdline"],
  "examples_hint": ["Looks for encoded patterns in command lines"],
  "telemetry_dependency": ["Sysmon 1", "Security 4688"]
}
```

**PrerequisitesSchema:**
```json
{
  "requires_admin": false,
  "requires_sysmon": true,
  "requires_security_log": false,
  "sensors": ["sysmon"],
  "fact_types": ["Exec", "ShellCommand"]
}
```

**Validation Hint IDs** (Debug Mode Only):
The `validation_hint_id` maps to a curated registry of benign validation triggers in the UI. These are only shown when `?debug=1` query parameter is present. Known IDs:
- `encoded_powershell_whoami` - Base64 whoami for encoded PS detection
- `schtasks_create_delete` - Task scheduler create/delete cycle
- `service_create_delete` - Service create/delete cycle
- `registry_run_key` - Registry persistence test
- `certutil_decode` - Certutil base64 decode test

**Security Note**: Slot patterns (regex) are NEVER exposed in the API. The `intent` and `examples_hint` fields provide safe human-readable descriptions only.

---

### GET /api/capability/gaps (Dev-Only)

Coverage gaps analysis - internal planning tool to identify telemetry needs.

**Query Parameters:**
- `run_id` (optional): Include observed facts from a specific run

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "analyzed_at": "2026-01-12T15:30:22Z",
    "run_id": null,                    // or run_id if provided
    "attack_surfaces": [
      {
        "surface": "process",
        "configured_possible": true,
        "observed_in_run": null,       // or true/false if run_id provided
        "playbooks_enabled_count": 15,
        "playbooks_blocked_count": 2,
        "playbooks_fired_count": null, // or count if run_id provided
        "required_fact_types": ["ProcSpawn", "Exec", "ShellCommand", "ScriptExec", "ModuleLoad"],
        "available_fact_types": ["ProcSpawn", "Exec", "ShellCommand", "ModuleLoad"],
        "missing_prerequisites": [],
        "coverage_percent": 80
      },
      {
        "surface": "auth",
        "configured_possible": false,
        "observed_in_run": null,
        "playbooks_enabled_count": 0,
        "playbooks_blocked_count": 3,
        "playbooks_fired_count": null,
        "required_fact_types": ["AuthEvent", "PrivilegeBoundary"],
        "available_fact_types": [],
        "missing_prerequisites": ["Run as Administrator for Security Event Log access"],
        "coverage_percent": 0
      }
    ],
    "overall_coverage_percent": 67,
    "recommendations": [
      "Run as Administrator to unlock Security Event Log and auth detections",
      "Install Sysmon from Microsoft Sysinternals for process, network, and file monitoring"
    ],
    "summary": {
      "surfaces_fully_covered": 2,
      "surfaces_partially_covered": 3,
      "surfaces_blocked": 1,
      "total_playbooks_enabled": 25,
      "total_playbooks_blocked": 8,
      "fact_types_available": 15,
      "fact_types_total": 22
    }
  }
}
```

**Attack Surfaces**: `process`, `auth`, `persistence`, `network`, `evasion`, `file`, `credential_access`

**Fact Types Reference**:

| Fact Type | Source | Description |
|-----------|--------|-------------|
| `ProcSpawn` | Sysmon 1, Security 4688 | Process spawned another process |
| `Exec` | Sysmon 1, Security 4688 | Executable execution with cmdline |
| `ProcessAccess` | **Sysmon 10 only** | Process access event (e.g., LSASS access) |
| `OutboundConnect` | Sysmon 3 | Outbound network connection |
| `DnsResolve` | Sysmon 22 | DNS query |
| `WritePath` | Sysmon 11 | File write |
| `CreatePath` | Sysmon 11 | File creation |
| `RegistryMod` | Sysmon 12-14, Security 4657 | Registry modification |
| `PersistArtifact` | System 7045, Security 4698 | Persistence mechanism |
| `AuthEvent` | Security 4624/4625 | Authentication event |
| `LogTamper` | Security 1102, System 104 | Log clearing |
| `ProcessAccess` | **Sysmon 10** | Credential access detection (LSASS) |

**Note on ProcessAccess**: This fact type is semantically distinct from `MemAlloc`. ProcessAccess maps specifically to Sysmon Event ID 10 (Process Access) and is required for LSASS access detection. Without Sysmon, this fact type cannot be generated and the `credential_access` surface will be blocked.

**Usage**: Dev/planning tool to identify what telemetry is needed for complete coverage. Not designed for production UI display.

---

### GET /api/evidence/deref

Dereference an evidence pointer to retrieve the exact source telemetry record. Used by the UI Evidence Viewer (drawer) to show the raw JSON event that triggered a signal.

**Query Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `run_id` | Yes | Run containing the evidence |
| `stream_id` | No | Stream identifier (echoed in response, not used for lookup) |
| `segment_id` | Yes* | Segment filename (e.g., `evtx_000001.jsonl`) - must match `^[A-Za-z0-9._-]+\.jsonl$` |
| `record_index` | Yes* | Line number within segment (0-based, max 10,000,000) |
| `kind` | No | Evidence kind (default: "segment_record") |

*Required for `segment_record` kind.

**Response Shape (available=true):**
```json
{
  "success": true,
  "data": {
    "available": true,
    "evidence_ptr": {
      "kind": "segment_record",
      "run_id": "run_20260112_143022",
      "stream_id": "System",
      "segment_id": "evtx_000000.jsonl",
      "record_index": 42
    },
    "resolved": {
      "segment_path": "C:\\data\\runs\\run_20260112_143022\\segments\\evtx_000000.jsonl",
      "segment_sha256": "abc123...",
      "record_index": 42,
      "line_bytes": 1523,
      "json": { "ts_ms": 1736694622000, "host": "WORKSTATION-1", ... },
      "json_parse_error": null,
      "ts_ms": 1736694622000,
      "preview": "{\"ts_ms\":1736694622000,\"host\":\"WORKSTATION-1\"..."
    }
  }
}
```

**Response Shape (available=false):**
```json
{
  "success": true,
  "data": {
    "available": false,
    "reason_code": "SEGMENT_NOT_FOUND",
    "message": "Segment file 'evtx_000099.jsonl' not found. Available segments (first 5): [\"evtx_000000.jsonl\"]",
    "evidence_ptr": {
      "kind": "segment_record",
      "run_id": "run_20260112_143022",
      "stream_id": "System",
      "segment_id": "evtx_000099.jsonl",
      "record_index": 42
    }
  }
}
```

**Reason Codes:**
| Code | Description |
|------|-------------|
| `RUN_NOT_FOUND` | The specified run does not exist |
| `SEGMENT_NOT_FOUND` | Segment file not found in run's segments directory |
| `RECORD_INDEX_OUT_OF_RANGE` | Record index exceeds line count in segment |
| `JSON_PARSE_FAILED` | Record exists but is not valid JSON |
| `PATH_TRAVERSAL_BLOCKED` | Invalid segment_id (must match `^[A-Za-z0-9._-]+\.jsonl$`) |
| `EVIDENCE_KIND_UNSUPPORTED` | Only `segment_record` kind is supported |
| `IMPORTED_BUNDLE_MISSING_SEGMENTS` | Imported bundle doesn't include segment files |
| `IO_ERROR` | File system error reading segment |
| `SCAN_LIMIT_EXCEEDED` | Record too deep (>10M), line too large (>256KB), or scan limit (32MB) exceeded |

**Path Safety Rules (Hardened):**
- `segment_id` must match regex: `^[A-Za-z0-9._-]+\.jsonl$`
- No `..`, `/`, or `\` allowed
- Uses `safe_join_under()` to ensure resolved path stays under `{run_dir}/segments/`
- Maximum line size: 256KB
- Maximum scan bytes: 32MB
- Maximum record_index: 10,000,000

**Required Fields**: `available`, `evidence_ptr`
**Conditional Fields**: When `available=true`: `resolved`; When `available=false`: `reason_code`, `message`

---

## Contract Verification

The contract can be verified via:
- `GET /api/meta/contract` - Returns this contract version and hash
- `GET /api/meta/features` - Returns tier-aware feature flags
- UI wiring check validates `requiredKeys` per endpoint

### GET /api/meta/features

Returns current tier and feature availability for UI gating.

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "tier": "Free",
    "upgrade_url": "https://locint.io/upgrade",
    "features": {
      "run_workflow": true,
      "capability_model": true,
      "playbook_system": true,
      "signals_explain": true,
      "evidence_deref": true,
      "next_steps": true,
      "import_export": true,
      "wiring_audit": true,
      "diff_phase": true,
      "baselines": false,
      "diff_advanced": false,
      "custom_packs": false,
      "case_summary": false
    },
    "gating": {
      "baselines": { "endpoint": "/api/baselines", "required_tier": "Pro" },
      "diff_advanced": { "endpoint": "/api/runs/:id/diff?mode=baseline|marker", "required_tier": "Pro" },
      "custom_packs": { "endpoint": "/api/packs/:custom_name", "required_tier": "Pro" },
      "case_summary": { "endpoint": "/api/runs/:id/case_summary", "required_tier": "Pro" }
    }
  }
}
```

**Feature Flags:**

| Feature | Free | Pro+ | Description |
|---------|------|------|-------------|
| `run_workflow` | ✓ | ✓ | Start/stop/manage runs |
| `capability_model` | ✓ | ✓ | Sensor capability detection |
| `playbook_system` | ✓ | ✓ | Builtin playbook analysis |
| `signals_explain` | ✓ | ✓ | Full explainability for signals |
| `evidence_deref` | ✓ | ✓ | Raw event dereference |
| `next_steps` | ✓ | ✓ | Guided next steps |
| `import_export` | ✓ | ✓ | Bundle import/export |
| `wiring_audit` | ✓ | ✓ | Debug wiring panel |
| `diff_phase` | ✓ | ✓ | Diff in phase mode |
| `baselines` | ✗ | ✓ | Mark/manage baselines |
| `diff_advanced` | ✗ | ✓ | Diff in baseline/marker mode |
| `custom_packs` | ✗ | ✓ | Custom content packs |
| `case_summary` | ✗ | ✓ | Case summary export |

### Contract Hash Computation
```
v1-core-{YYYYMM} e.g. v1-core-202601
```

Update the hash when making breaking changes to response shapes.

---

## UI Binding Notes

### List Endpoint Unwrapping
```javascript
// OLD (inconsistent):
const runs = response.data;  // array
const signals = response.data.signals;  // named field

// NEW (consistent - always named field):
const runs = response.data.runs;
const signals = response.data.signals;
```

### ExplainResponse Unwrapping
```javascript
const { available, signal, source, evidence_ptrs, evidence_ptrs_count, confidence } = response.data;
if (!available) {
  const { reason_code, message, partial_context } = response.data;
  // Show unavailable banner
}
```

---

## Pro/Team Foundation Endpoints (v1.1)

### 11. POST /api/runs/:id/baseline

Mark a run as baseline for comparison.

**Request Body:**
```json
{
  "scope": "host",           // "host" | "install"
  "description": "Golden baseline",
  "set_as_default": true     // Make this the default for scope
}
```

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "run_id": "run_20260112_143022",
    "scope": "host",
    "marked_at": "2026-01-12T15:00:00Z",
    "description": "Golden baseline",
    "is_default": true,
    "metrics_snapshot": {
      "events_count": 1234,
      "segments_count": 12,
      "facts_count": 567,
      "signals_count": 3
    },
    "message": "Run 'run_20260112_143022' marked as host baseline"
  }
}
```

**Required Fields**: `run_id`, `scope`, `marked_at`

---

### 12. GET /api/baselines

List all marked baselines.

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "baselines": [
      {
        "run_id": "run_20260112_143022",
        "scope": "host",
        "marked_at": "2026-01-12T15:00:00Z",
        "description": "Golden baseline",
        "is_default": true,
        "metrics_snapshot": { ... }
      }
    ],
    "defaults": {
      "host": "run_20260112_143022",
      "install": null
    },
    "count": 1
  }
}
```

**Required Fields**: `baselines`, `defaults`, `count`

---

### 13. GET /api/runs/:id/case_summary

Export case summary JSON for reporting.

**Contract Version**: `1.1.0`  
**Contract Hash**: `v1-case-202601`

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "contract_version": "1.1.0",
    "contract_hash": "v1-case-202601",
    "schema_version": "1.0.0",
    "generated_at": "2026-01-12T16:00:00Z",
    "run_id": "run_20260112_143022",
    "name": "Investigation Alpha",
    
    "capability_snapshot": {
      "is_admin": true,
      "sysmon_installed": true,
      "security_log_accessible": true,
      "overall_status": "full",
      "enabled_sensors": ["sysmon", "security"],
      "fact_types_observed": ["exec", "netconn", "authevent", "regmod"]
    },
    
    "telemetry_caveats": [
      "⚠️ Sysmon not installed - Process tree and network connections may be incomplete"
    ],
    
    "evidence_availability": {
      "segments_present": true,
      "segments_count": 12,
      "total_findings": 8,
      "findings_with_evidence": 7,
      "findings_without_evidence": 1,
      "availability_rate": 0.875,
      "unavailable_reasons": ["AGGREGATED_DATA"]
    },
    
    "run_story": "This capture ran for 15 minutes...",
    "next_steps": [
      {
        "priority": 1,
        "action": "Review critical findings immediately",
        "rationale": "Critical severity findings may indicate active compromise"
      }
    ],
    "summary": {
      "started_at": "2026-01-12T14:30:22Z",
      "stopped_at": "2026-01-12T14:45:54Z",
      "status": "completed",
      "events_total": 12345,
      "segments_count": 12,
      "facts_extracted": 567,
      "signals_count": 8,
      "earliest_ts": 1736694622000,
      "latest_ts": 1736695554000
    },
    "top_findings": [
      {
        "id": "sig_001",
        "rule_id": "persistence/scheduled_task",
        "title": "Suspicious Scheduled Task Created",
        "severity": "critical",
        "category": "persistence",
        "confidence": 0.95,
        "ts_start": 1736694800000,
        "evidence_available": true
      }
    ],
    "top_changes": [
      {
        "fact_key": "service:malware_svc",
        "fact_type": "service_change",
        "ts": 1736694900000
      }
    ],
    "evidence_pointers": []
  }
}
```

**Contract Metadata Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `contract_version` | string | Semantic version of case summary contract |
| `contract_hash` | string | Content-addressable hash for contract validation |

**Capability Snapshot Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `is_admin` | bool | Whether capture ran with admin privileges |
| `sysmon_installed` | bool | Whether Sysmon was available |
| `security_log_accessible` | bool | Whether Security Event Log was accessible |
| `overall_status` | string | `full`, `partial`, `limited`, or `blocked` |
| `enabled_sensors` | array | List of active sensor identifiers |
| `fact_types_observed` | array | Fact types actually observed in the run |

**Telemetry Caveats:**
- Generated from capability snapshot
- Warns consumers about detection blind spots
- Example: "Sysmon not installed - Process tree incomplete"

**Evidence Availability Stats:**
| Field | Type | Description |
|-------|------|-------------|
| `segments_present` | bool | Whether segments directory exists |
| `segments_count` | i32 | Number of segment files |
| `total_findings` | i32 | Total signals/findings |
| `findings_with_evidence` | i32 | Findings with dereferenceable evidence |
| `findings_without_evidence` | i32 | Findings without evidence pointers |
| `availability_rate` | f64 | Ratio of findings with evidence (0.0-1.0) |
| `unavailable_reasons` | array | Reasons why evidence is unavailable |

**Required Fields**: `contract_version`, `contract_hash`, `schema_version`, `generated_at`, `run_id`, `run_story`, `summary`, `capability_snapshot`, `evidence_availability`

---

### 14. POST /api/import/validate

Validate a bundle ZIP before import.

**Request**: Multipart form with `file` or `bundle` field.

**Response Shape (valid):**
```json
{
  "success": true,
  "data": {
    "available": true,
    "reason_code": "",
    "missing_artifacts": [],
    "found_artifacts": ["run_meta.json", "workbench.db"],
    "schema_version": "1.0.0",
    "schema_supported": true,
    "suggested_fix": "",
    "can_compile": true,
    "can_diff": true,
    "can_case_summary": true,
    "evidence_deref_available": true
  }
}
```

**Response Shape (invalid):**
```json
{
  "success": true,
  "data": {
    "available": false,
    "reason_code": "MISSING_DB_AND_SEGMENTS",
    "missing_artifacts": ["workbench.db", "segments/"],
    "found_artifacts": ["run_meta.json"],
    "schema_version": "1.0.0",
    "schema_supported": true,
    "suggested_fix": "Bundle must contain either workbench.db (for immediate use) or segments/ directory (for compilation)",
    "can_compile": true,
    "can_diff": false,
    "can_case_summary": false,
    "evidence_deref_available": false
  }
}
```

**Reason Codes:**
| Code | Description |
|------|-------------|
| `NO_FILE_UPLOADED` | No file provided in multipart form |
| `INVALID_ZIP` | ZIP file is corrupt, invalid, or extraction failed |
| `MISSING_RUN_META` | Bundle missing required `run_meta.json` |
| `SCHEMA_UNSUPPORTED` | Schema version not in supported list |
| `MISSING_DB_AND_SEGMENTS` | Bundle has neither `workbench.db` nor `segments/` directory |

**Capability Flags:**
| Flag | Description |
|------|-------------|
| `can_compile` | Bundle has run_meta.json (compilation possible) |
| `can_diff` | Bundle has workbench.db (diff available) |
| `can_case_summary` | Bundle has workbench.db (case summary available) |
| `evidence_deref_available` | Bundle has segments/ directory (evidence dereference available) |

**Bundle Acceptance Logic:**
- Bundle MUST contain `run_meta.json`
- Bundle MUST contain EITHER `workbench.db` OR `segments/` directory
- Bundles with only segments can be compiled to produce workbench.db
- Bundles with only workbench.db cannot dereference evidence

**Required Fields**: `available`, `reason_code`, `missing_artifacts`, `found_artifacts`, `can_compile`, `can_diff`, `can_case_summary`, `evidence_deref_available`

---

### 15. GET /api/packs

List available content packs.

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "packs": [
      {
        "name": "builtin",
        "display_name": "Built-in Detections",
        "version": "1.0.0",
        "schema_version": "1.0.0",
        "description": "Default detection playbooks",
        "playbook_count": 42,
        "is_builtin": true,
        "enabled": true,
        "integrity": {
          "playbooks_hash": "sha256:abc123...",
          "validated": true,
          "validation_errors": []
        }
      }
    ],
    "rejected_packs": [
      {
        "path": "C:\\custom\\bad_pack",
        "reason": "Missing pack.yaml manifest"
      }
    ],
    "tier_allows_custom": true,
    "count": 1
  }
}
```

**Tier Gating:**
- Free tier: Only built-in pack available, `tier_allows_custom: false`
- Pro/Team/Enterprise: Custom packs allowed, `tier_allows_custom: true`

**Pack Validation:**
- Each pack must have a valid `pack.yaml` manifest
- Schema version must be in supported versions (`1.0.0`, `1.1.0`)
- Playbooks are counted and hashed for integrity verification

**Rejected Packs:**
- Packs that fail validation appear in `rejected_packs` with reason
- Reasons include: missing manifest, invalid schema version, YAML parse errors

**Required Fields**: `packs`, `rejected_packs`, `tier_allows_custom`, `count`

---

### 16. GET /api/packs/:pack_name

Get content pack details.

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "name": "builtin",
    "display_name": "Built-in Detections",
    "version": "1.0.0",
    "schema_version": "1.0.0",
    "description": "Default detection playbooks",
    "author": "LocInt Team",
    "playbook_count": 42,
    "playbooks": [
      { 
        "filename": "scheduled_task_persistence.yaml", 
        "path": "...",
        "hash": "sha256:def456..."
      }
    ],
    "is_builtin": true,
    "enabled": true,
    "integrity": {
      "playbooks_hash": "sha256:abc123...",
      "validated": true,
      "validation_errors": []
    }
  }
}
```

**Tier Gating:**
- Free tier requesting custom pack returns:
  ```json
  {
    "success": false,
    "error": "Custom packs require Pro tier or higher",
    "code": "TIER_BLOCKED"
  }
  ```

**Required Fields**: `name`, `version`, `schema_version`, `playbook_count`, `integrity`

---

### Diff v2 Extended Query Parameter (Pro)

The `/api/runs/:id/diff` endpoint now accepts an additional parameter:

| Param | Required | Default | Description |
|-------|----------|---------|-------------|
| `baseline_filter` | No | `false` | When `true` with baseline mode, suppress unchanged baseline keys |

When `baseline_filter=true`:
- Keys that exist unchanged in both baseline and current run are hidden
- High-severity persistence modifications remain visible regardless
- Reduces noise when comparing against a known-good baseline

---

## Team Tier Endpoints

**Schema Version**: 1.1.0 (Hardened for SMB/NAS)

All Team endpoints require Team tier. When called without Team tier, they return HTTP 403:

```json
{
  "success": false,
  "error": {
    "code": "FEATURE_LOCKED",
    "feature": "Team Case Store",
    "required_tier": "Team",
    "current_tier": "Free",
    "upgrade_url": "https://locint.io/upgrade"
  }
}
```

### Team Case Store Locking Protocol

The case store uses file-based locking with heartbeat support for SMB/NAS safety:

**Lock Characteristics:**
- **Lock timeout**: 5 minutes (configurable via `LOCINT_CASE_LOCK_TIMEOUT_SECS`)
- **Heartbeat interval**: 30 seconds (lock holder must update heartbeat)
- **Stale detection**: Lock considered stale if `last_heartbeat_at` > timeout
- **Fallback**: If heartbeat timestamp missing, uses file modification time

**Lock File Format** (`{store}/.locks/{case_id}.lock`):
```json
{
  "install_id": "inst_abc123",
  "host_name": "ANALYST-PC",
  "pid": 12345,
  "acquired_at": "2025-01-10T12:00:00Z",
  "last_heartbeat_at": "2025-01-10T12:00:30Z"
}
```

**Lock Error Response:**
```json
{
  "success": false,
  "error": "Case is locked by another process",
  "code": "CASE_LOCKED",
  "lock_owner": {
    "install_id": "inst_abc123",
    "host_name": "ANALYST-PC",
    "pid": 12345,
    "acquired_at": "2025-01-10T12:00:00Z",
    "last_heartbeat_at": "2025-01-10T12:00:30Z"
  }
}
```

### Team Case Store Reason Codes

| Code | HTTP | Description |
|------|------|-------------|
| `STORE_NOT_CONFIGURED` | 503 | No case store path configured |
| `STORE_UNREACHABLE` | 503 | Store path doesn't exist or network unreachable |
| `STORE_READONLY` | 503 | Store path is not writable |
| `INVALID_CASE_ID` | 400 | Case ID contains invalid characters |
| `CASE_NOT_FOUND` | 404 | Case doesn't exist in store |
| `CASE_LOCKED` | 409 | Another process holds the lock |
| `LOCK_ACQUIRE_FAILED` | 409 | Could not acquire lock |
| `RUN_NOT_FOUND` | 404 | Local run doesn't exist |
| `RUN_ALREADY_PUBLISHED` | 409 | Run already published to case |
| `BUNDLE_FAILED` | 500 | Failed to create run bundle |
| `TEMP_WRITE_FAILED` | 500 | Failed to write temp file to store |
| `HASH_MISMATCH` | 500 | SHA256 verification failed after copy |
| `ATOMIC_RENAME_FAILED` | 500 | Failed to rename temp to final |
| `WRITE_FAILED` | 500 | General write failure |

### Two-Phase Atomic Publish

Run publishing uses a two-phase commit for SMB safety:

1. **Phase 1**: Create bundle locally, compute SHA256
2. **Phase 2**: Write bundle to `{case}/runs/{run_id}.zip.tmp`
3. **Phase 3**: Re-read temp file, verify size and SHA256
4. **Phase 4**: Atomic rename `.zip.tmp` → `.zip`
5. **Phase 5**: Update `case.json` with run entry

**Failure Recovery:**
- On any failure in phases 2-4, temp file is deleted
- Bundle is never left in partial/corrupt state
- `case.json` update failure after publish logs warning but succeeds

### Provenance Attribution

All case store operations include provenance fields for audit:

**Note Entry** (`notes.jsonl`):
```json
{
  "note_id": "note_1736500000_1234",
  "content": "Found evidence of lateral movement",
  "created_at": "2025-01-10T14:00:00Z",
  "install_id": "inst_abc123",
  "host_name": "ANALYST-PC",
  "user_hint": "jsmith"
}
```

**Audit Event** (`audit/events.jsonl`):
```json
{
  "event": "run_published",
  "timestamp": "2025-01-10T12:00:00Z",
  "install_id": "inst_abc123",
  "host_name": "ANALYST-PC",
  "user_hint": "jsmith",
  "case_id": "case_1736500000_abc123",
  "run_id": "run_1736500000",
  "bundle_size": 1048576,
  "sha256": "a1b2c3d4..."
}
```

**Run Entry** (`case.json` runs array):
```json
{
  "run_id": "run_1736500000",
  "published_at": "2025-01-10T12:00:00Z",
  "bundle_filename": "run_1736500000.zip",
  "bundle_size": 1048576,
  "sha256": "a1b2c3d4...",
  "published_by": "inst_abc123",
  "publisher_host": "ANALYST-PC"
}
```

### 17. GET /api/team/store/status

Check team case store configuration and availability.

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "configured": true,
    "store_dir": "\\\\server\\share\\locint_cases",
    "available": true,
    "writable": true,
    "reason": null
  }
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `configured` | bool | Whether a store path is configured |
| `store_dir` | string? | The configured store path |
| `available` | bool | Whether the store is accessible |
| `writable` | bool | Whether the store is writable |
| `reason` | string? | Reason if not available/writable |

---

### 18. POST /api/team/store/configure

Configure the team case store path.

**Request:**
```json
{
  "case_store_dir": "\\\\server\\share\\locint_cases"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "saved": true
  }
}
```

---

### 19. GET /api/team/cases

List all cases in the team store.

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "cases": [
      {
        "case_id": "case_1736500000_abc123",
        "title": "Suspicious PowerShell Activity",
        "description": "Investigation of encoded commands",
        "tags": ["investigation", "powershell"],
        "run_count": 2,
        "notes_count": 5,
        "created_at": "2025-01-10T12:00:00Z",
        "updated_at": "2025-01-10T15:30:00Z"
      }
    ],
    "count": 5,
    "unreadable_count": 0
  }
}
```

**Unreadable Case Handling:**

When a case directory exists but `case.json` is corrupt or missing, the case is returned with a stub:

```json
{
  "case_id": "case_1736500000_corrupt",
  "title": "(unreadable)",
  "status": "unreadable",
  "error": "corrupt_json",
  "updated_at": "1970-01-01T00:00:00Z"
}
```

Error values: `corrupt_json`, `missing_json`, `read_failed`

Unreadable cases sort to the bottom (1970 date). UI should display these distinctly.

**Required Fields**: `cases` (array), each with `case_id`, `title`, `tags`

---

### 20. POST /api/team/cases

Create a new case.

**Request:**
```json
{
  "title": "Investigation Title",
  "description": "Optional description",
  "tags": ["tag1", "tag2"]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "case_id": "case_1736500000_abc123"
  }
}
```

**Required Fields**: `case_id`

---

### 21. GET /api/team/cases/:case_id

Get case details including recent notes.

**Response Shape:**
```json
{
  "success": true,
  "data": {
    "case_id": "case_1736500000_abc123",
    "title": "Investigation Title",
    "description": "Description text",
    "tags": ["tag1", "tag2"],
    "runs": [
      {
        "run_id": "run_1736500000",
        "published_at": "2025-01-10T12:00:00Z",
        "published_by": "ANALYST-PC"
      }
    ],
    "recent_notes": [
      {
        "ts": "2025-01-10T14:00:00Z",
        "author": "ANALYST-PC",
        "content": "Found evidence of lateral movement"
      }
    ],
    "created_at": "2025-01-10T12:00:00Z",
    "updated_at": "2025-01-10T15:30:00Z"
  }
}
```

**Required Fields**: `case_id`, `title`, `tags`, `runs`, `recent_notes`

---

### 22. POST /api/team/cases/:case_id/tags

Add or remove tags from a case.

**Request:**
```json
{
  "add": ["new-tag"],
  "remove": ["old-tag"]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "updated": true,
    "tags": ["new-tag", "existing-tag"]
  }
}
```

---

### 23. POST /api/team/cases/:case_id/notes

Add a note to the case (append-only, no lock required).

**Request:**
```json
{
  "content": "Note content text"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "note_id": "note_1736500000_1234",
    "content": "Note content text",
    "created_at": "2025-01-10T14:00:00Z",
    "install_id": "inst_abc123",
    "host_name": "ANALYST-PC",
    "user_hint": "jsmith"
  }
}
```

Notes are append-only to `notes.jsonl`. If case is locked when updating `notes_count` in `case.json`, the note is still added but count update is skipped (non-blocking).

---

### 24. POST /api/team/cases/:case_id/runs

Publish a local run to the case store (two-phase atomic).

**Request:**
```json
{
  "run_id": "run_1736500000"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "published": true,
    "run": {
      "run_id": "run_1736500000",
      "published_at": "2025-01-10T12:00:00Z",
      "bundle_filename": "run_1736500000.zip",
      "bundle_size": 1048576,
      "sha256": "a1b2c3d4e5f6...",
      "published_by": "inst_abc123",
      "publisher_host": "ANALYST-PC"
    }
  }
}
```

**Errors:**
- `RUN_NOT_FOUND` - The specified run doesn't exist locally
- `RUN_ALREADY_PUBLISHED` - The run is already in the case
- `CASE_LOCKED` - Another process holds the lock
- `TEMP_WRITE_FAILED` - Failed to write temp file to store
- `HASH_MISMATCH` - SHA256 verification failed after copy
- `ATOMIC_RENAME_FAILED` - Failed to rename temp to final

---

### 25. POST /api/team/cases/:case_id/runs/:run_id/import

Import a published run from the case store to local storage.

**Response:**
```json
{
  "success": true,
  "data": {
    "imported": true,
    "local_run_id": "run_1736500000"
  }
}
```

**Errors:**
- `"Run not found in case"` - The run doesn't exist in the case store

---

### 26. GET /api/team/cases/:case_id/aggregate

**Team V2 Endpoint (Hardened)** - Get aggregated view across all runs in a case.

Returns deduplicated findings with canonical dedupe keys, merged timeline, unique hosts list, 
run-level evidence availability flags, and per-finding evidence status. Supports per-case
aggregate caching for performance.

**Response:**
```json
{
  "success": true,
  "data": {
    "case_id": "550e8400-e29b-41d4-a716-446655440000",
    "run_count": 3,
    "hosts": ["WORKSTATION-01", "SERVER-02"],
    "cache_hit": true,
    "per_host_findings": [
      {
        "dedupe_key": "playbook_windows_detection|sus_powershell_encoded|signal|detector_42::proc_key_abc123",
        "rule_id": "sus_powershell_encoded",
        "title": "Encoded PowerShell Command",
        "total_count": 3,
        "first_seen_ts": "2025-01-08T10:00:00Z",
        "last_seen_ts": "2025-01-08T14:30:00Z",
        "run_ids_involved": ["run_001", "run_002"],
        "hosts_involved": ["WORKSTATION-01"],
        "top_signal_ref": {
          "run_id": "run_001",
          "signal_id": "sig_abc123"
        },
        "evidence_available": true,
        "evidence_available_count": 3,
        "evidence_ptr_sample": "etl_segment_42|offset:1024|len:512"
      }
    ],
    "cross_host_findings": [
      {
        "dedupe_key": "playbook_windows_detection|sus_powershell_encoded|signal|detector_42::proc_key_abc123",
        "rule_id": "sus_powershell_encoded",
        "title": "Encoded PowerShell Command",
        "total_count": 5,
        "first_seen_ts": "2025-01-08T10:00:00Z",
        "last_seen_ts": "2025-01-08T14:30:00Z",
        "run_ids_involved": ["run_001", "run_002", "run_003"],
        "hosts_involved": ["WORKSTATION-01", "SERVER-02"],
        "top_signal_ref": {
          "run_id": "run_001",
          "signal_id": "sig_abc123"
        },
        "evidence_available": true,
        "evidence_available_count": 4,
        "evidence_ptr_sample": "etl_segment_42|offset:1024|len:512"
      }
    ],
    "runs": [
      {
        "run_id": "run_001",
        "host": "WORKSTATION-01",
        "signal_count": 12,
        "segments_present": true,
        "evidence_deref_available": true,
        "evidence_reason_code": null
      },
      {
        "run_id": "run_002",
        "host": "SERVER-02",
        "signal_count": 8,
        "segments_present": false,
        "evidence_deref_available": false,
        "evidence_reason_code": "segments_missing"
      }
    ],
    "timeline": [
      {
        "timestamp": "2025-01-08T10:00:00Z",
        "event": "run_started",
        "host": "WORKSTATION-01",
        "run_id": "run_001"
      },
      {
        "timestamp": "2025-01-08T10:05:00Z",
        "event": "run_published",
        "host": "WORKSTATION-01",
        "run_id": "run_001"
      }
    ],
    "merged_at": "2025-01-08T15:30:00Z"
  }
}
```

**Dedupe Key Format:**
The canonical dedupe key follows the pattern `rule_key::entity_key`:
- **rule_key**: `playbook_id|rule_id|signal_type|detector_id` (or `unknown_rule` fallback)
- **entity_key**: First non-empty in priority order:
  1. `proc_key` - Process entity key
  2. `file_key` - File entity key
  3. `ip:port` - Network endpoint (formatted as `${remote_ip}:${port}`)
  4. `identity_key` - User/identity entity key
  5. `host` - Host name
  6. `unknown_entity` - Fallback

**Network Endpoint Extraction:**
The `ip:port` entity is extracted from signal metadata fields:
- IP: `remote_ip`, `ip`, `dest_ip`, or `destination_ip`
- Port: `port`, `dest_port`, `destination_port`, or `remote_port`

**Dedupe Modes:**
- `per_host_findings`: Signals deduplicated within each host (preserves per-host uniqueness)
- `cross_host_findings`: Signals deduplicated across all hosts (shows unique patterns)

**Evidence Availability:**
- `segments_present`: Whether the run bundle contains ETL segments
- `evidence_deref_available`: Whether evidence can be dereferenced from this run
- `evidence_reason_code`: Reason code when evidence is unavailable:
  - `segments_missing` - No segments directory in bundle
  - `db_unavailable` - workbench.db could not be read
  - `ptr_format_error` - Evidence pointer format is invalid

**Caching:**
- Aggregate is cached in `<case_dir>/aggregate_cache.json`
- Cache version: `2.0.0`
- Cache inputs per run:
  ```json
  {
    "run_id": "run_001",
    "bundle_filename": "run_001.zip",
    "sha256": "abc123...",
    "published_at": null,
    "size_bytes": 1048576
  }
  ```
- Cache invalidation triggers:
  - `case.json` mtime changed
  - Run list changed (additions, removals)
  - Bundle sha256 mismatch (bundle replaced/corrupted)
  - Bundle size changed
  - Cache version mismatch
- `cache_hit: true/false` indicates whether the response was served from cache

**Notes:**
- Timeline is limited to 100 events
- Findings limited to 1000 signals per run for performance
- Full signal extraction from `workbench.db` inside ZIP bundles
- UI shows "Cross-Host" / "Per-Host" toggle to switch dedupe modes

**Errors:**
- `CASE_NOT_FOUND` - Case doesn't exist
- `STORE_NOT_AVAILABLE` - Case store unreachable
- `AGGREGATE_COMPUTE_ERROR` - Failed to compute aggregate (check server logs)

---

## Pro: Entity Explorer Endpoints

### GET /api/runs/:run_id/entities

**Tier**: Pro (returns 403 FEATURE_LOCKED for Free tier)

Returns all entities observed in a run, grouped by type.

**Response:**
```json
{
  "success": true,
  "data": {
    "processes": [
      {
        "value": "cmd.exe",
        "count": 15,
        "first_seen": 1704067200000,
        "last_seen": 1704070800000,
        "top_signals": ["T1059.001", "T1055"]
      }
    ],
    "files": [
      {
        "value": "C:\\Windows\\Temp\\malware.exe",
        "count": 3,
        "first_seen": 1704067500000,
        "last_seen": 1704068000000,
        "top_signals": ["T1204.002"]
      }
    ],
    "ips": [
      {
        "value": "192.168.1.100",
        "count": 42,
        "first_seen": 1704067200000,
        "last_seen": 1704070800000,
        "top_signals": ["T1071"]
      }
    ],
    "users": [
      {
        "value": "SYSTEM",
        "count": 200,
        "first_seen": 1704067200000,
        "last_seen": 1704070800000,
        "top_signals": []
      }
    ],
    "hosts": [
      {
        "value": "WORKSTATION-01",
        "count": 500,
        "first_seen": 1704067200000,
        "last_seen": 1704070800000,
        "top_signals": ["T1059", "T1055"]
      }
    ]
  }
}
```

**Entity Fields:**
- `value`: Entity identifier (process name, file path, IP address, username, hostname)
- `count`: Number of observations in the run
- `first_seen`: Timestamp (ms) of first observation
- `last_seen`: Timestamp (ms) of last observation
- `top_signals`: Array of signal types associated with this entity (up to 5)

**Notes:**
- Entities are extracted from `entity_rollup` table in workbench.db
- Each entity type array is sorted by count descending
- Maximum 500 entities per type returned

---

### GET /api/runs/:run_id/pivot

**Tier**: Pro (returns 403 FEATURE_LOCKED for Free tier)

Pivots from an entity to all related findings, changes, and evidence.

**Query Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `kind` | Yes | Entity type: `process`, `proc`, `file`, `ip`, `network`, `user`, `host` |
| `value` | Yes | Entity identifier (e.g., `cmd.exe`, `192.168.1.1`) |

**Response:**
```json
{
  "success": true,
  "data": {
    "entity": {
      "kind": "process",
      "value": "cmd.exe"
    },
    "related_findings": [
      {
        "signal_id": "sig_001",
        "signal_type": "T1059.001_CommandLineExec",
        "severity": "high",
        "ts": 1704067500000
      }
    ],
    "related_changes": [
      {
        "category": "Process",
        "direction": "added",
        "label": "cmd.exe spawned by powershell.exe",
        "key": "proc::cmd.exe::powershell.exe",
        "novelty": "new",
        "novelty_basis": "first_appearance_in_current_run"
      }
    ],
    "related_evidence_ptrs": [
      "ptr://run_001/evtx_000001.jsonl#42",
      "ptr://run_001/evtx_000001.jsonl#108"
    ],
    "mini_timeline": [
      {
        "ts": 1704067500000,
        "type": "signal",
        "label": "T1059.001 fired"
      },
      {
        "ts": 1704067600000,
        "type": "change",
        "label": "Process added"
      }
    ]
  }
}
```

**Kind Mapping:**
| Query Value | Maps To |
|-------------|---------|
| `process`, `proc` | `proc_key` in entity_rollup |
| `file` | `file_key` in entity_rollup |
| `ip`, `network` | `metadata` (IP addresses) |
| `user` | `identity_key` in entity_rollup |
| `host` | `host` in entity_rollup |

**Notes:**
- `related_findings`: Signals where entity appears in matched facts
- `related_changes`: Diff changes involving this entity
- `related_evidence_ptrs`: Evidence pointers (NOT dereferenced - read-only)
- `mini_timeline`: Combined chronological view (limited to 50 events)

---

### POST /api/runs/:run_id/export/case_pack

**Tier**: Pro (returns 403 FEATURE_LOCKED for Free tier)

Exports a self-contained case pack ZIP for client sharing.

**Request Body:**
```json
{
  "include": {
    "summary": true,
    "findings": true,
    "changes": true,
    "evidence": true,
    "next_steps": true
  }
}
```

**Response:** Binary ZIP file (`application/zip`)

**ZIP Contents:**
```
case_pack_<run_id>.zip
├── manifest.json           # Pack metadata and schema version
├── case_summary.json       # Run metadata, host info, timestamps
├── findings.json           # All signals from the run
├── changes.json            # All diff changes (with novelty)
├── next_steps.json         # Recommended actions
└── evidence/
    └── records/            # Evidence JSON files (if include.evidence)
        ├── evt_001.json
        └── evt_002.json
```

**manifest.json Schema:**
```json
{
  "schema_version": "1.0.0",
  "generated_at": "2024-01-01T12:00:00Z",
  "run_id": "run_001",
  "includes": ["summary", "findings", "changes", "evidence", "next_steps"]
}
```

**Notes:**
- Case pack is self-contained (no DB access required to view)
- Designed for sharing with clients or archiving
- Evidence records are included as JSON (not raw EVTX)
- Size limit: 50MB (large runs may be truncated)

---

## Pro: Novelty Scoring

Novelty scoring is automatically included in diff responses for Pro tier users.

**DiffChange with Novelty:**
```json
{
  "category": "Process",
  "direction": "added",
  "label": "mimikatz.exe",
  "key": "proc::mimikatz.exe",
  "novelty": "new",
  "novelty_basis": "first_appearance_in_current_run",
  "count_after": 5,
  "count_before": 0
}
```

**Novelty Values:**
| Value | Meaning | Typical Basis |
|-------|---------|---------------|
| `new` | First time seeing this artifact | `first_appearance_in_current_run` |
| `known` | Previously seen, now absent | `present_in_baseline_but_absent_now` |
| `changed` | Count or persistence modified | `count_delta_N` or `persistence_path_modified` |
| `reappeared` | Previously removed, now back | `reappeared_after_previous_removal` |

**Notes:**
- Novelty is DETERMINISTIC (no AI, no randomness)
- Based purely on diff calculations
- Free tier receives diff without novelty fields

---

## Import Report Enhancement

The `POST /api/import/bundle` endpoint now returns an import report.

**Response with Import Report:**
```json
{
  "success": true,
  "data": {
    "run_id": "imported_20240101_120000",
    "imported": true,
    "read_only": true,
    "message": "Bundle imported successfully"
  },
  "import_report": {
    "normalized_artifacts": [
      {
        "artifact": "segments/evtx_000001.jsonl",
        "size": 1048576,
        "category": "segment"
      }
    ],
    "dropped_artifacts": [
      {
        "artifact": "raw.evtx",
        "reason": "Raw EVTX not supported - convert to JSONL first",
        "category": "evtx"
      }
    ],
    "evidence_deref_available": true,
    "summary": {
      "total_files": 10,
      "imported_files": 8,
      "dropped_files": 2,
      "segment_count": 5,
      "has_manifest": true,
      "has_run_meta": true,
      "has_database": true
    }
  }
}
```

**Artifact Categories:**
- `segment`: JSONL telemetry segments (enable evidence deref)
- `database`: SQLite database files
- `manifest`: Bundle manifest files
- `metadata`: Run metadata files
- `json`: Other JSON files
- `evtx`: Raw EVTX files (dropped - need conversion)
- `other`: Unrecognized file types

**Notes:**
- Import report is returned even on partial failure
- `evidence_deref_available` is true only if JSONL segments are present
- Dropped artifacts include reason codes for debugging

# Explainability API Reference

> **Version**: 2.0 (Post demo-mode removal)
> **Updated**: 2025-01-XX

## Overview

The Explainability API provides end-to-end truth from real capture data through signal generation to explain bundles. All data is derived from actual telemetry—there is no simulation or demo mode.

## Core Principles

1. **End-to-End Truth**: Real capture → real signals → real explanations
2. **Run Isolation**: Signals are scoped by `run_id`, not timestamp heuristics
3. **Detector Provenance**: Every signal carries `detector_id`, `detector_version`, `source_sensor`
4. **Deref-Ready Evidence**: Evidence pointers have required fields for dereferencing
5. **Round-Trip Preservation**: Import/export preserves all explainability fields

---

## Endpoints

### GET /api/signals

List signals with optional filters and pagination.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `run_id` | string | Filter by run ID (exact match) |
| `host` | string | Filter by host |
| `signal_type` | string | Filter by signal type |
| `severity` | string | Filter by severity (critical/high/medium/low/info) |
| `limit` | int | Max results (default: 100, max: 1000) |
| `offset` | int | Pagination offset (default: 0) |

**Response:**
```json
{
  "ok": true,
  "data": [
    {
      "signal_id": "sig_abc123",
      "signal_type": "ProcessInjection",
      "ts": 1700000000000,
      "severity": "critical",
      "host": "WORKSTATION-1",
      "playbook_id": "playbook:process_injection_v2",
      "detector_version": "1.2.0",
      "risk_score": 85.0,
      "entities": { ... },
      "evidence_count": 3
    }
  ]
}
```

### GET /api/signals/:id

Get a single signal by ID.

**Response:**
```json
{
  "ok": true,
  "data": {
    "signal_id": "sig_abc123",
    "run_id": "run_20241201_100000",
    "signal_type": "ProcessInjection",
    "severity": "critical",
    "host": "WORKSTATION-1",
    "ts": 1700000000000,
    "ts_start": 1699999900000,
    "ts_end": 1700000000000,
    "proc_key": "proc_123",
    "file_key": null,
    "identity_key": "NT AUTHORITY\\SYSTEM",
    "detector_id": "playbook:process_injection_v2",
    "detector_version": "1.2.0",
    "source_sensor": "etw:kernel",
    "metadata": { "technique": "T1055" },
    "evidence_ptrs": [...],
    "dropped_evidence_count": 0
  }
}
```

### GET /api/signals/:id/explain

Get comprehensive explanation bundle for a signal.

**Response Schema: ExplainResponse**
```json
{
  "ok": true,
  "data": {
    "signal_id": "sig_abc123",
    "signal_type": "ProcessInjection",
    "ts": 1700000000000,
    "severity": "critical",
    "playbook_id": "playbook:process_injection_v2",
    "hypothesis_name": "Remote Thread Injection",
    "detector_version": "1.2.0",
    
    "entities": {
      "host": "WORKSTATION-1",
      "proc_key": "proc_123",
      "proc_path": "C:\\Windows\\System32\\svchost.exe",
      "file_key": null,
      "file_path": null,
      "identity_key": "NT AUTHORITY\\SYSTEM",
      "identity_user": "SYSTEM"
    },
    
    "evidence": [
      {
        "stream_id": "etw_kernel",
        "segment_id": 42,
        "record_index": 1337,
        "reference": "etw_kernel:42:1337",
        "ts_ms": 1700000000000,
        "event_type": "ProcessCreate",
        "summary": "Process svchost.exe created remote thread"
      }
    ],
    
    "scoring": {
      "risk_score": 85.0,
      "confidence": 0.92,
      "severity_factors": ["remote_thread", "system_process"],
      "mitigating_factors": [],
      "raw_score": 0.85,
      "components": [
        { "name": "technique_score", "value": 0.9 },
        { "name": "context_score", "value": 0.8 }
      ],
      "scoring_unavailable": false
    },
    
    "summary": "Remote thread injection detected in system process",
    "family": "defense_evasion",
    "slots": [...],
    "matched_facts": [...],
    "limitations": ["Network telemetry unavailable"],
    "generated_at": 1700000001000
  }
}
```

### GET /api/runs

List available runs.

**Response:**
```json
{
  "ok": true,
  "data": [
    {
      "run_id": "run_20241201_100000",
      "signal_count": 42,
      "earliest_ts": 1700000000000,
      "latest_ts": 1700003600000,
      "hosts": ["HOST1", "HOST2"]
    }
  ]
}
```

---

## Data Types

### StoredSignal

Core signal record with full provenance:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `signal_id` | string | Yes | Unique signal identifier |
| `run_id` | string | Yes | Run that produced this signal |
| `signal_type` | string | Yes | Detection type (e.g., ProcessInjection) |
| `severity` | string | Yes | critical/high/medium/low/info |
| `host` | string | Yes | Host where detected |
| `ts` | i64 | Yes | Primary timestamp (epoch ms) |
| `ts_start` | i64 | Yes | Window start timestamp |
| `ts_end` | i64 | Yes | Window end timestamp |
| `proc_key` | string? | No | Process entity key |
| `file_key` | string? | No | File entity key |
| `identity_key` | string? | No | Identity entity key |
| `detector_id` | string | Yes | Detector/playbook identifier |
| `detector_version` | string | Yes | Detector version |
| `source_sensor` | string | Yes | Data source (e.g., etw:kernel, sysmon) |
| `metadata` | object | Yes | Additional signal metadata |
| `evidence_ptrs` | array | Yes | Array of evidence pointers |
| `dropped_evidence_count` | int | Yes | Evidence dropped due to limits |

### EvidencePointer

Reference to raw telemetry:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `stream_id` | string | Yes | Telemetry stream identifier |
| `segment_id` | int | Yes | Segment within stream |
| `record_index` | int? | No | Record within segment |
| `reference` | string | Auto | Canonical reference string |
| `ts_ms` | i64? | No | Event timestamp |
| `event_type` | string? | No | Event type if known |
| `summary` | string? | No | Human-readable summary |

### SignalEntities

Entity context for a signal:

| Field | Type | Description |
|-------|------|-------------|
| `host` | string? | Host name |
| `proc_key` | string? | Process key |
| `proc_path` | string? | Process path |
| `proc_user` | string? | Process user |
| `file_key` | string? | File key |
| `file_path` | string? | File path |
| `identity_key` | string? | Identity key |
| `identity_user` | string? | Identity user name |

### ScoringBreakdown

Signal risk scoring details:

| Field | Type | Description |
|-------|------|-------------|
| `risk_score` | float? | Final risk score (0-100) |
| `confidence` | float? | Detection confidence (0-1) |
| `severity_factors` | string[] | Factors increasing severity |
| `mitigating_factors` | string[] | Factors decreasing severity |
| `raw_score` | float? | Raw detector score |
| `components` | array? | Score component breakdown |
| `scoring_unavailable` | bool | True if scoring couldn't be computed |

---

## Smoke Testing

Run the smoke test to validate the pipeline:

```powershell
.\scripts\smoke_explainability.ps1 -ServerUrl http://127.0.0.1:3030 -Verbose
```

The test validates:
- Server health
- Signal list with pagination
- Signal schema compliance
- Explain response structure
- Evidence pointer dereferencability
- Run isolation filtering

---

## Migration Notes

### From v1 (pre-run_id)

If upgrading from a version without `run_id`:
- New signals will have `run_id` from capture
- Old signals default to `run_id = 'unknown'`
- Query without `?run_id` to see all signals

### Demo Mode Removal

As of v2.0, demo mode has been completely removed:
- `StartRunRequest.demo_mode` field removed
- `RunStatus.demo_mode` field removed
- `RunMetrics.demo_mode` field removed
- UI demo banner removed
- All metrics now come from real telemetry only

# Pro/Team Foundation — Implementation Summary

> Extends Diff v2 with baseline system, import validation, content packs, and case summaries.
> **Scope:** Minimal, deterministic, evidence-backed only.

## Status Overview

| Feature | API | UI | Status |
|---------|-----|-----|--------|
| **P0 — Baseline System v1** | ✅ | ⏳ | Handlers implemented |
| **P1 — Import Normalization v1** | ✅ | — | Validation endpoint |
| **P2 — Custom Playbooks (Packs)** | ✅ | — | Pack listing/details |
| **P3 — Case Summary (Reports)** | ✅ | — | JSON export only |

---

## P0 — Baseline System v1 (Deterministic)

### Endpoints

#### POST `/api/runs/:run_id/baseline`
Mark a run as a baseline.

**Request Body:**
```json
{
  "scope": "host",         // "host" (this machine) or "install" (this LocInt install)
  "description": "Golden baseline after clean install",
  "set_as_default": true   // Make this the default for the scope
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "run_id": "run_20260601_120000",
    "scope": "host",
    "marked_at": "2026-06-01T12:00:00Z",
    "description": "Golden baseline after clean install",
    "is_default": true,
    "metrics_snapshot": {
      "events_count": 1234,
      "segments_count": 12,
      "facts_count": 567,
      "signals_count": 3
    },
    "message": "Run 'run_20260601_120000' marked as host baseline"
  }
}
```

#### GET `/api/baselines`
List all marked baselines.

**Response:**
```json
{
  "success": true,
  "data": {
    "baselines": [
      {
        "run_id": "run_20260601_120000",
        "scope": "host",
        "marked_at": "2026-06-01T12:00:00Z",
        "description": "Golden baseline",
        "is_default": true,
        "metrics_snapshot": { ... }
      }
    ],
    "defaults": {
      "host": "run_20260601_120000",
      "install": null
    },
    "count": 1
  }
}
```

### Storage

- **Per-run:** `runs/<run_id>/baseline.json` — Baseline metadata
- **Registry:** `baselines.json` — Global baseline registry with defaults

### Baseline-as-Filter (Diff v2 Extension)

**New Query Parameter:** `baseline_filter=true`

When enabled with baseline mode, suppresses unchanged keys that exist in baseline.
Keeps high-severity persistence modifications visible regardless of baseline.

**Example:**
```
GET /api/runs/run_20260601_150000/diff?mode=baseline&baseline_run_id=run_20260601_120000&baseline_filter=true
```

### UI Integration Points

1. **Diff UI Dropdown:** Select baseline from available baselines
2. **Run Detail View:** "Mark as Baseline" button
3. **Baseline List:** View and manage baselines in settings

---

## P1 — Import Normalization v1

### Endpoints

#### POST `/api/import/validate`
Validate a bundle ZIP before import.

**Request:** Multipart form with `file` or `bundle` field containing ZIP.

**Response (valid):**
```json
{
  "success": true,
  "data": {
    "available": true,
    "reason_code": null,
    "missing_artifacts": [],
    "found_artifacts": ["run_meta.json", "workbench.db", "segments/seg_001.bin"],
    "schema_version": "1.0.0",
    "suggested_fix": null
  }
}
```

**Response (invalid):**
```json
{
  "success": true,
  "data": {
    "available": false,
    "reason_code": "missing_required",
    "missing_artifacts": ["workbench.db"],
    "found_artifacts": ["run_meta.json"],
    "schema_version": "1.0.0",
    "suggested_fix": "Ensure bundle contains workbench.db and run_meta.json"
  }
}
```

### Reason Codes

| Code | Description |
|------|-------------|
| `no_file` | No file uploaded |
| `invalid_zip` | ZIP file is corrupt or invalid |
| `missing_required` | Required artifacts not found |

### Required Artifacts

- `workbench.db` — Run database
- `run_meta.json` — Run metadata

### Optional Artifacts

- `baseline.json` — Baseline marking (if was baseline)
- `segments/` — Raw telemetry segments

---

## P2 — Custom Playbooks (Content Packs)

### Endpoints

#### GET `/api/packs`
List available content packs.

**Response:**
```json
{
  "success": true,
  "data": {
    "packs": [
      {
        "name": "builtin",
        "display_name": "Built-in Detections",
        "version": "1.0.0",
        "description": "Default detection playbooks included with LocInt",
        "playbook_count": 42,
        "is_builtin": true,
        "enabled": true
      },
      {
        "name": "enterprise-persistence",
        "display_name": "Enterprise Persistence Pack",
        "version": "1.2.0",
        "description": "Advanced persistence detection for enterprise environments",
        "playbook_count": 15,
        "is_builtin": false,
        "enabled": true
      }
    ],
    "count": 2
  }
}
```

#### GET `/api/packs/:pack_name`
Get details for a specific pack.

**Response:**
```json
{
  "success": true,
  "data": {
    "name": "enterprise-persistence",
    "display_name": "Enterprise Persistence Pack",
    "version": "1.2.0",
    "description": "Advanced persistence detection",
    "author": "Security Team",
    "playbook_count": 15,
    "playbooks": [
      { "filename": "scheduled_task_persistence.yaml", "path": "..." },
      { "filename": "wmi_persistence.yaml", "path": "..." }
    ],
    "is_builtin": false,
    "enabled": true
  }
}
```

### Pack Structure

```
packs/
  <pack_name>/
    pack.json           # Pack metadata
    playbooks/
      windows/
        detection1.yaml
        detection2.yaml
```

### pack.json Schema

```json
{
  "name": "my-pack",
  "display_name": "My Detection Pack",
  "version": "1.0.0",
  "description": "Description of detections",
  "author": "Author Name",
  "enabled": true
}
```

### Tier Gating

- **Free:** Built-in pack only
- **Pro:** Custom packs enabled

---

## P3 — Case Summary (Reports v1)

### Endpoints

#### GET `/api/runs/:run_id/case_summary`
Export case summary JSON for a run.

**Response:**
```json
{
  "success": true,
  "data": {
    "schema_version": "1.0.0",
    "generated_at": "2026-06-01T15:30:00Z",
    "run_id": "run_20260601_120000",
    "name": "Investigation Alpha",
    "run_story": "This capture ran for 15 minutes 32 seconds and processed 12,345 events, extracting 567 facts. Analysis identified 8 signals with 2 critical and 3 high severity findings.",
    "next_steps": [
      {
        "priority": 1,
        "action": "Review critical findings immediately",
        "rationale": "Critical severity findings may indicate active compromise"
      },
      {
        "priority": 2,
        "action": "Investigate high severity findings",
        "rationale": "High severity findings warrant prompt investigation"
      }
    ],
    "summary": {
      "started_at": "2026-06-01T12:00:00Z",
      "stopped_at": "2026-06-01T12:15:32Z",
      "status": "completed",
      "events_total": 12345,
      "segments_count": 12,
      "facts_extracted": 567,
      "signals_count": 8,
      "earliest_ts": 1719835200000,
      "latest_ts": 1719836132000
    },
    "top_findings": [
      {
        "id": "sig_001",
        "rule_id": "persistence/scheduled_task",
        "title": "Suspicious Scheduled Task Created",
        "severity": "critical",
        "category": "persistence",
        "confidence": 0.95,
        "ts_start": 1719835500000
      }
    ],
    "top_changes": [
      {
        "fact_key": "service:malware_svc",
        "fact_type": "service_change",
        "ts": 1719835600000
      }
    ],
    "evidence_pointers": []
  }
}
```

### PDF Export

**Deferred.** JSON-only for v1. PDF generation may be added in future.

---

## Implementation Notes

### Files Modified

- `crates/server/src/bin/locint.rs`:
  - Added routes for all new endpoints
  - Added handlers: `set_baseline_handler`, `list_baselines_handler`, `case_summary_handler`, `import_validate_handler`, `list_packs_handler`, `get_pack_handler`
  - Added `baseline_filter` query parameter to DiffQuery
  - Updated route registry

### No Changes Required

- Diff v2 core logic (untouched, extended only via query param)
- Existing import/export handlers
- Existing playbook evaluation

### Testing Checklist

- [ ] POST `/api/runs/:run_id/baseline` marks run correctly
- [ ] GET `/api/baselines` lists all baselines with defaults
- [ ] POST `/api/import/validate` validates ZIP structure
- [ ] GET `/api/packs` lists built-in pack
- [ ] GET `/api/runs/:run_id/case_summary` returns valid JSON

### Truth Contract

All endpoints follow the LocInt truth contract:
- No invented data
- Evidence-backed assertions only
- Deterministic results
- Clear provenance

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-06 | Initial Pro/Team foundation |

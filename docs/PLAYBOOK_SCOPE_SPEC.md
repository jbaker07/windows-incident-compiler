# Playbook Scope Specification

**Version:** 1.0  
**Status:** Implemented  
**Last Updated:** 2025-01-15

## Overview

This document specifies how playbook scope is computed, persisted, and exposed through APIs. The goal is to ensure that the "Investigate" view and "playbooks fired" summary show **only** playbooks that were in scope for a specific run—never the full global catalog.

## Core Principle

> Every run has a **canonical scope** determined at run start. Evaluation happens only within that scope. APIs always return scope + reason codes.

---

## A. Scope Modes

| Mode | Trigger | effective_playbook_ids | UI Label |
|------|---------|------------------------|----------|
| `Explicit` | User selected 1+ playbooks | User's selection | "Selected Playbooks" |
| `GeneralDiscovery` | User selected 0 playbooks | General Discovery set | "General Discovery (default)" |
| `PresetDefault` | User chose a preset | Preset's playbook list | "Preset: {name}" |
| `None` | Explicitly disabled | Empty | "No playbooks" |

### General Discovery Set

When no playbooks are selected, the following default set is used:

```json
[
  "registry_autorun",
  "script_exec",
  "process_exec",
  "outbound_connect",
  "file_create",
  "credential_access",
  "defense_evasion",
  "persistence"
]
```

---

## B. Scope Computation Rules

### B1. At Run Start (supervisor)

```
IF selected_playbooks.is_empty() AND preset_id.is_none():
    mode = GeneralDiscovery
    effective = GENERAL_DISCOVERY_SET
    rationale = "No playbooks selected. Defaulted to General Discovery."
    
ELIF preset_id.is_some():
    mode = PresetDefault
    effective = resolve_preset_playbooks(preset_id)
    rationale = "Using preset '{preset_id}'."
    
ELIF selection_mode == "none":
    mode = None
    effective = []
    rationale = "Playbooks explicitly disabled."
    
ELSE:
    mode = Explicit
    effective = selected_playbooks
    rationale = "User selected {N} playbook(s)."
```

### B2. Persistence

The computed scope is persisted in `run_meta.json`:

```json
{
  "playbook_scope": {
    "mode": "GeneralDiscovery",
    "effective_playbook_ids": ["registry_autorun", "script_exec", ...],
    "rationale": {
      "reason_code": "NO_SELECTION_DEFAULTED_TO_DISCOVERY",
      "message": "No playbooks selected. Defaulted to General Discovery."
    }
  },
  "playbook_selection": ["raw", "user", "selection"]  // Legacy, kept for backward compat
}
```

### B3. Environment Variables

When spawning `locald`, supervisor sets:

| Variable | Value |
|----------|-------|
| `EDR_SELECTED_PLAYBOOKS` | Comma-separated `effective_playbook_ids` |
| `EDR_SCOPE_MODE` | The scope mode string |

---

## C. Reason Code Taxonomy

### C1. Scope-Level Reason Codes

| Code | Meaning |
|------|---------|
| `USER_SELECTED_SCOPE` | User explicitly selected these playbooks |
| `NO_SELECTION_DEFAULTED_TO_DISCOVERY` | No selection → General Discovery |
| `PRESET_APPLIED` | Preset resolved to these playbooks |
| `SCOPE_EXPLICITLY_DISABLED` | User disabled playbooks |

### C2. Evaluation-Level Reason Codes

| Code | Meaning |
|------|---------|
| `IN_SCOPE_MATCH` | Playbook is in scope and fired |
| `IN_SCOPE_NO_MATCH` | Playbook is in scope but didn't match |
| `OUT_OF_SCOPE_NOT_SELECTED` | Playbook exists but wasn't selected |
| `MISSING_SENSOR_SYSMON` | Sysmon data required but unavailable |
| `MISSING_SENSOR_ETW` | ETW data required but unavailable |
| `MISSING_SENSOR_EDR` | EDR data required but unavailable |
| `PARTIAL_VISIBILITY` | Some slots blocked due to missing data |
| `NOT_APPLICABLE_OS` | Playbook requires different OS |
| `NOT_APPLICABLE_ARCH` | Playbook requires different architecture |
| `BLOCKED_BY_SENSOR` | All slots blocked by missing sensors |
| `BACKEND_PLAYBOOK_UNKNOWN` | Selected playbook not found in catalog |
| `DEPRECATED_PLAYBOOK` | Playbook is deprecated |

### C3. Slot-Level Status

| Status | Meaning |
|--------|---------|
| `match` | Slot found matching evidence |
| `no_match` | Slot evaluated, no match |
| `blocked` | Slot couldn't evaluate (missing data) |
| `skipped` | Slot skipped (optimization) |
| `error` | Slot evaluation failed |

---

## D. API Contracts

### D1. GET /api/runs/:id

Returns run details including playbook scope:

```json
{
  "success": true,
  "data": {
    "run_id": "...",
    "playbook_scope": {
      "mode": "GeneralDiscovery",
      "effective_playbook_ids": ["registry_autorun", ...],
      "rationale": {
        "reason_code": "NO_SELECTION_DEFAULTED_TO_DISCOVERY",
        "message": "No playbooks selected. Defaulted to General Discovery."
      }
    }
  }
}
```

### D2. GET /api/runs/:id/playbooks/eval

Returns evaluation results **only for in-scope playbooks**:

```json
{
  "success": true,
  "scope": {
    "mode": "GeneralDiscovery",
    "effective_playbook_ids": ["registry_autorun", "script_exec"],
    "rationale": {
      "reason_code": "NO_SELECTION_DEFAULTED_TO_DISCOVERY",
      "message": "No playbooks selected. Defaulted to General Discovery."
    }
  },
  "visibility": {
    "sysmon": { "available": true, "event_count": 1234 },
    "etw": { "available": false, "event_count": 0 },
    "edr": { "available": false, "event_count": 0 }
  },
  "evaluations": [
    {
      "playbook_id": "registry_autorun",
      "in_scope": true,
      "scope_mode": "GeneralDiscovery",
      "status": "match",
      "reason_codes": ["IN_SCOPE_MATCH"],
      "slots": [
        {
          "slot_id": "registry_write",
          "status": "match",
          "match_count": 3,
          "reason_codes": []
        }
      ]
    }
  ],
  "out_of_scope": ["advanced_persistence", "lateral_movement"],
  "capability": { ... }  // Legacy field, kept for backward compat
}
```

### D3. Response Invariants

1. `evaluations` array contains **only** playbooks where `in_scope == true`
2. `out_of_scope` array lists playbook IDs that exist but weren't selected
3. Every evaluation has at least one `reason_code`
4. Slot-level `reason_codes` explain blocking when `status == "blocked"`

---

## E. Acceptance Test Cases

### E1. Explicit Selection (1+ playbooks)

**Setup:**
- User selects `["registry_autorun", "script_exec"]`
- Import has Sysmon data

**Expected:**
```json
{
  "scope": {
    "mode": "Explicit",
    "effective_playbook_ids": ["registry_autorun", "script_exec"],
    "rationale": {
      "reason_code": "USER_SELECTED_SCOPE",
      "message": "User selected 2 playbook(s)."
    }
  },
  "evaluations": [
    { "playbook_id": "registry_autorun", "in_scope": true },
    { "playbook_id": "script_exec", "in_scope": true }
  ],
  "out_of_scope": ["process_exec", "outbound_connect", ...]
}
```

### E2. Empty Selection + Discovery Default

**Setup:**
- User selects no playbooks (empty array)
- Import has Sysmon data

**Expected:**
```json
{
  "scope": {
    "mode": "GeneralDiscovery",
    "effective_playbook_ids": ["registry_autorun", "script_exec", "process_exec", ...],
    "rationale": {
      "reason_code": "NO_SELECTION_DEFAULTED_TO_DISCOVERY",
      "message": "No playbooks selected. Defaulted to General Discovery."
    }
  }
}
```

**UI must show:** "General Discovery (default)" label

### E3. Empty Selection + Explicitly Disabled

**Setup:**
- User sets `selection_mode: "none"`

**Expected:**
```json
{
  "scope": {
    "mode": "None",
    "effective_playbook_ids": [],
    "rationale": {
      "reason_code": "SCOPE_EXPLICITLY_DISABLED",
      "message": "Playbooks explicitly disabled."
    }
  },
  "evaluations": []
}
```

### E4. Partial Visibility (Missing Sensors)

**Setup:**
- User selects `["registry_autorun"]`
- Import has NO Sysmon data

**Expected:**
```json
{
  "visibility": {
    "sysmon": { "available": false, "event_count": 0 }
  },
  "evaluations": [
    {
      "playbook_id": "registry_autorun",
      "in_scope": true,
      "status": "blocked",
      "reason_codes": ["PARTIAL_VISIBILITY", "MISSING_SENSOR_SYSMON"],
      "slots": [
        {
          "slot_id": "registry_write",
          "status": "blocked",
          "reason_codes": ["MISSING_SENSOR_SYSMON"]
        }
      ]
    }
  ]
}
```

### E5. Backend Mismatch (Playbook Not Found)

**Setup:**
- User selects `["nonexistent_playbook", "registry_autorun"]`
- `nonexistent_playbook` not in catalog

**Expected:**
```json
{
  "evaluations": [
    {
      "playbook_id": "nonexistent_playbook",
      "in_scope": true,
      "status": "error",
      "reason_codes": ["BACKEND_PLAYBOOK_UNKNOWN"],
      "slots": []
    },
    {
      "playbook_id": "registry_autorun",
      "in_scope": true,
      "status": "match",
      "reason_codes": ["IN_SCOPE_MATCH"]
    }
  ]
}
```

---

## F. Migration & Backward Compatibility

### F1. Legacy Runs

For runs created before this change:

1. `run_meta.json` won't have `playbook_scope` field
2. `read_playbook_scope()` returns `None`
3. API returns `playbook_scope: null`
4. UI should show "Scope unknown (legacy run)"

### F2. Legacy Fields

These fields are preserved for backward compatibility:

| Field | Location | Purpose |
|-------|----------|---------|
| `playbook_selection` | run_meta.json | Original user selection |
| `capability` | /playbooks/eval response | Legacy capability snapshot |

---

## G. Implementation Checklist

- [x] Define `PlaybookScope` types in `playbook_scope.rs`
- [x] Compute scope in `supervisor.rs` before spawning locald
- [x] Persist scope to `run_meta.json`
- [x] Pass `effective_playbook_ids` to locald via env var
- [x] Update `/api/runs/:id/playbooks/eval` to return scope + reason codes
- [x] Update `/api/runs/:id` to include playbook_scope
- [x] Create this spec document
- [ ] Add JSON snapshot tests for E1-E5 cases
- [ ] Update UI to display scope mode and reason codes

---

## H. Non-Goals (Out of Scope)

1. **Dynamic scope changes:** Scope is fixed at run start
2. **Per-slot sensor requirements:** Currently all slots assume same requirements
3. **Playbook dependencies:** No dependency resolution between playbooks
4. **Scope inheritance:** Each run has independent scope

---

## I. Appendix: Type Definitions

See `crates/server/src/playbook_scope.rs` for canonical Rust types:

- `PlaybookScope` - Canonical scope with mode, effective_ids, rationale
- `ScopeMode` - Enum of scope modes
- `ScopeReasonCode` - Scope-level reason codes
- `EvalReasonCode` - Evaluation-level reason codes  
- `SlotEvalStatus` - Slot evaluation status
- `PlaybookEvalResult` - Full evaluation result
- `PlaybooksEvalResponse` - API response structure

# Canonical Explainability API Schema Documentation

**BUILD_STAMP: 2026-01-10-SHIP-BACKEND**

This document defines the canonical response schemas for all explainability API endpoints.
These schemas ensure consistent UI rendering and backwards compatibility.

## Overview

| Endpoint | Response Type | Purpose |
|----------|--------------|---------|
| `GET /api/signals` | `SignalSummary[]` | List signals with minimal fields |
| `GET /api/signals/:id` | `StoredSignal` | Full signal detail |
| `GET /api/signals/:id/explain` | `ExplainResponse` | Complete explanation with scoring |
| `GET /api/signals/:id/narrative` | `NarrativeDoc` | Evidence-cited narrative |

---

## SignalSummary Schema

**Returned by:** `GET /api/signals`

```typescript
interface SignalSummary {
  // Required core fields
  signal_id: string;          // Unique signal identifier
  signal_type: string;        // e.g., "LogEvasion", "SuspiciousExec"
  ts: number;                 // Timestamp (milliseconds since epoch)
  severity: string;           // "critical" | "high" | "medium" | "low"
  host: string;               // Host where signal originated
  
  // Optional detector identification
  playbook_id?: string;       // null if unknown
  detector_version?: string;  // null if unknown
  
  // Optional scoring
  risk_score?: number;        // [0.0, 1.0] - null if unavailable
  
  // Optional entity info
  entities?: SignalEntities;  // null if no entity data
  
  // Evidence count (not full pointers)
  evidence_count: number;     // Number of evidence pointers
}
```

---

## ExplainResponse Schema

**Returned by:** `GET /api/signals/:id/explain`

```typescript
interface ExplainResponse {
  // === REQUIRED CORE FIELDS ===
  signal_id: string;
  signal_type: string;
  ts: number;
  severity: string;
  
  // === DETECTOR IDENTIFICATION (required) ===
  playbook_id: string;        // "unknown" if not available
  hypothesis_name?: string;   // null if not hypothesis-based
  detector_version?: string;  // null if not tracked
  
  // === ENTITIES (required, can be empty) ===
  entities: SignalEntities;
  
  // === EVIDENCE (required, can be empty array) ===
  evidence: EvidencePointer[];  // Always an array, never null
  
  // === SCORING (required, can indicate unavailable) ===
  scoring: ScoringBreakdown;
  
  // === OPTIONAL ENRICHMENT ===
  summary?: string;           // Human-readable summary
  family?: string;            // Security family
  slots?: object;             // Slot fill details
  matched_facts?: object;     // Facts that matched
  limitations: string[];      // Caveats/limitations
  generated_at: number;       // Generation timestamp
}
```

---

## EvidencePointer Schema

**Used in:** `ExplainResponse.evidence[]`

```typescript
type EvidenceKind = 
  | "segment_record"  // Reference to segment:record
  | "file_path"       // Reference to file
  | "db_row"          // Reference to database row
  | "event_id"        // Reference to event ID
  | "opaque";         // Future-proofing

interface EvidencePointer {
  // Required
  kind: EvidenceKind;
  ref: string;                // Stable reference identifier
  
  // For segment_record kind
  stream_id?: string;         // e.g., "evtx", "sysmon"
  segment_id?: number;        // Segment number
  record_index?: number;      // Index within segment
  
  // Optional enrichment
  ts?: number;                // Timestamp of the evidence
  summary?: string;           // Human hint, e.g., "Security/1102"
  bundle_rel_path?: string;   // Bundle-relative path
  content_hash?: string;      // For integrity verification
}
```

### Reference Format by Kind

| Kind | `ref` Format | Example |
|------|-------------|---------|
| `segment_record` | `{stream_id}:{segment_id}:{record_index}` | `"evtx:1:42"` |
| `file_path` | `{bundle_relative_path}` | `"segments/sysmon/001.jsonl"` |
| `event_id` | `{source}:{event_id}` | `"Security:4624"` |

---

## ScoringBreakdown Schema

**Used in:** `ExplainResponse.scoring`

```typescript
interface ScoringBreakdown {
  // Required
  risk_score: number;               // [0.0, 1.0]
  scoring_reasons: ScoringReason[]; // Always an array
  
  // Advanced scoring (optional)
  mahalanobis_distance?: number;
  elliptic_envelope_score?: number;
  krim_score?: number;
  
  // Unavailable marker
  scoring_unavailable: boolean;     // true if scoring couldn't be computed
}

interface ScoringReason {
  code: string;           // Stable identifier
  label: string;          // Human-readable
  weight: number;         // [0.0, 1.0] contribution
  detail?: string;        // Optional explanation
  evidence_refs?: string[]; // Links to EvidencePointer.ref
}
```

### Canonical Scoring Reason Codes

| Code | Label | When Used |
|------|-------|-----------|
| `SEVERITY_CRITICAL` | Critical severity | severity = "critical" |
| `SEVERITY_HIGH` | High severity | severity = "high" |
| `SEVERITY_MEDIUM` | Medium severity | severity = "medium" |
| `SEVERITY_LOW` | Low severity | severity = "low" |
| `PB_CHAIN_COMPLETE` | Playbook chain complete | All required slots filled |
| `PB_REQUIRED_SLOTS_FILLED` | Required slots filled | Required slots satisfied |
| `PB_OPTIONAL_SLOTS_FILLED` | Optional slots filled | Optional slots satisfied |
| `MAHALANOBIS_ANOMALY` | Mahalanobis anomaly | Advanced scoring enabled |
| `ELLIPTIC_ENVELOPE` | Elliptic envelope anomaly | Advanced scoring enabled |
| `KRIM_ENTROPY` | KRIM entropy score | Advanced scoring enabled |
| `MISSING_SCORING` | Scoring not available | Pre-scoring signal or insufficient data |

---

## SignalEntities Schema

**Used in:** `SignalSummary.entities`, `ExplainResponse.entities`

```typescript
interface SignalEntities {
  host?: string;
  proc_key?: string;        // Process key
  user?: string;            // Identity/user
  file_key?: string;        // File path
  ip?: string;              // Network address
  registry_key?: string;    // Windows registry
  extra?: Record<string, string>;  // Additional entities
}
```

---

## Sample JSON Payloads

### 1. Fully Populated ExplainResponse

```json
{
  "signal_id": "abc123def456",
  "signal_type": "LogEvasion",
  "ts": 1700000000000,
  "severity": "high",
  "playbook_id": "windows_log_tamper_clear",
  "hypothesis_name": "Windows Log Tamper: Clear",
  "detector_version": "1.2.0",
  "entities": {
    "host": "WORKSTATION-01",
    "proc_key": "proc_abc123",
    "user": "DOMAIN\\user"
  },
  "evidence": [
    {
      "kind": "segment_record",
      "ref": "evtx:1:42",
      "stream_id": "evtx",
      "segment_id": 1,
      "record_index": 42,
      "ts": 1700000000000,
      "summary": "Security/1102 Log Clear"
    },
    {
      "kind": "segment_record",
      "ref": "sysmon:5:100",
      "stream_id": "sysmon",
      "segment_id": 5,
      "record_index": 100,
      "ts": 1699999990000,
      "summary": "Sysmon/1 Process Create"
    }
  ],
  "scoring": {
    "risk_score": 0.78,
    "scoring_reasons": [
      {
        "code": "SEVERITY_HIGH",
        "label": "High severity",
        "weight": 0.75
      },
      {
        "code": "PB_CHAIN_COMPLETE",
        "label": "All required slots filled",
        "weight": 0.85,
        "detail": "3/3 required slots satisfied"
      }
    ],
    "scoring_unavailable": false
  },
  "summary": "Security event log was cleared by a non-system process.",
  "family": "defense_evasion",
  "limitations": ["DNS resolution telemetry not available"],
  "generated_at": 1700000001000
}
```

### 2. ExplainResponse with Missing Scoring

```json
{
  "signal_id": "legacy_xyz",
  "signal_type": "SuspiciousExec",
  "ts": 1699000000000,
  "severity": "medium",
  "playbook_id": "unknown",
  "hypothesis_name": null,
  "detector_version": null,
  "entities": {
    "host": "SERVER-01"
  },
  "evidence": [],
  "scoring": {
    "risk_score": 0.0,
    "scoring_reasons": [
      {
        "code": "MISSING_SCORING",
        "label": "Scoring not available",
        "weight": 0.0,
        "detail": "Signal was created before scoring was enabled or data is insufficient"
      }
    ],
    "scoring_unavailable": true
  },
  "summary": null,
  "family": null,
  "limitations": [],
  "generated_at": 1699000001000
}
```

### 3. ExplainResponse with Empty Evidence

```json
{
  "signal_id": "no_evidence_signal",
  "signal_type": "NetworkAnomaly",
  "ts": 1700000500000,
  "severity": "low",
  "playbook_id": "network_anomaly_detector",
  "hypothesis_name": "Network Anomaly Detection",
  "detector_version": "2.0.0",
  "entities": {
    "host": "EDGE-ROUTER-01",
    "ip": "192.168.1.100"
  },
  "evidence": [],
  "scoring": {
    "risk_score": 0.25,
    "scoring_reasons": [
      {
        "code": "SEVERITY_LOW",
        "label": "Low severity",
        "weight": 0.25
      }
    ],
    "scoring_unavailable": false
  },
  "summary": "Unusual network traffic pattern detected.",
  "family": "network_analysis",
  "limitations": ["No raw packet capture available"],
  "generated_at": 1700000500500
}
```

---

## Backwards Compatibility

### Filling Missing Fields

When older signals lack fields, the normalization layer fills:

| Field | Default Value |
|-------|--------------|
| `playbook_id` | `"unknown"` |
| `hypothesis_name` | `null` |
| `detector_version` | `null` |
| `entities` | Empty object `{}` |
| `evidence` | Empty array `[]` |
| `scoring` | `ScoringBreakdown.unavailable()` |
| `limitations` | Empty array `[]` |

### JSON Serialization Rules

1. **Arrays** are always serialized (never `null`, use `[]` for empty)
2. **Optional scalars** use `null` when absent
3. **Objects** are serialized even if all fields are null
4. **Timestamps** are always milliseconds since epoch (Unix × 1000)

---

## Evidence Dereference (Future)

**NOT IMPLEMENTED YET**

Evidence pointers are designed to be dereferenceable in the future:

```
GET /api/evidence/deref?ref={evidence_pointer.ref}
```

The `ref` field contains sufficient information to locate the evidence:
- For `segment_record`: stream + segment + index
- For `file_path`: bundle-relative path
- For `event_id`: event source + event ID

UI should show evidence pointers as **read-only** until deref endpoint is available.

---

## Implementation Notes

### Source Files

- **Schema definitions:** `crates/core/src/explain_api.rs`
- **Normalization:** `crates/server/src/explain_normalize.rs`
- **Tests:** `crates/server/tests/explain_api_tests.rs`
- **Scoring:** `crates/locald/src/scoring/scored_signal.rs`

### Key Functions

```rust
// Normalize signal to summary
explain_normalize::signal_to_summary(&StoredSignal) -> SignalSummary

// Normalize to explain response
explain_normalize::normalize_explain_response(&StoredSignal, Option<&Value>) -> ExplainResponse

// Build scoring from signal data
edr_core::build_scoring_from_signal(severity, risk_score, metadata) -> ScoringBreakdown

// Convert evidence
edr_core::normalize_evidence_array(&[Value]) -> Vec<EvidencePointer>
```

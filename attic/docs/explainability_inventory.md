# Explainability Inventory

> Generated: January 4, 2026  
> Scope: Windows-only EDR pipeline  
> Purpose: Document existing explainability surfaces and identify gaps

## Summary Table

| Component | Exists? | File/Type | What it Contains | Gaps |
|-----------|---------|-----------|------------------|------|
| **Evidence Pointers** | ✅ Partial | `crates/core/src/evidence_ptr.rs`, `locald/hypothesis/canonical_fact.rs` | `EvidencePtr { stream_id, segment_id, record_index }` + optional SHA256/timestamp | ❌ No deref API to fetch raw records; two incompatible struct versions (u64 vs String segment_id) |
| **Slot Fill Traces** | ✅ Partial | `locald/hypothesis/hypothesis_state.rs`, `crates/locald/src/slot_matcher.rs` | `SlotFill { slot_id, satisfied, strength, evidence_ptrs, fact_refs, count }` | ❌ No predicate match trace (why a fact matched); ordering constraint violations not surfaced |
| **Hypothesis Lifecycle** | ✅ Good | `locald/hypothesis/hypothesis_state.rs`, `locald/hypothesis/promotion.rs` | `HypothesisState`, `HypothesisStatus { Hypothesis, Promoted, Absorbed, Expired, Suppressed }`, TTL/cooldown | ❌ No audit trail of state transitions; absorption reason not captured |
| **Signal/Incident Model** | ✅ Partial | `crates/core/src/signal_result.rs`, `locald/hypothesis/incident.rs` | `SignalResult`, `Incident` with `promoted_from_hypothesis_ids`, `evidence_ptrs_summary` | ❌ Two different SignalResult structs; `explanation_bundle_ref` exists but bundles not implemented |
| **Explain Endpoint** | ✅ Exists | `locald/hypothesis/explanation.rs`, `crates/server/src/main.rs` | `GET /api/incidents/:id/explain` returns `ExplanationResponse` | ❌ Response mostly unpopulated; no signal-level explain endpoint |
| **UI Explain View** | ✅ Basic | `ui/workbench.html` | Renders top3 hypotheses, claims, evidence list | ❌ No interactive slot exploration; evidence pointers not dereferenceable |

---

## 1. Evidence Pointers

### Files
| File | Purpose |
|------|---------|
| `crates/core/src/evidence_ptr.rs` | Core `EvidencePtr` struct (segment_id: u64, record_index: u32) |
| `locald/hypothesis/canonical_fact.rs` | Rich `EvidencePtr` with SHA256, timestamp (segment_id: String) |
| `locald/hypothesis/evidence_ptr.rs` | `DerefResult` enum for verification |
| `crates/locald/src/os/windows/fact_extractor.rs` | Creates EvidencePtr from Windows events |

### Struct Definition (Core)
```rust
pub struct EvidencePtr {
    pub stream_id: String,
    pub segment_id: u64,
    pub record_index: u32,
}
```

### Struct Definition (locald/hypothesis)
```rust
pub struct EvidencePtr {
    pub stream_id: String,
    pub segment_id: String,          // String vs u64 mismatch!
    pub record_index: u64,
    pub record_sha256: Option<String>,
    pub ts: Option<DateTime<Utc>>,
}
```

### Gaps
- ❌ **Critical**: Two incompatible `EvidencePtr` types with different field types
- ❌ No deref endpoint to fetch raw record from segment file
- ❌ SHA256 integrity field rarely populated
- ❌ `dropped_evidence_count` tracked but dropped pointers not recoverable

---

## 2. Slot Fill Traces

### Files
| File | Purpose |
|------|---------|
| `locald/hypothesis/hypothesis_state.rs` | `Slot`, `SlotFill` structs |
| `crates/locald/src/slot_matcher.rs` | `PlaybookSlot`, `SlotPredicate`, slot matching logic |
| `locald/hypothesis/explanation.rs` | `SlotStatusSummary`, `SlotDetail` for UI |

### Key Structs
```rust
// SlotFill captures what filled a slot
pub struct SlotFill {
    pub slot_id: String,
    pub satisfied: bool,
    pub strength: FillStrength,      // Strong | Weak
    pub evidence_ptrs: Vec<EvidencePtr>,
    pub fact_refs: Vec<String>,
    pub first_ts: DateTime<Utc>,
    pub last_ts: DateTime<Utc>,
    pub count: u32,
    pub notes: Option<String>,
}

// SlotPredicate defines match criteria
pub struct SlotPredicate {
    pub fact_type: String,
    pub proc_exe_pattern: Option<String>,
    pub file_path_pattern: Option<String>,
    pub registry_key_pattern: Option<String>,
    // ...
}
```

### Gaps
- ❌ No predicate evaluation trace (why a fact matched/didn't match)
- ❌ Regex match groups not captured
- ❌ No "near miss" tracking for almost-matched slots
- ❌ Ordering constraint violations not surfaced in SlotFill

---

## 3. Hypothesis Lifecycle

### Files
| File | Purpose |
|------|---------|
| `locald/hypothesis/hypothesis_state.rs` | `HypothesisState`, `HypothesisStatus` |
| `locald/hypothesis/promotion.rs` | `PromotionDecision`, `PromotionReason` |
| `locald/hypothesis/visibility.rs` | `VisibilityState` (streams present/missing) |
| `crates/locald/src/slot_matcher.rs` | TTL, cooldown definitions in `PlaybookDef` |

### Lifecycle States
```rust
pub enum HypothesisStatus {
    Hypothesis,   // Active, gathering evidence
    Promoted,     // Promoted to incident/signal
    Absorbed,     // Merged into another hypothesis
    Expired,      // TTL expired without promotion
    Suppressed,   // Analyst or rule suppressed
}
```

### Promotion Tracking
```rust
pub struct PromotionDecision {
    pub should_promote: bool,
    pub reason: PromotionReason,
    pub maturity: f64,
    pub confidence: f64,
    pub severity: Severity,
}

pub enum PromotionReason {
    AllRequiredSlots,
    MaturityThreshold { threshold: f64 },
    InsufficientEvidence,
    VisibilityGap { missing_streams: Vec<String> },
}
```

### Gaps
- ❌ No audit trail of state transitions over time
- ❌ Missing explicit `expired_at`, `suppressed_at` timestamps
- ❌ Absorption reason not captured
- ❌ Cooldown state not directly queryable from API

---

## 4. Signal/Incident Model

### Files
| File | Purpose |
|------|---------|
| `crates/core/src/signal_result.rs` | Core `SignalResult` struct |
| `crates/locald/src/signal_result.rs` | locald-specific `SignalResult` |
| `locald/hypothesis/incident.rs` | `Incident` struct with full metadata |

### Signal Fields
```rust
// Core SignalResult
pub struct SignalResult {
    pub signal_id: String,
    pub signal_type: String,
    pub severity: Severity,
    pub host: String,
    pub ts_ms: i64,
    pub evidence_ptrs: Vec<EvidencePtr>,
    pub dropped_evidence_count: u32,
    pub metadata: BTreeMap<String, serde_json::Value>,
}
```

### Incident Fields (richer than Signal)
```rust
pub struct Incident {
    pub incident_id: String,
    pub family: String,
    pub promoted_from_hypothesis_ids: Vec<String>,
    pub timeline_entries: Vec<TimelineEntry>,
    pub entities: Vec<EntityRef>,
    pub explanation_bundle_ref: Option<String>,  // Exists but unused!
    pub mitre_techniques: Vec<String>,
    // ...
}
```

### Gaps
- ❌ **Critical**: Two different `SignalResult` structs need unification
- ❌ `explanation_bundle_ref` field exists but bundles never created
- ❌ `playbook_id` only in metadata, not first-class field
- ❌ MITRE techniques field exists but rarely populated

---

## 5. Explain Endpoint / UI

### Existing Endpoints
| Endpoint | Method | Status |
|----------|--------|--------|
| `GET /api/incidents/:id/explain` | GET | ✅ Exists, partial response |
| `GET /api/alerts/:id/explain` | GET | ⚠️ Legacy, may not work |
| `GET /api/signals/:id/explain` | GET | ❌ **Missing** |

### ExplanationResponse Structure
```rust
pub struct ExplanationResponse {
    pub query_context: QueryContext,
    pub observed_claims: Vec<Claim>,         // Rarely populated
    pub timeline: Vec<ExplanationTimelineEntry>,  // Often empty
    pub top3_hypotheses: Option<ArbitrationResponse>,
    pub slot_status_summary: Option<SlotStatusSummary>,
    pub visibility_state: ExplanationVisibilityState,
    pub missing_evidence: Vec<MissingEvidence>,
    pub confidence_severity_breakdown: Option<ConfidenceSeverityBreakdown>,
    pub summary: String,
}
```

### UI (workbench.html)
The UI renders:
- Top 3 hypotheses with confidence/severity badges
- Claims list (observed/inferred/unknown)
- Evidence pointers (up to 10, display only)
- Visibility state indicators

### Gaps
- ❌ No `GET /api/signals/:id/explain` endpoint
- ❌ Response fields mostly unpopulated in practice
- ❌ Evidence pointers shown but cannot be dereferenced to raw data
- ❌ No interactive slot fill exploration
- ❌ `confidence_severity_breakdown` not computed

---

## 6. Evidence Dereference

### Current State
- `DerefResult` enum defined in `locald/hypothesis/evidence_ptr.rs`
- No API endpoint to dereference pointers
- No helper to read segment files and extract records

### Required Implementation
```rust
pub fn deref_evidence(
    telemetry_root: &Path,
    ptr: &EvidencePtr,
) -> Result<DerefResult, Error>
```

---

## Recommendations for ExplanationBundle

Based on inventory, the new `ExplanationBundle` should:

1. **Unify evidence pointer format** - Use String segment_id consistently
2. **Include slot fill details** - Which facts filled which slots, with predicate descriptions
3. **Capture promotion reason** - Why the hypothesis became a signal
4. **Support evidence deref** - Include excerpts inline or provide deref endpoint
5. **Explicit limitations** - List what telemetry was missing

### Proposed Schema
```rust
pub struct ExplanationBundle {
    pub signal_id: String,
    pub playbook_id: String,
    pub matched_at: DateTime<Utc>,
    pub summary: String,
    pub slots: Vec<SlotExplanation>,
    pub entities: EntityBundle,
    pub evidence: Vec<EvidenceExcerpt>,
    pub counters: ExplanationCounters,
    pub limitations: Vec<String>,
}
```

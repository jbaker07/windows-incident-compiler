# Mission Harness + Real Telemetry Integration

This document describes the integration of the Mission Workflow Harness with the real Windows telemetry stack.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        MISSION HARNESS + REAL TELEMETRY                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐       │
│  │ Mission Profile Selection                                           │       │
│  │   - Discovery: Benign Admin, Developer Workflow                     │       │
│  │   - Adversary: LOLBin Tier A/B, Credential Access, etc.            │       │
│  └─────────────────────────────────────────────────────────────────────┘       │
│                             │                                                   │
│                             ▼                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐       │
│  │ start_mission()                                                     │       │
│  │   → supervisor.start_run() → capture + locald + server              │       │
│  └─────────────────────────────────────────────────────────────────────┘       │
│                             │                                                   │
│        ┌────────────────────┼────────────────────┐                             │
│        │                    │                    │                             │
│        ▼                    ▼                    ▼                             │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                       │
│  │ capture_     │   │ edr-locald   │   │ edr-server   │                       │
│  │ windows_     │   │              │   │              │                       │
│  │ rotating     │   │ Extracts     │   │ HTTP API     │                       │
│  │              │   │ facts from   │   │ /api/health  │                       │
│  │ Writes:      │   │ events       │   │ /api/signals │                       │
│  │ - index.json │   │              │   │ /api/explain │                       │
│  │ - segments/  │   │ Matches      │   │              │                       │
│  │   *.jsonl    │   │ playbooks    │   │ Evidence     │                       │
│  │              │   │              │   │ deref from   │                       │
│  └──────────────┘   │ Writes:      │   │ segments     │                       │
│        │            │ - workbench  │   │              │                       │
│        │            │   .db        │   └──────────────┘                       │
│        │            └──────────────┘          │                               │
│        │                    │                 │                               │
│        └────────────────────┴─────────────────┘                               │
│                             │                                                   │
│                             ▼                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐       │
│  │ PipelineCounterFetcher::fetch_all()                                 │       │
│  │   - CaptureCounters from index.json                                 │       │
│  │   - LocaldCounters from workbench.db                               │       │
│  │   - ServerCounters from API                                         │       │
│  └─────────────────────────────────────────────────────────────────────┘       │
│                             │                                                   │
│                             ▼                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐       │
│  │ Quality Gates + Baseline Comparison                                 │       │
│  │   → run_summary.json                                                │       │
│  │   → quality_report.json                                             │       │
│  └─────────────────────────────────────────────────────────────────────┘       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## New Modules

### 1. `baseline.rs` - Baseline Run Management

Provides mechanisms for:
- Marking a run as a baseline
- Comparing current runs against baselines  
- Detecting regressions and improvements
- Persisting baseline metadata

**Key Types:**
```rust
pub struct BaselineMetadata {
    pub run_id: String,
    pub marked_at: String,
    pub description: String,
    pub mission_profile: Option<String>,
    pub environment: BaselineEnvironment,
    pub metrics_snapshot: BaselineMetricsSnapshot,
}

pub struct BaselineComparison {
    pub baseline_run_id: String,
    pub current_run_id: String,
    pub deltas: MetricDeltas,
    pub regressions: Vec<RegressionItem>,
    pub improvements: Vec<ImprovementItem>,
    pub verdict: ComparisonVerdict,  // Stable | Improved | Regressed
}
```

**Commands:**
- `mark_run_as_baseline(run_id, description)` - Mark a run as baseline
- `set_default_baseline(run_id)` - Set default for comparisons
- `get_baselines()` - List all baselines
- `compare_against_baseline(current_run_id, baseline_run_id)` - Full delta report

### 2. `pipeline_counters.rs` - Real-Time Pipeline Counters

Fetches live metrics from the actual running telemetry stack (no in-memory estimates).

**Key Types:**
```rust
pub struct PipelineCounters {
    pub capture: CaptureCounters,   // From index.json
    pub locald: LocaldCounters,     // From workbench.db
    pub server: ServerCounters,     // From API
    pub pipeline_healthy: bool,
}

pub struct CaptureCounters {
    pub events_total: u64,
    pub segments_count: u32,
    pub bytes_written: u64,
    pub events_per_second: f64,
    pub channels: Vec<String>,
}

pub struct LocaldCounters {
    pub facts_count: u64,
    pub signals_count: u64,
    pub signals_by_playbook: HashMap<String, u64>,
    pub signals_by_severity: HashMap<String, u64>,
}
```

**Signal Provenance:**
```rust
pub struct SignalProvenanceProof {
    pub signal_id: String,
    pub evidence_pointers: Vec<EvidencePointer>,
    pub source_segments: Vec<SegmentReference>,
    pub evidence_excerpts: Vec<EvidenceExcerpt>,
    pub fully_proven: bool,
}
```

**Commands:**
- `get_pipeline_counters()` - Real-time counters from all components
- `prove_signal_origins()` - Prove signals came from captured segments

## Commands Reference

### Mission Lifecycle

| Command | Description |
|---------|-------------|
| `start_mission(profile_id, duration_override)` | Start real stack (capture + locald + server) |
| `get_mission_metrics()` | Live metrics from pipeline counters |
| `stop_mission()` | Stop all processes, write artifacts |
| `get_mission_readiness()` | Environment capability check |

### Baseline Management

| Command | Description |
|---------|-------------|
| `mark_run_as_baseline(run_id, description)` | Mark run as baseline |
| `set_default_baseline(run_id)` | Set default for comparisons |
| `get_baselines()` | List all marked baselines |
| `compare_against_baseline(current, baseline)` | Full delta report |

### Real Pipeline

| Command | Description |
|---------|-------------|
| `get_pipeline_counters()` | Real-time counters from stack |
| `prove_signal_origins()` | Evidence chain from segment to signal |

## E2E Proof Test

Run the full E2E proof test:

```powershell
cd src-tauri
.\tests\test_real_telemetry_e2e.ps1 -DurationSeconds 60
```

**What it proves:**
1. `capture_windows_rotating.exe` writes `index.json` + `segments/*.jsonl`
2. `edr-locald.exe` ingests segments → produces signals in `workbench.db`
3. `edr-server.exe` serves API with explain/deref from those segments
4. `run_summary.json` + `quality_report.json` validate against schemas

## Example Run Artifact Tree

```
%LOCALAPPDATA%\windows-incident-compiler\telemetry\runs\e2e_real_20260109_180000\
├── index.json                    # Segment manifest with SHA256 hashes
├── segments/
│   ├── evtx_000000.jsonl         # Raw events from Security log
│   ├── evtx_000001.jsonl
│   └── evtx_000002.jsonl
├── workbench.db                  # SQLite with signals + explanations
├── logs/
│   ├── capture.log
│   ├── capture_err.log
│   ├── locald.log
│   ├── locald_err.log
│   ├── server.log
│   └── server_err.log
├── metrics/
│   └── metrics_v3.json
├── run_summary.json              # Mission summary with all metrics
├── quality_report.json           # Quality gates + baseline comparison
└── baseline.json                 # (if marked as baseline)
```

## Proof Chain

The signal provenance proof demonstrates the evidence chain:

```json
{
  "signal_id": "sig_discovery_whoami_20260109_180015",
  "signal_type": "discovery_system_info",
  "evidence_pointers": [
    {
      "stream_id": "Microsoft-Windows-Security-Auditing",
      "segment_id": 0,
      "record_index": 42
    }
  ],
  "source_segments": [
    {
      "segment_id": "evtx_000000",
      "rel_path": "segments/evtx_000000.jsonl",
      "sha256": "a3f2b8c4d9e1..."
    }
  ],
  "evidence_excerpts": [
    {
      "from_segment": "evtx_000000",
      "record_index": 42,
      "event_excerpt": "{\"ts_ms\":1736438400000,\"fields\":{\"exe\":\"whoami.exe\"...}",
      "key_fields": {
        "exe": "C:\\Windows\\System32\\whoami.exe",
        "cmdline": "whoami /all",
        "pid": "4128"
      }
    }
  ],
  "fully_proven": true
}
```

## Baseline Comparison Example

```json
{
  "baseline_run_id": "run_20260108_120000",
  "current_run_id": "run_20260109_180000",
  "deltas": {
    "events_delta": 200,
    "events_delta_pct": 20.0,
    "signals_delta": -2,
    "signals_delta_pct": -20.0
  },
  "regressions": [
    {
      "metric": "signals_count",
      "severity": "Minor",
      "baseline_value": "10",
      "current_value": "8",
      "delta": "-2",
      "explanation": "Lost signal detections - check playbook matching"
    }
  ],
  "improvements": [
    {
      "metric": "events_count",
      "baseline_value": "1000",
      "current_value": "1200",
      "delta": "+20.0%"
    }
  ],
  "verdict": "regressed",
  "summary": "Run run_20260109_180000 has 1 regressions (0 critical) vs baseline run_20260108_120000"
}
```

## UI Integration

The UI can invoke these commands via Tauri:

```javascript
// Start mission with real stack
const result = await invoke('start_mission', {
  profile_id: 'adversary_lolbin_tier_a',
  duration_override_minutes: 5
});

// Get live counters during run
const counters = await invoke('get_pipeline_counters');
console.log(`Events: ${counters.capture.events_total}`);
console.log(`Signals: ${counters.locald.signals_count}`);

// Mark as baseline after run
await invoke('mark_run_as_baseline', {
  run_id: 'run_20260109_180000',
  description: 'First successful adversary run'
});

// Compare future runs against baseline
const comparison = await invoke('compare_against_baseline', {
  current_run_id: 'run_20260110_090000',
  baseline_run_id: null  // Uses default baseline
});

if (comparison.verdict === 'regressed') {
  showRegressionWarning(comparison.regressions);
}

// Prove signal origins
const proofs = await invoke('prove_signal_origins');
for (const proof of proofs) {
  console.log(`Signal ${proof.signal_id}: ${proof.fully_proven ? 'PROVEN' : 'PARTIAL'}`);
}
```

## Summary

The Mission Harness now:
1. ✅ Starts/stops the real stack (capture + locald + server)
2. ✅ Fetches counters from real pipeline artifacts
3. ✅ Supports baseline marking and regression comparison
4. ✅ Proves signal provenance from captured segments
5. ✅ Validates artifacts against JSON schemas

# Grounded Health Gates - Verification Runbook

## Overview

The 4 Health Gates are now **GROUNDED** - they compute their values ONLY from real artifacts:
- **Gate A (Telemetry)**: Reads from `run_dir/index.json` + counts lines in `segments/*.jsonl`
- **Gate B (Extraction)**: Reads from `workbench.db` / `analysis.db` / `facts.jsonl` / API fallback
- **Gate C (Detection)**: Reads from DB + verifies consistency with `/api/signals`
- **Gate D (Explainability)**: Validates explanations + tests evidence_ptr dereference against real segment files

**NO in-memory counters** are used as the source of truth.

---

## Quick Verification Steps

### 1. Start a Run in the Desktop App

```
1. Open EDR Desktop
2. Click "Start Run" with default settings (or 2-minute duration)
3. Wait for telemetry to flow
```

### 2. Open DevTools Console (F12)

Run these commands to verify grounded gates:

```javascript
// Get grounded health gates (computed from disk, not memory)
const gates = await window.__TAURI__.core.invoke('get_grounded_health_gates');
console.log('Grounded Gates:', JSON.stringify(gates, null, 2));

// Check the "how_computed" field - this MUST reference disk/db/api sources
console.log('Gate A source:', gates.gates.telemetry.how_computed);
console.log('Gate B source:', gates.gates.extraction.how_computed);
console.log('Gate C source:', gates.gates.detection.how_computed);
console.log('Gate D source:', gates.gates.explainability.how_computed);
```

### 3. Run E2E Verification

```javascript
// Run full E2E verification harness
const verification = await window.__TAURI__.core.invoke('verify_grounded_gates');
console.log('E2E Verification:', JSON.stringify(verification, null, 2));

// Check all checks passed
console.log('All passed:', verification.success);
console.log('Summary:', verification.summary);
```

### 4. Check the Metrics File

After stopping the run, verify the metrics file:

```powershell
# Find the latest metrics file
$metricsDir = "$env:LOCALAPPDATA\edr-desktop\telemetry\metrics"
$latest = Get-ChildItem $metricsDir -Filter "*_metrics.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$metrics = Get-Content $latest.FullName | ConvertFrom-Json

# Verify schema version is 3.1-grounded
$metrics.schema_version
# Expected: "3.1-grounded"

# Verify "how_computed" fields exist
$metrics.gates.telemetry.how_computed
$metrics.gates.extraction.how_computed
$metrics.gates.detection.how_computed
$metrics.gates.explainability.how_computed

# Verify grounding metadata
$metrics.grounding.source
# Expected: "disk+db+api"
```

---

## Gate Status Rules

### Gate A: Telemetry
| Status | Condition |
|--------|-----------|
| PASS | ≥1000 events AND ≥3 channels |
| PARTIAL | ≥100 events OR ≥1 channel |
| FAIL | 0 events OR 0 segments |

### Gate B: Extraction
| Status | Condition |
|--------|-----------|
| PASS | ≥100 facts AND ≥3 key fact types |
| PARTIAL | ≥10 facts OR ≥1 key type |
| FAIL | 0 facts |

Key fact types: `ProcessExecution`, `NetworkConnection`, `FileOperation`, `RegistryModification`, `PowershellCommand`, `ServiceOperation`, `UserLogon`

### Gate C: Detection
| Status | Condition |
|--------|-----------|
| PASS | ≥1 signal AND ≥50% playbook match AND DB/API consistent |
| PARTIAL | ≥1 signal but low match rate or inconsistent |
| FAIL | 0 signals (when facts exist) |
| NO_DATA | 0 signals and 0 facts |

### Gate D: Explainability
| Status | Condition |
|--------|-----------|
| PASS | ≥90% signals valid AND ≥90% evidence_ptr deref success |
| PARTIAL | ≥50% valid OR ≥50% deref success |
| FAIL | <50% on both metrics |
| NO_DATA | No signals to validate |

---

## E2E Verification Checks

The `verify_grounded_gates` command runs these checks:

1. **run_dir_exists**: Verify run directory exists
2. **segments_dir_exists**: Verify segments subdirectory exists
3. **has_jsonl_files**: At least one `.jsonl` segment file
4. **api_reachable**: Can connect to `/api/signals`
5. **gates_computed**: Successfully computed all 4 gates
6. **gate_a_grounded**: Gate A's `how_computed` mentions disk sources
7. **evidence_deref_works**: Evidence pointers can be dereferenced to actual segment lines

---

## Troubleshooting

### "No run directory" Error
- Make sure a run is active or completed
- Check `%LOCALAPPDATA%\edr-desktop\telemetry\` for run folders

### Gate A Shows 0 Events
- Check if `segments/*.jsonl` files exist
- Verify agent-windows is running and writing segments
- Check `index.json` for segment metadata

### Gate B Shows 0 Facts
- Extraction may not have completed yet
- Check if `workbench.db` or `analysis.db` exists
- API fallback: check `/api/facts` endpoint

### Gate C Shows DB/API Inconsistent
- Normal during active run (DB may lag API)
- After run stops, should become consistent
- Small drift (≤5 signals or <10%) is acceptable

### Gate D Evidence Deref Failures
- Segment file may have been rotated/deleted
- Evidence pointer may reference wrong segment ID
- Check segment file naming: `{segment_id}.jsonl` or `evtx_{segment_id:06}.jsonl`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         GROUNDED GATES                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
│  │  Gate A         │  │  Gate B         │  │  Gate C         │     │
│  │  Telemetry      │  │  Extraction     │  │  Detection      │     │
│  │                 │  │                 │  │                 │     │
│  │  Reads:         │  │  Reads:         │  │  Reads:         │     │
│  │  - index.json   │  │  - workbench.db │  │  - workbench.db │     │
│  │  - segments/    │  │  - analysis.db  │  │  - /api/signals │     │
│  │    *.jsonl      │  │  - facts.jsonl  │  │                 │     │
│  │                 │  │  - /api/facts   │  │  Verifies:      │     │
│  └────────┬────────┘  └────────┬────────┘  │  DB=API         │     │
│           │                    │           └────────┬────────┘     │
│           │                    │                    │              │
│  ┌────────┴────────────────────┴────────────────────┴────────┐    │
│  │                                                            │    │
│  │  ┌─────────────────┐                                       │    │
│  │  │  Gate D         │                                       │    │
│  │  │  Explainability │                                       │    │
│  │  │                 │                                       │    │
│  │  │  Validates:     │                                       │    │
│  │  │  - evidence_ptr │◄─── Dereferences to actual segment    │    │
│  │  │  - entity_bundle│     lines in segments/*.jsonl         │    │
│  │  │  - required_slots│                                      │    │
│  │  └─────────────────┘                                       │    │
│  │                                                            │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                   GroundedHealthGates::compute()              │  │
│  │                                                               │  │
│  │   SINGLE source of truth for:                                 │  │
│  │   - write_metrics()                                           │  │
│  │   - get_grounded_health_gates() (UI)                          │  │
│  │   - verify_grounded_gates() (E2E check)                       │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## API Reference

### Tauri Commands

| Command | Description | Returns |
|---------|-------------|---------|
| `get_grounded_health_gates` | Get computed gates from artifacts | JSON with all gate data |
| `verify_grounded_gates` | Run E2E verification | Verification result with checks |
| `get_grounded_gates_summary` | One-liner status | String like "✅ A ✅ B ⚠️ C ✅ D → ⚠️" |

### JavaScript Usage

```javascript
// Import Tauri
const { invoke } = window.__TAURI__.core;

// Get grounded gates
const gates = await invoke('get_grounded_health_gates');

// Run verification
const result = await invoke('verify_grounded_gates');

// Get summary for status bar
const summary = await invoke('get_grounded_gates_summary');
```

---

## Files Modified

- `src-tauri/src/grounded_gates.rs` - New grounded gates implementation
- `src-tauri/src/supervisor.rs` - Updated `write_metrics()` to use grounded gates
- `src-tauri/src/main.rs` - Added Tauri commands
- `src-tauri/src/lib.rs` - Exported new module

---

## Version History

| Version | Schema | Description |
|---------|--------|-------------|
| 3.0 | Legacy | In-memory counters, can drift |
| **3.1-grounded** | Current | Grounded to disk/DB/API artifacts |

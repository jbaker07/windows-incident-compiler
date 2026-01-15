# UI Verification Checklist
BUILD_STAMP: 2026-01-10T23:00:00Z_SHIP

This checklist validates all wiring requirements for the Incident Compiler UI, including explainability.

**TRUTH TESTS**: These are hard, verifiable tests using DevTools Network tab. No guessing.

---

## Pre-flight

1. Start the backend:
   ```powershell
   cd windows-incident-compiler
   cargo run --release --bin edr-server
   ```

2. Open UI at: http://localhost:3000/ui/

3. **Enable Debug Mode** (optional): http://localhost:3000/ui/?debug=1
   - Shows floating API debug panel (last 10 API calls)
   - Green = 200, Yellow = 404, Red = error/network failure
   - Shows context: `run:run_1234` or `signal:abc123...`
   - HTML responses marked with red `[HTML!]` label and preview

4. **Verify BUILD_STAMP**:
   - Console shows: `APP BOOT 2026-01-10-SHIP`
   - Bottom-right watermark shows: `BUILD 2026-01-10-SHIP`
   - HTML comment: `<!-- BUILD_STAMP: 2026-01-10T23:00:00Z_SHIP -->`

---

## A. Network Truth Tests (DevTools → Network)

### A1. Settings → Run checks (GET /api/selfcheck)
- [ ] Go to Settings tab
- [ ] Open DevTools → Network → filter "selfcheck"
- [ ] Click "Run checks" button
- [ ] **VERIFY**: Request to `GET /api/selfcheck` (NOT `/api/diagnostics/self-check`)
- [ ] **VERIFY**: Response is JSON (not HTML)
- [ ] **VERIFY**: UI shows readiness status (Healthy/Degraded/Blocked)

### A2. Export Bundle (POST /api/export/bundle)
- [ ] Go to Import / Export tab
- [ ] Open DevTools → Network → filter "bundle"
- [ ] Click "Export Bundle" button
- [ ] **VERIFY**: Request to `POST /api/export/bundle` (NOT `/api/bundles/export`)
- [ ] **VERIFY**: Response Content-Type is `application/zip`
- [ ] **VERIFY**: Browser downloads a `.zip` file

### A3. Import Bundle (POST /api/import/bundle)
- [ ] Go to Import / Export tab
- [ ] Open DevTools → Network → filter "bundle"
- [ ] Drag & drop a valid bundle ZIP onto the drop zone
- [ ] **VERIFY**: Request to `POST /api/import/bundle` (NOT `/api/bundles/import`)
- [ ] **VERIFY**: Request Content-Type is `multipart/form-data`
- [ ] **VERIFY**: UI switches to Runs tab with IMPORTED banner

### A4. Mission Start (POST /api/run/start, GET /api/run/status)
- [ ] Go to Mission tab
- [ ] Open DevTools → Network
- [ ] Click "Start Run" button
- [ ] **VERIFY**: Request to `POST /api/run/start`
- [ ] **VERIFY**: Followed by `GET /api/run/status`
- [ ] **VERIFY**: UI does NOT assume running until backend confirms
- [ ] **VERIFY**: Status badge changes to "Running" (yellow)

### A5. Mission Stop (POST /api/run/stop, GET /api/run/status)
- [ ] With a run active, click "Stop Run"
- [ ] **VERIFY**: Request to `POST /api/run/stop`
- [ ] **VERIFY**: Followed by `GET /api/run/status`
- [ ] **VERIFY**: UI does NOT assume stopped until backend confirms
- [ ] **VERIFY**: Status badge changes to "Stopped"

### A5b. Run Timestamps from run_meta.json (Hardening)
- [ ] Start a run, wait 5-10 seconds, stop the run
- [ ] Open DevTools → Network → filter "runs"
- [ ] **VERIFY**: GET /api/runs returns `started_at` and `stopped_at` timestamps
- [ ] **VERIFY**: `started_at` matches the actual start time (not derived from run_id pattern)
- [ ] Check the run directory for `run_meta.json` file
- [ ] **VERIFY**: `run_meta.json` contains `started_at` and `stopped_at` fields
- [ ] **VERIFY**: API timestamps match `run_meta.json` values (authoritative source)

### A5c. Noise Diagnostics (GET /api/run/metrics with stats)
- [ ] Start a run, wait 30+ seconds for signals to appear
- [ ] **VERIFY**: Mission tab → Noise Diagnostics card shows:
  - [ ] Signals/min: Shows calculated rate (not "—")
  - [ ] Top playbook: Shows playbook name when signals exist (not "N/A" or blank)
  - [ ] Top entity: Shows entity (process/file/host) when signals exist
  - [ ] Collapsed: Shows dedupe count (number or "—")
- [ ] If no signals exist yet:
  - [ ] **VERIFY**: Top playbook shows "—" (not "N/A" or error message)
  - [ ] **VERIFY**: Top entity shows "—" (not "N/A" or error message)
- [ ] Open DevTools → Network → filter "metrics"
- [ ] **VERIFY**: GET /api/run/metrics response includes:
  - [ ] `top_playbook` (string or null)
  - [ ] `top_entity` (string or null)
  - [ ] `collapsed_count` (number)

### A6. Zero-Signal Run Visibility (GET /api/runs)
- [ ] Start a run, let it capture for 5-10 seconds
- [ ] Stop the run
- [ ] Open DevTools → Network → filter "runs"
- [ ] **VERIFY**: GET /api/runs returns JSON with RunInfo including:
  - [ ] `run_id`, `started_at`, `stopped_at`, `status` (required)
  - [ ] `events_total`, `segments_count`, `facts_extracted`, `signals_fired` (metrics)
  - [ ] `profile` (capture profile used)
- [ ] **VERIFY**: Runs tab shows the run as a clickable row (not empty state)
- [ ] Click the run row
- [ ] **VERIFY**: Detail panel displays metrics (events, segments, facts, signals)
- [ ] **VERIFY**: UI calls GET /api/signals with run's time range
- [ ] **VERIFY**: Findings tab shows "No findings for this run" (not "No runs yet")
- [ ] Restart the server
- [ ] **VERIFY**: Run persists in Runs tab after restart (SQLite persistence)

### A7. Facts Tab Coverage Endpoint (GET /api/runs/:id/coverage)
- [ ] Select a run that has `signal_count=0` but `facts_extracted > 0`
- [ ] Click the "Facts" tab in the run detail panel
- [ ] Open DevTools → Network → filter "coverage"
- [ ] **VERIFY**: Request to `GET /api/runs/{run_id}/coverage` returns HTTP 200
- [ ] **VERIFY**: Response always includes `available` field (boolean)

#### A7a. When coverage is AVAILABLE (`available: true`)
- [ ] **VERIFY**: Response JSON includes:
  - [ ] `available: true`
  - [ ] `run_id` - matches request
  - [ ] `facts_total` - total fact count (u64)
  - [ ] `fact_types` - array of {fact_type, count} sorted by count desc
  - [ ] `top_hosts` - array of {host, count}
  - [ ] `sensor_modes` - array of strings
  - [ ] `sensors` (optional) - array of {sensor_name, status, fact_count, capabilities}
  - [ ] `pipeline_diagnostics` - {playbooks_loaded, coverage_minutes, explanation, etc.}
- [ ] **VERIFY**: UI displays:
  - [ ] Total Facts, Fact Types count, Hosts count metrics
  - [ ] Top Fact Types table with distribution bars
  - [ ] Top Hosts badges
  - [ ] Sensors section (when present) showing each sensor with status badge
  - [ ] "Why no signals?" panel (when signals=0 but facts>0)
  - [ ] Pipeline Diagnostics expandable section

#### A7c. Sensor Status Values
- [ ] **VERIFY**: `status` field is one of:
  - [ ] `active` - sensor produced facts (fact_count > 0)
  - [ ] `configured` - sensor configured but no facts
  - [ ] `missing` - expected sensor not found
- [ ] **VERIFY**: Sensors section displays appropriate icon for each status

#### A7b. When coverage is UNAVAILABLE (`available: false`)
- [ ] Test with a run that has no `run_dir` (old format or seeded run)
- [ ] **VERIFY**: Response JSON includes:
  - [ ] `available: false`
  - [ ] `reason_code` - one of: `MISSING_RUN_DIR`, `MISSING_DB`, `MISSING_TABLE`, `PIPELINE_NOT_FINALIZED`, `RUN_NOT_FOUND`, `DATABASE_ERROR`
  - [ ] `message` - human-readable explanation
  - [ ] `run_id` - matches request
  - [ ] `debug` (optional) - {expected_path, run_status}
- [ ] **VERIFY**: UI displays empty state with the `message` (not stack traces)
- [ ] **VERIFY**: "Why no signals?" panel is hidden when available=false
- [ ] **VERIFY**: Sensors section is hidden when available=false

---

## B. Failure Truth Tests

### B6. Backend Offline
- [ ] Stop edr-server (Ctrl+C)
- [ ] Refresh UI at http://localhost:3000/ui/
- [ ] **VERIFY**: Server badge shows **OFFLINE** (red)
- [ ] **VERIFY**: Error banner shows: "Backend offline. Start edr-server to continue."
- [ ] **VERIFY**: Start Run button hard-fails (no state change)
- [ ] **VERIFY**: Counters show **—** (not "0")

### B7. Missing Binaries (HTTP 412)
- [ ] Ensure `locald` binary not built OR rename it temporarily
- [ ] Start edr-server, go to Mission tab
- [ ] Click "Start Run"
- [ ] **VERIFY**: HTTP 412 error returned
- [ ] **VERIFY**: Error shows missing binaries list
- [ ] **VERIFY**: "Copy build commands" button appears

---

## C. Explainability Truth Tests (CRITICAL)

### C8. Runs → Explain Flow
- [ ] Go to Runs tab
- [ ] Select a run with findings
- [ ] Click "Findings" tab
- [ ] Select a finding/signal
- [ ] Click "Explain" tab
- [ ] **VERIFY**: Explain tab shows backend-provided fields:
  - [ ] `signal_type` from `/api/signals`
  - [ ] `signal_id` from `/api/signals`
  - [ ] `playbook_id` or `hypothesis_name` from `/api/signals/:id/explain`
  - [ ] `detector_version` from explanation
  - [ ] Entities: `proc_key`, `file_key`, `host` from signal
  - [ ] Evidence pointers: `evidence_ptrs` array
  - [ ] Scoring: `risk_score`, `scoring_reasons` (if present)
- [ ] **VERIFY**: DevTools shows `GET /api/signals/:id/explain` called

### C9. Raw JSON Tab (Exact Backend Payload)
- [ ] With a finding selected, click "Raw JSON" tab
- [ ] **VERIFY**: JSON shown is EXACT backend payload (pretty-printed only)
- [ ] **VERIFY**: Contains `signal`, `explanation`, `narrative` keys
- [ ] **VERIFY**: "Copy" button copies JSON to clipboard
- [ ] Cross-check: Compare with DevTools Network response body

### C10. Missing Endpoint Behavior
- [ ] If `/api/signals` returns 404:
  - [ ] **VERIFY**: Findings tab shows "Not available (missing: /api/signals)"
  - [ ] **VERIFY**: Tab is NOT blank
- [ ] If `/api/signals/:id/explain` returns 404:
  - [ ] **VERIFY**: Explain tab shows "Not available (missing: /api/signals/:id/explain)"
  - [ ] **VERIFY**: Tab is NOT blank

### C11. Changes Tab - Layer 1 Explainability (GET /api/runs/:run_id/changes)
- [ ] Select a run (any run, even with signal_count=0)
- [ ] Click the "Changes" tab in run detail panel
- [ ] Open DevTools → Network → filter "changes"
- [ ] **VERIFY**: Request to `GET /api/runs/{run_id}/changes` returns HTTP 200
- [ ] **VERIFY**: Response always includes `available` field (boolean)

#### C11a. When changes are AVAILABLE (`available: true`)
- [ ] **VERIFY**: Response JSON includes:
  - [ ] `available: true`
  - [ ] `run_id` - matches request
  - [ ] `highlights` - array of top 5 most significant changes
  - [ ] `changes` - full array of categorized changes
  - [ ] `categories` - object mapping category names to counts
  - [ ] `stats` - {total_changes, fact_types, hosts}
- [ ] **VERIFY**: Each change item includes (Product Hardening):
  - [ ] `change_id` - stable identifier
  - [ ] `ts` - timestamp in milliseconds
  - [ ] `category` - one of: Process, Files, Network, Persistence, Auth, Evasion, Other
  - [ ] `title` - human-readable title
  - [ ] `summary` - brief description
  - [ ] `entities` - {host, fact_type, ...}
  - [ ] `evidence` - array of EvidencePointer objects (may be empty)
  - [ ] `evidence_unavailable_reason` - string explaining why evidence is empty (if applicable)
  - [ ] `supporting_facts_count` - number of related facts
  - [ ] `severity` - deterministic severity: info/low/medium/high/critical
  - [ ] `severity_basis` - human-readable explanation of severity calculation
- [ ] **VERIFY**: Highlights Evidence Invariant:
  - [ ] Each item in `highlights[]` MUST have either:
    - [ ] `evidence.length > 0`, OR
    - [ ] `evidence_unavailable_reason` explaining why evidence is missing
  - [ ] Items with empty evidence AND no reason are filtered out of highlights
- [ ] **VERIFY**: Severity is deterministic (same inputs → same severity)
- [ ] **VERIFY**: UI displays:
  - [ ] Stats metrics (Total Changes, Fact Types, Hosts)
  - [ ] Highlights section with top 5 changes
  - [ ] Categories section with colored badges showing counts
  - [ ] All Changes list (scrollable, max 50 items)
  - [ ] Severity badges match the `severity` field (not `severity_hint`)

#### C11b. When changes are UNAVAILABLE (`available: false`)
- [ ] Test with a run that has no `workbench.db`
- [ ] **VERIFY**: Response JSON includes `available: false` and `reason`
- [ ] **VERIFY**: UI shows "Not available" message (not blank)

#### C11c. Changes Work Even With signal_count=0
- [ ] Select a run where `signals_fired = 0` but `facts_extracted > 0`
- [ ] **VERIFY**: Changes tab still shows system changes from facts
- [ ] **VERIFY**: This is Layer 1 explainability - always works if facts exist

### C12. Playbooks Tab - Layer 2 Explainability (GET /api/runs/:run_id/playbooks)
- [ ] Select a run
- [ ] Click the "Playbooks" tab in run detail panel
- [ ] Open DevTools → Network → filter "playbooks"
- [ ] **VERIFY**: Request to `GET /api/runs/{run_id}/playbooks` returns HTTP 200
- [ ] **VERIFY**: Response always includes `available` field (boolean)

#### C12a. When playbooks are ENABLED
- [ ] Playbooks directory exists in one of the fallback locations:
  - [ ] `<binary_dir>/playbooks`
  - [ ] `%LOCALAPPDATA%/LocInt/playbooks`
  - [ ] `EDR_PLAYBOOKS_DIR` environment variable
- [ ] Select a run with signals
- [ ] **VERIFY**: Response JSON includes (Product Hardening):
  - [ ] `available: true`
  - [ ] `playbooks_enabled: true`
  - [ ] `playbooks_dir` - path to playbooks directory
  - [ ] `searched_paths` - array of paths that were checked
  - [ ] `not_found_reason` - null when found, string when not found
  - [ ] `loaded_count` - number of .yaml/.yml files found
  - [ ] `loaded_playbooks` - array of playbook names
  - [ ] `fired_count` - number that produced matches
  - [ ] `fired_playbooks` - array of playbook names that fired
  - [ ] `matches` - array of match objects with signal details
  - [ ] `by_category` - object mapping MITRE tactics to playbooks
  - [ ] `mitre_techniques` - array of ONLY valid MITRE IDs from playbook metadata
- [ ] **VERIFY**: MITRE Truthfulness Invariant:
  - [ ] `mitre_techniques[]` contains ONLY technique IDs that:
    - [ ] Are actually specified in playbook metadata
    - [ ] Start with "T" and have at least 4 characters
  - [ ] Empty array `[]` if no MITRE IDs in metadata (not invented IDs)
  - [ ] UI displays "—" when `mitre_techniques` is empty
- [ ] **VERIFY**: UI displays:
  - [ ] Stats (Loaded, Fired, Matches)
  - [ ] Playbooks directory path
  - [ ] Matches list with severity badges and MITRE technique IDs
  - [ ] By MITRE Tactic section (when matches exist)
  - [ ] MITRE Techniques section (shows real techniques only, or "—")

#### C12b. When playbooks are NOT FOUND
- [ ] Remove all playbook directories from fallback chain
- [ ] Restart backend
- [ ] **VERIFY**: Response JSON includes:
  - [ ] `playbooks_enabled: false`
  - [ ] `searched_paths` - array of paths that were searched
  - [ ] `not_found_reason` - explains where it looked and how to fix
  - [ ] `mitre_techniques: []` - empty array (not null)
- [ ] **VERIFY**: UI shows "Playbooks not evaluated for this run" message
- [ ] **VERIFY**: Message includes searched paths and hint about EDR_PLAYBOOKS_DIR

#### C12c. Playbooks Tab Shows "Not evaluated" vs Empty Matches
- [ ] If playbooks disabled: Shows "Playbooks not evaluated" (distinct from no matches)
- [ ] If playbooks enabled but no matches: Shows "No playbook matches found" with stats

---

## D. Imported Mode Tests

### D11. Import/Export Flow
- [ ] Export a bundle → downloads `.zip` file
- [ ] Import a bundle → switches to Runs tab
- [ ] **IMPORTED** banner appears at top (purple)
- [ ] Server badge shows **IMPORTED** (purple)
- [ ] Start Run button is **disabled**
- [ ] Runs list shows imported runs

### D12. Explainability on Imported Data
- [ ] Select an imported run
- [ ] Findings tab loads signals from imported data
- [ ] Explain tab works for imported signals
- [ ] Raw JSON tab shows imported data

### D13. Return to Local
- [ ] Click "Return to Local" button in banner
- [ ] Banner hides
- [ ] Server badge returns to normal
- [ ] Start Run re-enabled
- [ ] Polling resumes

---

## E. Console Verification

```javascript
// Should see on load:
// APP BOOT 2026-01-10-VERIFY
// [Init] Incident Compiler UI starting... 2026-01-10-VERIFY
// [probeCapabilities] Checking backend capabilities...
// [probeCapabilities] Result: {...}
// [Init] Capabilities: {...}

// API calls logged (always):
// [API] GET /api/health
// [API] GET /api/selfcheck
// [API] GET /api/run/status
// [API] GET /api/runs

// When selecting a run:
// [API] GET /api/signals?limit=500

// When viewing explanation:
// [API] GET /api/signals/:id
// [API] GET /api/signals/:id/explain
// [API] GET /api/signals/:id/narrative
```

---

## F. Endpoint Map (Backend Routes → UI Sections)

| Method | Endpoint | Response Shape | UI Section |
|--------|----------|----------------|------------|
| GET | `/api/health` | `{status: "ok"}` | Server badge online/offline |
| GET | `/api/selfcheck` | `SelfCheckResponse` | Settings → Readiness |
| GET | `/api/run/status` | `{running, run_id, started_at, elapsed_seconds, profile}` | Mission → Run state |
| POST | `/api/run/start` | `{run_id, profile, ...}` | Mission → Start button |
| POST | `/api/run/stop` | `{stopped: true}` | Mission → Stop button |
| GET | `/api/run/metrics` | `{events, segments, facts, signals}` | Mission → Counters |
| GET | `/api/runs` | `RunInfo[]` | Runs → Left panel list |
| GET | `/api/signals` | `StoredSignal[]` | Runs → Findings tab |
| GET | `/api/signals/:id` | `StoredSignal` | Runs → Selected finding |
| GET | `/api/signals/:id/explain` | `ExplanationBundle` | Runs → Explain tab |
| GET | `/api/signals/:id/narrative` | `Narrative` | Runs → Explain → Summary |
| GET | `/api/signals/stats` | `SignalStats` | (Future: dashboard stats) |
| POST | `/api/export/bundle` | Binary ZIP | Import/Export → Export |
| POST | `/api/import/bundle` | `{success, imported_runs}` | Import/Export → Import |

### Data Structures (from backend)

**StoredSignal** (from /api/signals):
```json
{
  "signal_id": "uuid",
  "signal_type": "string",
  "ts": 1234567890,
  "host": "hostname",
  "severity": "critical|high|medium|low",
  "proc_key": "process_name.exe",
  "file_key": "C:\\path\\file.txt",
  "identity_key": "DOMAIN\\User",
  "evidence_ptrs": [...],
  "dropped_evidence_count": 0,
  "metadata": {...}
}
```

**ExplanationBundle** (from /api/signals/:id/explain):
```json
{
  "hypothesis_name": "string",
  "playbook_id": "string",
  "detector_version": "string",
  "matched_slots": {...},
  "evidence_refs": [...],
  "scoring": {
    "risk_score": 0.85,
    "base_severity": "high",
    "mahalanobis_distance": 2.3,
    "scoring_reasons": [
      {"reason": "...", "weight": 0.3}
    ]
  }
}
```

**Narrative** (from /api/signals/:id/narrative):
```json
{
  "sentences": [
    {"text": "...", "confidence": 0.9}
  ],
  "entities": {
    "processes": [...],
    "users": [...],
    "hosts": [...]
  }
}
```

---

## G. Summary Table

| # | Requirement | Verified |
|---|-------------|----------|
| A1 | GET /api/selfcheck (not /api/diagnostics/self-check) | ☐ |
| A2 | POST /api/export/bundle (not /api/bundles/export) | ☐ |
| A3 | POST /api/import/bundle (not /api/bundles/import) | ☐ |
| A4 | Start Run → POST then GET status | ☐ |
| A5 | Stop Run → POST then GET status | ☐ |
| B6 | Backend offline → hard fail with banner | ☐ |
| B7 | Missing binaries (412) → hard fail | ☐ |
| C8 | Explain tab shows backend fields | ☐ |
| C9 | Raw JSON = exact backend payload | ☐ |
| C10 | Missing endpoint → explicit message (not blank) | ☐ |
| D11 | Import/Export with correct endpoints | ☐ |
| D12 | Imported mode explainability works | ☐ |
| D13 | Return to Local resets properly | ☐ |

---

## H. SHIP TESTS (Critical - Must Pass Before Release)

### H1. Run Isolation Test (NO SIGNAL MIXING)
**Purpose**: Ensure selecting a run ONLY shows signals belonging to that run.

1. Create or ensure you have at least 2 runs with signals in different time buckets
2. Open http://localhost:3000/ui/?debug=1
3. Go to Runs tab
4. Select Run A → Note the findings count
5. Switch to Findings tab → Note the signal IDs / timestamps
6. Return to run list, select Run B → Note the findings count (should differ)
7. Check Findings tab → Signal IDs / timestamps should be DIFFERENT from Run A

**VERIFY in debug panel**:
- [ ] Debug panel shows `run:run_XXXXX` context when loading signals
- [ ] Different run_ids appear when switching runs
- [ ] Console log shows: `[fetchSignalsForRun] Run run_X: N/M signals in time range [earliest, latest]`
- [ ] NO signal from Run A appears when Run B is selected (strict isolation)

**FAIL CRITERIA**: If ANY signal appears in both runs when it shouldn't, this is a ship-blocker.

### H2. Evidence Dereference Truthfulness Test
**Purpose**: Ensure UI does NOT have non-functional "View evidence" buttons.

1. Select a run with findings
2. Select a finding
3. Go to Explain tab
4. Look at the "Evidence Pointers" section

**VERIFY**:
- [ ] Evidence pointers are displayed as read-only text (JSON format)
- [ ] A note appears: "Evidence dereference not available yet. Pointers are for reference only."
- [ ] There is NO clickable "View" or "Open" button next to pointers
- [ ] If `dropped_evidence_count > 0`, it shows "+ N additional evidence items (truncated)"

**FAIL CRITERIA**: If there's a clickable element that does nothing or throws an error, this is a ship-blocker.

### H3. Scoring Integrity Test (NO UI RECOMPUTATION)
**Purpose**: Ensure UI displays backend scores exactly as returned, without recomputation.

1. Select a finding that has an explanation
2. Go to Explain tab
3. Look at the "Scoring" section

**VERIFY if backend provides scoring**:
- [ ] Label "🔒 Backend Score (unmodified)" appears
- [ ] `risk_score` displayed as percentage matches backend payload exactly
- [ ] `mahalanobis_distance`, `elliptic_envelope_score`, `krim_score` shown if present
- [ ] `scoring_reasons` list shown with "(from backend)" label
- [ ] If `scoring_reasons` is missing, shows "Not available (missing: scoring_reasons)"

**VERIFY if backend does NOT provide scoring**:
- [ ] Shows "Not available" with "(missing: scoring object in explanation)"
- [ ] Shows signal severity as reference only
- [ ] Does NOT show a computed/fake score (no "Severity-based Score: XX%")

**VERIFY in Raw JSON tab**:
- [ ] The `scoring` object in raw JSON matches what's displayed in Scoring section
- [ ] No additional fields or transformations applied by UI

**FAIL CRITERIA**: If UI shows a different score than backend provides, or computes its own score when backend doesn't provide one, this is a ship-blocker.

---

## I. Reliability Fixes Verification (RD-1 through RD-5)

### I1. RD-1: facts_extracted from DB Query (P0)
**Purpose**: Verify facts_extracted counter uses DB query, not log parsing.

1. Start a run, let it capture for 10+ seconds
2. Open DevTools → Network → filter "metrics"
3. **VERIFY**: GET /api/run/metrics response includes `facts_extracted`
4. **VERIFY**: `facts_extracted` increases as facts are written to `coverage_rollup` table
5. Stop the run
6. Check `run_meta.json` in run directory
7. **VERIFY**: `facts_extracted` field has final count from DB

**Expected Behavior**:
- [ ] `facts_extracted` updates during run (reflects DB state)
- [ ] If DB unavailable, `facts_extracted` returns `null` (UI shows "—")
- [ ] No longer parses `locald.log` for "facts:" keyword

### I2. RD-3: Playbooks Endpoint Contract (P0)
**Purpose**: Verify playbooks endpoint returns `available=false` when not configured.

1. Ensure no playbooks directory exists (or set `LOCINT_PLAYBOOKS=off`)
2. Start a run, then stop it
3. Open DevTools → Network → filter "playbooks"
4. Request `GET /api/runs/{run_id}/playbooks`

**VERIFY when playbooks not found**:
- [ ] Response: `{ "available": false, "reason_code": "PLAYBOOKS_NOT_FOUND", "message": "...", "searched_paths": [...] }`
- [ ] Does NOT return `available: true` with `playbooks_enabled: false` (old broken contract)
- [ ] UI displays clean "Playbooks not configured" message (not network error)

**VERIFY when playbooks disabled by config**:
- [ ] Set `LOCINT_PLAYBOOKS=off` environment variable
- [ ] Response: `{ "available": false, "reason_code": "PLAYBOOKS_DISABLED", "message": "..." }`

### I3. RD-5: Run Finalize on Stop (P1)
**Purpose**: Verify run_meta.json gets finalized with complete stats on stop.

1. Start a run, let it capture for 10+ seconds
2. Stop the run
3. Open run directory and check `run_meta.json`

**VERIFY**:
- [ ] `run_meta.json` contains `stopped_at` timestamp
- [ ] `run_meta.json` contains `finalized: true`
- [ ] `run_meta.json` contains final counts:
  - [ ] `events_total` - from segments
  - [ ] `segments_count` - from segments directory
  - [ ] `facts_extracted` - from `coverage_rollup` table
  - [ ] `signals_fired` - from `signals` table
- [ ] Runs list shows stable final counts (not stale/zero)
- [ ] Counts persist after server restart

### I4. RD-4: Export Isolation (P1)
**Purpose**: Verify export cannot generate signals and is blocked while running.

#### I4a. Export Blocked While Running
1. Start a run
2. While run is active, try to export: POST /api/export/bundle with run_id
3. **VERIFY**: Returns HTTP 409 with `{"error": "Stop run before export", "code": "RUN_ACTIVE"}`
4. Stop the run
5. Try export again
6. **VERIFY**: Export succeeds (HTTP 200)

#### I4b. Self-Process Allowlist
1. Start a run in the background
2. Perform file operations that might trigger signals (if testing manually)
3. Stop the run
4. **VERIFY**: No signals from these processes:
  - [ ] `locint.exe`
  - [ ] `edr-server.exe`
  - [ ] `edr-locald.exe`
  - [ ] `capture_windows_rotating.exe`

### I5. RD-2: Tag Mapping Improvements (P2)
**Purpose**: Verify additional tag mappings reduce TAG_BASED_UNSUPPORTED skips.

1. Check locald stderr output or `playbook_manager.log_summary()` output
2. **VERIFY**: Skipped playbook count is reduced
3. **VERIFY**: New mappings work:
  - [ ] `wmi` tag → maps to Exec fact with wmiprvse/scrcons filter
  - [ ] `mof` tag → maps to Exec fact with mofcomp/wmi filter  
  - [ ] `audit_*` tags → map to Exec fact with auditpol filter
4. **VERIFY**: WARN-level logging shows:
  - [ ] Count of skipped playbooks by reason
  - [ ] Format: `[PlaybookManager] WARN: N playbooks skipped due to: REASON`

---

## Debug Mode

Enable with `?debug=1` in URL: http://localhost:3000/ui/?debug=1

Shows floating panel in bottom-right with last 10 API calls:
- Time of call
- HTTP method (GET/POST)
- Endpoint path + context (run_id, signal_id)
- Status code (green=200, yellow=404, red=error)
- HTML responses marked `[HTML!]` with preview snippet

This is for verification only and hidden in production.

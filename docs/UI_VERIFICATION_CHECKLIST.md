# UI Verification Checklist - CORE PRODUCT
BUILD_STAMP: 2026-01-11-CORE

This checklist validates the **Core Loop** for the Incident Compiler UI.
See [CORE_PRODUCT.md](CORE_PRODUCT.md) for the Core Product Constitution.

**CORE LOOP**: Start App → Start Run → Capture + Detect → Stop Run → Review → Export/Import

**TRUTH TESTS**: These are hard, verifiable tests using DevTools Network tab. No guessing.

---

## Pre-flight

1. **Build core binaries** (default features only):
   ```powershell
   cd windows-incident-compiler
   cargo build --release --bin locint
   cargo build --release --bin edr-locald
   cargo build --release -p agent-windows --bin capture_windows_rotating
   ```

2. **Start the app** (one of):
   - Double-click `locint.exe` (desktop mode)
   - OR: `cargo run --release --bin locint`

3. **Open UI**: http://localhost:3000/ui/

4. **Verify Build**:
   - Console shows: `APP BOOT 2026-01-11-CORE` (or later)
   - Browser shows: Four main tabs (Mission, Runs, Import/Export, Settings)

---

## Section A: Core Loop Tests

### A1. Health Check (GET /api/health)
- [ ] Open UI, server badge shows **ONLINE** (green)
- [ ] Open DevTools → Network → filter "health"
- [ ] **VERIFY**: `GET /api/health` returns `{success: true, data: {status: "ok"}}`
- [ ] **VERIFY**: Response is JSON (not HTML)

### A2. Start Run (POST /api/run/start)
- [ ] Go to Mission tab
- [ ] Open DevTools → Network
- [ ] Click **Start Run** button
- [ ] **VERIFY**: `POST /api/run/start` returns `{run_id, started_at}`
- [ ] **VERIFY**: Status badge changes to "Running" (yellow)
- [ ] **VERIFY**: `GET /api/run/status` confirms `running: true`
- [ ] **VERIFY**: Live counters start updating (Segments, Events, etc.)

### A3. Live Metrics (GET /api/run/metrics)
- [ ] With run active, wait 5-10 seconds
- [ ] **VERIFY**: Segments counter increases
- [ ] Open DevTools → Network → filter "metrics"
- [ ] **VERIFY**: `GET /api/run/metrics` returns:
  - `segments_count` (number)
  - `events_total` (number)
  - `facts_extracted` (number or null)
  - `signals_fired` (number)

### A4. Stop Run (POST /api/run/stop)
- [ ] With run active, click **Stop Run** button
- [ ] **VERIFY**: `POST /api/run/stop` returns `{stopped: true, finalized: true}`
- [ ] **VERIFY**: Status badge changes to "Stopped"
- [ ] **VERIFY**: `GET /api/run/status` confirms `running: false`
- [ ] **VERIFY**: Counters freeze at final values

### A5. Run Finalization (run_meta.json)
- [ ] After stopping, check run directory (`%LOCALAPPDATA%/LocInt/runs/run_*`)
- [ ] **VERIFY**: `run_meta.json` exists with:
  - `started_at` (ISO timestamp)
  - `stopped_at` (ISO timestamp)
  - `finalized: true`
  - `events_total`, `signals_fired`, etc.
- [ ] **VERIFY**: `workbench.db` exists in run directory

### A6. List Runs (GET /api/runs)
- [ ] Go to Runs tab
- [ ] Open DevTools → Network → filter "runs"
- [ ] **VERIFY**: `GET /api/runs` returns array of runs
- [ ] **VERIFY**: Each run has:
  - `run_id`
  - `started_at`
  - `stopped_at` (if completed)
  - `status`
- [ ] **VERIFY**: UI shows run list with clickable rows

### A7. Review Run - Overview
- [ ] Click a completed run in Runs tab
- [ ] **VERIFY**: Detail panel shows run info:
  - Events, Segments, Facts, Signals metrics
  - Started/Stopped timestamps
  - Duration

### A8. Review Run - Facts (GET /api/runs/:id/coverage)
- [ ] Click **Facts** tab in run detail
- [ ] Open DevTools → Network → filter "coverage"
- [ ] **VERIFY**: `GET /api/runs/{run_id}/coverage` returns:
  - `available: true` (if data exists)
  - `facts_total`
  - `fact_types[]`
  - `top_hosts[]`
- [ ] **VERIFY**: UI displays fact types table

### A8a. Facts Tab - No Telemetry State (readiness_snapshot)
- [ ] Run the app **without** Administrator privileges
- [ ] Complete a short run (5+ seconds)
- [ ] Click **Facts** tab in run detail
- [ ] **IF** `facts_total = 0` AND `readiness_snapshot` exists:
  - [ ] **VERIFY**: "No Security Telemetry Collected" panel shows
  - [ ] **VERIFY**: Reasons list shows specific issues:
    - "Security Event Log: Access Denied" (if not admin)
    - "Sysmon: Not Installed" (if Sysmon missing)
  - [ ] **VERIFY**: "How to Fix" section expands with remediation steps
- [ ] **VERIFY**: `GET /api/runs/{run_id}/coverage` includes `readiness_snapshot`

### A8b. Mission Tab - Readiness Warning
- [ ] Open Mission tab
- [ ] **IF** selfcheck returns `telemetry.status: "limited"` or `"partial"`:
  - [ ] **VERIFY**: Yellow warning banner appears below "Start Run"
  - [ ] **VERIFY**: Warning shows: "Limited Telemetry Expected"
  - [ ] **VERIFY**: Issues list shows missing prerequisites
- [ ] **VERIFY**: `GET /api/selfcheck` includes `telemetry` object with:
  - `status`: "full" | "partial" | "limited"
  - `is_admin`: boolean
  - `sysmon_installed`: boolean
  - `issues[]`: array of issue descriptions

### A8c. Mission Tab - Restart as Administrator (POST /api/app/restart_admin)
- [ ] Open Mission tab **without** running as Administrator
- [ ] **VERIFY**: `GET /api/selfcheck` returns `is_admin: false` and `supports_restart_admin: true`
- [ ] **VERIFY**: Yellow warning shows "Security Log: Not Accessible (not running as Admin)"
- [ ] **VERIFY**: "Restart as Administrator" button appears with shield icon
- [ ] Click "Restart as Administrator" button
- [ ] **VERIFY**: UAC prompt appears
- [ ] **IF** user clicks "Yes" on UAC:
  - [ ] **VERIFY**: Button shows "✓ Relaunching..."
  - [ ] **VERIFY**: App exits and relaunches with elevated privileges
  - [ ] **VERIFY**: Warning banner disappears (now running as admin)
- [ ] **IF** user clicks "No" on UAC:
  - [ ] **VERIFY**: Error hint shows "Elevation canceled"
  - [ ] **VERIFY**: Button returns to enabled state
- [ ] **ALREADY ADMIN**: If already running as admin, restart button should be hidden

### A9. Review Run - Findings (GET /api/signals)
- [ ] Click **Findings** tab in run detail
- [ ] **VERIFY**: `GET /api/signals?run_id=X` is called
- [ ] **VERIFY**: Response uses CONTRACT shape: `{success, data: {signals: [...], run_id, available, next_since_ts_ms}}`
- [ ] **VERIFY**: UI shows signals list (or "No findings for this run")
- [ ] If signals exist, click one
- [ ] **VERIFY**: Signal detail appears with severity, type, timestamp

### A10. Review Run - Explain (GET /api/signals/:id/explain)
- [ ] With a signal selected, click **Explain** tab
- [ ] **VERIFY**: `GET /api/signals/{id}/explain?run_id=X` is called
- [ ] **VERIFY**: Response matches CONTRACT ExplainResponse schema:
  - `available`: boolean (required)
  - `signal`: object with signal_id, signal_type, ts_ms, severity (required)
  - `source`: object with kind ("playbook"|"detector"|"unknown"), id, version (required)
  - `evidence_ptrs`: array (required, possibly empty)
  - `evidence_ptrs_count`: number (required)
- [ ] **VERIFY**: UI shows **Explain Header** summary bar with:
  - Source: "Playbook <name>" | "Detector <name>" | "Unknown"
  - Evidence: count of evidence pointers
  - Confidence: percentage or "—"
  - Run: run_id + timestamp

### A10a. Explain Tab - available=true
- [ ] With a signal that has full explanation, click **Explain** tab
- [ ] **VERIFY**: No yellow "unavailable" banner shown
- [ ] **VERIFY**: Narrative section shows summary text
- [ ] **VERIFY**: Matched slots section shows slot matches (if playbook)
- [ ] **VERIFY**: Evidence pointers section populated

### A10b. Explain Tab - available=false
- [ ] With a signal that has NO explanation (EXPLANATION_NOT_FOUND), click **Explain** tab
- [ ] **VERIFY**: Yellow "unavailable" banner shows:
  - "Explanation unavailable: EXPLANATION_NOT_FOUND"
  - Message: "Explanation bundle not found..."
- [ ] **VERIFY**: Explain Header still shows Source/Evidence/Confidence/Run
- [ ] **VERIFY**: Narrative shows "Showing partial signal context only."
- [ ] **VERIFY**: Scoring shows "Not available (explanation unavailable)"
- [ ] **VERIFY**: Slots shows "Not available (explanation unavailable)"
- [ ] **VERIFY**: NO synthetic/invented narrative text is shown

### A10c. Explain Auto-Refresh (Real-Time Update)
Tests that the Explain tab auto-refreshes when explanation becomes available during an active run.

**Setup**: This test requires triggering a known detection during an active run.

1. **Trigger Known Fire**:
   - Start a run (or use an active run)
   - Execute encoded PowerShell to trigger `signal_encoded_powershell`:
     ```powershell
     powershell -EncodedCommand ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==
     ```
   - Wait ~2-3 seconds for signal to appear in Findings tab

2. **Immediate Selection Test**:
   - [ ] As soon as the signal appears in Findings tab, click on it
   - [ ] Immediately switch to **Explain** tab
   - [ ] **VERIFY**: One of:
     - (a) Explanation shows `available=true` immediately (signal+explanation written together), OR
     - (b) Brief "unavailable" state with retry indicator: "Waiting for explanation… retrying (N)"

3. **Auto-Refresh Behavior**:
   - [ ] If unavailable state shows:
     - [ ] **VERIFY**: Retry status shows below the unavailable banner
     - [ ] **VERIFY**: Status updates: "Waiting for explanation… retrying (1)", then (2), etc.
     - [ ] **VERIFY**: Elapsed time shown (e.g., "0.5s elapsed")
   - [ ] **VERIFY**: Within 10 seconds, explanation auto-updates to `available=true`
   - [ ] **VERIFY**: Once available, retry indicator disappears
   - [ ] **VERIFY**: Full explanation content renders (narrative, slots, evidence)

4. **Stop Conditions**:
   - [ ] **VERIFY**: Selecting a different signal stops the retry loop for the previous signal
   - [ ] **VERIFY**: Leaving the Explain tab (switching to another tab) stops the retry loop
   - [ ] **VERIFY**: Returning to Explain tab resumes retry if still unavailable
   - [ ] **VERIFY**: Stopping the run stops the retry loop (run ends)

5. **Exhausted Retries**:
   - [ ] If explanation remains unavailable after 10s:
     - [ ] **VERIFY**: Message shows "Still unavailable after 10s"
     - [ ] **VERIFY**: "Retry" button appears
     - [ ] **VERIFY**: Clicking Retry restarts the refresh loop

6. **Imported Mode**:
   - [ ] Import a bundle and select a signal
   - [ ] **VERIFY**: No retry loop starts (imported data is static)

7. **Network Tab Verification**:
   - [ ] Open DevTools → Network → filter "explain"
   - [ ] **VERIFY**: Requests are spaced out (exponential backoff: 500ms, 1s, 2s, 3s…)
   - [ ] **VERIFY**: No overlapping/parallel explain requests
   - [ ] **VERIFY**: Requests stop once `available=true` returned

### A10d. Diff v2 - Phase Mode (GET /api/runs/:id/diff?mode=phase)
- [ ] Select a completed run in Runs tab
- [ ] Click **Changes** tab
- [ ] **VERIFY**: Default mode is "Phase (First N min vs Rest)"
- [ ] **VERIFY**: `GET /api/runs/{run_id}/diff?mode=phase&phase_minutes=2` is called
- [ ] **VERIFY**: Response includes:
  - `available: true`
  - `mode: "phase"`
  - `comparison: "First 2min vs Rest"`
  - `capability_snapshot_a` and `capability_snapshot_b`
  - `changes[]` array with canonical Change objects
  - `stats.by_category` and `stats.by_direction` counts
- [ ] **VERIFY**: Comparison header shows "📊 First 2min vs Rest (N changes)"
- [ ] **VERIFY**: Stats tiles show Total, Added, Removed, Modified counts
- [ ] **VERIFY**: Categories badges show counts (click to filter)
- [ ] **VERIFY**: Changes list shows items with direction badges (➕/➖/📈/📉/✏️)

### A10e. Diff v2 - Baseline Mode (GET /api/runs/:id/diff?mode=baseline)
- [ ] Have at least 2 completed runs available
- [ ] Select a run in Runs tab, click **Changes** tab
- [ ] Change mode dropdown to "Baseline (Compare to Run)"
- [ ] **VERIFY**: Baseline run dropdown appears
- [ ] Select another run as baseline
- [ ] Click **Refresh**
- [ ] **VERIFY**: `GET /api/runs/{run_id}/diff?mode=baseline&baseline_run_id={other}` is called
- [ ] **VERIFY**: Response includes:
  - `comparison: "{baseline_id} vs {current_id}"`
  - Both `capability_snapshot_a` (baseline) and `capability_snapshot_b` (current)
- [ ] **VERIFY**: If capability differs, `telemetry_caveats[]` is populated
- [ ] **VERIFY**: If baseline not found, error message shown

### A10f. Diff v2 - Telemetry Caveat Behavior
- [ ] Create scenario with differing telemetry:
  - Baseline run: Sysmon installed, Security log accessible
  - Current run: Sysmon missing OR Security log not accessible
- [ ] Compare using Baseline mode
- [ ] **VERIFY**: Yellow "Telemetry Alignment Notes" banner appears
- [ ] **VERIFY**: Caveat message explains limitation, e.g.:
  - "⚠️ Sysmon was present in set A but missing in set B - Process/Network changes may be incomplete"
- [ ] **VERIFY**: "Removed" items are NOT reported if current cannot observe that surface
- [ ] **VERIFY**: "Added" items are NOT reported if baseline couldn't observe that surface

### A10g. Diff v2 - Filter Controls
- [ ] With changes displayed, select a category filter (e.g., "Persistence")
- [ ] **VERIFY**: Request includes `&category=Persistence`
- [ ] **VERIFY**: Only Persistence changes shown
- [ ] Select a direction filter (e.g., "added")
- [ ] **VERIFY**: Request includes `&direction=added`
- [ ] **VERIFY**: Only added items shown
- [ ] Clear filters
- [ ] **VERIFY**: All changes shown again

### A10h. Diff v2 - Evidence Viewing
- [ ] Find a change item with evidence (shows "🔗 N evidence")
- [ ] Click on the change item
- [ ] **VERIFY**: Evidence viewer modal opens
- [ ] **VERIFY**: Modal shows evidence pointers
- [ ] Close modal by clicking X or outside
- [ ] Find a change without evidence (shows "⚠️ No evidence")
- [ ] **VERIFY**: Clicking shows no modal (not clickable or shows unavailable reason)

### A10i. Diff v2 - Canonical Change Schema
- [ ] In DevTools → Network, inspect a diff response
- [ ] **VERIFY**: Each change object has ALL required fields:
  - `change_id`: stable unique string
  - `ts_ms`: timestamp in milliseconds
  - `category`: one of process|persistence|auth|network|evasion|file|other
  - `direction`: one of added|removed|increased|decreased|modified
  - `title`: human-readable string
  - `summary`: detailed string
  - `entities`: object with host, proc_key, user, etc. (some nullable)
  - `severity`: critical|high|medium|low|info
  - `severity_basis`: explanation string
  - `evidence_ptrs`: array (may be empty)
  - `supporting_facts_count`: number
  - `stable_key`: deterministic key string
- [ ] **VERIFY**: `evidence_unavailable_reason` present if `evidence_ptrs` empty

### A11. Export Bundle (POST /api/export/bundle)
- [ ] Go to Import/Export tab
- [ ] **VERIFY**: Export button is disabled while run is active
- [ ] With no run active, click **Export Bundle**
- [ ] Open DevTools → Network → filter "bundle"
- [ ] **VERIFY**: `POST /api/export/bundle` with `run_id`
- [ ] **VERIFY**: Response is `application/zip`
- [ ] **VERIFY**: ZIP file downloads

### A12. Import Bundle (POST /api/import/bundle)
- [ ] Drag & drop a valid ZIP onto Import/Export drop zone
- [ ] **VERIFY**: `POST /api/import/bundle` with multipart form
- [ ] **VERIFY**: IMPORTED banner appears
- [ ] **VERIFY**: UI switches to Runs tab with imported run
- [ ] **VERIFY**: Imported run is read-only (cannot delete)

### A13. System State Summary Panel (GET /api/runs/:id/state)
- [ ] Complete a run and click on it in Runs tab
- [ ] **VERIFY**: "System State Summary" panel appears below run title
- [ ] **VERIFY**: Panel shows:
  - Telemetry status badge (Full/Partial/Limited/Blocked)
  - Sensors list with status icons (✓ available, ✗ unavailable)
  - Facts count and Signals count
  - Top observed process (if any)
- [ ] Open DevTools → Network → filter "state"
- [ ] **VERIFY**: `GET /api/runs/{run_id}/state` returns:
  - `telemetry_status`: "full" | "partial" | "limited" | "blocked"
  - `sensors[]`: array of {name, status}
  - `facts_total`: number
  - `signals_count`: number
  - `top_entities`: {processes[], users[], network[], hosts[]}

### A13a. State Panel - Zero Facts Case
- [ ] Complete a run with 0 facts (e.g., non-admin)
- [ ] **VERIFY**: State panel still shows (not blank)
- [ ] **VERIFY**: Telemetry status shows "Limited" or "Blocked"
- [ ] **VERIFY**: Sensors show unavailable status where appropriate
- [ ] **VERIFY**: `notes[]` array includes explanation

### A14. Playbooks Tab - Slot Progress (GET /api/runs/:id/playbooks)
- [ ] Click **Playbooks** tab in run detail
- [ ] **VERIFY**: `GET /api/runs/{run_id}/playbooks` returns:
  - `loaded_count`: number of playbooks loaded
  - `fired_count`: number that produced signals
  - `playbook_evals[]`: per-playbook status array
  - `top_near_misses[]`: top 5 partial matches
  - `telemetry_blocked_count`: count blocked by missing telemetry
  - `explanation`: human-readable summary

### A14a. Playbook Evaluation Cards
- [ ] **VERIFY**: Each playbook eval shows:
  - Status icon: ✓ (fired), ◐ (partial), ○ (no_match), ⚠ (blocked)
  - Progress bar showing slots filled (e.g., "2/4 slots, 50%")
  - Missing slots list (if partial)
  - Telemetry blocked warning (if applicable)
- [ ] **VERIFY**: Filter dropdown works (All/Fired/Partial/No Match/Telemetry Missing)

### A14b. Near-Misses Section
- [ ] **IF** any playbooks had partial matches:
  - [ ] **VERIFY**: "Near Misses" section appears
  - [ ] **VERIFY**: Shows top 5 playbooks sorted by completion_ratio
  - [ ] **VERIFY**: Each card shows which slots matched/missing

### A14c. Playbook Detail Drawer (Interactivity Feature)
Tests the interactive playbook detail drawer for both catalog and run contexts.

**Catalog Context (Detection Plan):**
1. [ ] Go to Detection Plan tab (from Mission or main nav)
2. [ ] **VERIFY**: Playbook catalog rows are clickable (cursor: pointer, hover effect)
3. [ ] Click on any playbook row
4. [ ] **VERIFY**: Detail drawer slides in from right
5. [ ] **VERIFY**: Drawer shows:
   - Playbook name and category at top
   - Status badge (enabled/blocked/disabled)
   - Description text
   - Prerequisites badges (Admin, Sysmon, Security Log) if applicable
   - MITRE ATT&CK techniques and tactics
   - "How It Fires" guidance text (human-readable, no regex)
   - Detection Slots list with:
     - Slot name and required/optional badge
     - Intent description (what it looks for)
     - Required fields list
     - Examples hint (safe text, no commands)
     - Telemetry dependency (Sysmon 1, Security 4688, etc.)
6. [ ] **VERIFY**: Close button (✕) closes drawer
7. [ ] **VERIFY**: ESC key closes drawer
8. [ ] **VERIFY**: Selecting different playbook updates drawer content

**Run Context (Playbook Evaluations):**
1. [ ] Go to a completed run's Playbooks tab
2. [ ] Click on any playbook evaluation card
3. [ ] **VERIFY**: Detail drawer opens with run-specific data:
   - Same fields as catalog view PLUS
   - Run Evaluation section showing:
     - Status (fired/partial/no_match/blocked)
     - Completion percentage
     - Matched slots list (green ✓)
     - Missing slots list (yellow ○)
     - `why_not_fired` explanation (if partial/no_match)
     - Evidence pointer count (if fired)
4. [ ] **VERIFY**: "View in Catalog" button opens catalog version

**Debug Mode Validation Triggers:**
1. [ ] Open UI with `?debug=1` query parameter
2. [ ] Open a playbook with validation_hint_id (e.g., encoded_powershell)
3. [ ] **VERIFY**: Debug-only "Validation Trigger" section appears
4. [ ] **VERIFY**: Shows trigger notes and requirements
5. [ ] **VERIFY**: "Copy Validation Command" button works
6. [ ] **VERIFY**: Button shows "✓ Copied!" briefly after click
7. [ ] Close debug mode (remove ?debug=1)
8. [ ] **VERIFY**: Validation trigger section does NOT appear

**Security Verification:**
- [ ] **VERIFY**: NO raw regex patterns shown anywhere in drawer
- [ ] **VERIFY**: Slot `intent` shows human-readable description only
- [ ] **VERIFY**: `examples_hint` shows safe hints (no executable commands)
- [ ] **VERIFY**: Validation triggers only shown in debug mode

### A14d. Next Steps Workflow Guidance (GET /api/runs/:id/next_steps)
Tests the deterministic workflow guidance system that tells users what to do next after a run.

**Endpoint Verification:**
1. [ ] Complete any run
2. [ ] Open DevTools → Network → filter "next_steps"
3. [ ] **VERIFY**: `GET /api/runs/{run_id}/next_steps` returns:
   - `run_id`: string
   - `scenario`: one of "telemetry_blocked"|"limited_no_facts"|"no_findings"|"near_miss"|"findings_present"
   - `summary`: { `text`: string, `severity`: "info"|"low"|"medium"|"high" }
   - `actions`: array of action objects
   - `evidence_basis`: object with facts_total, signals_total, etc.

**UI Panel Verification:**
1. [ ] Select a completed run in Runs tab
2. [ ] **VERIFY**: "Next Steps" panel appears below State Summary panel
3. [ ] **VERIFY**: Panel shows:
   - Header with scenario badge (e.g., "telemetry_blocked", "findings_present")
   - Summary text explaining the situation
   - Action cards (3-7 cards based on scenario)
4. [ ] **VERIFY**: Panel border color matches severity:
   - `high` → red border
   - `medium` → orange border
   - `low` → blue border
   - `info` → green border

**Scenario: Telemetry Blocked:**
1. [ ] Run without Administrator and without Sysmon
2. [ ] **VERIFY**: Scenario is "telemetry_blocked" or "limited"
3. [ ] **VERIFY**: Actions include:
   - "Restart as Administrator" (requires: admin)
   - "Install Sysmon" (requires: sysmon)
   - "View Detection Plan" (deep link to Mission tab)
4. [ ] **VERIFY**: Requirements badges show 🔐 Admin and 📊 Sysmon

**Scenario: No Findings but Near-Miss:**
1. [ ] Complete a run with facts but partial playbook matches
2. [ ] **VERIFY**: Scenario is "near_miss"
3. [ ] **VERIFY**: Actions include:
   - "Inspect Near-Miss: [playbook name]" with playbook deep link
   - Completion percentage and missing slots count shown in rationale
4. [ ] Click the inspect action
5. [ ] **VERIFY**: Deep link navigates to Playbooks tab
6. [ ] **VERIFY**: (If playbook drawer supported) Opens playbook detail

**Scenario: Findings Present:**
1. [ ] Complete a run that produces signals
2. [ ] **VERIFY**: Scenario is "findings_present"
3. [ ] **VERIFY**: Actions include:
   - "Review Top Finding" with Explain tab deep link
   - "Export Evidence Bundle" with Export deep link
4. [ ] Click "Review Top Finding"
5. [ ] **VERIFY**: Navigates to Explain tab with signal selected

**Deep Link Navigation:**
1. [ ] Click each action card with a deep_link
2. [ ] **VERIFY**: Navigation works:
   - Mission tab actions → switches to Mission tab
   - Facts tab actions → switches to Facts tab within run detail
   - Playbooks tab actions → switches to Playbooks tab
   - Explain actions → switches to Explain tab
   - Export actions → switches to Import/Export tab

**Post-Stop Teaser:**
1. [ ] Start and stop a run
2. [ ] **VERIFY**: Teaser notification appears (bottom-right corner)
3. [ ] **VERIFY**: Teaser shows:
   - "✓ Run Completed" header
   - Summary text from next_steps
   - "View Next Steps →" button
4. [ ] Click "View Next Steps"
5. [ ] **VERIFY**: Scrolls to Next Steps panel in run detail
6. [ ] **VERIFY**: Teaser auto-dismisses after ~15 seconds

**Truth Verification:**
- [ ] **VERIFY**: All rationale text cites observed data (e.g., "2 issue(s) detected", "42% complete")
- [ ] **VERIFY**: No invented/guessed recommendations
- [ ] **VERIFY**: Actions are deterministic based on scenario rules

### A14e. Evidence Dereference (GET /api/evidence/deref)
Tests the evidence viewer drawer that shows exact source telemetry records from evidence pointers.

**Endpoint Verification:**
1. [ ] Complete a run that produces signals
2. [ ] Get the signal explanation: `GET /api/signals/{signal_id}/explain?run_id={run_id}`
3. [ ] Note an evidence_ptr from the response (segment_record kind)
4. [ ] Open DevTools → Network
5. [ ] Call: `GET /api/evidence/deref?run_id={run_id}&stream_id={stream_id}&segment_id=evtx_000000.jsonl&record_index={record_index}`
6. [ ] **VERIFY**: Response has:
   - `available: true`
   - `evidence_ptr`: echoes the request parameters
   - `resolved.segment_path`: full path to segment file
   - `resolved.segment_sha256`: hash of segment file
   - `resolved.line_bytes`: size of the record
   - `resolved.json`: parsed JSON object of the record
   - `resolved.ts_ms`: timestamp if present in record
   - `resolved.preview`: first 200 chars of raw line

**UI Evidence Viewer Drawer:**
1. [ ] Select a run with signals
2. [ ] Go to Explain tab
3. [ ] **VERIFY**: Evidence Pointers section shows clickable pointer items (segment_record kind)
4. [ ] **VERIFY**: Non-dereferenceable pointers (missing fields or other kinds) show plain text
5. [ ] Click a dereferenceable evidence pointer
6. [ ] **VERIFY**: Evidence Viewer drawer slides in from right:
   - Header shows "Evidence Viewer" with pointer reference
   - Metadata section shows: Timestamp, Size (bytes)
   - Segment Info shows: full path and SHA-256 prefix
   - Content section shows: pretty-printed JSON
7. [ ] **VERIFY**: Close button is focusable (keyboard accessibility)
8. [ ] **VERIFY**: Pressing Escape closes the drawer
9. [ ] **VERIFY**: "Copy JSON" button copies formatted JSON to clipboard
10. [ ] **VERIFY**: "Download" button downloads a properly named .json file
11. [ ] Click close button (✕)
12. [ ] **VERIFY**: Drawer slides out cleanly

**Path Traversal Security (Hardened):**
1. [ ] Attempt deref with path traversal in segment_id: `GET /api/evidence/deref?run_id=...&segment_id=../../../etc/passwd`
2. [ ] **VERIFY**: Response has:
   - `available: false`
   - `reason_code: "PATH_TRAVERSAL_BLOCKED"`
   - Message: "Invalid segment_id: must match ^[A-Za-z0-9._-]+\\.jsonl$"
3. [ ] Attempt with backslashes: `segment_id=..\\..\\evil.txt`
4. [ ] **VERIFY**: Same PATH_TRAVERSAL_BLOCKED response
5. [ ] Attempt without .jsonl extension: `segment_id=evtx_000000`
6. [ ] **VERIFY**: PATH_TRAVERSAL_BLOCKED (extension required)

**Scan Guardrails:**
1. [ ] Attempt deref with record_index > 10,000,000: `record_index=99999999`
2. [ ] **VERIFY**: Response has:
   - `available: false`
   - `reason_code: "SCAN_LIMIT_EXCEEDED"`
   - Message mentions "exceeds maximum allowed"
3. [ ] **VERIFY**: UI guidance shows "Record is too deep in the file..."

**Index Out of Range:**
1. [ ] Attempt deref with record_index beyond file lines but < 10M
2. [ ] **VERIFY**: Response has:
   - `available: false`
   - `reason_code: "RECORD_INDEX_OUT_OF_RANGE"`
   - Message shows actual line count

**Run Not Found:**
1. [ ] Attempt deref with invalid run_id
2. [ ] **VERIFY**: Response has:
   - `available: false`
   - `reason_code: "RUN_NOT_FOUND"`

**Imported Bundle Missing Segments:**
1. [ ] Import a bundle that does NOT include segments
2. [ ] Select the imported run, go to Explain tab
3. [ ] Click an evidence pointer
4. [ ] **VERIFY**: Drawer shows:
   - Unavailable state
   - `reason_code: "IMPORTED_BUNDLE_MISSING_SEGMENTS"`
   - Guidance about re-importing with segments

**UI Unavailable State:**
1. [ ] Trigger any unavailable reason (run_not_found, segment_not_found, etc.)
2. [ ] **VERIFY**: Evidence Viewer drawer shows:
   - Warning icon (⚠️)
   - "Evidence Not Available" header
   - Reason code in styled box
   - Detail message
   - Guidance tip (if available for the reason code)

**XSS Safety:**
1. [ ] **VERIFY**: All user-supplied values in drawer are HTML-escaped
2. [ ] **VERIFY**: JSON content is safely stringified then escaped
3. [ ] **VERIFY**: Error messages are escaped via `escapeHtml()`

### A15. Post-Run UI Never Blank Invariant
- [ ] Complete a run with 0 signals
- [ ] Click on the run in Runs tab
- [ ] **VERIFY**: At least one of the following shows meaningful content:
  - System State Summary panel
  - Facts tab (with No Telemetry explanation OR fact type breakdown)
  - Playbooks tab (with near-misses OR "why no matches" explanation)
- [ ] **VERIFY**: No panel shows blank/empty state without explanation

### A16. Telemetry → Playbook Causality (Part D)
- [ ] Complete a run without Sysmon installed
- [ ] Go to Playbooks tab
- [ ] **VERIFY**: Playbooks requiring Sysmon show `telemetry_blocked: true`
- [ ] **VERIFY**: Banner explains why playbooks couldn't evaluate
- [ ] **IF** Security log was inaccessible:
  - [ ] **VERIFY**: Playbooks requiring Security events show `telemetry_blocked: true`

### A17. API Contract Verification (GET /api/meta/contract)
- [ ] Open DevTools → Network
- [ ] Fetch `GET /api/meta/contract`
- [ ] **VERIFY**: Response includes:
  - `contract_version`: "1.0.0"
  - `contract_hash`: "v1-core-202601"
  - `list_convention`: "named_array"
  - `core_endpoints`: object with required keys per endpoint
- [ ] **VERIFY**: List endpoints match contract:
  - `GET /api/runs` → `data.runs` array
  - `GET /api/signals` → `data.signals` array
- [ ] **VERIFY**: ExplainResponse matches contract:
  - Always has: `available`, `signal`, `source`, `evidence_ptrs`, `evidence_ptrs_count`
  - When `available=false`: has `reason_code`, `message`

### A18. Wiring Check - Contract Validation
- [ ] Open Settings tab
- [ ] Click "Run Wiring Check" (if present) OR open DevTools console
- [ ] For each UI_ACTION with `expects.requiredKeys`:
  - [ ] **VERIFY**: Response contains all required keys
  - [ ] **VERIFY**: `dataPath` field (if specified) contains expected array

### A19. Explainability Stats Endpoint (GET /api/signals/explainability_stats)
- [ ] Complete a run that produces signals
- [ ] Open DevTools → Network
- [ ] Fetch `GET /api/signals/explainability_stats?run_id=X`
- [ ] **VERIFY**: `run_id` parameter is REQUIRED (returns error without it)
- [ ] **VERIFY**: Response includes:
  - `run_id`: the queried run
  - `total_signals`: count of all signals
  - `explanations_available`: count with available=true
  - `explanations_unavailable`: count with available=false
  - `unavailable_by_reason`: object with counts per reason_code
  - `structural_invariant.every_signal_has_explanation_row`: boolean
  - `structural_invariant.missing_rows`: count (should be 0)
- [ ] **VERIFY**: `explanations_available + explanations_unavailable = total_signals`

### A19a. Structural Invariant: Every Signal Has Explanation Row
- [ ] After any run with signals:
  - [ ] **INVARIANT**: `structural_invariant.every_signal_has_explanation_row = true`
  - [ ] **INVARIANT**: `structural_invariant.missing_rows = 0`
  - [ ] **VERIFY**: If invariant fails, investigate locald explanation write path

### A19b. Known-Fire Validation: Encoded PowerShell
- [ ] Run PowerShell with encoded command (e.g., `powershell -enc <base64>`)
- [ ] Complete run, go to Findings tab
- [ ] Find the `encoded_powershell` signal (if Sysmon captured it)
- [ ] Click **Explain** tab
- [ ] **VERIFY**: `available = true` (NOT a stub)
- [ ] **VERIFY**: `explanation.slots` array is populated
- [ ] **VERIFY**: `matched_slots` shows filled slot count
- [ ] **IF** `available = false`: investigate `reason_code` in stats endpoint

---

## Section B: Failure Tests

### B1. Backend Offline
- [ ] Stop server (Ctrl+C)
- [ ] Refresh UI
- [ ] **VERIFY**: Server badge shows **OFFLINE** (red)
- [ ] **VERIFY**: Error banner shows: "Backend offline"
- [ ] **VERIFY**: Start Run button fails (no state change)
- [ ] **VERIFY**: Counters show **—** (not "0")

### B2. Missing Binaries
- [ ] Rename `edr-locald.exe` temporarily
- [ ] Start server, click "Start Run"
- [ ] **VERIFY**: Error shows missing binary
- [ ] **VERIFY**: "Copy build commands" button appears

### B3. Export While Running
- [ ] Start a run
- [ ] Try to export bundle
- [ ] **VERIFY**: `{success: false, error: "Stop run before export", code: "RUN_ACTIVE"}`
- [ ] **VERIFY**: UI shows error message

---

## Section C: Feature Flag Tests

### C1. Features Endpoint (GET /api/features)
- [ ] Open DevTools → Network → filter "features"
- [ ] **VERIFY**: `GET /api/features` returns:
  - `core: true` (always)
  - `diff: false` (default build)
  - `narrative: false` (default build)
  - `playbook_debug: false` (default build)

### C2. Non-Core Tabs Hidden
- [ ] Go to Runs tab, select a run
- [ ] **VERIFY**: These tabs are **HIDDEN** by default:
  - Changes (requires `diff` feature)
  - Playbooks (requires `playbook_debug` feature)
  - Timeline (requires `timeline` feature)
- [ ] **VERIFY**: These tabs are **VISIBLE**:
  - Overview
  - Findings
  - Facts
  - Explain
  - Raw JSON

---

## Section D: Database Integrity

### D1. Signals in DB
- [ ] Run a capture for 30+ seconds
- [ ] Stop the run
- [ ] Open `workbench.db` with SQLite viewer
- [ ] **VERIFY**: `signals` table has rows
- [ ] **VERIFY**: Each signal has:
  - `id` (TEXT PRIMARY KEY)
  - `signal_type`
  - `severity`
  - `ts_ms`
  - `json_blob` (full signal data)

### D2. Coverage in DB
- [ ] **VERIFY**: `coverage_rollup` table has rows
- [ ] **VERIFY**: Each row has:
  - `technique_id` (MITRE ATT&CK ID)
  - `signal_count`

---

## Section E: UI Wiring Audit (Ship-Grade Truth Gate)

**Purpose**: Verify all UI buttons are properly wired to backend API endpoints WITHOUT starting a run or spawning binaries. This is a ship-grade truth gate that blocks release if required actions are broken.

### Tier Classification

| Tier | Badge | Description |
|------|-------|-------------|
| 🔷 Core | `required: true` | Essential functionality — ship blockers if broken |
| 💎 Pro | `required: false` | Advanced features — nice-to-have |
| 👥 Team | `required: false` | Collaboration features |
| 🔧 Dev | `required: false` | Debugging/meta endpoints |

**Ship Blocker Rule**: `tier: core` + `required: true` + `status: broken` = **CANNOT SHIP**

### E1. Run Wiring Check
- [ ] Go to **Settings** tab
- [ ] Scroll to **UI Wiring Audit** section
- [ ] Click **🔌 Wiring Check** button
- [ ] **VERIFY**: Button shows "⏳ Checking..." during audit
- [ ] **VERIFY**: Results panel appears with summary counts

### E2. Verify Summary Counts
- [ ] **VERIFY**: Summary shows:
  - ✅ OK: Number of properly wired actions
  - ❌ Broken: 0 (should be zero if all wiring correct)
  - ⏸️ Not Executed: Mutating endpoints (run/start, run/stop, export)
  - ⚠️ Capability Missing: Missing binaries, blocked features
- [ ] **VERIFY**: Tier summary shows counts by tier (Core: N, Pro: N, Team: N, Dev: N)
- [ ] **VERIFY**: Timestamp shows when check was performed

### E3. Ship Blockers Banner
- [ ] **VERIFY**: If any `required: true` action is broken, red banner appears:
  ```
  🚫 SHIP BLOCKERS: N
  These required actions are broken and must be fixed before shipping:
  • Action Label [tier]: reason
  ```
- [ ] **VERIFY**: If no blockers, banner does not appear

### E4. No Run Started
- [ ] **VERIFY**: Status badge still shows "Stopped" (no run started)
- [ ] **VERIFY**: Network tab shows NO `POST /api/run/start` call
- [ ] **VERIFY**: Network tab shows NO `POST /api/run/stop` call
- [ ] **VERIFY**: Segments/Facts/Signals counters unchanged

### E5. Route Inventory (GET /api/meta/routes)
- [ ] Open DevTools → Network → filter "meta/routes"
- [ ] **VERIFY**: `GET /api/meta/routes` returns:
  ```json
  {
    "success": true,
    "data": [
      {"method": "GET", "path": "/api/health", "description": "...", "mutates": false},
      {"method": "POST", "path": "/api/run/start", "description": "...", "mutates": true},
      ...
    ]
  }
  ```
- [ ] **VERIFY**: Each route has `method`, `path`, `description`, `mutates`

### E6. API Contract (GET /api/meta/contract)
- [ ] Filter "meta/contract"
- [ ] **VERIFY**: `GET /api/meta/contract` returns wrapper specification
- [ ] **VERIFY**: Wrapper contract enforced:
  - `success` must be boolean
  - If `success: true`: must have `data` key
  - If `success: false`: must have `error` (string) and `code` (string)

### E7. Status Classifications
Review results panel for correct status classification:

| Status | Meaning | Examples |
|--------|---------|----------|
| ✅ OK | Endpoint exists, responds correctly | /api/health, /api/runs |
| ❌ Broken | Missing route, wrong method, HTML response, invalid wrapper | - |
| ⏸️ Not Executed | Safe to not call during audit | /api/run/start, /api/run/stop |
| ⚠️ Capability Missing | Route exists but dependency missing | Missing binaries (412) |

### E8. Not Executed Shows Route Status
For `⏸️ Not Executed` items (mutating endpoints):
- [ ] **VERIFY**: Each shows either:
  - `✅ route exists` — route registered, safe to call manually
  - `❌ route missing` — route NOT registered, needs fix

### E9. Content-Type and HTML Detection
If an endpoint returns HTML (404 page, misconfigured route):
- [ ] **VERIFY**: Status shows `❌ Broken`
- [ ] **VERIFY**: Reason shows "Response is HTML (likely 404 page or misconfigured route)"
- [ ] **VERIFY**: HTML preview shows first 100 chars of response
- [ ] **VERIFY**: Content-Type validation enforces `application/json` for JSON endpoints

### E10. Export Audit Report
- [ ] Click **📋 Copy JSON** button
- [ ] **VERIFY**: "✓ Copied!" confirmation appears
- [ ] Paste in text editor
- [ ] **VERIFY**: JSON contains:
  ```json
  {
    "_meta": {"exportedAt": "...", "buildStamp": "...", "userAgent": "...", "baseUrl": "..."},
    "timestamp": "...",
    "summary": {"ok": N, "broken": N, ...},
    "tierSummary": {"core": N, "pro": N, ...},
    "shipBlockers": [...],
    "routeInventoryHash": N,
    "actions": [...]
  }
  ```
- [ ] Click **💾 Download** button
- [ ] **VERIFY**: `wiring-check-YYYY-MM-DD.json` file downloads
- [ ] **VERIFY**: Downloaded file matches clipboard content

### E11. Broken Wiring Detection
If any action shows ❌ Broken:
- [ ] **VERIFY**: Tier badge shown (🔷/💎/👥/🔧)
- [ ] **VERIFY**: REQUIRED label shown if `required: true`
- [ ] **VERIFY**: Reason is shown (e.g., "Endpoint not registered")
- [ ] **VERIFY**: Suggestion is shown (e.g., "Add route to build_locint_router()")
- [ ] **VERIFY**: Fix by adding missing route or correcting handler

---

## Section F: RD Fixes Verification (FINISH LINE)

**Purpose**: Verify all Reliability Defect fixes (RD-1 through RD-5) are working correctly.
See [RD_FIXES_SUMMARY.md](RD_FIXES_SUMMARY.md) for full details.

### F1. RD-1: DB-Backed Metrics (No Estimates)
- [ ] Start a run, wait 10+ seconds
- [ ] Open DevTools → Network → filter "metrics"
- [ ] **VERIFY**: `GET /api/run/metrics` returns DB-queried values
- [ ] **VERIFY**: `events_total` comes from DB, NOT bytes/500 estimate
- [ ] **VERIFY**: `facts_extracted` comes from DB (SUM from coverage_rollup)
- [ ] **VERIFY**: If DB unavailable, values show `null` (not 0)

### F2. RD-2: Signal Counts Persist After Stop
- [ ] Start a run, wait 30+ seconds for signals to fire
- [ ] Stop the run
- [ ] **VERIFY**: `/api/runs` shows correct `signal_count` for the run
- [ ] **VERIFY**: `run_meta.json` has `signals_fired` field populated
- [ ] **VERIFY**: `run_meta.json` has `finalized: true`

### F3. RD-3: Playbooks Error Response
- [ ] Start server without playbooks directory
- [ ] Filter network for "playbooks"
- [ ] **VERIFY**: `GET /api/runs/:id/playbooks` returns:
  ```json
  {
    "success": true,
    "data": {
      "available": false,
      "reason_code": "PLAYBOOKS_NOT_FOUND",
      "message": "...",
      "searched_paths": [...]
    }
  }
  ```
- [ ] **VERIFY**: Response is NOT a network error (5xx or timeout)
- [ ] **VERIFY**: UI shows appropriate "Playbooks not configured" message

### F4. RD-4: Export Blocked While Running/Finalizing
- [ ] Start a run
- [ ] Try to export: `POST /api/export/bundle`
- [ ] **VERIFY**: Returns 409 with `code: "RUN_ACTIVE"`
- [ ] Stop the run (wait for finalizing phase to complete)
- [ ] **VERIFY**: `/api/run/status` shows phase != "finalizing"
- [ ] Try export again
- [ ] **VERIFY**: Export succeeds when phase is "idle" or "completed"

### F5. RD-5: Finalize Pipeline Phases
- [ ] Start a run
- [ ] Stop the run
- [ ] Watch `/api/run/status` responses during stop:
- [ ] **VERIFY**: Phase transitions: running → draining_locald → finalizing → completed
- [ ] **VERIFY**: `run_meta.json` written AFTER phase reaches "completed"
- [ ] **VERIFY**: `finalized: true` in run_meta.json

### F6. Response Wrapper Consistency
- [ ] Check the following endpoints for consistent wrapper:
- [ ] **VERIFY**: `/api/runs/:id/coverage` returns `{success: true, data: {...}}`
- [ ] **VERIFY**: `/api/runs/:id/changes` returns `{success: true, data: {...}}`
- [ ] **VERIFY**: `/api/signals` returns `{success: true, data: {signals: [...]}}`
- [ ] **VERIFY**: `/api/selfcheck` returns `{success: true, data: {...}}`
- [ ] **VERIFY**: Error responses return `{success: false, error: "...", code: "..."}`

---

## Section G: Capability Model Verification

**Purpose**: Verify the Capability Model provides truthful, always-on visibility into sensor status and detection coverage. This surfaces "what detection is possible" at all times.

### G1. Capability Status (GET /api/capability/status)
- [ ] Open DevTools → Network → filter "capability"
- [ ] Go to **Settings** tab
- [ ] **VERIFY**: `GET /api/capability/status` returns:
  - `overall_status`: "full" | "partial" | "limited" | "blocked"
  - `is_admin`: boolean
  - `sensors`: array of sensor check results
  - `fact_types_possible`: array of fact types available
  - `attack_surfaces`: coverage per surface (process, auth, persistence, etc.)
  - `guidance`: actionable recommendations

### G2. Sensor Status Truth
- [ ] For each sensor in `sensors` array:
  - `status: "active"` → sensor is working, `capabilities` populated
  - `status: "blocked"` → must have `reason_code` and `message`
  - `status: "missing"` → must have `reason_code` and `message`
- [ ] **VERIFY**: If NOT running as Admin:
  - Security log sensor shows `status: "blocked"` 
  - `reason_code: "REQUIRES_ADMIN"`
- [ ] **VERIFY**: If Sysmon NOT installed:
  - Sysmon sensor shows `status: "missing"`
  - `reason_code: "NOT_INSTALLED"`

### G3. Attack Surface Coverage Truth
- [ ] For each surface in `attack_surfaces`:
  - `status: "covered"` → has `active_sensors` populated, `missing_sensors` empty
  - `status: "partial"` → has both active and missing sensors
  - `status: "blocked"` → no active sensors, has `blocked_reason`
- [ ] **VERIFY**: `auth` surface is blocked when Security log blocked
- [ ] **VERIFY**: `process` surface shows partial/covered based on Sysmon status

### G4. Detection Plan (GET /api/capability/detection_plan)
- [ ] **VERIFY**: `GET /api/capability/detection_plan` returns:
  - `capability`: same shape as /api/capability/status
  - `playbooks.total`: total playbook count
  - `playbooks.enabled`: array of enabled playbooks
  - `playbooks.blocked_by_telemetry`: playbooks blocked by missing sensors
  - `playbooks.disabled_by_config`: playbooks with `enabled: false` in YAML
  - `playbooks.skipped_invalid`: playbooks that failed to parse
  - `coverage_by_surface`: which enabled playbooks cover which surfaces

### G5. Playbook Derived Status Truth
For each playbook:
- [ ] **VERIFY**: `derived_status: "enabled"` ONLY IF:
  - YAML has `enabled: true` (or omitted, defaults to true)
  - AND all required sensors are active
- [ ] **VERIFY**: `derived_status: "blocked_by_telemetry"` shows:
  - `blocked_by`: list of sensor IDs blocking it
  - `reasons`: human-readable explanations
- [ ] **VERIFY**: Never claims a playbook is enabled when sensors are missing

### G6. Run Capability Snapshot
- [ ] Start a run, then stop it
- [ ] Check run_meta.json in run directory
- [ ] **VERIFY**: `readiness_snapshot.capability_snapshot` contains:
  - `overall_status`
  - `sensors` array with status at run start
  - `fact_types_possible`
  - `attack_surface_coverage`
  - `captured_at` timestamp

### G7. Coverage Truth Gate
The capability model passes if:
- [ ] Sensors never show `status: "active"` when actually blocked/missing
- [ ] Attack surfaces never show `status: "covered"` when sensors are missing
- [ ] Playbooks never show `derived_status: "enabled"` when telemetry requirements not met
- [ ] Every blocked state has `reason_code` and `message`

---

## Section H: Status Semantics Consistency

This section verifies that status badges (Configured/Active/Blocked/Missing/Disabled) are consistently displayed across all UI surfaces.

### Status Semantics Contract

| Status | Meaning | Icon | Color | When Used |
|--------|---------|------|-------|-----------|
| **Active** | Facts/events observed in THIS run | ✅ | Green | Run context only, after facts observed |
| **Configured** | Accessible but no events observed yet | ⚙️ | Gray/Blue | Live capability checks, before run |
| **Missing** | Not installed/present | ⛔ | Red | Static checks, install required |
| **Blocked** | Present but inaccessible | 🔒 | Amber | Permission/policy issue |
| **Disabled** | Explicitly disabled by config | 🚫 | Gray | User/admin disabled |

### H1. Detection Plan (Settings Tab)

- [ ] Load Detection Plan in Settings → Detection Plan
- [ ] **VERIFY**: Overall badge shows "configured" status (NOT green "live")
- [ ] **VERIFY**: Summary text mentions "will evaluate when facts are available"
- [ ] **VERIFY**: Each enabled playbook shows gray "ENABLED" badge (NOT green)
- [ ] **VERIFY**: Enabled playbooks show note "Will evaluate when matching facts are observed"
- [ ] **VERIFY**: Blocked playbooks show amber "BLOCKED" badge with 🔒 icon
- [ ] **VERIFY**: Block reasons displayed below blocked playbooks

### H2. State Panel (Run Detail)

- [ ] Select a completed run in Runs tab
- [ ] **VERIFY**: Telemetry badge uses semantic colors:
  - Full/Partial → "configured" (gray-blue)
  - Blocked → "blocked" (amber)
- [ ] **VERIFY**: Sensor badges use consistent semantics:
  - Available sensors → "configured" badge
  - Unavailable sensors → "blocked" or "missing" badge

### H3. Facts Tab (Run Detail)

- [ ] Select a run with observed facts in Facts tab
- [ ] **VERIFY**: Sensors with observed facts show **green "Active (observed)"** badge
- [ ] **VERIFY**: Sensors without facts show **gray "Configured"** badge
- [ ] **VERIFY**: Capability tags use consistent `badge--configured` styling
- [ ] **VERIFY**: "No hosts recorded" uses configured badge (not error)

### H4. Capability Model (API Verification)

- [ ] Open DevTools → Network
- [ ] Call `GET /api/capability/status`
- [ ] **VERIFY**: Sensor status values are one of: `active`, `configured`, `missing`, `blocked`
- [ ] **VERIFY**: Each sensor has `status_label` field
- [ ] **VERIFY**: Attack surfaces use `configured_sensors` (not `active_sensors`)
- [ ] **VERIFY**: Attack surface status values: `configured`, `partial`, `blocked`

### H5. Negative Tests

- [ ] **VERIFY**: Green "active" badge NEVER appears in Detection Plan (pre-run context)
- [ ] **VERIFY**: "Configured" label NEVER claims events have been observed
- [ ] **VERIFY**: Blocked status ALWAYS shows reason when available
- [ ] **VERIFY**: Missing/blocked icons distinguish permission issues (🔒) from install issues (⛔)

---

## Section I: Pro/Team Foundation (v1.1) - Hardened

### I1. Baseline System (POST /api/runs/:id/baseline)

- [ ] Select a completed run
- [ ] Open DevTools → Network
- [ ] POST to `/api/runs/{run_id}/baseline` with body:
  ```json
  {"scope": "host", "description": "Test baseline", "set_as_default": true}
  ```
- [ ] **VERIFY**: Response has `success: true`
- [ ] **VERIFY**: `data.run_id` matches the run
- [ ] **VERIFY**: `data.scope` is "host"
- [ ] **VERIFY**: `data.is_default` is true
- [ ] **VERIFY**: `data.metrics_snapshot` contains event/fact counts
- [ ] **VERIFY (SQLite persistence)**: Open `workbench_master.db` with sqlite3:
  ```sql
  SELECT run_id, baseline_scope, baseline_enabled, baseline_set_at FROM runs WHERE baseline_enabled=1;
  ```
  - Baseline run should have `baseline_enabled=1`, `baseline_scope='host'`, `baseline_set_at` set
- [ ] **VERIFY (Single default per scope)**: Mark second run as host baseline with `set_as_default: true`
  - Previous baseline should have `is_default: false` in response
  - SQLite should only show ONE baseline with scope='host' and is_default

### I2. List Baselines (GET /api/baselines)

- [ ] After marking a baseline, call `GET /api/baselines`
- [ ] **VERIFY**: Response has `success: true`
- [ ] **VERIFY**: `data.baselines` is an array containing the marked baseline
- [ ] **VERIFY**: `data.defaults.host` matches the baseline run_id
- [ ] **VERIFY**: `data.count` matches the array length
- [ ] **VERIFY (SQLite-backed)**: Response reflects data from SQLite, not just JSON files

### I3. Case Summary Export (GET /api/runs/:id/case_summary) - Hardened

- [ ] Select a completed run with signals
- [ ] Call `GET /api/runs/{run_id}/case_summary`
- [ ] **VERIFY**: Response has `success: true`
- [ ] **VERIFY (Contract metadata)**:
  - `data.contract_version` is "1.1.0"
  - `data.contract_hash` is "v1-case-202601"
  - `data.schema_version` is "1.0.0"
- [ ] **VERIFY (Capability snapshot)**:
  - `data.capability_snapshot` contains `is_admin`, `sysmon_installed`, `security_log_accessible`
  - `data.capability_snapshot.overall_status` is one of: "full", "partial", "limited", "blocked"
  - `data.capability_snapshot.enabled_sensors` is an array
  - `data.capability_snapshot.fact_types_observed` is an array
- [ ] **VERIFY (Telemetry caveats)**:
  - `data.telemetry_caveats` is an array
  - If Sysmon was missing, caveats include warning about Process detections
  - If Security log was blocked, caveats include warning about Auth detections
- [ ] **VERIFY (Evidence availability)**:
  - `data.evidence_availability.segments_present` is boolean
  - `data.evidence_availability.segments_count` is integer >= 0
  - `data.evidence_availability.total_findings` matches signal count
  - `data.evidence_availability.findings_with_evidence` is integer >= 0
  - `data.evidence_availability.availability_rate` is 0.0-1.0
- [ ] **VERIFY**: `data.run_story` is a non-empty string
- [ ] **VERIFY**: `data.next_steps` is an array of action items
- [ ] **VERIFY**: `data.summary` contains run statistics
- [ ] **VERIFY (Evidence flag on findings)**:
  - Each item in `data.top_findings` has `evidence_available` boolean

### I4. Import Validation (POST /api/import/validate) - Hardened

- [ ] Export a run to ZIP bundle first
- [ ] POST the bundle to `/api/import/validate` as multipart form
- [ ] **VERIFY**: Response has `success: true`
- [ ] **VERIFY**: `data.available` is true for valid bundle
- [ ] **VERIFY**: `data.found_artifacts` contains expected files
- [ ] **VERIFY**: `data.schema_version` is extracted from bundle
- [ ] **VERIFY (Capability flags)**:
  - `data.can_compile` is boolean
  - `data.can_diff` is boolean
  - `data.can_case_summary` is boolean
  - `data.evidence_deref_available` is boolean

### I5. Import Validation (Precise Reason Codes)

- [ ] **Test NO_FILE_UPLOADED**: POST empty form to `/api/import/validate`
  - **VERIFY**: `data.reason_code` is "NO_FILE_UPLOADED"
- [ ] **Test INVALID_ZIP**: POST a text file as "file"
  - **VERIFY**: `data.reason_code` is "INVALID_ZIP"
- [ ] **Test MISSING_RUN_META**: Create ZIP without run_meta.json
  - **VERIFY**: `data.reason_code` is "MISSING_RUN_META"
- [ ] **Test SCHEMA_UNSUPPORTED**: Create run_meta.json with `schema_version: "99.0.0"`
  - **VERIFY**: `data.reason_code` is "SCHEMA_UNSUPPORTED"
  - **VERIFY**: `data.suggested_fix` mentions supported versions
- [ ] **Test MISSING_DB_AND_SEGMENTS**: Create ZIP with only run_meta.json
  - **VERIFY**: `data.reason_code` is "MISSING_DB_AND_SEGMENTS"
  - **VERIFY**: `data.suggested_fix` mentions workbench.db OR segments
- [ ] **Test DB-only bundle**: ZIP with run_meta.json and workbench.db (no segments)
  - **VERIFY**: `data.available` is true
  - **VERIFY**: `data.can_diff` is true
  - **VERIFY**: `data.evidence_deref_available` is false
- [ ] **Test Segments-only bundle**: ZIP with run_meta.json and segments/ (no workbench.db)
  - **VERIFY**: `data.available` is true
  - **VERIFY**: `data.can_compile` is true
  - **VERIFY**: `data.can_diff` is false (until compiled)

### I6. Content Packs (GET /api/packs) - Hardened

- [ ] Call `GET /api/packs`
- [ ] **VERIFY**: Response has `success: true`
- [ ] **VERIFY**: `data.packs` contains at least the "builtin" pack
- [ ] **VERIFY (Schema version)**: Each pack has `schema_version` (e.g., "1.0.0")
- [ ] **VERIFY (Integrity)**: Each pack has `integrity` object:
  - `integrity.playbooks_hash` starts with "sha256:"
  - `integrity.validated` is boolean
  - `integrity.validation_errors` is array (empty for valid packs)
- [ ] **VERIFY (Rejected packs)**: `data.rejected_packs` is array
  - If custom packs directory has invalid packs, they appear here with reason
- [ ] **VERIFY (Tier gating)**: `data.tier_allows_custom` is boolean
  - Free tier: Should be false
  - Pro/Team: Should be true

### I7. Pack Details (GET /api/packs/:name) - Hardened

- [ ] Call `GET /api/packs/builtin`
- [ ] **VERIFY**: Response has `success: true`
- [ ] **VERIFY**: `data.name` is "builtin"
- [ ] **VERIFY**: `data.schema_version` is present
- [ ] **VERIFY (Per-file hashes)**: `data.playbooks` array has items with:
  - `filename`, `path`, and `hash` (sha256 per file)
- [ ] **VERIFY (Integrity)**: `data.integrity` object present

### I7a. Pack Tier Gating

- [ ] Set `LOCINT_TIER=free` environment variable
- [ ] Restart server
- [ ] Call `GET /api/packs/custom_pack` (if custom pack exists)
- [ ] **VERIFY**: Response is `{success: false, error: "...", code: "TIER_BLOCKED"}`
- [ ] Set `LOCINT_TIER=pro` environment variable
- [ ] Restart server
- [ ] **VERIFY**: Custom packs now accessible

### I8. Diff v2 with Baseline Filter

- [ ] Mark run A as baseline
- [ ] Create run B with some changes
- [ ] Call `GET /api/runs/{run_B}/diff?mode=baseline&baseline_run_id={run_A}&baseline_filter=true`
- [ ] **VERIFY**: Unchanged baseline keys are suppressed in response
- [ ] **VERIFY**: High-severity persistence changes remain visible

---

## Section J: Tier Enforcement Tests (v1.2)

### J1. Feature Flags Endpoint (GET /api/meta/features)

- [ ] Call `GET /api/meta/features`
- [ ] **VERIFY**: Response has `success: true`
- [ ] **VERIFY**: `data.tier` is one of "Free", "Pro", "Team", "Dev"
- [ ] **VERIFY**: `data.upgrade_url` is a valid URL
- [ ] **VERIFY**: `data.features` contains all expected flags:
  - Core (always true): `run_workflow`, `capability_model`, `playbook_system`, `signals_explain`, `evidence_deref`, `next_steps`, `import_export`, `wiring_audit`, `diff_phase`
  - Pro-gated: `baselines`, `diff_advanced`, `custom_packs`, `case_summary`
- [ ] **VERIFY**: `data.gating` maps Pro features to their endpoints

### J2. Free Tier Core Loop (No License)

- [ ] Ensure no `LOCINT_LICENSE_KEY` env var
- [ ] Delete any `license.json` in data directory
- [ ] Restart server
- [ ] **VERIFY (Free tier detected)**: `/api/meta/features` returns `tier: "Free"`
- [ ] **VERIFY (Core loop works)**:
  - `POST /api/run/start` → 200 OK
  - `POST /api/run/stop` → 200 OK
  - `GET /api/runs` → 200 OK
  - `GET /api/signals` → 200 OK
  - `GET /api/signals/:id/explain` → 200 OK
  - `GET /api/signals/:id/evidence` → 200 OK
  - `GET /api/runs/:id/playbooks` → 200 OK
  - `POST /api/import` → 200 OK
  - `POST /api/export` → 200 OK
  - `GET /api/runs/:id/diff` (phase mode) → 200 OK

### J3. Free Tier Pro Endpoints (403 FEATURE_LOCKED)

- [ ] With Free tier active, call Pro endpoints:
- [ ] **Test Baselines**:
  - `POST /api/runs/:id/baseline` with valid body
  - **VERIFY**: Response is HTTP 403
  - **VERIFY**: `code: "FEATURE_LOCKED"`
  - **VERIFY**: `required_tier: "Pro"`
  - **VERIFY**: `current_tier: "Free"`
  - **VERIFY**: `upgrade_url` is present
- [ ] **Test List Baselines**:
  - `GET /api/baselines`
  - **VERIFY**: Response is HTTP 403 with `code: "FEATURE_LOCKED"`
- [ ] **Test Case Summary**:
  - `GET /api/runs/:id/case_summary`
  - **VERIFY**: Response is HTTP 403 with `code: "FEATURE_LOCKED"`
- [ ] **Test Diff Advanced (baseline mode)**:
  - `GET /api/runs/:id/diff?mode=baseline&baseline_run_id=...`
  - **VERIFY**: Response is HTTP 403 with `code: "FEATURE_LOCKED"`
- [ ] **Test Diff Advanced (marker mode)**:
  - `GET /api/runs/:id/diff?mode=marker&marker_ts=...`
  - **VERIFY**: Response is HTTP 403 with `code: "FEATURE_LOCKED"`
- [ ] **Test Diff Advanced (baseline_filter)**:
  - `GET /api/runs/:id/diff?baseline_filter=true`
  - **VERIFY**: Response is HTTP 403 with `code: "FEATURE_LOCKED"`
- [ ] **Test Custom Packs**:
  - `GET /api/packs/my_custom_pack` (non-builtin pack)
  - **VERIFY**: Response is HTTP 403 with `code: "FEATURE_LOCKED"`

### J4. Pro Tier Unlock

- [ ] Set `LOCINT_LICENSE_KEY=LK-PRO-TEST-KEY` (or valid Pro key)
- [ ] Restart server
- [ ] **VERIFY (Pro tier detected)**: `/api/meta/features` returns `tier: "Pro"`
- [ ] **VERIFY (Pro features enabled)**:
  - `baselines: true`
  - `diff_advanced: true`
  - `custom_packs: true`
  - `case_summary: true`
- [ ] **VERIFY (Pro endpoints work)**:
  - `POST /api/runs/:id/baseline` → 200 OK
  - `GET /api/baselines` → 200 OK
  - `GET /api/runs/:id/case_summary` → 200 OK
  - `GET /api/runs/:id/diff?mode=baseline&baseline_run_id=...` → 200 OK
  - `GET /api/packs/custom_pack` → 200 OK (if custom pack exists)

### J5. UI Tier Lock Display

- [ ] With Free tier active, open UI
- [ ] **VERIFY**: Baseline buttons show 🔒 Pro lock icon
- [ ] **VERIFY**: Case Summary export button shows 🔒 Pro lock icon
- [ ] **VERIFY**: Diff mode selector disables baseline/marker options with Pro tag
- [ ] **VERIFY**: Baseline filter toggle disabled with Pro tag
- [ ] **VERIFY**: Custom Packs section shows "Pro required" notice
- [ ] **VERIFY**: Clicking locked feature shows upgrade modal with link

### J6. UI Feature Locked Error Handling

- [ ] With Free tier active, intercept network to allow locked button click
- [ ] Click a tier-locked action (e.g., mark baseline)
- [ ] **VERIFY**: 403 FEATURE_LOCKED error handled gracefully
- [ ] **VERIFY**: Upgrade modal shown with feature name
- [ ] **VERIFY**: Upgrade link points to correct URL

---

## Section K: Team Case Store Tests

These tests require Team tier. Skip if testing Free/Pro tier only.

### K1. Team Tab Visibility

- [ ] With Free tier, verify Team tab shows 🔒 icon
- [ ] Click Team tab with Free tier
- [ ] **VERIFY**: Tier lock banner is visible
- [ ] **VERIFY**: "Upgrade to Team" link is visible
- [ ] With Team tier, verify Team tab shows no lock icon
- [ ] Click Team tab with Team tier
- [ ] **VERIFY**: Team content is visible (not lock banner)

### K2. Store Status Check (GET /api/team/store/status)

- [ ] With Team tier, go to Team tab
- [ ] Open DevTools → Network → filter "team"
- [ ] **VERIFY**: `GET /api/team/store/status` called automatically
- [ ] **VERIFY**: Response has `configured`, `available`, `writable` fields
- [ ] **VERIFY**: Store status badge reflects actual status

### K3. Store Configuration (POST /api/team/store/configure)

- [ ] Click "Configure" button
- [ ] **VERIFY**: Configuration modal appears
- [ ] Enter a test path (e.g., `C:\temp\locint_test_store`)
- [ ] Click "Save & Connect"
- [ ] **VERIFY**: `POST /api/team/store/configure` called
- [ ] **VERIFY**: Store status updates after save
- [ ] **VERIFY**: Modal closes on success

### K4. Case Creation (POST /api/team/cases)

- [ ] With store configured, enter case title
- [ ] Add tags (comma-separated)
- [ ] Click "Create Case"
- [ ] **VERIFY**: `POST /api/team/cases` called
- [ ] **VERIFY**: Response contains `case_id`
- [ ] **VERIFY**: Case appears in case list
- [ ] **VERIFY**: Form clears after successful creation

### K5. Case List (GET /api/team/cases)

- [ ] After creating cases, verify case list populates
- [ ] **VERIFY**: Each case shows title, run count, notes count
- [ ] Use search box to filter cases
- [ ] **VERIFY**: Case list filters by search term
- [ ] Click a case to select it
- [ ] **VERIFY**: Case detail panel shows case info

### K6. Case Detail (GET /api/team/cases/:case_id)

- [ ] Select a case from the list
- [ ] **VERIFY**: `GET /api/team/cases/:case_id` called
- [ ] **VERIFY**: Case title, description, tags displayed
- [ ] **VERIFY**: Published runs section visible
- [ ] **VERIFY**: Notes section visible

### K7. Tag Management (POST /api/team/cases/:case_id/tags)

- [ ] With case selected, enter a new tag
- [ ] Click "Add" button
- [ ] **VERIFY**: `POST /api/team/cases/:case_id/tags` called
- [ ] **VERIFY**: Tag appears in case detail
- [ ] Click remove (×) on an existing tag
- [ ] **VERIFY**: Tag removed from display

### K8. Notes (POST /api/team/cases/:case_id/notes)

- [ ] With case selected, enter a note
- [ ] Click "Add Note" button
- [ ] **VERIFY**: `POST /api/team/cases/:case_id/notes` called
- [ ] **VERIFY**: Note appears in notes list
- [ ] **VERIFY**: Note shows author and timestamp

### K9. Publish Run (POST /api/team/cases/:case_id/runs)

- [ ] Complete a local run first (start, wait, stop)
- [ ] Select a case, click "Publish Run"
- [ ] **VERIFY**: Publish modal shows local runs
- [ ] Select a run and click "Publish"
- [ ] **VERIFY**: `POST /api/team/cases/:case_id/runs` called
- [ ] **VERIFY**: Run appears in case runs list
- [ ] **VERIFY**: Modal closes on success

### K10. Import Run (POST /api/team/cases/:case_id/runs/:run_id/import)

- [ ] With published run in case, click "Import" button
- [ ] **VERIFY**: `POST /api/team/cases/:case_id/runs/:run_id/import` called
- [ ] **VERIFY**: Success message displayed
- [ ] Go to Runs tab
- [ ] **VERIFY**: Imported run appears in local run list

### K11. Team Tier Gate Enforcement

- [ ] With Free tier, attempt to call Team endpoints via DevTools
- [ ] **VERIFY**: All `/api/team/*` endpoints return 403
- [ ] **VERIFY**: Error has `code: "FEATURE_LOCKED"`
- [ ] **VERIFY**: Error has `required_tier: "Team"`

### K12. Publish Atomicity Test (SMB Safety)

- [ ] Configure store to an SMB/network path (e.g., `\\server\share`)
- [ ] Start a long publish (large run with many segments)
- [ ] While publishing, check the `runs/` directory on the share
- [ ] **VERIFY**: Only `.zip.tmp` file exists during publish (no partial `.zip`)
- [ ] Wait for publish to complete
- [ ] **VERIFY**: `.zip.tmp` is gone, `.zip` file exists
- [ ] **VERIFY**: Response includes `sha256` hash
- [ ] **VERIFY**: Case.json `runs[]` entry includes `sha256` and `publisher_host`

### K13. Lock Contention Test (Double-Writer Prevention)

- [ ] Configure store to a shared path
- [ ] Open UI in two separate browsers/windows
- [ ] Both: Navigate to same case
- [ ] Instance 1: Click "Update Tags" (or any locking operation)
- [ ] Instance 2: Immediately try same operation
- [ ] **VERIFY**: Instance 2 gets `CASE_LOCKED` error with HTTP 409
- [ ] **VERIFY**: Error shows `lock_owner.host_name` (who holds lock)
- [ ] **VERIFY**: Instance 2's operation is blocked (no partial write)

### K14. Stale Lock Recovery Test

- [ ] Start a tag update or publish operation
- [ ] Kill the process mid-operation (Task Manager → End Task)
- [ ] Wait 5+ minutes (lock timeout)
- [ ] Start fresh locint instance
- [ ] Try the same operation again
- [ ] **VERIFY**: Operation succeeds (stale lock was cleaned up)
- [ ] **VERIFY**: No user intervention required

### K15. Provenance Attribution Test

- [ ] Publish a run to a case
- [ ] Add a note to the case
- [ ] Check `case.json` on the store
- [ ] **VERIFY**: Run entry has `published_by`, `publisher_host` fields
- [ ] Check `notes.jsonl` on the store
- [ ] **VERIFY**: Note entry has `install_id`, `host_name`, `user_hint` fields
- [ ] **VERIFY**: UI displays attribution info (who/where)

### K16. Unreadable Case Handling Test

- [ ] On the store, manually corrupt a `case.json` (invalid JSON)
- [ ] Refresh the case list in UI
- [ ] **VERIFY**: Corrupt case shows "(unreadable)" title
- [ ] **VERIFY**: Corrupt case has `status: "unreadable"` in response
- [ ] **VERIFY**: Other valid cases are still listed
- [ ] **VERIFY**: Response includes `unreadable_count` field

### K17. SMB Disconnect Resilience Test

- [ ] Configure store to an SMB path
- [ ] Start a publish operation
- [ ] During publish, disconnect network (disable adapter)
- [ ] **VERIFY**: Publish fails with appropriate error code
- [ ] **VERIFY**: No partial `.zip` file left on store (only `.zip.tmp` at most)
- [ ] Reconnect network
- [ ] **VERIFY**: Retry publish succeeds

---

## Section L: Team UX Polish Tests (V1.2)

> Added: 2025-01-08 — Team V1 UX Polish release

### L1. Auto-Refresh Store Status

- [ ] Open Team tab with configured store
- [ ] Wait 10+ seconds without interaction
- [ ] **VERIFY**: "Last refresh" timestamp updates automatically
- [ ] **VERIFY**: No visible flicker during auto-refresh
- [ ] Switch to another tab (Mission, Runs)
- [ ] **VERIFY**: Auto-refresh stops (no background polling)

### L2. Search with Debounce

- [ ] Create multiple cases with varied titles
- [ ] Type quickly in the search box
- [ ] **VERIFY**: List does not update on every keystroke
- [ ] **VERIFY**: List updates ~300ms after typing stops
- [ ] Clear search box
- [ ] **VERIFY**: All cases reappear

### L3. Tag Filter Dropdown

- [ ] Create cases with different tags (e.g., "urgent", "malware", "phishing")
- [ ] Open tag filter dropdown
- [ ] **VERIFY**: Dropdown lists all unique tags from all cases
- [ ] Select a specific tag
- [ ] **VERIFY**: Only cases with that tag are shown
- [ ] Select "All Tags"
- [ ] **VERIFY**: All cases reappear

### L4. Sort Options

- [ ] Create multiple cases with different update times and run counts
- [ ] Test each sort option:
  - [ ] **Updated**: Most recently updated first
  - [ ] **Created**: Most recently created first
  - [ ] **Runs**: Most runs first
  - [ ] **Notes**: Most notes first
- [ ] **VERIFY**: Each sort option correctly orders the list

### L5. Has Runs Only Filter

- [ ] Create a case with runs and a case without runs
- [ ] Check "Has Runs Only" checkbox
- [ ] **VERIFY**: Empty cases are hidden
- [ ] Uncheck the filter
- [ ] **VERIFY**: All cases reappear

### L6. Provenance Chips in Case List

- [ ] View case list
- [ ] **VERIFY**: Cases show 🖥️ chip with host name
- [ ] Hover over chip
- [ ] **VERIFY**: Chip text is readable

### L7. Case Detail Sub-Tabs

- [ ] Select a case with runs, notes, and tags
- [ ] Click each sub-tab:
  - [ ] **📊 Runs**: Shows published runs list
  - [ ] **📝 Notes**: Shows notes timeline
  - [ ] **🏷️ Tags**: Shows tag management UI
  - [ ] **📈 Overview**: Shows V2 placeholder message
- [ ] **VERIFY**: Only one tab content visible at a time
- [ ] **VERIFY**: Active tab has visual highlight

### L8. Multi-Select Runs

- [ ] Select a case with multiple runs
- [ ] Check 2+ run checkboxes
- [ ] **VERIFY**: "Import Selected (N)" button appears with correct count
- [ ] Uncheck all runs
- [ ] **VERIFY**: Button hides

### L9. Bulk Import Progress

- [ ] Select multiple runs and click "Import Selected"
- [ ] **VERIFY**: Progress bar appears
- [ ] **VERIFY**: Status text shows "Importing X of N: run_id"
- [ ] Wait for completion
- [ ] **VERIFY**: Progress bar shows 100%
- [ ] **VERIFY**: Success toast appears
- [ ] **VERIFY**: Selection is cleared after import

### L10. Copy Bundle Path

- [ ] Select a case with published runs
- [ ] Click "Copy Path" on a run
- [ ] **VERIFY**: Toast shows "Copied bundle path"
- [ ] Paste in a text editor
- [ ] **VERIFY**: Valid file path appears (e.g., `\\server\share\cases\...\run.zip`)

### L11. Copy Note

- [ ] Select a case with notes
- [ ] Go to Notes sub-tab
- [ ] Click 📋 on a note
- [ ] **VERIFY**: Toast shows "Note copied"
- [ ] Paste in a text editor
- [ ] **VERIFY**: Note text appears

### L12. Copy Case ID

- [ ] Select a case
- [ ] Click 📋 next to the case ID
- [ ] **VERIFY**: Toast shows "Case ID copied"
- [ ] Paste in a text editor
- [ ] **VERIFY**: UUID appears (e.g., `550e8400-e29b-41d4-a716-446655440000`)

### L13. Copy Diagnostics (Disconnected State)

- [ ] Configure store to an invalid/inaccessible path
- [ ] **VERIFY**: Status shows "Disconnected"
- [ ] **VERIFY**: "📋 Copy Diagnostics" button appears
- [ ] Click the diagnostics button
- [ ] **VERIFY**: Toast shows "Diagnostics copied"
- [ ] Paste in a text editor
- [ ] **VERIFY**: JSON object with store_dir, available, code, reason fields

### L14. Notes Timeline Grouping

- [ ] Add notes to a case across multiple days
- [ ] Go to Notes sub-tab
- [ ] **VERIFY**: Notes are grouped by day headers
- [ ] **VERIFY**: Day headers show readable dates (e.g., "Monday, Jan 8")
- [ ] **VERIFY**: Notes within each day are in reverse chronological order

### L15. Toast Notifications

- [ ] Trigger various actions (import, copy, error)
- [ ] **VERIFY**: Toasts appear centered at bottom of screen
- [ ] **VERIFY**: Success toasts have green styling
- [ ] **VERIFY**: Warning toasts have orange styling
- [ ] **VERIFY**: Toasts auto-dismiss after ~3 seconds
- [ ] **VERIFY**: Multiple toasts don't overlap (queue or stack)

### L16. Empty State Messages

- [ ] Test each empty state:
  - [ ] No cases: "No cases found — create one to get started"
  - [ ] No matching search: "No cases match your filters"
  - [ ] No runs in case: "No runs published yet"
  - [ ] Store disconnected: "Configure a store to view cases"
- [ ] **VERIFY**: Each empty state has helpful message
- [ ] **VERIFY**: No blank/white screens

### L17. Create Case Form Toggle

- [ ] Click "Create Case" header
- [ ] **VERIFY**: Form expands with title, description, tags fields
- [ ] Click header again
- [ ] **VERIFY**: Form collapses
- [ ] **VERIFY**: Arrow indicator toggles (▼ ↔ ▲)

---

## Section M: Team V2 Aggregate Hardened Tests

> Added: 2025-01-13 — Team V2 Aggregate Hardening release

### M1. Aggregate Endpoint Response Format

- [ ] Select a case with multiple published runs
- [ ] Open DevTools → Network → filter "aggregate"
- [ ] Click 📈 Overview sub-tab
- [ ] **VERIFY**: `GET /api/team/cases/:id/aggregate` returns:
  - `per_host_findings`: Array of deduplicated findings per host
  - `cross_host_findings`: Array of deduplicated findings across hosts
  - `runs`: Array with evidence availability per run
  - `cache_hit`: Boolean indicating cache status
  - `hosts`: Array of unique hostnames
  - `timeline`: Array of events (max 100)

### M2. Canonical Dedupe Key Format

- [ ] Inspect `per_host_findings[0].dedupe_key` in DevTools
- [ ] **VERIFY**: Key follows format `rule_key::entity_key`
- [ ] **VERIFY**: Rule key contains: `playbook_id|rule_id|signal_type|detector_id` (or `unknown_rule`)
- [ ] **VERIFY**: Entity key is one of: `proc_key`, `file_key`, `identity_key`, `host`, or `unknown_entity`
- [ ] **VERIFY**: Same signal in same run gets same dedupe key on repeated requests

### M3. Dedupe Mode Toggle

- [ ] In Overview sub-tab, locate dedupe toggle (Cross-Host / Per-Host)
- [ ] Default should be "Cross-Host" (summary view)
- [ ] Click "Per-Host"
- [ ] **VERIFY**: Finding count may increase (more unique findings per host)
- [ ] **VERIFY**: Toggle visually indicates selected mode
- [ ] Click "Cross-Host"
- [ ] **VERIFY**: Finding count may decrease (signals collapsed across hosts)

### M4. Evidence Availability per Run

- [ ] Check `runs` array in aggregate response
- [ ] **VERIFY**: Each run has:
  - `run_id`: String
  - `host`: String
  - `signal_count`: Number
  - `segments_present`: Boolean
  - `evidence_deref_available`: Boolean
  - `evidence_reason_code`: String (or null if available)
- [ ] **VERIFY**: UI shows evidence status badge per run in "Run Evidence Status" section:
  - ✓ green for available
  - ⚠ orange with reason for unavailable

### M5. Evidence Availability per Finding

- [ ] Inspect `per_host_findings` or `cross_host_findings` entries
- [ ] **VERIFY**: Each finding has:
  - `evidence_available`: Boolean
  - `evidence_available_count`: Number (how many occurrences have evidence)
  - `evidence_ptr_sample`: String (sample evidence pointer, or null)
- [ ] **VERIFY**: UI shows 📎 badge for findings with evidence available

### M6. Finding Metadata

- [ ] Inspect a finding in the aggregate response
- [ ] **VERIFY**: Finding has:
  - `dedupe_key`: Canonical key string
  - `rule_id`: Original rule ID
  - `title`: Human-readable title (or rule_id fallback)
  - `total_count`: Total occurrences collapsed
  - `first_seen_ts`: ISO timestamp of earliest occurrence
  - `last_seen_ts`: ISO timestamp of latest occurrence
  - `run_ids_involved`: Array of run IDs where this finding appears
  - `hosts_involved`: Array of hosts where this finding appears
  - `top_signal_ref`: Object with `run_id` and `signal_id` for deep-link

### M7. Deep-Link to Finding

- [ ] Click a finding in the Overview tab
- [ ] **VERIFY**: UI switches to Runs tab
- [ ] **VERIFY**: Run is selected (if present locally)
- [ ] **VERIFY**: Signal is selected (if present in run)
- [ ] **VERIFY**: Explain tab is activated
- [ ] **VERIFY**: Toast shows navigation status (success or "not found locally")

### M8. Deep-Link from Finding Without Local Run

- [ ] Remove a run from local (keep only on team store)
- [ ] Click a finding that references that run in Overview
- [ ] **VERIFY**: Toast shows "Run not found locally. Import it first."
- [ ] **VERIFY**: No crash or error

### M9. Aggregate Cache Behavior

- [ ] Select a case with published runs
- [ ] Click Overview sub-tab (first load)
- [ ] Note `cache_hit: false` in DevTools (fresh computation)
- [ ] Refresh or re-click Overview
- [ ] **VERIFY**: `cache_hit: true` (served from cache)
- [ ] **VERIFY**: Response time is faster on cache hit

### M10. Cache Invalidation

- [ ] Load aggregate with `cache_hit: true`
- [ ] Publish a new run to the same case
- [ ] Re-load aggregate
- [ ] **VERIFY**: `cache_hit: false` (cache invalidated)
- [ ] **VERIFY**: New run appears in `runs` array
- [ ] **VERIFY**: New findings (if any) appear in findings arrays

### M11. Cache Status Indicator

- [ ] Check bottom-right of Overview panel
- [ ] **VERIFY**: Shows "⚡ Cached" when cache_hit is true
- [ ] **VERIFY**: Shows "🔄 Fresh" when cache_hit is false

### M12. Empty Case Aggregate

- [ ] Create a case with no runs
- [ ] Click Overview sub-tab
- [ ] **VERIFY**: Shows empty state message: "No runs published yet"
- [ ] **VERIFY**: No findings displayed
- [ ] **VERIFY**: Stats show 0 runs, 0 hosts, 0 findings

### M13. Case with Runs but No Signals

- [ ] Create a case and publish a run with no signals
- [ ] Click Overview sub-tab
- [ ] **VERIFY**: Shows run in `runs` array
- [ ] **VERIFY**: Shows "No findings detected across N run(s)"
- [ ] **VERIFY**: Run evidence status shows signal_count: 0

### M14. Large Findings List (>50)

- [ ] Generate a case with many signals (>50 unique findings)
- [ ] Click Overview sub-tab
- [ ] **VERIFY**: First 50 findings shown
- [ ] **VERIFY**: Footer shows "+N more findings" with correct count
- [ ] **VERIFY**: No UI freeze or excessive scroll lag

### M15. Dedupe Key Stability

- [ ] Note the `dedupe_key` for a finding
- [ ] Stop and start the server
- [ ] Reload aggregate
- [ ] **VERIFY**: Same finding has same `dedupe_key`
- [ ] **VERIFY**: Dedupe key is deterministic (not random)

### M16. Network Endpoint Dedupe (ip:port)

- [ ] Create two signals with same rule_id but different `remote_ip:port`:
  - Signal A: `metadata: { "remote_ip": "192.168.1.100", "port": 443 }`
  - Signal B: `metadata: { "remote_ip": "10.0.0.50", "port": 8080 }`
- [ ] Publish both in same run
- [ ] Load aggregate for the case
- [ ] **VERIFY**: Two separate findings appear (not collapsed)
- [ ] **VERIFY**: Dedupe keys differ: `...::192.168.1.100:443` vs `...::10.0.0.50:8080`
- [ ] **VERIFY**: Network endpoint takes priority over identity_key when no proc_key/file_key

### M17. Cache SHA256 Invalidation

- [ ] Load aggregate for a case (note `cache_hit: false` on first load)
- [ ] Reload aggregate (note `cache_hit: true`)
- [ ] Replace a run bundle with a different zip file (same filename, different content)
- [ ] Reload aggregate
- [ ] **VERIFY**: `cache_hit: false` (sha256 mismatch forces recompute)
- [ ] **VERIFY**: New aggregate reflects replaced bundle content
- [ ] Reload again
- [ ] **VERIFY**: `cache_hit: true` (new sha256 now cached)

---

## Exit Criteria

The core loop passes if ALL of the following:

- [ ] A1-A12: All core loop tests pass
- [ ] B1-B3: Failure modes handled gracefully
- [ ] C1-C2: Non-core features hidden
- [ ] D1-D2: Database contains expected data
- [ ] **E1-E11: UI Wiring Audit shows:**
  - **🚫 Ship Blockers = 0** (no required actions broken)
  - **❌ Broken = 0** (all actions wired correctly)
  - **Export JSON is valid** (can copy/download)
- [ ] **F1-F6: RD Fixes Verification passes:**
  - **F1**: Metrics DB-backed (no estimates)
  - **F2**: Signal counts persist after stop
  - **F3**: Playbooks returns structured error
  - **F4**: Export blocked while running/finalizing
  - **F5**: Finalize pipeline phases visible
  - **F6**: Response wrappers consistent
- [ ] **G1-G7: Capability Model Verification passes:**
  - Sensor status truthful (never claims active when blocked)
  - Attack surface coverage truthful (never claims covered when blocked)
  - Playbook derived status truthful (never claims enabled when blocked)
  - Run capability snapshot captured at run start
- [ ] **H1-H5: Status Semantics Consistency passes:**
  - Configured is NOT green (gray/blue neutral)
  - Active ONLY appears in run context with observed facts
  - Blocked ALWAYS shows reason when available
  - Detection Plan uses "enabled" not "active" for potential detections
- [ ] **J1-J6: Tier Enforcement tests pass:**
  - **J1**: `/api/meta/features` returns correct tier and feature flags
  - **J2**: Free tier core loop fully functional
  - **J3**: Free tier Pro endpoints return 403 FEATURE_LOCKED
  - **J4**: Pro tier unlocks all Pro features
  - **J5**: UI shows 🔒 icons on locked features
  - **J6**: UI handles FEATURE_LOCKED errors gracefully
- [ ] **K1-K17: Team Case Store tests pass** (Team tier only):
  - **K1**: Team tab shows locked state for non-Team tiers
  - **K2-K10**: All Team features functional when unlocked
  - **K11**: Team endpoints properly gated for non-Team tiers
  - **K12**: Publish atomicity (no partial bundles on SMB)
  - **K13**: Lock contention (double-writer prevented)
  - **K14**: Stale lock recovery (5-min timeout honored)
  - **K15**: Provenance attribution visible
  - **K16**: Unreadable cases handled gracefully
  - **K17**: SMB disconnect handled (no partial writes)
- [ ] **L1-L17: Team UX Polish tests pass** (Team tier only):
  - **L1**: Auto-refresh every 10s when Team tab open
  - **L2-L5**: Filters/sort/search work correctly
  - **L6**: Provenance chips visible in case list
  - **L7**: Sub-tabs navigate correctly
  - **L8-L9**: Multi-select and bulk import functional
  - **L10-L13**: Copy buttons work (path, note, case ID, diagnostics)
  - **L14**: Notes grouped by day
  - **L15**: Toast notifications styled and auto-dismiss
  - **L16-L17**: Empty states and form toggle work
- [ ] **M1-M17: Team V2 Aggregate Hardened tests pass** (Team tier only):
  - **M1**: Aggregate endpoint returns new V2 format
  - **M2**: Dedupe keys use canonical `rule_key::entity_key` format
  - **M3**: Dedupe toggle switches between per-host and cross-host
  - **M4**: Evidence availability per run with reason codes
  - **M5**: Evidence availability per finding with count and pointer sample
  - **M6**: Finding metadata includes timestamps, run_ids, hosts, top_signal_ref
  - **M7-M8**: Deep-links navigate to run/signal/explain
  - **M9-M11**: Cache works (hit/miss indicator, invalidation on new runs)
  - **M12-M13**: Empty states handled gracefully
  - **M14**: Large findings list (>50) handled with pagination
  - **M15**: Dedupe keys are stable/deterministic across restarts
  - **M16**: Network endpoint (ip:port) dedupe - distinct endpoints don't collapse
  - **M17**: Cache sha256 invalidation - replaced bundles force recompute
- [ ] **N1-N12: Pro Entity Explorer tests pass** (Pro tier only):
  - **N1**: `GET /api/runs/:id/entities` returns entities grouped by type (processes, files, ips, users, hosts)
  - **N2**: Each entity has: value, count, first_seen, last_seen, top_signals
  - **N3**: Explore tab shows 🔒 locked state for Free tier
  - **N4**: Explore tab shows entity list with search and type filters
  - **N5**: Entity click triggers pivot query (`GET /api/runs/:id/pivot?kind=X&value=Y`)
  - **N6**: Pivot returns: related_findings, related_changes, related_evidence_ptrs, mini_timeline
  - **N7**: Pivot panel shows findings with severity badges (click navigates to Explain)
  - **N8**: Pivot panel shows changes with novelty badges (NEW for novelty="new")
  - **N9**: Pivot panel shows evidence pointers (read-only, no deref)
  - **N10**: Pivot panel shows mini timeline with timestamps
  - **N11**: "Open Top Finding Explain" button navigates to Explain tab with top finding
  - **N12**: "Export Case Pack" button triggers `POST /api/runs/:id/export/case_pack`
- [ ] **N13-N18: Pro Novelty Scoring tests pass** (Pro tier only):
  - **N13**: `GET /api/runs/:id/diff` returns DiffChange with `novelty` field
  - **N14**: `novelty` values: "new" (added), "known" (removed), "changed" (count delta), "changed" (modified)
  - **N15**: `novelty_basis` explains the novelty decision
  - **N16**: Changes tab displays novelty badges on changes
  - **N17**: Explore pivot view shows novelty badges on related changes
  - **N18**: Novelty is deterministic (no AI, no random)
- [ ] **N19-N24: Pro Case Pack Export tests pass** (Pro tier only):
  - **N19**: `POST /api/runs/:id/export/case_pack` returns ZIP file
  - **N20**: ZIP contains: manifest.json, case_summary.json, findings.json, changes.json, next_steps.json
  - **N21**: ZIP contains: evidence/records/*.json (evidence pointers)
  - **N22**: Case pack includes run metadata (run_id, timestamps, hosts)
  - **N23**: Case pack is self-contained (can be shared without DB access)
  - **N24**: Free tier receives 403 FEATURE_LOCKED on case pack endpoint
- [ ] **O1-O5: Import Report tests pass** (all tiers):
  - **O1**: `POST /api/import/bundle` returns `import_report` object
  - **O2**: Import report includes `normalized_artifacts` (files successfully imported)
  - **O3**: Import report includes `dropped_artifacts` (files skipped with reasons)
  - **O4**: Import report includes `evidence_deref_available` boolean
  - **O5**: UI shows import report modal with summary, dropped files, and imported files

**Run `cargo run --bin wi_run_all --release` for automated verification.**

---

*Document version: CORE PRODUCT v1.9.0 — Pro Entity Explorer + Novelty + Case Pack*
*See also: [CORE_PRODUCT.md](CORE_PRODUCT.md), [TEAM_CASE_STORE.md](TEAM_CASE_STORE.md), [TEAM_V1_WORKFLOW.md](TEAM_V1_WORKFLOW.md), [API_CONTRACT_CORE.md](API_CONTRACT_CORE.md)*

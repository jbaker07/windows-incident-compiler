/**
 * Incident Compiler - UI Application
 * BUILD_STAMP: 2026-01-12T00:00:00Z_STATUS_SEMANTICS
 * 
 * TRUTHFUL BY DEFAULT:
 * - All state comes from backend endpoints, never simulated
 * - If backend unreachable, UI shows error and does NOT fake running state
 * - 0 renders as "0", null/undefined renders as "—"
 * 
 * STATUS SEMANTICS (v1.4):
 * - Active: facts/events observed in current run (green)
 * - Configured: accessible but no events yet (gray/blue)
 * - Missing: not installed/present (red)
 * - Blocked: present but inaccessible (amber)
 * - Disabled: explicitly disabled (gray)
 * 
 * EXPLAINABILITY:
 * - Runs → Findings → Explain flow fully backend-driven
 * - Capability probe at boot to detect available endpoints
 * - Missing endpoints show "Not available (missing: ...)" - no blank screens
 */

(function() {
  'use strict';

  // ============ BUILD STAMP ============
  const BUILD_STAMP = '2026-01-10-SHIP';
  console.log('APP BOOT', BUILD_STAMP);

  // ============ DEBUG MODE ============
  // Enable with ?debug=1 in URL
  const DEBUG_MODE = new URLSearchParams(window.location.search).get('debug') === '1';
  const apiCallLog = [];  // Last 10 API calls for debug panel
  const MAX_API_LOG = 10;

  const API_BASE = window.location.origin;
  
  // ============ STATE ============
  // Single source of truth: all state comes from backend
  const state = {
    currentTab: 'mission',
    // Run state - ONLY set from backend /api/run/status
    isRunning: false,
    runId: null,
    startedAt: null,
    elapsedSeconds: null,
    profile: null,
    // Counters - from backend /api/run/metrics
    counters: { events: null, segments: null, facts: null, signals: null },
    // Runs list - from backend /api/runs
    runs: [],
    selectedRunId: null,
    // Connection state
    serverOnline: false,
    lastError: null,
    lastErrorEndpoint: null,
    // Import state
    importedMode: false,
    // Readiness
    readinessState: 'unknown',
    readinessSummary: null,
    // Telemetry readiness details
    telemetryReadiness: null,
    supportsRestartAdmin: false, // Whether restart-as-admin is supported
    isRestartingAsAdmin: false,  // Whether we're in the process of restarting
    // Explainability state
    currentRunTab: 'overview',
    selectedRun: null,
    signals: [],           // Findings/signals for selected run (STRICTLY isolated to run)
    selectedSignalId: null,
    selectedSignal: null,
    signalExplanation: null,
    signalNarrative: null,
    runCoverage: null,     // Coverage data for selected run (facts, types, hosts, diagnostics)
    // Run isolation tracking
    signalsRunId: null,    // Which run the current signals belong to (for strict isolation verification)
    signalsCursor: null,   // Cursor for incremental signal polling (since_ts_ms)
    // Explore tab state (PRO - Entity Explorer)
    exploreEntities: null,     // Cached entities for current run
    exploreEntitiesRunId: null,// Which run the cached entities belong to
    exploreSelectedEntity: null, // { kind: 'process'|'file'|'ip'|'user'|'host', value: 'xxx' }
    explorePivotResult: null,  // Pivot query result for selected entity
    exploreTypeFilter: 'all',  // Current type filter: all, processes, files, ips, users, hosts
    exploreSearchQuery: '',    // Current search filter
    // Capability probe results (which endpoints exist)
    capabilities: {
      signals: null,      // null = unknown, true = available, false = 404
      signalsStats: null,
      signalExplain: null,
      signalNarrative: null,
      runCoverage: null,    // /api/runs/:id/coverage endpoint
      evidenceDeref: false, // Evidence dereference NOT supported by current backend
      runEntities: null,    // /api/runs/:id/entities endpoint (PRO)
      runPivot: null,       // /api/runs/:id/pivot endpoint (PRO)
      casePack: null        // /api/runs/:id/export/case_pack endpoint (PRO)
    },
    // Wiring check results (populated by runWiringCheck)
    wiringCheckResults: null,
    // Debug mode - enables diagnosis banner and extra logging
    debugMode: window.location.search.includes('debug=1') || localStorage.getItem('debugMode') === 'true',
    // Tier gating - from /api/meta/features
    tier: 'Free',           // Current tier: Free, Pro, Team, Dev
    features: {},           // Feature flags from server
    upgradeUrl: 'https://locint.io/upgrade',
    // Playbook selection state
    playbookSelection: {
      mode: 'preset',       // 'preset' or 'custom'
      preset: 'general',    // Current preset ID - default to 'general' for system-changes focus
      selectedPlaybooks: [], // Explicit playbook IDs when custom
      presets: null,        // Cached presets from API
      presetsLoading: false,
      selectedCount: 0,
      runnableCount: 0,
      blockedCount: 0,
      showUnselected: false, // Toggle to show/hide non-selected playbooks in UI
    },
    // Team Case Store state
    teamStore: {
      status: null,         // Store status object from /api/team/store/status
      cases: [],            // List of cases from store
      selectedCaseId: null, // Currently selected case
      selectedCase: null,   // Full case detail object
      selectedCaseTab: 'runs', // Current sub-tab: runs, notes, tags, overview
      selectedRunIds: new Set(), // Multi-select for bulk import
      allTags: [],          // All unique tags across cases (for filter)
      searchDebounceTimer: null,
      storeRefreshInterval: null, // Auto-refresh timer
      aggregate: null       // Team V2: Case aggregate data
    }
  };

  // ============ GLOSSARY (Term Definitions) ============
  // Single source of truth for all terminology info bubbles
  // Used by renderInfoBubble() to show contextual help tooltips
  const GLOSSARY = {
    // Core counters
    facts: {
      term: 'Facts',
      definition: 'Rows extracted by locald from canonical events in segments. Each fact represents a structured observation (process, file, network, registry, etc.) with normalized fields.'
    },
    signals: {
      term: 'Signals',
      definition: 'Detection matches when facts match playbook patterns. A signal indicates suspicious or notable activity was found, referencing the matched facts as evidence.'
    },
    events: {
      term: 'Events',
      definition: 'Raw telemetry records received from sensors (Sysmon, ETW, etc.). Events are parsed and normalized into canonical format before fact extraction.'
    },
    segments: {
      term: 'Segments',
      definition: 'Batches of events written to disk by the agent. Each segment contains a time-bounded collection of events for efficient processing.'
    },
    // Detection plan
    playbooks_loaded: {
      term: 'Playbooks Loaded',
      definition: 'Total detection playbooks parsed and available. Includes both enabled and disabled playbooks from the detection plan.'
    },
    playbooks_enabled: {
      term: 'Playbooks Enabled',
      definition: 'Playbooks actively checking incoming facts for matches. Only enabled playbooks can generate signals.'
    },
    playbooks_fired: {
      term: 'Playbooks Fired',
      definition: 'Playbooks that matched at least one fact this run. A fired playbook has generated one or more signals.'
    },
    playbooks_near_miss: {
      term: 'Near Miss',
      definition: 'Playbooks where some but not all conditions matched. Useful for understanding what telemetry would enable additional detections.'
    },
    playbooks_blocked: {
      term: 'Blocked',
      definition: 'Playbooks that cannot fire because required telemetry is unavailable. Missing sensors or channels block detection capability.'
    },
    // Coverage
    coverage_minutes: {
      term: 'Coverage Minutes',
      definition: 'Approximate duration of telemetry based on fact timestamps (max - min). Note: may be imperfect if timestamps are sparse or clustered.'
    },
    coverage_hours: {
      term: 'Coverage Hours',
      definition: 'Approximate duration of telemetry based on fact timestamps. Calculated from the span of observed facts.'
    },
    // Infrastructure
    sensors: {
      term: 'Sensors',
      definition: 'Data sources that generate raw events (Sysmon, ETW providers, etc.). Active sensors have produced events this run.'
    },
    channels: {
      term: 'Channels',
      definition: 'Event log channels being monitored (Security, PowerShell, etc.). Each channel can contain events from multiple sensors.'
    },
    readiness: {
      term: 'System Readiness',
      definition: 'Overall health status indicating whether the system can collect telemetry and run detections. Checks sensor access, channel availability, and agent configuration.'
    },
    telemetry_status: {
      term: 'Telemetry Status',
      definition: 'Current state of event collection: Full (all sensors active), Partial (some sensors blocked), or None (no telemetry accessible).'
    },
    // Processing
    dedupe: {
      term: 'Dedupe',
      definition: 'Duplicate event suppression to prevent counting the same event multiple times. Improves accuracy of fact counts.'
    },
    startup_suppress: {
      term: 'Startup Suppress',
      definition: 'Filtering of noisy startup events that occur when the system boots. Reduces false positives from normal boot activity.'
    },
    // Analysis
    top_process: {
      term: 'Top Process',
      definition: 'Most frequently observed process in the telemetry. Identifies the dominant executable by fact count.'
    },
    top_entities: {
      term: 'Top Entities',
      definition: 'Most frequently observed entities (processes, files, IPs, users, hosts) across all facts. Shows what is most active in the telemetry.'
    },
    evidence_pointers: {
      term: 'Evidence Pointers',
      definition: 'References to source facts that triggered a signal. Each pointer identifies the specific fact (by ID) that matched a playbook condition.'
    },
    matched_facts: {
      term: 'Matched Facts',
      definition: 'Facts that satisfied playbook detection conditions. These facts are the evidence supporting a signal.'
    },
    // Findings
    findings: {
      term: 'Findings',
      definition: 'Detection results from playbook matches. Each finding represents a potential security incident with severity, matched facts, and context.'
    },
    severity: {
      term: 'Severity',
      definition: 'Risk level assigned to a finding: Critical (immediate threat), High (serious concern), Medium (investigate), Low (informational).'
    },
    // Capability gaps
    capability_gaps: {
      term: 'Capability Gaps',
      definition: 'Missing telemetry or sensors that prevent certain detections from firing. Addressing gaps improves detection coverage.'
    },
    next_steps: {
      term: 'Next Steps',
      definition: 'Recommended actions based on current run state. May include enabling sensors, reviewing findings, or addressing configuration issues.'
    },
    // Fact Inspector
    fact_types: {
      term: 'Fact Types',
      definition: 'Categories of facts by source or nature: ProcessCreate, FileCreate, NetworkConnect, RegistryEvent, etc.'
    },
    fact_hosts: {
      term: 'Hosts',
      definition: 'Unique computer names observed in the telemetry. Facts are attributed to the host where they were collected.'
    },
    total_facts: {
      term: 'Total Facts',
      definition: 'Count of all extracted facts across all types and hosts for this run.'
    },
    // Runs
    run_id: {
      term: 'Run ID',
      definition: 'Unique identifier for a collection session. Each run captures a distinct time window of telemetry and analysis.'
    },
    run_status: {
      term: 'Run Status',
      definition: 'Current state of the run: Running (actively collecting), Stopped (collection paused), Completed (analysis finished).'
    }
  };

  /**
   * Render an info bubble (ⓘ) with glossary-driven tooltip
   * @param {string} glossaryKey - Key from GLOSSARY object
   * @returns {string} HTML string for the info bubble
   */
  function renderInfoBubble(glossaryKey) {
    const entry = GLOSSARY[glossaryKey];
    if (!entry) {
      console.warn(`[InfoBubble] Unknown glossary key: ${glossaryKey}`);
      return '';
    }
    // Escape HTML in definition to prevent XSS
    const escapedDef = entry.definition
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
    const escapedTerm = entry.term
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    
    return `<span class="info-bubble" tabindex="0" role="button" aria-label="Info about ${escapedTerm}">i<span class="info-bubble-popup"><strong>${escapedTerm}</strong>${escapedDef}</span></span>`;
  }

  // ============ DEBUG SCOPE GUARDS ============
  // These helpers warn in console when live endpoints are called in run-scoped contexts
  // Only active in debug mode (?debug=1). Helps catch SSoT violations during development.
  
  /**
   * Check if we're currently viewing a specific run's data (run-scoped context)
   */
  function isInRunScope() {
    // We're in run scope if:
    // 1. On the 'runs' tab with a selected run
    // 2. On any sub-tab of a run detail (findings, facts, coverage, etc.)
    return state.currentTab === 'runs' && state.selectedRunId != null;
  }
  
  /**
   * Debug-only: Warn when /api/selfcheck (live probe) is called while viewing run data.
   * Run views should use readiness_snapshot from run_meta.json, not live capability.
   */
  function debugWarnLiveProbeInRunScope(endpoint) {
    if (!DEBUG_MODE) return;
    if (isInRunScope()) {
      console.warn(
        `⚠️ [SCOPE GUARD] Live endpoint ${endpoint} called while viewing run ${state.selectedRunId}. ` +
        `Run-scoped views should use readiness_snapshot from run data, not live probes.`
      );
    }
  }

  /**
   * Initialize all info bubbles on the page.
   * Maps element IDs to glossary keys and injects the bubble HTML.
   */
  function initInfoBubbles() {
    // Map of element ID -> glossary key
    const infoBubbleMap = {
      // Mission tab - Live Counters
      'infoBubbleEvents': 'events',
      'infoBubbleSegments': 'segments',
      'infoBubbleFacts': 'facts',
      'infoBubbleSignals': 'signals',
      'infoBubbleDedupe': 'dedupe',
      'infoBubbleStartupSuppress': 'startup_suppress',
      // Mission tab - Readiness
      'infoBubbleReadiness': 'readiness',
      'infoBubbleSensors': 'sensors',
      'infoBubbleChannels': 'channels',
      'infoBubblePlaybooksEnabled': 'playbooks_enabled',
      'infoBubblePlaybooksBlocked': 'playbooks_blocked',
      // Runs tab - Overview metrics
      'infoBubbleRunEvents': 'events',
      'infoBubbleRunSegments': 'segments',
      'infoBubbleRunFacts': 'facts',
      'infoBubbleRunSignals': 'signals',
      // Runs tab - Playbooks
      'infoBubblePlaybooksLoaded': 'playbooks_loaded',
      'infoBubblePlaybooksFired': 'playbooks_fired',
      'infoBubblePlaybooksNearMiss': 'playbooks_near_miss',
      'infoBubblePlaybooksBlockedRuns': 'playbooks_blocked',
      // Facts tab
      'infoBubbleTotalFacts': 'total_facts',
      'infoBubbleFactTypes': 'fact_types',
      'infoBubbleFactHosts': 'fact_hosts',
      // Explain tab
      'infoBubbleExplainEvidence': 'evidence_pointers',
      'infoBubbleEvidencePointers': 'evidence_pointers',
      'infoBubbleMatchedFacts': 'matched_facts'
    };

    let populated = 0;
    for (const [elementId, glossaryKey] of Object.entries(infoBubbleMap)) {
      const el = document.getElementById(elementId);
      if (el) {
        el.innerHTML = renderInfoBubble(glossaryKey);
        populated++;
      }
    }
    console.log(`[InfoBubbles] Populated ${populated}/${Object.keys(infoBubbleMap).length} info bubbles`);
  }

  // ============ UI ACTIONS REGISTRY ============
  // Single source of truth: every UI button that triggers an API call MUST be listed here.
  // Used by the Wiring Check feature to verify all actions are properly connected.
  //
  // tier: "core" (essential functionality), "pro" (advanced features), "team" (collaboration), "dev" (debugging/meta)
  // required: true = ship blocker if broken, false = nice-to-have
  const UI_ACTIONS = [
    // Health & Selfcheck
    {
      id: 'system.health',
      label: 'Health Check',
      buttonSelector: null, // Automatic polling, no explicit button
      request: { method: 'GET', path: '/api/health' },
      expects: { json: true, wrapper: true, requiredKeys: ['status'] },
      safeToCall: true,
      tier: 'core',
      required: true,
      notes: 'Automatic health polling'
    },
    {
      id: 'settings.selfcheck',
      label: 'Run Checks',
      buttonSelector: '#btnRunChecks',
      request: { method: 'GET', path: '/api/selfcheck' },
      expects: { json: true, wrapper: true, requiredKeys: ['overall_status'] },
      safeToCall: true,
      tier: 'core',
      required: true,
      notes: 'System readiness check'
    },
    {
      id: 'settings.detectionPlan',
      label: 'Detection Plan',
      buttonSelector: '#btnLoadDetectionPlan',
      request: { method: 'GET', path: '/api/playbooks/catalog' },
      expects: { json: true, wrapper: true, requiredKeys: ['playbooks'] },
      safeToCall: true,
      tier: 'core',
      required: true,
      notes: 'Playbook catalog showing enabled/blocked detections'
    },
    // Run Control
    {
      id: 'mission.start',
      label: 'Start Run',
      buttonSelector: '#btnStartRun',
      request: { method: 'POST', path: '/api/run/start' },
      expects: { json: true, wrapper: true, requiredKeys: ['run_id'] },
      safeToCall: false, // DO NOT call during wiring check
      tier: 'core',
      required: true,
      notes: 'Starts telemetry capture - MUTATING'
    },
    {
      id: 'mission.stop',
      label: 'Stop Run',
      buttonSelector: '#btnStopRun',
      request: { method: 'POST', path: '/api/run/stop' },
      expects: { json: true, wrapper: true, requiredKeys: ['stopped'] },
      safeToCall: false, // DO NOT call during wiring check
      tier: 'core',
      required: true,
      notes: 'Stops telemetry capture - MUTATING'
    },
    {
      id: 'mission.status',
      label: 'Run Status',
      buttonSelector: null, // Automatic polling
      request: { method: 'GET', path: '/api/run/status' },
      expects: { json: true, wrapper: true, requiredKeys: ['running'] },
      safeToCall: true,
      tier: 'core',
      required: true,
      notes: 'Current run status polling'
    },
    {
      id: 'mission.metrics',
      label: 'Run Metrics',
      buttonSelector: null, // Automatic polling
      request: { method: 'GET', path: '/api/run/metrics' },
      expects: { json: true, wrapper: true },
      safeToCall: true,
      tier: 'core',
      required: true,
      notes: 'Live metrics polling'
    },
    // Runs Tab
    {
      id: 'runs.list',
      label: 'List Runs',
      buttonSelector: null, // Automatic on tab switch
      request: { method: 'GET', path: '/api/runs' },
      expects: { json: true, wrapper: true, dataPath: 'runs', requiredKeys: ['run_id', 'signal_count', 'status'] },
      safeToCall: true,
      tier: 'core',
      required: true,
      notes: 'Past runs listing - CONTRACT: data.runs array'
    },
    {
      id: 'runs.coverage',
      label: 'Run Coverage',
      buttonSelector: null, // Automatic on run select
      request: { method: 'GET', path: '/api/runs/:run_id/coverage' },
      expects: { json: true, wrapper: true, requiredKeys: ['available', 'run_id'] },
      safeToCall: true, // Safe with placeholder run_id
      tier: 'core',
      required: true,
      notes: 'Facts and coverage for a run'
    },
    {
      id: 'runs.changes',
      label: 'Run Changes',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/runs/:run_id/changes' },
      expects: { json: true, wrapper: true },
      safeToCall: true,
      tier: 'pro',
      required: false,
      notes: 'Changes/diff for a run'
    },
    {
      id: 'runs.playbooks',
      label: 'Run Playbooks',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/runs/:run_id/playbooks' },
      expects: { json: true, wrapper: true, requiredKeys: ['available', 'run_id'] },
      safeToCall: true,
      tier: 'core',
      required: true,
      notes: 'Playbook status for a run'
    },
    // Signals
    {
      id: 'signals.list',
      label: 'List Signals',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/signals', needsRunId: true },
      expects: { json: true, wrapper: true, dataPath: 'signals', requiredKeys: ['signal_id', 'signal_type', 'severity', 'ts'] },
      safeToCall: true,
      tier: 'core',
      required: true,
      notes: 'Findings/signals list - CONTRACT: data.signals array'
    },
    {
      id: 'signals.stats',
      label: 'Signal Stats',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/signals/stats' },
      expects: { json: true, wrapper: true },
      safeToCall: true,
      tier: 'pro',
      required: false,
      notes: 'Signal statistics'
    },
    {
      id: 'signals.get',
      label: 'Get Signal',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/signals/:id' },
      expects: { json: true, wrapper: true },
      safeToCall: true,
      tier: 'core',
      required: true,
      notes: 'Single signal details'
    },
    {
      id: 'signals.explain',
      label: 'Explain Signal',
      buttonSelector: null, // Dynamic selection
      request: { method: 'GET', path: '/api/signals/:id/explain', needsRunId: true },
      expects: { json: true, wrapper: true, requiredKeys: ['available', 'signal', 'source', 'evidence_ptrs', 'evidence_ptrs_count'] },
      safeToCall: true,
      tier: 'core',
      required: true,
      notes: 'Signal explanation - CONTRACT: canonical ExplainResponse schema'
    },
    // Features
    {
      id: 'features.list',
      label: 'Feature Flags',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/features' },
      expects: { json: true, wrapper: true },
      safeToCall: true,
      tier: 'pro',
      required: false,
      notes: 'Available feature flags'
    },
    {
      id: 'capture.profiles',
      label: 'Capture Profiles',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/capture/profiles' },
      expects: { json: true, wrapper: true },
      safeToCall: true,
      tier: 'pro',
      required: false,
      notes: 'Available capture profiles'
    },
    // Export (mutating but safe to verify route)
    {
      id: 'bundle.export',
      label: 'Export Bundle',
      buttonSelector: '#btnExportBundle',
      request: { method: 'POST', path: '/api/export/bundle' },
      expects: { json: false, binary: true, contentType: 'application/zip' },
      safeToCall: false, // Requires run_id, don't call without one
      tier: 'core',
      required: true,
      notes: 'Exports bundle ZIP - MUTATING/requires run_id'
    },
    {
      id: 'bundle.exportRun',
      label: 'Export Run',
      buttonSelector: '#btnExportRun',
      request: { method: 'POST', path: '/api/export/bundle' },
      expects: { json: false, binary: true, contentType: 'application/zip' },
      safeToCall: false,
      tier: 'core',
      required: true,
      notes: 'Export selected run - MUTATING/requires run_id'
    },
    // Meta (wiring audit)
    {
      id: 'meta.routes',
      label: 'Route Inventory',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/meta/routes' },
      expects: { json: true, wrapper: true },
      safeToCall: true,
      tier: 'dev',
      required: false,
      notes: 'Authoritative route list for wiring check'
    },
    {
      id: 'meta.contract',
      label: 'API Contract',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/meta/contract' },
      expects: { json: true, wrapper: true },
      safeToCall: true,
      tier: 'dev',
      required: false,
      notes: 'Response wrapper specification'
    },
    // App lifecycle
    {
      id: 'app.restart_admin',
      label: 'Restart as Administrator',
      buttonSelector: '#btnRestartAdmin',
      request: { method: 'POST', path: '/api/app/restart_admin' },
      expects: { json: true, wrapper: true },
      safeToCall: false,
      tier: 'core',
      required: false,
      notes: 'Restart with UAC elevation - MUTATING action, requires Windows desktop'
    },
    // ============ PRO TIER ENDPOINTS ============
    {
      id: 'baselines.set',
      label: 'Mark as Baseline',
      buttonSelector: '#btnMarkBaseline',
      request: { method: 'POST', path: '/api/runs/:run_id/baseline' },
      expects: { json: true, wrapper: true, requiredKeys: ['run_id', 'scope'] },
      safeToCall: false,
      tier: 'pro',
      required: false,
      notes: 'Mark run as baseline for comparison - TIER GATED: Pro'
    },
    {
      id: 'baselines.list',
      label: 'List Baselines',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/baselines' },
      expects: { json: true, wrapper: true, requiredKeys: ['baselines', 'count'] },
      safeToCall: true,
      tier: 'pro',
      required: false,
      notes: 'List all baseline runs - TIER GATED: Pro'
    },
    {
      id: 'runs.diff_baseline',
      label: 'Diff (Baseline Mode)',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/runs/:run_id/diff?mode=baseline' },
      expects: { json: true, wrapper: true },
      safeToCall: true,
      tier: 'pro',
      required: false,
      notes: 'Diff against baseline run - TIER GATED: Pro'
    },
    {
      id: 'runs.diff_marker',
      label: 'Diff (Marker Mode)',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/runs/:run_id/diff?mode=marker' },
      expects: { json: true, wrapper: true },
      safeToCall: true,
      tier: 'pro',
      required: false,
      notes: 'Diff around a timestamp marker - TIER GATED: Pro'
    },
    {
      id: 'runs.case_summary',
      label: 'Case Summary Export',
      buttonSelector: '#btnExportCaseSummary',
      request: { method: 'GET', path: '/api/runs/:run_id/case_summary' },
      expects: { json: true, wrapper: true, requiredKeys: ['contract_version', 'run_id', 'run_story', 'summary'] },
      safeToCall: true,
      tier: 'pro',
      required: false,
      notes: 'Export case summary JSON - TIER GATED: Pro'
    },
    {
      id: 'packs.custom',
      label: 'Custom Content Packs',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/packs/:pack_name' },
      expects: { json: true, wrapper: true },
      safeToCall: true,
      tier: 'pro',
      required: false,
      notes: 'Get custom content pack details - TIER GATED: Pro (builtin always allowed)'
    },
    {
      id: 'meta.features',
      label: 'Tier Feature Flags',
      buttonSelector: null,
      request: { method: 'GET', path: '/api/meta/features' },
      expects: { json: true, wrapper: true, requiredKeys: ['tier', 'features'] },
      safeToCall: true,
      tier: 'core',
      required: true,
      notes: 'Tier-aware feature flags for UI gating'
    },
    // Team Case Store actions
    {
      id: 'team.store_status',
      label: 'Team Store Status',
      buttonSelector: '#btnRefreshStore',
      request: { method: 'GET', path: '/api/team/store/status' },
      expects: { json: true, wrapper: true },
      safeToCall: true,
      tier: 'team',
      required: false,
      notes: 'Get team case store status - TIER GATED: Team'
    },
    {
      id: 'team.configure_store',
      label: 'Configure Team Store',
      buttonSelector: '#btnSaveStoreConfig',
      request: { method: 'POST', path: '/api/team/store/configure' },
      expects: { json: true, wrapper: true },
      safeToCall: false,
      tier: 'team',
      required: false,
      notes: 'Configure team case store path - TIER GATED: Team'
    },
    {
      id: 'team.create_case',
      label: 'Create Team Case',
      buttonSelector: '#btnCreateCase',
      request: { method: 'POST', path: '/api/team/cases' },
      expects: { json: true, wrapper: true },
      safeToCall: false,
      tier: 'team',
      required: false,
      notes: 'Create new team case - TIER GATED: Team'
    },
    {
      id: 'team.add_note',
      label: 'Add Case Note',
      buttonSelector: '#btnAddCaseNote',
      request: { method: 'POST', path: '/api/team/cases/:case_id/notes' },
      expects: { json: true, wrapper: true },
      safeToCall: false,
      tier: 'team',
      required: false,
      notes: 'Add note to team case - TIER GATED: Team'
    },
    {
      id: 'team.publish_run',
      label: 'Publish Run to Case',
      buttonSelector: '#btnConfirmPublishRun',
      request: { method: 'POST', path: '/api/team/cases/:case_id/runs' },
      expects: { json: true, wrapper: true },
      safeToCall: false,
      tier: 'team',
      required: false,
      notes: 'Publish run to team case - TIER GATED: Team'
    }
  ];

  // ============ POLLING STATE ============
  // CRITICAL: Single polling loop, no duplicates
  let pollTimeoutId = null;
  let healthIntervalId = null;
  let isPageVisible = true;
  let pollingStopped = false;

  // ============ EXPLAIN AUTO-REFRESH STATE ============
  // Auto-refresh controller for Explain tab when available=false
  // Uses exponential backoff: 500ms, 1s, 2s, 3s... up to 10s max total
  let explainRefreshTimeoutId = null;
  let explainRefreshAttempt = 0;
  let explainRefreshSignalId = null;  // Track which signal we're refreshing
  const EXPLAIN_REFRESH_BASE_DELAY = 500;  // 500ms base
  const EXPLAIN_REFRESH_MAX_TOTAL_MS = 10000;  // 10s max total wait
  let explainRefreshStartTime = null;  // Track total elapsed time

  // ============ PLAYBOOK DETAIL STATE ============
  let selectedPlaybookId = null;  // Currently selected playbook in detail drawer

  // ============ BENIGN VALIDATION REGISTRY ============
  // Curated list of safe, vetted validation triggers from VALIDATION_RUN.md
  // Only shown in debug mode (?debug=1)
  const VALIDATION_TRIGGERS = {
    "encoded_powershell_whoami": {
      title: "Encoded PowerShell (whoami)",
      command: "powershell.exe -NoProfile -EncodedCommand dwBoAG8AYQBtAGkA",
      requires_admin: false,
      requires_sysmon: true,
      notes: "Runs encoded 'whoami' command. Completely benign, triggers encoded PowerShell detection."
    },
    "schtasks_create_delete": {
      title: "Scheduled Task (create & delete)",
      command: `$taskName = "LocInt_Validation_Test_$(Get-Date -Format 'HHmmss')"; schtasks /create /tn $taskName /tr "cmd.exe /c echo test" /sc once /st 23:59 /f; Start-Sleep -Seconds 5; schtasks /delete /tn $taskName /f`,
      requires_admin: true,
      requires_sysmon: false,
      notes: "Creates and immediately deletes a harmless scheduled task. Requires Administrator."
    },
    "service_create_delete": {
      title: "Service (create & delete)",
      command: `$svcName = "LocIntValidationSvc"; sc.exe create $svcName binPath= "cmd.exe /c exit" start= disabled; Start-Sleep -Seconds 5; sc.exe delete $svcName`,
      requires_admin: true,
      requires_sysmon: false,
      notes: "Creates a disabled test service and deletes it. Requires Administrator."
    },
    "registry_run_key": {
      title: "Registry Run Key (set & remove)",
      command: `$keyPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"; $valueName = "LocIntValidationTest"; New-ItemProperty -Path $keyPath -Name $valueName -Value "notepad.exe" -PropertyType String -Force; Start-Sleep -Seconds 5; Remove-ItemProperty -Path $keyPath -Name $valueName -Force`,
      requires_admin: false,
      requires_sysmon: true,
      notes: "Sets and removes a harmless HKCU Run key entry. Triggers registry persistence detection."
    },
    "certutil_decode": {
      title: "CertUtil Decode (benign)",
      command: `echo "dGVzdA==" > $env:TEMP\\test.b64; certutil -decode $env:TEMP\\test.b64 $env:TEMP\\test.txt; del $env:TEMP\\test.b64, $env:TEMP\\test.txt`,
      requires_admin: false,
      requires_sysmon: true,
      notes: "Decodes a benign base64 string using certutil. Triggers certutil abuse detection."
    }
  };

  // ============ PLAYBOOK METADATA REGISTRY ============
  // Static metadata for all playbooks - provides descriptions, categories, and requirements
  // This enables the Mission tab to show meaningful information instead of "Unknown category"
  const PLAYBOOK_METADATA = {
    // Execution
    "signal_encoded_powershell": {
      category: "Execution",
      title: "Encoded PowerShell Execution",
      description: "Detects encoded or obfuscated PowerShell commands commonly used in initial access via malicious documents, download cradles (IEX/DownloadString), fileless malware execution, and C2 frameworks like Empire or Cobalt Strike. Fires when PowerShell is invoked with -EncodedCommand, -e, or similar flags containing base64-encoded payloads. Benign use cases include legitimate admin scripts using encoding for special characters.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Execution", "Defense Evasion"],
      mitre_techniques: ["T1059.001", "T1027"]
    },
    "signal_powershell_download": {
      category: "Execution",
      title: "PowerShell Download Cradle",
      description: "Detects PowerShell download cradles using Invoke-Expression with Net.WebClient, DownloadString, or Invoke-WebRequest patterns. These are commonly used for staging malware or pulling additional payloads from remote servers. May trigger on legitimate software installers or admin scripts that fetch configurations from internal servers.",
      required_sensors: ["security_eventlog", "sysmon", "powershell_logging"],
      required_facts: ["Exec", "ScriptExec"],
      mitre_tactics: ["Execution", "Command and Control"],
      mitre_techniques: ["T1059.001", "T1105"]
    },
    "signal_wscript_cscript_abuse": {
      category: "Execution",
      title: "WScript/CScript Abuse",
      description: "Detects suspicious use of Windows Script Host (wscript.exe, cscript.exe) executing VBS or JS files from unusual locations like temp folders, downloads, or user profiles. Commonly abused for initial access via malicious email attachments. Benign triggers may include legitimate admin scripts or software installations.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Execution"],
      mitre_techniques: ["T1059.005", "T1059.007"]
    },
    "signal_mshta_abuse": {
      category: "Execution",
      title: "MSHTA Abuse",
      description: "Detects mshta.exe executing inline scripts, remote HTA files, or suspicious local HTAs. MSHTA is a signed Microsoft binary frequently abused for proxy execution and defense evasion. Fires on inline VBScript/JScript execution or HTA files from temp/download locations. Rarely used legitimately in modern environments.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Execution", "Defense Evasion"],
      mitre_techniques: ["T1218.005"]
    },
    "signal_office_child_process": {
      category: "Execution",
      title: "Office Application Child Process",
      description: "Detects Office applications (Word, Excel, PowerPoint, Outlook) spawning suspicious child processes like cmd.exe, powershell.exe, wscript.exe, or mshta.exe. This is a strong indicator of macro-based malware or exploitation. May trigger on legitimate add-ins or automation workflows that spawn helper processes.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Execution", "Initial Access"],
      mitre_techniques: ["T1204.002", "T1566.001"]
    },
    // Defense Evasion
    "signal_defense_evasion": {
      category: "Defense Evasion",
      title: "Defense Evasion Techniques",
      description: "Detects various defense evasion techniques including process injection, DLL side-loading, timestomping, and AMSI bypasses. Monitors for suspicious API calls, unusual parent-child relationships, and memory manipulation patterns. May fire on legitimate security tools performing similar operations.",
      required_sensors: ["sysmon"],
      required_facts: ["Exec", "ProcessAccess"],
      mitre_tactics: ["Defense Evasion"],
      mitre_techniques: ["T1055", "T1574", "T1070"]
    },
    "signal_process_injection": {
      category: "Defense Evasion",
      title: "Process Injection",
      description: "Detects process injection attempts via Sysmon ProcessAccess events (Event ID 10) showing cross-process memory access. Monitors for PROCESS_VM_WRITE and PROCESS_CREATE_THREAD access patterns targeting system processes. Commonly used by malware to evade detection by running code in legitimate processes. May trigger on debugging tools or legitimate security software.",
      required_sensors: ["sysmon"],
      required_facts: ["ProcessAccess"],
      mitre_tactics: ["Defense Evasion", "Privilege Escalation"],
      mitre_techniques: ["T1055"]
    },
    "signal_dll_side_loading": {
      category: "Defense Evasion",
      title: "DLL Side-Loading",
      description: "Detects potential DLL side-loading attacks where legitimate signed executables load malicious DLLs from non-standard paths. Monitors for DLL loads from user-writable directories by trusted applications. May trigger on legitimate software with non-standard installation paths.",
      required_sensors: ["sysmon"],
      required_facts: ["ImageLoad"],
      mitre_tactics: ["Defense Evasion", "Persistence"],
      mitre_techniques: ["T1574.002"]
    },
    "signal_log_tampering": {
      category: "Defense Evasion",
      title: "Log Tampering Detection",
      description: "Detects attempts to clear, disable, or tamper with Windows event logs. Monitors Security Event ID 1102 (log cleared), wevtutil clear-log commands, and EventLog service manipulation. Fires when audit logs are cleared or logging is disabled. Rarely occurs legitimately except during controlled maintenance windows.",
      required_sensors: ["security_eventlog"],
      required_facts: ["LogTamper"],
      mitre_tactics: ["Defense Evasion"],
      mitre_techniques: ["T1070.001"]
    },
    "signal_log_tamper_detection": {
      category: "Defense Evasion",
      title: "Event Log Clearing",
      description: "Specifically detects Windows Security event log clearing via Event ID 1102. This is a high-confidence indicator of attacker activity attempting to cover tracks. Also monitors for EventLog service stop commands and log file deletion. Legitimate clearing should be documented and scheduled.",
      required_sensors: ["security_eventlog"],
      required_facts: ["LogTamper"],
      mitre_tactics: ["Defense Evasion"],
      mitre_techniques: ["T1070.001"]
    },
    "signal_security_tool_disable": {
      category: "Defense Evasion",
      title: "Security Tool Tampering",
      description: "Detects attempts to disable or tamper with security tools including Windows Defender, antivirus software, and EDR agents. Monitors for service stops, registry modifications to security settings, and processes terminating security software. May trigger on legitimate admin operations but should be investigated.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec", "RegistryMod"],
      mitre_tactics: ["Defense Evasion"],
      mitre_techniques: ["T1562.001"]
    },
    // Credential Access
    "signal_credential_access": {
      category: "Credential Access",
      title: "Credential Dumping Detection",
      description: "Detects credential access attempts including LSASS memory access via Sysmon Event ID 10, SAM database access, and credential dumping tool signatures (mimikatz, sekurlsa, procdump targeting lsass). Requires Sysmon for ProcessAccess events. High-confidence detections indicate active compromise. May trigger on legitimate memory forensics tools.",
      required_sensors: ["sysmon", "security_eventlog"],
      required_facts: ["Exec", "ProcessAccess"],
      mitre_tactics: ["Credential Access"],
      mitre_techniques: ["T1003.001", "T1003.002", "T1003.003"]
    },
    // Persistence
    "signal_persistence_windows": {
      category: "Persistence",
      title: "Windows Persistence Mechanisms",
      description: "Comprehensive detection of Windows persistence techniques including Run/RunOnce registry keys, scheduled tasks, services, and startup folder modifications. Fires when new persistence mechanisms are created in common autostart locations. May trigger on legitimate software installations - review the target path and binary reputation.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["RegistryMod", "ServiceInstall", "ScheduledTask"],
      mitre_tactics: ["Persistence"],
      mitre_techniques: ["T1547.001", "T1053.005", "T1543.003"]
    },
    "signal_registry_persistence": {
      category: "Persistence",
      title: "Registry Run Key Persistence",
      description: "Detects modifications to registry Run and RunOnce keys used for persistence. Monitors HKLM and HKCU autostart locations for new or modified entries. Fires when executables are added to run at user login or system startup. Common for both malware and legitimate software - verify the target binary.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["RegistryMod"],
      mitre_tactics: ["Persistence"],
      mitre_techniques: ["T1547.001"]
    },
    "signal_service_persistence": {
      category: "Persistence",
      title: "Service-Based Persistence",
      description: "Detects new Windows service creation used for persistence. Monitors Security Event ID 7045 and Sysmon service events. Fires when new services are installed, especially those with suspicious binary paths (temp folders, user directories) or unusual service names. Review service binary path and signing status.",
      required_sensors: ["security_eventlog"],
      required_facts: ["ServiceInstall"],
      mitre_tactics: ["Persistence", "Privilege Escalation"],
      mitre_techniques: ["T1543.003"]
    },
    "signal_task_persistence": {
      category: "Persistence",
      title: "Scheduled Task Persistence",
      description: "Detects scheduled task creation used for persistence. Monitors schtasks.exe invocations and Task Scheduler event logs. Fires when new tasks are created with suspicious actions (script interpreters, encoded commands) or unusual schedules. May trigger on legitimate automation - verify task purpose.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["ScheduledTask", "Exec"],
      mitre_tactics: ["Persistence", "Execution"],
      mitre_techniques: ["T1053.005"]
    },
    "signal_schtasks_abuse": {
      category: "Persistence",
      title: "Schtasks.exe Abuse",
      description: "Detects suspicious schtasks.exe usage patterns including task creation with encoded commands, tasks running from temp directories, and remote task creation. Commonly abused for persistence and lateral movement. Review the task action and schedule for legitimacy.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Persistence", "Execution"],
      mitre_techniques: ["T1053.005"]
    },
    "signal_sc_abuse": {
      category: "Persistence",
      title: "SC.exe Service Abuse",
      description: "Detects suspicious sc.exe usage for service manipulation including service creation, modification, and configuration changes. Monitors for services being created with suspicious binary paths or being modified to change start types. Review service binary and purpose.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Persistence", "Privilege Escalation"],
      mitre_techniques: ["T1543.003"]
    },
    // Discovery
    "signal_discovery_burst": {
      category: "Discovery",
      title: "Discovery Command Burst",
      description: "Detects rapid execution of multiple discovery commands (whoami, net user, net group, systeminfo, ipconfig, etc.) within a short time window. This pattern is characteristic of post-exploitation reconnaissance. May trigger on legitimate admin troubleshooting - review command sequence and user context.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Discovery"],
      mitre_techniques: ["T1087", "T1082", "T1016", "T1033"]
    },
    "signal_net_command_abuse": {
      category: "Discovery",
      title: "Net Command Reconnaissance",
      description: "Detects suspicious use of net.exe commands for user, group, and share enumeration. Monitors for net user, net group, net localgroup, net share, and net view commands. Common in post-exploitation reconnaissance phases. May trigger on legitimate admin operations.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Discovery"],
      mitre_techniques: ["T1087.001", "T1087.002", "T1135"]
    },
    "signal_group_membership_change": {
      category: "Discovery",
      title: "Group Membership Enumeration",
      description: "Detects enumeration of group memberships and potential privilege escalation through group changes. Monitors for commands querying admin group membership and attempts to add users to privileged groups. Review user context and authorization for group modifications.",
      required_sensors: ["security_eventlog"],
      required_facts: ["AuthEvent"],
      mitre_tactics: ["Discovery", "Privilege Escalation"],
      mitre_techniques: ["T1087.001", "T1078"]
    },
    // Lateral Movement
    "signal_lateral_movement_detection": {
      category: "Lateral Movement",
      title: "Lateral Movement Detection",
      description: "Detects lateral movement indicators including remote logons (RDP, network logon types), administrative share access (C$, ADMIN$, IPC$), remote service creation, and Kerberos ticket anomalies. Requires Security event log access for authentication events. Review source host and user for authorization.",
      required_sensors: ["security_eventlog"],
      required_facts: ["AuthEvent", "NetworkConnect"],
      mitre_tactics: ["Lateral Movement"],
      mitre_techniques: ["T1021.001", "T1021.002", "T1021.006"]
    },
    "signal_logon_anomaly": {
      category: "Lateral Movement",
      title: "Logon Anomaly Detection",
      description: "Detects anomalous logon patterns including unusual logon types, logons from unexpected source hosts, and authentication to sensitive systems. Monitors Security Event IDs 4624, 4625, and 4648. May trigger on legitimate remote administration - verify user and source authorization.",
      required_sensors: ["security_eventlog"],
      required_facts: ["AuthEvent"],
      mitre_tactics: ["Lateral Movement", "Initial Access"],
      mitre_techniques: ["T1078", "T1021"]
    },
    // Collection
    "signal_file_staging": {
      category: "Collection",
      title: "File Staging Detection",
      description: "Detects file collection and staging activities commonly seen before exfiltration. Monitors for archive creation (zip, rar, 7z) in staging directories, large file copies to temp locations, and suspicious file access patterns. May trigger on legitimate backup operations.",
      required_sensors: ["sysmon"],
      required_facts: ["FileCreate", "Exec"],
      mitre_tactics: ["Collection"],
      mitre_techniques: ["T1074", "T1560"]
    },
    // Living Off the Land (LOLBins)
    "signal_lolbin_abuse": {
      category: "Execution",
      title: "LOLBin Abuse Detection",
      description: "Detects abuse of Living-off-the-Land Binaries (LOLBins) - legitimate Windows binaries used for malicious purposes. Monitors certutil, bitsadmin, mshta, regsvr32, rundll32, and other commonly abused utilities. Fires on suspicious command-line patterns. Some benign admin use cases exist.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Execution", "Defense Evasion"],
      mitre_techniques: ["T1218", "T1105"]
    },
    "signal_certutil_abuse": {
      category: "Defense Evasion",
      title: "Certutil Abuse",
      description: "Detects abuse of certutil.exe for file download, encoding/decoding, and hash computation. Monitors for -urlcache, -decode, -encode flags commonly used to download payloads or obfuscate files. May trigger on legitimate certificate operations - review the target files.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Defense Evasion", "Command and Control"],
      mitre_techniques: ["T1140", "T1105"]
    },
    "signal_bitsadmin_abuse": {
      category: "Defense Evasion",
      title: "BITSAdmin Abuse",
      description: "Detects abuse of bitsadmin.exe for file downloads and persistence through BITS jobs. Monitors for /transfer, /create, and /addfile commands used to fetch remote payloads. BITS transfers can bypass some security controls. Review target URLs and files for legitimacy.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Defense Evasion", "Persistence"],
      mitre_techniques: ["T1197", "T1105"]
    },
    "signal_regsvr32_abuse": {
      category: "Defense Evasion",
      title: "Regsvr32 Abuse",
      description: "Detects abuse of regsvr32.exe for proxy execution via /s /n /u /i flags or loading scriptlets from remote URLs. Commonly used to bypass application whitelisting. Fires on network-based scriptlet loads or unusual DLL registrations. Legitimate use is typically for local COM object registration.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Defense Evasion"],
      mitre_techniques: ["T1218.010"]
    },
    "signal_rundll32_abuse": {
      category: "Defense Evasion",
      title: "Rundll32 Abuse",
      description: "Detects suspicious rundll32.exe usage including execution of DLLs from temp folders, JavaScript/VBScript execution via mshtml, and known LOLBin patterns. Monitors for unusual export function calls and network-based DLL loads. Some legitimate software uses rundll32 for DLL execution.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Defense Evasion"],
      mitre_techniques: ["T1218.011"]
    },
    "signal_wmic_abuse": {
      category: "Execution",
      title: "WMIC Abuse",
      description: "Detects suspicious wmic.exe usage for process creation, remote execution, and system reconnaissance. Monitors for wmic process call create, /node: remote execution, and XSL script execution. WMIC is deprecated but still commonly abused. Review remote targets and created processes.",
      required_sensors: ["security_eventlog", "sysmon"],
      required_facts: ["Exec"],
      mitre_tactics: ["Execution", "Lateral Movement"],
      mitre_techniques: ["T1047"]
    }
  };

  /**
   * Compute unified readiness label and score from telemetry data.
   * Returns { label, score, tooltip, isBlocked, isPartial } for consistent display.
   * 
   * Semantics:
   * - "Blocked" = required sensor(s) are blocked/missing (Security log inaccessible OR not admin)
   * - "Partial" = only optional sensors missing (e.g., Sysmon not installed but Security OK)
   * - "Ready" = all required + most optional sensors available
   */
  function computeReadinessStatus(telemetry) {
    if (!telemetry) {
      return { label: 'Unknown', score: 0, tooltip: 'No telemetry data', isBlocked: false, isPartial: false, cssClass: 'badge-stopped' };
    }
    
    const isAdmin = telemetry.is_admin === true;
    const securityOk = telemetry.security_log_accessible === true;
    const sysmonOk = telemetry.sysmon_installed === true;
    
    // Required sensors: admin + security log (for core detection)
    const requiredOk = isAdmin && securityOk;
    // Optional sensors: Sysmon (enhanced detection)
    const optionalOk = sysmonOk;
    
    // Compute score: required sensors weighted 60%, optional 40%
    const requiredCount = (isAdmin ? 1 : 0) + (securityOk ? 1 : 0);
    const requiredTotal = 2;
    const optionalCount = sysmonOk ? 1 : 0;
    const optionalTotal = 1;
    
    const requiredScore = (requiredCount / requiredTotal) * 60;
    const optionalScore = (optionalCount / optionalTotal) * 40;
    const score = Math.round(requiredScore + optionalScore);
    
    // Build tooltip explaining the score
    const parts = [];
    parts.push(`Required: ${requiredCount}/${requiredTotal} (Admin${isAdmin ? '✓' : '✗'}, Security${securityOk ? '✓' : '✗'})`);
    parts.push(`Optional: ${optionalCount}/${optionalTotal} (Sysmon${sysmonOk ? '✓' : '✗'})`);
    const tooltip = parts.join(' | ');
    
    // Determine label
    let label, cssClass, isBlocked = false, isPartial = false;
    
    if (!requiredOk) {
      // Missing required = Blocked
      label = 'Blocked';
      cssClass = 'badge-error';
      isBlocked = true;
    } else if (!optionalOk) {
      // Required OK but optional missing = Partial
      label = 'Partial';
      cssClass = 'badge-running';
      isPartial = true;
    } else {
      // All OK = Ready
      label = 'Ready';
      cssClass = 'badge-live';
    }
    
    return { label, score, tooltip, isBlocked, isPartial, cssClass };
  }

  /**
   * Get enriched playbook data with metadata from PLAYBOOK_METADATA registry
   * Falls back to sensible defaults if metadata not found
   */
  function enrichPlaybookWithMetadata(playbook) {
    const playbookId = playbook.playbook_id || playbook.name || '';
    const metadata = PLAYBOOK_METADATA[playbookId];
    
    if (metadata) {
      return {
        ...playbook,
        category: playbook.category || metadata.category,
        description: playbook.description || metadata.description,
        title: playbook.title || metadata.title || playbook.name,
        // Support both new 'requires' and old 'required_sensors' field names
        requires: playbook.requires || playbook.required_sensors || metadata.required_sensors,
        required_sensors: playbook.requires || playbook.required_sensors || metadata.required_sensors,
        required_facts: playbook.required_facts || metadata.required_facts,
        mitre_tactics: playbook.mitre_tactics || metadata.mitre_tactics,
        mitre_techniques: playbook.mitre_techniques || metadata.mitre_techniques
      };
    }
    
    // Fallback: derive category from playbook_id prefix
    const derivedCategory = derivePlaybookCategory(playbookId);
    const fallbackDescription = `This playbook fires when its required facts are observed. Review the detection slots for specific trigger conditions. This environment may not be collecting all required telemetry for optimal detection coverage.`;
    
    return {
      ...playbook,
      category: playbook.category || derivedCategory,
      description: playbook.description || fallbackDescription,
      // Ensure requires is populated for consistency
      requires: playbook.requires || playbook.required_sensors || [],
      required_sensors: playbook.requires || playbook.required_sensors || []
    };
  }

  /**
   * Derive category from playbook ID prefix when explicit metadata is not available
   */
  function derivePlaybookCategory(playbookId) {
    const id = (playbookId || '').toLowerCase();
    
    if (id.includes('credential')) return 'Credential Access';
    if (id.includes('lateral') || id.includes('logon')) return 'Lateral Movement';
    if (id.includes('persist') || id.includes('service_persist') || id.includes('task_persist') || id.includes('registry_persist')) return 'Persistence';
    if (id.includes('evasion') || id.includes('injection') || id.includes('log_tamper') || id.includes('security_tool')) return 'Defense Evasion';
    if (id.includes('discovery') || id.includes('net_command') || id.includes('group_membership')) return 'Discovery';
    if (id.includes('collection') || id.includes('staging')) return 'Collection';
    if (id.includes('exfil')) return 'Exfiltration';
    if (id.includes('c2') || id.includes('beacon')) return 'Command and Control';
    if (id.includes('impact')) return 'Impact';
    // Default to Execution for most LOLBin and code execution patterns
    if (id.includes('powershell') || id.includes('script') || id.includes('exec') || id.includes('lolbin') || 
        id.includes('certutil') || id.includes('bitsadmin') || id.includes('wmic') || id.includes('mshta') ||
        id.includes('office') || id.includes('rundll') || id.includes('regsvr')) return 'Execution';
    
    return 'Detection';  // Generic fallback, never "Unknown"
  }

  // ============ DOM ELEMENTS ============
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const els = {
    // Banners
    errorBanner: $('#errorBanner'),
    errorBannerText: $('#errorBannerText'),
    errorBannerDismiss: $('#errorBannerDismiss'),
    importedBanner: $('#importedBanner'),
    btnReturnToLocal: $('#btnReturnToLocal'),
    diagnosisBanner: $('#diagnosisBanner'),
    diagnosisText: $('#diagnosisText'),
    diagnosisLink: $('#diagnosisLink'),
    
    // Header
    serverBadge: $('#serverBadge'),
    runStatusBadge: $('#runStatusBadge'),
    settingsGear: $('#settingsGear'),
    
    // Tabs
    tabs: $$('.tab[data-tab]'),
    tabContents: $$('.tab-content'),
    
    // Mission
    profileSelect: $('#profileSelect'),
    durationSelect: $('#durationSelect'),
    playbookPresetSelect: $('#playbookPresetSelect'),
    playbookSelectionSummary: $('#playbookSelectionSummary'),
    playbookSelectedCount: $('#playbookSelectedCount'),
    playbookRunnableCount: $('#playbookRunnableCount'),
    playbookBlockedCount: $('#playbookBlockedCount'),
    btnCustomizePlaybooks: $('#btnCustomizePlaybooks'),
    btnStartRun: $('#btnStartRun'),
    btnStopRun: $('#btnStopRun'),
    runStatus: $('#runStatus'),
    runDuration: $('#runDuration'),
    readinessStatus: $('#readinessStatus'),
    missionError: $('#missionError'),
    missionErrorText: $('#missionErrorText'),
    missionHint: $('#missionHint'),
    missionReadinessWarning: $('#missionReadinessWarning'),
    missionReadinessIssues: $('#missionReadinessIssues'),
    restartAdminSection: $('#restartAdminSection'),
    btnRestartAdmin: $('#btnRestartAdmin'),
    restartAdminHint: $('#restartAdminHint'),
    
    // Mission System Readiness & Detection Plan Card
    missionReadinessLabel: $('#missionReadinessLabel'),
    missionReadinessStatus: $('#missionReadinessStatus'),
    missionSensorsAvailable: $('#missionSensorsAvailable'),
    missionSensorsTotal: $('#missionSensorsTotal'),
    missionChannelsAccessible: $('#missionChannelsAccessible'),
    missionChannelsTotal: $('#missionChannelsTotal'),
    btnMissionViewReadiness: $('#btnMissionViewReadiness'),
    btnMissionRerunReadiness: $('#btnMissionRerunReadiness'),
    btnMissionLoadPlan: $('#btnMissionLoadPlan'),
    missionPlanEnabled: $('#missionPlanEnabled'),
    missionPlanBlocked: $('#missionPlanBlocked'),
    missionPlanPanel: $('#missionPlanPanel'),
    missionPlanSearch: $('#missionPlanSearch'),
    missionPlanList: $('#missionPlanList'),
    
    // Counters
    counterEvents: $('#counterEvents'),
    counterSegments: $('#counterSegments'),
    counterFacts: $('#counterFacts'),
    counterSignals: $('#counterSignals'),
    dedupeStatus: $('#dedupeStatus'),
    suppressionTime: $('#suppressionTime'),
    
    // Noise diagnostics
    noiseContent: $('#noiseContent'),
    noiseHint: $('#noiseHint'),
    signalsPerMin: $('#signalsPerMin'),
    topPlaybook: $('#topPlaybook'),
    topEntity: $('#topEntity'),
    dedupeCount: $('#dedupeCount'),
    
    // Error actions
    btnCopyBuildCmd: $('#btnCopyBuildCmd'),
    btnRetryStart: $('#btnRetryStart'),
    
    // Debug: Validation helper
    validationHelper: $('#validationHelper'),
    btnCopyValidationCmd: $('#btnCopyValidationCmd'),
    
    // Runs
    runsEmpty: $('#runsEmpty'),
    runsContent: $('#runsContent'),
    runsList: $('#runsList'),
    runDetailEmpty: $('#runDetailEmpty'),
    runDetail: $('#runDetail'),
    runDetailTitle: $('#runDetailTitle'),
    runDetailTime: $('#runDetailTime'),
    detailEvents: $('#detailEvents'),
    detailSegments: $('#detailSegments'),
    detailFacts: $('#detailFacts'),
    detailSignals: $('#detailSignals'),
    btnGoToMission: $('#btnGoToMission'),
    btnViewFindings: $('#btnViewFindings'),
    btnExportRun: $('#btnExportRun'),
    
    // Run detail tabs & content
    runTabs: $$('.run-tab[data-run-tab]'),
    runTabOverview: $('#runTabOverview'),
    runTabChanges: $('#runTabChanges'),
    runTabFindings: $('#runTabFindings'),
    runTabPlaybooks: $('#runTabPlaybooks'),
    runTabTimeline: $('#runTabTimeline'),
    runTabExplain: $('#runTabExplain'),
    runTabExplore: $('#runTabExplore'),
    runTabRaw: $('#runTabRaw'),
    
    // Overview tab
    dataSources: $('#dataSources'),
    detailProfile: $('#detailProfile'),
    detailDuration: $('#detailDuration'),
    detailHosts: $('#detailHosts'),
    detailMode: $('#detailMode'),
    // Discovery Workflow panels
    discoverySummaryPanel: $('#discoverySummaryPanel'),
    discoverySummaryCount: $('#discoverySummaryCount'),
    discoveryChangeGrid: $('#discoveryChangeGrid'),
    discoveryMilestonesList: $('#discoveryMilestonesList'),
    discoveryVisibilityLimits: $('#discoveryVisibilityLimits'),
    discoveryLimitsList: $('#discoveryLimitsList'),
    
    // Changes tab (Diff v2)
    changesLoading: $('#changesLoading'),
    changesEmpty: $('#changesEmpty'),
    changesContent: $('#changesContent'),
    changesUnavailable: $('#changesUnavailable'),
    changesMissingEndpoint: $('#changesMissingEndpoint'),
    changesTotalCount: $('#changesTotalCount'),
    changesAddedCount: $('#changesAddedCount'),
    changesRemovedCount: $('#changesRemovedCount'),
    changesModifiedCount: $('#changesModifiedCount'),
    changesHighlightsList: $('#changesHighlightsList'),
    changesCategoriesList: $('#changesCategoriesList'),
    changesAllList: $('#changesAllList'),
    // Diff v2 controls
    diffModeSelect: $('#diffModeSelect'),
    diffPhaseOptions: $('#diffPhaseOptions'),
    diffPhaseMinutes: $('#diffPhaseMinutes'),
    diffBaselineOptions: $('#diffBaselineOptions'),
    diffBaselineRunId: $('#diffBaselineRunId'),
    diffMarkerOptions: $('#diffMarkerOptions'),
    diffMarkerTs: $('#diffMarkerTs'),
    btnRefreshDiff: $('#btnRefreshDiff'),
    diffComparisonHeader: $('#diffComparisonHeader'),
    diffComparisonLabel: $('#diffComparisonLabel'),
    diffCaveatsBanner: $('#diffCaveatsBanner'),
    diffCaveatsList: $('#diffCaveatsList'),
    diffCategoryFilter: $('#diffCategoryFilter'),
    diffDirectionFilter: $('#diffDirectionFilter'),
    
    // Playbooks tab
    playbooksLoading: $('#playbooksLoading'),
    playbooksDisabled: $('#playbooksDisabled'),
    playbooksContent: $('#playbooksContent'),
    playbooksUnavailable: $('#playbooksUnavailable'),
    playbooksMissingEndpoint: $('#playbooksMissingEndpoint'),
    playbooksLoadedCount: $('#playbooksLoadedCount'),
    playbooksFiredCount: $('#playbooksFiredCount'),
    playbooksPartialCount: $('#playbooksPartialCount'),
    playbooksBlockedCount: $('#playbooksBlockedCount'),
    playbooksExplanation: $('#playbooksExplanation'),
    playbooksDirPath: $('#playbooksDirPath'),
    playbooksNoMatches: $('#playbooksNoMatches'),
    playbooksMatchesList: $('#playbooksMatchesList'),
    playbooksMatchesSection: $('#playbooksMatchesSection'),
    playbooksByCategorySection: $('#playbooksByCategorySection'),
    playbooksCategoriesList: $('#playbooksCategoriesList'),
    playbooksNearMissesSection: $('#playbooksNearMissesSection'),
    playbooksNearMissesList: $('#playbooksNearMissesList'),
    playbooksEvalSection: $('#playbooksEvalSection'),
    playbooksEvalList: $('#playbooksEvalList'),
    playbooksStatusFilter: $('#playbooksStatusFilter'),
    
    // System State panel (Part A)
    runStatePanel: $('#runStatePanel'),
    stateTelemetryBadge: $('#stateTelemetryBadge'),
    stateSensorsList: $('#stateSensorsList'),
    stateFactsCount: $('#stateFactsCount'),
    stateSignalsCount: $('#stateSignalsCount'),
    stateTopProcess: $('#stateTopProcess'),
    stateEntitiesSection: $('#stateEntitiesSection'),
    stateEntitiesList: $('#stateEntitiesList'),
    stateNotesSection: $('#stateNotesSection'),
    stateNotesList: $('#stateNotesList'),
    
    // Next Steps panel (Workflow Guidance)
    runNextStepsPanel: $('#runNextStepsPanel'),
    nextStepsSeverityBadge: $('#nextStepsSeverityBadge'),
    nextStepsSummary: $('#nextStepsSummary'),
    nextStepsActions: $('#nextStepsActions'),
    coverageChecklist: $('#coverageChecklist'),
    coverageChecklistItems: $('#coverageChecklistItems'),
    
    // Findings tab
    findingsEmpty: $('#findingsEmpty'),
    findingsContent: $('#findingsContent'),
    findingsUnavailable: $('#findingsUnavailable'),
    findingsMissingEndpoint: $('#findingsMissingEndpoint'),
    findingsCount: $('#findingsCount'),
    findingsSeverityFilter: $('#findingsSeverityFilter'),
    findingsList: $('#findingsList'),
    
    // Timeline tab
    timelineEmpty: $('#timelineEmpty'),
    timelineContent: $('#timelineContent'),
    timelineUnavailable: $('#timelineUnavailable'),
    timelineMissingEndpoint: $('#timelineMissingEndpoint'),
    timelineList: $('#timelineList'),
    
    // Facts tab
    runTabFacts: $('#runTabFacts'),
    factsLoading: $('#factsLoading'),
    factsEmpty: $('#factsEmpty'),
    factsNoTelemetry: $('#factsNoTelemetry'),
    factsNoTelemetryReasons: $('#factsNoTelemetryReasons'),
    factsNoTelemetryFixes: $('#factsNoTelemetryFixes'),
    factsContent: $('#factsContent'),
    factsUnavailable: $('#factsUnavailable'),
    factsMissingEndpoint: $('#factsMissingEndpoint'),
    factsTotalCount: $('#factsTotalCount'),
    factsTypeCount: $('#factsTypeCount'),
    factsHostCount: $('#factsHostCount'),
    factsTypeRows: $('#factsTypeRows'),
    factsHostsList: $('#factsHostsList'),
    factsSensorsSection: $('#factsSensorsSection'),
    factsSensorsList: $('#factsSensorsList'),
    playbookSummarySection: $('#playbookSummarySection'),
    playbookSummaryContent: $('#playbookSummaryContent'),
    playbookLoadedCount: $('#playbookLoadedCount'),
    playbookEnabledCount: $('#playbookEnabledCount'),
    playbookFiredCount: $('#playbookFiredCount'),
    playbookCategoriesList: $('#playbookCategoriesList'),
    whyNoSignalsPanel: $('#whyNoSignalsPanel'),
    whyNoSignalsContent: $('#whyNoSignalsContent'),
    pipelineDiagnostics: $('#pipelineDiagnostics'),
    
    // Explain tab
    explainSelectPrompt: $('#explainSelectPrompt'),
    explainContent: $('#explainContent'),
    explainUnavailable: $('#explainUnavailable'),
    explainMissingEndpoint: $('#explainMissingEndpoint'),
    // Explain Header (canonical summary)
    explainUnavailableBanner: $('#explainUnavailableBanner'),
    explainUnavailableReason: $('#explainUnavailableReason'),
    explainUnavailableMessage: $('#explainUnavailableMessage'),
    explainHeaderSummary: $('#explainHeaderSummary'),
    explainHeaderSource: $('#explainHeaderSource'),
    explainHeaderEvidence: $('#explainHeaderEvidence'),
    explainHeaderConfidence: $('#explainHeaderConfidence'),
    explainHeaderRun: $('#explainHeaderRun'),
    // Signal details
    explainSignalType: $('#explainSignalType'),
    explainSignalId: $('#explainSignalId'),
    explainSeverity: $('#explainSeverity'),
    explainNarrativeSection: $('#explainNarrativeSection'),
    explainNarrative: $('#explainNarrative'),
    explainDetectorSection: $('#explainDetectorSection'),
    explainPlaybook: $('#explainPlaybook'),
    explainDetectorVersion: $('#explainDetectorVersion'),
    explainEntitiesSection: $('#explainEntitiesSection'),
    explainEntities: $('#explainEntities'),
    explainEvidenceSection: $('#explainEvidenceSection'),
    explainEvidence: $('#explainEvidence'),
    explainScoringSection: $('#explainScoringSection'),
    explainScoring: $('#explainScoring'),
    explainSlotsSection: $('#explainSlotsSection'),
    explainSlots: $('#explainSlots'),
    
    // Explore tab (PRO - Entity Explorer)
    exploreLoading: $('#exploreLoading'),
    exploreProLocked: $('#exploreProLocked'),
    exploreEmpty: $('#exploreEmpty'),
    exploreContent: $('#exploreContent'),
    exploreUnavailable: $('#exploreUnavailable'),
    exploreMissingEndpoint: $('#exploreMissingEndpoint'),
    exploreSearchInput: $('#exploreSearchInput'),
    exploreEntityList: $('#exploreEntityList'),
    exploreEntityCount: $('#exploreEntityCount'),
    explorePivotHeader: $('#explorePivotHeader'),
    explorePivotEmpty: $('#explorePivotEmpty'),
    explorePivotContent: $('#explorePivotContent'),
    explorePivotFindingsCount: $('#explorePivotFindingsCount'),
    explorePivotFindingsList: $('#explorePivotFindingsList'),
    explorePivotChangesCount: $('#explorePivotChangesCount'),
    explorePivotChangesList: $('#explorePivotChangesList'),
    explorePivotEvidenceCount: $('#explorePivotEvidenceCount'),
    explorePivotEvidenceList: $('#explorePivotEvidenceList'),
    explorePivotTimelineList: $('#explorePivotTimelineList'),
    explorePivotActions: $('#explorePivotActions'),
    btnPivotOpenExplain: $('#btnPivotOpenExplain'),
    btnPivotExportCasePack: $('#btnPivotExportCasePack'),
    
    // Raw JSON tab
    rawSelectPrompt: $('#rawSelectPrompt'),
    rawContent: $('#rawContent'),
    rawJson: $('#rawJson'),
    btnCopyRawJson: $('#btnCopyRawJson'),
    
    // Import/Export
    importDropZone: $('#importDropZone'),
    importFileInput: $('#importFileInput'),
    btnExportBundle: $('#btnExportBundle'),
    
    // Settings
    settingsReadinessStatus: $('#settingsReadinessStatus'),
    settingsLicenseStatus: $('#settingsLicenseStatus'),
    btnRunChecks: $('#btnRunChecks'),
    readinessSummary: $('#readinessSummary'),
    connectionDetails: $('#connectionDetails'),
    connectionDetailsToggle: $('#connectionDetailsToggle'),
    btnViewConnectionDetails: $('#btnViewConnectionDetails'),
    apiBaseUrl: $('#apiBaseUrl'),
    lastErrorMsg: $('#lastErrorMsg'),
    // Settings - Detection Plan
    settingsDetectionPlanCount: $('#settingsDetectionPlanCount'),
    settingsDetectionPlanPanel: $('#settingsDetectionPlanPanel'),
    settingsPlanSearch: $('#settingsPlanSearch'),
    settingsPlanList: $('#settingsPlanList'),
    
    // Detection Plan
    detectionPlanStatus: $('#detectionPlanStatus'),
    detectionPlanSummary: $('#detectionPlanSummary'),
    detectionPlanPanel: $('#detectionPlanPanel'),
    detectionPlanContent: $('#detectionPlanContent'),
    btnLoadDetectionPlan: $('#btnLoadDetectionPlan'),
    dpTotalEnabled: $('#dpTotalEnabled'),
    dpTotalBlocked: $('#dpTotalBlocked'),
    dpRequiresSysmon: $('#dpRequiresSysmon'),
    dpRequiresAdmin: $('#dpRequiresAdmin'),
    dpSearchInput: $('#dpSearchInput'),
    dpPlaybookList: $('#dpPlaybookList'),
    
    // Team Case Store
    tabBtnTeam: $('#tabBtnTeam'),
    teamTierLockBanner: $('#teamTierLockBanner'),
    teamUpgradeLink: $('#teamUpgradeLink'),
    teamContent: $('#teamContent'),
    teamStoreStatusBadge: $('#teamStoreStatusBadge'),
    teamStorePath: $('#teamStorePath'),
    teamStoreStats: $('#teamStoreStats'),
    teamCaseCount: $('#teamCaseCount'),
    teamUnreadableCount: $('#teamUnreadableCount'),
    teamStoreReason: $('#teamStoreReason'),
    teamStoreLastRefresh: $('#teamStoreLastRefresh'),
    btnConfigureStore: $('#btnConfigureStore'),
    btnRefreshStore: $('#btnRefreshStore'),
    btnCopyStoreDiagnostics: $('#btnCopyStoreDiagnostics'),
    createCaseHeader: $('#createCaseHeader'),
    createCaseForm: $('#createCaseForm'),
    createCaseToggle: $('#createCaseToggle'),
    newCaseTitle: $('#newCaseTitle'),
    newCaseDescription: $('#newCaseDescription'),
    newCaseTags: $('#newCaseTags'),
    btnCreateCase: $('#btnCreateCase'),
    teamCaseSearch: $('#teamCaseSearch'),
    teamCaseTagFilter: $('#teamCaseTagFilter'),
    teamCaseSortBy: $('#teamCaseSortBy'),
    teamCaseHasRunsFilter: $('#teamCaseHasRunsFilter'),
    teamCaseList: $('#teamCaseList'),
    teamCaseDetailEmpty: $('#teamCaseDetailEmpty'),
    teamCaseDetail: $('#teamCaseDetail'),
    teamCaseTitle: $('#teamCaseTitle'),
    teamCaseId: $('#teamCaseId'),
    teamCaseProvenance: $('#teamCaseProvenance'),
    teamCaseTags: $('#teamCaseTags'),
    teamCaseDescription: $('#teamCaseDescription'),
    teamCaseNewTag: $('#teamCaseNewTag'),
    btnAddCaseTag: $('#btnAddCaseTag'),
    btnCopyCaseId: $('#btnCopyCaseId'),
    btnPublishRunToCase: $('#btnPublishRunToCase'),
    btnImportSelectedRuns: $('#btnImportSelectedRuns'),
    teamCaseRuns: $('#teamCaseRuns'),
    teamCaseRunsTab: $('#teamCaseRunsTab'),
    teamCaseNotesTab: $('#teamCaseNotesTab'),
    teamCaseTagsTab: $('#teamCaseTagsTab'),
    teamCaseOverviewTab: $('#teamCaseOverviewTab'),
    teamCaseTabsContainer: $('#teamCaseTabsContainer'),
    teamCaseTagsList: $('#teamCaseTagsList'),
    teamBulkImportProgress: $('#teamBulkImportProgress'),
    teamBulkImportBar: $('#teamBulkImportBar'),
    teamBulkImportStatus: $('#teamBulkImportStatus'),
    teamCaseNotes: $('#teamCaseNotes'),
    teamCaseNewNote: $('#teamCaseNewNote'),
    btnAddCaseNote: $('#btnAddCaseNote'),
    teamCaseOverviewEmpty: $('#teamCaseOverviewEmpty'),
    teamCaseOverviewContent: $('#teamCaseOverviewContent'),
    teamStoreConfigModal: $('#teamStoreConfigModal'),
    teamStorePathInput: $('#teamStorePathInput'),
    btnCancelStoreConfig: $('#btnCancelStoreConfig'),
    btnSaveStoreConfig: $('#btnSaveStoreConfig'),
    teamPublishRunModal: $('#teamPublishRunModal'),
    teamPublishRunSelect: $('#teamPublishRunSelect'),
    btnCancelPublishRun: $('#btnCancelPublishRun'),
    btnConfirmPublishRun: $('#btnConfirmPublishRun')
  };

  // ============ UTILITIES ============
  function formatDuration(seconds) {
    if (seconds === null || seconds === undefined || isNaN(seconds)) return '—';
    const secs = Math.floor(seconds);
    const mins = Math.floor(secs / 60);
    const hrs = Math.floor(mins / 60);
    return `${String(hrs).padStart(2, '0')}:${String(mins % 60).padStart(2, '0')}:${String(secs % 60).padStart(2, '0')}`;
  }

  function formatTimestamp(ts) {
    if (!ts) return 'Unknown time';
    const d = new Date(ts);
    if (isNaN(d.getTime())) return 'Unknown time';
    return d.toLocaleDateString('en-US', { 
      month: 'short', day: 'numeric', year: 'numeric' 
    }) + ' at ' + d.toLocaleTimeString('en-US', { 
      hour: 'numeric', minute: '2-digit' 
    });
  }

  /**
   * Format value for display:
   * - null/undefined => "—"
   * - 0 => "0"
   * - number => localized string
   */
  function formatValue(val) {
    if (val === null || val === undefined) return '—';
    if (typeof val === 'number') return val.toLocaleString();
    return String(val);
  }

  /**
   * Escape HTML special characters to prevent XSS
   */
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Get badge class for severity level
   */
  function getSeverityClass(severity) {
    const mapping = {
      'critical': 'error',
      'high': 'error',
      'medium': 'warn',
      'low': 'info',
      'info': 'info'
    };
    return mapping[severity?.toLowerCase()] || 'info';
  }

  // ============ STATUS BADGE HELPER ============
  // Single source of truth for status indicator rendering
  // 
  // Status Semantics:
  // - active: facts/events observed in current run (positive/green) ✅
  // - configured: accessible but no events yet (neutral/gray-blue) ⚙️
  // - missing: not installed/present (negative/red) ⛔
  // - blocked: present but inaccessible (negative/amber) 🔒
  // - disabled: explicitly disabled by config (neutral/gray) 🚫
  // - enabled: playbook requirements met, will evaluate (neutral) —
  // - fired: playbook matched and produced signal (positive/green) ✅
  // - partial: near miss or some conditions met (amber) ⚠️
  //
  // Usage: getStatusBadge('configured', 'Configured (no events yet)', 'Requires Sysmon')
  
  const STATUS_CONFIG = {
    active:     { icon: '✅', cssClass: 'badge--active',     label: 'Active' },
    configured: { icon: '⚙️', cssClass: 'badge--configured', label: 'Configured' },
    missing:    { icon: '⛔', cssClass: 'badge--missing',    label: 'Missing' },
    blocked:    { icon: '🔒', cssClass: 'badge--blocked',    label: 'Blocked' },
    disabled:   { icon: '🚫', cssClass: 'badge--disabled',   label: 'Disabled' },
    enabled:    { icon: '',   cssClass: 'badge--enabled',    label: 'Enabled' },
    fired:      { icon: '✅', cssClass: 'badge--fired',      label: 'Fired' },
    partial:    { icon: '⚠️', cssClass: 'badge--partial',    label: 'Partial' },
    // Fallback for unknown statuses
    unknown:    { icon: '?',  cssClass: 'badge-stopped',     label: 'Unknown' },
  };
  
  /**
   * Get a consistent status badge HTML string
   * @param {string} status - Status key (active, configured, missing, blocked, disabled, enabled, fired, partial)
   * @param {string} [statusLabel] - Optional display label (defaults to status name)
   * @param {string} [reason] - Optional reason message (shown as tooltip or inline)
   * @param {object} [options] - Additional options
   * @param {boolean} [options.showIcon=true] - Whether to show the icon
   * @param {boolean} [options.small=false] - Use smaller badge style
   * @param {boolean} [options.inlineReason=false] - Show reason inline instead of tooltip
   * @returns {string} HTML string for the badge
   */
  function getStatusBadge(status, statusLabel, reason, options = {}) {
    const { showIcon = true, small = false, inlineReason = false } = options;
    
    // Normalize status key
    const statusKey = (status || 'unknown').toLowerCase().replace(/[^a-z]/g, '');
    const config = STATUS_CONFIG[statusKey] || STATUS_CONFIG.unknown;
    
    // Determine display text
    const displayLabel = statusLabel || config.label;
    
    // Build badge
    const iconHtml = showIcon && config.icon ? `<span style="margin-right: 4px;">${config.icon}</span>` : '';
    const sizeStyle = small ? 'font-size: 10px; padding: 2px 6px;' : '';
    const titleAttr = reason && !inlineReason ? `title="${escapeHtml(reason)}"` : '';
    
    let html = `<span class="badge ${config.cssClass}" style="${sizeStyle}" ${titleAttr}>${iconHtml}${escapeHtml(displayLabel)}</span>`;
    
    // Optionally show reason inline
    if (reason && inlineReason) {
      html += `<span style="font-size: 10px; color: var(--muted); margin-left: 6px;">${escapeHtml(reason)}</span>`;
    }
    
    return html;
  }
  
  /**
   * Get sensor status badge based on sensor data
   * Maps sensor status to consistent badge appearance
   * @param {object} sensor - Sensor object with status, status_label, message fields
   * @returns {string} HTML badge string
   */
  function getSensorStatusBadge(sensor) {
    const status = sensor.status || 'unknown';
    const label = sensor.status_label || status;
    const reason = sensor.message || sensor.reason_code;
    return getStatusBadge(status, label, reason, { small: true });
  }
  
  /**
   * Get playbook status badge based on derived_status
   * @param {object} playbook - Playbook info with derived_status, blocked_by, reasons fields
   * @returns {string} HTML badge string
   */
  function getPlaybookStatusBadge(playbook) {
    const derivedStatus = playbook.derived_status || playbook.status || 'unknown';
    
    // Map derived_status to our status system
    const statusMap = {
      'enabled': 'enabled',
      'ok': 'enabled',            // Backend returns 'ok' for runnable
      'blocked_by_telemetry': 'blocked',
      'blocked': 'blocked',
      'disabled_by_config': 'disabled',
      'disabled': 'disabled',
      'skipped_invalid': 'missing',
      'skipped': 'missing',
      'fired': 'fired',
    };
    
    const status = statusMap[derivedStatus] || 'unknown';
    
    // Build label - use RUNNABLE for enabled playbooks to make it crystal clear
    const labelMap = {
      'enabled': 'RUNNABLE',
      'ok': 'RUNNABLE',
      'blocked_by_telemetry': 'BLOCKED',
      'blocked': 'BLOCKED',
      'disabled_by_config': 'DISABLED',
      'disabled': 'DISABLED',
      'skipped_invalid': 'SKIPPED',
      'skipped': 'SKIPPED',
      'fired': 'FIRED',
    };
    const label = labelMap[derivedStatus] || derivedStatus.toUpperCase();
    
    // Build reason from blocked_by or reasons
    let reason = '';
    if (playbook.blocked_by && playbook.blocked_by.length > 0) {
      reason = `Blocked by: ${playbook.blocked_by.join(', ')}`;
    } else if (playbook.reasons && playbook.reasons.length > 0) {
      reason = playbook.reasons[0];
    }
    
    return getStatusBadge(status, label, reason, { small: true });
  }
  
  /**
   * Get attack surface coverage badge
   * @param {object} surface - Attack surface object with status, status_label, configured_sensors, missing_sensors
   * @returns {string} HTML badge string
   */
  function getAttackSurfaceBadge(surface) {
    const status = surface.status || 'unknown';
    
    // Map attack surface status to our system
    // Note: "configured" means sensors accessible, "partial" means some blocked, "blocked" means no sensors
    const statusMap = {
      'configured': 'configured',
      'covered': 'active',      // "covered" only in run views with observed facts
      'partial': 'partial',
      'blocked': 'blocked',
    };
    
    const mappedStatus = statusMap[status] || status;
    const label = surface.status_label || status;
    
    // Build reason from missing sensors
    let reason = '';
    if (surface.missing_sensors && surface.missing_sensors.length > 0) {
      reason = `Missing: ${surface.missing_sensors.join(', ')}`;
    } else if (surface.blocked_reason) {
      reason = surface.blocked_reason;
    }
    
    return getStatusBadge(mappedStatus, label, reason, { small: true });
  }

  // ============ ERROR HANDLING ============
  function showError(message, options = {}) {
    const { 
      inCard = false, 
      showActions = false, 
      isMissingBinaries = false,
      fixCommands = [],
      endpoint = null 
    } = options;
    
    state.lastError = message;
    state.lastErrorEndpoint = endpoint;
    state.fixCommands = fixCommands.length > 0 ? fixCommands : null;
    
    // Build error message with endpoint hint
    let displayMsg = message;
    if (endpoint) {
      displayMsg = `${message} [${endpoint}]`;
    }
    
    if (els.errorBanner) {
      els.errorBanner.classList.remove('hidden');
      els.errorBannerText.textContent = displayMsg;
    }
    
    if (inCard && els.missionError) {
      els.missionError.classList.remove('hidden');
      
      // Build rich error message with fix commands
      let errorHtml = `<strong>${message}</strong>`;
      if (isMissingBinaries && fixCommands.length > 0) {
        errorHtml += '<br><br><strong>Run these commands in terminal:</strong><pre style="background:#1a1a2e;padding:8px;border-radius:4px;font-size:12px;overflow-x:auto">';
        errorHtml += fixCommands.join('\n');
        errorHtml += '</pre>';
      }
      els.missionErrorText.innerHTML = errorHtml;
      
      // Show action buttons for recoverable errors
      if (showActions || isMissingBinaries) {
        if (els.btnCopyBuildCmd) els.btnCopyBuildCmd.classList.remove('hidden');
        if (els.btnRetryStart) els.btnRetryStart.classList.remove('hidden');
      } else {
        if (els.btnCopyBuildCmd) els.btnCopyBuildCmd.classList.add('hidden');
        if (els.btnRetryStart) els.btnRetryStart.classList.add('hidden');
      }
    }
    
    // Update connection details
    if (els.apiBaseUrl) els.apiBaseUrl.textContent = API_BASE;
    if (els.lastErrorMsg) els.lastErrorMsg.textContent = message;
  }

  function hideError() {
    state.lastError = null;
    state.lastErrorEndpoint = null;
    state.fixCommands = null;
    if (els.errorBanner) els.errorBanner.classList.add('hidden');
    if (els.missionError) els.missionError.classList.add('hidden');
    if (els.btnCopyBuildCmd) els.btnCopyBuildCmd.classList.add('hidden');
    if (els.btnRetryStart) els.btnRetryStart.classList.add('hidden');
  }

  function copyBuildCommands() {
    // Use fix commands from state if available
    const commands = state.fixCommands 
      ? state.fixCommands.join('\n')
      : `cargo build --release -p agent-windows --bin capture_windows_rotating
cargo build --release -p edr-locald --bin edr-locald`;
    
    navigator.clipboard.writeText(commands).then(() => {
      if (els.btnCopyBuildCmd) {
        const orig = els.btnCopyBuildCmd.textContent;
        els.btnCopyBuildCmd.textContent = '✅ Copied!';
        setTimeout(() => { els.btnCopyBuildCmd.textContent = orig; }, 2000);
      }
    }).catch((err) => {
      console.warn('[copyBuildCommands] Clipboard failed:', err);
      alert('Build commands:\n\n' + commands);
    });
  }

  /**
   * Copy validation trigger command to clipboard (debug mode helper)
   * This command runs `whoami` encoded as base64, triggering the encoded PowerShell detection
   */
  function copyValidationCommand() {
    // The encoded command is: whoami (UTF-16LE base64)
    // dwBoAG8AYQBtAGkA = "whoami" in UTF-16LE base64
    const cmd = 'powershell.exe -NoProfile -EncodedCommand dwBoAG8AYQBtAGkA';
    
    navigator.clipboard.writeText(cmd).then(() => {
      if (els.btnCopyValidationCmd) {
        const orig = els.btnCopyValidationCmd.textContent;
        els.btnCopyValidationCmd.textContent = '✅ Copied!';
        setTimeout(() => { els.btnCopyValidationCmd.textContent = orig; }, 2000);
      }
      console.log('[Validation] Command copied. Run in Admin PowerShell to trigger detection.');
    }).catch((err) => {
      console.warn('[copyValidationCommand] Clipboard failed:', err);
      alert('Validation command:\n\n' + cmd + '\n\nRun this in an Administrator PowerShell window.');
    });
  }

  // ============ API HELPER ============
  class ApiError extends Error {
    constructor(message, status, code = null, body = null, endpoint = null) {
      super(message);
      this.name = 'ApiError';
      this.status = status;
      this.code = code;
      this.body = body;
      this.endpoint = endpoint;
    }
  }

  /**
   * Log API call to debug panel
   * Enhanced: shows context (run_id, signal_id), HTML detection, response preview
   */
  function logApiCall(method, endpoint, status, error = null, extra = {}) {
    const entry = {
      time: new Date().toLocaleTimeString(),
      method,
      endpoint,
      status,
      error,
      isHtml: extra.isHtml || false,
      htmlPreview: extra.htmlPreview || null,
      context: extra.context || null  // e.g., "run_1234" or "signal_abc"
    };
    apiCallLog.unshift(entry);
    if (apiCallLog.length > MAX_API_LOG) apiCallLog.pop();
    renderDebugPanel();
  }

  /**
   * Render debug API panel (only if DEBUG_MODE)
   * Enhanced: shows context, HTML marker with preview, API_BASE info
   */
  function renderDebugPanel() {
    if (!DEBUG_MODE) return;
    const panel = document.getElementById('debugApiPanel');
    const log = document.getElementById('debugApiLog');
    if (!panel || !log) return;
    
    panel.classList.remove('hidden');
    
    // Show API origin info at top
    const originInfo = `<div style="margin-bottom: 8px; padding: 4px; background: var(--bg-alt); border-radius: 4px; font-size: 11px;">
      <div><strong>API_BASE:</strong> ${API_BASE}</div>
      <div><strong>window.location.origin:</strong> ${window.location.origin}</div>
      <div><strong>state.isRunning:</strong> ${state.isRunning} | <strong>state.runId:</strong> ${state.runId || 'null'}</div>
      <div><strong>signalsCursor:</strong> ${state.signalsCursor}</div>
    </div>`;
    
    if (apiCallLog.length === 0) {
      log.innerHTML = originInfo + '<div style="color: var(--muted);">No API calls yet</div>';
      return;
    }
    
    log.innerHTML = originInfo + apiCallLog.map(e => {
      const statusColor = e.status === 200 ? 'var(--good)' : e.status === 404 ? 'var(--warn)' : e.status === 0 ? 'var(--bad)' : 'var(--muted)';
      const errorPart = e.error ? ` - ${e.error}` : '';
      const htmlMarker = e.isHtml ? '<span style="color: var(--bad); font-weight: bold;"> [HTML!]</span>' : '';
      const contextPart = e.context ? `<span style="color: var(--accent); font-size: 10px;"> (${e.context})</span>` : '';
      const htmlPreviewPart = e.htmlPreview ? `<div style="color: var(--bad); font-size: 10px; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${e.htmlPreview}</div>` : '';
      
      return `<div style="margin-bottom: 4px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 4px;">
        <span style="color: var(--muted);">${e.time}</span> 
        <span style="color: var(--accent);">${e.method}</span> 
        <span>${e.endpoint}</span>${contextPart}
        <span style="color: ${statusColor};">[${e.status}]</span>${htmlMarker}
        ${errorPart ? `<div style="color: var(--bad); font-size: 10px;">${errorPart}</div>` : ''}
        ${htmlPreviewPart}
      </div>`;
    }).join('');
  }

  /**
   * Robust API helper with:
   * - HTML response detection (shows "API returned HTML; check same-origin and base path")
   * - {data: ...} wrapper unwrapping
   * - Structured error with status code and endpoint
   * - Debug logging (when ?debug=1) with context
   */
  async function api(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const method = options.method || 'GET';
    
    // Extract context for debug panel (run_id, signal_id from endpoint)
    let context = null;
    if (endpoint.includes('/api/signals/') && !endpoint.includes('/stats')) {
      const match = endpoint.match(/\/api\/signals\/([^\/]+)/);
      if (match) context = `signal:${match[1].slice(0,8)}...`;
    } else if (state.selectedRun?.run_id && endpoint.includes('/api/signals')) {
      context = `run:${state.selectedRun.run_id}`;
    }
    
    console.log(`[API] ${method} ${endpoint}${context ? ` [${context}]` : ''}`);
    
    try {
      const fetchOptions = {
        method,
        headers: {},
        ...options
      };
      
      // Set content-type for JSON body
      if (options.body && typeof options.body === 'string') {
        fetchOptions.headers['Content-Type'] = 'application/json';
      }
      
      const res = await fetch(url, fetchOptions);
      const contentType = res.headers.get('content-type') || '';
      
      // Check for HTML response (wrong route or error page)
      if (contentType.includes('text/html')) {
        const text = await res.text();
        const preview = text.slice(0, 60).replace(/</g, '&lt;').replace(/>/g, '&gt;');
        console.error(`[API] Received HTML instead of JSON for ${endpoint}:`, text.slice(0, 200));
        
        // Log with HTML marker and preview
        logApiCall(method, endpoint, res.status, 'HTML response', { isHtml: true, htmlPreview: preview, context });
        
        throw new ApiError(
          'API returned HTML; check same-origin (:3000) and base path',
          res.status,
          'HTML_RESPONSE',
          null,
          endpoint
        );
      }
      
      // Log successful call
      logApiCall(method, endpoint, res.status, null, { context });
      
      // Check HTTP status
      if (!res.ok) {
        let errorBody = null;
        try {
          errorBody = await res.json();
        } catch (e) {
          errorBody = { message: res.statusText };
        }
        
        const errorMsg = errorBody?.error || errorBody?.message || `HTTP ${res.status}`;
        const errorCode = errorBody?.code || null;
        
        throw new ApiError(errorMsg, res.status, errorCode, errorBody, endpoint);
      }
      
      // Parse JSON
      const data = await res.json();
      
      // Unwrap wrapper shapes:
      // - {success: true, data: X} -> X
      // - {data: X} -> X (if no other meaningful keys)
      // - raw array/object -> as-is
      if (data && typeof data === 'object' && !Array.isArray(data)) {
        const keys = Object.keys(data);
        // Unwrap {success: bool, data: X} or just {data: X}
        if ('data' in data && (keys.length <= 2 || (keys.includes('success') && keys.length === 2))) {
          console.log(`[API] Unwrapping {data: ...} wrapper for ${endpoint}`);
          return data.data;
        }
      }
      
      return data;
    } catch (err) {
      if (err instanceof ApiError) {
        throw err;
      }
      // Network error or other fetch failure
      console.error(`[API] Network error for ${endpoint}:`, err);
      logApiCall(method, endpoint, 0, err.message, { context });
      throw new ApiError(
        err.message || 'Network error',
        0,
        'NETWORK_ERROR',
        null,
        endpoint
      );
    }
  }

  // ============ BACKEND API CALLS ============

  /**
   * Health check - GET /api/health
   */
  async function checkHealth() {
    try {
      await api('/api/health');
      state.serverOnline = true;
      updateServerBadge(true);
      return true;
    } catch (err) {
      state.serverOnline = false;
      updateServerBadge(false);
      showError('Backend offline. Start edr-server to continue.', { 
        inCard: true, 
        showActions: true,
        endpoint: err.endpoint 
      });
      return false;
    }
  }

  /**
   * Readiness check - GET /api/selfcheck
   */
  async function checkReadiness(showSpinner = false) {
    // Debug guard: warn if called while viewing run data
    debugWarnLiveProbeInRunScope('/api/selfcheck');
    
    if (showSpinner && els.btnRunChecks) {
      els.btnRunChecks.disabled = true;
      els.btnRunChecks.textContent = 'Checking...';
    }
    
    try {
      const data = await api('/api/selfcheck');
      
      const status = data.overall_status || data.overall || data.status || 'unknown';
      const summary = data.summary || data.message || '';
      
      state.readinessState = status.toLowerCase();
      state.readinessSummary = summary;
      
      // Store telemetry readiness for UI display
      // The selfcheck endpoint returns capability data directly in the response
      // If there's a nested 'telemetry' key, use that; otherwise use the data itself
      state.telemetryReadiness = data.telemetry || data;
      
      // Store restart-as-admin capability
      state.supportsRestartAdmin = data.supports_restart_admin === true;
      
      // Update instance info with admin status
      const isAdmin = data.is_admin === true || state.telemetryReadiness?.is_admin === true;
      updateInstanceInfo(isAdmin);
      
      updateReadinessUI();
      
      // Hide connection details when reachable
      if (els.connectionDetailsToggle) els.connectionDetailsToggle.classList.add('hidden');
      if (els.connectionDetails) els.connectionDetails.classList.add('hidden');
      
    } catch (err) {
      state.readinessState = 'unreachable';
      state.readinessSummary = 'Could not reach backend';
      state.lastError = err.message;
      state.telemetryReadiness = null;
      state.supportsRestartAdmin = false;
      
      updateReadinessUI();
      updateInstanceInfo(false);
      
      // Show connection details toggle
      if (els.connectionDetailsToggle) els.connectionDetailsToggle.classList.remove('hidden');
      if (els.apiBaseUrl) els.apiBaseUrl.textContent = API_BASE;
      if (els.lastErrorMsg) els.lastErrorMsg.textContent = err.message;
    } finally {
      updateReadinessButton();
    }
  }

  function updateReadinessButton() {
    if (!els.btnRunChecks) return;
    els.btnRunChecks.disabled = false;
    
    // Smart button labeling
    if (state.readinessState === 'unreachable' || !state.serverOnline) {
      els.btnRunChecks.textContent = 'Retry';
    } else if (state.readinessState === 'unknown') {
      els.btnRunChecks.textContent = 'Run checks';
    } else {
      els.btnRunChecks.textContent = 'Re-run';
    }
  }

  /**
   * Show System Readiness details panel
   * Switches to Settings tab and expands the readiness details
   */
  function showSystemReadinessDetails() {
    // Switch to Settings tab (use the existing switchTab function)
    switchTab('settings');
    
    // Ensure readiness row is visible and scroll to it
    const readinessRow = document.getElementById('settingsReadiness');
    if (readinessRow) {
      readinessRow.scrollIntoView({ behavior: 'smooth', block: 'start' });
      // Highlight the row briefly
      readinessRow.style.transition = 'background 0.3s';
      readinessRow.style.background = 'rgba(59, 130, 246, 0.1)';
      setTimeout(() => {
        readinessRow.style.background = '';
      }, 1500);
    }
    
    // Run checks if not already done
    if (state.readinessState === 'unknown') {
      checkReadiness(true);
    }
  }

  // ============ DETECTION PLAN ============
  // Stores the loaded playbook catalog for filtering
  let detectionPlanCatalog = null;

  /**
   * Load Detection Plan - GET /api/playbooks/catalog
   * Fetches the playbook catalog and shows which detections are enabled vs blocked
   */
  async function loadDetectionPlan() {
    if (!els.btnLoadDetectionPlan) return;
    
    els.btnLoadDetectionPlan.disabled = true;
    els.btnLoadDetectionPlan.textContent = '⏳ Loading...';
    if (els.btnMissionLoadPlan) els.btnMissionLoadPlan.textContent = '⏳ Loading...';
    
    try {
      const data = await api('/api/playbooks/catalog');
      detectionPlanCatalog = data.playbooks || [];
      
      // Update summary stats - use counts from backend (enabled vs blocked vs runnable)
      const total = data.loaded_count ?? detectionPlanCatalog.length;
      const enabled = data.enabled_count ?? detectionPlanCatalog.filter(p => p.enabled !== false).length;
      const blocked = data.blocked_count ?? detectionPlanCatalog.filter(p => p.telemetry_blocked).length;
      const runnable = data.runnable_count ?? (enabled - blocked);
      const requiresSysmon = detectionPlanCatalog.filter(p => 
        (p.requires || p.required_sensors || []).some(r => r.toLowerCase().includes('sysmon'))
      ).length;
      const requiresAdmin = detectionPlanCatalog.filter(p =>
        (p.requires || p.required_sensors || []).some(r => 
          r.toLowerCase().includes('security') || r.toLowerCase().includes('admin')
        )
      ).length;
      
      // Update detailed stats (Settings tab)
      if (els.dpTotalEnabled) els.dpTotalEnabled.textContent = enabled;
      if (els.dpTotalBlocked) els.dpTotalBlocked.textContent = blocked;
      if (els.dpRequiresSysmon) els.dpRequiresSysmon.textContent = requiresSysmon;
      if (els.dpRequiresAdmin) els.dpRequiresAdmin.textContent = requiresAdmin;
      
      // Update Mission tab summary counts - show RUNNABLE prominently
      if (els.missionPlanEnabled) els.missionPlanEnabled.textContent = runnable;  // Changed to runnable
      if (els.missionPlanBlocked) els.missionPlanBlocked.textContent = blocked;
      
      // Update status badge - show runnable/total for clarity
      if (els.detectionPlanStatus) {
        if (runnable === 0 && blocked > 0) {
          els.detectionPlanStatus.innerHTML = getStatusBadge('blocked', `0/${total} runnable`, `${blocked} blocked by telemetry`);
        } else if (blocked > 0) {
          els.detectionPlanStatus.innerHTML = getStatusBadge('partial', `${runnable}/${total} runnable`, `${blocked} blocked`);
        } else {
          els.detectionPlanStatus.innerHTML = getStatusBadge('configured', `${runnable} runnable`, 'All playbooks can evaluate');
        }
        els.detectionPlanStatus.className = '';
      }
      
      // Update summary text - crystal clear about what's runnable NOW
      if (els.detectionPlanSummary) {
        if (runnable === 0 && blocked > 0) {
          els.detectionPlanSummary.textContent = `All ${blocked} playbooks blocked by missing telemetry. See unlock actions below.`;
        } else if (blocked > 0) {
          els.detectionPlanSummary.textContent = `${runnable} playbook(s) runnable now · ${blocked} blocked (unlock below)`;
        } else {
          els.detectionPlanSummary.textContent = `All ${runnable} playbooks runnable · Will evaluate when matching facts are observed`;
        }
      }
      
      // Show the panel (Settings tab)
      if (els.detectionPlanPanel) {
        els.detectionPlanPanel.classList.remove('hidden');
      }
      // Show the settings panel (new Settings tab row)
      if (els.settingsDetectionPlanPanel) {
        els.settingsDetectionPlanPanel.classList.remove('hidden');
      }
      
      // Update settings badge
      if (els.settingsDetectionPlanCount) {
        els.settingsDetectionPlanCount.textContent = `${enabled} enabled`;
        els.settingsDetectionPlanCount.className = 'badge badge-live';
      }
      
      // Show the panel (Mission tab)
      if (els.missionPlanPanel) {
        els.missionPlanPanel.classList.remove('hidden');
      }
      // Render the playbook list
      renderDetectionPlanList('');
      
      // Setup search filtering (Settings tab)
      if (els.dpSearchInput) {
        els.dpSearchInput.oninput = (e) => renderDetectionPlanList(e.target.value);
      }
      // Setup search filtering (Settings tab - new row)
      if (els.settingsPlanSearch) {
        els.settingsPlanSearch.oninput = (e) => renderDetectionPlanList(e.target.value);
      }
      // Setup search filtering (Mission tab)
      if (els.missionPlanSearch) {
        els.missionPlanSearch.oninput = (e) => renderDetectionPlanList(e.target.value);
      }
      
    } catch (err) {
      if (els.detectionPlanStatus) {
        els.detectionPlanStatus.innerHTML = getStatusBadge('blocked', 'Error', err.message);
        els.detectionPlanStatus.className = '';
      }
      if (els.detectionPlanSummary) {
        els.detectionPlanSummary.textContent = `Could not load catalog: ${err.message}`;
      }
      console.error('[loadDetectionPlan] Error:', err);
    } finally {
      if (els.btnLoadDetectionPlan) {
        els.btnLoadDetectionPlan.disabled = false;
        els.btnLoadDetectionPlan.textContent = 'Reload';
      }
      if (els.btnMissionLoadPlan) {
        els.btnMissionLoadPlan.disabled = false;
        els.btnMissionLoadPlan.textContent = 'View';
      }
    }
  }

  /**
   * Render the detection plan playbook list with optional filter
   * Rows are clickable to open detail drawer
   * Renders to both Settings and Mission tabs
   */
  function renderDetectionPlanList(filterText) {
    if (!detectionPlanCatalog) return;
    
    // Enrich playbooks with metadata
    const enrichedCatalog = detectionPlanCatalog.map(p => enrichPlaybookWithMetadata(p));
    
    const filter = (filterText || '').toLowerCase();
    const filtered = enrichedCatalog.filter(p => {
      if (!filter) return true;
      return (p.name || '').toLowerCase().includes(filter) ||
             (p.description || '').toLowerCase().includes(filter) ||
             (p.playbook_id || '').toLowerCase().includes(filter) ||
             (p.category || '').toLowerCase().includes(filter) ||
             (p.mitre_techniques || []).some(t => t.toLowerCase().includes(filter)) ||
             (p.mitre_tactics || []).some(t => t.toLowerCase().includes(filter));
    });
    
    // Sort: blocked first (so user sees what needs attention), then by category, then by name
    filtered.sort((a, b) => {
      if (a.telemetry_blocked && !b.telemetry_blocked) return -1;
      if (!a.telemetry_blocked && b.telemetry_blocked) return 1;
      // Then by category
      const catCompare = (a.category || '').localeCompare(b.category || '');
      if (catCompare !== 0) return catCompare;
      return (a.name || '').localeCompare(b.name || '');
    });
    
    // Generate HTML for the list
    const emptyHtml = filter 
      ? `<div style="color: var(--muted); text-align: center; padding: 16px;">No playbooks match "${escapeHtml(filter)}"</div>`
      : `<div style="color: var(--muted); text-align: center; padding: 12px;">No playbooks available</div>`;
    
    const html = filtered.length === 0 ? emptyHtml : filtered.map(p => {
      // Use the playbook status badge helper - map telemetry_blocked to derived_status
      const derivedStatus = p.telemetry_blocked ? 'blocked_by_telemetry' : 'enabled';
      const statusBadge = getPlaybookStatusBadge({
        derived_status: derivedStatus,
        blocked_by: p.requires || p.required_sensors || [],
        reasons: p.blocked_reasons || p.telemetry_blocked_reasons || []
      });
      
      const mitreStr = [...(p.mitre_techniques || []), ...(p.mitre_tactics || [])].slice(0, 3).join(', ');
      const slotsStr = (p.slots_summary || []).map(s => s.intent || s.slot_name).slice(0, 2).join('; ');
      
      // Category badge
      const categoryBadge = p.category ? `<span style="background: var(--panel); color: var(--accent); padding: 1px 6px; border-radius: 3px; font-size: 9px; margin-right: 6px;">${escapeHtml(p.category)}</span>` : '';
      
      // Truncate description for list view
      const shortDesc = (p.description || '').length > 100 ? (p.description || '').substring(0, 100) + '...' : (p.description || '');
      
      // Build prerequisite chips based on requires (or fallback to required_sensors)
      const telemetry = state.telemetryReadiness;
      const prereqChips = [];
      const reqSensors = p.requires || p.required_sensors || [];
      
      // Sysmon chip: warning style if Sysmon not installed
      if (reqSensors.some(r => r.toLowerCase().includes('sysmon'))) {
        const sysmonOk = telemetry?.sysmon_installed === true;
        prereqChips.push(`<span style="background: ${sysmonOk ? 'var(--panel2)' : 'rgba(245,158,11,0.2)'}; color: ${sysmonOk ? 'var(--muted)' : 'var(--warn)'}; padding: 1px 5px; border-radius: 3px; font-size: 9px;">${sysmonOk ? '' : '⚠ '}Sysmon</span>`);
      }
      // Security log chip: error style if not accessible
      if (reqSensors.some(r => r.toLowerCase().includes('security') || r.toLowerCase().includes('audit_proc'))) {
        const secOk = telemetry?.security_log_accessible === true;
        prereqChips.push(`<span style="background: ${secOk ? 'var(--panel2)' : 'rgba(239,68,68,0.2)'}; color: ${secOk ? 'var(--muted)' : 'var(--error)'}; padding: 1px 5px; border-radius: 3px; font-size: 9px;">${secOk ? '' : '🔒 '}Security</span>`);
      }
      // PowerShell logging chip
      if (reqSensors.some(r => r.toLowerCase().includes('powershell'))) {
        prereqChips.push(`<span style="background: var(--panel2); color: var(--muted); padding: 1px 5px; border-radius: 3px; font-size: 9px;">PowerShell</span>`);
      }
      
      const prereqRow = prereqChips.length > 0 
        ? `<div style="display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px;">${prereqChips.join('')}</div>`
        : '';
      
      // Show block reasons with 🔒 icon for blocked playbooks + unlock CTAs
      const blockReasonsArr = p.blocked_reasons || p.telemetry_blocked_reasons || [];
      let blockReasons = '';
      let unlockCtas = '';
      
      if (p.telemetry_blocked && blockReasonsArr.length > 0) {
        blockReasons = `<div style="color: var(--warn); font-size: 10px; margin-top: 4px;">🔒 ${escapeHtml(blockReasonsArr.join(', '))}</div>`;
        
        // Build unlock CTAs based on what's blocking
        const unlockButtons = [];
        const reasonsLower = blockReasonsArr.map(r => r.toLowerCase()).join(' ');
        if (reasonsLower.includes('admin') || reasonsLower.includes('security')) {
          unlockButtons.push(`<button class="unlock-cta" data-action="run-admin" style="background: var(--panel); border: 1px solid var(--accent); color: var(--accent); padding: 2px 6px; border-radius: 3px; font-size: 9px; cursor: pointer; margin-right: 4px;">🔓 Run as Admin</button>`);
        }
        if (reasonsLower.includes('sysmon')) {
          unlockButtons.push(`<button class="unlock-cta" data-action="install-sysmon" style="background: var(--panel); border: 1px solid var(--warn); color: var(--warn); padding: 2px 6px; border-radius: 3px; font-size: 9px; cursor: pointer; margin-right: 4px;">⬇️ Install Sysmon</button>`);
        }
        if (reasonsLower.includes('powershell')) {
          unlockButtons.push(`<button class="unlock-cta" data-action="enable-ps" style="background: var(--panel); border: 1px solid var(--muted); color: var(--muted); padding: 2px 6px; border-radius: 3px; font-size: 9px; cursor: pointer;">⚙️ Enable PS Logging</button>`);
        }
        if (unlockButtons.length > 0) {
          unlockCtas = `<div style="margin-top: 4px; display: flex; flex-wrap: wrap;">${unlockButtons.join('')}</div>`;
        }
      }
      
      // Runnable playbooks show a note about evaluation
      const enabledNote = !p.telemetry_blocked 
        ? `<div style="color: var(--success); font-size: 10px; margin-top: 4px; font-style: italic;">✓ Runnable · Will evaluate when matching facts are observed</div>`
        : '';
      
      return `
        <div class="playbook-catalog-row" data-playbook-id="${escapeHtml(p.playbook_id)}" 
             style="padding: 8px; border-bottom: 1px solid var(--border); cursor: pointer; transition: background 0.15s;
                    ${p.telemetry_blocked ? 'background: rgba(255,100,100,0.05);' : ''}"
             onmouseover="this.style.background='var(--panel2)'" 
             onmouseout="this.style.background='${p.telemetry_blocked ? 'rgba(255,100,100,0.05)' : ''}'">
          <div style="display: flex; justify-content: space-between; align-items: flex-start;">
            <div style="flex: 1;">
              <div style="font-weight: 500;">${categoryBadge}${escapeHtml(p.name || p.title || p.playbook_id)}</div>
              <div style="font-size: 11px; color: var(--muted);">${escapeHtml(shortDesc)}</div>
              ${mitreStr ? `<div style="font-size: 10px; color: var(--accent); margin-top: 2px;">${escapeHtml(mitreStr)}</div>` : ''}
              ${prereqRow}
              ${blockReasons}
              ${unlockCtas}
              ${enabledNote}
            </div>
            <div style="margin-left: 8px; display: flex; align-items: center; gap: 6px;">
              ${statusBadge}
              <span style="font-size: 12px; color: var(--muted);">›</span>
            </div>
          </div>
        </div>
      `;
    }).join('');
    
    // Render to Settings tab list
    if (els.dpPlaybookList) {
      els.dpPlaybookList.innerHTML = html;
      els.dpPlaybookList.querySelectorAll('.playbook-catalog-row').forEach(row => {
        row.onclick = (e) => {
          // Don't open drawer if clicking on unlock CTA button
          if (e.target.classList.contains('unlock-cta')) return;
          const playbookId = row.dataset.playbookId;
          const playbook = detectionPlanCatalog.find(p => p.playbook_id === playbookId);
          if (playbook) openPlaybookDetailDrawer(playbook, 'catalog');
        };
      });
      // Handle unlock CTA clicks
      els.dpPlaybookList.querySelectorAll('.unlock-cta').forEach(btn => {
        btn.onclick = (e) => {
          e.stopPropagation();
          handleUnlockCta(btn.dataset.action);
        };
      });
    }
    
    // Render to Settings tab list (new row)
    if (els.settingsPlanList) {
      els.settingsPlanList.innerHTML = html;
      els.settingsPlanList.querySelectorAll('.playbook-catalog-row').forEach(row => {
        row.onclick = (e) => {
          if (e.target.classList.contains('unlock-cta')) return;
          const playbookId = row.dataset.playbookId;
          const playbook = detectionPlanCatalog.find(p => p.playbook_id === playbookId);
          if (playbook) openPlaybookDetailDrawer(playbook, 'catalog');
        };
      });
      els.settingsPlanList.querySelectorAll('.unlock-cta').forEach(btn => {
        btn.onclick = (e) => {
          e.stopPropagation();
          handleUnlockCta(btn.dataset.action);
        };
      });
    }
    
    // Render to Mission tab list
    if (els.missionPlanList) {
      els.missionPlanList.innerHTML = html;
      els.missionPlanList.querySelectorAll('.playbook-catalog-row').forEach(row => {
        row.onclick = (e) => {
          if (e.target.classList.contains('unlock-cta')) return;
          const playbookId = row.dataset.playbookId;
          const playbook = detectionPlanCatalog.find(p => p.playbook_id === playbookId);
          if (playbook) openPlaybookDetailDrawer(playbook, 'catalog');
        };
      });
      els.missionPlanList.querySelectorAll('.unlock-cta').forEach(btn => {
        btn.onclick = (e) => {
          e.stopPropagation();
          handleUnlockCta(btn.dataset.action);
        };
      });
    }
  }
  
  /**
   * Handle unlock CTA button clicks
   * Opens the Readiness modal with the appropriate recommendation highlighted
   */
  function handleUnlockCta(action) {
    switch (action) {
      case 'run-admin':
        // Open System Readiness modal/panel and scroll to Admin recommendation
        if (typeof showSystemReadinessDetails === 'function') {
          showSystemReadinessDetails();
        }
        // Show a toast explaining what to do
        showToast('To unlock Security log access, restart the application as Administrator', 'info');
        break;
      case 'install-sysmon':
        // Open System Readiness modal/panel and scroll to Sysmon recommendation
        if (typeof showSystemReadinessDetails === 'function') {
          showSystemReadinessDetails();
        }
        showToast('Install Sysmon for deeper process and network visibility. See Readiness panel for instructions.', 'info');
        break;
      case 'enable-ps':
        // Open System Readiness modal/panel
        if (typeof showSystemReadinessDetails === 'function') {
          showSystemReadinessDetails();
        }
        showToast('Enable PowerShell Script Block Logging via Group Policy or registry.', 'info');
        break;
      default:
        console.warn('[handleUnlockCta] Unknown action:', action);
    }
  }

  // ============ PLAYBOOK SELECTION / PROFILES ============
  
  /**
   * Load playbook presets from server (capability-aware)
   * Populates the preset dropdown with available options
   */
  async function loadPlaybookPresets() {
    if (state.playbookSelection.presetsLoading) return;
    
    console.log('[loadPlaybookPresets] Loading presets...');
    state.playbookSelection.presetsLoading = true;
    
    try {
      const data = await api('/api/playbooks/presets');
      state.playbookSelection.presets = data.presets || [];
      
      console.log('[loadPlaybookPresets] Loaded presets:', state.playbookSelection.presets.map(p => p.preset_id));
      
      // Populate dropdown
      if (els.playbookPresetSelect) {
        // Clear existing options
        els.playbookPresetSelect.innerHTML = '';
        
        // Add preset options - show count and unlock info
        for (const preset of state.playbookSelection.presets) {
          const opt = document.createElement('option');
          opt.value = preset.preset_id;
          // Show runnable indicator and unlock count for capability-aware presets
          const runnableIndicator = preset.runnable_now ? '' : ' ⚠️';
          const unlockInfo = preset.unlocks && !preset.runnable_now ? ` (+${preset.unlocks} if unlocked)` : '';
          opt.textContent = `${preset.icon || ''} ${preset.name} (${preset.count})${runnableIndicator}${unlockInfo}`;
          if (preset.preset_id === state.playbookSelection.preset) {
            opt.selected = true;
          }
          els.playbookPresetSelect.appendChild(opt);
        }
        
        // Add Custom option
        const customOpt = document.createElement('option');
        customOpt.value = 'custom';
        customOpt.textContent = '⚙️ Custom Selection...';
        if (state.playbookSelection.mode === 'custom') {
          customOpt.selected = true;
        }
        els.playbookPresetSelect.appendChild(customOpt);
      }
      
      // Update counts from default preset
      updatePlaybookSelectionSummary();
      
    } catch (err) {
      console.error('[loadPlaybookPresets] Error:', err);
      // On error, show static presets with general as default
      if (els.playbookPresetSelect) {
        els.playbookPresetSelect.innerHTML = `
          <option value="general" selected>🌐 General (System Changes)</option>
          <option value="extended">🔮 Extended (All)</option>
          <option value="custom">⚙️ Custom Selection...</option>
        `;
      }
    } finally {
      state.playbookSelection.presetsLoading = false;
    }
  }
  
  /**
   * Handle preset dropdown change
   */
  function handlePlaybookPresetChange(event) {
    const value = event.target.value;
    console.log('[handlePlaybookPresetChange] Selected:', value);
    
    if (value === 'custom') {
      state.playbookSelection.mode = 'custom';
      // Show custom selection UI (modal or expand inline)
      openPlaybookCustomSelectModal();
    } else {
      state.playbookSelection.mode = 'preset';
      state.playbookSelection.preset = value;
      state.playbookSelection.selectedPlaybooks = []; // Clear custom selection
      
      // Save as default
      savePlaybookSelectionDefault();
    }
    
    updatePlaybookSelectionSummary();
  }
  
  /**
   * Update the playbook selection summary counts display
   */
  function updatePlaybookSelectionSummary() {
    const ps = state.playbookSelection;
    
    // Find current preset info
    let selectedCount = 0;
    let runnableCount = 0;
    let blockedCount = 0;
    
    if (ps.mode === 'preset' && ps.presets) {
      const preset = ps.presets.find(p => p.preset_id === ps.preset);
      if (preset) {
        selectedCount = preset.count || 0;
        
        // Calculate runnable/blocked from readiness data + preset's playbook_ids
        const readiness = state.readiness;
        if (readiness && readiness.playbooks && preset.playbook_ids) {
          for (const pid of preset.playbook_ids) {
            const pb = readiness.playbooks.find(p => p.playbook_id === pid);
            if (pb) {
              if (pb.telemetry_blocked) {
                blockedCount++;
              } else if (pb.enabled) {
                runnableCount++;
              }
            }
          }
        } else {
          // Fallback: if runnable_now flag is set, assume all are runnable
          runnableCount = preset.runnable_now ? selectedCount : 0;
          blockedCount = preset.runnable_now ? 0 : selectedCount;
        }
      }
    } else if (ps.mode === 'custom') {
      selectedCount = ps.selectedPlaybooks.length;
      // Calculate runnable/blocked from readiness data
      const readiness = state.readiness;
      if (readiness && readiness.playbooks) {
        for (const pid of ps.selectedPlaybooks) {
          const pb = readiness.playbooks.find(p => p.playbook_id === pid);
          if (pb) {
            if (pb.telemetry_blocked) {
              blockedCount++;
            } else if (pb.enabled) {
              runnableCount++;
            }
          }
        }
      } else {
        // Fallback: assume all selected are runnable
        runnableCount = selectedCount;
      }
    }
    
    // Update state
    ps.selectedCount = selectedCount;
    ps.runnableCount = runnableCount;
    ps.blockedCount = blockedCount;
    
    // Update UI
    if (els.playbookSelectedCount) {
      els.playbookSelectedCount.textContent = selectedCount;
    }
    if (els.playbookRunnableCount) {
      els.playbookRunnableCount.textContent = runnableCount;
      els.playbookRunnableCount.style.color = runnableCount > 0 ? 'var(--good)' : 'var(--muted)';
    }
    if (els.playbookBlockedCount) {
      els.playbookBlockedCount.textContent = blockedCount;
      els.playbookBlockedCount.style.color = blockedCount > 0 ? 'var(--error)' : 'var(--muted)';
    }
    
    // Show/hide selection summary row
    if (els.playbookSelectionSummary) {
      const showSummary = ps.presets && ps.presets.length > 0;
      els.playbookSelectionSummary.style.display = showSummary ? 'block' : 'none';
    }
    
    // Show upgrade hint for General preset
    const upgradeHintEl = document.getElementById('playbookUpgradeHint');
    const upgradeHintTextEl = document.getElementById('playbookUpgradeHintText');
    if (upgradeHintEl && upgradeHintTextEl) {
      const isGeneral = ps.mode === 'preset' && ps.preset === 'general';
      if (isGeneral && ps.presets) {
        // Find Admin and Sysmon presets to show unlock counts
        const adminPreset = ps.presets.find(p => p.preset_id === 'admin');
        const sysmonPreset = ps.presets.find(p => p.preset_id === 'sysmon');
        const adminUnlocks = adminPreset?.unlocks || 0;
        const sysmonUnlocks = sysmonPreset?.unlocks || 0;
        
        if (adminUnlocks > 0 || sysmonUnlocks > 0) {
          let hints = [];
          if (adminUnlocks > 0) hints.push(`Admin (+${adminUnlocks} playbooks)`);
          if (sysmonUnlocks > 0) hints.push(`Sysmon (+${sysmonUnlocks} playbooks)`);
          upgradeHintTextEl.textContent = `Need deeper coverage? Try ${hints.join(' or ')}`;
          upgradeHintEl.style.display = 'block';
        } else {
          upgradeHintEl.style.display = 'none';
        }
      } else {
        upgradeHintEl.style.display = 'none';
      }
    }
    
    console.log('[updatePlaybookSelectionSummary]', { selectedCount, runnableCount, blockedCount });
  }
  
  /**
   * Save playbook selection as user default
   */
  async function savePlaybookSelectionDefault() {
    const ps = state.playbookSelection;
    const payload = {
      mode: ps.mode,
      preset: ps.preset,
      selected_playbooks: ps.selectedPlaybooks
    };
    
    try {
      await api('/api/playbooks/selection', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      console.log('[savePlaybookSelectionDefault] Saved');
    } catch (err) {
      console.warn('[savePlaybookSelectionDefault] Failed to save:', err);
      // Non-fatal - don't show error to user
    }
  }
  
  /**
   * Load saved playbook selection default
   */
  async function loadPlaybookSelectionDefault() {
    try {
      const data = await api('/api/playbooks/selection');
      if (data) {
        state.playbookSelection.mode = data.mode || 'preset';
        state.playbookSelection.preset = data.preset || 'extended';
        state.playbookSelection.selectedPlaybooks = data.selected_playbooks || [];
        console.log('[loadPlaybookSelectionDefault] Loaded:', data);
      }
    } catch (err) {
      console.log('[loadPlaybookSelectionDefault] No saved default or error:', err.message);
      // Use defaults
    }
  }
  
  /**
   * Open custom playbook selection modal
   * Shows all playbooks with checkboxes for multi-select
   */
  function openPlaybookCustomSelectModal() {
    // Check if we have readiness data with playbooks
    const readiness = state.readiness;
    if (!readiness || !readiness.playbooks || readiness.playbooks.length === 0) {
      showToast('Playbook catalog not loaded. Run readiness check first.', 'warning');
      // Revert to previous preset
      if (els.playbookPresetSelect) {
        els.playbookPresetSelect.value = state.playbookSelection.preset || 'extended';
      }
      state.playbookSelection.mode = 'preset';
      return;
    }
    
    // Create modal if it doesn't exist
    let modal = document.getElementById('playbookSelectModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'playbookSelectModal';
      modal.className = 'modal-overlay';
      modal.innerHTML = `
        <div class="modal" style="max-width: 700px; max-height: 80vh; display: flex; flex-direction: column;">
          <div class="modal-header" style="flex-shrink: 0;">
            <h3>🎯 Select Playbooks</h3>
            <button class="modal-close" id="playbookSelectModalClose">&times;</button>
          </div>
          <div class="modal-body" style="flex: 1; overflow-y: auto; padding: 16px;">
            <p style="color: var(--muted); margin-bottom: 12px;">
              Choose which playbooks to include in your run. Blocked playbooks (missing telemetry) are shown but won't produce findings.
            </p>
            <div style="margin-bottom: 12px;">
              <button id="btnSelectAllPlaybooks" class="btn btn-secondary btn-sm">Select All</button>
              <button id="btnSelectNonePlaybooks" class="btn btn-secondary btn-sm">Select None</button>
              <button id="btnSelectRunnable" class="btn btn-secondary btn-sm">Select Runnable Only</button>
            </div>
            <div id="playbookSelectList" style="display: flex; flex-direction: column; gap: 8px;"></div>
          </div>
          <div class="modal-footer" style="flex-shrink: 0; border-top: 1px solid var(--border); padding: 12px 16px;">
            <span id="playbookSelectCount" style="color: var(--muted);">0 selected</span>
            <div>
              <button id="btnCancelPlaybookSelect" class="btn btn-secondary">Cancel</button>
              <button id="btnApplyPlaybookSelect" class="btn btn-primary">Apply Selection</button>
            </div>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
      
      // Bind close handlers
      modal.querySelector('#playbookSelectModalClose').addEventListener('click', closePlaybookCustomSelectModal);
      modal.querySelector('#btnCancelPlaybookSelect').addEventListener('click', closePlaybookCustomSelectModal);
      modal.addEventListener('click', (e) => {
        if (e.target === modal) closePlaybookCustomSelectModal();
      });
      
      // Select all / none / runnable
      modal.querySelector('#btnSelectAllPlaybooks').addEventListener('click', () => {
        modal.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = true);
        updatePlaybookSelectCount();
      });
      modal.querySelector('#btnSelectNonePlaybooks').addEventListener('click', () => {
        modal.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
        updatePlaybookSelectCount();
      });
      modal.querySelector('#btnSelectRunnable').addEventListener('click', () => {
        modal.querySelectorAll('input[type="checkbox"]').forEach(cb => {
          cb.checked = cb.dataset.runnable === 'true';
        });
        updatePlaybookSelectCount();
      });
      
      // Apply button
      modal.querySelector('#btnApplyPlaybookSelect').addEventListener('click', applyPlaybookCustomSelection);
    }
    
    // Populate playbook list
    const listEl = modal.querySelector('#playbookSelectList');
    listEl.innerHTML = '';
    
    // Group by category
    const byCategory = {};
    for (const pb of readiness.playbooks) {
      const cat = PLAYBOOK_METADATA[pb.playbook_id]?.category || 'Other';
      if (!byCategory[cat]) byCategory[cat] = [];
      byCategory[cat].push(pb);
    }
    
    // Determine what's currently selected
    const currentlySelected = new Set(
      state.playbookSelection.mode === 'custom' 
        ? state.playbookSelection.selectedPlaybooks 
        : readiness.playbooks.filter(p => p.enabled).map(p => p.playbook_id)
    );
    
    for (const [category, playbooks] of Object.entries(byCategory).sort((a, b) => a[0].localeCompare(b[0]))) {
      // Category header
      const catHeader = document.createElement('div');
      catHeader.style.cssText = 'font-weight: 600; color: var(--text); margin-top: 12px; padding-bottom: 4px; border-bottom: 1px solid var(--border);';
      catHeader.textContent = category;
      listEl.appendChild(catHeader);
      
      for (const pb of playbooks) {
        const isBlocked = pb.telemetry_blocked;
        const isRunnable = pb.enabled && !isBlocked;
        const isSelected = currentlySelected.has(pb.playbook_id);
        const meta = PLAYBOOK_METADATA[pb.playbook_id] || {};
        
        const row = document.createElement('label');
        row.style.cssText = `
          display: flex; align-items: flex-start; gap: 8px; padding: 8px; 
          border-radius: 4px; cursor: pointer;
          background: ${isBlocked ? 'rgba(255,100,100,0.1)' : 'transparent'};
          opacity: ${isBlocked ? '0.7' : '1'};
        `;
        row.innerHTML = `
          <input type="checkbox" 
            value="${pb.playbook_id}" 
            data-runnable="${isRunnable}" 
            ${isSelected ? 'checked' : ''}
            style="margin-top: 4px;">
          <div style="flex: 1;">
            <div style="display: flex; align-items: center; gap: 6px;">
              <span style="font-weight: 500;">${meta.title || pb.playbook_id}</span>
              ${isBlocked ? '<span style="font-size: 11px; background: var(--error); color: white; padding: 1px 5px; border-radius: 3px;">BLOCKED</span>' : ''}
              ${!isBlocked && isRunnable ? '<span style="font-size: 11px; background: var(--good); color: white; padding: 1px 5px; border-radius: 3px;">RUNNABLE</span>' : ''}
            </div>
            <div style="font-size: 12px; color: var(--muted); margin-top: 2px;">
              ${pb.playbook_id}
            </div>
          </div>
        `;
        
        // Update count on change
        row.querySelector('input').addEventListener('change', updatePlaybookSelectCount);
        listEl.appendChild(row);
      }
    }
    
    // Show modal
    modal.classList.add('active');
    updatePlaybookSelectCount();
  }
  
  /**
   * Update count display in custom selection modal
   */
  function updatePlaybookSelectCount() {
    const modal = document.getElementById('playbookSelectModal');
    if (!modal) return;
    
    const checked = modal.querySelectorAll('input[type="checkbox"]:checked');
    const countEl = modal.querySelector('#playbookSelectCount');
    if (countEl) {
      const runnableCount = Array.from(checked).filter(cb => cb.dataset.runnable === 'true').length;
      countEl.textContent = `${checked.length} selected (${runnableCount} runnable)`;
    }
  }
  
  /**
   * Apply custom playbook selection from modal
   */
  function applyPlaybookCustomSelection() {
    const modal = document.getElementById('playbookSelectModal');
    if (!modal) return;
    
    const checked = modal.querySelectorAll('input[type="checkbox"]:checked');
    const selectedIds = Array.from(checked).map(cb => cb.value);
    
    if (selectedIds.length === 0) {
      showToast('Select at least one playbook', 'warning');
      return;
    }
    
    state.playbookSelection.mode = 'custom';
    state.playbookSelection.selectedPlaybooks = selectedIds;
    
    // Update dropdown to show "Custom"
    if (els.playbookPresetSelect) {
      els.playbookPresetSelect.value = 'custom';
    }
    
    // Save as default
    savePlaybookSelectionDefault();
    
    // Update summary
    updatePlaybookSelectionSummary();
    
    // Close modal
    closePlaybookCustomSelectModal();
    
    showToast(`Custom selection: ${selectedIds.length} playbooks`, 'success');
  }
  
  /**
   * Close custom playbook selection modal
   */
  function closePlaybookCustomSelectModal() {
    const modal = document.getElementById('playbookSelectModal');
    if (modal) {
      modal.classList.remove('active');
    }
    
    // If we were trying to switch to custom but cancelled, revert dropdown
    if (state.playbookSelection.mode !== 'custom' && els.playbookPresetSelect) {
      els.playbookPresetSelect.value = state.playbookSelection.preset || 'extended';
    }
  }
  
  /**
   * Get current playbook selection for run start request
   * @returns {Object} PlaybookSelection payload for API
   */
  function getPlaybookSelectionPayload() {
    const ps = state.playbookSelection;
    return {
      mode: ps.mode,
      preset: ps.mode === 'preset' ? ps.preset : null,
      selected_playbooks: ps.mode === 'custom' ? ps.selectedPlaybooks : []
    };
  }

  /**
   * Open playbook detail drawer (works for both catalog and run evaluation views)
   * @param {Object} playbook - Playbook data (from catalog or run evaluation)
   * @param {string} context - 'catalog' or 'run'
   */
  function openPlaybookDetailDrawer(playbookRaw, context) {
    // Enrich playbook with metadata from PLAYBOOK_METADATA registry
    const playbook = enrichPlaybookWithMetadata(playbookRaw);
    selectedPlaybookId = playbook.playbook_id;
    
    // Create or get the drawer element
    let drawer = document.getElementById('playbookDetailDrawer');
    if (!drawer) {
      drawer = document.createElement('div');
      drawer.id = 'playbookDetailDrawer';
      drawer.style.cssText = `
        position: fixed; right: 0; top: 0; width: 450px; height: 100vh;
        background: var(--panel); border-left: 1px solid var(--border);
        z-index: 1000; overflow-y: auto; transform: translateX(100%);
        transition: transform 0.25s ease-out; box-shadow: -4px 0 20px rgba(0,0,0,0.3);
        display: flex; flex-direction: column;
      `;
      document.body.appendChild(drawer);
    }
    
    // Determine status for display
    const statusLabel = !playbook.valid ? 'invalid' : 
                        playbook.telemetry_blocked ? 'blocked' : 
                        (playbook.enabled ? 'runnable' : 'disabled');
    const statusColor = !playbook.valid ? 'var(--error)' :
                        playbook.telemetry_blocked ? 'var(--error)' : 
                        (playbook.enabled ? 'var(--good)' : 'var(--muted)');
    
    // Build source badge
    const sourceBadge = playbook.source === 'custom' ? 
      '<span style="background: var(--accent); color: white; padding: 2px 6px; border-radius: 4px; font-size: 10px; margin-left: 8px;">CUSTOM</span>' : '';
    
    // Prerequisites badges - from requires array
    const requires = playbook.requires || [];
    const prereqBadges = [];
    if (requires.includes('admin') || requires.includes('administrator')) 
      prereqBadges.push('<span style="background: var(--warn); color: white; padding: 2px 6px; border-radius: 4px; font-size: 10px;">🔐 Admin</span>');
    if (requires.includes('sysmon')) 
      prereqBadges.push('<span style="background: var(--accent); color: white; padding: 2px 6px; border-radius: 4px; font-size: 10px;">📊 Sysmon</span>');
    if (requires.includes('security_log') || requires.includes('security')) 
      prereqBadges.push('<span style="background: #6366f1; color: white; padding: 2px 6px; border-radius: 4px; font-size: 10px;">🔒 Security Log</span>');
    if (requires.includes('powershell') || requires.includes('powershell_logging')) 
      prereqBadges.push('<span style="background: #0891b2; color: white; padding: 2px 6px; border-radius: 4px; font-size: 10px;">📝 PowerShell</span>');
    
    // MITRE info
    const mitreTechniques = playbook.mitre_techniques || [];
    const mitreTactics = playbook.mitre_tactics || [];
    
    // Steps from backend
    const steps = playbook.steps || [];
    const hasDerivedStructure = steps.some(s => s.derived_structure);
    
    // Build drawer with 3 tabs
    drawer.innerHTML = `
      <div style="padding: 16px; border-bottom: 1px solid var(--border); background: var(--panel2); flex-shrink: 0;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
          <div style="flex: 1;">
            <div style="font-size: 14px; font-weight: 600;">${escapeHtml(playbook.name || playbook.playbook_id)}${sourceBadge}</div>
            <div style="font-size: 11px; color: var(--muted);">${escapeHtml(playbook.category || 'Detection')}</div>
          </div>
          <button id="btnClosePlaybookDrawer" style="background: transparent; border: none; font-size: 20px; cursor: pointer; color: var(--muted); padding: 4px 8px; flex-shrink: 0;">✕</button>
        </div>
        <div style="margin-top: 8px; display: flex; align-items: center; gap: 8px;">
          <span style="color: ${statusColor}; font-weight: 600; text-transform: uppercase; font-size: 11px; padding: 2px 8px; background: ${statusColor}22; border-radius: 4px;">${statusLabel}</span>
          ${playbook.blocked_reasons?.length > 0 ? `<span style="font-size: 10px; color: var(--muted);">${playbook.blocked_reasons.join('; ')}</span>` : ''}
        </div>
      </div>
      
      <!-- Tab Bar -->
      <div style="display: flex; border-bottom: 1px solid var(--border); background: var(--panel); flex-shrink: 0;">
        <button class="pb-drawer-tab active" data-tab="overview" style="flex: 1; padding: 10px; background: transparent; border: none; border-bottom: 2px solid var(--accent); color: var(--text); cursor: pointer; font-size: 12px; font-weight: 500;">Overview</button>
        <button class="pb-drawer-tab" data-tab="trace" style="flex: 1; padding: 10px; background: transparent; border: none; border-bottom: 2px solid transparent; color: var(--muted); cursor: pointer; font-size: 12px;">Trace</button>
        <button class="pb-drawer-tab" data-tab="yaml" style="flex: 1; padding: 10px; background: transparent; border: none; border-bottom: 2px solid transparent; color: var(--muted); cursor: pointer; font-size: 12px;">${DEBUG_MODE ? 'YAML' : '🔒 YAML'}</button>
      </div>
      
      <!-- Tab Content Container -->
      <div style="flex: 1; overflow-y: auto;">
        <!-- Overview Tab -->
        <div id="pbTabOverview" class="pb-drawer-content" style="padding: 16px;">
          <!-- Description -->
          <div style="margin-bottom: 16px;">
            <div style="font-size: 12px; color: var(--text); line-height: 1.5;">${escapeHtml(playbook.description || 'This playbook evaluates when matching facts are observed.')}</div>
          </div>
          
          <!-- Prerequisites -->
          ${prereqBadges.length > 0 ? `
            <div style="margin-bottom: 16px;">
              <div style="font-size: 11px; font-weight: 600; margin-bottom: 8px; color: var(--muted); text-transform: uppercase;">Prerequisites</div>
              <div style="display: flex; gap: 6px; flex-wrap: wrap;">${prereqBadges.join('')}</div>
            </div>
          ` : ''}
          
          <!-- MITRE -->
          ${(mitreTechniques.length > 0 || mitreTactics.length > 0) ? `
            <div style="margin-bottom: 16px;">
              <div style="font-size: 11px; font-weight: 600; margin-bottom: 8px; color: var(--muted); text-transform: uppercase;">MITRE ATT&CK</div>
              ${mitreTechniques.length > 0 ? `<div style="margin-bottom: 4px; font-size: 12px;"><strong>Techniques:</strong> ${mitreTechniques.map(t => `<code style="background: var(--panel2); padding: 1px 4px; border-radius: 2px; font-size: 11px;">${escapeHtml(t)}</code>`).join(' ')}</div>` : ''}
              ${mitreTactics.length > 0 ? `<div style="font-size: 12px;"><strong>Tactics:</strong> ${mitreTactics.map(t => escapeHtml(t)).join(', ')}</div>` : ''}
            </div>
          ` : ''}
          
          <!-- Steps/Slots Structure (Tier A) -->
          ${steps.length > 0 ? `
            <div style="margin-bottom: 16px;">
              <div style="font-size: 11px; font-weight: 600; margin-bottom: 8px; color: var(--muted); text-transform: uppercase;">
                Detection Steps (${steps.length})
                ${hasDerivedStructure ? '<span style="font-size: 9px; color: var(--warn); margin-left: 4px;">DERIVED</span>' : ''}
              </div>
              ${steps.map((step, idx) => `
                <div style="margin-bottom: 6px; padding: 8px; background: var(--panel2); border-radius: 4px; border-left: 3px solid ${step.required !== false ? 'var(--accent)' : 'var(--muted)'};">
                  <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="font-size: 11px;">${escapeHtml(step.name || step.id || `Step ${idx + 1}`)}</strong>
                    <span style="font-size: 9px; color: ${step.required !== false ? 'var(--accent)' : 'var(--muted)'};">${step.required !== false ? 'REQUIRED' : 'optional'}</span>
                  </div>
                  ${step.description ? `<div style="font-size: 10px; color: var(--muted); margin-top: 4px;">${escapeHtml(step.description)}</div>` : ''}
                  ${step.expected_fact_types?.length > 0 ? `<div style="font-size: 10px; color: var(--accent); margin-top: 4px;">📊 ${step.expected_fact_types.join(', ')}</div>` : ''}
                  ${step.window_secs ? `<div style="font-size: 9px; color: var(--muted); margin-top: 2px;">⏱️ ${step.window_secs}s window</div>` : ''}
                </div>
              `).join('')}
            </div>
          ` : `
            <div style="margin-bottom: 16px; padding: 12px; background: var(--panel2); border-radius: 6px; text-align: center;">
              <div style="font-size: 11px; color: var(--muted);">No explicit step structure defined</div>
            </div>
          `}
          
          <!-- Actions -->
          <div style="margin-top: 16px; display: flex; gap: 8px; flex-wrap: wrap;">
            ${playbook.source !== 'custom' ? `
              <button id="btnDuplicatePlaybook" style="padding: 8px 12px; background: var(--panel2); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; font-size: 11px; color: var(--text);">
                📋 Duplicate
              </button>
            ` : ''}
            ${context === 'run' ? `
              <button id="btnViewInCatalog" style="padding: 8px 12px; background: var(--panel2); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; font-size: 11px; color: var(--text);">
                📓 View in Catalog
              </button>
            ` : ''}
          </div>
          
          <!-- Parse Error -->
          ${playbook.parse_error ? `
            <div style="margin-top: 16px; padding: 12px; background: #7f1d1d22; border: 1px solid var(--error); border-radius: 6px;">
              <div style="font-size: 11px; font-weight: 600; color: var(--error); margin-bottom: 4px;">⚠️ Parse Error</div>
              <div style="font-size: 10px; color: var(--error);">${escapeHtml(playbook.parse_error)}</div>
            </div>
          ` : ''}
        </div>
        
        <!-- Trace Tab -->
        <div id="pbTabTrace" class="pb-drawer-content" style="padding: 16px; display: none;">
          <div id="pbTraceContent">
            <div style="text-align: center; padding: 20px; color: var(--muted);">
              <div style="font-size: 13px;">Loading trace...</div>
            </div>
          </div>
        </div>
        
        <!-- YAML Tab -->
        <div id="pbTabYaml" class="pb-drawer-content" style="padding: 16px; display: none;">
          <div id="pbYamlContent">
            ${DEBUG_MODE ? `
              <div style="text-align: center; padding: 20px; color: var(--muted);">
                <div style="font-size: 13px;">Loading YAML...</div>
              </div>
            ` : `
              <div style="text-align: center; padding: 40px; color: var(--muted);">
                <div style="font-size: 32px; margin-bottom: 12px;">🔒</div>
                <div style="font-size: 13px; font-weight: 500;">Dev Mode Required</div>
                <div style="font-size: 11px; margin-top: 8px;">YAML view requires LOCINT_DEV_VIEW=1<br>or ?debug=1 URL parameter</div>
              </div>
            `}
          </div>
        </div>
      </div>
    `;
    
    // Show drawer
    requestAnimationFrame(() => {
      drawer.style.transform = 'translateX(0)';
    });
    
    // Bind close button
    drawer.querySelector('#btnClosePlaybookDrawer').onclick = () => closePlaybookDetailDrawer();
    
    // Tab switching
    drawer.querySelectorAll('.pb-drawer-tab').forEach(tab => {
      tab.onclick = () => {
        const targetTab = tab.dataset.tab;
        
        // Update tab styles
        drawer.querySelectorAll('.pb-drawer-tab').forEach(t => {
          t.classList.remove('active');
          t.style.borderBottomColor = 'transparent';
          t.style.color = 'var(--muted)';
        });
        tab.classList.add('active');
        tab.style.borderBottomColor = 'var(--accent)';
        tab.style.color = 'var(--text)';
        
        // Show/hide content
        drawer.querySelectorAll('.pb-drawer-content').forEach(c => c.style.display = 'none');
        const content = drawer.querySelector(`#pbTab${targetTab.charAt(0).toUpperCase() + targetTab.slice(1)}`);
        if (content) content.style.display = 'block';
        
        // Load trace on first view
        if (targetTab === 'trace') {
          loadPlaybookTrace(playbook.playbook_id, context);
        }
        
        // Load YAML on first view (if dev mode)
        if (targetTab === 'yaml' && DEBUG_MODE) {
          loadPlaybookYaml(playbook.playbook_id);
        }
      };
    });
    
    // Bind Duplicate button
    const dupBtn = drawer.querySelector('#btnDuplicatePlaybook');
    if (dupBtn) {
      dupBtn.onclick = async () => {
        dupBtn.disabled = true;
        dupBtn.textContent = '⏳ Duplicating...';
        try {
          const resp = await fetch(`/api/playbooks/${encodeURIComponent(playbook.playbook_id)}/duplicate`, {
            method: 'POST'
          });
          const data = await resp.json();
          if (data.success) {
            showToast(`✓ Duplicated to ${data.data.new_playbook_id}`, 'success');
            dupBtn.textContent = '✓ Duplicated';
            // Suggest rescan
            setTimeout(() => {
              if (confirm('Playbook duplicated! Rescan playbooks to load it?')) {
                fetch('/api/packs/rescan', { method: 'POST' }).then(() => {
                  loadDetectionPlan();
                  showToast('Playbooks rescanned', 'success');
                });
              }
            }, 500);
          } else {
            showToast(`Error: ${data.error?.message || 'Unknown error'}`, 'error');
            dupBtn.textContent = '📋 Duplicate';
            dupBtn.disabled = false;
          }
        } catch (e) {
          showToast(`Error: ${e.message}`, 'error');
          dupBtn.textContent = '📋 Duplicate';
          dupBtn.disabled = false;
        }
      };
    }
    
    // Bind "View in Catalog" button
    const viewCatalogBtn = drawer.querySelector('#btnViewInCatalog');
    if (viewCatalogBtn) {
      viewCatalogBtn.onclick = () => {
        const catalogPb = detectionPlanCatalog?.find(p => p.playbook_id === playbook.playbook_id);
        if (catalogPb) {
          openPlaybookDetailDrawer(catalogPb, 'catalog');
        }
      };
    }
    
    // Close on escape key
    const escHandler = (e) => {
      if (e.key === 'Escape') {
        closePlaybookDetailDrawer();
        document.removeEventListener('keydown', escHandler);
      }
    };
    document.addEventListener('keydown', escHandler);
  }
  
  /**
   * Load playbook trace for a run (Tier B)
   */
  async function loadPlaybookTrace(playbookId, context) {
    const container = document.getElementById('pbTraceContent');
    if (!container) return;
    
    // If not in run context, show appropriate message
    if (context !== 'run' || !state.selectedRunId) {
      container.innerHTML = `
        <div style="text-align: center; padding: 20px; color: var(--muted);">
          <div style="font-size: 32px; margin-bottom: 12px;">📊</div>
          <div style="font-size: 13px; font-weight: 500;">No Run Selected</div>
          <div style="font-size: 11px; margin-top: 8px;">Trace is only available when viewing a playbook in the context of a specific run.</div>
        </div>
      `;
      return;
    }
    
    try {
      const resp = await fetch(`/api/runs/${state.selectedRunId}/playbooks/eval`);
      const data = await resp.json();
      
      if (!data.success || !data.data?.evaluations) {
        container.innerHTML = `
          <div style="text-align: center; padding: 20px; color: var(--muted);">
            <div style="font-size: 13px;">Trace unavailable: ${data.data?.reason || 'unknown'}</div>
          </div>
        `;
        return;
      }
      
      // Find this playbook's evaluation
      const evalData = data.data.evaluations.find(e => e.playbook_id === playbookId);
      
      if (!evalData) {
        container.innerHTML = `
          <div style="text-align: center; padding: 20px; color: var(--muted);">
            <div style="font-size: 13px;">No evaluation data for this playbook</div>
          </div>
        `;
        return;
      }
      
      // Build trace UI
      const statusIcon = {
        'fired': '✅',
        'blocked': '🚫',
        'no_match': '❌',
        'partial': '⚠️'
      }[evalData.status] || '❓';
      
      const statusColor = {
        'fired': 'var(--good)',
        'blocked': 'var(--error)',
        'no_match': 'var(--muted)',
        'partial': 'var(--warn)'
      }[evalData.status] || 'var(--muted)';
      
      let html = `
        <div style="margin-bottom: 16px; padding: 12px; background: ${statusColor}22; border-radius: 6px; border-left: 4px solid ${statusColor};">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 20px;">${statusIcon}</span>
            <div>
              <div style="font-size: 13px; font-weight: 600; color: ${statusColor}; text-transform: uppercase;">${evalData.status}</div>
              ${evalData.blocked_reason ? `<div style="font-size: 11px; color: var(--muted); margin-top: 2px;">${escapeHtml(evalData.blocked_reason)}</div>` : ''}
            </div>
          </div>
        </div>
      `;
      
      // Fired signals info
      if (evalData.fired_signals?.length > 0) {
        html += `
          <div style="margin-bottom: 16px;">
            <div style="font-size: 11px; font-weight: 600; margin-bottom: 8px; color: var(--good); text-transform: uppercase;">🎯 Fired Signals (${evalData.fired_signals.length})</div>
            ${evalData.fired_signals.map(sig => `
              <div style="padding: 8px; background: var(--panel2); border-radius: 4px; margin-bottom: 4px; border-left: 3px solid var(--good);">
                <div style="font-size: 11px; font-weight: 500;">${escapeHtml(sig.signal_id)}</div>
                <div style="font-size: 10px; color: var(--muted);">Severity: ${sig.severity} | ${new Date(sig.ts).toLocaleString()}</div>
                ${sig.evidence_pointers?.length > 0 ? `<div style="font-size: 10px; color: var(--accent); margin-top: 4px;">📋 ${sig.evidence_pointers.length} evidence pointer(s)</div>` : ''}
              </div>
            `).join('')}
          </div>
        `;
      }
      
      // Step statuses
      if (evalData.step_statuses?.length > 0) {
        html += `
          <div style="margin-bottom: 16px;">
            <div style="font-size: 11px; font-weight: 600; margin-bottom: 8px; color: var(--muted); text-transform: uppercase;">Step Evaluation</div>
            ${evalData.step_statuses.map(step => {
              const stepIcon = {
                'matched': '✅',
                'blocked': '🚫',
                'unmatched': '❌',
                'partial': '⚠️'
              }[step.status] || '❓';
              const stepColor = {
                'matched': 'var(--good)',
                'blocked': 'var(--error)',
                'unmatched': 'var(--muted)',
                'partial': 'var(--warn)'
              }[step.status] || 'var(--muted)';
              
              return `
                <div style="padding: 8px; background: var(--panel2); border-radius: 4px; margin-bottom: 4px; border-left: 3px solid ${stepColor};">
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span>${stepIcon}</span>
                    <div style="flex: 1;">
                      <div style="font-size: 11px; font-weight: 500;">${escapeHtml(step.step_name || step.step_id)}</div>
                      ${step.reason ? `<div style="font-size: 10px; color: var(--muted);">${escapeHtml(step.reason)}</div>` : ''}
                      ${step.note ? `<div style="font-size: 10px; color: var(--warn); font-style: italic;">${escapeHtml(step.note)}</div>` : ''}
                    </div>
                  </div>
                  ${step.expected_fact_types?.length > 0 ? `<div style="font-size: 10px; color: var(--accent); margin-top: 4px; margin-left: 24px;">Expected: ${step.expected_fact_types.join(', ')}</div>` : ''}
                </div>
              `;
            }).join('')}
          </div>
        `;
      } else if (evalData.trace_note) {
        html += `
          <div style="padding: 12px; background: var(--panel2); border-radius: 6px; text-align: center;">
            <div style="font-size: 11px; color: var(--warn);">⚠️ ${escapeHtml(evalData.trace_note)}</div>
          </div>
        `;
      }
      
      container.innerHTML = html;
      
    } catch (e) {
      container.innerHTML = `
        <div style="text-align: center; padding: 20px; color: var(--error);">
          <div style="font-size: 13px;">Error loading trace: ${escapeHtml(e.message)}</div>
        </div>
      `;
    }
  }
  
  /**
   * Load playbook YAML content (Tier C - dev mode only)
   */
  async function loadPlaybookYaml(playbookId) {
    const container = document.getElementById('pbYamlContent');
    if (!container) return;
    
    try {
      const resp = await fetch(`/api/playbooks/${encodeURIComponent(playbookId)}/yaml`);
      const data = await resp.json();
      
      if (!data.success) {
        container.innerHTML = `
          <div style="text-align: center; padding: 20px; color: var(--error);">
            <div style="font-size: 13px;">${escapeHtml(data.error?.message || 'Failed to load YAML')}</div>
          </div>
        `;
        return;
      }
      
      const yamlContent = data.data.yaml_content || '';
      
      container.innerHTML = `
        <div style="margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
          <div style="font-size: 10px; color: var(--muted);">${escapeHtml(data.data.file_path || '')} (${data.data.size_bytes || 0} bytes)</div>
          <button id="btnCopyYaml" style="padding: 4px 8px; background: var(--panel2); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; font-size: 10px; color: var(--text);">
            📋 Copy
          </button>
        </div>
        <pre style="background: var(--panel2); padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 11px; line-height: 1.4; white-space: pre-wrap; word-break: break-word; max-height: 60vh; overflow-y: auto; border: 1px solid var(--border);">${escapeHtml(yamlContent)}</pre>
      `;
      
      // Bind copy button
      const copyBtn = container.querySelector('#btnCopyYaml');
      if (copyBtn) {
        copyBtn.onclick = () => {
          navigator.clipboard.writeText(yamlContent).then(() => {
            copyBtn.textContent = '✓ Copied';
            setTimeout(() => { copyBtn.textContent = '📋 Copy'; }, 2000);
          });
        };
      }
      
    } catch (e) {
      container.innerHTML = `
        <div style="text-align: center; padding: 20px; color: var(--error);">
          <div style="font-size: 13px;">Error: ${escapeHtml(e.message)}</div>
        </div>
      `;
    }
  }

  /**
   * Close the playbook detail drawer
   */
  function closePlaybookDetailDrawer() {
    const drawer = document.getElementById('playbookDetailDrawer');
    if (drawer) {
      drawer.style.transform = 'translateX(100%)';
      setTimeout(() => { selectedPlaybookId = null; }, 250);
    }
  }

  // ============================================================================
  // Evidence Viewer Drawer (uses same pattern as playbook detail drawer)
  // ============================================================================

  let evidenceDrawerEscHandler = null; // Track ESC handler for cleanup

  /**
   * Open the Evidence Viewer drawer to dereference an evidence pointer
   * Uses the same drawer pattern as playbook detail drawer for consistency.
   * @param {Object} ptr - Evidence pointer with run_id, stream_id, segment_id, record_index
   */
  async function openEvidenceViewer(ptr) {
    // Create or get the drawer element
    let drawer = document.getElementById('evidenceViewerDrawer');
    if (!drawer) {
      drawer = document.createElement('div');
      drawer.id = 'evidenceViewerDrawer';
      drawer.style.cssText = `
        position: fixed; right: 0; top: 0; width: 500px; max-width: 90vw; height: 100vh;
        background: var(--panel); border-left: 1px solid var(--border);
        z-index: 1001; overflow-y: auto; transform: translateX(100%);
        transition: transform 0.25s ease-out; box-shadow: -4px 0 20px rgba(0,0,0,0.3);
      `;
      drawer.setAttribute('role', 'dialog');
      drawer.setAttribute('aria-modal', 'true');
      drawer.setAttribute('aria-label', 'Evidence Viewer');
      document.body.appendChild(drawer);
    }
    
    // Build segment_id display (now it's the filename string)
    const segmentDisplay = escapeHtml(String(ptr.segment_id || '?'));
    const ptrSummary = `${escapeHtml(ptr.stream_id || '?')}:${segmentDisplay}:${ptr.record_index ?? '?'}`;
    
    // Show loading state
    drawer.innerHTML = `
      <div style="padding: 16px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: var(--panel2);">
        <div>
          <div style="font-size: 14px; font-weight: 600;">📋 Evidence Viewer</div>
          <div style="font-size: 11px; color: var(--muted);">${ptrSummary}</div>
        </div>
        <button id="btnCloseEvidenceDrawer" style="background: transparent; border: none; font-size: 20px; cursor: pointer; color: var(--muted); padding: 4px 8px;" aria-label="Close">✕</button>
      </div>
      <div style="padding: 24px; text-align: center;">
        <div style="color: var(--muted);">Loading evidence...</div>
      </div>
    `;
    
    // Show drawer with animation
    requestAnimationFrame(() => {
      drawer.style.transform = 'translateX(0)';
    });
    
    // Setup close handler
    const closeBtn = drawer.querySelector('#btnCloseEvidenceDrawer');
    if (closeBtn) {
      closeBtn.onclick = () => closeEvidenceViewer();
    }
    
    // Setup ESC handler (remove any previous one first)
    if (evidenceDrawerEscHandler) {
      document.removeEventListener('keydown', evidenceDrawerEscHandler);
    }
    evidenceDrawerEscHandler = (e) => {
      if (e.key === 'Escape') {
        closeEvidenceViewer();
      }
    };
    document.addEventListener('keydown', evidenceDrawerEscHandler);
    
    // Focus trap: focus the close button
    setTimeout(() => {
      const closeBtn = drawer.querySelector('#btnCloseEvidenceDrawer');
      if (closeBtn) closeBtn.focus();
    }, 100);
    
    // Fetch the evidence
    // CONTRACT: Backend expects (run_id, segment_id, offset, context_lines)
    // EvidencePtr uses record_index which maps to offset (line number in segment)
    try {
      const params = new URLSearchParams({
        run_id: ptr.run_id,
        segment_id: String(ptr.segment_id),
        offset: String(ptr.record_index ?? ptr.offset ?? 0),
        context_lines: '3'  // Provide some context around the record
      });
      
      const resp = await api(`/api/evidence/deref?${params.toString()}`);
      
      if (!resp || !resp.data) {
        renderEvidenceError(drawer, 'No response from server', ptr);
        return;
      }
      
      if (resp.data.available) {
        renderEvidenceSuccess(drawer, resp.data, ptr);
      } else {
        renderEvidenceUnavailable(drawer, resp.data, ptr);
      }
    } catch (err) {
      renderEvidenceError(drawer, err.message || 'Failed to fetch evidence', ptr);
    }
  }

  /**
   * Render evidence drawer with successfully resolved data (XSS-safe)
   * CONTRACT: Backend returns resolved.record (the JSON object) not resolved.json
   */
  function renderEvidenceSuccess(drawer, data, ptr) {
    const resolved = data.resolved;
    // Backend returns "record" not "json" - handle both for backwards compat
    const jsonData = resolved.record ?? resolved.json;
    const hasJson = jsonData != null;
    
    // Extract segment_info from backend response
    const segmentInfo = resolved.segment_info || {};
    
    // XSS-safe: Pretty print JSON and escape for display
    let contentHtml;
    if (hasJson) {
      // Stringify then escape to prevent XSS
      const prettyJson = JSON.stringify(jsonData, null, 2);
      contentHtml = `<pre style="margin: 0; padding: 12px; background: var(--panel2); border-radius: 4px; overflow: auto; max-height: 400px; font-size: 11px; line-height: 1.5; white-space: pre-wrap; word-break: break-all;">${escapeHtml(prettyJson)}</pre>`;
    } else {
      // XSS-safe: escape the preview and error message
      contentHtml = `
        <div style="padding: 12px; background: var(--panel2); border-radius: 4px; margin-bottom: 8px;">
          <div style="color: var(--warn); font-size: 12px; margin-bottom: 8px;">⚠️ JSON parse failed: ${escapeHtml(resolved.json_parse_error || 'Unknown error')}</div>
          <pre style="margin: 0; overflow: auto; max-height: 300px; font-size: 11px; white-space: pre-wrap; word-break: break-all;">${escapeHtml(resolved.preview || '(no preview)')}</pre>
        </div>
      `;
    }
    
    // Format timestamp from record if available (backend doesn't extract ts_ms)
    // Try common timestamp field names from the record itself
    const tsFromRecord = jsonData?.ts || jsonData?.timestamp || jsonData?.TimeCreated || jsonData?.EventTime;
    const tsDisplay = tsFromRecord 
      ? (typeof tsFromRecord === 'number' ? new Date(tsFromRecord).toISOString() : tsFromRecord)
      : '(not extracted)';
    
    // Build segment_id display
    const segmentDisplay = escapeHtml(String(ptr.segment_id || '?'));
    const ptrSummary = `${escapeHtml(ptr.stream_id || '?')}:${segmentDisplay}:${ptr.record_index ?? '?'}`;
    
    drawer.innerHTML = `
      <div style="padding: 16px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: var(--panel2);">
        <div>
          <div style="font-size: 14px; font-weight: 600;">📋 Evidence Viewer</div>
          <div style="font-size: 11px; color: var(--muted);">${ptrSummary}</div>
        </div>
        <button id="btnCloseEvidenceDrawer" style="background: transparent; border: none; font-size: 20px; cursor: pointer; color: var(--muted); padding: 4px 8px;" aria-label="Close">✕</button>
      </div>
      
      <div style="padding: 16px;">
        <!-- Metadata -->
        <div style="margin-bottom: 16px; display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
          <div style="padding: 10px; background: var(--panel2); border-radius: 4px;">
            <div style="font-size: 10px; color: var(--muted); margin-bottom: 4px;">Timestamp</div>
            <div style="font-size: 12px; font-family: monospace;">${escapeHtml(tsDisplay)}</div>
          </div>
          <div style="padding: 10px; background: var(--panel2); border-radius: 4px;">
            <div style="font-size: 10px; color: var(--muted); margin-bottom: 4px;">Segment</div>
            <div style="font-size: 12px; font-family: monospace;">Line ${ptr.record_index ?? ptr.offset ?? '?'} of ${segmentInfo.total_lines ?? '?'}</div>
          </div>
        </div>
        
        <!-- Segment Info - use backend segment_info fields -->
        <div style="margin-bottom: 16px; padding: 10px; background: var(--panel2); border-radius: 4px;">
          <div style="font-size: 10px; color: var(--muted); margin-bottom: 4px;">Segment File</div>
          <div style="font-size: 11px; font-family: monospace; word-break: break-all;">${escapeHtml(segmentInfo.segment_id || ptr.segment_id || '(unknown)')}.jsonl</div>
          ${segmentInfo.file_size ? `<div style="font-size: 10px; color: var(--muted); margin-top: 4px;">File size: ${(segmentInfo.file_size / 1024).toFixed(1)} KB</div>` : ''}
        </div>
        </div>
        
        <!-- Content -->
        <div style="margin-bottom: 16px;">
          <div style="font-size: 12px; font-weight: 600; margin-bottom: 8px; color: var(--muted);">Record Content</div>
          ${contentHtml}
        </div>
        
        <!-- Actions -->
        <div style="display: flex; gap: 8px;">
          <button id="btnCopyEvidenceJson" style="padding: 8px 16px; background: var(--accent); color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500;">
            📋 Copy JSON
          </button>
          <button id="btnDownloadEvidenceJson" style="padding: 8px 16px; background: var(--panel2); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; font-size: 12px; color: var(--text);">
            💾 Download
          </button>
        </div>
      </div>
    `;
    
    // Bind close handler
    drawer.querySelector('#btnCloseEvidenceDrawer').onclick = () => closeEvidenceViewer();
    
    // Copy button
    const copyBtn = drawer.querySelector('#btnCopyEvidenceJson');
    if (copyBtn && hasJson) {
      copyBtn.onclick = () => {
        const text = JSON.stringify(jsonData, null, 2);
        navigator.clipboard.writeText(text).then(() => {
          copyBtn.textContent = '✓ Copied!';
          setTimeout(() => { copyBtn.textContent = '📋 Copy JSON'; }, 2000);
        });
      };
    } else if (copyBtn) {
      copyBtn.disabled = true;
      copyBtn.style.opacity = '0.5';
    }
    
    // Download button
    const downloadBtn = drawer.querySelector('#btnDownloadEvidenceJson');
    if (downloadBtn && hasJson) {
      downloadBtn.onclick = () => {
        const text = JSON.stringify(jsonData, null, 2);
        const blob = new Blob([text], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `evidence_${escapeHtml(ptr.stream_id || 'unknown')}_${ptr.segment_id}_${ptr.record_index}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      };
    } else if (downloadBtn) {
      downloadBtn.disabled = true;
      downloadBtn.style.opacity = '0.5';
    }
    
    // Focus close button for keyboard accessibility
    setTimeout(() => {
      drawer.querySelector('#btnCloseEvidenceDrawer')?.focus();
    }, 50);
  }

  /**
   * Render evidence drawer with unavailable state (XSS-safe)
   */
  function renderEvidenceUnavailable(drawer, data, ptr) {
    const reasonCode = escapeHtml(data.reason_code || 'UNKNOWN');
    const message = escapeHtml(data.message || 'Evidence is not available.');
    
    // Map reason codes to user-friendly guidance
    // Backend uses: MISSING_RUN_ID, MISSING_SEGMENT_ID, RUN_NOT_FOUND, SEGMENT_NOT_FOUND,
    //               OFFSET_OUT_OF_BOUNDS, PARSE_ERROR, IO_ERROR, PATH_TRAVERSAL
    const guidance = {
      'RUN_NOT_FOUND': 'The run may have been deleted or the run_id is incorrect.',
      'SEGMENT_NOT_FOUND': 'The segment file was not found. It may have been deleted or the segment_id is incorrect.',
      'OFFSET_OUT_OF_BOUNDS': 'The record offset exceeds the number of lines in the segment file.',
      'RECORD_INDEX_OUT_OF_RANGE': 'The record index exceeds the number of lines in the segment file.',  // Legacy alias
      'PARSE_ERROR': 'The record exists but contains invalid JSON.',
      'JSON_PARSE_FAILED': 'The record exists but contains invalid JSON.',  // Legacy alias
      'PATH_TRAVERSAL': 'The request was blocked for security reasons.',
      'PATH_TRAVERSAL_BLOCKED': 'The request was blocked for security reasons.',  // Legacy alias
      'EVIDENCE_KIND_UNSUPPORTED': 'Only segment_record evidence pointers can be dereferenced currently.',
      'IMPORTED_BUNDLE_MISSING_SEGMENTS': 'This imported bundle does not include the original segment files. Export the bundle with segments included to enable evidence viewing.',
      'IO_ERROR': 'A file system error occurred while reading the segment.',
      'SCAN_LIMIT_EXCEEDED': 'The record is too deep in the file or the line is too large to retrieve safely.',
      'MISSING_RUN_ID': 'Missing required run_id parameter.',
      'MISSING_SEGMENT_ID': 'Missing required segment_id parameter.',
    };
    
    // Build segment_id display
    const segmentDisplay = escapeHtml(String(ptr.segment_id || '?'));
    const ptrSummary = `${escapeHtml(ptr.stream_id || '?')}:${segmentDisplay}:${ptr.record_index ?? '?'}`;
    
    drawer.innerHTML = `
      <div style="padding: 16px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: var(--panel2);">
        <div>
          <div style="font-size: 14px; font-weight: 600;">📋 Evidence Viewer</div>
          <div style="font-size: 11px; color: var(--muted);">${ptrSummary}</div>
        </div>
        <button id="btnCloseEvidenceDrawer" style="background: transparent; border: none; font-size: 20px; cursor: pointer; color: var(--muted); padding: 4px 8px;" aria-label="Close">✕</button>
      </div>
      
      <div style="padding: 24px;">
        <div style="text-align: center; margin-bottom: 20px;">
          <div style="font-size: 48px; margin-bottom: 12px;">⚠️</div>
          <div style="font-size: 14px; font-weight: 600; color: var(--warn); margin-bottom: 8px;">Evidence Not Available</div>
        </div>
        
        <div style="padding: 12px; background: var(--panel2); border-radius: 4px; margin-bottom: 16px;">
          <div style="font-size: 10px; color: var(--muted); margin-bottom: 4px;">Reason Code</div>
          <div style="font-size: 12px; font-family: monospace; color: var(--error);">${reasonCode}</div>
        </div>
        
        <div style="padding: 12px; background: var(--panel2); border-radius: 4px; margin-bottom: 16px;">
          <div style="font-size: 10px; color: var(--muted); margin-bottom: 4px;">Details</div>
          <div style="font-size: 12px;">${message}</div>
        </div>
        
        ${guidance[data.reason_code] ? `
          <div style="padding: 12px; background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 4px;">
            <div style="font-size: 11px; color: var(--accent);">💡 ${escapeHtml(guidance[data.reason_code])}</div>
          </div>
        ` : ''}
      </div>
    `;
    
    drawer.querySelector('#btnCloseEvidenceDrawer').onclick = () => closeEvidenceViewer();
    
    // Focus close button
    setTimeout(() => {
      drawer.querySelector('#btnCloseEvidenceDrawer')?.focus();
    }, 50);
  }

  /**
   * Render evidence drawer with error state (XSS-safe)
   */
  function renderEvidenceError(drawer, errorMsg, ptr) {
    // Build segment_id display
    const segmentDisplay = escapeHtml(String(ptr.segment_id || '?'));
    const ptrSummary = `${escapeHtml(ptr.stream_id || '?')}:${segmentDisplay}:${ptr.record_index ?? '?'}`;
    
    drawer.innerHTML = `
      <div style="padding: 16px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: var(--panel2);">
        <div>
          <div style="font-size: 14px; font-weight: 600;">📋 Evidence Viewer</div>
          <div style="font-size: 11px; color: var(--muted);">${ptrSummary}</div>
        </div>
        <button id="btnCloseEvidenceDrawer" style="background: transparent; border: none; font-size: 20px; cursor: pointer; color: var(--muted); padding: 4px 8px;" aria-label="Close">✕</button>
      </div>
      
      <div style="padding: 24px; text-align: center;">
        <div style="font-size: 48px; margin-bottom: 12px;">❌</div>
        <div style="font-size: 14px; font-weight: 600; color: var(--error); margin-bottom: 8px;">Error Loading Evidence</div>
        <div style="font-size: 12px; color: var(--muted);">${escapeHtml(errorMsg)}</div>
      </div>
    `;
    
    drawer.querySelector('#btnCloseEvidenceDrawer').onclick = () => closeEvidenceViewer();
    
    // Focus close button
    setTimeout(() => {
      drawer.querySelector('#btnCloseEvidenceDrawer')?.focus();
    }, 50);
  }

  /**
   * Close the Evidence Viewer drawer
   */
  function closeEvidenceViewer() {
    const drawer = document.getElementById('evidenceViewerDrawer');
    if (drawer) {
      drawer.style.transform = 'translateX(100%)';
    }
    // Remove ESC handler
    if (evidenceDrawerEscHandler) {
      document.removeEventListener('keydown', evidenceDrawerEscHandler);
      evidenceDrawerEscHandler = null;
    }
  }

  /**
   * Fetch run status - GET /api/run/status
   * This is the SINGLE SOURCE OF TRUTH for run state
   */
  async function fetchRunStatus() {
    // Skip if in imported mode (read-only)
    if (state.importedMode) {
      console.log('[fetchRunStatus] Skipped: imported mode');
      return null;
    }
    
    try {
      const data = await api('/api/run/status');
      
      // Update state from backend ONLY
      const wasRunning = state.isRunning;
      state.isRunning = data.running === true;
      state.runId = data.run_id || null;
      state.startedAt = data.started_at || null;
      state.elapsedSeconds = data.elapsed_seconds ?? null;
      state.profile = data.profile || null;
      
      // Stop explain refresh when run stops (explanation won't change anymore)
      if (wasRunning && !state.isRunning) {
        stopExplainRefresh();
      }
      
      // Update UI based on backend state
      if (state.isRunning) {
        updateRunningUI();
      } else {
        updateStoppedUI();
      }
      
      return data;
    } catch (err) {
      // On error, assume not running (safe default)
      state.isRunning = false;
      state.runId = null;
      state.startedAt = null;
      state.elapsedSeconds = null;
      updateStoppedUI();
      
      if (err.status !== 0) {
        console.warn('[fetchRunStatus] Error:', err.message);
      }
      return null;
    }
  }

  /**
   * Fetch run metrics - GET /api/run/metrics
   */
  async function fetchMetrics() {
    // Skip if not running or offline
    if (!state.isRunning || !state.serverOnline) return;
    
    try {
      const data = await api('/api/run/metrics');
      
      // Map backend field names to our state
      // Use ?? to preserve 0 values, only null/undefined become null
      state.counters = {
        events: data.events_total ?? data.events ?? null,
        segments: data.segments_count ?? data.segments_written ?? data.segments ?? null,
        facts: data.facts_extracted ?? data.facts ?? null,
        signals: data.signals_fired ?? data.signals_emitted ?? data.signals ?? null
      };
      
      // Update elapsed from metrics if available
      if (data.elapsed_seconds != null) {
        state.elapsedSeconds = data.elapsed_seconds;
        if (els.runDuration) {
          els.runDuration.textContent = formatDuration(state.elapsedSeconds);
        }
      }
      
      updateCountersUI();
      
      // Also update noise diagnostics with current run stats
      updateNoiseDiagnostics(data);
    } catch (err) {
      // On metrics failure, show "—" for counters and show error banner
      console.warn('[fetchMetrics] Error:', err.message);
      state.counters = { events: null, segments: null, facts: null, signals: null };
      updateCountersUI();
      showError(`Metrics unavailable: ${err.message}`, { endpoint: err.endpoint });
    }
  }

  /**
   * Update noise diagnostics UI with current run metrics
   * Shows signals/min, top playbook, top entity, collapsed count
   */
  function updateNoiseDiagnostics(metrics) {
    // Calculate signals per minute
    const signalsFired = metrics?.signals_fired ?? metrics?.signals ?? 0;
    const elapsedSec = metrics?.elapsed_seconds ?? state.elapsedSeconds ?? 0;
    const elapsedMin = elapsedSec / 60;
    const signalsPerMin = elapsedMin > 0 ? (signalsFired / elapsedMin).toFixed(1) : '—';
    
    if (els.signalsPerMin) {
      els.signalsPerMin.textContent = signalsPerMin;
    }
    
    // Top playbook - show value if present, else "—" (no signals yet)
    if (els.topPlaybook) {
      if (metrics?.top_playbook) {
        // Truncate long playbook names
        const pb = metrics.top_playbook;
        els.topPlaybook.textContent = pb.length > 20 ? pb.slice(0, 20) + '…' : pb;
        els.topPlaybook.title = pb; // Full name on hover
      } else if (signalsFired > 0) {
        // Signals exist but no top_playbook from backend
        els.topPlaybook.textContent = '—';
        els.topPlaybook.title = '';
      } else {
        els.topPlaybook.textContent = '—';
        els.topPlaybook.title = 'No signals yet';
      }
    }
    
    // Top entity - show value if present, else "—"
    if (els.topEntity) {
      if (metrics?.top_entity) {
        // Truncate long entity names
        const ent = metrics.top_entity;
        els.topEntity.textContent = ent.length > 20 ? ent.slice(0, 20) + '…' : ent;
        els.topEntity.title = ent; // Full name on hover
      } else if (signalsFired > 0) {
        els.topEntity.textContent = '—';
        els.topEntity.title = '';
      } else {
        els.topEntity.textContent = '—';
        els.topEntity.title = 'No signals yet';
      }
    }
    
    // Collapsed count
    if (els.dedupeCount) {
      const collapsed = metrics?.collapsed_count ?? metrics?.dedupe_count ?? metrics?.collapsed;
      els.dedupeCount.textContent = collapsed != null ? String(collapsed) : '—';
    }
    
    // Make noise section visible (full opacity)
    setNoiseOpacity(1);
    if (els.noiseHint) els.noiseHint.classList.add('hidden');
  }

  /**
   * Start run - POST /api/run/start
   * HARD FAIL if backend offline or missing binaries
   */
  async function startRun() {
    // HARD FAIL #1: Backend offline
    // This should rarely happen since UI is served BY the backend
    if (!state.serverOnline) {
      showError('Backend connection lost. Refresh the page or restart edr-server.exe', { 
        inCard: true, 
        showActions: false 
      });
      return;
    }
    
    // HARD FAIL #2: In imported mode
    if (state.importedMode) {
      showError('Cannot start: viewing imported data. Return to local mode first.', { 
        inCard: true 
      });
      return;
    }
    
    const profile = els.profileSelect?.value || 'extended';
    const durationMin = parseInt(els.durationSelect?.value || '10', 10);
    
    // Disable button and show spinner
    if (els.btnStartRun) {
      els.btnStartRun.disabled = true;
      els.btnStartRun.textContent = '⏳ Starting...';
    }
    
    try {
      hideError();
      
      // Build playbook selection payload
      const playbookSelection = getPlaybookSelectionPayload();
      
      const data = await api('/api/run/start', {
        method: 'POST',
        body: JSON.stringify({
          profile: profile,
          duration_s: durationMin * 60,
          playbook_selection: playbookSelection
        })
      });
      
      console.log('[startRun] Response:', data);
      
      // DO NOT assume running - re-fetch status from backend
      await fetchRunStatus();
      
      // If running, fetch initial metrics
      if (state.isRunning) {
        await fetchMetrics();
      }
      
    } catch (err) {
      console.error('[startRun] Error:', err);
      
      let errorMsg = err.message;
      let isMissingBinaries = false;
      let fixCommands = [];
      
      // Handle specific error codes
      if (err.status === 412 || err.code === 'MISSING_BINARIES' || (err.body && err.body.code === 'MISSING_BINARIES')) {
        isMissingBinaries = true;
        const body = err.body || {};
        const missing = body.missing || [];
        fixCommands = body.fix || [
          'cargo build --release -p agent-windows --bin capture_windows_rotating',
          'cargo build --release -p edr-locald --bin edr-locald'
        ];
        errorMsg = `Missing capture binaries: ${missing.join(', ') || 'capture, locald'}`;
      } else if (err.status === 409) {
        errorMsg = 'A run is already in progress.';
        // Re-fetch status to sync UI
        await fetchRunStatus();
      } else if (err.status === 404) {
        errorMsg = 'Run endpoint not found. Update edr-server.';
      } else if (err.code === 'NETWORK_ERROR') {
        errorMsg = 'Connection lost. Refresh the page.';
        state.serverOnline = false;
        updateServerBadge(false);
      } else if (err.code === 'HTML_RESPONSE') {
        errorMsg = 'API returned HTML; check same-origin (:3000) and base path';
      }
      
      showError(errorMsg, { 
        inCard: true, 
        showActions: isMissingBinaries, 
        isMissingBinaries,
        fixCommands,
        endpoint: err.endpoint 
      });
      
    } finally {
      // Re-enable button
      if (els.btnStartRun && !state.isRunning) {
        els.btnStartRun.disabled = false;
        els.btnStartRun.textContent = '▶️ Start Run';
      }
    }
  }

  /**
   * Stop run - POST /api/run/stop
   * After stop, auto-selects the just-completed run to show findings
   */
  async function stopRun() {
    if (els.btnStopRun) {
      els.btnStopRun.disabled = true;
      els.btnStopRun.textContent = '⏳ Stopping...';
    }
    
    try {
      hideError();
      
      // Capture the run_id BEFORE stopping (from stop response or current state)
      const stopResp = await api('/api/run/stop', { method: 'POST' });
      const stopData = stopResp.data || stopResp;
      const stoppedRunId = stopData.run_id || state.runId;
      
      console.log('[stopRun] Stopped run:', stoppedRunId);
      
      // DO NOT assume stopped - re-fetch status from backend
      await fetchRunStatus();
      
      // Refresh runs list (new run should appear)
      await fetchRuns();
      
      // AUTO-SELECT the just-stopped run so user sees findings immediately
      // This is critical for the "Findings don't update" flake
      if (stoppedRunId && state.runs.length > 0) {
        // Find the run in the list
        const stoppedRun = state.runs.find(r => (r.run_id || r.id) === stoppedRunId);
        if (stoppedRun) {
          console.log('[stopRun] Auto-selecting stopped run:', stoppedRunId);
          selectRun(stoppedRunId);
          
          // Show post-stop teaser notification
          showPostStopTeaser(stoppedRunId);
        } else {
          console.warn('[stopRun] Stopped run not found in runs list:', stoppedRunId);
          // Fall back to selecting first run
          if (!state.selectedRunId) {
            selectRun(state.runs[0].run_id || state.runs[0].id);
          }
        }
      }
      
    } catch (err) {
      console.error('[stopRun] Error:', err);
      showError(`Failed to stop: ${err.message}`, { inCard: true, endpoint: err.endpoint });
      
    } finally {
      // Re-enable button if still running
      if (els.btnStopRun && state.isRunning) {
        els.btnStopRun.disabled = false;
        els.btnStopRun.textContent = '⏹️ Stop Run';
      }
    }
  }

  /**
   * Show post-stop teaser notification with quick next steps preview
   */
  async function showPostStopTeaser(runId) {
    try {
      const resp = await fetch(`/api/runs/${runId}/next_steps`);
      if (!resp.ok) return;
      
      const json = await resp.json();
      if (!json.success || !json.data) return;
      
      const data = json.data;
      const scenario = data.scenario || 'unknown';
      const summaryText = data.summary?.text || 'Run completed';
      
      // Create teaser notification element
      let teaser = document.getElementById('postStopTeaser');
      if (!teaser) {
        teaser = document.createElement('div');
        teaser.id = 'postStopTeaser';
        teaser.style.cssText = `
          position: fixed; bottom: 20px; right: 20px; max-width: 400px;
          background: var(--panel); border: 1px solid var(--border); 
          border-radius: var(--radius-md); box-shadow: 0 4px 20px rgba(0,0,0,0.3);
          z-index: 1000; padding: 16px; animation: slideInRight 0.3s ease-out;
        `;
        document.body.appendChild(teaser);
        
        // Add animation keyframes if not present
        if (!document.getElementById('teaserAnimationStyle')) {
          const style = document.createElement('style');
          style.id = 'teaserAnimationStyle';
          style.textContent = `
            @keyframes slideInRight {
              from { transform: translateX(100%); opacity: 0; }
              to { transform: translateX(0); opacity: 1; }
            }
          `;
          document.head.appendChild(style);
        }
      }
      
      // Severity color
      const severityColors = {
        'high': 'var(--error)',
        'medium': 'var(--warn)',
        'low': 'var(--accent)',
        'info': 'var(--good)'
      };
      const borderColor = severityColors[data.summary?.severity] || 'var(--good)';
      teaser.style.borderLeftWidth = '4px';
      teaser.style.borderLeftColor = borderColor;
      
      teaser.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
          <div style="font-weight: 600; font-size: 14px; color: var(--text);">✓ Run Completed</div>
          <button id="closeTeaserBtn" style="background: transparent; border: none; font-size: 16px; cursor: pointer; color: var(--muted); padding: 0;">✕</button>
        </div>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 12px; line-height: 1.4;">${escapeHtml(summaryText)}</div>
        <button id="viewNextStepsBtn" style="width: 100%; padding: 8px 16px; background: var(--accent); color: white; border: none; border-radius: var(--radius-sm); cursor: pointer; font-size: 12px; font-weight: 500;">
          View Next Steps →
        </button>
      `;
      
      // Bind close button
      teaser.querySelector('#closeTeaserBtn').onclick = () => {
        teaser.remove();
      };
      
      // Bind view button - scroll to Next Steps panel
      teaser.querySelector('#viewNextStepsBtn').onclick = () => {
        teaser.remove();
        // Ensure Runs tab is active and run is selected
        switchTab('runs');
        if (runId !== state.selectedRunId) {
          selectRun(runId);
        }
        // Scroll to Next Steps panel
        setTimeout(() => {
          if (els.runNextStepsPanel) {
            els.runNextStepsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }
        }, 200);
      };
      
      // Auto-dismiss after 15 seconds
      setTimeout(() => {
        if (teaser.parentNode) {
          teaser.style.opacity = '0';
          teaser.style.transition = 'opacity 0.3s';
          setTimeout(() => teaser.remove(), 300);
        }
      }, 15000);
      
    } catch (err) {
      console.warn('[PostStopTeaser] Error:', err);
    }
  }

  /**
   * Restart as Administrator - POST /api/app/restart_admin
   * Triggers UAC elevation prompt. On success, app exits and relaunches elevated.
   * After relaunch, polls for up to 10s to reconnect to elevated server.
   */
  async function restartAsAdmin() {
    if (!state.supportsRestartAdmin) {
      showError('Restart as Administrator not supported', { inCard: true });
      return;
    }
    
    // Prevent double-click
    if (state.isRestartingAsAdmin) return;
    state.isRestartingAsAdmin = true;
    
    // Update button UI
    if (els.btnRestartAdmin) {
      els.btnRestartAdmin.disabled = true;
      els.btnRestartAdmin.textContent = '⏳ Requesting elevation...';
    }
    if (els.restartAdminHint) {
      els.restartAdminHint.textContent = 'UAC prompt will appear...';
    }
    
    try {
      const data = await api('/api/app/restart_admin', { method: 'POST' });
      
      console.log('[restartAsAdmin] Response:', data);
      
      // Check if already admin (no restart needed)
      if (data.relaunching === false) {
        state.isRestartingAsAdmin = false;
        if (els.btnRestartAdmin) {
          els.btnRestartAdmin.textContent = '✓ Already Admin';
          els.btnRestartAdmin.disabled = true;
        }
        if (els.restartAdminHint) {
          els.restartAdminHint.textContent = 'Already running with elevated privileges';
        }
        // Refresh readiness to update UI
        await checkReadiness();
        return;
      }
      
      // UAC was approved and app is about to exit - start reconnect polling
      await pollForElevatedReconnect();
      
    } catch (err) {
      console.error('[restartAsAdmin] Error:', err);
      
      // Parse error codes from backend
      const body = err.body || {};
      const errorCode = body.code || err.code || '';
      
      let userMsg = 'Failed to restart as Administrator';
      let hint = 'Try right-clicking locint.exe → Run as administrator';
      
      if (errorCode === 'UAC_CANCELED') {
        userMsg = 'Elevation canceled';
        hint = 'You declined the UAC prompt. Click again to retry.';
        resetRestartAdminUI(userMsg, hint);
      } else if (errorCode === 'UAC_FAILED') {
        userMsg = 'UAC elevation failed';
        hint = body.message || 'Try manually: right-click locint.exe → Run as administrator';
        resetRestartAdminUI(userMsg, hint);
      } else if (errorCode === 'RESTART_NOT_SUPPORTED') {
        userMsg = 'Restart not supported';
        hint = 'This feature requires the desktop app (locint.exe)';
        state.supportsRestartAdmin = false;
        resetRestartAdminUI(userMsg, hint);
      } else if (err.code === 'NETWORK_ERROR') {
        // Connection dropped - this likely means success (app exited)
        // Start polling for reconnect
        await pollForElevatedReconnect();
      } else {
        resetRestartAdminUI(userMsg, hint);
      }
    }
  }
  
  /**
   * Poll for reconnection after admin restart.
   * Waits up to 10s for the elevated server to become reachable.
   */
  async function pollForElevatedReconnect() {
    // Show "relaunching" state
    if (els.btnRestartAdmin) {
      els.btnRestartAdmin.textContent = '⏳ Relaunching...';
    }
    if (els.restartAdminHint) {
      els.restartAdminHint.textContent = 'Waiting for elevated server...';
    }
    
    const maxAttempts = 20;  // 10 seconds (500ms intervals)
    const pollInterval = 500;
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      await new Promise(r => setTimeout(r, pollInterval));
      
      // Update progress hint
      const elapsed = (attempt * pollInterval / 1000).toFixed(1);
      if (els.restartAdminHint) {
        els.restartAdminHint.textContent = `Reconnecting... (${elapsed}s)`;
      }
      
      try {
        // Try to reach the selfcheck endpoint
        const response = await fetch(`${API_BASE}/api/selfcheck`, {
          method: 'GET',
          headers: { 'Accept': 'application/json' },
          signal: AbortSignal.timeout(2000)
        });
        
        if (response.ok) {
          const data = await response.json();
          const payload = data.data || data;
          
          // Check if now running as admin
          const telemetry = payload.telemetry || {};
          if (telemetry.is_admin === true) {
            // Success! Server is back and elevated
            console.log('[restartAsAdmin] Reconnected to elevated server');
            state.isRestartingAsAdmin = false;
            
            if (els.btnRestartAdmin) {
              els.btnRestartAdmin.textContent = '✓ Now Admin';
            }
            if (els.restartAdminHint) {
              els.restartAdminHint.textContent = 'Successfully elevated';
              els.restartAdminHint.style.color = 'var(--success)';
            }
            
            // Refresh all state from new server
            await checkReadiness();
            
            // Hide the warning panel after a moment (it should auto-hide since is_admin is now true)
            setTimeout(() => {
              updateMissionReadinessWarning();
            }, 1000);
            
            return;
          } else {
            // Server is back but NOT admin - something went wrong
            console.warn('[restartAsAdmin] Server reconnected but not elevated');
          }
        }
      } catch (e) {
        // Expected during restart - server not ready yet
        console.log(`[restartAsAdmin] Poll attempt ${attempt}/${maxAttempts} - not ready`);
      }
    }
    
    // Timeout - show manual instructions
    console.warn('[restartAsAdmin] Timeout waiting for elevated server');
    state.isRestartingAsAdmin = false;
    
    if (els.btnRestartAdmin) {
      els.btnRestartAdmin.disabled = false;
      els.btnRestartAdmin.textContent = '🛡️ Restart as Administrator';
    }
    if (els.restartAdminHint) {
      els.restartAdminHint.innerHTML = `
        <span style="color: var(--warn);">Could not reconnect</span><br>
        <span style="font-size: 10px;">If a new window opened, close this one. Otherwise, manually run as Administrator.</span>
      `;
    }
  }
  
  /**
   * Reset the restart admin button to initial state with error message
   */
  function resetRestartAdminUI(errorMsg, hint) {
    state.isRestartingAsAdmin = false;
    
    if (els.btnRestartAdmin) {
      els.btnRestartAdmin.disabled = false;
      els.btnRestartAdmin.textContent = '🛡️ Restart as Administrator';
    }
    if (els.restartAdminHint) {
      els.restartAdminHint.innerHTML = `<span style="color: var(--error);">${errorMsg}</span> — ${hint}`;
    }
  }

  /**
   * Fetch runs list - GET /api/runs
   */
  async function fetchRuns() {
    try {
      const response = await api('/api/runs');
      
      // CONTRACT: List endpoints return {success, data: {runs: [...], count}}
      // NOTE: api() already unwraps {success,data:X} → X, so response = {runs:[...], count:N}
      // Handle both unwrapped and legacy response shapes
      if (response.runs && Array.isArray(response.runs)) {
        // Normal case: unwrapped response with named array
        state.runs = response.runs;
      } else if (response.data?.runs) {
        // Legacy: double-wrapped response (shouldn't happen but safe fallback)
        state.runs = response.data.runs;
      } else if (Array.isArray(response)) {
        // Very old: raw array
        state.runs = response;
      } else {
        state.runs = [];
      }
      
      renderRunsList();
    } catch (err) {
      console.warn('[fetchRuns] Error:', err.message);
      state.runs = [];
      renderRunsList();
    }
  }

  // ============ EXPLAINABILITY API FUNCTIONS ============

  /**
   * Probe backend capabilities at boot
   * Records which endpoints exist (200) vs missing (404)
   */
  async function probeCapabilities() {
    console.log('[probeCapabilities] Checking backend capabilities...');
    
    // Probe signals endpoint
    try {
      await api('/api/signals?limit=1');
      state.capabilities.signals = true;
    } catch (err) {
      state.capabilities.signals = err.status === 404 ? false : null;
    }
    
    // Probe signal stats
    try {
      await api('/api/signals/stats');
      state.capabilities.signalsStats = true;
    } catch (err) {
      state.capabilities.signalsStats = err.status === 404 ? false : null;
    }
    
    // Fetch feature flags and update UI
    await fetchFeatureFlags();
    
    console.log('[probeCapabilities] Result:', state.capabilities);
  }
  
  /**
   * Fetch feature flags from /api/meta/features and show/hide non-core UI elements
   * TIER GATING: Shows locked features with 🔒 icon and upgrade link
   */
  async function fetchFeatureFlags() {
    try {
      const data = await api('/api/meta/features');
      const features = data.features || data || {};
      const tierInfo = data.tier_display || data.tier || 'Free';
      const upgradeUrl = data.upgrade_url || 'https://locint.io/upgrade';
      
      console.log('[fetchFeatureFlags] Tier:', tierInfo, 'Features:', features);
      
      // Store feature flags and tier info
      state.features = features;
      state.tier = tierInfo;
      state.upgradeUrl = upgradeUrl;
      
      // Update tier badge in UI if exists
      const tierBadge = document.getElementById('tierBadge');
      if (tierBadge) {
        tierBadge.textContent = tierInfo;
        tierBadge.className = `tier-badge tier-${(tierInfo || 'free').toLowerCase()}`;
      }
      
      // Show non-core tabs based on enabled features
      document.querySelectorAll('.non-core-feature').forEach(el => {
        const featureName = el.dataset.feature;
        if (featureName && features[featureName]) {
          el.classList.remove('hidden');
          console.log(`[fetchFeatureFlags] Enabled non-core feature: ${featureName}`);
        }
      });
      
      // Apply tier locks to Pro features
      applyTierLocks(features, upgradeUrl);
      
      // Initialize Team tab based on tier
      initializeTeamTab();
      
    } catch (err) {
      console.log('[fetchFeatureFlags] Features endpoint not available, using core-only mode');
      state.features = { core: true };
      state.tier = 'Free';
      
      // Still initialize Team tab (will show locked state)
      initializeTeamTab();
    }
  }
  
  /**
   * Apply visual tier locks to Pro-gated features
   * Shows 🔒 icon and disables controls for locked features
   */
  function applyTierLocks(features, upgradeUrl) {
    // Baseline controls - Pro only
    const baselineBtn = document.getElementById('btnMarkBaseline');
    if (baselineBtn) {
      if (!features.baselines) {
        baselineBtn.disabled = true;
        baselineBtn.innerHTML = '🔒 Mark as Baseline <span class="tier-lock">(Pro)</span>';
        baselineBtn.title = 'Baselines require Pro tier. Click to upgrade.';
        baselineBtn.onclick = () => showUpgradePrompt('Baselines', upgradeUrl);
      }
    }
    
    // Case summary export - Pro only
    const caseSummaryBtn = document.getElementById('btnExportCaseSummary');
    if (caseSummaryBtn) {
      if (!features.case_summary) {
        caseSummaryBtn.disabled = true;
        caseSummaryBtn.innerHTML = '🔒 Export Case Summary <span class="tier-lock">(Pro)</span>';
        caseSummaryBtn.title = 'Case Summary export requires Pro tier. Click to upgrade.';
        caseSummaryBtn.onclick = () => showUpgradePrompt('Case Summary Export', upgradeUrl);
      }
    }
    
    // Diff mode select - Lock baseline/marker modes in Free
    const diffModeSelect = document.getElementById('diffModeSelect');
    if (diffModeSelect) {
      const options = diffModeSelect.querySelectorAll('option');
      options.forEach(opt => {
        if ((opt.value === 'baseline' || opt.value === 'marker') && !features.diff_advanced) {
          opt.disabled = true;
          opt.textContent = `🔒 ${opt.textContent} (Pro)`;
        }
      });
    }
    
    // Baseline filter toggle - Pro only
    const baselineFilterToggle = document.getElementById('baselineFilterToggle');
    if (baselineFilterToggle && !features.diff_advanced) {
      baselineFilterToggle.disabled = true;
      baselineFilterToggle.parentElement?.classList.add('tier-locked');
    }
    
    // Custom packs notice
    const packsContainer = document.getElementById('packsContainer');
    if (packsContainer && !features.custom_packs) {
      const notice = document.createElement('div');
      notice.className = 'tier-notice';
      notice.innerHTML = `🔒 <strong>Custom Content Packs</strong> require Pro tier. <a href="${upgradeUrl}" target="_blank">Upgrade</a>`;
      packsContainer.prepend(notice);
    }
  }
  
  /**
   * Show upgrade prompt modal for locked features
   */
  function showUpgradePrompt(featureName, upgradeUrl) {
    const existing = document.querySelector('.upgrade-modal');
    if (existing) existing.remove();
    
    const modal = document.createElement('div');
    modal.className = 'upgrade-modal';
    modal.innerHTML = `
      <div class="upgrade-modal-content">
        <h3>🔒 ${featureName} Requires Pro</h3>
        <p>This feature is available in the Pro tier.</p>
        <p>Upgrade to unlock advanced features including:</p>
        <ul>
          <li>✓ Baseline comparison & management</li>
          <li>✓ Advanced diff modes (baseline, marker)</li>
          <li>✓ Custom content packs</li>
          <li>✓ Case summary export</li>
        </ul>
        <div class="upgrade-modal-buttons">
          <a href="${upgradeUrl}" target="_blank" class="btn btn-primary">Upgrade to Pro</a>
          <button class="btn btn-secondary" onclick="this.closest('.upgrade-modal').remove()">Close</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }
  
  /**
   * Handle FEATURE_LOCKED error from API
   * Returns true if error was handled, false otherwise
   */
  function handleFeatureLockedError(err) {
    if (err?.error?.code === 'FEATURE_LOCKED') {
      const { feature, required_tier, upgrade_url } = err.error;
      showUpgradePrompt(feature || 'This feature', upgrade_url || state.upgradeUrl || 'https://locint.io/upgrade');
      return true;
    }
    return false;
  }

  // ============ TEAM CASE STORE FUNCTIONS ============
  
  /**
   * Initialize Team tab based on tier
   * Called after fetchFeatureFlags
   */
  function initializeTeamTab() {
    const isTeamTier = state.tier === 'Team' || state.tier === 'Dev';
    const hasStoreFeature = state.features?.case_store === true;
    
    console.log('[initializeTeamTab] tier:', state.tier, 'hasStoreFeature:', hasStoreFeature, 'isTeamTier:', isTeamTier);
    
    // Show/hide tier lock banner vs content
    if (els.teamTierLockBanner && els.teamContent) {
      if (isTeamTier && hasStoreFeature) {
        els.teamTierLockBanner.classList.add('hidden');
        els.teamContent.classList.remove('hidden');
        // Auto-fetch store status
        fetchTeamStoreStatus();
        // Start auto-refresh when Team tab is visible
        startTeamStoreAutoRefresh();
      } else {
        els.teamTierLockBanner.classList.remove('hidden');
        els.teamContent.classList.add('hidden');
        if (els.teamUpgradeLink) {
          els.teamUpgradeLink.href = state.upgradeUrl || 'https://locint.io/upgrade';
        }
        stopTeamStoreAutoRefresh();
      }
    }
    
    // Style the Team tab button based on tier
    if (els.tabBtnTeam) {
      if (!isTeamTier || !hasStoreFeature) {
        els.tabBtnTeam.innerHTML = '🔒 Team';
        els.tabBtnTeam.title = 'Team Case Store requires Team tier';
      } else {
        els.tabBtnTeam.innerHTML = 'Team';
        els.tabBtnTeam.title = '';
      }
    }
  }
  
  /**
   * Start auto-refresh of store status (every 10s when Team tab open)
   */
  function startTeamStoreAutoRefresh() {
    stopTeamStoreAutoRefresh();
    if (state.currentTab === 'team') {
      state.teamStore.storeRefreshInterval = setInterval(() => {
        if (state.currentTab === 'team') {
          fetchTeamStoreStatus(true); // silent refresh
        }
      }, 10000);
    }
  }
  
  function stopTeamStoreAutoRefresh() {
    if (state.teamStore.storeRefreshInterval) {
      clearInterval(state.teamStore.storeRefreshInterval);
      state.teamStore.storeRefreshInterval = null;
    }
  }
  
  /**
   * Fetch team store status from backend
   */
  async function fetchTeamStoreStatus(silent = false) {
    try {
      const data = await api('/api/team/store/status');
      state.teamStore.status = data;
      renderTeamStoreStatus(data);
      
      // If store is available, fetch cases
      if (data.available && data.writable) {
        fetchTeamCases();
      }
    } catch (err) {
      console.error('[fetchTeamStoreStatus] Error:', err);
      if (handleFeatureLockedError(err)) return;
      
      state.teamStore.status = { 
        available: false, 
        reason: err.message || 'Failed to check store status',
        code: err.code || 'UNKNOWN_ERROR'
      };
      renderTeamStoreStatus(state.teamStore.status);
    }
  }
  
  /**
   * Render team store status in UI
   */
  function renderTeamStoreStatus(status) {
    if (!els.teamStoreStatusBadge) return;
    
    // Status badge
    if (status.available && status.writable) {
      els.teamStoreStatusBadge.textContent = 'Connected';
      els.teamStoreStatusBadge.className = 'badge badge-running';
    } else if (status.available && !status.writable) {
      els.teamStoreStatusBadge.textContent = 'Read-Only';
      els.teamStoreStatusBadge.className = 'badge badge-warning';
    } else if (status.configured && !status.available) {
      els.teamStoreStatusBadge.textContent = 'Unavailable';
      els.teamStoreStatusBadge.className = 'badge badge-stopped';
    } else {
      els.teamStoreStatusBadge.textContent = 'Not Configured';
      els.teamStoreStatusBadge.className = 'badge badge-stopped';
    }
    
    // Update path display (escaped for safety)
    if (els.teamStorePath) {
      const pathSpan = els.teamStorePath.querySelector('span');
      if (pathSpan) {
        pathSpan.textContent = status.store_dir || '—';
      }
    }
    
    // Show/hide stats
    if (els.teamStoreStats) {
      if (status.available) {
        els.teamStoreStats.classList.remove('hidden');
      } else {
        els.teamStoreStats.classList.add('hidden');
      }
    }
    
    // Show reason code if store unavailable
    if (els.teamStoreReason) {
      if (!status.available && (status.reason || status.code)) {
        els.teamStoreReason.classList.remove('hidden');
        els.teamStoreReason.textContent = `⚠️ ${status.code || ''}: ${status.reason || 'Store unavailable'}`;
      } else {
        els.teamStoreReason.classList.add('hidden');
      }
    }
    
    // Show copy diagnostics button when there's an issue
    if (els.btnCopyStoreDiagnostics) {
      if (!status.available || !status.writable) {
        els.btnCopyStoreDiagnostics.classList.remove('hidden');
      } else {
        els.btnCopyStoreDiagnostics.classList.add('hidden');
      }
    }
    
    // Update last refresh time
    if (els.teamStoreLastRefresh) {
      els.teamStoreLastRefresh.textContent = `Last checked: ${new Date().toLocaleTimeString()}`;
    }
  }
  
  /**
   * Copy store diagnostics to clipboard
   */
  function copyStoreDiagnostics() {
    const diag = {
      status: state.teamStore.status,
      timestamp: new Date().toISOString(),
      tier: state.tier,
      caseCount: state.teamStore.cases.length
    };
    navigator.clipboard.writeText(JSON.stringify(diag, null, 2))
      .then(() => showToast('Diagnostics copied to clipboard'))
      .catch(() => showError('Failed to copy diagnostics'));
  }
  
  /**
   * Show toast notification
   * @param {string} message - The message to display
   * @param {string} type - 'success', 'warning', 'error', or 'info' (default)
   */
  function showToast(message, type = 'info') {
    const colors = {
      success: 'background: #065f46; color: #d1fae5; border-color: #10b981;',
      warning: 'background: #92400e; color: #fef3c7; border-color: #f59e0b;',
      error: 'background: #991b1b; color: #fecaca; border-color: #ef4444;',
      info: 'background: var(--panel2); color: var(--fg); border-color: var(--border);'
    };
    const toast = document.createElement('div');
    toast.style.cssText = `position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); padding: 10px 20px; border-radius: var(--radius-sm); font-size: 13px; z-index: 9999; border: 1px solid; ${colors[type] || colors.info}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
  }
  
  /**
   * Fetch list of cases from team store
   */
  async function fetchTeamCases() {
    try {
      const data = await api('/api/team/cases');
      state.teamStore.cases = data.cases || [];
      
      // Update case count
      if (els.teamCaseCount) {
        els.teamCaseCount.textContent = state.teamStore.cases.length;
      }
      
      // Update unreadable count
      if (els.teamUnreadableCount) {
        const unreadable = data.unreadable_count || 0;
        if (unreadable > 0) {
          els.teamUnreadableCount.classList.remove('hidden');
          els.teamUnreadableCount.querySelector('span').textContent = unreadable;
        } else {
          els.teamUnreadableCount.classList.add('hidden');
        }
      }
      
      // Build unique tags list for filter
      const tagSet = new Set();
      state.teamStore.cases.forEach(c => (c.tags || []).forEach(t => tagSet.add(t)));
      state.teamStore.allTags = Array.from(tagSet).sort();
      
      // Populate tag filter dropdown
      if (els.teamCaseTagFilter) {
        const currentVal = els.teamCaseTagFilter.value;
        els.teamCaseTagFilter.innerHTML = '<option value="">All tags</option>' +
          state.teamStore.allTags.map(t => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join('');
        els.teamCaseTagFilter.value = currentVal;
      }
      
      renderTeamCaseList();
    } catch (err) {
      console.error('[fetchTeamCases] Error:', err);
      if (handleFeatureLockedError(err)) return;
      state.teamStore.cases = [];
      renderTeamCaseList();
    }
  }
  
  /**
   * Render team case list with search/filter/sort
   */
  function renderTeamCaseList() {
    if (!els.teamCaseList) return;
    
    const searchTerm = (els.teamCaseSearch?.value || '').toLowerCase().trim();
    const tagFilter = els.teamCaseTagFilter?.value || '';
    const sortBy = els.teamCaseSortBy?.value || 'updated_at';
    const hasRunsOnly = els.teamCaseHasRunsFilter?.checked || false;
    
    // Filter cases
    let cases = state.teamStore.cases.filter(c => {
      // Search filter
      if (searchTerm) {
        const matchesSearch = 
          c.title?.toLowerCase().includes(searchTerm) ||
          c.case_id?.toLowerCase().includes(searchTerm) ||
          c.tags?.some(t => t.toLowerCase().includes(searchTerm)) ||
          c.description?.toLowerCase().includes(searchTerm);
        if (!matchesSearch) return false;
      }
      // Tag filter
      if (tagFilter && !(c.tags || []).includes(tagFilter)) return false;
      // Has runs filter
      if (hasRunsOnly && !(c.runs?.length > 0 || (c.run_count || 0) > 0)) return false;
      return true;
    });
    
    // Sort cases
    cases.sort((a, b) => {
      switch (sortBy) {
        case 'created_at':
          return (b.created_at || '').localeCompare(a.created_at || '');
        case 'runs_count':
          return ((b.runs?.length || b.run_count || 0) - (a.runs?.length || a.run_count || 0));
        case 'notes_count':
          return ((b.notes_count || 0) - (a.notes_count || 0));
        case 'updated_at':
        default:
          return (b.updated_at || '').localeCompare(a.updated_at || '');
      }
    });
    
    // Empty state
    if (cases.length === 0) {
      const reason = state.teamStore.status?.available 
        ? (searchTerm || tagFilter || hasRunsOnly ? 'No cases match your filters' : 'No cases found — create one to get started')
        : 'Configure a store to view cases';
      els.teamCaseList.innerHTML = `
        <div style="color: var(--muted); font-size: 12px; text-align: center; padding: 24px;">
          ${escapeHtml(reason)}
        </div>
      `;
      return;
    }
    
    // Render case items with provenance chip
    els.teamCaseList.innerHTML = cases.map(c => {
      const isSelected = c.case_id === state.teamStore.selectedCaseId;
      const isUnreadable = c.status === 'unreadable';
      const runCount = c.runs?.length || c.run_count || 0;
      const notesCount = c.notes_count || 0;
      // Provenance chip: last updated by host
      const lastHost = c.creator_host || c.last_updated_by_host || '';
      
      return `
        <div class="team-case-item ${isSelected ? 'selected' : ''} ${isUnreadable ? 'unreadable' : ''}"
             data-case-id="${escapeHtml(c.case_id)}"
             style="padding: 8px 10px; background: var(--panel2); border-radius: var(--radius-sm); cursor: pointer; border: 1px solid ${isSelected ? 'var(--accent)' : 'transparent'}; ${isUnreadable ? 'opacity: 0.6;' : ''}">
          <div style="font-size: 13px; font-weight: 500; margin-bottom: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
            ${isUnreadable ? '⚠️ ' : ''}${escapeHtml(c.title || 'Untitled Case')}
          </div>
          <div style="font-size: 11px; color: var(--muted); display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
            <span>📊 ${runCount} runs</span>
            <span>📝 ${notesCount} notes</span>
            ${lastHost ? `<span style="font-size: 10px;">🖥️ ${escapeHtml(lastHost)}</span>` : ''}
          </div>
          ${c.tags?.length ? `
            <div style="display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px;">
              ${c.tags.slice(0, 3).map(t => `<span class="badge" style="font-size: 9px; padding: 1px 4px;">${escapeHtml(t)}</span>`).join('')}
              ${c.tags.length > 3 ? `<span style="font-size: 9px; color: var(--muted);">+${c.tags.length - 3}</span>` : ''}
            </div>
          ` : ''}
        </div>
      `;
    }).join('');
    
    // Add click handlers
    els.teamCaseList.querySelectorAll('.team-case-item').forEach(item => {
      item.addEventListener('click', () => {
        const caseId = item.dataset.caseId;
        const caseData = state.teamStore.cases.find(c => c.case_id === caseId);
        if (caseData?.status === 'unreadable') {
          showError('This case is unreadable: ' + (caseData.error || 'corrupt or missing data'));
          return;
        }
        selectTeamCase(caseId);
      });
    });
  }
  
  /**
   * Select and load a team case
   */
  async function selectTeamCase(caseId) {
    state.teamStore.selectedCaseId = caseId;
    state.teamStore.selectedRunIds = new Set(); // Reset multi-select
    
    // Update list selection
    renderTeamCaseList();
    
    // Fetch case details
    try {
      const data = await api(`/api/team/cases/${caseId}`);
      state.teamStore.selectedCase = data;
      renderTeamCaseDetail(data);
    } catch (err) {
      console.error('[selectTeamCase] Error:', err);
      if (handleFeatureLockedError(err)) return;
      showError('Failed to load case: ' + (err.message || 'Unknown error'));
    }
  }
  
  /**
   * Switch case detail sub-tab
   */
  function switchCaseTab(tabName) {
    state.teamStore.selectedCaseTab = tabName;
    
    // Update tab buttons
    document.querySelectorAll('.team-case-tab').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    
    // Update tab content
    document.querySelectorAll('.team-case-tab-content').forEach(content => {
      content.classList.add('hidden');
    });
    
    const tabEl = document.getElementById(`teamCase${tabName.charAt(0).toUpperCase() + tabName.slice(1)}Tab`);
    if (tabEl) tabEl.classList.remove('hidden');
    
    // Load overview if switching to it
    if (tabName === 'overview' && state.teamStore.selectedCaseId) {
      fetchCaseAggregate(state.teamStore.selectedCaseId);
    }
  }
  
  /**
   * Render team case detail view
   */
  function renderTeamCaseDetail(caseData) {
    if (!els.teamCaseDetail || !els.teamCaseDetailEmpty) return;
    
    if (!caseData) {
      els.teamCaseDetail.classList.add('hidden');
      els.teamCaseDetailEmpty.classList.remove('hidden');
      return;
    }
    
    els.teamCaseDetail.classList.remove('hidden');
    els.teamCaseDetailEmpty.classList.add('hidden');
    
    // Header
    if (els.teamCaseTitle) els.teamCaseTitle.textContent = caseData.title || 'Untitled Case';
    if (els.teamCaseId) els.teamCaseId.textContent = caseData.case_id;
    if (els.teamCaseDescription) {
      els.teamCaseDescription.textContent = caseData.description || 'No description';
      els.teamCaseDescription.style.display = caseData.description ? 'block' : 'none';
    }
    
    // Provenance line
    if (els.teamCaseProvenance) {
      const createdBy = caseData.creator_host || caseData.created_by || '';
      const userHint = caseData.creator_user_hint || '';
      const createdAt = caseData.created_at ? new Date(caseData.created_at).toLocaleDateString() : '';
      els.teamCaseProvenance.textContent = createdBy 
        ? `Created by ${userHint ? userHint + '@' : ''}${createdBy}${createdAt ? ' on ' + createdAt : ''}`
        : '';
    }
    
    // Tags in header
    if (els.teamCaseTags) {
      els.teamCaseTags.innerHTML = (caseData.tags || []).slice(0, 4).map(tag => `
        <span class="badge" style="font-size: 10px; padding: 2px 6px;">${escapeHtml(tag)}</span>
      `).join('');
      if ((caseData.tags || []).length > 4) {
        els.teamCaseTags.innerHTML += `<span style="font-size: 10px; color: var(--muted);">+${caseData.tags.length - 4}</span>`;
      }
    }
    
    // Tags in Tags tab
    if (els.teamCaseTagsList) {
      els.teamCaseTagsList.innerHTML = (caseData.tags || []).map(tag => `
        <span class="badge" style="display: inline-flex; align-items: center; gap: 6px; font-size: 12px; padding: 4px 10px;">
          ${escapeHtml(tag)}
          <button class="team-remove-tag" data-tag="${escapeHtml(tag)}" style="background: none; border: none; color: var(--muted); cursor: pointer; padding: 0; font-size: 12px;" title="Remove tag">×</button>
        </span>
      `).join('') || '<span style="color: var(--muted); font-size: 12px;">No tags</span>';
      
      // Add remove handlers
      els.teamCaseTagsList.querySelectorAll('.team-remove-tag').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          removeTeamCaseTag(caseData.case_id, btn.dataset.tag);
        });
      });
    }
    
    // Render runs with multi-select
    renderCaseRuns(caseData);
    
    // Render notes with timeline grouping
    renderCaseNotes(caseData);
    
    // Switch to current tab
    switchCaseTab(state.teamStore.selectedCaseTab);
  }
  
  /**
   * Render case runs with multi-select and import status
   */
  function renderCaseRuns(caseData) {
    if (!els.teamCaseRuns) return;
    
    const runs = (caseData.runs || []).slice().sort((a, b) => 
      (b.published_at || '').localeCompare(a.published_at || '')
    );
    
    if (runs.length === 0) {
      els.teamCaseRuns.innerHTML = `<div style="color: var(--muted); font-size: 12px; text-align: center; padding: 16px;">No runs published yet</div>`;
      if (els.btnImportSelectedRuns) els.btnImportSelectedRuns.classList.add('hidden');
      return;
    }
    
    els.teamCaseRuns.innerHTML = runs.map(run => {
      const runId = run.run_id || run;
      const isSelected = state.teamStore.selectedRunIds.has(runId);
      const publishedBy = run.publisher_host || run.published_by || '';
      const bundleSize = run.bundle_size ? `${(run.bundle_size / 1024).toFixed(0)} KB` : '';
      
      return `
        <div class="team-run-item" style="display: flex; align-items: center; gap: 10px; padding: 10px 12px; background: var(--panel2); border-radius: var(--radius-sm); border: 1px solid ${isSelected ? 'var(--accent)' : 'transparent'};">
          <input type="checkbox" class="team-run-checkbox" data-run-id="${escapeHtml(runId)}" ${isSelected ? 'checked' : ''} style="cursor: pointer;">
          <div style="flex: 1; min-width: 0;">
            <div style="font-size: 12px; font-weight: 500; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(runId)}</div>
            <div style="font-size: 10px; color: var(--muted); display: flex; gap: 8px; flex-wrap: wrap;">
              ${run.published_at ? `<span>${new Date(run.published_at).toLocaleString()}</span>` : ''}
              ${publishedBy ? `<span>by ${escapeHtml(publishedBy)}</span>` : ''}
              ${bundleSize ? `<span>${bundleSize}</span>` : ''}
            </div>
          </div>
          <div style="display: flex; gap: 4px;">
            <button class="btn-secondary team-copy-bundle-path" data-run-id="${escapeHtml(runId)}" style="font-size: 10px; padding: 4px 8px;" title="Copy bundle path">📋</button>
            <button class="btn-secondary team-import-run" data-run-id="${escapeHtml(runId)}" style="font-size: 10px; padding: 4px 8px;">Import</button>
          </div>
        </div>
      `;
    }).join('');
    
    // Checkbox handlers
    els.teamCaseRuns.querySelectorAll('.team-run-checkbox').forEach(cb => {
      cb.addEventListener('change', () => {
        const runId = cb.dataset.runId;
        if (cb.checked) {
          state.teamStore.selectedRunIds.add(runId);
        } else {
          state.teamStore.selectedRunIds.delete(runId);
        }
        updateBulkImportButton();
      });
    });
    
    // Import handlers
    els.teamCaseRuns.querySelectorAll('.team-import-run').forEach(btn => {
      btn.addEventListener('click', () => importTeamRun(caseData.case_id, btn.dataset.runId));
    });
    
    // Copy bundle path handlers
    els.teamCaseRuns.querySelectorAll('.team-copy-bundle-path').forEach(btn => {
      btn.addEventListener('click', () => {
        const runId = btn.dataset.runId;
        const storePath = state.teamStore.status?.store_dir || '';
        const bundlePath = `${storePath}\\cases\\${caseData.case_id}\\runs\\${runId}.zip`;
        navigator.clipboard.writeText(bundlePath)
          .then(() => showToast('Bundle path copied'))
          .catch(() => showError('Failed to copy path'));
      });
    });
    
    updateBulkImportButton();
  }
  
  /**
   * Update bulk import button visibility
   */
  function updateBulkImportButton() {
    if (els.btnImportSelectedRuns) {
      if (state.teamStore.selectedRunIds.size > 0) {
        els.btnImportSelectedRuns.classList.remove('hidden');
        els.btnImportSelectedRuns.textContent = `Import Selected (${state.teamStore.selectedRunIds.size})`;
      } else {
        els.btnImportSelectedRuns.classList.add('hidden');
      }
    }
  }
  
  /**
   * Render case notes with day grouping
   */
  function renderCaseNotes(caseData) {
    if (!els.teamCaseNotes) return;
    
    const notes = caseData.recent_notes || caseData.notes || [];
    
    if (notes.length === 0) {
      els.teamCaseNotes.innerHTML = `<div style="color: var(--muted); font-size: 12px; text-align: center; padding: 16px;">No notes yet — add the first note below</div>`;
      return;
    }
    
    // Group by day
    const notesByDay = {};
    notes.forEach(note => {
      const ts = note.created_at || note.ts || '';
      const day = ts ? new Date(ts).toLocaleDateString() : 'Unknown date';
      if (!notesByDay[day]) notesByDay[day] = [];
      notesByDay[day].push(note);
    });
    
    // Render grouped
    let html = '';
    Object.entries(notesByDay).forEach(([day, dayNotes]) => {
      html += `<div style="font-size: 11px; color: var(--muted); margin: 12px 0 6px 0; font-weight: 500;">${escapeHtml(day)}</div>`;
      dayNotes.forEach(note => {
        const author = note.host_name || note.user_hint || note.author || 'Unknown';
        const time = note.created_at ? new Date(note.created_at).toLocaleTimeString() : '';
        html += `
          <div style="padding: 10px; background: var(--panel2); border-radius: var(--radius-sm); border-left: 3px solid var(--accent); position: relative;">
            <div style="font-size: 12px; white-space: pre-wrap;">${escapeHtml(note.content || note.text || '')}</div>
            <div style="font-size: 10px; color: var(--muted); margin-top: 6px; display: flex; gap: 8px; align-items: center;">
              <span>👤 ${escapeHtml(author)}</span>
              ${time ? `<span>• ${time}</span>` : ''}
              <button class="team-copy-note" data-note="${escapeHtml(note.content || note.text || '')}" style="background: none; border: none; color: var(--muted); cursor: pointer; font-size: 10px; padding: 2px; margin-left: auto;" title="Copy note">📋</button>
            </div>
          </div>
        `;
      });
    });
    
    els.teamCaseNotes.innerHTML = html;
    
    // Copy note handlers
    els.teamCaseNotes.querySelectorAll('.team-copy-note').forEach(btn => {
      btn.addEventListener('click', () => {
        navigator.clipboard.writeText(btn.dataset.note)
          .then(() => showToast('Note copied'))
          .catch(() => showError('Failed to copy note'));
      });
    });
  }
  
  /**
   * Create a new team case
   */
  async function createTeamCase() {
    const title = els.newCaseTitle?.value?.trim();
    const description = els.newCaseDescription?.value?.trim();
    const tagsRaw = els.newCaseTags?.value?.trim();
    
    if (!title) {
      showError('Please enter a case title');
      return;
    }
    
    const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim()).filter(t => t) : [];
    
    try {
      const data = await api('/api/team/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, description, tags })
      });
      
      console.log('[createTeamCase] Created:', data);
      
      // Clear form
      if (els.newCaseTitle) els.newCaseTitle.value = '';
      if (els.newCaseDescription) els.newCaseDescription.value = '';
      if (els.newCaseTags) els.newCaseTags.value = '';
      
      // Refresh cases and select the new one
      await fetchTeamCases();
      if (data.case_id) {
        selectTeamCase(data.case_id);
      }
    } catch (err) {
      console.error('[createTeamCase] Error:', err);
      if (handleFeatureLockedError(err)) return;
      showError('Failed to create case: ' + (err.message || 'Unknown error'));
    }
  }
  
  /**
   * Add a tag to the selected case
   */
  async function addTeamCaseTag() {
    const tag = els.teamCaseNewTag?.value?.trim();
    const caseId = state.teamStore.selectedCaseId;
    
    if (!tag || !caseId) return;
    
    try {
      await api(`/api/team/cases/${caseId}/tags`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ add: [tag] })
      });
      
      if (els.teamCaseNewTag) els.teamCaseNewTag.value = '';
      
      // Refresh case detail
      selectTeamCase(caseId);
    } catch (err) {
      console.error('[addTeamCaseTag] Error:', err);
      if (handleFeatureLockedError(err)) return;
      showError('Failed to add tag: ' + (err.message || 'Unknown error'));
    }
  }
  
  /**
   * Remove a tag from the selected case
   */
  async function removeTeamCaseTag(caseId, tag) {
    try {
      await api(`/api/team/cases/${caseId}/tags`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ remove: [tag] })
      });
      
      // Refresh case detail
      selectTeamCase(caseId);
    } catch (err) {
      console.error('[removeTeamCaseTag] Error:', err);
      if (handleFeatureLockedError(err)) return;
      showError('Failed to remove tag: ' + (err.message || 'Unknown error'));
    }
  }
  
  /**
   * Add a note to the selected case
   */
  async function addTeamCaseNote() {
    const content = els.teamCaseNewNote?.value?.trim();
    const caseId = state.teamStore.selectedCaseId;
    
    if (!content || !caseId) return;
    
    try {
      await api(`/api/team/cases/${caseId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
      });
      
      if (els.teamCaseNewNote) els.teamCaseNewNote.value = '';
      
      // Refresh case detail
      selectTeamCase(caseId);
    } catch (err) {
      console.error('[addTeamCaseNote] Error:', err);
      if (handleFeatureLockedError(err)) return;
      showError('Failed to add note: ' + (err.message || 'Unknown error'));
    }
  }
  
  /**
   * Show publish run modal
   */
  async function showPublishRunModal() {
    if (!els.teamPublishRunModal || !els.teamPublishRunSelect) return;
    
    // Populate runs dropdown
    try {
      const runsData = await api('/api/runs');
      const runs = runsData.runs || [];
      
      if (runs.length === 0) {
        els.teamPublishRunSelect.innerHTML = '<option value="">No runs available</option>';
      } else {
        els.teamPublishRunSelect.innerHTML = runs.map(r => `
          <option value="${r.run_id}">${r.run_id} (${r.event_count || 0} events)</option>
        `).join('');
      }
    } catch (err) {
      console.error('[showPublishRunModal] Error fetching runs:', err);
      els.teamPublishRunSelect.innerHTML = '<option value="">Failed to load runs</option>';
    }
    
    els.teamPublishRunModal.classList.remove('hidden');
  }
  
  /**
   * Publish selected run to current case
   */
  async function publishRunToCase() {
    const runId = els.teamPublishRunSelect?.value;
    const caseId = state.teamStore.selectedCaseId;
    
    if (!runId || !caseId) {
      showError('Please select a run to publish');
      return;
    }
    
    try {
      await api(`/api/team/cases/${caseId}/runs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ run_id: runId })
      });
      
      // Hide modal
      if (els.teamPublishRunModal) els.teamPublishRunModal.classList.add('hidden');
      
      // Refresh case detail
      selectTeamCase(caseId);
    } catch (err) {
      console.error('[publishRunToCase] Error:', err);
      if (handleFeatureLockedError(err)) return;
      showError('Failed to publish run: ' + (err.message || 'Unknown error'));
    }
  }
  
  /**
   * Import a run from team store
   */
  async function importTeamRun(caseId, runId) {
    try {
      const data = await api(`/api/team/cases/${caseId}/runs/${runId}/import`, {
        method: 'POST'
      });
      
      console.log('[importTeamRun] Imported:', data);
      
      // Show toast notification
      showToast('Run imported successfully! Switch to Runs tab to view.', 'success');
      
      // Refresh runs list
      fetchRuns();
      
      // Refresh case detail to update import status
      if (state.teamStore.selectedCaseId === caseId) {
        selectTeamCase(caseId);
      }
    } catch (err) {
      console.error('[importTeamRun] Error:', err);
      if (handleFeatureLockedError(err)) return;
      showError('Failed to import run: ' + (err.message || 'Unknown error'));
    }
  }
  
  /**
   * Bulk import selected runs from team store
   * Shows progress bar and imports runs sequentially
   */
  async function bulkImportSelectedRuns() {
    const caseId = state.teamStore.selectedCaseId;
    const selectedRuns = Array.from(state.teamStore.selectedRunIds);
    
    if (!caseId || selectedRuns.length === 0) {
      showToast('No runs selected for import', 'warning');
      return;
    }
    
    // Show progress UI
    const progressContainer = els.teamBulkImportProgress;
    const progressBar = els.teamBulkImportProgressBar;
    const progressStatus = els.teamBulkImportStatus;
    
    if (progressContainer) progressContainer.classList.remove('hidden');
    if (progressBar) progressBar.style.width = '0%';
    if (progressStatus) progressStatus.textContent = `Importing 0 of ${selectedRuns.length}...`;
    
    let successCount = 0;
    let failCount = 0;
    
    for (let i = 0; i < selectedRuns.length; i++) {
      const runId = selectedRuns[i];
      
      // Update progress
      const pct = Math.round(((i) / selectedRuns.length) * 100);
      if (progressBar) progressBar.style.width = pct + '%';
      if (progressStatus) progressStatus.textContent = `Importing ${i + 1} of ${selectedRuns.length}: ${runId}`;
      
      try {
        await api(`/api/team/cases/${caseId}/runs/${runId}/import`, {
          method: 'POST'
        });
        successCount++;
        console.log(`[bulkImportSelectedRuns] Imported ${runId}`);
      } catch (err) {
        failCount++;
        console.error(`[bulkImportSelectedRuns] Failed to import ${runId}:`, err);
      }
    }
    
    // Complete progress
    if (progressBar) progressBar.style.width = '100%';
    if (progressStatus) {
      if (failCount === 0) {
        progressStatus.textContent = `Imported ${successCount} runs successfully!`;
      } else {
        progressStatus.textContent = `Imported ${successCount} runs, ${failCount} failed`;
      }
    }
    
    // Clear selection
    state.teamStore.selectedRunIds.clear();
    
    // Refresh runs list
    fetchRuns();
    
    // Refresh case detail
    selectTeamCase(caseId);
    
    // Hide progress after delay
    setTimeout(() => {
      if (progressContainer) progressContainer.classList.add('hidden');
    }, 3000);
    
    // Show final toast
    if (failCount === 0) {
      showToast(`Successfully imported ${successCount} runs`, 'success');
    } else {
      showToast(`Imported ${successCount} runs, ${failCount} failed`, 'warning');
    }
  }
  
  /**
   * Fetch case aggregate data for Team V2 overview
   * Returns merged findings, timeline across all runs in the case
   */
  async function fetchCaseAggregate(caseId) {
    if (!caseId) return null;
    
    try {
      const resp = await api(`/api/team/cases/${caseId}/aggregate`);
      // Handle wrapper response
      const data = resp.data || resp;
      state.teamStore.aggregate = data;
      renderCaseOverview();
      return data;
    } catch (err) {
      console.warn('[fetchCaseAggregate] Aggregate endpoint not available:', err.message);
      // V2 feature - graceful degradation
      state.teamStore.aggregate = null;
      renderCaseOverview();
      return null;
    }
  }
  
  /**
   * Render case overview tab (Team V2 aggregate view)
   * Shows merged findings across all runs in the case
   * V2 HARDENED: 
   * - Toggle for per-host vs cross-host dedupe
   * - Deep-links to run/finding/evidence
   * - Evidence availability indicators
   */
  function renderCaseOverview() {
    const emptyContainer = els.teamCaseOverviewEmpty;
    const contentContainer = els.teamCaseOverviewContent;
    
    if (!emptyContainer && !contentContainer) return;
    
    const aggregate = state.teamStore.aggregate;
    
    if (!aggregate || !aggregate.run_count) {
      // Show empty/loading state
      if (emptyContainer) emptyContainer.classList.remove('hidden');
      if (contentContainer) contentContainer.classList.add('hidden');
      return;
    }
    
    // Show content, hide empty
    if (emptyContainer) emptyContainer.classList.add('hidden');
    if (contentContainer) {
      contentContainer.classList.remove('hidden');
      
      // Get the current dedupe mode (default to cross_host for summary view)
      const dedupeMode = state.teamStore.overviewDedupeMode || 'cross_host';
      
      // Get the right findings list based on mode
      const findings = dedupeMode === 'per_host' 
        ? (aggregate.per_host_findings || [])
        : (aggregate.cross_host_findings || []);
      
      const { timeline = [], hosts = [], run_count = 0, runs = [], merged_at, cache_hit } = aggregate;
      
      contentContainer.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 16px; height: 100%; overflow-y: auto; padding: 4px;">
          <!-- Stats Row -->
          <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;">
            <div style="background: var(--panel2); border-radius: var(--radius-sm); padding: 12px; text-align: center;">
              <div style="font-size: 24px; font-weight: 700;">${run_count}</div>
              <div style="font-size: 11px; color: var(--muted);">Runs</div>
            </div>
            <div style="background: var(--panel2); border-radius: var(--radius-sm); padding: 12px; text-align: center;">
              <div style="font-size: 24px; font-weight: 700;">${hosts.length}</div>
              <div style="font-size: 11px; color: var(--muted);">Hosts</div>
            </div>
            <div style="background: var(--panel2); border-radius: var(--radius-sm); padding: 12px; text-align: center;">
              <div style="font-size: 24px; font-weight: 700;">${findings.length}</div>
              <div style="font-size: 11px; color: var(--muted);">Unique Findings</div>
            </div>
            <div style="background: var(--panel2); border-radius: var(--radius-sm); padding: 12px; text-align: center;">
              <div style="font-size: 24px; font-weight: 700;">${timeline.length}</div>
              <div style="font-size: 11px; color: var(--muted);">Events</div>
            </div>
          </div>
          
          <!-- Hosts -->
          ${hosts.length > 0 ? `
            <div>
              <div style="font-size: 12px; font-weight: 600; margin-bottom: 8px;">Hosts Involved</div>
              <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                ${hosts.map(h => `
                  <span style="padding: 4px 10px; background: var(--accent-light, #3b82f620); color: var(--accent); border-radius: var(--radius-sm); font-size: 11px;">🖥️ ${escapeHtml(h)}</span>
                `).join('')}
              </div>
            </div>
          ` : ''}
          
          <!-- Runs Info with Evidence Status -->
          ${runs.length > 0 ? `
            <div>
              <div style="font-size: 12px; font-weight: 600; margin-bottom: 8px;">Run Evidence Status</div>
              <div style="display: flex; flex-direction: column; gap: 4px; max-height: 120px; overflow-y: auto;">
                ${runs.map(r => `
                  <div style="display: flex; align-items: center; gap: 8px; padding: 6px 10px; background: var(--panel2); border-radius: var(--radius-sm); font-size: 11px;">
                    <span style="flex: 1;">${escapeHtml(r.run_id || 'unknown')}</span>
                    <span style="color: var(--muted);">${r.signal_count || 0} signals</span>
                    ${r.evidence_deref_available 
                      ? '<span style="color: #10b981;">✓ Evidence</span>'
                      : `<span style="color: #f59e0b;" title="${escapeHtml(r.evidence_reason_code || 'unavailable')}">⚠ ${escapeHtml(r.evidence_reason_code || 'No evidence')}</span>`
                    }
                  </div>
                `).join('')}
              </div>
            </div>
          ` : ''}
          
          <!-- Findings with dedupe toggle -->
          <div style="flex: 1; min-height: 0;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
              <div style="font-size: 12px; font-weight: 600;">Unique Findings (Deduplicated)</div>
              <div style="display: flex; gap: 4px; font-size: 10px;">
                <button class="overview-dedupe-toggle ${dedupeMode === 'cross_host' ? 'active' : ''}" 
                        data-mode="cross_host"
                        style="padding: 3px 8px; border: 1px solid var(--border); border-radius: var(--radius-sm); cursor: pointer; background: ${dedupeMode === 'cross_host' ? 'var(--accent)' : 'var(--panel2)'}; color: ${dedupeMode === 'cross_host' ? 'white' : 'var(--fg)'};">
                  Cross-Host
                </button>
                <button class="overview-dedupe-toggle ${dedupeMode === 'per_host' ? 'active' : ''}"
                        data-mode="per_host"
                        style="padding: 3px 8px; border: 1px solid var(--border); border-radius: var(--radius-sm); cursor: pointer; background: ${dedupeMode === 'per_host' ? 'var(--accent)' : 'var(--panel2)'}; color: ${dedupeMode === 'per_host' ? 'white' : 'var(--fg)'};">
                  Per-Host
                </button>
              </div>
            </div>
            ${findings.length > 0 ? `
              <div style="display: flex; flex-direction: column; gap: 6px; max-height: 300px; overflow-y: auto;">
                ${findings.slice(0, 50).map((f, idx) => `
                  <div class="overview-finding-item" 
                       data-finding-idx="${idx}"
                       data-run-id="${escapeHtml(f.top_signal_ref?.run_id || '')}"
                       data-signal-id="${escapeHtml(f.top_signal_ref?.signal_id || '')}"
                       style="padding: 10px 12px; background: var(--panel2); border-radius: var(--radius-sm); cursor: pointer; border: 1px solid transparent; transition: border-color 0.15s;"
                       onmouseover="this.style.borderColor='var(--accent)'" 
                       onmouseout="this.style.borderColor='transparent'">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                      <div style="font-size: 13px; font-weight: 500;">${escapeHtml(f.title || f.rule_id || 'Unknown Finding')}</div>
                      ${f.evidence_available 
                        ? '<span style="font-size: 10px; color: #10b981; padding: 2px 6px; background: #10b98120; border-radius: 4px;">📎 Evidence</span>'
                        : '<span style="font-size: 10px; color: var(--muted);">No evidence</span>'
                      }
                    </div>
                    <div style="font-size: 11px; color: var(--muted); margin-top: 4px; display: flex; flex-wrap: wrap; gap: 8px;">
                      <span>${f.total_count || 1} occurrence(s)</span>
                      <span>across ${(f.hosts_involved || []).length || 1} host(s)</span>
                      <span>in ${(f.run_ids_involved || []).length || 1} run(s)</span>
                      ${f.first_seen_ts ? `<span>First: ${new Date(f.first_seen_ts).toLocaleDateString()}</span>` : ''}
                    </div>
                    ${f.dedupe_key ? `<div style="font-size: 9px; color: var(--muted); margin-top: 4px; font-family: monospace; opacity: 0.7;">Key: ${escapeHtml(f.dedupe_key.substring(0, 60))}${f.dedupe_key.length > 60 ? '...' : ''}</div>` : ''}
                  </div>
                `).join('')}
                ${findings.length > 50 ? `<div style="text-align: center; font-size: 11px; color: var(--muted); padding: 8px;">+${findings.length - 50} more findings</div>` : ''}
              </div>
            ` : `
              <div style="text-align: center; padding: 24px; color: var(--muted);">
                <p>No findings detected across ${run_count} run(s).</p>
                <p style="font-size: 11px; margin-top: 8px;">Runs have been published but no signals were recorded.</p>
              </div>
            `}
          </div>
          
          <!-- Timeline -->
          ${timeline.length > 0 ? `
            <div>
              <div style="font-size: 12px; font-weight: 600; margin-bottom: 8px;">Activity Timeline</div>
              <div style="display: flex; flex-direction: column; gap: 8px; max-height: 150px; overflow-y: auto;">
                ${timeline.map(ev => `
                  <div style="display: flex; align-items: center; gap: 12px; padding: 8px 12px; background: var(--panel2); border-radius: var(--radius-sm); font-size: 12px;">
                    <span style="color: var(--muted); white-space: nowrap;">${ev.timestamp ? new Date(ev.timestamp).toLocaleString() : 'N/A'}</span>
                    <span style="flex: 1;">${escapeHtml(ev.event || 'event')} ${ev.run_id ? `<span style="color: var(--muted);">(${escapeHtml(ev.run_id)})</span>` : ''}</span>
                    ${ev.host ? `<span style="font-size: 10px; color: var(--muted);">🖥️ ${escapeHtml(ev.host)}</span>` : ''}
                  </div>
                `).join('')}
              </div>
            </div>
          ` : ''}
          
          <!-- Merged At + Cache Status -->
          <div style="font-size: 10px; color: var(--muted); text-align: right; display: flex; justify-content: space-between;">
            <span>${cache_hit ? '⚡ Cached' : '🔄 Fresh'}</span>
            <span>Aggregated: ${merged_at ? new Date(merged_at).toLocaleString() : 'N/A'}</span>
          </div>
        </div>
      `;
      
      // Bind dedupe toggle handlers
      contentContainer.querySelectorAll('.overview-dedupe-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
          state.teamStore.overviewDedupeMode = btn.dataset.mode;
          renderCaseOverview();
        });
      });
      
      // Bind finding click handlers for deep-links
      contentContainer.querySelectorAll('.overview-finding-item').forEach(item => {
        item.addEventListener('click', () => {
          const runId = item.dataset.runId;
          const signalId = item.dataset.signalId;
          if (runId && signalId) {
            navigateToFinding(runId, signalId);
          } else if (runId) {
            // Just navigate to run
            navigateToRun(runId);
          } else {
            showToast('No run reference available for this finding', 'warning');
          }
        });
      });
    }
  }
  
  /**
   * Navigate to a specific run (deep-link from Overview)
   */
  function navigateToRun(runId) {
    // Switch to Runs tab
    switchTab('runs');
    
    // Find and select the run
    const run = state.runs.find(r => r.run_id === runId);
    if (run) {
      selectRun(run);
      showToast(`Navigated to run: ${runId}`, 'info');
    } else {
      showToast(`Run ${runId} not found locally. Import it first.`, 'warning');
    }
  }
  
  /**
   * Navigate to a specific finding in a run (deep-link from Overview)
   */
  async function navigateToFinding(runId, signalId) {
    // Switch to Runs tab
    switchTab('runs');
    
    // Find and select the run
    const run = state.runs.find(r => r.run_id === runId);
    if (!run) {
      showToast(`Run ${runId} not found locally. Import it first.`, 'warning');
      return;
    }
    
    await selectRun(run);
    
    // Try to find and select the signal
    const signal = state.signals.find(s => s.signal_id === signalId);
    if (signal) {
      selectSignal(signal);
      // Switch to Explain tab
      if (els.storyTabExplain) {
        els.storyTabExplain.click();
      }
      showToast(`Found signal: ${signalId}`, 'info');
    } else {
      showToast(`Signal ${signalId} not found in this run`, 'warning');
    }
  }
  
  /**
   * Show store configuration modal
   */
  function showStoreConfigModal() {
    if (!els.teamStoreConfigModal) return;
    
    // Pre-fill with current path if available
    if (els.teamStorePathInput && state.teamStore.status?.store_dir) {
      els.teamStorePathInput.value = state.teamStore.status.store_dir;
    }
    
    els.teamStoreConfigModal.classList.remove('hidden');
  }
  
  /**
   * Save store configuration
   */
  async function saveStoreConfig() {
    const storePath = els.teamStorePathInput?.value?.trim();
    
    if (!storePath) {
      showError('Please enter a store path');
      return;
    }
    
    try {
      await api('/api/team/store/configure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_store_dir: storePath })
      });
      
      // Hide modal
      if (els.teamStoreConfigModal) els.teamStoreConfigModal.classList.add('hidden');
      
      // Refresh store status
      fetchTeamStoreStatus();
    } catch (err) {
      console.error('[saveStoreConfig] Error:', err);
      if (handleFeatureLockedError(err)) return;
      showError('Failed to configure store: ' + (err.message || 'Unknown error'));
    }
  }
  
  /**
   * Bind Team tab event handlers
   */
  function bindTeamEvents() {
    // Store configuration
    if (els.btnConfigureStore) {
      els.btnConfigureStore.addEventListener('click', showStoreConfigModal);
    }
    if (els.btnRefreshStore) {
      els.btnRefreshStore.addEventListener('click', () => {
        fetchTeamStoreStatus();
        fetchTeamCases();
      });
    }
    if (els.btnCancelStoreConfig) {
      els.btnCancelStoreConfig.addEventListener('click', () => {
        if (els.teamStoreConfigModal) els.teamStoreConfigModal.classList.add('hidden');
      });
    }
    if (els.btnSaveStoreConfig) {
      els.btnSaveStoreConfig.addEventListener('click', saveStoreConfig);
    }
    
    // Copy diagnostics button
    if (els.btnCopyStoreDiagnostics) {
      els.btnCopyStoreDiagnostics.addEventListener('click', copyStoreDiagnostics);
    }
    
    // Case creation toggle (click header to expand/collapse)
    if (els.createCaseHeader) {
      els.createCaseHeader.addEventListener('click', () => {
        if (els.createCaseForm) {
          const isHidden = els.createCaseForm.style.display === 'none';
          els.createCaseForm.style.display = isHidden ? 'flex' : 'none';
          if (els.createCaseToggle) {
            els.createCaseToggle.textContent = isHidden ? '▲' : '▼';
          }
        }
      });
    }
    
    // Case creation submit
    if (els.btnCreateCase) {
      els.btnCreateCase.addEventListener('click', createTeamCase);
    }
    
    // Case search with debounce
    if (els.teamCaseSearch) {
      els.teamCaseSearch.addEventListener('input', () => {
        // Clear existing timer
        if (state.teamStore.searchDebounceTimer) {
          clearTimeout(state.teamStore.searchDebounceTimer);
        }
        // Set new debounce timer (300ms)
        state.teamStore.searchDebounceTimer = setTimeout(() => {
          renderTeamCaseList();
        }, 300);
      });
    }
    
    // Tag filter dropdown
    if (els.teamCaseTagFilter) {
      els.teamCaseTagFilter.addEventListener('change', renderTeamCaseList);
    }
    
    // Sort dropdown
    if (els.teamCaseSortBy) {
      els.teamCaseSortBy.addEventListener('change', renderTeamCaseList);
    }
    
    // Has runs filter checkbox
    if (els.teamCaseHasRunsFilter) {
      els.teamCaseHasRunsFilter.addEventListener('change', renderTeamCaseList);
    }
    
    // Case detail sub-tab switching (using event delegation)
    if (els.teamCaseTabsContainer) {
      els.teamCaseTabsContainer.addEventListener('click', (e) => {
        const tabBtn = e.target.closest('.team-case-tab');
        if (tabBtn) {
          const tabName = tabBtn.dataset.tab;
          if (tabName) switchCaseTab(tabName);
        }
      });
    }
    
    // Copy case ID button
    if (els.btnCopyCaseId) {
      els.btnCopyCaseId.addEventListener('click', () => {
        const caseId = state.teamStore.selectedCaseId;
        if (caseId) {
          navigator.clipboard.writeText(caseId).then(() => {
            showToast('Case ID copied to clipboard', 'success');
          }).catch(() => {
            showToast('Failed to copy Case ID', 'error');
          });
        }
      });
    }
    
    // Bulk import button
    if (els.btnImportSelectedRuns) {
      els.btnImportSelectedRuns.addEventListener('click', bulkImportSelectedRuns);
    }
    
    // Tag management
    if (els.btnAddCaseTag) {
      els.btnAddCaseTag.addEventListener('click', addTeamCaseTag);
    }
    if (els.teamCaseNewTag) {
      els.teamCaseNewTag.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') addTeamCaseTag();
      });
    }
    
    // Notes
    if (els.btnAddCaseNote) {
      els.btnAddCaseNote.addEventListener('click', addTeamCaseNote);
    }
    
    // Publish run
    if (els.btnPublishRunToCase) {
      els.btnPublishRunToCase.addEventListener('click', showPublishRunModal);
    }
    if (els.btnCancelPublishRun) {
      els.btnCancelPublishRun.addEventListener('click', () => {
        if (els.teamPublishRunModal) els.teamPublishRunModal.classList.add('hidden');
      });
    }
    if (els.btnConfirmPublishRun) {
      els.btnConfirmPublishRun.addEventListener('click', publishRunToCase);
    }
    
    // Modal backdrop clicks
    if (els.teamStoreConfigModal) {
      els.teamStoreConfigModal.addEventListener('click', (e) => {
        if (e.target === els.teamStoreConfigModal) {
          els.teamStoreConfigModal.classList.add('hidden');
        }
      });
    }
    if (els.teamPublishRunModal) {
      els.teamPublishRunModal.addEventListener('click', (e) => {
        if (e.target === els.teamPublishRunModal) {
          els.teamPublishRunModal.classList.add('hidden');
        }
      });
    }
  }

  /**
   * Fetch signals (findings) for a run - STRICT RUN ISOLATION
   * Backend groups signals by hour buckets into "runs" with earliest_ts/latest_ts
   * We filter client-side since backend doesn't support run_id query param
   * 
   * ISOLATION GUARANTEE:
   * - Only signals within [run.earliest_ts, run.latest_ts] are returned
   * - signalsRunId tracks which run the signals belong to
   * - If run has no time bounds, returns empty (fail-safe, not fail-silent)
   */
  async function fetchSignalsForRun(run) {
    // Clear previous run's signals first (isolation)
    state.signals = [];
    state.signalsRunId = null;
    state.signalsCursor = 0; // Reset cursor for fresh fetch (0 = from beginning)
    
    if (state.capabilities.signals === false) {
      console.log('[fetchSignalsForRun] Signals endpoint not available');
      return [];
    }
    
    if (!run || !run.run_id) {
      console.warn('[fetchSignalsForRun] No run provided');
      return [];
    }
    
    try {
      // Pass run_id to backend for per-run DB query (TRUTH_CONTRACT invariant 8)
      const resp = await api(`/api/signals?run_id=${encodeURIComponent(run.run_id)}`);
      const data = resp.data || resp;
      const signals = Array.isArray(data.signals) ? data.signals : [];
      
      // Track which run these signals belong to
      state.signalsRunId = run.run_id;
      
      // Track cursor for incremental updates (next_since_ts_ms from contract)
      if (typeof data.next_since_ts_ms === 'number') {
        state.signalsCursor = data.next_since_ts_ms;
      }
      
      console.log(`[fetchSignalsForRun] Run ${run.run_id}: ${signals.length} signals, next_since_ts_ms=${state.signalsCursor}`);
      
      return signals;
    } catch (err) {
      console.warn('[fetchSignalsForRun] Error:', err.message);
      if (err.status === 404) {
        state.capabilities.signals = false;
      }
      return [];
    }
  }

  /**
   * Live incremental signal polling during active run
   * Uses next_since_ts_ms cursor to fetch only NEW signals since last poll
   * Merges new signals into state.signals without full reload
   * INVARIANT: Only polls when state.isRunning AND state.runId are set
   */
  async function pollLiveSignals() {
    if (state.capabilities.signals === false) {
      console.log('[pollLiveSignals] Signals capability disabled');
      return;
    }
    
    // INVARIANT: Must have both isRunning AND runId from /api/run/status
    if (!state.isRunning) {
      console.log('[pollLiveSignals] Not running, skipping');
      return;
    }
    
    const runId = state.runId;
    if (!runId) {
      console.log('[pollLiveSignals] isRunning=true but no runId, skipping');
      return;
    }
    
    try {
      // Build URL with cursor (since_ts_ms)
      let url = `/api/signals?run_id=${encodeURIComponent(runId)}`;
      if (state.signalsCursor && state.signalsCursor > 0) {
        url += `&since_ts_ms=${state.signalsCursor}`;
      }
      
      const resp = await api(url);
      const data = resp.data || resp;
      const newSignals = Array.isArray(data.signals) ? data.signals : [];
      
      // Update cursor from next_since_ts_ms (contract: always present)
      const nextCursor = data.next_since_ts_ms;
      if (typeof nextCursor === 'number') {
        state.signalsCursor = nextCursor;
      }
      
      if (newSignals.length > 0) {
        console.log(`[pollLiveSignals] Got ${newSignals.length} new signals, cursor=${state.signalsCursor}`);
        
        // Merge new signals (prepend since they're newer, sorted DESC)
        // Deduplicate by signal_id
        const existingIds = new Set(state.signals.map(s => s.signal_id));
        const uniqueNew = newSignals.filter(s => !existingIds.has(s.signal_id));
        
        if (uniqueNew.length > 0) {
          state.signals = [...uniqueNew, ...state.signals];
          state.signalsRunId = runId;
          
          // Update UI if Findings tab is visible
          if (state.currentRunTab === 'findings') {
            renderFindingsTab();
          }
          
          // Update timeline if visible
          if (state.currentRunTab === 'timeline') {
            renderTimelineTab();
          }
          
          console.log(`[pollLiveSignals] Added ${uniqueNew.length} signals, total now ${state.signals.length}`);
        }
      }
      
      // Auto-refresh Explain tab if a signal is selected and explain tab is visible
      if (state.selectedSignalId && state.currentRunTab === 'explain') {
        await refreshExplanationIfNeeded();
      }
    } catch (err) {
      console.warn('[pollLiveSignals] Error:', err.message);
      // Don't disable capability on transient errors
    }
  }

  /**
   * Refresh explanation for currently selected signal if needed
   * Called during live polling to ensure explain stays current
   */
  async function refreshExplanationIfNeeded() {
    if (!state.selectedSignalId || !state.selectedRun) return;
    
    try {
      const runIdParam = `?run_id=${encodeURIComponent(state.selectedRun.run_id || state.runId)}`;
      const data = await api(`/api/signals/${state.selectedSignalId}/explain${runIdParam}`);
      
      const newExplanation = data.data || data;
      
      // Only update if explanation changed (prevents flickering)
      const oldJson = JSON.stringify(state.signalExplanation);
      const newJson = JSON.stringify(newExplanation);
      
      if (oldJson !== newJson) {
        state.signalExplanation = newExplanation;
        console.log('[refreshExplanationIfNeeded] Explanation updated');
        
        // Re-render explain tab
        if (state.currentRunTab === 'explain') {
          renderExplainTab();
        }
      }
    } catch (err) {
      // Silent fail - explanation may not exist yet
    }
  }

  /**
   * Fetch a single signal by ID
   * Passes run_id for per-run DB query (TRUTH_CONTRACT invariant 8)
   */
  async function fetchSignal(signalId) {
    try {
      // Pass run_id if we have a selected run
      const runIdParam = state.selectedRun?.run_id 
        ? `?run_id=${encodeURIComponent(state.selectedRun.run_id)}` 
        : '';
      const data = await api(`/api/signals/${signalId}${runIdParam}`);
      const signal = data.data || data;
      
      return signal;
    } catch (err) {
      console.warn('[fetchSignal] Error:', err.message);
      return null;
    }
  }

  /**
   * Fetch explanation for a signal
   * Passes run_id for per-run DB query (TRUTH_CONTRACT invariant 8)
   */
  async function fetchSignalExplanation(signalId) {
    try {
      // Pass run_id if we have a selected run (required for per-run DB)
      const runIdParam = state.selectedRun?.run_id 
        ? `?run_id=${encodeURIComponent(state.selectedRun.run_id)}` 
        : '';
      const data = await api(`/api/signals/${signalId}/explain${runIdParam}`);
      state.capabilities.signalExplain = true;
      return data.data || data;
    } catch (err) {
      console.warn('[fetchSignalExplanation] Error:', err.message);
      if (err.status === 404) {
        // Could be endpoint missing OR explanation not found for this signal
        // Check message to differentiate
        if (err.message?.includes('not found') && !err.message?.includes('endpoint')) {
          // Explanation not found for this signal, but endpoint exists
          return null;
        }
        state.capabilities.signalExplain = false;
      }
      return null;
    }
  }

  /**
   * Fetch narrative for a signal
   */
  async function fetchSignalNarrative(signalId) {
    try {
      const data = await api(`/api/signals/${signalId}/narrative`);
      state.capabilities.signalNarrative = true;
      return data.data || data;
    } catch (err) {
      console.warn('[fetchSignalNarrative] Error:', err.message);
      if (err.status === 404) {
        if (err.message?.includes('not found') && !err.message?.includes('endpoint')) {
          return null;
        }
        state.capabilities.signalNarrative = false;
      }
      return null;
    }
  }

  // ============ EXPLAIN AUTO-REFRESH CONTROLLER ============
  /**
   * Stop any running explain auto-refresh loop.
   * Call this when: user selects different signal, leaves Explain tab, run stops, or explanation becomes available.
   */
  function stopExplainRefresh() {
    if (explainRefreshTimeoutId !== null) {
      clearTimeout(explainRefreshTimeoutId);
      explainRefreshTimeoutId = null;
      console.log('[ExplainRefresh] Stopped');
    }
    explainRefreshAttempt = 0;
    explainRefreshSignalId = null;
    explainRefreshStartTime = null;
  }

  /**
   * Start explain auto-refresh loop for a signal.
   * Only starts if: signal selected, on Explain tab, available=false, run active (not imported mode).
   * Uses exponential backoff: 500ms, 1s, 2s, 3s... up to 10s total.
   */
  function startExplainRefresh(signalId) {
    // Stop any existing refresh loop first
    stopExplainRefresh();

    // Guard: Don't retry in imported mode (static data)
    if (state.importedMode) {
      console.log('[ExplainRefresh] Skipped: imported mode');
      return;
    }

    // Guard: Only retry when on Explain tab
    if (state.currentRunTab !== 'explain') {
      console.log('[ExplainRefresh] Skipped: not on Explain tab');
      return;
    }

    // Guard: Need a signal selected
    if (!signalId || !state.selectedSignal) {
      console.log('[ExplainRefresh] Skipped: no signal selected');
      return;
    }

    // Guard: Only retry if current explanation is unavailable
    const explainResp = state.signalExplanation || {};
    if (explainResp.available !== false) {
      console.log('[ExplainRefresh] Skipped: explanation already available');
      return;
    }

    // Start tracking
    explainRefreshSignalId = signalId;
    explainRefreshStartTime = Date.now();
    explainRefreshAttempt = 0;

    console.log('[ExplainRefresh] Started for signal:', signalId);
    scheduleExplainRefresh();
  }

  /**
   * Schedule the next explain refresh attempt with exponential backoff.
   */
  function scheduleExplainRefresh() {
    // Check total elapsed time
    const elapsed = Date.now() - explainRefreshStartTime;
    if (elapsed >= EXPLAIN_REFRESH_MAX_TOTAL_MS) {
      console.log('[ExplainRefresh] Max time exceeded, stopping');
      updateExplainRefreshUI('exhausted');
      stopExplainRefresh();
      return;
    }

    // Calculate delay with exponential backoff: 500ms, 1000ms, 2000ms, 3000ms
    // Cap individual delays at 3 seconds
    const delay = Math.min(EXPLAIN_REFRESH_BASE_DELAY * Math.pow(2, explainRefreshAttempt), 3000);
    
    explainRefreshTimeoutId = setTimeout(async () => {
      explainRefreshTimeoutId = null;

      // Re-check guards before fetching
      if (state.importedMode) {
        stopExplainRefresh();
        return;
      }
      if (state.currentRunTab !== 'explain') {
        stopExplainRefresh();
        return;
      }
      if (document.hidden) {
        // Page not visible - reschedule without incrementing attempt
        console.log('[ExplainRefresh] Page hidden, pausing');
        scheduleExplainRefresh();
        return;
      }
      if (state.selectedSignalId !== explainRefreshSignalId) {
        // User selected different signal
        stopExplainRefresh();
        return;
      }
      if (!state.isRunning && !state.selectedRun) {
        // Run stopped and no selected run
        stopExplainRefresh();
        return;
      }

      explainRefreshAttempt++;
      console.log(`[ExplainRefresh] Attempt ${explainRefreshAttempt} for ${explainRefreshSignalId}`);
      updateExplainRefreshUI('retrying');

      try {
        // Fetch fresh explanation
        const newExplanation = await fetchSignalExplanation(explainRefreshSignalId);
        
        // Check if still the same signal
        if (state.selectedSignalId !== explainRefreshSignalId) {
          stopExplainRefresh();
          return;
        }

        if (newExplanation && newExplanation.available !== false) {
          // Success! Explanation is now available
          console.log('[ExplainRefresh] Explanation now available');
          state.signalExplanation = newExplanation;
          updateExplainRefreshUI('success');
          stopExplainRefresh();
          renderExplainTab();
        } else {
          // Still unavailable - update state and schedule next retry
          state.signalExplanation = newExplanation;
          renderExplainTab();
          scheduleExplainRefresh();
        }
      } catch (err) {
        console.warn('[ExplainRefresh] Fetch error:', err.message);
        // Schedule retry on error too
        scheduleExplainRefresh();
      }
    }, delay);

    console.log(`[ExplainRefresh] Next attempt in ${delay}ms (attempt ${explainRefreshAttempt + 1})`);
  }

  /**
   * Update UI to show explain refresh status.
   * @param {'retrying'|'exhausted'|'success'|'idle'} status
   */
  function updateExplainRefreshUI(status) {
    const banner = els.explainUnavailableBanner;
    if (!banner) return;

    // Find or create the retry status element
    let retryStatus = banner.querySelector('.explain-retry-status');
    if (!retryStatus) {
      retryStatus = document.createElement('div');
      retryStatus.className = 'explain-retry-status';
      retryStatus.style.cssText = 'font-size: 11px; margin-top: 8px; padding: 6px 8px; background: var(--panel2); border-radius: 4px;';
      banner.appendChild(retryStatus);
    }

    switch (status) {
      case 'retrying':
        const elapsed = ((Date.now() - explainRefreshStartTime) / 1000).toFixed(1);
        retryStatus.innerHTML = `
          <span style="color: var(--accent);">⏳</span>
          Waiting for explanation… retrying (${explainRefreshAttempt})
          <span style="color: var(--muted); margin-left: 8px;">${elapsed}s elapsed</span>
        `;
        retryStatus.style.display = 'block';
        break;
      case 'exhausted':
        retryStatus.innerHTML = `
          <span style="color: var(--warn);">⚠️</span>
          Still unavailable after ${(EXPLAIN_REFRESH_MAX_TOTAL_MS / 1000)}s
          <button id="btnExplainRetry" style="margin-left: 8px; padding: 2px 8px; font-size: 11px; cursor: pointer; background: var(--panel); border: 1px solid var(--border); border-radius: 4px; color: var(--text);">
            Retry
          </button>
        `;
        retryStatus.style.display = 'block';
        // Bind retry button
        const retryBtn = retryStatus.querySelector('#btnExplainRetry');
        if (retryBtn) {
          retryBtn.onclick = () => {
            if (state.selectedSignalId) {
              startExplainRefresh(state.selectedSignalId);
            }
          };
        }
        break;
      case 'success':
        retryStatus.style.display = 'none';
        break;
      case 'idle':
      default:
        retryStatus.style.display = 'none';
        break;
    }
  }

  /**
   * Fetch signal stats for a run
   */
  async function fetchSignalStats() {
    if (state.capabilities.signalsStats === false) {
      return null;
    }
    
    try {
      const data = await api('/api/signals/stats');
      return data.data || data;
    } catch (err) {
      console.warn('[fetchSignalStats] Error:', err.message);
      if (err.status === 404) {
        state.capabilities.signalsStats = false;
      }
      return null;
    }
  }

  /**
   * Export bundle - POST /api/export/bundle
   */
  async function exportBundle(runId = null) {
    const btn = els.btnExportBundle || els.btnExportRun;
    const originalText = btn?.textContent || 'Export';
    
    if (btn) {
      btn.disabled = true;
      btn.textContent = '⏳ Exporting...';
    }
    
    try {
      const res = await fetch(`${API_BASE}/api/export/bundle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          run_id: runId || state.runId || state.selectedRunId,
          include_evidence_excerpts: true,
          redact: false
        })
      });
      
      if (!res.ok) {
        let errMsg = `HTTP ${res.status}`;
        try {
          const errData = await res.json();
          errMsg = errData.error || errData.message || errMsg;
        } catch (e) {}
        throw new Error(errMsg);
      }
      
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      
      // Generate filename with run_id and timestamp
      const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
      const id = runId || state.selectedRunId || 'export';
      const shortId = id.length > 8 ? id.slice(0, 8) : id;
      const filename = `incident-bundle-${shortId}-${ts}.zip`;
      
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      console.log('[exportBundle] Success:', filename);
      
      // Show brief success feedback
      if (btn) {
        btn.textContent = '✅ Exported!';
        setTimeout(() => { btn.textContent = originalText; }, 2000);
      }
      
    } catch (err) {
      console.error('[exportBundle] Error:', err);
      showError(`Export failed: ${err.message}`);
      if (btn) {
        btn.textContent = originalText;
      }
    } finally {
      if (btn) {
        btn.disabled = false;
      }
    }
  }

  /**
   * Import bundle - POST /api/import/bundle
   */
  async function importBundle(file) {
    console.log('[importBundle] Starting import:', file.name);
    
    try {
      const formData = new FormData();
      formData.append('bundle', file);
      
      const res = await fetch(`${API_BASE}/api/import/bundle`, {
        method: 'POST',
        body: formData
      });
      
      if (!res.ok) {
        let errMsg = `HTTP ${res.status}`;
        let importReport = null;
        try {
          const errData = await res.json();
          errMsg = errData.error || errData.message || errMsg;
          importReport = errData.import_report;
        } catch (e) {}
        
        // Show import report even on error
        if (importReport) {
          showImportReport(importReport, false, errMsg);
        }
        throw new Error(errMsg);
      }
      
      const data = await res.json();
      console.log('[importBundle] Success:', data);
      
      // Show import report if available
      if (data.import_report) {
        showImportReport(data.import_report, true, data.data?.message);
      } else {
        showToast(`Import successful: ${data.data?.run_id}`, 'success');
      }
      
      // Switch to imported mode
      enterImportedMode();
      
      // Refresh runs list to show imported data
      await fetchRuns();
      
      // Switch to Runs tab to show imported content
      switchTab('runs');
      
    } catch (err) {
      console.error('[importBundle] Error:', err);
      showError(`Import failed: ${err.message}`);
    }
  }

  /**
   * Show import report in a modal/toast
   */
  function showImportReport(report, success, message) {
    const normalized = report.normalized_artifacts || [];
    const dropped = report.dropped_artifacts || [];
    const summary = report.summary || {};
    const evidenceAvailable = report.evidence_deref_available;
    
    // Build report HTML
    const html = `
      <div style="max-width: 500px;">
        <div style="margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 20px;">${success ? '✅' : '⚠️'}</span>
          <div>
            <div style="font-weight: 600; font-size: 14px;">${success ? 'Import Successful' : 'Import Issue'}</div>
            ${message ? `<div style="font-size: 12px; color: var(--muted);">${escapeHtml(message)}</div>` : ''}
          </div>
        </div>
        
        <div style="background: var(--panel2); border-radius: var(--radius-sm); padding: 12px; margin-bottom: 12px;">
          <div style="font-size: 11px; font-weight: 600; color: var(--muted); text-transform: uppercase; margin-bottom: 8px;">Summary</div>
          <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; font-size: 12px;">
            <div><span style="color: var(--muted);">Files:</span> ${summary.total_files || 0}</div>
            <div><span style="color: var(--good);">Imported:</span> ${summary.imported_files || 0}</div>
            <div><span style="color: ${dropped.length > 0 ? 'var(--warn)' : 'var(--muted)'};">Dropped:</span> ${summary.dropped_files || 0}</div>
            <div><span style="color: var(--muted);">Segments:</span> ${summary.segment_count || 0}</div>
            <div><span style="color: var(--muted);">Database:</span> ${summary.has_database ? '✅' : '❌'}</div>
            <div><span style="color: var(--muted);">Evidence:</span> ${evidenceAvailable ? '✅' : '❌'}</div>
          </div>
        </div>
        
        ${dropped.length > 0 ? `
          <details style="background: var(--panel2); border-radius: var(--radius-sm); overflow: hidden; margin-bottom: 12px;">
            <summary style="padding: 10px; cursor: pointer; font-size: 12px; font-weight: 600; color: var(--warn);">
              ⚠️ Dropped Artifacts (${dropped.length})
            </summary>
            <div style="padding: 10px; border-top: 1px solid var(--border); max-height: 150px; overflow-y: auto;">
              ${dropped.map(d => `
                <div style="font-size: 11px; padding: 4px 0; border-bottom: 1px solid var(--border);">
                  <div style="font-weight: 500;">${escapeHtml(d.artifact)}</div>
                  <div style="color: var(--muted);">${escapeHtml(d.reason)}</div>
                </div>
              `).join('')}
            </div>
          </details>
        ` : ''}
        
        ${normalized.length > 0 ? `
          <details style="background: var(--panel2); border-radius: var(--radius-sm); overflow: hidden;">
            <summary style="padding: 10px; cursor: pointer; font-size: 12px; font-weight: 600; color: var(--good);">
              ✅ Imported Artifacts (${normalized.length})
            </summary>
            <div style="padding: 10px; border-top: 1px solid var(--border); max-height: 150px; overflow-y: auto;">
              ${normalized.slice(0, 20).map(n => `
                <div style="font-size: 11px; padding: 4px 0; border-bottom: 1px solid var(--border);">
                  <span style="font-weight: 500;">${escapeHtml(n.artifact)}</span>
                  <span style="color: var(--muted); margin-left: 8px;">${n.category}</span>
                  ${n.size ? `<span style="color: var(--muted); margin-left: 8px;">${formatSize(n.size)}</span>` : ''}
                </div>
              `).join('')}
              ${normalized.length > 20 ? `<div style="font-size: 11px; color: var(--muted); padding: 8px; text-align: center;">+${normalized.length - 20} more</div>` : ''}
            </div>
          </details>
        ` : ''}
      </div>
    `;
    
    // Show in a custom modal or toast
    showModal('Import Report', html);
  }

  /**
   * Show a modal dialog
   */
  function showModal(title, contentHtml) {
    // Remove any existing modal
    const existing = document.querySelector('.custom-modal-overlay');
    if (existing) existing.remove();
    
    const overlay = document.createElement('div');
    overlay.className = 'custom-modal-overlay';
    overlay.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 10000;';
    
    overlay.innerHTML = `
      <div style="background: var(--panel); border-radius: var(--radius); padding: 20px; max-width: 90%; max-height: 90%; overflow: auto; box-shadow: 0 4px 24px rgba(0,0,0,0.4);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
          <h3 style="font-size: 16px; font-weight: 600; margin: 0;">${escapeHtml(title)}</h3>
          <button class="modal-close-btn" style="background: none; border: none; font-size: 20px; cursor: pointer; color: var(--muted); padding: 4px 8px;">×</button>
        </div>
        ${contentHtml}
      </div>
    `;
    
    document.body.appendChild(overlay);
    
    // Close on click outside or close button
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay || e.target.classList.contains('modal-close-btn')) {
        overlay.remove();
      }
    });
  }

  /**
   * Format file size
   */
  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
    return (bytes / 1024 / 1024 / 1024).toFixed(1) + ' GB';
  }

  /**
   * Enter imported mode - stop polling, show banner, disable start
   */
  function enterImportedMode() {
    state.importedMode = true;
    
    // Stop run polling (imported data is read-only)
    stopPolling();
    
    // Update UI
    updateImportedBanner();
    
    // Disable start controls
    if (els.btnStartRun) {
      els.btnStartRun.disabled = true;
      els.btnStartRun.title = 'Cannot start: viewing imported data';
    }
    
    // Update mission hint
    if (els.missionHint) {
      els.missionHint.innerHTML = '📥 <span style="color: var(--accent);">Imported mode</span> · Viewing imported bundle data';
    }
  }

  /**
   * Exit imported mode - return to local
   */
  function exitImportedMode() {
    state.importedMode = false;
    
    // Update UI
    updateImportedBanner();
    
    // Re-enable start controls
    if (els.btnStartRun) {
      els.btnStartRun.disabled = false;
      els.btnStartRun.title = '';
    }
    
    // Restart polling
    startPolling();
    
    // Refresh local state
    fetchRunStatus();
    fetchRuns();
  }

  // ============ UI WIRING AUDIT ============
  // Verifies every UI action is properly wired to a backend endpoint.
  // Does NOT start runs or spawn binaries.

  /**
   * Validate wrapper shape per API contract
   * - success must be boolean
   * - If success === true: must have data key
   * - If success === false: must have error (string) and code (string)
   * @returns {valid: boolean, reason: string}
   */
  function validateWrapper(json) {
    if (typeof json !== 'object' || json === null) {
      return { valid: false, reason: 'Response is not an object' };
    }
    
    if (!('success' in json)) {
      return { valid: false, reason: 'Missing "success" field' };
    }
    
    if (typeof json.success !== 'boolean') {
      return { valid: false, reason: '"success" must be boolean' };
    }
    
    if (json.success === true) {
      if (!('data' in json)) {
        return { valid: false, reason: 'success:true requires "data" field' };
      }
    } else {
      if (!('error' in json)) {
        return { valid: false, reason: 'success:false requires "error" field' };
      }
      if (typeof json.error !== 'string') {
        return { valid: false, reason: '"error" must be string' };
      }
      if (!('code' in json)) {
        return { valid: false, reason: 'success:false requires "code" field' };
      }
      if (typeof json.code !== 'string') {
        return { valid: false, reason: '"code" must be string' };
      }
    }
    
    return { valid: true, reason: 'Wrapper valid' };
  }

  /**
   * Validate Content-Type header
   * @returns {valid: boolean, reason: string, isHtml: boolean, preview: string}
   */
  function validateContentType(contentType, body, expectsJson, expectsBinary, expectedMime) {
    const ct = (contentType || '').toLowerCase();
    
    // Detect HTML response (common error case)
    const bodyPrefix = typeof body === 'string' ? body.slice(0, 200).toLowerCase() : '';
    const looksLikeHtml = ct.includes('text/html') || 
                          bodyPrefix.includes('<!doctype') || 
                          bodyPrefix.includes('<html');
    
    if (looksLikeHtml) {
      return { 
        valid: false, 
        reason: 'Response is HTML (likely 404 page or misconfigured route)', 
        isHtml: true,
        preview: bodyPrefix.slice(0, 100) + '...'
      };
    }
    
    if (expectsJson) {
      if (!ct.includes('application/json')) {
        return { 
          valid: false, 
          reason: `Expected application/json, got: ${ct || 'none'}`,
          isHtml: false,
          preview: null
        };
      }
    }
    
    if (expectsBinary && expectedMime) {
      if (!ct.includes(expectedMime)) {
        return { 
          valid: false, 
          reason: `Expected ${expectedMime}, got: ${ct || 'none'}`,
          isHtml: false,
          preview: null
        };
      }
    }
    
    return { valid: true, reason: 'Content-Type OK', isHtml: false, preview: null };
  }

  /**
   * Run UI Wiring Check
   * - Fetches authoritative route list from /api/meta/routes
   * - For each UI_ACTION, verifies the endpoint exists
   * - For safe endpoints, makes a test call and validates response
   * - Reports: OK, Broken, Not Executed, Capability Missing
   * - Tracks ship blockers (required:true + broken = blocker)
   */
  async function runWiringCheck() {
    console.log('[WiringCheck] Starting audit...');
    
    const results = {
      timestamp: new Date().toISOString(),
      baseUrl: API_BASE,
      userAgent: navigator.userAgent,
      summary: { ok: 0, broken: 0, notExecuted: 0, capabilityMissing: 0, locked: 0 },
      tierSummary: { core: 0, pro: 0, team: 0, dev: 0 },
      shipBlockers: [], // required:true + broken = ship blocker
      actions: [],
      routeInventory: []
    };
    
    // Step 1: Fetch authoritative route list
    let serverRoutes = [];
    try {
      const routesData = await api('/api/meta/routes');
      serverRoutes = Array.isArray(routesData) ? routesData : (routesData.data || routesData.routes || []);
      results.routeInventory = serverRoutes;
      console.log('[WiringCheck] Server routes:', serverRoutes.length);
    } catch (err) {
      console.error('[WiringCheck] Failed to fetch routes:', err);
      results.summary.broken++;
      const action = UI_ACTIONS.find(a => a.id === 'meta.routes') || { tier: 'dev', required: false };
      results.actions.push({
        id: 'meta.routes',
        label: 'Route Inventory',
        tier: action.tier,
        required: action.required,
        status: 'broken',
        reason: `Cannot fetch route list: ${err.message}`,
        suggestion: 'Ensure server is running and /api/meta/routes endpoint exists'
      });
      if (action.required) {
        results.shipBlockers.push({ id: 'meta.routes', label: 'Route Inventory', reason: 'Cannot fetch route list' });
      }
      state.wiringCheckResults = results;
      renderWiringCheckPanel();
      return results;
    }
    
    // Build route lookup map (method:path -> route info)
    const routeMap = new Map();
    serverRoutes.forEach(r => {
      const key = `${r.method}:${r.path}`;
      routeMap.set(key, r);
    });
    
    // Step 2: Check each UI_ACTION
    for (const action of UI_ACTIONS) {
      const result = {
        id: action.id,
        label: action.label,
        method: action.request.method,
        path: action.request.path,
        buttonSelector: action.buttonSelector,
        tier: action.tier || 'core',
        required: action.required !== false, // default true
        status: 'unknown',
        reason: null,
        suggestion: null,
        routeExists: null // For notExecuted actions
      };
      
      // Track tier counts
      results.tierSummary[result.tier] = (results.tierSummary[result.tier] || 0) + 1;
      
      // Check if route exists in server registry
      const routeKey = `${action.request.method}:${action.request.path}`;
      const directMatch = routeMap.has(routeKey);
      // Check parameterized routes (e.g., /api/runs/:run_id/coverage matches /api/runs/xxx/coverage)
      const patternMatch = serverRoutes.some(r => {
        if (r.method !== action.request.method) return false;
        // Convert :param patterns to regex
        const pattern = r.path.replace(/:[^/]+/g, '[^/]+');
        const regex = new RegExp(`^${pattern}$`);
        return regex.test(action.request.path) || action.request.path.includes(':');
      });
      const routeExists = directMatch || patternMatch;
      
      if (!routeExists) {
        result.status = 'broken';
        result.reason = `Endpoint not registered: ${action.request.method} ${action.request.path}`;
        result.suggestion = `Add route to build_locint_router() in locint.rs`;
        result.routeExists = false;
        results.summary.broken++;
        if (result.required) {
          results.shipBlockers.push({ id: result.id, label: result.label, reason: result.reason, tier: result.tier });
        }
        results.actions.push(result);
        continue;
      }
      
      result.routeExists = true;
      
      // Check if button exists (if specified)
      if (action.buttonSelector) {
        const btn = document.querySelector(action.buttonSelector);
        if (!btn) {
          result.status = 'broken';
          result.reason = `Button not found: ${action.buttonSelector}`;
          result.suggestion = `Add button element to index.html or update selector`;
          results.summary.broken++;
          if (result.required) {
            results.shipBlockers.push({ id: result.id, label: result.label, reason: result.reason, tier: result.tier });
          }
          results.actions.push(result);
          continue;
        }
      }
      
      // If not safe to call, mark as not executed (UPGRADE 4: show route exists)
      if (!action.safeToCall) {
        result.status = 'notExecuted';
        result.reason = action.notes || 'Mutating endpoint - not called during wiring check';
        result.routeExistsVerified = routeExists ? '✅ route exists' : '❌ route missing';
        results.summary.notExecuted++;
        results.actions.push(result);
        continue;
      }
      
      // Step 3: Make test call for safe endpoints
      try {
        // For parameterized routes, use a test value
        let testPath = action.request.path;
        let testRunId = null;
        let testSignalId = null;
        
        // For endpoints that need run_id, find a real run first
        if (action.request.needsRunId || testPath.includes(':run_id')) {
          testRunId = state.runs?.[0]?.run_id;
          if (!testRunId) {
            try {
              const runsResp = await fetch(`${API_BASE}/api/runs`);
              const runsData = await runsResp.json();
              testRunId = runsData.data?.runs?.[0]?.run_id;
            } catch (e) {}
          }
        }
        
        // For signal explain endpoint, we need a real signal_id too
        if (action.id === 'signals.explain' && testRunId) {
          testSignalId = state.signals?.[0]?.signal_id;
          if (!testSignalId) {
            try {
              const sigsResp = await fetch(`${API_BASE}/api/signals?run_id=${encodeURIComponent(testRunId)}`);
              const sigsData = await sigsResp.json();
              testSignalId = sigsData.data?.signals?.[0]?.signal_id;
            } catch (e) {}
          }
        }
        
        // Replace path parameters
        if (testPath.includes(':run_id')) {
          testPath = testPath.replace(':run_id', testRunId || 'test-run-id-wiring-check');
        }
        if (testPath.includes(':id')) {
          testPath = testPath.replace(':id', testSignalId || 'test-id-wiring-check');
        }
        
        // Add run_id as query param if needed
        if (action.request.needsRunId && testRunId) {
          testPath += (testPath.includes('?') ? '&' : '?') + `run_id=${encodeURIComponent(testRunId)}`;
        }
        
        const res = await fetch(`${API_BASE}${testPath}`, {
          method: action.request.method,
          headers: { 'Accept': 'application/json' }
        });
        
        const contentType = res.headers.get('content-type') || '';
        let bodyText = '';
        let bodyJson = null;
        
        // Read body as text first for HTML detection
        try {
          bodyText = await res.clone().text();
        } catch (e) {}
        
        // UPGRADE 2: Content-Type and HTML detection hardening
        const ctValidation = validateContentType(
          contentType, 
          bodyText, 
          action.expects.json,
          action.expects.binary,
          action.expects.contentType
        );
        
        if (!ctValidation.valid) {
          result.status = 'broken';
          result.reason = ctValidation.reason;
          if (ctValidation.isHtml) {
            result.htmlPreview = ctValidation.preview;
          }
          result.suggestion = 'Check route registration and handler';
          results.summary.broken++;
          if (result.required) {
            results.shipBlockers.push({ id: result.id, label: result.label, reason: result.reason, tier: result.tier });
          }
          results.actions.push(result);
          continue;
        }
        
        // Check for capability issues (412, 503, etc.)
        if (res.status === 412) {
          result.status = 'capabilityMissing';
          try {
            const errData = await res.json();
            result.reason = errData.error || 'Missing binary or dependency';
            result.missingBinaries = errData.searched_paths || [];
            result.buildHint = errData.build_hint;
          } catch (e) {
            result.reason = 'HTTP 412 - Missing prerequisite';
          }
          results.summary.capabilityMissing++;
          results.actions.push(result);
          continue;
        }
        
        // Check for tier-locked features (403 FEATURE_LOCKED)
        if (res.status === 403) {
          try {
            const errData = await res.json();
            if (errData.error?.code === 'FEATURE_LOCKED') {
              // This is expected for tier-locked features, not a bug
              result.status = 'locked';
              result.reason = errData.error.message || 'Feature requires higher tier';
              result.requiredTier = errData.error.required_tier;
              result.currentTier = errData.error.current_tier;
              result.upgradeUrl = errData.error.upgrade_url;
              results.summary.locked = (results.summary.locked || 0) + 1;
              results.actions.push(result);
              continue;
            }
          } catch (e) {}
          // Other 403s are actual errors
        }
        
        // Check for blocked/degraded from selfcheck
        if (res.status === 200 && testPath.includes('selfcheck')) {
          try {
            const data = await res.json();
            const status = data.data?.overall_status || data.overall_status;
            if (status === 'blocked' || status === 'degraded') {
              result.status = 'capabilityMissing';
              result.reason = `System ${status}: ${data.data?.summary || data.summary || 'Check readiness'}`;
              results.summary.capabilityMissing++;
              results.actions.push(result);
              continue;
            }
          } catch (e) {}
        }
        
        // 404 on parameterized routes is expected (no such run/signal exists)
        if (res.status === 404 && (testPath.includes('test-run-id') || testPath.includes('test-id'))) {
          // This is OK - route exists but resource not found
          result.status = 'ok';
          result.reason = 'Route exists (404 on test ID is expected)';
          results.summary.ok++;
          results.actions.push(result);
          continue;
        }
        
        // For successful responses, validate JSON structure
        if (res.ok) {
          if (action.expects.json) {
            try {
              bodyJson = JSON.parse(bodyText);
              
              // UPGRADE 3: Use canonical validateWrapper helper
              if (action.expects.wrapper) {
                const wrapperValidation = validateWrapper(bodyJson);
                if (!wrapperValidation.valid) {
                  result.status = 'broken';
                  result.reason = `Wrapper invalid: ${wrapperValidation.reason}`;
                  result.suggestion = 'Handler should return {success: true, data: {...}} or {success: false, error: "...", code: "..."}';
                  results.summary.broken++;
                  if (result.required) {
                    results.shipBlockers.push({ id: result.id, label: result.label, reason: result.reason, tier: result.tier });
                  }
                  results.actions.push(result);
                  continue;
                }
              }
              
              // Check required keys
              if (action.expects.requiredKeys) {
                let responseData = bodyJson.data || bodyJson;
                
                // If dataPath is specified, drill into that array and check first item
                if (action.expects.dataPath && responseData[action.expects.dataPath]) {
                  const arr = responseData[action.expects.dataPath];
                  if (Array.isArray(arr) && arr.length > 0) {
                    responseData = arr[0]; // Check keys in first array item
                  } else if (Array.isArray(arr) && arr.length === 0) {
                    // Empty array - can't validate keys, but structure is OK
                    result.status = 'ok';
                    result.reason = 'Endpoint responds correctly (empty array)';
                    results.summary.ok++;
                    results.actions.push(result);
                    continue;
                  }
                }
                
                const missing = action.expects.requiredKeys.filter(k => !(k in responseData));
                if (missing.length > 0) {
                  result.status = 'broken';
                  result.reason = `Missing required keys: ${missing.join(', ')}`;
                  result.suggestion = `Handler should include: ${missing.join(', ')}`;
                  results.summary.broken++;
                  if (result.required) {
                    results.shipBlockers.push({ id: result.id, label: result.label, reason: result.reason, tier: result.tier });
                  }
                  results.actions.push(result);
                  continue;
                }
              }
              
              result.status = 'ok';
              result.reason = 'Endpoint responds correctly';
              results.summary.ok++;
            } catch (e) {
              result.status = 'broken';
              result.reason = `Invalid JSON: ${e.message}`;
              result.suggestion = 'Check handler is returning valid JSON';
              results.summary.broken++;
              if (result.required) {
                results.shipBlockers.push({ id: result.id, label: result.label, reason: result.reason, tier: result.tier });
              }
            }
          } else if (action.expects.binary) {
            // For binary endpoints, content-type already validated above
            result.status = 'ok';
            result.reason = 'Binary endpoint responds';
            results.summary.ok++;
          } else {
            result.status = 'ok';
            result.reason = 'Endpoint responds';
            results.summary.ok++;
          }
        } else {
          // Non-OK status (not 404 on test)
          result.status = 'broken';
          result.reason = `HTTP ${res.status}`;
          results.summary.broken++;
          if (result.required) {
            results.shipBlockers.push({ id: result.id, label: result.label, reason: result.reason, tier: result.tier });
          }
        }
        
        results.actions.push(result);
        
      } catch (err) {
        result.status = 'broken';
        result.reason = `Network error: ${err.message}`;
        result.suggestion = 'Check server is running';
        results.summary.broken++;
        if (result.required) {
          results.shipBlockers.push({ id: result.id, label: result.label, reason: result.reason, tier: result.tier });
        }
        results.actions.push(result);
      }
    }
    
    console.log('[WiringCheck] Complete:', results.summary, 'Ship blockers:', results.shipBlockers.length);
    state.wiringCheckResults = results;
    renderWiringCheckPanel();
    return results;
  }

  /**
   * Export wiring check results as JSON
   */
  function exportWiringCheckResults(download = false) {
    const results = state.wiringCheckResults;
    if (!results) {
      console.warn('[WiringCheck] No results to export');
      return;
    }
    
    // Build export object with full context
    const exportData = {
      _meta: {
        exportedAt: new Date().toISOString(),
        buildStamp: document.querySelector('.build-stamp')?.textContent || 'unknown',
        userAgent: navigator.userAgent,
        baseUrl: results.baseUrl || API_BASE
      },
      timestamp: results.timestamp,
      summary: results.summary,
      tierSummary: results.tierSummary,
      shipBlockers: results.shipBlockers,
      routeInventoryHash: results.routeInventory?.length || 0,
      actions: results.actions.map(a => ({
        id: a.id,
        label: a.label,
        tier: a.tier,
        required: a.required,
        method: a.method,
        path: a.path,
        status: a.status,
        reason: a.reason,
        routeExists: a.routeExists,
        routeExistsVerified: a.routeExistsVerified,
        htmlPreview: a.htmlPreview
      }))
    };
    
    const json = JSON.stringify(exportData, null, 2);
    
    if (download) {
      // Download as file
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `wiring-check-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      console.log('[WiringCheck] Report downloaded');
    } else {
      // Copy to clipboard
      navigator.clipboard.writeText(json).then(() => {
        console.log('[WiringCheck] Report copied to clipboard');
        // Visual feedback
        const copyBtn = document.getElementById('btnWiringCopyJson');
        if (copyBtn) {
          const orig = copyBtn.textContent;
          copyBtn.textContent = '✓ Copied!';
          setTimeout(() => copyBtn.textContent = orig, 1500);
        }
      }).catch(err => {
        console.error('[WiringCheck] Failed to copy:', err);
      });
    }
    
    return json;
  }

  /**
   * Render wiring check results panel
   */
  function renderWiringCheckPanel() {
    const panel = document.getElementById('wiringCheckPanel');
    const content = document.getElementById('wiringCheckContent');
    
    if (!panel || !content) {
      console.warn('[WiringCheck] Panel elements not found');
      return;
    }
    
    const results = state.wiringCheckResults;
    if (!results) {
      content.innerHTML = '<div style="color: var(--muted); padding: 16px; text-align: center;">Click "Wiring Check" to audit UI actions</div>';
      return;
    }
    
    const { summary, actions, shipBlockers, tierSummary } = results;
    
    // Status icon helper
    const statusIcon = (status) => ({
      'ok': '✅',
      'broken': '❌',
      'notExecuted': '⏸️',
      'capabilityMissing': '⚠️',
      'locked': '🔒'
    }[status] || '❓');
    
    const statusLabel = (status) => ({
      'ok': 'OK',
      'broken': 'Broken',
      'notExecuted': 'Not Executed',
      'capabilityMissing': 'Capability Missing',
      'locked': 'Tier Locked'
    }[status] || 'Unknown');
    
    const statusColor = (status) => ({
      'ok': 'var(--good)',
      'broken': 'var(--bad)',
      'notExecuted': 'var(--muted)',
      'capabilityMissing': 'var(--warn)',
      'locked': 'var(--accent)'
    }[status] || 'var(--text)');
    
    const tierLabel = (tier) => ({
      'core': '🔷 Core',
      'pro': '💎 Pro',
      'team': '👥 Team',
      'dev': '🔧 Dev'
    }[tier] || tier);
    
    // Build HTML
    let html = '';
    
    // Ship Blockers Banner (if any)
    if (shipBlockers && shipBlockers.length > 0) {
      html += `
        <div style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); color: white; padding: 12px 16px; border-radius: var(--radius-sm); margin-bottom: 16px;">
          <div style="font-size: 14px; font-weight: 700; margin-bottom: 8px;">🚫 SHIP BLOCKERS: ${shipBlockers.length}</div>
          <div style="font-size: 11px; opacity: 0.9; margin-bottom: 8px;">These required actions are broken and must be fixed before shipping:</div>
          <div style="font-size: 12px;">
            ${shipBlockers.map(b => `<div style="padding: 4px 0;">• <strong>${b.label}</strong> [${b.tier}]: ${b.reason}</div>`).join('')}
          </div>
        </div>
      `;
    }
    
    // Summary
    html += `
      <div style="margin-bottom: 16px; padding: 12px; background: var(--panel2); border-radius: var(--radius-sm);">
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 8px;">Summary</div>
        <div style="display: flex; gap: 16px; flex-wrap: wrap;">
          <span style="color: var(--good);">✅ OK: ${summary.ok}</span>
          <span style="color: var(--bad);">❌ Broken: ${summary.broken}</span>
          <span style="color: var(--muted);">⏸️ Not Executed: ${summary.notExecuted}</span>
          <span style="color: var(--warn);">⚠️ Capability Missing: ${summary.capabilityMissing}</span>
          <span style="color: var(--accent);">🔒 Tier Locked: ${summary.locked || 0}</span>
        </div>
        <div style="font-size: 11px; color: var(--muted); margin-top: 8px; border-top: 1px solid var(--border); padding-top: 8px;">
          <strong>By Tier:</strong>
          ${tierSummary ? Object.entries(tierSummary).map(([t, c]) => `<span style="margin-left: 8px;">${tierLabel(t)}: ${c}</span>`).join('') : ''}
        </div>
        <div style="font-size: 10px; color: var(--muted); margin-top: 8px; display: flex; justify-content: space-between; align-items: center;">
          <span>Checked at ${new Date(results.timestamp).toLocaleTimeString()}</span>
          <span style="display: flex; gap: 8px;">
            <button id="btnWiringCopyJson" onclick="window.__wiringExport && window.__wiringExport(false)" style="background: var(--panel); border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; font-size: 10px; cursor: pointer; color: var(--text);">📋 Copy JSON</button>
            <button id="btnWiringDownload" onclick="window.__wiringExport && window.__wiringExport(true)" style="background: var(--panel); border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; font-size: 10px; cursor: pointer; color: var(--text);">💾 Download</button>
          </span>
        </div>
      </div>
      
      <div style="max-height: 300px; overflow-y: auto;">
    `;
    
    // Expose export function globally for onclick
    window.__wiringExport = exportWiringCheckResults;
    
    // Group by status
    const grouped = {
      broken: actions.filter(a => a.status === 'broken'),
      locked: actions.filter(a => a.status === 'locked'),
      capabilityMissing: actions.filter(a => a.status === 'capabilityMissing'),
      notExecuted: actions.filter(a => a.status === 'notExecuted'),
      ok: actions.filter(a => a.status === 'ok')
    };
    
    // Render broken first (most important)
    for (const [group, items] of Object.entries(grouped)) {
      if (items.length === 0) continue;
      
      html += `<div style="margin-bottom: 12px;">
        <div style="font-size: 11px; font-weight: 600; color: ${statusColor(group)}; text-transform: uppercase; margin-bottom: 6px;">
          ${statusIcon(group)} ${statusLabel(group)} (${items.length})
        </div>`;
      
      for (const action of items) {
        const tierBadge = action.tier ? `<span style="font-size: 9px; padding: 1px 4px; background: var(--panel2); border-radius: 2px; margin-right: 4px;">${tierLabel(action.tier)}</span>` : '';
        const requiredBadge = action.required ? '<span style="font-size: 9px; color: var(--bad); margin-right: 4px;">REQUIRED</span>' : '';
        const routeExistsBadge = action.routeExistsVerified ? `<span style="font-size: 10px; margin-left: 8px;">${action.routeExistsVerified}</span>` : '';
        const requiredTierBadge = action.requiredTier ? `<span style="font-size: 9px; padding: 1px 4px; background: var(--accent); color: #fff; border-radius: 2px; margin-left: 4px;">Requires ${action.requiredTier}</span>` : '';
        
        html += `
          <div style="padding: 8px; background: var(--panel); border: 1px solid var(--border); border-radius: 4px; margin-bottom: 4px; font-size: 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 4px;">
              <span style="font-weight: 500;">${tierBadge}${requiredBadge}${action.label}${requiredTierBadge}</span>
              <code style="font-size: 10px; color: var(--muted);">${action.method} ${action.path}${routeExistsBadge}</code>
            </div>
            ${action.reason ? `<div style="color: ${statusColor(action.status)}; font-size: 11px; margin-top: 4px;">${escapeHtml(action.reason)}</div>` : ''}
            ${action.suggestion ? `<div style="color: var(--accent); font-size: 10px; margin-top: 2px;">💡 ${escapeHtml(action.suggestion)}</div>` : ''}
            ${action.upgradeUrl ? `<div style="font-size: 10px; margin-top: 4px;"><a href="${action.upgradeUrl}" target="_blank" style="color: var(--accent); text-decoration: underline;">🔗 Upgrade to unlock</a></div>` : ''}
            ${action.htmlPreview ? `<div style="font-family: monospace; font-size: 9px; margin-top: 4px; padding: 4px; background: #1a1a1a; border-radius: 2px; color: #ff6b6b; white-space: pre-wrap; overflow: hidden;">${escapeHtml(action.htmlPreview)}</div>` : ''}
            ${action.buildHint ? `<div style="font-family: monospace; font-size: 10px; margin-top: 4px; padding: 4px; background: var(--panel2); border-radius: 2px;">${escapeHtml(action.buildHint)}</div>` : ''}
          </div>
        `;
      }
      
      html += '</div>';
    }
    
    html += '</div>';
    
    content.innerHTML = html;
    panel.classList.remove('hidden');
  }

  // ============ UI UPDATE FUNCTIONS ============

  function updateServerBadge(online) {
    if (!els.serverBadge) return;
    
    if (online) {
      els.serverBadge.className = 'badge badge-live';
      els.serverBadge.innerHTML = '<span style="width: 6px; height: 6px; background: currentColor; border-radius: 50%; margin-right: 6px;"></span>LOCAL';
    } else {
      els.serverBadge.className = 'badge badge-error';
      els.serverBadge.innerHTML = '<span style="width: 6px; height: 6px; background: currentColor; border-radius: 50%; margin-right: 6px;"></span>OFFLINE';
    }
  }
  
  /**
   * Update instance info badge with port and admin status
   */
  function updateInstanceInfo(isAdmin = false) {
    const port = window.location.port || (window.location.protocol === 'https:' ? '443' : '80');
    const portEl = document.getElementById('instancePort');
    const adminEl = document.getElementById('instanceAdmin');
    const badgeEl = document.getElementById('instanceInfoBadge');
    
    if (portEl) {
      portEl.textContent = `:${port}`;
    }
    if (adminEl) {
      adminEl.style.display = isAdmin ? 'inline' : 'none';
    }
    if (badgeEl) {
      badgeEl.title = `Port: ${port}\nAdmin: ${isAdmin ? 'Yes' : 'No'}\nClick for dataflow debug`;
      badgeEl.onclick = () => openDataflowSnapshot();
    }
    
    // Check diagnosis in debug mode (only during active run or after errors)
    if (state.debugMode || state.isRunning) {
      checkDiagnosis();
    }
  }
  
  /**
   * Check dataflow diagnosis and show banner if issues detected
   */
  async function checkDiagnosis() {
    try {
      const response = await fetch(`${API_BASE}/api/meta/dataflow_snapshot?debug=1`, {
        signal: AbortSignal.timeout(3000)
      });
      if (!response.ok) return;
      
      const result = await response.json();
      const data = result.data || result;
      const diagnosis = data.diagnosis || [];
      
      // Filter out "OK" status
      const issues = diagnosis.filter(d => !d.startsWith('OK:'));
      
      if (issues.length > 0 && els.diagnosisBanner) {
        els.diagnosisBanner.style.display = 'block';
        if (els.diagnosisText) {
          els.diagnosisText.textContent = issues.join(' | ');
        }
        if (els.diagnosisLink) {
          els.diagnosisLink.onclick = (e) => {
            e.preventDefault();
            openDataflowSnapshot();
          };
        }
      } else if (els.diagnosisBanner) {
        els.diagnosisBanner.style.display = 'none';
      }
    } catch (e) {
      // Silently ignore - this is a debug feature
      console.debug('[checkDiagnosis] Error:', e.message);
    }
  }
  
  /**
   * Open dataflow snapshot in new tab (for debugging)
   */
  function openDataflowSnapshot() {
    const url = `${API_BASE}/api/meta/dataflow_snapshot?debug=1`;
    window.open(url, '_blank');
  }

  function updateImportedBanner() {
    if (els.importedBanner) {
      els.importedBanner.classList.toggle('hidden', !state.importedMode);
    }
    // Also update server badge to show IMPORTED
    if (state.importedMode && els.serverBadge) {
      els.serverBadge.className = 'badge badge-running';
      els.serverBadge.innerHTML = '<span style="width: 6px; height: 6px; background: currentColor; border-radius: 50%; margin-right: 6px;"></span>IMPORTED';
    }
    updateBodyPadding();
  }

  function updateBodyPadding() {
    // Show top padding if any banner is visible
    const hasBanner = state.importedMode;
    document.body.style.paddingTop = hasBanner ? '32px' : '0';
  }

  function updateReadinessUI() {
    const statusText = state.readinessState.charAt(0).toUpperCase() + state.readinessState.slice(1);
    
    if (els.readinessStatus) {
      els.readinessStatus.textContent = statusText;
    }
    
    if (els.settingsReadinessStatus) {
      els.settingsReadinessStatus.textContent = statusText;
      
      // Update badge class
      const statusLower = state.readinessState.toLowerCase();
      if (statusLower === 'ok' || statusLower === 'ready' || statusLower === 'pass') {
        els.settingsReadinessStatus.className = 'badge badge-live';
      } else if (statusLower === 'limited' || statusLower === 'partial' || statusLower === 'warn') {
        els.settingsReadinessStatus.className = 'badge badge-running';
      } else if (statusLower === 'unreachable' || statusLower === 'error' || statusLower === 'fail') {
        els.settingsReadinessStatus.className = 'badge badge-error';
      } else {
        els.settingsReadinessStatus.className = 'badge badge-stopped';
      }
    }
    
    if (els.readinessSummary) {
      els.readinessSummary.textContent = state.readinessSummary || 'Check ETW providers, permissions, and telemetry health';
    }
    
    // Update Mission tab System Readiness card
    updateMissionReadinessCard();
    
    // Update Mission tab readiness warning
    updateMissionReadinessWarning();
  }
  
  /**
   * Update the Mission tab's System Readiness card with selfcheck data
   * Uses unified computeReadinessStatus for consistent labels
   */
  function updateMissionReadinessCard() {
    const telemetry = state.telemetryReadiness;
    const readiness = computeReadinessStatus(telemetry);
    
    // Readiness status label - use unified semantics
    if (els.missionReadinessLabel) {
      if (!telemetry) {
        els.missionReadinessLabel.textContent = 'Checking telemetry access...';
      } else if (readiness.isBlocked) {
        els.missionReadinessLabel.textContent = 'Telemetry blocked (required sensors missing)';
      } else if (readiness.isPartial) {
        els.missionReadinessLabel.textContent = 'Partial telemetry (optional sensors missing)';
      } else {
        els.missionReadinessLabel.textContent = 'Full telemetry access';
      }
    }
    
    // Readiness badge with score and tooltip
    if (els.missionReadinessStatus) {
      if (!telemetry) {
        els.missionReadinessStatus.textContent = '—';
        els.missionReadinessStatus.className = 'badge badge-stopped';
        els.missionReadinessStatus.title = '';
      } else {
        els.missionReadinessStatus.textContent = `${readiness.score}%`;
        els.missionReadinessStatus.className = `badge ${readiness.cssClass}`;
        els.missionReadinessStatus.title = readiness.tooltip;
      }
    }
    
    // Sensors summary
    if (els.missionSensorsAvailable) {
      els.missionSensorsAvailable.textContent = telemetry?.sensors_available ?? '—';
    }
    if (els.missionSensorsTotal) {
      els.missionSensorsTotal.textContent = telemetry?.sensors_total ?? '—';
    }
    
    // Channels summary
    if (els.missionChannelsAccessible) {
      els.missionChannelsAccessible.textContent = telemetry?.channels_accessible ?? '—';
    }
    if (els.missionChannelsTotal) {
      els.missionChannelsTotal.textContent = telemetry?.channels_total ?? '—';
    }
  }
  
  /**
   * Show/hide the Mission tab readiness warning based on telemetry status
   * Uses security_log_accessible as authoritative blocker
   */
  function updateMissionReadinessWarning() {
    if (!els.missionReadinessWarning) return;
    
    const telemetry = state.telemetryReadiness;
    
    // Hide if no telemetry data, running, or imported mode
    if (!telemetry || state.isRunning || state.importedMode) {
      els.missionReadinessWarning.classList.add('hidden');
      return;
    }
    
    // Use unified readiness status for consistent display
    const readiness = computeReadinessStatus(telemetry);
    
    // Show warning if blocked or partial
    if (readiness.isBlocked || readiness.isPartial) {
      els.missionReadinessWarning.classList.remove('hidden');
      
      if (els.missionReadinessIssues) {
        let html = '';
        
        // PRIMARY: security_log_accessible is authoritative
        if (telemetry.security_log_accessible === false) {
          const adminNote = telemetry.is_admin === false ? ' (not running as Admin)' : '';
          html += `
            <div style="margin-bottom: 10px;">
              <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
                <span style="color: var(--error);">✗</span>
                <strong>Security Log: Not Accessible</strong>${adminNote}
              </div>
              <div style="font-size: 11px; padding: 8px; background: var(--panel); border-radius: var(--radius-sm); border-left: 3px solid var(--accent);">
                <strong style="color: var(--accent);">🔧 Fix it:</strong> Close app → Right-click locint.exe → "Run as administrator"
              </div>
            </div>
          `;
        }
        
        // SECONDARY: Sysmon (optional, so shown with warning not error)
        if (telemetry.sysmon_installed === false) {
          html += `
            <div style="margin-bottom: 10px;">
              <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
                <span style="color: var(--warn);">⚠</span>
                <strong>Sysmon: Not Installed</strong> <span style="font-size: 10px; color: var(--muted);">(optional)</span>
              </div>
              <div style="font-size: 11px; padding: 8px; background: var(--panel); border-radius: var(--radius-sm); border-left: 3px solid var(--warn);">
                <strong style="color: var(--warn);">🔧 Fix it:</strong> Install from <a href="https://docs.microsoft.com/sysinternals/downloads/sysmon" target="_blank" style="color: var(--accent);">Sysinternals</a>, run <code style="background: var(--panel2); padding: 1px 4px; border-radius: 2px;">sysmon -accepteula -i</code>
              </div>
            </div>
          `;
        }
        
        // Fallback if no specific issues
        if (!html) {
          html = '<div style="color: var(--muted);">Some telemetry sources may be unavailable</div>';
        }
        
        els.missionReadinessIssues.innerHTML = html;
      }
      
      // Show/hide restart-as-admin button section
      const restartSection = $('#restartAdminSection');
      const restartHint = $('#restartAdminHint');
      if (restartSection) {
        // Show restart button if: not admin AND restart is supported
        const showRestart = telemetry.is_admin === false && state.supportsRestartAdmin;
        if (showRestart) {
          restartSection.classList.remove('hidden');
          if (restartHint) {
            restartHint.textContent = 'One-click elevation';
          }
        } else if (telemetry.is_admin === false) {
          // Not admin but restart not supported - hide button, manual instructions only
          restartSection.classList.add('hidden');
        } else {
          restartSection.classList.add('hidden');
        }
      }
    } else {
      els.missionReadinessWarning.classList.add('hidden');
    }
  }

  /**
   * Open the System Readiness modal showing detailed sensor and channel status
   * Uses unified computeReadinessStatus for consistent display
   */
  function openReadinessModal() {
    const telemetry = state.telemetryReadiness;
    const readiness = computeReadinessStatus(telemetry);
    
    // Create or get the modal element
    let modal = document.getElementById('readinessModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'readinessModal';
      modal.style.cssText = `
        position: fixed; top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(0, 0, 0, 0.7); z-index: 1000;
        display: flex; align-items: center; justify-content: center;
        opacity: 0; transition: opacity 0.2s ease-out;
      `;
      document.body.appendChild(modal);
    }
    
    // Build modal content
    const isAdmin = telemetry?.is_admin;
    const sysmonInstalled = telemetry?.sysmon_installed;
    const securityLogAccessible = telemetry?.security_log_accessible;
    
    // Use unified readiness status
    const statusLabel = readiness.label.toUpperCase();
    const statusColor = readiness.isBlocked ? 'var(--error)' : readiness.isPartial ? 'var(--warn)' : 'var(--good)';
    const score = readiness.score;
    
    // Sensors list
    const sensors = telemetry?.sensors || [];
    const sensorsHtml = sensors.length > 0 ? sensors.map(s => {
      const available = s.available === true;
      const icon = available ? '✓' : '✗';
      const color = available ? 'var(--good)' : 'var(--error)';
      const reason = !available && s.required_privileges ? `(requires ${s.required_privileges})` : '';
      return `
        <div style="display: flex; align-items: center; gap: 8px; padding: 6px 0; border-bottom: 1px solid var(--border-subtle);">
          <span style="color: ${color}; font-weight: 600; width: 16px;">${icon}</span>
          <div style="flex: 1;">
            <div style="font-weight: 500;">${escapeHtml(s.name || s.id)}</div>
            <div style="font-size: 11px; color: var(--muted);">${escapeHtml(s.source || '')} ${reason}</div>
          </div>
          <span class="badge ${available ? 'badge-live' : 'badge-error'}" style="font-size: 10px;">${available ? 'OK' : 'BLOCKED'}</span>
        </div>
      `;
    }).join('') : '<div style="color: var(--muted); text-align: center; padding: 12px;">No sensor data available</div>';
    
    // Channels list - normalize status labels for consistency
    const channels = telemetry?.channels || [];
    const channelsHtml = channels.length > 0 ? channels.map(c => {
      const accessible = c.accessible === true;
      const icon = accessible ? '✓' : '✗';
      const color = accessible ? 'var(--good)' : 'var(--error)';
      
      // Normalize channel status for display consistency
      // Map server reasons to user-friendly status labels
      let statusLabel = 'OK';
      let statusClass = 'badge-live';
      let reasonHint = '';
      
      if (!accessible) {
        const reason = (c.reason || '').toUpperCase();
        
        // Sysmon channel not found = MISSING (consistent with header "Sysmon NotFound")
        if (reason.includes('NOT_FOUND') || reason.includes('CHANNEL_NOT_FOUND')) {
          statusLabel = 'MISSING';
          statusClass = 'badge-error';
          reasonHint = c.name.includes('Sysmon') ? 'Sysmon not installed' : 'Channel not found';
        } else if (reason.includes('ACCESS_DENIED')) {
          statusLabel = 'BLOCKED';
          statusClass = 'badge-warn';
          reasonHint = 'Requires admin';
        } else if (reason.includes('DISABLED')) {
          statusLabel = 'DISABLED';
          statusClass = 'badge-stopped';
          reasonHint = 'Channel disabled in policy';
        } else if (reason.includes('PROBE_FAILED') || reason.includes('ERROR')) {
          statusLabel = 'ERROR';
          statusClass = 'badge-error';
          reasonHint = reason.includes(':') ? reason.split(':')[1].trim().substring(0, 30) : 'Query failed';
        } else {
          // Fallback: infer from Sysmon header status if this is Sysmon channel
          if (c.name.includes('Sysmon') && sysmonInstalled === false) {
            statusLabel = 'MISSING';
            statusClass = 'badge-error';
            reasonHint = 'Sysmon not installed';
          } else {
            statusLabel = 'BLOCKED';
            statusClass = 'badge-error';
            reasonHint = reason || 'Not accessible';
          }
        }
      }
      
      return `
        <div style="display: flex; align-items: center; gap: 8px; padding: 6px 0; border-bottom: 1px solid var(--border-subtle);">
          <span style="color: ${color}; font-weight: 600; width: 16px;">${icon}</span>
          <div style="flex: 1;">
            <div style="font-weight: 500; font-size: 12px;">${escapeHtml(c.name)}</div>
            ${c.supported_event_ids?.length > 0 ? `<div style="font-size: 10px; color: var(--muted);">Events: ${c.supported_event_ids.join(', ')}</div>` : ''}
            ${reasonHint && !accessible ? `<div style="font-size: 10px; color: var(--muted); font-style: italic;">${escapeHtml(reasonHint)}</div>` : ''}
          </div>
          <span class="badge ${statusClass}" style="font-size: 10px;">${statusLabel}</span>
        </div>
      `;
    }).join('') : '<div style="color: var(--muted); text-align: center; padding: 12px;">No channel data available</div>';
    
    // Recommendations with Verify steps
    const recommendations = [];
    if (isAdmin === false) {
      recommendations.push({
        icon: '🔐',
        title: 'Run as Administrator',
        description: 'Close the app and right-click locint.exe → "Run as administrator" to access Security event logs.',
        verify: 'After restart: Admin status should show "✓ Elevated" and Security Log should show "✓ Accessible".',
        severity: 'high'
      });
    }
    if (sysmonInstalled === false) {
      recommendations.push({
        icon: '📊',
        title: 'Install Sysmon',
        description: 'Download from Sysinternals and run: sysmon -accepteula -i',
        verify: 'After install: Re-run checks. Sysmon should show "✓ Installed" and Sysmon channel should show "OK".',
        severity: 'medium'
      });
    }
    if (securityLogAccessible === false && isAdmin === true) {
      recommendations.push({
        icon: '🔒',
        title: 'Check Security Log Permissions',
        description: 'Security event log may be restricted by policy. Verify local security policy allows reading Security logs.',
        verify: 'After policy change: Re-run checks. Security channel should show "OK" instead of "BLOCKED".',
        severity: 'high'
      });
    }
    
    const recommendationsHtml = recommendations.length > 0 ? recommendations.map(r => `
      <div style="padding: 10px; margin-bottom: 8px; background: ${r.severity === 'high' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(245, 158, 11, 0.1)'}; border-radius: var(--radius-sm); border-left: 3px solid ${r.severity === 'high' ? 'var(--error)' : 'var(--warn)'};">
        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
          <span style="font-size: 16px;">${r.icon}</span>
          <strong style="font-size: 12px;">${escapeHtml(r.title)}</strong>
        </div>
        <div style="font-size: 11px; color: var(--text);">${escapeHtml(r.description)}</div>
        ${r.verify ? `<div style="font-size: 10px; color: var(--accent); margin-top: 6px; padding-top: 6px; border-top: 1px solid rgba(255,255,255,0.1);">✓ <strong>Verify:</strong> ${escapeHtml(r.verify)}</div>` : ''}
      </div>
    `).join('') : '<div style="color: var(--good); text-align: center; padding: 12px;">✓ All recommendations met</div>';
    
    modal.innerHTML = `
      <div style="background: var(--panel); border-radius: var(--radius-md); max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto; box-shadow: 0 8px 32px rgba(0,0,0,0.4);">
        <!-- Header -->
        <div style="padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; background: var(--panel); z-index: 1;">
          <div>
            <div style="font-size: 16px; font-weight: 600;">🛡️ System Readiness</div>
            <div style="font-size: 12px; color: var(--muted);">Telemetry access and sensor status</div>
          </div>
          <div style="display: flex; align-items: center; gap: 12px;">
            <div style="text-align: right;" title="${escapeHtml(readiness.tooltip)}">
              <div style="font-size: 24px; font-weight: 600; color: ${statusColor};">${score}%</div>
              <div style="font-size: 10px; color: var(--muted);">${statusLabel}</div>
            </div>
            <button id="btnCloseReadinessModal" style="background: transparent; border: none; font-size: 24px; cursor: pointer; color: var(--muted); padding: 4px;">✕</button>
          </div>
        </div>
        
        <!-- Summary - annotate required vs optional -->
        <div style="padding: 16px 20px; background: var(--panel2); border-bottom: 1px solid var(--border);">
          <div style="display: flex; gap: 20px; flex-wrap: wrap;">
            <div style="flex: 1; min-width: 100px;">
              <div style="font-size: 11px; color: var(--muted); text-transform: uppercase; margin-bottom: 4px;">Admin <span style="font-size: 9px; color: var(--accent);">(required)</span></div>
              <div style="font-size: 14px; font-weight: 500; color: ${isAdmin ? 'var(--good)' : 'var(--error)'};">
                ${isAdmin === true ? '✓ Elevated' : isAdmin === false ? '✗ Not Admin' : '— Unknown'}
              </div>
            </div>
            <div style="flex: 1; min-width: 100px;">
              <div style="font-size: 11px; color: var(--muted); text-transform: uppercase; margin-bottom: 4px;">Sysmon <span style="font-size: 9px; color: var(--muted);">(optional)</span></div>
              <div style="font-size: 14px; font-weight: 500; color: ${sysmonInstalled ? 'var(--good)' : 'var(--warn)'};">
                ${sysmonInstalled === true ? '✓ Installed' : sysmonInstalled === false ? '✗ Not Found' : '— Unknown'}
              </div>
            </div>
            <div style="flex: 1; min-width: 100px;">
              <div style="font-size: 11px; color: var(--muted); text-transform: uppercase; margin-bottom: 4px;">Security Log <span style="font-size: 9px; color: var(--accent);">(required)</span></div>
              <div style="font-size: 14px; font-weight: 500; color: ${securityLogAccessible ? 'var(--good)' : 'var(--error)'};">
                ${securityLogAccessible === true ? '✓ Accessible' : securityLogAccessible === false ? '✗ Blocked' : '— Unknown'}
              </div>
            </div>
          </div>
        </div>
        
        <!-- Recommendations -->
        ${recommendations.length > 0 ? `
          <div style="padding: 16px 20px; border-bottom: 1px solid var(--border);">
            <div style="font-size: 12px; font-weight: 600; margin-bottom: 12px; color: var(--muted); text-transform: uppercase;">Recommendations</div>
            ${recommendationsHtml}
          </div>
        ` : ''}
        
        <!-- Sensors -->
        <div style="padding: 16px 20px; border-bottom: 1px solid var(--border);">
          <div style="font-size: 12px; font-weight: 600; margin-bottom: 12px; color: var(--muted); text-transform: uppercase;">
            Sensors (${telemetry?.sensors_available ?? 0}/${telemetry?.sensors_total ?? 0})
          </div>
          ${sensorsHtml}
        </div>
        
        <!-- Channels -->
        <div style="padding: 16px 20px;">
          <div style="font-size: 12px; font-weight: 600; margin-bottom: 12px; color: var(--muted); text-transform: uppercase;">
            Event Log Channels (${telemetry?.channels_accessible ?? 0}/${telemetry?.channels_total ?? 0})
          </div>
          ${channelsHtml}
        </div>
        
        <!-- Footer -->
        <div style="padding: 12px 20px; background: var(--panel2); border-top: 1px solid var(--border); text-align: center;">
          <button id="btnReadinessRerun" class="btn-secondary" style="padding: 8px 16px;">
            🔄 Re-run Checks
          </button>
        </div>
      </div>
    `;
    
    // Show modal with animation
    requestAnimationFrame(() => {
      modal.style.opacity = '1';
    });
    
    // Bind close handlers
    modal.querySelector('#btnCloseReadinessModal').onclick = closeReadinessModal;
    modal.onclick = (e) => {
      if (e.target === modal) closeReadinessModal();
    };
    
    // Bind re-run button
    modal.querySelector('#btnReadinessRerun').onclick = async () => {
      const btn = modal.querySelector('#btnReadinessRerun');
      btn.disabled = true;
      btn.textContent = '⏳ Checking...';
      try {
        await checkReadiness(true);
        // Re-render modal with new data
        openReadinessModal();
      } finally {
        btn.disabled = false;
        btn.textContent = '🔄 Re-run Checks';
      }
    };
    
    // Close on escape
    const escHandler = (e) => {
      if (e.key === 'Escape') {
        closeReadinessModal();
        document.removeEventListener('keydown', escHandler);
      }
    };
    document.addEventListener('keydown', escHandler);
  }
  
  // Expose readiness panel opener globally for onclick handlers
  window.showReadinessPanel = openReadinessModal;
  
  /**
   * Pivot to Facts tab with a filter for the specified category
   * @param {string} category - Category like 'services', 'registry', etc.
   */
  window.pivotToFacts = function(category) {
    // Map discovery categories to fact_type filters
    const factTypeMap = {
      'services': 'persistence_service',
      'scheduled_tasks': 'persistence_task',
      'logs_cleared': 'log_clear',
      'registry': 'registry_mod',
      'process_execution': 'Exec',
      'network_connections': 'NetConnect',
      'powershell': 'powershell_exec'
    };
    
    const factType = factTypeMap[category] || category;
    
    // Switch to Facts tab
    switchRunTab('facts');
    
    // Apply filter to Fact Inspector
    setTimeout(() => {
      const factTypeFilter = document.getElementById('factTypeFilter');
      if (factTypeFilter) {
        factTypeFilter.value = factType;
        factInspectorState.filters.fact_type = factType;
        factInspectorState.pagination.offset = 0;
        loadFactInspectorData();
        
        // Scroll to inspector section
        const inspectorSection = document.getElementById('factInspectorSection');
        if (inspectorSection) {
          inspectorSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }
    }, 100);
    
    console.log('[Discovery] Pivoted to facts with filter:', factType);
  };
  
  /**
   * View evidence for a specific fact ID
   * @param {string} factId - The fact_id to view details for
   */
  window.viewEvidence = function(factId) {
    if (!factId) return;
    
    // Switch to Facts tab and load the specific fact
    switchRunTab('facts');
    
    setTimeout(async () => {
      // Try to find the fact in current data
      let fact = factInspectorState.facts.find(f => f.fact_id === factId);
      
      if (!fact && state.selectedRunId) {
        // Fetch the specific fact
        try {
          const resp = await fetch(`/api/runs/${state.selectedRunId}/facts?search=${factId}&limit=1`);
          if (resp.ok) {
            const json = await resp.json();
            if (json.data?.facts?.length > 0) {
              fact = json.data.facts[0];
            }
          }
        } catch (err) {
          console.warn('[viewEvidence] Failed to fetch fact:', err);
        }
      }
      
      if (fact) {
        showFactDetailDrawer(fact);
      }
    }, 100);
    
    console.log('[Discovery] View evidence for fact:', factId);
  };

  /**
   * Close the System Readiness modal
   */
  function closeReadinessModal() {
    const modal = document.getElementById('readinessModal');
    if (modal) {
      modal.style.opacity = '0';
      setTimeout(() => {
        modal.remove();
      }, 200);
    }
  }

  function updateRunningUI() {
    // Buttons
    if (els.btnStartRun) els.btnStartRun.classList.add('hidden');
    if (els.btnStopRun) {
      els.btnStopRun.classList.remove('hidden');
      els.btnStopRun.disabled = false;
      els.btnStopRun.textContent = '⏹️ Stop Run';
    }
    
    // Status badge
    if (els.runStatusBadge) {
      els.runStatusBadge.className = 'badge badge-running pulse';
      els.runStatusBadge.textContent = 'Running';
    }
    
    // Status text
    if (els.runStatus) {
      els.runStatus.textContent = 'Capturing';
    }
    
    // Elapsed time from backend
    if (els.runDuration) {
      els.runDuration.textContent = formatDuration(state.elapsedSeconds);
    }
    
    // Mission hint
    if (els.missionHint) {
      els.missionHint.innerHTML = `🔴 <span style="color: var(--accent);">Capture in progress</span> · Click Stop to finalize`;
    }
    
    // Show noise values (remove placeholder opacity)
    setNoiseOpacity(1);
  }

  function updateStoppedUI() {
    // Buttons
    if (els.btnStopRun) els.btnStopRun.classList.add('hidden');
    if (els.btnStartRun) {
      els.btnStartRun.classList.remove('hidden');
      // Only enable if not in imported mode and online
      els.btnStartRun.disabled = state.importedMode || !state.serverOnline;
      els.btnStartRun.textContent = '▶️ Start Run';
    }
    
    // Status badge
    if (els.runStatusBadge) {
      els.runStatusBadge.className = 'badge badge-stopped';
      els.runStatusBadge.textContent = 'Stopped';
    }
    
    // Status text
    if (els.runStatus) {
      els.runStatus.textContent = 'Idle';
    }
    
    // Elapsed time
    if (els.runDuration) {
      els.runDuration.textContent = '—';
    }
    
    // Mission hint (unless in imported mode)
    if (els.missionHint && !state.importedMode) {
      els.missionHint.innerHTML = '🔒 Runs locally · Click Start Run to begin capture';
    }
    
    // Show noise placeholder state
    if (els.noiseHint) els.noiseHint.classList.remove('hidden');
    setNoiseOpacity(0.4);
  }

  function setNoiseOpacity(opacity) {
    [els.signalsPerMin, els.topPlaybook, els.topEntity, els.dedupeCount].forEach(el => {
      if (el) el.style.opacity = String(opacity);
    });
    if (opacity === 1 && els.noiseHint) {
      els.noiseHint.classList.add('hidden');
    }
  }

  function updateCountersUI() {
    // Use formatValue which shows "—" for null/undefined, "0" for 0
    if (els.counterEvents) els.counterEvents.textContent = formatValue(state.counters.events);
    if (els.counterSegments) els.counterSegments.textContent = formatValue(state.counters.segments);
    if (els.counterFacts) els.counterFacts.textContent = formatValue(state.counters.facts);
    if (els.counterSignals) els.counterSignals.textContent = formatValue(state.counters.signals);
  }

  function renderRunsList() {
    if (state.runs.length === 0) {
      if (els.runsEmpty) els.runsEmpty.classList.remove('hidden');
      if (els.runsContent) els.runsContent.classList.add('hidden');
      return;
    }
    
    if (els.runsEmpty) els.runsEmpty.classList.add('hidden');
    if (els.runsContent) {
      els.runsContent.classList.remove('hidden');
      els.runsContent.style.display = 'grid';
    }
    
    if (!els.runsList) return;
    
    els.runsList.innerHTML = state.runs.map(run => {
      const id = run.run_id || run.id || 'unknown';
      const time = run.started_at || run.start_time || run.timestamp || run.created_at;
      const isActive = id === state.selectedRunId;
      
      // Build display name: use custom name if set, otherwise derive from profile/host/time
      const customName = run.name;
      const profile = run.profile || 'extended';
      const host = run.hosts?.[0] || getHostnameFromRun(run) || 'local';
      const timeStr = time ? formatTimestampShort(time) : '';
      const defaultName = `${capitalize(profile)} • ${host} • ${timeStr}`;
      const displayName = customName || defaultName;
      
      // Only show source badge if backend provides it
      const source = run.source || run.origin || null;
      const sourceBadge = source ? 
        `<span class="badge badge-${source === 'imported' ? 'running' : 'live'}" style="font-size: 9px; padding: 2px 6px; margin-left: 8px;">${source.toUpperCase()}</span>` : 
        '';
      
      return `
        <div class="run-item ${isActive ? 'active' : ''}" data-run-id="${id}">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px;">
            <div style="display: flex; align-items: center; gap: 6px; flex: 1; min-width: 0;">
              <span class="run-display-name" data-run-id="${id}" style="font-size: 13px; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(displayName)}">${escapeHtml(displayName)}</span>
              ${sourceBadge}
              <button class="btn-rename-run" data-run-id="${id}" title="Rename run" style="background: none; border: none; color: var(--muted); cursor: pointer; padding: 2px; font-size: 12px; opacity: 0.5; flex-shrink: 0;" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=0.5">✏️</button>
            </div>
            <button class="btn-delete-run" data-run-id="${id}" title="Delete this run" style="background: none; border: none; color: var(--muted); cursor: pointer; padding: 2px 6px; font-size: 14px; opacity: 0.5; flex-shrink: 0;" onmouseover="this.style.opacity=1;this.style.color='var(--danger)'" onmouseout="this.style.opacity=0.5;this.style.color='var(--muted)'">&times;</button>
          </div>
          <div style="font-size: 11px; color: var(--muted); display: flex; gap: 8px;">
            <span>${formatTimestamp(time)}</span>
            <span>•</span>
            <span>${run.signal_count ?? run.signals_fired ?? 0} signals</span>
          </div>
        </div>
      `;
    }).join('');
    
    // Bind click events for selecting runs
    els.runsList.querySelectorAll('.run-item').forEach(el => {
      el.addEventListener('click', (e) => {
        // Don't select if clicking delete or rename button
        if (e.target.classList.contains('btn-delete-run') || e.target.classList.contains('btn-rename-run')) return;
        selectRun(el.dataset.runId);
      });
    });
    
    // Bind rename button events
    els.runsList.querySelectorAll('.btn-rename-run').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const runId = btn.dataset.runId;
        showRunRenameInput(runId);
      });
    });
    
    // Bind delete button events
    els.runsList.querySelectorAll('.btn-delete-run').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const runId = btn.dataset.runId;
        if (!confirm(`Delete run "${runId}"? This cannot be undone.`)) return;
        
        try {
          const resp = await fetch(`/api/runs/${encodeURIComponent(runId)}/delete`, { method: 'POST' });
          const data = await resp.json();
          if (data.success || data.deleted) {
            // Remove from state and re-render
            state.runs = state.runs.filter(r => (r.run_id || r.id) !== runId);
            if (state.selectedRunId === runId) {
              state.selectedRunId = null;
              state.selectedRun = null;
            }
            renderRunsList();
            // If we deleted the selected run, select another
            if (!state.selectedRunId && state.runs.length > 0) {
              selectRun(state.runs[0].run_id || state.runs[0].id);
            }
          } else {
            alert(`Failed to delete run: ${data.error || 'Unknown error'}`);
          }
        } catch (err) {
          alert(`Error deleting run: ${err.message}`);
        }
      });
    });
    
    // Auto-select first (latest) run if none selected
    if (!state.selectedRunId && state.runs.length > 0) {
      const firstRun = state.runs[0];
      selectRun(firstRun.run_id || firstRun.id);
    }
  }
  
  /**
   * Show inline rename input for a run
   */
  function showRunRenameInput(runId) {
    const run = state.runs.find(r => (r.run_id || r.id) === runId);
    if (!run) return;
    
    const nameSpan = document.querySelector(`.run-display-name[data-run-id="${runId}"]`);
    if (!nameSpan) return;
    
    const currentName = run.name || '';
    const profile = run.profile || 'extended';
    const host = run.hosts?.[0] || getHostnameFromRun(run) || 'local';
    const time = run.started_at || run.start_time;
    const timeStr = time ? formatTimestampShort(time) : '';
    const placeholder = `${capitalize(profile)} • ${host} • ${timeStr}`;
    
    // Create input element
    const input = document.createElement('input');
    input.type = 'text';
    input.value = currentName;
    input.placeholder = placeholder;
    input.style.cssText = 'width: 100%; padding: 2px 6px; font-size: 13px; font-weight: 500; background: var(--panel); border: 1px solid var(--accent); border-radius: 3px; color: var(--text);';
    
    // Replace span with input
    const originalContent = nameSpan.innerHTML;
    nameSpan.innerHTML = '';
    nameSpan.appendChild(input);
    input.focus();
    input.select();
    
    // Handle save
    const saveRename = async () => {
      const newName = input.value.trim() || null;
      try {
        const resp = await fetch(`/api/runs/${encodeURIComponent(runId)}/rename`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: newName })
        });
        const data = await resp.json();
        if (data.success) {
          // Update local state
          run.name = newName;
          renderRunsList();
          // Update detail title if this run is selected
          if (state.selectedRunId === runId) {
            updateRunDetailTitle(run);
          }
        } else {
          alert(`Failed to rename: ${data.error}`);
          nameSpan.innerHTML = originalContent;
        }
      } catch (err) {
        alert(`Error renaming: ${err.message}`);
        nameSpan.innerHTML = originalContent;
      }
    };
    
    input.addEventListener('blur', saveRename);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        input.blur();
      } else if (e.key === 'Escape') {
        nameSpan.innerHTML = originalContent;
      }
    });
  }
  
  /**
   * Update run detail title with display name
   */
  function updateRunDetailTitle(run) {
    if (!els.runDetailTitle) return;
    const runId = run.run_id || run.id;
    const customName = run.name;
    const profile = run.profile || 'extended';
    const host = run.hosts?.[0] || getHostnameFromRun(run) || 'local';
    const time = run.started_at || run.start_time;
    const timeStr = time ? formatTimestampShort(time) : '';
    const defaultName = `${capitalize(profile)} • ${host} • ${timeStr}`;
    const displayName = customName || defaultName;
    els.runDetailTitle.textContent = displayName;
  }
  
  /**
   * Extract hostname from run data if available
   */
  function getHostnameFromRun(run) {
    if (run.hosts?.length > 0) return run.hosts[0];
    if (run.hostname) return run.hostname;
    if (run.machine_name) return run.machine_name;
    // Try to get from OS environment (only works locally)
    try { return (typeof os !== 'undefined') ? os.hostname() : null; } catch { return null; }
  }
  
  /**
   * Get local hostname from various sources
   */
  function getLocalHostname() {
    // Check if we've cached it
    if (state.localHostname) return state.localHostname;
    
    // Try to get from mission capabilities if loaded
    if (state.missionCapabilities?.hostname) {
      state.localHostname = state.missionCapabilities.hostname;
      return state.localHostname;
    }
    
    // Try environment variable approach
    try {
      if (typeof process !== 'undefined' && process.env?.COMPUTERNAME) {
        state.localHostname = process.env.COMPUTERNAME;
        return state.localHostname;
      }
    } catch { }
    
    return null;
  }
  
  /**
   * Capitalize first letter
   */
  function capitalize(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
  }
  
  /**
   * Format timestamp to short form (for run names)
   */
  function formatTimestampShort(ts) {
    if (!ts) return '';
    try {
      const d = new Date(ts);
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch { return ''; }
  }

  /**
   * Select a run and load its data
   */
  async function selectRun(runId) {
    // Debug: Log scope transition
    if (DEBUG_MODE) {
      console.log(`🔵 [SCOPE] Entering RUN scope: ${runId}`);
    }
    
    state.selectedRunId = runId;
    state.selectedRun = state.runs.find(r => (r.run_id || r.id) === runId);
    state.signals = [];
    state.runCoverage = null;  // Reset coverage when switching runs
    state.selectedSignalId = null;
    state.selectedSignal = null;
    state.signalExplanation = null;
    state.signalNarrative = null;
    // Reset explore state when switching runs
    state.exploreEntities = null;
    state.exploreEntitiesRunId = null;
    state.exploreSelectedEntity = null;
    state.explorePivotResult = null;
    
    if (!state.selectedRun) return;
    
    const run = state.selectedRun;
    
    // Update list active state
    if (els.runsList) {
      els.runsList.querySelectorAll('.run-item').forEach(el => {
        el.classList.toggle('active', el.dataset.runId === runId);
      });
    }
    
    // Show detail panel
    if (els.runDetailEmpty) els.runDetailEmpty.classList.add('hidden');
    if (els.runDetail) els.runDetail.classList.remove('hidden');
    
    // Update title with display name
    updateRunDetailTitle(run);
    if (els.runDetailTime) els.runDetailTime.textContent = formatTimestamp(run.started_at || run.start_time || run.earliest_ts);
    
    // Show run metrics in Overview tab
    if (els.detailEvents) els.detailEvents.textContent = formatValue(run.events_total ?? run.events ?? run.event_count);
    if (els.detailSegments) els.detailSegments.textContent = formatValue(run.segments_count ?? run.segments ?? run.segment_count);
    if (els.detailFacts) els.detailFacts.textContent = formatValue(run.facts_extracted ?? run.facts ?? run.fact_count);
    if (els.detailSignals) els.detailSignals.textContent = formatValue(run.signal_count ?? run.signals_fired ?? run.signals);
    
    // Overview: Profile, Duration, Hosts (Mode removed)
    if (els.detailProfile) els.detailProfile.textContent = run.profile || 'extended';
    if (els.detailDuration) {
      // Compute duration from timestamps
      const startMs = run.earliest_ts || (run.started_at ? new Date(run.started_at).getTime() : 0);
      const endMs = run.latest_ts || (run.stopped_at ? new Date(run.stopped_at).getTime() : 0);
      const durationMs = endMs > startMs ? endMs - startMs : 0;
      if (durationMs > 0) {
        els.detailDuration.textContent = formatDuration(durationMs / 1000);
      } else if (run.stopped_at && run.started_at) {
        // Try ISO timestamps directly
        const start = new Date(run.started_at).getTime();
        const end = new Date(run.stopped_at).getTime();
        const dur = end > start ? end - start : 0;
        els.detailDuration.textContent = dur > 0 ? formatDuration(dur / 1000) : '—';
      } else {
        els.detailDuration.textContent = '—';
      }
    }
    if (els.detailHosts) {
      const host = run.hosts?.[0] || getHostnameFromRun(run) || getLocalHostname() || 'localhost';
      els.detailHosts.textContent = host;
    }
    
    // Data sources - derive from signal types if available
    updateDataSourcesUI(run);
    
    // Reset to Overview tab
    switchRunTab('overview');
    
    // Fetch signals for this run in background
    loadSignalsForRun(run);
    
    // Fetch coverage data for this run in background
    loadCoverageForRun(run);
    
    // Fetch system state summary for this run (Part A)
    loadStateForRun(run);
    
    // Fetch next steps guidance for this run
    loadNextStepsForRun(run);
    
    // Fetch discovery summary for General preset runs
    loadDiscoverySummaryForRun(run);
  }

  /**
   * Load signals for selected run
   */
  async function loadSignalsForRun(run) {
    state.signals = await fetchSignalsForRun(run);
    
    // Update findings count in tab if visible
    if (state.currentRunTab === 'findings') {
      renderFindingsTab();
    }
    
    // Update timeline if visible
    if (state.currentRunTab === 'timeline') {
      renderTimelineTab();
    }
  }

  /**
   * Load coverage data for selected run
   */
  async function loadCoverageForRun(run) {
    const runId = run.run_id || run.id;
    state.runCoverage = null;
    
    try {
      const resp = await fetch(`/api/runs/${runId}/coverage`);
      if (resp.status === 404) {
        state.capabilities.runCoverage = false;
        state.runCoverage = { available: false, reason_code: 'ENDPOINT_NOT_FOUND', message: 'Coverage endpoint not available' };
        if (state.currentRunTab === 'facts') renderFactsTab();
        return;
      }
      if (!resp.ok) {
        console.warn('[Coverage] Failed to load coverage:', resp.status);
        state.runCoverage = { available: false, reason_code: 'HTTP_ERROR', message: `HTTP ${resp.status}` };
        if (state.currentRunTab === 'facts') renderFactsTab();
        return;
      }
      
      state.capabilities.runCoverage = true;
      const json = await resp.json();
      // Extract data from wrapper: {success: true, data: {...}}
      state.runCoverage = json.data || json;
    } catch (err) {
      console.warn('[Coverage] Error loading coverage:', err);
      state.runCoverage = { available: false, reason_code: 'NETWORK_ERROR', message: 'Network error loading coverage' };
    }
    
    // Update facts tab if visible
    if (state.currentRunTab === 'facts') {
      renderFactsTab();
    }
  }

  /**
   * Load system state summary for selected run (Part A)
   * Always shows something - never blank
   */
  async function loadStateForRun(run) {
    const runId = run.run_id || run.id;
    
    // Hide panel initially
    if (els.runStatePanel) els.runStatePanel.classList.add('hidden');
    
    try {
      const resp = await fetch(`/api/runs/${runId}/state`);
      if (!resp.ok) {
        console.warn('[State] Failed to load state:', resp.status);
        // Show minimal state info from run data even if endpoint fails
        renderStateFromRun(run);
        return;
      }
      
      const stateData = await resp.json();
      renderStatePanel(stateData);
    } catch (err) {
      console.warn('[State] Error loading state:', err);
      // Fallback: show minimal state from run data
      renderStateFromRun(run);
    }
  }

  /**
   * Render State panel from /api/runs/:id/state endpoint data
   * Handles both full state response and minimal response from run_state_handler
   */
  function renderStatePanel(rawResp) {
    if (!els.runStatePanel) return;
    
    // Extract data from wrapper if present
    const data = rawResp?.data || rawResp;
    
    // Always show the panel
    els.runStatePanel.classList.remove('hidden');
    
    // Telemetry status badge - map overall status to our semantic system
    if (els.stateTelemetryBadge) {
      const status = data.telemetry_status || (data.available ? 'full' : 'unknown');
      // Map telemetry status to our semantic badges
      const statusMap = {
        'full': 'configured',      // All sensors accessible
        'partial': 'partial',      // Some sensors blocked
        'limited': 'partial',      // Limited coverage
        'blocked': 'blocked',      // No telemetry available
        'unknown': 'configured',   // Unknown state
      };
      const mappedStatus = statusMap[status] || 'configured';
      const label = status.charAt(0).toUpperCase() + status.slice(1);
      els.stateTelemetryBadge.innerHTML = getStatusBadge(mappedStatus, label, null, { small: false });
      els.stateTelemetryBadge.className = ''; // Clear class since using innerHTML
    }
    
    // Sensors list - use semantic badges
    // Derive from state data or compute from capabilities/telemetry
    if (els.stateSensorsList) {
      let sensors = data.sensors || [];
      
      // If no sensors in response, derive from run capabilities or default set
      if (sensors.length === 0) {
        sensors = deriveSensorsFromRun(data);
      }
      
      if (sensors.length > 0) {
        els.stateSensorsList.innerHTML = sensors.map(s => {
          // Map sensor status: available → configured, unavailable → blocked/missing
          const statusMap = {
            'available': 'configured',
            'active': 'active',
            'configured': 'configured',
            'ok': 'configured',
            'OK': 'configured',
            'unavailable': 'blocked',
            'missing': 'missing',
            'blocked': 'blocked',
            'BLOCKED': 'blocked',
            'MISSING': 'missing',
            'ERROR': 'blocked',
          };
          const mappedStatus = statusMap[s.status] || 'configured';
          return getSensorStatusBadge({
            status: mappedStatus,
            status_label: s.name || s.label,
            message: s.reason || s.message
          });
        }).join(' ');
      } else {
        // No sensors data and couldn't derive - show note
        els.stateSensorsList.innerHTML = '<span style="font-size: 11px; color: var(--muted);">No sensor status available for this run</span>';
      }
    }
    
    // Facts and signals counts - handle both field names (facts_total and facts_extracted)
    const factsCount = data.facts_total ?? data.facts_extracted ?? '—';
    const signalsCount = data.signals_count ?? '—';
    if (els.stateFactsCount) els.stateFactsCount.textContent = factsCount;
    if (els.stateSignalsCount) els.stateSignalsCount.textContent = signalsCount;
    
    // Top process - MUST show a value or explicit reason (never just "—")
    // Uses enhanced diagnostics from backend including has_exec_facts
    if (els.stateTopProcess) {
      const processes = data.top_entities?.processes || [];
      const hasFacts = (data.facts_total ?? data.facts_extracted ?? 0) > 0;
      const hasExecFacts = data.top_entities?.has_exec_facts || false;
      const execFactCount = data.top_entities?.exec_fact_count || 0;
      
      if (processes.length > 0 && processes[0].entity_key) {
        // We have top process data - show it
        const topProc = processes[0].entity_key;
        const factCount = processes[0].fact_count;
        // Truncate long process paths for display
        const displayProc = topProc.length > 50 ? '...' + topProc.slice(-47) : topProc;
        els.stateTopProcess.innerHTML = `<span title="${escapeHtml(topProc)}">${escapeHtml(displayProc)}</span>`;
        if (factCount) {
          els.stateTopProcess.innerHTML += ` <span style="color: var(--muted); font-size: 10px;">(${factCount} facts)</span>`;
        }
      } else if (!hasFacts) {
        // No facts extracted at all
        els.stateTopProcess.innerHTML = `<span style="color: var(--muted); font-size: 11px;">No facts extracted in this run</span>`;
      } else if (hasExecFacts && execFactCount > 0) {
        // Exec facts exist but no proc_key aggregation - show count with explanation
        els.stateTopProcess.innerHTML = `<span style="color: var(--muted); font-size: 11px;">${execFactCount} process facts (no entity key extraction)</span>`;
      } else {
        // Facts exist but no process/exec facts specifically
        els.stateTopProcess.innerHTML = `<span style="color: var(--muted); font-size: 11px;">No process telemetry (check Sysmon)</span>`;
      }
    }
    
    // Top entities section
    if (els.stateEntitiesSection && els.stateEntitiesList) {
      const entities = data.top_entities || {};
      const allEntities = [
        ...(entities.processes || []).slice(0, 3).map(e => ({ type: 'process', ...e })),
        ...(entities.users || []).slice(0, 2).map(e => ({ type: 'user', ...e })),
        ...(entities.network || []).slice(0, 2).map(e => ({ type: 'network', ...e }))
      ];
      
      if (allEntities.length > 0) {
        els.stateEntitiesSection.classList.remove('hidden');
        els.stateEntitiesList.innerHTML = allEntities.map(e => {
          const icon = { process: '⚙️', user: '👤', network: '🌐', host: '💻' }[e.type] || '📦';
          return `<span style="padding: 2px 6px; background: var(--panel); border-radius: 2px; font-family: monospace;">
            ${icon} ${e.entity_key} <span style="color: var(--muted);">(${e.fact_count})</span>
          </span>`;
        }).join('');
      } else {
        els.stateEntitiesSection.classList.add('hidden');
      }
    }
    
    // Notes section
    if (els.stateNotesSection && els.stateNotesList && data.notes?.length > 0) {
      els.stateNotesSection.classList.remove('hidden');
      els.stateNotesList.innerHTML = data.notes.map(n => `<div style="margin-bottom: 4px;">⚠️ ${n}</div>`).join('');
    } else if (els.stateNotesSection) {
      els.stateNotesSection.classList.add('hidden');
    }
  }

  /**
   * Derive sensor status from run data when not explicitly provided
   * Uses telemetry_status, capabilities, or signal types to infer sensor states
   */
  function deriveSensorsFromRun(data) {
    const sensors = [];
    
    // Core sensors we expect - mark based on telemetry status and signal presence
    const telemetryStatus = data.telemetry_status || 'unknown';
    const hasSignals = (data.signals_count ?? 0) > 0;
    const hasFacts = (data.facts_total ?? data.facts_extracted ?? 0) > 0;
    
    // ETW Security - infer from login/auth signals or assume if signals fired
    if (hasSignals || hasFacts) {
      sensors.push({ name: 'Security', status: 'ok', reason: 'Events collected' });
    }
    
    // Sysmon - check capabilities or signal types  
    const capabilities = data.capabilities || state.missionCapabilities || {};
    const sysmonCapable = capabilities.sysmon_available ?? capabilities.has_sysmon;
    if (sysmonCapable === true) {
      sensors.push({ name: 'Sysmon', status: 'ok', reason: 'Process telemetry available' });
    } else if (sysmonCapable === false) {
      sensors.push({ name: 'Sysmon', status: 'missing', reason: 'Not installed' });
    }
    
    // PowerShell - check if PS events were seen
    const psCapable = capabilities.powershell_logging ?? capabilities.has_powershell;
    if (psCapable === true) {
      sensors.push({ name: 'PowerShell', status: 'ok', reason: 'ScriptBlock logging enabled' });
    } else if (psCapable === false) {
      sensors.push({ name: 'PowerShell', status: 'missing', reason: 'Logging not enabled' });
    }
    
    // If telemetry_status indicates issues, mark sensors accordingly
    if (telemetryStatus === 'blocked' || telemetryStatus === 'limited') {
      if (sensors.length === 0) {
        sensors.push({ name: 'ETW', status: 'blocked', reason: 'No telemetry received' });
      }
    }
    
    return sensors;
  }

  /**
   * Fallback: render minimal state panel from run data when endpoint unavailable
   */
  function renderStateFromRun(run) {
    if (!els.runStatePanel) return;
    
    els.runStatePanel.classList.remove('hidden');
    
    if (els.stateTelemetryBadge) {
      els.stateTelemetryBadge.innerHTML = getStatusBadge('configured', 'Unknown', 'State endpoint unavailable');
      els.stateTelemetryBadge.className = '';
    }
    
    if (els.stateSensorsList) {
      // Try to derive sensors even for fallback
      const sensors = deriveSensorsFromRun({ facts_total: run.facts_extracted ?? run.facts, signals_count: run.signal_count ?? run.signals });
      if (sensors.length > 0) {
        els.stateSensorsList.innerHTML = sensors.map(s => getSensorStatusBadge({
          status: s.status === 'ok' ? 'configured' : s.status,
          status_label: s.name,
          message: s.reason
        })).join(' ');
      } else {
        els.stateSensorsList.innerHTML = '<span style="font-size: 11px; color: var(--muted);">State endpoint unavailable</span>';
      }
    }
    
    if (els.stateFactsCount) els.stateFactsCount.textContent = run.facts_extracted ?? run.facts ?? '—';
    if (els.stateSignalsCount) els.stateSignalsCount.textContent = run.signal_count ?? run.signals ?? '—';
    
    // Top process - show explicit reason when unavailable
    if (els.stateTopProcess) {
      els.stateTopProcess.innerHTML = '<span style="color: var(--muted); font-size: 11px;">State endpoint unavailable</span>';
    }
    
    if (els.stateEntitiesSection) els.stateEntitiesSection.classList.add('hidden');
    if (els.stateNotesSection) els.stateNotesSection.classList.add('hidden');
  }

  // ============================================================================
  // Next Steps Workflow Guidance
  // ============================================================================

  /**
   * Load next steps guidance for selected run
   */
  async function loadNextStepsForRun(run) {
    const runId = run.run_id || run.id;
    
    // Hide panel initially
    if (els.runNextStepsPanel) els.runNextStepsPanel.classList.add('hidden');
    
    try {
      const resp = await fetch(`/api/runs/${runId}/next_steps`);
      if (!resp.ok) {
        console.warn('[NextSteps] Failed to load:', resp.status);
        return;
      }
      
      const json = await resp.json();
      if (json.success && json.data) {
        renderNextStepsPanel(json.data);
      }
    } catch (err) {
      console.warn('[NextSteps] Error loading next steps:', err);
    }
  }

  /**
   * Load Discovery Summary for General preset runs
   * Shows observed changes (services, logs, tasks) and upgrade CTAs
   */
  async function loadDiscoverySummaryForRun(run) {
    const runId = run.run_id || run.id;
    
    // Hide panel initially
    if (els.discoverySummaryPanel) els.discoverySummaryPanel.classList.add('hidden');
    
    // Check if this is a General preset run (or if we should show for all runs)
    const profile = run.profile || state.playbookSelection?.preset || 'general';
    
    try {
      const resp = await fetch(`/api/runs/${runId}/discovery_summary`);
      if (!resp.ok) {
        console.warn('[DiscoverySummary] Failed to load:', resp.status);
        return;
      }
      
      const json = await resp.json();
      if (json.success && json.data?.available) {
        renderDiscoverySummary(json.data, profile);
      }
    } catch (err) {
      console.warn('[DiscoverySummary] Error loading:', err);
    }
  }

  /**
   * Render Discovery Summary with three panels:
   * 1. What Changed - grouped changes with evidence pointers
   * 2. Milestones Observed - observed/not observed/not observable
   * 3. Visibility Limits - what's blocked and unlock CTAs
   */
  function renderDiscoverySummary(data, profile) {
    if (!els.discoverySummaryPanel) return;
    
    const stats = data.stats || {};
    const totalChanges = stats.total_changes || 0;
    const whatChanged = data.what_changed || {};
    const milestones = data.milestones || {};
    const visibilityLimits = data.visibility_limits || [];
    const driftSummary = data.drift_summary || { has_drift: false, items: [] };
    
    // Update total count badge
    if (els.discoverySummaryCount) {
      els.discoverySummaryCount.textContent = totalChanges;
    }
    
    // ===== DRIFT BANNER (Consolidated mismatch notification) =====
    // Show when observed telemetry exists but capability says unavailable
    const driftBannerEl = document.getElementById('discoveryDriftBanner');
    if (driftBannerEl) {
      if (driftSummary.has_drift && driftSummary.items?.length > 0) {
        const driftSurfaces = driftSummary.items.map(d => d.surface).join(', ');
        driftBannerEl.innerHTML = `
          <div style="display: flex; align-items: flex-start; gap: 10px; padding: 10px 12px; background: rgba(59, 130, 246, 0.1); border: 1px solid var(--accent); border-radius: var(--radius-sm); margin-bottom: 12px;">
            <span style="font-size: 16px; flex-shrink: 0;">👁️</span>
            <div style="flex: 1;">
              <div style="font-size: 12px; font-weight: 600; color: var(--accent);">Observed Despite Configuration Mismatch</div>
              <div style="font-size: 11px; color: var(--text); margin-top: 4px;">${escapeHtml(driftSummary.banner_message || 'Telemetry was observed for surfaces that configuration reports as unavailable.')}</div>
              <div style="font-size: 10px; color: var(--muted); margin-top: 4px;">Affected: ${escapeHtml(driftSurfaces)}</div>
            </div>
            <span style="font-size: 9px; background: var(--accent); color: white; padding: 2px 6px; border-radius: 10px; white-space: nowrap;">Verify Config</span>
          </div>
        `;
        driftBannerEl.classList.remove('hidden');
      } else {
        driftBannerEl.innerHTML = '';
        driftBannerEl.classList.add('hidden');
      }
    }
    
    // Build drift lookup for badges
    const driftLookup = {};
    (driftSummary.items || []).forEach(d => {
      const key = d.surface.toLowerCase().replace(/\s+/g, '_');
      driftLookup[key] = d;
    });
    
    // ===== PANEL 1: WHAT CHANGED =====
    const changeGridEl = document.getElementById('discoveryChangeGrid');
    if (changeGridEl) {
      const categories = [
        { key: 'services', icon: '⚙️', label: 'Services', driftKey: null },
        { key: 'scheduled_tasks', icon: '📅', label: 'Tasks', driftKey: null },
        { key: 'logs_cleared', icon: '🗑️', label: 'Logs Cleared', driftKey: null },
        { key: 'registry', icon: '📝', label: 'Registry', driftKey: 'registry' },
        { key: 'process_execution', icon: '▶️', label: 'Processes', driftKey: 'process_execution' },
        { key: 'network_connections', icon: '🌐', label: 'Network', driftKey: 'network' },
        { key: 'powershell', icon: '⚡', label: 'PowerShell', driftKey: 'powershell' }
      ];
      
      changeGridEl.innerHTML = categories.map(cat => {
        const catData = whatChanged[cat.key] || {};
        const count = catData.count || 0;
        const sampleCount = catData.sample_count || count;
        const totalCount = catData.total_count || count;
        const observable = catData.observable !== false;
        const source = catData.source || '';
        const blockedReason = catData.blocked_reason;
        const observedInRun = catData.observed_in_run === true;
        
        // Check for drift on this surface
        const hasDrift = cat.driftKey && driftLookup[cat.driftKey];
        
        const hasData = (sampleCount || totalCount) > 0;
        const borderColor = !observable ? 'var(--warn)' : hasData ? 'var(--good)' : 'var(--border)';
        const bgColor = hasDrift ? 'rgba(59, 130, 246, 0.08)' : (!observable ? 'rgba(245, 158, 11, 0.05)' : 'var(--panel2)');
        const countColor = hasData ? 'var(--good)' : 'var(--muted)';
        const opacity = observable ? 1 : 0.7;
        
        // Tooltip with first item preview if available
        const items = catData.items || [];
        let tooltip = source;
        if (items.length > 0 && items[0].entity) {
          tooltip += `\n\nLatest: ${items[0].entity}`;
        }
        if (blockedReason) {
          tooltip += `\n\n⚠️ ${blockedReason}`;
        }
        if (hasDrift) {
          tooltip += `\n\n👁️ Observed despite config mismatch`;
        }
        if (totalCount > sampleCount) {
          tooltip += `\n\n📊 Showing ${sampleCount} of ${totalCount} total`;
        }
        
        // Build "Observed" badge for drift cases
        const observedBadge = hasDrift ? `<span style="font-size: 8px; background: var(--accent); color: white; padding: 1px 4px; border-radius: 8px; margin-left: 4px;">Observed</span>` : '';
        
        // Build count display: use sample_count and total_count for clarity
        // Show "N (of M total)" when total > sample, else just show the count
        // Never display the internal page-size 'count' to users
        const displayCount = totalCount > sampleCount ? sampleCount : (sampleCount || totalCount);
        const countDisplay = observable 
          ? (totalCount > sampleCount 
              ? `<span>${displayCount}</span><span style="font-size: 10px; font-weight: 400; color: var(--muted); margin-left: 4px;">(of ${totalCount.toLocaleString()} total)</span>`
              : `${displayCount}`)
          : '—';
        
        return `
          <div style="padding: 10px; background: ${bgColor}; border-radius: var(--radius-sm); border: 1px solid ${borderColor}; opacity: ${opacity}; cursor: ${hasData ? 'pointer' : 'default'}; position: relative;"
               title="${tooltip.replace(/"/g, '&quot;')}"
               ${hasData ? `onclick="window.pivotToFacts && window.pivotToFacts('${cat.key}')"` : ''}>
            <div style="display: flex; align-items: center; gap: 4px; margin-bottom: 4px;">
              <span style="font-size: 14px;">${cat.icon}</span>
              <span style="font-size: 11px; font-weight: 600; color: var(--text);">${cat.label}</span>
              ${observedBadge}
            </div>
            <div style="font-size: 18px; font-weight: 700; color: ${countColor};">${countDisplay}</div>
            <div style="font-size: 9px; color: var(--muted);">${observable ? source : blockedReason || 'Not available'}</div>
          </div>
        `;
      }).join('');
    }
    
    // ===== PANEL 2: MILESTONES OBSERVED =====
    const milestonesListEl = document.getElementById('discoveryMilestonesList');
    const observedCountEl = document.getElementById('milestonesObservedCount');
    const notObservableCountEl = document.getElementById('milestonesNotObservableCount');
    
    // Milestone to drift surface mapping
    const milestoneDriftMap = {
      'powershell_scriptblock': 'powershell',
      'network_connection': 'network',
      'process_execution': 'process_execution',
      'registry_autorun': 'registry'
    };
    
    if (milestonesListEl && milestones.items) {
      if (observedCountEl) observedCountEl.textContent = `${milestones.observed || 0} ✓`;
      if (notObservableCountEl) notObservableCountEl.textContent = `${milestones.not_observable || 0} blocked`;
      
      milestonesListEl.innerHTML = milestones.items.map(m => {
        const status = m.status || 'not_observed';
        const observedInRun = m.observed_in_run === true;
        const milestoneId = m.id || '';
        const hasDrift = milestoneDriftMap[milestoneId] && driftLookup[milestoneDriftMap[milestoneId]];
        
        let statusIcon, statusColor, statusBg;
        
        if (status === 'observed') {
          statusIcon = '✅';
          statusColor = 'var(--good)';
          statusBg = 'rgba(16, 185, 129, 0.1)';
        } else if (status === 'not_observable') {
          statusIcon = hasDrift ? '👁️' : '❌';
          statusColor = hasDrift ? 'var(--accent)' : 'var(--warn)';
          statusBg = hasDrift ? 'rgba(59, 130, 246, 0.1)' : 'rgba(245, 158, 11, 0.1)';
        } else {
          statusIcon = '⚪';
          statusColor = 'var(--muted)';
          statusBg = 'transparent';
        }
        
        const count = m.count || 0;
        const evidence = m.evidence;
        const blockedReason = m.blocked_reason;
        
        // Build "Observed" badge for drift cases
        const observedBadge = hasDrift ? `<span style="font-size: 8px; background: var(--accent); color: white; padding: 1px 4px; border-radius: 8px; margin-left: 4px;">Observed</span>` : '';
        
        return `
          <div style="display: flex; align-items: center; gap: 10px; padding: 8px 10px; background: ${statusBg}; border-radius: var(--radius-sm); border: 1px solid ${status === 'observed' ? 'var(--good)' : hasDrift ? 'var(--accent)' : 'var(--border)'};">
            <span style="font-size: 14px;">${statusIcon}</span>
            <div style="flex: 1;">
              <div style="display: flex; align-items: center;">
                <span style="font-size: 12px; font-weight: 600; color: ${statusColor};">${m.name || 'Unknown'}</span>
                ${observedBadge}
              </div>
              <div style="font-size: 10px; color: var(--muted);">${m.source || ''}</div>
            </div>
            ${count > 0 ? `<span style="font-size: 11px; font-weight: 600; color: var(--good);">${count}</span>` : ''}
            ${blockedReason && !hasDrift ? `<span style="font-size: 9px; color: var(--warn);" title="${blockedReason}">🔒</span>` : ''}
            ${evidence ? `<button onclick="window.viewEvidence && window.viewEvidence('${evidence}')" style="font-size: 9px; padding: 2px 6px; background: var(--panel); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; color: var(--accent);">View</button>` : ''}
          </div>
        `;
      }).join('');
    }
    
    // ===== PANEL 3: VISIBILITY LIMITS =====
    const limitsPanel = document.getElementById('discoveryVisibilityLimits');
    const limitsListEl = document.getElementById('discoveryLimitsList');
    
    if (limitsPanel && limitsListEl) {
      if (visibilityLimits.length > 0) {
        limitsPanel.classList.remove('hidden');
        
        limitsListEl.innerHTML = visibilityLimits.map(limit => {
          const affectedCount = (limit.affected_milestones || []).length;
          const hasDrift = limit.has_drift === true;
          const subtext = limit.unlock_subtext || '';
          
          // Use different styling for drift cases (more informational, less urgent)
          const borderColor = hasDrift ? 'var(--accent)' : 'var(--border)';
          const bgColor = hasDrift ? 'rgba(59, 130, 246, 0.05)' : 'var(--panel)';
          const buttonBg = hasDrift ? 'var(--accent)' : 'var(--accent)';
          
          return `
            <div style="display: flex; align-items: flex-start; gap: 10px; padding: 10px; background: ${bgColor}; border-radius: var(--radius-sm); border: 1px solid ${borderColor};">
              <span style="font-size: 16px;">${limit.unlock_icon || '🔒'}</span>
              <div style="flex: 1;">
                <div style="display: flex; align-items: center; gap: 6px;">
                  <span style="font-size: 12px; font-weight: 600; color: var(--text);">${limit.title}</span>
                  ${hasDrift ? `<span style="font-size: 8px; background: var(--accent); color: white; padding: 1px 4px; border-radius: 8px;">Observed</span>` : ''}
                </div>
                <div style="font-size: 10px; color: var(--muted); margin-top: 2px;">${limit.impact}</div>
                ${subtext ? `<div style="font-size: 10px; color: ${hasDrift ? 'var(--accent)' : 'var(--muted)'}; margin-top: 4px; font-style: italic;">${escapeHtml(subtext)}</div>` : ''}
                ${!hasDrift && affectedCount > 0 ? `<div style="font-size: 9px; color: var(--warn); margin-top: 4px;">Blocks ${affectedCount} milestones</div>` : ''}
              </div>
              <button onclick="window.showReadinessPanel && window.showReadinessPanel()" 
                      style="padding: 4px 10px; background: ${buttonBg}; color: var(--bg); border: none; border-radius: 4px; cursor: pointer; font-size: 10px; font-weight: 600; white-space: nowrap;">
                ${limit.unlock_label || 'Unlock'}
              </button>
            </div>
          `;
        }).join('');
      } else {
        limitsPanel.classList.add('hidden');
      }
    }
    
    // Show the panel for all runs that have data or use General preset
    if (totalChanges > 0 || profile === 'general') {
      els.discoverySummaryPanel.classList.remove('hidden');
    }
  }

  /**
   * Render Next Steps panel from /api/runs/:id/next_steps endpoint
   * Enhanced to support structured why/how/verify format
   */
  function renderNextStepsPanel(data) {
    if (!els.runNextStepsPanel) return;
    
    // Show the panel
    els.runNextStepsPanel.classList.remove('hidden');
    
    // Update border color based on severity
    const severityColors = {
      'high': 'var(--error)',
      'medium': 'var(--warn)',
      'low': 'var(--accent)',
      'info': 'var(--good)'
    };
    const borderColor = severityColors[data.summary?.severity] || 'var(--good)';
    els.runNextStepsPanel.style.borderLeftColor = borderColor;
    
    // Update header color
    const header = els.runNextStepsPanel.querySelector('h4');
    if (header) header.style.color = borderColor;
    
    // Severity badge
    if (els.nextStepsSeverityBadge) {
      const severity = data.summary?.severity || 'info';
      const badgeClass = {
        'high': 'badge-critical',
        'medium': 'badge-warn',
        'low': 'badge-info',
        'info': 'badge-info'
      }[severity] || 'badge-info';
      els.nextStepsSeverityBadge.className = `badge ${badgeClass}`;
      els.nextStepsSeverityBadge.textContent = data.scenario?.replace(/_/g, ' ') || 'unknown';
    }
    
    // Summary text
    if (els.nextStepsSummary) {
      els.nextStepsSummary.textContent = data.summary?.text || '';
    }
    
    // Coverage Checklist - shows attack surface visibility status
    if (els.coverageChecklist && els.coverageChecklistItems) {
      const checklist = data.coverage_checklist || [];
      
      if (checklist.length === 0) {
        els.coverageChecklist.classList.add('hidden');
      } else {
        els.coverageChecklist.classList.remove('hidden');
        
        els.coverageChecklistItems.innerHTML = checklist.map(item => {
          const statusIcon = {
            'ok': '✅',
            'partial': '⚠️',
            'blocked': '❌'
          }[item.status] || '❓';
          
          const statusColor = {
            'ok': 'var(--good)',
            'partial': 'var(--warn)',
            'blocked': 'var(--error)'
          }[item.status] || 'var(--muted)';
          
          // Build unlock CTA if available
          let unlockCta = '';
          if (item.status !== 'ok' && item.unlock) {
            const unlockAction = item.unlock.toLowerCase().includes('admin') ? 'run-admin' :
                                 item.unlock.toLowerCase().includes('sysmon') ? 'install-sysmon' :
                                 item.unlock.toLowerCase().includes('powershell') ? 'enable-ps' : '';
            if (unlockAction) {
              unlockCta = `<button class="coverage-unlock-btn" data-unlock="${unlockAction}" 
                            style="margin-left: 8px; font-size: 10px; padding: 2px 6px; background: var(--accent); 
                                   color: white; border: none; border-radius: 3px; cursor: pointer;">
                            🔓 ${escapeHtml(item.unlock)}
                          </button>`;
            }
          }
          
          return `
            <div style="display: flex; align-items: center; font-size: 12px;">
              <span style="width: 20px; flex-shrink: 0;">${statusIcon}</span>
              <span style="font-weight: 500; min-width: 140px; color: ${statusColor};">${escapeHtml(item.surface || item.name)}</span>
              <span style="color: var(--muted); font-size: 11px; flex: 1;">${escapeHtml(item.reason || '')}</span>
              ${unlockCta}
            </div>
          `;
        }).join('');
        
        // Bind click handlers for unlock buttons
        els.coverageChecklistItems.querySelectorAll('.coverage-unlock-btn').forEach(btn => {
          btn.onclick = (e) => {
            e.stopPropagation();
            const action = btn.dataset.unlock;
            if (action && typeof handleUnlockCta === 'function') {
              handleUnlockCta(action);
            }
          };
        });
      }
    }
    
    // Action cards - enhanced to support why/how/verify structure
    if (els.nextStepsActions) {
      const actions = data.actions || [];
      
      // If no actions provided, show fallback guidance
      if (actions.length === 0) {
        els.nextStepsActions.innerHTML = `
          <div style="padding: 12px; background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius-sm); text-align: center;">
            <div style="font-size: 13px; color: var(--muted);">✓ No additional actions recommended</div>
            <div style="font-size: 11px; color: var(--muted); margin-top: 4px;">Detection coverage is complete for this run</div>
          </div>
        `;
        return;
      }
      
      els.nextStepsActions.innerHTML = actions.slice(0, 7).map(action => {
        const isBlocked = !!action.blocking_reason;
        const hasDeepLink = !!action.deep_link;
        const requiresAdmin = action.requires?.admin;
        const requiresSysmon = action.requires?.sysmon;
        
        // Build requirements badges
        const reqBadges = [];
        if (requiresAdmin) reqBadges.push('<span style="font-size: 9px; background: var(--warn); color: white; padding: 1px 4px; border-radius: 2px;">🔐 Admin</span>');
        if (requiresSysmon) reqBadges.push('<span style="font-size: 9px; background: var(--accent); color: white; padding: 1px 4px; border-radius: 2px;">📊 Sysmon</span>');
        
        // Render structured why/how/verify if available
        const hasStructured = action.why || action.how || action.verify;
        let structuredContent = '';
        
        if (hasStructured) {
          // Why section
          if (action.why) {
            structuredContent += `<div style="font-size: 11px; color: var(--muted); margin-top: 6px;"><strong>Why:</strong> ${escapeHtml(action.why)}</div>`;
          }
          
          // How section (array of bullets)
          if (action.how && action.how.length > 0) {
            const howItems = action.how.map(h => `<li>${escapeHtml(h)}</li>`).join('');
            structuredContent += `<div style="font-size: 11px; color: var(--muted); margin-top: 4px;"><strong>How:</strong><ul style="margin: 2px 0 0 16px; padding: 0;">${howItems}</ul></div>`;
          }
          
          // Verify section (array of bullets)
          if (action.verify && action.verify.length > 0) {
            const verifyItems = action.verify.map(v => `<li>${escapeHtml(v)}</li>`).join('');
            structuredContent += `<div style="font-size: 11px; color: var(--success); margin-top: 4px;"><strong>Verify:</strong><ul style="margin: 2px 0 0 16px; padding: 0;">${verifyItems}</ul></div>`;
          }
        }
        
        return `
          <div class="next-step-action" data-action-id="${escapeHtml(action.action_id || action.id || '')}" 
               data-deep-link='${hasDeepLink ? escapeHtml(JSON.stringify(action.deep_link)) : ""}'
               style="padding: 10px 12px; background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius-sm);
                      cursor: ${hasDeepLink && !isBlocked ? 'pointer' : 'default'}; 
                      ${isBlocked ? 'opacity: 0.6;' : ''}
                      transition: background 0.15s;"
               ${hasDeepLink && !isBlocked ? 'onmouseover="this.style.background=\'var(--panel2)\'" onmouseout="this.style.background=\'var(--panel)\'"' : ''}>
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 4px;">
              <div style="font-weight: 500; font-size: 13px;">${escapeHtml(action.title)}</div>
              ${reqBadges.length > 0 ? `<div style="display: flex; gap: 4px;">${reqBadges.join('')}</div>` : ''}
            </div>
            ${action.rationale ? `<div style="font-size: 11px; color: var(--muted); line-height: 1.4;">${escapeHtml(action.rationale)}</div>` : ''}
            ${structuredContent}
            ${isBlocked ? `<div style="font-size: 10px; color: var(--error); margin-top: 4px;">🚫 ${escapeHtml(action.blocking_reason)}</div>` : ''}
            ${hasDeepLink && !isBlocked ? '<div style="font-size: 10px; color: var(--accent); margin-top: 4px;">Click to navigate →</div>' : ''}
          </div>
        `;
      }).join('');
      
      // Bind click handlers for deep links
      els.nextStepsActions.querySelectorAll('.next-step-action[data-deep-link]').forEach(el => {
        const deepLinkStr = el.dataset.deepLink;
        if (!deepLinkStr) return;
        
        el.onclick = () => {
          try {
            const deepLink = JSON.parse(deepLinkStr);
            handleNextStepDeepLink(deepLink);
          } catch (e) {
            console.warn('[NextSteps] Invalid deep link:', e);
          }
        };
      });
    }
  }

  /**
   * Handle deep link navigation from Next Steps actions
   */
  function handleNextStepDeepLink(deepLink) {
    if (!deepLink || !deepLink.tab) return;
    
    const tab = deepLink.tab.toLowerCase();
    const runId = deepLink.run_id || state.selectedRunId;
    const signalId = deepLink.signal_id;
    const playbookId = deepLink.playbook_id;
    const filter = deepLink.filter;
    const section = deepLink.section;
    
    console.log('[NextSteps] Deep link navigation:', { tab, runId, signalId, playbookId, filter, section });
    
    switch (tab) {
      case 'mission':
        switchTab('mission');
        // Scroll to section if specified
        if (section === 'detection_plan') {
          setTimeout(() => {
            const dpSection = document.getElementById('detectionPlanSection');
            if (dpSection) dpSection.scrollIntoView({ behavior: 'smooth' });
          }, 100);
        } else if (section === 'capability') {
          setTimeout(() => {
            const capSection = document.getElementById('capabilityPanel');
            if (capSection) capSection.scrollIntoView({ behavior: 'smooth' });
          }, 100);
        }
        break;
        
      case 'runs':
        switchTab('runs');
        if (runId) {
          selectRun(runId);
        }
        break;
        
      case 'facts':
        // Switch to Facts tab within run detail
        if (runId && runId !== state.selectedRunId) {
          selectRun(runId);
        }
        switchRunTab('facts');
        // Apply filter if specified
        if (filter) {
          setTimeout(() => {
            // Parse filter string (e.g., "fact_type=persistence_service")
            const params = new URLSearchParams(filter);
            const factType = params.get('fact_type');
            
            if (factType) {
              const factTypeFilter = document.getElementById('factTypeFilter');
              if (factTypeFilter) {
                factTypeFilter.value = factType;
                factInspectorState.filters.fact_type = factType;
                factInspectorState.pagination.offset = 0;
                loadFactInspectorData();
              }
            }
            
            // Scroll to inspector
            const inspectorSection = document.getElementById('factInspectorSection');
            if (inspectorSection) {
              inspectorSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
          }, 200);
        }
        break;
        
      case 'playbooks':
        // Switch to Playbooks tab within run detail
        if (runId && runId !== state.selectedRunId) {
          selectRun(runId);
        }
        switchRunTab('playbooks');
        // Open playbook detail if specified
        if (playbookId) {
          setTimeout(() => {
            // Try to find playbook in evaluations and open drawer
            const pb = state.run?.playbook_evaluations?.find(p => p.playbook_id === playbookId);
            if (pb && typeof openPlaybookDetailDrawer === 'function') {
              openPlaybookDetailDrawer(pb, 'run');
            }
          }, 300);
        }
        break;
        
      case 'findings':
        // Switch to Findings tab within run detail
        if (runId && runId !== state.selectedRunId) {
          selectRun(runId);
        }
        switchRunTab('findings');
        break;
        
      case 'explain':
        // Switch to Explain tab and select signal
        if (runId && runId !== state.selectedRunId) {
          selectRun(runId);
        }
        switchRunTab('explain');
        if (signalId) {
          setTimeout(() => {
            // Find and select the signal
            const signal = state.signals?.find(s => s.signal_id === signalId);
            if (signal) {
              selectSignal(signal);
            }
          }, 300);
        }
        break;
        
      case 'export':
      case 'import-export':
        switchTab('import-export');
        // Scroll to export section
        setTimeout(() => {
          const exportSection = document.getElementById('exportSection');
          if (exportSection) exportSection.scrollIntoView({ behavior: 'smooth' });
        }, 100);
        break;
        
      case 'settings':
        switchTab('settings');
        break;
        
      default:
        console.warn('[NextSteps] Unknown tab:', tab);
    }
  }

  /**
   * Render Facts tab - showing extracted facts and "why no signals"
   */
  function renderFactsTab() {
    // Hide all states first
    if (els.factsLoading) els.factsLoading.classList.add('hidden');
    if (els.factsEmpty) els.factsEmpty.classList.add('hidden');
    if (els.factsNoTelemetry) els.factsNoTelemetry.classList.add('hidden');
    if (els.factsContent) els.factsContent.classList.add('hidden');
    if (els.factsUnavailable) els.factsUnavailable.classList.add('hidden');
    
    // Check if endpoint is unavailable (404)
    if (state.capabilities.runCoverage === false) {
      if (els.factsUnavailable) els.factsUnavailable.classList.remove('hidden');
      if (els.factsMissingEndpoint) els.factsMissingEndpoint.textContent = '(missing: /api/runs/:id/coverage)';
      return;
    }
    
    // If coverage not loaded yet, show loading
    if (!state.runCoverage) {
      if (els.factsLoading) els.factsLoading.classList.remove('hidden');
      return;
    }
    
    const coverage = state.runCoverage;
    
    // INVARIANT 1: coverage.available=false → show unavailable reason only
    if (coverage.available === false) {
      if (els.factsEmpty) els.factsEmpty.classList.remove('hidden');
      const emptyMsg = els.factsEmpty.querySelector('div:last-child');
      if (emptyMsg) {
        const reason = coverage.reason_code ? `[${coverage.reason_code}] ` : '';
        emptyMsg.textContent = reason + (coverage.message || 'Coverage data not available');
        emptyMsg.style.maxWidth = '400px';
      }
      return;
    }
    
    // INVARIANT 2: coverage.available=true AND facts_total=0 → show factsNoTelemetry
    if (!coverage.facts_total || coverage.facts_total === 0) {
      // Prefer run-scoped readiness_snapshot from run_meta over live selfcheck
      const readiness = coverage.readiness_snapshot || state.telemetryReadiness;
      if (readiness && els.factsNoTelemetry) {
        els.factsNoTelemetry.classList.remove('hidden');
        renderNoTelemetryPanel(readiness);
      } else {
        // Fallback: no readiness info available
        if (els.factsEmpty) els.factsEmpty.classList.remove('hidden');
      }
      return;
    }
    
    // Show content
    if (els.factsContent) els.factsContent.classList.remove('hidden');
    
    // Update summary metrics
    if (els.factsTotalCount) els.factsTotalCount.textContent = formatValue(coverage.facts_total);
    if (els.factsTypeCount) els.factsTypeCount.textContent = formatValue(coverage.fact_types?.length || 0);
    if (els.factsHostCount) els.factsHostCount.textContent = formatValue(coverage.top_hosts?.length || 0);
    
    // Render fact types table
    if (els.factsTypeRows && coverage.fact_types) {
      const maxCount = Math.max(...coverage.fact_types.map(ft => ft.count));
      els.factsTypeRows.innerHTML = coverage.fact_types.slice(0, 15).map(ft => {
        const pct = maxCount > 0 ? (ft.count / maxCount) * 100 : 0;
        return `
          <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 8px 12px; font-family: monospace; font-size: 12px;">${escapeHtml(ft.fact_type)}</td>
            <td style="padding: 8px 12px; text-align: right; font-weight: 600;">${formatValue(ft.count)}</td>
            <td style="padding: 8px 12px;">
              <div style="background: var(--panel); border-radius: 2px; height: 6px; overflow: hidden;">
                <div style="background: var(--accent); width: ${pct}%; height: 100%;"></div>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    }
    
    // Render top hosts
    if (els.factsHostsList && coverage.top_hosts) {
      if (coverage.top_hosts.length === 0) {
        els.factsHostsList.innerHTML = getStatusBadge('configured', 'No hosts recorded');
      } else {
        els.factsHostsList.innerHTML = coverage.top_hosts.slice(0, 10).map(h => 
          `<span class="badge badge--configured" style="font-family: monospace; font-size: 11px;">
            ${escapeHtml(h.host)} <span style="opacity: 0.7;">(${formatValue(h.count)})</span>
          </span>`
        ).join('');
      }
    }
    
    // Render sensors section (if sensors data available)
    // Use consistent status semantics: active = facts observed, configured = accessible
    if (els.factsSensorsSection && els.factsSensorsList && coverage.sensors && coverage.sensors.length > 0) {
      els.factsSensorsSection.classList.remove('hidden');
      els.factsSensorsList.innerHTML = coverage.sensors.map(sensor => {
        // Determine status: "active" only if facts observed from this sensor
        const hasObservedFacts = sensor.fact_count && sensor.fact_count > 0;
        const effectiveStatus = hasObservedFacts ? 'active' : (sensor.status || 'configured');
        
        // Get consistent badge colors/icons
        const config = STATUS_CONFIG[effectiveStatus] || STATUS_CONFIG.configured;
        const statusIcon = config.icon;
        const statusColor = effectiveStatus === 'active' ? 'var(--good)' : 
                           effectiveStatus === 'configured' ? '#64748b' : 
                           effectiveStatus === 'blocked' ? 'var(--warn)' : 'var(--bad)';
        
        const factCountStr = sensor.fact_count ? ` (${formatValue(sensor.fact_count)} facts)` : '';
        const capsStr = sensor.capabilities?.length > 0 
          ? `<div style="display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px;">
              ${sensor.capabilities.map(cap => 
                `<span class="badge badge--configured" style="font-size: 10px; padding: 2px 6px;">${escapeHtml(cap)}</span>`
              ).join('')}
             </div>`
          : '';
        
        // Status label with semantic meaning
        const statusLabel = hasObservedFacts ? 'Active (observed)' : 
                           sensor.status_label || config.label;
        
        return `
          <div style="background: var(--panel2); border-radius: var(--radius-sm); padding: 10px 12px; border-left: 3px solid ${statusColor};">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="font-weight: 600; font-size: 13px;">
                <span style="margin-right: 6px;">${statusIcon}</span>
                ${escapeHtml(sensor.sensor_name)}
                <span style="font-weight: normal; color: var(--muted);">${factCountStr}</span>
              </div>
              ${getStatusBadge(effectiveStatus, statusLabel, null, { small: true, showIcon: false })}
            </div>
            ${capsStr}
          </div>
        `;
      }).join('');
    } else if (els.factsSensorsSection) {
      els.factsSensorsSection.classList.add('hidden');
    }
    
    // Render Playbook Summary section
    const diag = coverage.pipeline_diagnostics || {};
    if (els.playbookSummarySection && diag.playbooks_loaded !== undefined) {
      els.playbookSummarySection.classList.remove('hidden');
      
      // Update counts
      if (els.playbookLoadedCount) {
        els.playbookLoadedCount.textContent = formatValue(diag.playbooks_loaded);
      }
      if (els.playbookEnabledCount) {
        els.playbookEnabledCount.textContent = formatValue(diag.playbooks_enabled ?? diag.playbooks_loaded);
      }
      if (els.playbookFiredCount) {
        const fired = diag.playbooks_fired_this_run ?? 0;
        els.playbookFiredCount.textContent = formatValue(fired);
        // Highlight if playbooks fired
        els.playbookFiredCount.style.color = fired > 0 ? 'var(--success)' : 'var(--muted)';
      }
      
      // Render categories as badges
      if (els.playbookCategoriesList && diag.playbook_categories && diag.playbook_categories.length > 0) {
        els.playbookCategoriesList.innerHTML = diag.playbook_categories.map(cat => {
          // Format category name nicely
          const displayName = cat.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
          return `<span class="badge" style="font-size: 10px; padding: 3px 8px; background: var(--panel); color: var(--text); border: 1px solid var(--border);">${escapeHtml(displayName)}</span>`;
        }).join('');
      } else if (els.playbookCategoriesList) {
        els.playbookCategoriesList.innerHTML = '<span style="font-size: 11px; color: var(--muted);">Categories not available</span>';
      }
    } else if (els.playbookSummarySection) {
      els.playbookSummarySection.classList.add('hidden');
    }
    
    // Show "Why no signals?" panel ONLY if available=true, facts > 0, and signals = 0
    const signalCount = state.selectedRun?.signal_count ?? state.selectedRun?.signals_fired ?? 0;
    if (els.whyNoSignalsPanel && els.whyNoSignalsContent) {
      if (coverage.available === true && coverage.facts_total > 0 && signalCount === 0) {
        els.whyNoSignalsPanel.classList.remove('hidden');
        const reasons = [];
        
        if (diag.playbooks_loaded === 0 || diag.playbooks_loaded === undefined) {
          reasons.push('• <strong>No playbooks loaded</strong> - ensure playbooks are configured in the agent');
        } else {
          // Playbooks are loaded but nothing fired
          const categoryInfo = diag.playbook_categories?.length > 0 
            ? ` covering ${diag.playbook_categories.length} categories`
            : '';
          reasons.push(`• <strong>${diag.playbooks_loaded} playbooks loaded</strong>${categoryInfo} — no patterns matched`);
        }
        
        if (coverage.facts_total < 50) {
          reasons.push('• <strong>Low fact count</strong> (<50) - short telemetry capture may miss complex patterns');
        }
        
        // Check if fact types match common detection patterns
        const factTypes = new Set(coverage.fact_types?.map(ft => ft.fact_type) || []);
        if (!factTypes.has('ProcessCreate') && !factTypes.has('ImageLoad') && !factTypes.has('Exec')) {
          reasons.push('• <strong>No process execution facts</strong> - many playbooks rely on process events');
        }
        
        // Add explanation if provided
        if (diag.explanation && reasons.length === 1) {
          reasons.push(`• ${diag.explanation}`);
        }
        
        if (reasons.length === 0) {
          reasons.push('• The captured telemetry did not match any playbook detection patterns');
          reasons.push('• This may indicate benign activity or that additional playbooks are needed');
        }
        
        els.whyNoSignalsContent.innerHTML = reasons.join('<br>');
      } else {
        els.whyNoSignalsPanel.classList.add('hidden');
      }
    }
    
    // Render pipeline diagnostics with full detail
    if (els.pipelineDiagnostics && coverage.pipeline_diagnostics) {
      let diagHtml = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px;">
          <div><span style="color: var(--muted);">Playbooks Loaded:</span> <strong>${formatValue(diag.playbooks_loaded)}</strong></div>
          <div><span style="color: var(--muted);">Playbooks Enabled:</span> <strong>${formatValue(diag.playbooks_enabled ?? diag.playbooks_loaded)}</strong></div>
          <div><span style="color: var(--muted);">Fired This Run:</span> <strong style="color: ${(diag.playbooks_fired_this_run || 0) > 0 ? 'var(--warn)' : 'var(--muted)'}">${formatValue(diag.playbooks_fired_this_run ?? 0)}</strong></div>
          <div><span style="color: var(--muted);">Coverage Minutes:</span> <strong>${formatValue(diag.coverage_minutes)}</strong></div>
        </div>
      `;
      
      // Show skipped playbooks if any
      if (diag.playbooks_skipped > 0) {
        diagHtml += `
          <div style="margin-bottom: 12px; padding: 8px; background: rgba(251, 191, 36, 0.1); border: 1px solid var(--warn); border-radius: var(--radius-sm);">
            <div style="font-size: 12px; color: var(--warn); font-weight: 500; margin-bottom: 4px;">⚠️ ${diag.playbooks_skipped} Playbooks Skipped</div>
        `;
        if (diag.skipped_by_reason) {
          const reasons = Object.entries(diag.skipped_by_reason);
          diagHtml += `<div style="font-size: 11px; color: var(--muted);">`;
          reasons.forEach(([reason, count]) => {
            diagHtml += `<div>• ${reason.replace(/_/g, ' ')}: ${count}</div>`;
          });
          diagHtml += `</div>`;
        }
        if (diag.skipped_examples?.length > 0) {
          diagHtml += `<div style="font-size: 10px; color: var(--muted); margin-top: 4px;">Examples: ${diag.skipped_examples.slice(0, 3).map(e => e.playbook_id).join(', ')}</div>`;
        }
        diagHtml += `</div>`;
      }
      
      // Show fired by category breakdown
      if (diag.fired_by_category && Object.keys(diag.fired_by_category).length > 0) {
        diagHtml += `
          <div style="margin-bottom: 12px;">
            <div style="font-size: 11px; color: var(--muted); margin-bottom: 6px;">Fired by Category:</div>
            <div style="display: flex; flex-wrap: wrap; gap: 6px;">
        `;
        Object.entries(diag.fired_by_category).forEach(([category, count]) => {
          const displayCat = category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
          diagHtml += `<span class="badge" style="font-size: 10px; padding: 3px 8px; background: var(--panel); color: var(--text); border: 1px solid var(--border);">${displayCat}: ${count}</span>`;
        });
        diagHtml += `</div></div>`;
      }
      
      // Show categories covered
      if (diag.playbook_categories?.length > 0) {
        diagHtml += `
          <div style="margin-bottom: 8px;">
            <div style="font-size: 11px; color: var(--muted); margin-bottom: 6px;">Categories Available:</div>
            <div style="display: flex; flex-wrap: wrap; gap: 4px;">
              ${diag.playbook_categories.map(c => `<span class="badge badge-stopped" style="font-size: 10px;">${c.replace(/_/g, ' ')}</span>`).join('')}
            </div>
          </div>
        `;
      }
      
      // Show explanation
      if (diag.explanation) {
        diagHtml += `
          <div style="margin-top: 12px; padding: 8px; background: var(--panel); border-radius: var(--radius-sm); font-size: 11px; color: var(--muted);">
            ℹ️ ${escapeHtml(diag.explanation)}
          </div>
        `;
      }
      
      els.pipelineDiagnostics.innerHTML = diagHtml;
    }
    
    // Initialize Fact Inspector when facts are loaded
    initFactInspector();
  }

  // ============================================================================
  // Fact Inspector - Browse actual fact rows
  // ============================================================================

  // Fact Inspector state
  const factInspectorState = {
    facts: [],
    pagination: { total: 0, limit: 50, offset: 0, has_more: false },
    filters: { fact_type: '', host: '', search: '' },
    available_filters: { fact_types: [], hosts: [] },
    initialized: false
  };

  /**
   * Initialize Fact Inspector with event handlers
   */
  function initFactInspector() {
    if (factInspectorState.initialized) return;
    
    // Get DOM elements
    const factTypeFilter = document.getElementById('factTypeFilter');
    const factHostFilter = document.getElementById('factHostFilter');
    const factSearchInput = document.getElementById('factSearchInput');
    const factInspectorRefresh = document.getElementById('factInspectorRefresh');
    const factPrevBtn = document.getElementById('factPrevBtn');
    const factNextBtn = document.getElementById('factNextBtn');
    const factDrawerClose = document.getElementById('factDrawerClose');
    
    // Filter change handlers
    if (factTypeFilter) {
      factTypeFilter.addEventListener('change', () => {
        factInspectorState.filters.fact_type = factTypeFilter.value;
        factInspectorState.pagination.offset = 0;
        loadFactInspectorData();
      });
    }
    
    if (factHostFilter) {
      factHostFilter.addEventListener('change', () => {
        factInspectorState.filters.host = factHostFilter.value;
        factInspectorState.pagination.offset = 0;
        loadFactInspectorData();
      });
    }
    
    // Search input with debounce
    let searchTimeout = null;
    if (factSearchInput) {
      factSearchInput.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
          factInspectorState.filters.search = factSearchInput.value;
          factInspectorState.pagination.offset = 0;
          loadFactInspectorData();
        }, 300);
      });
    }
    
    // Refresh button
    if (factInspectorRefresh) {
      factInspectorRefresh.addEventListener('click', () => {
        loadFactInspectorData();
      });
    }
    
    // Pagination buttons
    if (factPrevBtn) {
      factPrevBtn.addEventListener('click', () => {
        if (factInspectorState.pagination.offset > 0) {
          factInspectorState.pagination.offset = Math.max(0, factInspectorState.pagination.offset - factInspectorState.pagination.limit);
          loadFactInspectorData();
        }
      });
    }
    
    if (factNextBtn) {
      factNextBtn.addEventListener('click', () => {
        if (factInspectorState.pagination.has_more) {
          factInspectorState.pagination.offset += factInspectorState.pagination.limit;
          loadFactInspectorData();
        }
      });
    }
    
    // Drawer close button
    if (factDrawerClose) {
      factDrawerClose.addEventListener('click', () => {
        const drawer = document.getElementById('factDetailDrawer');
        if (drawer) drawer.classList.add('hidden');
      });
    }
    
    // Make fact type rows clickable in the coverage table
    const factsTypeRows = document.getElementById('factsTypeRows');
    if (factsTypeRows) {
      factsTypeRows.addEventListener('click', (e) => {
        const row = e.target.closest('tr');
        if (row) {
          const factType = row.querySelector('td')?.textContent?.trim();
          if (factType && factTypeFilter) {
            factTypeFilter.value = factType;
            factInspectorState.filters.fact_type = factType;
            factInspectorState.pagination.offset = 0;
            loadFactInspectorData();
            
            // Scroll to inspector
            const inspectorSection = document.getElementById('factInspectorSection');
            if (inspectorSection) {
              inspectorSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
          }
        }
      });
    }
    
    factInspectorState.initialized = true;
    
    // Auto-load facts if we have a selected run
    if (state.selectedRunId) {
      loadFactInspectorData();
    }
  }

  /**
   * Load facts from the API with current filters
   */
  async function loadFactInspectorData() {
    const runId = state.selectedRunId;
    if (!runId) return;
    
    const rows = document.getElementById('factInspectorRows');
    if (rows) {
      rows.innerHTML = `
        <tr>
          <td colspan="4" style="padding: 20px; text-align: center; color: var(--muted);">
            <div style="font-size: 12px;">Loading facts...</div>
          </td>
        </tr>
      `;
    }
    
    try {
      // Build query params
      const params = new URLSearchParams();
      if (factInspectorState.filters.fact_type) params.append('fact_type', factInspectorState.filters.fact_type);
      if (factInspectorState.filters.host) params.append('host', factInspectorState.filters.host);
      if (factInspectorState.filters.search) params.append('search', factInspectorState.filters.search);
      params.append('limit', factInspectorState.pagination.limit.toString());
      params.append('offset', factInspectorState.pagination.offset.toString());
      
      const resp = await fetch(`/api/runs/${runId}/facts?${params}`);
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }
      
      const json = await resp.json();
      if (!json.success || !json.data) {
        throw new Error(json.error || 'Invalid response');
      }
      
      // Update state
      factInspectorState.facts = json.data.facts || [];
      factInspectorState.pagination = json.data.pagination || factInspectorState.pagination;
      factInspectorState.available_filters = json.data.available_filters || factInspectorState.available_filters;
      
      // Update filter dropdowns
      updateFactFilterDropdowns();
      
      // Render facts
      renderFactInspectorTable();
      
      // Update count badge
      const countBadge = document.getElementById('factInspectorCount');
      if (countBadge) {
        countBadge.textContent = formatValue(factInspectorState.pagination.total);
      }
      
    } catch (err) {
      console.error('[FactInspector] Failed to load facts:', err);
      if (rows) {
        rows.innerHTML = `
          <tr>
            <td colspan="4" style="padding: 20px; text-align: center; color: var(--error);">
              <div style="font-size: 12px;">Failed to load facts: ${escapeHtml(err.message)}</div>
            </td>
          </tr>
        `;
      }
    }
  }

  /**
   * Update filter dropdown options based on available data
   */
  function updateFactFilterDropdowns() {
    const factTypeFilter = document.getElementById('factTypeFilter');
    const factHostFilter = document.getElementById('factHostFilter');
    
    if (factTypeFilter) {
      const current = factTypeFilter.value;
      factTypeFilter.innerHTML = '<option value="">All Fact Types</option>';
      (factInspectorState.available_filters.fact_types || []).forEach(ft => {
        const opt = document.createElement('option');
        opt.value = ft;
        opt.textContent = ft;
        factTypeFilter.appendChild(opt);
      });
      factTypeFilter.value = current;
    }
    
    if (factHostFilter) {
      const current = factHostFilter.value;
      factHostFilter.innerHTML = '<option value="">All Hosts</option>';
      (factInspectorState.available_filters.hosts || []).forEach(h => {
        const opt = document.createElement('option');
        opt.value = h;
        opt.textContent = h;
        factHostFilter.appendChild(opt);
      });
      factHostFilter.value = current;
    }
  }

  /**
   * Render the facts table
   */
  function renderFactInspectorTable() {
    const rows = document.getElementById('factInspectorRows');
    const paginationDiv = document.getElementById('factInspectorPagination');
    
    if (!rows) return;
    
    if (factInspectorState.facts.length === 0) {
      rows.innerHTML = `
        <tr>
          <td colspan="4" style="padding: 20px; text-align: center; color: var(--muted);">
            <div style="font-size: 12px;">No facts match the current filters</div>
          </td>
        </tr>
      `;
      if (paginationDiv) paginationDiv.classList.add('hidden');
      return;
    }
    
    rows.innerHTML = factInspectorState.facts.map(fact => {
      // Generate summary from details
      const summary = generateFactSummary(fact);
      
      // Format timestamp
      const ts = fact.ts ? formatTimestamp(fact.ts) : '—';
      
      // Fact type badge color
      const typeColor = getFactTypeColor(fact.fact_type);
      
      return `
        <tr class="fact-row" data-fact-id="${escapeHtml(fact.fact_id)}" style="cursor: pointer; border-bottom: 1px solid var(--border);" 
            onmouseover="this.style.background='var(--panel)'" onmouseout="this.style.background=''">
          <td style="padding: 6px 10px; font-size: 11px; color: var(--muted); font-family: monospace;">${escapeHtml(ts)}</td>
          <td style="padding: 6px 10px;">
            <span style="background: ${typeColor}; color: white; font-size: 10px; padding: 2px 6px; border-radius: 2px; font-family: monospace;">${escapeHtml(fact.fact_type)}</span>
          </td>
          <td style="padding: 6px 10px; font-size: 11px; color: var(--text); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(summary)}">
            ${escapeHtml(summary)}
          </td>
          <td style="padding: 6px 10px; text-align: center;">
            <button class="fact-detail-btn" style="background: var(--accent); color: white; border: none; border-radius: 2px; padding: 2px 8px; font-size: 10px; cursor: pointer;">
              View
            </button>
          </td>
        </tr>
      `;
    }).join('');
    
    // Add click handlers for detail buttons
    rows.querySelectorAll('.fact-detail-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const row = e.target.closest('tr');
        const factId = row?.dataset.factId;
        if (factId) {
          const fact = factInspectorState.facts.find(f => f.fact_id === factId);
          if (fact) showFactDetailDrawer(fact);
        }
      });
    });
    
    // Row click also opens drawer
    rows.querySelectorAll('.fact-row').forEach(row => {
      row.addEventListener('click', () => {
        const factId = row.dataset.factId;
        if (factId) {
          const fact = factInspectorState.facts.find(f => f.fact_id === factId);
          if (fact) showFactDetailDrawer(fact);
        }
      });
    });
    
    // Update pagination
    if (paginationDiv) {
      paginationDiv.classList.remove('hidden');
      
      const start = factInspectorState.pagination.offset + 1;
      const end = Math.min(
        factInspectorState.pagination.offset + factInspectorState.facts.length,
        factInspectorState.pagination.total
      );
      
      const infoEl = document.getElementById('factPaginationInfo');
      if (infoEl) {
        infoEl.textContent = `Showing ${start}-${end} of ${formatValue(factInspectorState.pagination.total)}`;
      }
      
      const prevBtn = document.getElementById('factPrevBtn');
      const nextBtn = document.getElementById('factNextBtn');
      
      if (prevBtn) prevBtn.disabled = factInspectorState.pagination.offset === 0;
      if (nextBtn) nextBtn.disabled = !factInspectorState.pagination.has_more;
    }
  }

  /**
   * Generate a readable summary from fact details
   */
  function generateFactSummary(fact) {
    const details = fact.details || {};
    const keys = fact.entity_keys || {};
    
    // Different summaries by fact type
    switch (fact.fact_type) {
      case 'Exec':
      case 'ProcessCreate':
        return details.image || details.exe || details.cmdline || keys.proc_key || 'Process execution';
      case 'FileCreate':
        return details.target_filename || details.file_path || keys.file_key || 'File created';
      case 'FileDelete':
        return details.target_filename || details.file_path || 'File deleted';
      case 'NetworkConnect':
        const dst = details.dest_ip || details.destination_ip || '';
        const port = details.dest_port || details.destination_port || '';
        return dst ? `${dst}:${port}` : 'Network connection';
      case 'DnsQuery':
        return details.query_name || details.dns_query || 'DNS query';
      case 'RegistryEvent':
      case 'RegistrySetValue':
        return details.target_object || details.registry_key || 'Registry operation';
      case 'Login':
      case 'Logon':
        return details.user_name || details.account_name || keys.user_key || 'User logon';
      case 'ProcSpawn':
        return details.child_image || details.parent_image || 'Process spawn';
      default:
        // Try to find something useful in details
        const values = Object.values(details).filter(v => typeof v === 'string' && v.length < 100);
        return values[0] || fact.fact_type;
    }
  }

  /**
   * Get badge color for fact type
   */
  function getFactTypeColor(factType) {
    const colors = {
      'Exec': '#4CAF50',
      'ProcessCreate': '#4CAF50',
      'ProcSpawn': '#8BC34A',
      'FileCreate': '#2196F3',
      'FileDelete': '#F44336',
      'NetworkConnect': '#9C27B0',
      'DnsQuery': '#673AB7',
      'RegistryEvent': '#FF9800',
      'RegistrySetValue': '#FF9800',
      'Login': '#00BCD4',
      'Logon': '#00BCD4',
      'ImageLoad': '#607D8B'
    };
    return colors[factType] || '#757575';
  }

  /**
   * Show fact detail in side drawer
   */
  function showFactDetailDrawer(fact) {
    const drawer = document.getElementById('factDetailDrawer');
    const content = document.getElementById('factDetailContent');
    
    if (!drawer || !content) return;
    
    // Format timestamp
    const tsDisplay = fact.ts ? new Date(fact.ts).toISOString() : '—';
    
    // Build detail view
    let html = `
      <div style="margin-bottom: 16px;">
        <div style="font-size: 10px; color: var(--muted); text-transform: uppercase; margin-bottom: 4px;">Fact ID</div>
        <div style="font-family: monospace; font-size: 11px; word-break: break-all;">${escapeHtml(fact.fact_id)}</div>
      </div>
      
      <div style="margin-bottom: 16px;">
        <div style="font-size: 10px; color: var(--muted); text-transform: uppercase; margin-bottom: 4px;">Type</div>
        <span style="background: ${getFactTypeColor(fact.fact_type)}; color: white; font-size: 12px; padding: 3px 8px; border-radius: 3px;">${escapeHtml(fact.fact_type)}</span>
        ${fact.category ? `<span style="background: var(--panel); border: 1px solid var(--border); font-size: 11px; padding: 2px 6px; border-radius: 3px; margin-left: 6px;">${escapeHtml(fact.category)}</span>` : ''}
      </div>
      
      <div style="margin-bottom: 16px;">
        <div style="font-size: 10px; color: var(--muted); text-transform: uppercase; margin-bottom: 4px;">Timestamp</div>
        <div style="font-family: monospace; font-size: 12px;">${escapeHtml(tsDisplay)}</div>
      </div>
      
      <div style="margin-bottom: 16px;">
        <div style="font-size: 10px; color: var(--muted); text-transform: uppercase; margin-bottom: 4px;">Host</div>
        <div style="font-size: 12px;">${escapeHtml(fact.host || '—')}</div>
      </div>
    `;
    
    // Entity Key section
    if (fact.entity_key) {
      html += `
        <div style="margin-bottom: 16px;">
          <div style="font-size: 10px; color: var(--muted); text-transform: uppercase; margin-bottom: 4px;">Entity Key</div>
          <div style="font-family: monospace; font-size: 12px; word-break: break-all; background: var(--panel); padding: 8px; border-radius: var(--radius-sm);">${escapeHtml(fact.entity_key)}</div>
        </div>
      `;
    }
    
    // Legacy entity_keys section (backwards compat)
    if (fact.entity_keys && Object.keys(fact.entity_keys).length > 0) {
      html += `
        <div style="margin-bottom: 16px;">
          <div style="font-size: 10px; color: var(--muted); text-transform: uppercase; margin-bottom: 8px;">Entity Keys</div>
          <div style="background: var(--panel); padding: 10px; border-radius: var(--radius-sm); font-size: 11px;">
      `;
      Object.entries(fact.entity_keys).forEach(([key, value]) => {
        if (value) {
          html += `<div style="margin-bottom: 4px;"><span style="color: var(--muted);">${escapeHtml(key)}:</span> <span style="font-family: monospace; word-break: break-all;">${escapeHtml(String(value))}</span></div>`;
        }
      });
      html += `</div></div>`;
    }
    
    // Full Fact JSON section (TWEAK B - for Fact Inspector)
    if (fact.fact_full && typeof fact.fact_full === 'object' && Object.keys(fact.fact_full).length > 0) {
      html += `
        <div style="margin-bottom: 16px;">
          <div style="font-size: 10px; color: var(--muted); text-transform: uppercase; margin-bottom: 8px;">📋 Full Fact (Raw)</div>
          <pre style="background: var(--panel); padding: 10px; border-radius: var(--radius-sm); font-size: 10px; max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; margin: 0; border: 1px solid var(--border);">${escapeHtml(JSON.stringify(fact.fact_full, null, 2))}</pre>
        </div>
      `;
    } else if (fact.details && Object.keys(fact.details).length > 0) {
      // Fallback to details if fact_full not present
      html += `
        <div style="margin-bottom: 16px;">
          <div style="font-size: 10px; color: var(--muted); text-transform: uppercase; margin-bottom: 8px;">Details</div>
          <div style="background: var(--panel); padding: 10px; border-radius: var(--radius-sm); font-size: 11px; max-height: 300px; overflow-y: auto;">
      `;
      Object.entries(fact.details).forEach(([key, value]) => {
        const displayValue = typeof value === 'object' ? JSON.stringify(value) : String(value);
        html += `<div style="margin-bottom: 6px;">
          <div style="color: var(--muted); font-size: 10px;">${escapeHtml(key)}</div>
          <div style="font-family: monospace; word-break: break-all; padding: 2px 0;">${escapeHtml(displayValue)}</div>
        </div>`;
      });
      html += `</div></div>`;
    }
    
    // Evidence Pointers section
    if (fact.evidence && fact.evidence !== null && (Array.isArray(fact.evidence) ? fact.evidence.length > 0 : true)) {
      html += `
        <div style="margin-bottom: 16px;">
          <div style="font-size: 10px; color: var(--muted); text-transform: uppercase; margin-bottom: 8px;">📎 Evidence Pointers</div>
          <pre style="background: var(--panel); padding: 10px; border-radius: var(--radius-sm); font-size: 10px; max-height: 150px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; margin: 0;">${escapeHtml(JSON.stringify(fact.evidence, null, 2))}</pre>
        </div>
      `;
    }
    
    // Copy JSON button (copy full fact if available, otherwise the fact object)
    const copyTarget = fact.fact_full || fact;
    html += `
      <div style="margin-top: 16px;">
        <button onclick="navigator.clipboard.writeText(JSON.stringify(${escapeHtml(JSON.stringify(copyTarget))}, null, 2)).then(() => { this.textContent = '✓ Copied!'; setTimeout(() => this.textContent = '📋 Copy as JSON', 1500); })" 
                style="background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 8px 16px; font-size: 12px; cursor: pointer; color: var(--text); width: 100%;">
          📋 Copy as JSON
        </button>
      </div>
    `;
    
    content.innerHTML = html;
    drawer.classList.remove('hidden');
  }

  /**
   * Update data sources display based on run info
   * Shows actual ETW channels that provided telemetry
   */
  function updateDataSourcesUI(run) {
    if (!els.dataSources) return;
    
    // Build sources from observed channels or signal types
    const sources = new Set();
    
    // Check for actual channel data from run state
    const channels = run.observed_channels || run.channels || state.runState?.channels || [];
    if (channels.length > 0) {
      channels.forEach(ch => {
        // Map channel names to friendly display names
        const name = typeof ch === 'string' ? ch : (ch.name || ch.channel);
        if (name) {
          if (name.includes('Security')) sources.add('Security');
          else if (name.includes('Sysmon')) sources.add('Sysmon');
          else if (name.includes('PowerShell')) sources.add('PowerShell');
          else if (name.includes('System')) sources.add('System');
          else if (name.includes('Microsoft-Windows-')) {
            // Extract provider name
            const provider = name.replace('Microsoft-Windows-', '').split('/')[0];
            sources.add(provider);
          } else {
            sources.add(name);
          }
        }
      });
    }
    
    // Derive from signal types if no channel data
    if (sources.size === 0 && state.signals.length > 0) {
      state.signals.forEach(sig => {
        const sigType = sig.signal_type || '';
        if (sigType.includes('Process')) sources.add('Process');
        if (sigType.includes('File')) sources.add('File');
        if (sigType.includes('Network') || sigType.includes('Dns')) sources.add('Network');
        if (sigType.includes('Registry')) sources.add('Registry');
        if (sigType.includes('WMI')) sources.add('WMI');
        if (sigType.includes('PowerShell')) sources.add('PowerShell');
        if (sigType.includes('Login') || sigType.includes('Auth')) sources.add('Security');
      });
    }
    
    // Final fallback based on run metadata
    if (sources.size === 0) {
      if (run.events_total > 0 || run.event_count > 0) {
        sources.add('Windows ETW');
      } else {
        sources.add('No data');
      }
    }
    
    // Render as badges
    els.dataSources.innerHTML = Array.from(sources).slice(0, 6).map(src => 
      `<span class="badge badge-live" style="font-size: 11px;">${escapeHtml(src)}</span>`
    ).join('');
  }

  /**
   * Switch run detail tab
   */
  function switchRunTab(tabName) {
    const previousTab = state.currentRunTab;
    state.currentRunTab = tabName;
    
    // Stop explain refresh when leaving Explain tab
    if (previousTab === 'explain' && tabName !== 'explain') {
      stopExplainRefresh();
    }
    
    // Update tab buttons
    if (els.runTabs) {
      els.runTabs.forEach(tab => {
        const isActive = tab.dataset.runTab === tabName;
        tab.classList.toggle('active', isActive);
        tab.style.color = isActive ? 'var(--text)' : 'var(--muted)';
        tab.style.borderBottomColor = isActive ? 'var(--accent)' : 'transparent';
      });
    }
    
    // Hide all tab contents
    [els.runTabOverview, els.runTabChanges, els.runTabFindings, els.runTabPlaybooks, els.runTabFacts, els.runTabTimeline, els.runTabExplain, els.runTabExplore, els.runTabRaw].forEach(el => {
      if (el) el.classList.add('hidden');
    });
    
    // Show selected tab content
    switch (tabName) {
      case 'overview':
        if (els.runTabOverview) els.runTabOverview.classList.remove('hidden');
        break;
      case 'changes':
        if (els.runTabChanges) els.runTabChanges.classList.remove('hidden');
        renderChangesTab();
        break;
      case 'findings':
        if (els.runTabFindings) els.runTabFindings.classList.remove('hidden');
        renderFindingsTab();
        break;
      case 'playbooks':
        if (els.runTabPlaybooks) els.runTabPlaybooks.classList.remove('hidden');
        renderPlaybooksTab();
        break;
      case 'facts':
        if (els.runTabFacts) els.runTabFacts.classList.remove('hidden');
        renderFactsTab();
        break;
      case 'timeline':
        if (els.runTabTimeline) els.runTabTimeline.classList.remove('hidden');
        renderTimelineTab();
        break;
      case 'explain':
        if (els.runTabExplain) els.runTabExplain.classList.remove('hidden');
        renderExplainTab();
        // Resume explain refresh if signal selected and explanation unavailable
        if (state.selectedSignalId && state.signalExplanation?.available === false) {
          startExplainRefresh(state.selectedSignalId);
        }
        break;
      case 'explore':
        if (els.runTabExplore) els.runTabExplore.classList.remove('hidden');
        renderExploreTab();
        break;
      case 'raw':
        if (els.runTabRaw) els.runTabRaw.classList.remove('hidden');
        renderRawTab();
        break;
    }
  }

  /**
   * Render the "No Security Telemetry" panel with readiness snapshot details
   * Uses security_log_accessible as authoritative blocker; admin status as contributing factor
   */
  function renderNoTelemetryPanel(readiness) {
    if (!els.factsNoTelemetryReasons || !els.factsNoTelemetryFixes) return;
    
    const reasons = [];
    const fixes = [];
    
    // PRIMARY BLOCKER: security_log_accessible is the authoritative check
    if (readiness.security_log_accessible === false) {
      const adminNote = readiness.is_admin === false 
        ? ' (not running as Administrator)' 
        : '';
      reasons.push(`
        <div style="display: flex; align-items: flex-start; gap: 8px; margin-bottom: 8px;">
          <span style="color: var(--error);">✗</span>
          <div>
            <strong>Security Event Log: Not Accessible</strong>${adminNote}
            <div style="font-size: 11px; color: var(--muted); margin-top: 2px;">
              Windows Security log contains logon, process creation, and privilege events required for detection.
            </div>
          </div>
        </div>
      `);
      fixes.push(`
        <div style="margin-bottom: 12px; padding: 10px; background: var(--panel); border-radius: var(--radius-sm); border-left: 3px solid var(--accent);">
          <strong style="color: var(--accent);">🔧 Fix it: Run as Administrator</strong>
          <div style="font-size: 11px; color: var(--muted); margin-top: 4px;">
            1. Close this application<br>
            2. Right-click <code style="background: var(--panel2); padding: 1px 4px; border-radius: 2px;">locint.exe</code> (or shortcut)<br>
            3. Select <strong>"Run as administrator"</strong><br>
            4. Re-run your capture
          </div>
        </div>
      `);
    }
    
    // SECONDARY: Sysmon provides richer telemetry
    if (readiness.sysmon_installed === false) {
      reasons.push(`
        <div style="display: flex; align-items: flex-start; gap: 8px; margin-bottom: 8px;">
          <span style="color: var(--warning);">⚠</span>
          <div>
            <strong>Sysmon: Not Installed</strong>
            <div style="font-size: 11px; color: var(--muted); margin-top: 2px;">
              Sysmon provides detailed process, network, and file events. Many playbooks rely on Sysmon telemetry.
            </div>
          </div>
        </div>
      `);
      fixes.push(`
        <div style="margin-bottom: 12px; padding: 10px; background: var(--panel); border-radius: var(--radius-sm); border-left: 3px solid var(--warn);">
          <strong style="color: var(--warn);">🔧 Fix it: Install Sysmon</strong>
          <div style="font-size: 11px; color: var(--muted); margin-top: 4px;">
            1. Download from <a href="https://docs.microsoft.com/sysinternals/downloads/sysmon" target="_blank" style="color: var(--accent);">Microsoft Sysinternals</a><br>
            2. Open an Administrator command prompt<br>
            3. Run: <code style="background: var(--panel2); padding: 1px 4px; border-radius: 2px;">sysmon -accepteula -i</code><br>
            4. Re-run your capture
          </div>
        </div>
      `);
    }
    
    // Fallback: No specific issues identified
    if (reasons.length === 0) {
      reasons.push(`
        <div style="display: flex; align-items: flex-start; gap: 8px; margin-bottom: 8px;">
          <span style="color: var(--muted);">○</span>
          <div>
            <strong>No actionable telemetry captured</strong>
            <div style="font-size: 11px; color: var(--muted); margin-top: 2px;">
              The capture ran but did not collect security-relevant events. This may be normal for short captures.
            </div>
          </div>
        </div>
      `);
      fixes.push(`
        <div style="margin-bottom: 12px; padding: 10px; background: var(--panel); border-radius: var(--radius-sm); border-left: 3px solid var(--muted);">
          <strong>Recommendations</strong>
          <div style="font-size: 11px; color: var(--muted); margin-top: 4px;">
            • Run as Administrator for Security log access<br>
            • Install Sysmon for detailed process telemetry<br>
            • Run capture for longer duration (30+ seconds)
          </div>
        </div>
      `);
    }
    
    // Render into the DOM
    els.factsNoTelemetryReasons.innerHTML = reasons.join('');
    els.factsNoTelemetryFixes.innerHTML = fixes.join('');
  }

  /**
   * Render Findings tab
   */
  function renderFindingsTab() {
    // Check if endpoint available
    if (state.capabilities.signals === false) {
      if (els.findingsEmpty) els.findingsEmpty.classList.add('hidden');
      if (els.findingsContent) els.findingsContent.classList.add('hidden');
      if (els.findingsUnavailable) els.findingsUnavailable.classList.remove('hidden');
      if (els.findingsMissingEndpoint) els.findingsMissingEndpoint.textContent = '(missing: /api/signals)';
      return;
    }
    
    if (els.findingsUnavailable) els.findingsUnavailable.classList.add('hidden');
    
    // Get filtered signals
    const severityFilter = els.findingsSeverityFilter?.value || '';
    let filtered = state.signals;
    if (severityFilter) {
      filtered = state.signals.filter(s => s.severity === severityFilter);
    }
    
    if (filtered.length === 0) {
      if (els.findingsContent) els.findingsContent.classList.add('hidden');
      if (els.findingsEmpty) els.findingsEmpty.classList.remove('hidden');
      return;
    }
    
    if (els.findingsEmpty) els.findingsEmpty.classList.add('hidden');
    if (els.findingsContent) els.findingsContent.classList.remove('hidden');
    
    // Update count
    if (els.findingsCount) {
      els.findingsCount.textContent = `${filtered.length} finding${filtered.length !== 1 ? 's' : ''}`;
    }
    
    // Render findings list
    if (els.findingsList) {
      els.findingsList.innerHTML = filtered.map(sig => {
        const isSelected = sig.signal_id === state.selectedSignalId;
        const severityClass = {
          'critical': 'badge-error',
          'high': 'badge-error',
          'medium': 'badge-running',
          'low': 'badge-stopped'
        }[sig.severity] || 'badge-stopped';
        
        const ts = new Date(sig.ts || 0).toLocaleTimeString();
        const entity = sig.proc_key || sig.file_key || sig.identity_key || sig.host || '—';
        const displayEntity = entity.length > 30 ? entity.slice(0, 30) + '...' : entity;
        
        return `
          <div class="finding-item ${isSelected ? 'selected' : ''}" data-signal-id="${sig.signal_id}" style="padding: 10px 12px; background: ${isSelected ? 'var(--panel2)' : 'var(--panel)'}; border: 1px solid ${isSelected ? 'var(--accent)' : 'var(--border)'}; border-radius: var(--radius-sm); cursor: pointer; transition: all 0.15s;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 4px;">
              <span style="font-size: 13px; font-weight: 500;">${sig.signal_type || 'Unknown'}</span>
              <span class="badge ${severityClass}" style="font-size: 10px; padding: 2px 6px;">${sig.severity || 'unknown'}</span>
            </div>
            <div style="font-size: 11px; color: var(--muted);">
              <span>${ts}</span> · <span title="${entity}">${displayEntity}</span>
            </div>
          </div>
        `;
      }).join('');
      
      // Bind click events
      els.findingsList.querySelectorAll('.finding-item').forEach(el => {
        el.addEventListener('click', () => selectSignal(el.dataset.signalId));
      });
    }
  }

  /**
   * Render Changes tab (Diff v2 - deterministic, evidence-backed)
   */
  async function renderChangesTab() {
    if (!state.selectedRunId) return;
    
    // Show loading
    if (els.changesLoading) els.changesLoading.classList.remove('hidden');
    if (els.changesEmpty) els.changesEmpty.classList.add('hidden');
    if (els.changesContent) els.changesContent.classList.add('hidden');
    if (els.changesUnavailable) els.changesUnavailable.classList.add('hidden');
    
    // Get current diff mode and params
    const mode = els.diffModeSelect?.value || 'phase';
    let diffUrl = `/api/runs/${state.selectedRunId}/diff?mode=${mode}`;
    
    if (mode === 'phase') {
      const mins = els.diffPhaseMinutes?.value || 2;
      diffUrl += `&phase_minutes=${mins}`;
    } else if (mode === 'baseline') {
      const baselineId = els.diffBaselineRunId?.value;
      if (!baselineId) {
        if (els.changesLoading) els.changesLoading.classList.add('hidden');
        if (els.changesUnavailable) els.changesUnavailable.classList.remove('hidden');
        if (els.changesMissingEndpoint) {
          els.changesMissingEndpoint.textContent = 'Select a baseline run to compare against';
        }
        return;
      }
      diffUrl += `&baseline_run_id=${encodeURIComponent(baselineId)}`;
    } else if (mode === 'marker') {
      const markerTs = els.diffMarkerTs?.value;
      if (!markerTs) {
        if (els.changesLoading) els.changesLoading.classList.add('hidden');
        if (els.changesUnavailable) els.changesUnavailable.classList.remove('hidden');
        if (els.changesMissingEndpoint) {
          els.changesMissingEndpoint.textContent = 'Enter a timestamp (ms) to split on';
        }
        return;
      }
      diffUrl += `&marker_ts=${markerTs}`;
    }
    
    // Add filters
    const catFilter = els.diffCategoryFilter?.value;
    const dirFilter = els.diffDirectionFilter?.value;
    if (catFilter) diffUrl += `&category=${encodeURIComponent(catFilter)}`;
    if (dirFilter) diffUrl += `&direction=${encodeURIComponent(dirFilter)}`;
    
    try {
      const data = await api(diffUrl);
      
      if (els.changesLoading) els.changesLoading.classList.add('hidden');
      
      if (!data || !data.available) {
        if (els.changesUnavailable) els.changesUnavailable.classList.remove('hidden');
        if (els.changesMissingEndpoint) {
          els.changesMissingEndpoint.textContent = data?.message || data?.reason || '(endpoint unavailable)';
        }
        return;
      }
      
      const changes = data.changes || [];
      const highlights = data.highlights || [];
      const categories = data.stats?.by_category || {};
      const directions = data.stats?.by_direction || {};
      const stats = data.stats || {};
      const caveats = data.telemetry_caveats || [];
      const comparison = data.comparison || '';
      
      if (changes.length === 0) {
        if (els.changesEmpty) els.changesEmpty.classList.remove('hidden');
        return;
      }
      
      if (els.changesContent) els.changesContent.classList.remove('hidden');
      
      // Update comparison header
      if (els.diffComparisonLabel) {
        els.diffComparisonLabel.textContent = `📊 ${comparison} (${stats.total_changes || 0} changes)`;
      }
      
      // Show/hide telemetry caveats
      if (caveats.length > 0 && els.diffCaveatsBanner) {
        els.diffCaveatsBanner.classList.remove('hidden');
        if (els.diffCaveatsList) {
          els.diffCaveatsList.innerHTML = caveats.map(c => `<div style="margin-bottom: 4px;">${escapeHtml(c)}</div>`).join('');
        }
      } else if (els.diffCaveatsBanner) {
        els.diffCaveatsBanner.classList.add('hidden');
      }
      
      // Update stats
      if (els.changesTotalCount) els.changesTotalCount.textContent = stats.total_changes || 0;
      if (els.changesAddedCount) els.changesAddedCount.textContent = directions.added || 0;
      if (els.changesRemovedCount) els.changesRemovedCount.textContent = directions.removed || 0;
      if (els.changesModifiedCount) {
        const modCount = (directions.modified || 0) + (directions.increased || 0) + (directions.decreased || 0);
        els.changesModifiedCount.textContent = modCount;
      }
      
      // Render highlights
      if (els.changesHighlightsList) {
        if (highlights.length === 0) {
          els.changesHighlightsList.innerHTML = '<div style="color: var(--muted); font-size: 12px;">No high-severity changes detected</div>';
        } else {
          els.changesHighlightsList.innerHTML = highlights.map(h => renderDiffChangeItem(h, true)).join('');
        }
      }
      
      // Render categories
      if (els.changesCategoriesList) {
        const categoryColors = {
          'Process': 'var(--accent)',
          'File': 'var(--warn)',
          'Network': 'var(--info)',
          'Persistence': 'var(--bad)',
          'Auth': 'var(--muted)',
          'Evasion': 'var(--bad)',
          'Other': 'var(--muted)'
        };
        els.changesCategoriesList.innerHTML = Object.entries(categories)
          .sort((a, b) => b[1] - a[1])
          .map(([cat, count]) => `
            <span style="padding: 4px 10px; background: ${categoryColors[cat] || 'var(--panel2)'}22; 
                         border: 1px solid ${categoryColors[cat] || 'var(--border)'}44; 
                         border-radius: var(--radius-sm); font-size: 12px; color: var(--text); cursor: pointer;"
                  onclick="document.getElementById('diffCategoryFilter').value='${cat}'; document.getElementById('btnRefreshDiff').click();">
              ${cat}: <strong>${count}</strong>
            </span>
          `).join('');
      }
      
      // Render all changes
      if (els.changesAllList) {
        els.changesAllList.innerHTML = changes.slice(0, 100).map(c => renderDiffChangeItem(c, false)).join('');
        
        // Bind click events for evidence viewing
        els.changesAllList.querySelectorAll('.diff-change-item[data-has-evidence="true"]').forEach(el => {
          el.addEventListener('click', () => {
            const changeId = el.dataset.changeId;
            const change = changes.find(c => c.change_id === changeId);
            if (change && change.evidence_ptrs && change.evidence_ptrs.length > 0) {
              showEvidenceViewer(change.evidence_ptrs, change.title);
            }
          });
        });
      }
      
    } catch (err) {
      console.error('[Diff v2] Error:', err);
      if (els.changesLoading) els.changesLoading.classList.add('hidden');
      if (els.changesUnavailable) els.changesUnavailable.classList.remove('hidden');
      if (els.changesMissingEndpoint) {
        els.changesMissingEndpoint.textContent = `(error: ${err.message || 'network error'})`;
      }
    }
  }
  
  /**
   * Render a single Diff v2 change item
   */
  function renderDiffChangeItem(change, isHighlight) {
    const severityColors = {
      'critical': 'var(--bad)',
      'high': 'var(--bad)',
      'medium': 'var(--warn)',
      'low': 'var(--muted)',
      'info': 'var(--muted)'
    };
    const color = severityColors[change.severity] || severityColors[change.severity_hint] || 'var(--muted)';
    
    const directionIcons = {
      'added': '➕',
      'removed': '➖',
      'increased': '📈',
      'decreased': '📉',
      'modified': '✏️'
    };
    const dirIcon = directionIcons[change.direction] || '📋';
    
    const categoryIcon = {
      'process': '⚙️',
      'file': '📁',
      'network': '🌐',
      'persistence': '🔒',
      'auth': '🔑',
      'evasion': '🛡️',
      'other': '📋'
    }[change.category?.toLowerCase()] || '📋';
    
    const ts = change.ts_ms ? new Date(change.ts_ms).toLocaleTimeString() : '';
    const evidenceCount = (change.evidence_ptrs || []).length;
    const hasEvidence = evidenceCount > 0;
    
    const directionBadge = change.direction ? `
      <span style="font-size: 10px; padding: 2px 6px; background: ${
        change.direction === 'added' ? 'var(--good)' :
        change.direction === 'removed' ? 'var(--bad)' : 'var(--warn)'
      }22; border-radius: 2px; color: ${
        change.direction === 'added' ? 'var(--good)' :
        change.direction === 'removed' ? 'var(--bad)' : 'var(--warn)'
      };">${dirIcon} ${change.direction}</span>
    ` : '';
    
    return `
      <div class="diff-change-item" 
           data-change-id="${change.change_id}"
           data-has-evidence="${hasEvidence}"
           style="padding: ${isHighlight ? '12px' : '8px'} 12px; 
                  background: var(--panel); 
                  border: 1px solid var(--border); 
                  border-left: 3px solid ${color};
                  border-radius: var(--radius-sm);
                  ${hasEvidence ? 'cursor: pointer;' : ''}">
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
          <div style="flex: 1;">
            <span style="font-size: 12px;">${categoryIcon}</span>
            <span style="font-size: 13px; font-weight: 500; margin-left: 4px;">${change.title || 'Unknown change'}</span>
            ${directionBadge}
          </div>
          <span style="font-size: 10px; color: var(--muted);">${ts}</span>
        </div>
        <div style="font-size: 12px; color: var(--text); margin-top: 4px;">
          ${escapeHtml(change.summary || '')}
        </div>
        <div style="display: flex; gap: 8px; margin-top: 6px; font-size: 11px; color: var(--muted); flex-wrap: wrap;">
          <span style="padding: 2px 6px; background: var(--panel2); border-radius: 2px;">${change.category}</span>
          <span style="padding: 2px 6px; background: ${color}22; border-radius: 2px; color: ${color};">${change.severity}</span>
          ${hasEvidence ? `<span style="color: var(--good);">🔗 ${evidenceCount} evidence</span>` : 
            (change.evidence_unavailable_reason ? `<span style="color: var(--warn);" title="${escapeHtml(change.evidence_unavailable_reason)}">⚠️ No evidence</span>` : '')}
          ${change.supporting_facts_count > 0 ? `<span>${change.supporting_facts_count} facts</span>` : ''}
        </div>
        ${change.severity_basis ? `<div style="font-size: 10px; color: var(--muted); margin-top: 4px; font-style: italic;">📝 ${escapeHtml(change.severity_basis)}</div>` : ''}
      </div>
    `;
  }
  
  /**
   * Show evidence viewer modal for a change
   */
  function showEvidenceViewer(evidencePtrs, title) {
    // Simple modal for evidence viewing - could be enhanced
    const evidenceList = evidencePtrs.map((ptr, i) => {
      const ptrStr = typeof ptr === 'string' ? ptr : JSON.stringify(ptr, null, 2);
      return `<div style="margin-bottom: 8px; padding: 8px; background: var(--panel2); border-radius: 4px; font-family: monospace; font-size: 11px; overflow-x: auto;">
        <div style="color: var(--muted); margin-bottom: 4px;">#${i + 1}</div>
        <div>${escapeHtml(ptrStr)}</div>
      </div>`;
    }).join('');
    
    // Use existing modal infrastructure or create simple overlay
    const existingModal = document.getElementById('evidenceViewerModal');
    if (existingModal) {
      existingModal.remove();
    }
    
    const modal = document.createElement('div');
    modal.id = 'evidenceViewerModal';
    modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 10000; display: flex; align-items: center; justify-content: center;';
    modal.innerHTML = `
      <div style="background: var(--bg); border: 1px solid var(--border); border-radius: 8px; max-width: 600px; max-height: 80vh; overflow: auto; padding: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
          <h3 style="margin: 0; font-size: 16px;">🔗 Evidence for: ${escapeHtml(title || 'Change')}</h3>
          <button onclick="this.closest('#evidenceViewerModal').remove()" style="background: none; border: none; color: var(--muted); cursor: pointer; font-size: 20px;">&times;</button>
        </div>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 12px;">${evidencePtrs.length} evidence pointer(s)</div>
        ${evidenceList}
      </div>
    `;
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.remove();
    });
    document.body.appendChild(modal);
  }
  
  /**
   * Initialize Diff v2 UI controls
   */
  function initDiffV2Controls() {
    // Mode selector
    if (els.diffModeSelect) {
      els.diffModeSelect.addEventListener('change', () => {
        const mode = els.diffModeSelect.value;
        
        // Show/hide mode-specific options
        if (els.diffPhaseOptions) els.diffPhaseOptions.style.display = mode === 'phase' ? 'flex' : 'none';
        if (els.diffBaselineOptions) els.diffBaselineOptions.style.display = mode === 'baseline' ? 'flex' : 'none';
        if (els.diffMarkerOptions) els.diffMarkerOptions.style.display = mode === 'marker' ? 'flex' : 'none';
        
        // Load baseline runs list if switching to baseline mode
        if (mode === 'baseline') {
          loadBaselineRunsList();
        }
      });
    }
    
    // Refresh button
    if (els.btnRefreshDiff) {
      els.btnRefreshDiff.addEventListener('click', () => {
        renderChangesTab();
      });
    }
    
    // Filter change handlers
    if (els.diffCategoryFilter) {
      els.diffCategoryFilter.addEventListener('change', () => renderChangesTab());
    }
    if (els.diffDirectionFilter) {
      els.diffDirectionFilter.addEventListener('change', () => renderChangesTab());
    }
  }
  
  /**
   * Load available runs for baseline comparison
   */
  async function loadBaselineRunsList() {
    if (!els.diffBaselineRunId) return;
    
    try {
      const data = await api('/api/runs');
      if (data && data.runs) {
        // Filter out current run
        const otherRuns = data.runs.filter(r => r.run_id !== state.selectedRunId);
        els.diffBaselineRunId.innerHTML = '<option value="">Select a run...</option>' +
          otherRuns.map(r => `<option value="${r.run_id}">${r.run_id} (${r.signal_count || 0} signals)</option>`).join('');
      }
    } catch (err) {
      console.error('[Diff v2] Failed to load baseline runs:', err);
    }
  }
  
  /**
   * Render a single change item (legacy, for backward compat)
   */
  function renderChangeItem(change, isHighlight) {
    // Delegate to new renderer
    return renderDiffChangeItem(change, isHighlight);
  }

  /**
   * Render Playbooks tab (Layer 2 Explainability) - with slot progress (Part B)
   */
  async function renderPlaybooksTab() {
    if (!state.selectedRunId) return;
    
    // Show loading
    if (els.playbooksLoading) els.playbooksLoading.classList.remove('hidden');
    if (els.playbooksDisabled) els.playbooksDisabled.classList.add('hidden');
    if (els.playbooksContent) els.playbooksContent.classList.add('hidden');
    if (els.playbooksUnavailable) els.playbooksUnavailable.classList.add('hidden');
    
    try {
      const data = await api(`/api/runs/${state.selectedRunId}/playbooks`);
      
      if (els.playbooksLoading) els.playbooksLoading.classList.add('hidden');
      
      if (!data || !data.available) {
        if (els.playbooksUnavailable) els.playbooksUnavailable.classList.remove('hidden');
        if (els.playbooksMissingEndpoint) {
          els.playbooksMissingEndpoint.textContent = data?.reason || '(endpoint unavailable)';
        }
        return;
      }
      
      // Check if playbooks are enabled
      if (!data.playbooks_enabled) {
        if (els.playbooksDisabled) els.playbooksDisabled.classList.remove('hidden');
        return;
      }
      
      if (els.playbooksContent) els.playbooksContent.classList.remove('hidden');
      
      // Update stats
      if (els.playbooksLoadedCount) els.playbooksLoadedCount.textContent = data.loaded_count || 0;
      if (els.playbooksFiredCount) els.playbooksFiredCount.textContent = data.fired_count || 0;
      
      // Part B: Count partial matches and blocked playbooks (excluding not_selected)
      const allEvals = data.playbook_evals || [];
      // Filter out not_selected by default (unless showUnselected is true)
      const evals = state.playbookSelection.showUnselected 
        ? allEvals 
        : allEvals.filter(e => e.status !== 'not_selected');
      const notSelectedCount = allEvals.filter(e => e.status === 'not_selected').length;
      const partialCount = evals.filter(e => e.status === 'partial').length;
      const blockedCount = data.telemetry_blocked_count || evals.filter(e => e.telemetry_blocked).length;
      if (els.playbooksPartialCount) els.playbooksPartialCount.textContent = partialCount;
      if (els.playbooksBlockedCount) els.playbooksBlockedCount.textContent = blockedCount;
      
      // Part B: Show explanation banner
      if (els.playbooksExplanation && data.explanation) {
        els.playbooksExplanation.querySelector('div').textContent = data.explanation;
        els.playbooksExplanation.classList.remove('hidden');
      } else if (els.playbooksExplanation) {
        els.playbooksExplanation.classList.add('hidden');
      }
      
      if (els.playbooksDirPath) els.playbooksDirPath.textContent = data.playbooks_dir || '—';
      
      const matches = data.matches || [];
      
      // Render matches
      if (matches.length === 0) {
        if (els.playbooksNoMatches) els.playbooksNoMatches.classList.remove('hidden');
        if (els.playbooksMatchesList) els.playbooksMatchesList.classList.add('hidden');
      } else {
        if (els.playbooksNoMatches) els.playbooksNoMatches.classList.add('hidden');
        if (els.playbooksMatchesList) {
          els.playbooksMatchesList.classList.remove('hidden');
          els.playbooksMatchesList.innerHTML = matches.map(m => {
            const severityClass = {
              'critical': 'badge-error',
              'high': 'badge-error',
              'medium': 'badge-running',
              'low': 'badge-stopped'
            }[m.severity] || 'badge-stopped';
            
            const ts = m.ts ? new Date(m.ts).toLocaleTimeString() : '';
            const mitre = m.mitre_technique ? `<span style="font-family: monospace; font-size: 10px; padding: 2px 4px; background: var(--panel2); border-radius: 2px;">${m.mitre_technique}</span>` : '';
            
            return `
              <div class="playbook-match" style="padding: 10px 12px; background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius-sm);">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 4px;">
                  <span style="font-size: 13px; font-weight: 500;">📓 ${m.playbook || m.signal_type}</span>
                  <span class="badge ${severityClass}" style="font-size: 10px; padding: 2px 6px;">${m.severity || 'unknown'}</span>
                </div>
                <div style="font-size: 11px; color: var(--muted);">
                  <span>${ts}</span>
                  ${m.host ? ` · <span>${m.host}</span>` : ''}
                  ${mitre ? ` · ${mitre}` : ''}
                </div>
                ${m.description ? `<div style="font-size: 12px; color: var(--text); margin-top: 6px;">${m.description}</div>` : ''}
              </div>
            `;
          }).join('');
        }
      }
      
      // Part B: Render near-misses section
      const nearMisses = data.top_near_misses || [];
      if (nearMisses.length > 0 && els.playbooksNearMissesSection && els.playbooksNearMissesList) {
        els.playbooksNearMissesSection.classList.remove('hidden');
        els.playbooksNearMissesList.innerHTML = nearMisses.map(pb => renderPlaybookEvalCard(pb, true)).join('');
      } else if (els.playbooksNearMissesSection) {
        els.playbooksNearMissesSection.classList.add('hidden');
      }
      
      // Part B: Render all playbook evaluations (filtered for selected only by default)
      if (els.playbooksEvalList && evals.length > 0) {
        els.playbooksEvalList.innerHTML = evals.map(pb => renderPlaybookEvalCard(pb, false)).join('');
        
        // Set up filter (status filter + show unselected toggle)
        if (els.playbooksStatusFilter) {
          els.playbooksStatusFilter.onchange = () => {
            const filter = els.playbooksStatusFilter.value;
            // Re-apply not_selected filter based on showUnselected state
            const baseFiltered = state.playbookSelection.showUnselected 
              ? allEvals 
              : allEvals.filter(e => e.status !== 'not_selected');
            const filtered = filter ? baseFiltered.filter(e => e.status === filter) : baseFiltered;
            els.playbooksEvalList.innerHTML = filtered.map(pb => renderPlaybookEvalCard(pb, false)).join('');
            // Re-bind click handlers after filter change
            bindPlaybookEvalCardClicks();
          };
        }
        
        // Show "X unselected playbooks hidden" hint if applicable
        if (notSelectedCount > 0 && !state.playbookSelection.showUnselected) {
          const existingHint = document.getElementById('unselectedPlaybooksHint');
          if (existingHint) existingHint.remove();
          
          const hintEl = document.createElement('div');
          hintEl.id = 'unselectedPlaybooksHint';
          hintEl.style.cssText = 'padding: 8px 12px; background: var(--panel2); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;';
          hintEl.innerHTML = `
            <span style="font-size: 11px; color: var(--muted);">
              ${notSelectedCount} unselected playbook(s) hidden
            </span>
            <button id="btnShowUnselected" style="font-size: 10px; padding: 3px 8px; background: var(--panel); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; color: var(--muted);">
              Show all
            </button>
          `;
          els.playbooksEvalList.parentNode.insertBefore(hintEl, els.playbooksEvalList);
          
          document.getElementById('btnShowUnselected').onclick = () => {
            state.playbookSelection.showUnselected = true;
            hintEl.remove();
            // Re-render with all evals
            els.playbooksEvalList.innerHTML = allEvals.map(pb => renderPlaybookEvalCard(pb, false)).join('');
            bindPlaybookEvalCardClicks();
          };
        }
      }
      
      // Bind click handlers for playbook eval cards
      bindPlaybookEvalCardClicks();
      
      // Render by category
      const byCategory = data.by_category || {};
      if (Object.keys(byCategory).length > 0) {
        if (els.playbooksByCategorySection) els.playbooksByCategorySection.classList.remove('hidden');
        if (els.playbooksCategoriesList) {
          els.playbooksCategoriesList.innerHTML = Object.entries(byCategory)
            .map(([tactic, playbooks]) => `
              <span style="padding: 4px 10px; background: var(--panel2); border: 1px solid var(--border); 
                           border-radius: var(--radius-sm); font-size: 12px; color: var(--text);">
                ${tactic}: <strong>${playbooks.length}</strong>
              </span>
            `).join('');
        }
      } else {
        if (els.playbooksByCategorySection) els.playbooksByCategorySection.classList.add('hidden');
      }
      
    } catch (err) {
      console.error('[Playbooks] Error:', err);
      if (els.playbooksLoading) els.playbooksLoading.classList.add('hidden');
      if (els.playbooksUnavailable) els.playbooksUnavailable.classList.remove('hidden');
      if (els.playbooksMissingEndpoint) {
        els.playbooksMissingEndpoint.textContent = '(network error)';
      }
    }
  }

  /**
   * Render a single playbook evaluation card (Part B)
   */
  function renderPlaybookEvalCard(pb, highlight) {
    const statusColors = {
      'fired': 'var(--accent)',
      'partial': 'var(--warn)',
      'no_match': 'var(--muted)',
      'telemetry_missing': 'var(--error)',
      'not_selected': 'var(--muted)',
      'skipped': 'var(--muted)'
    };
    const statusIcons = {
      'fired': '✓',
      'partial': '◐',
      'no_match': '○',
      'telemetry_missing': '⚠',
      'not_selected': '⊘',
      'skipped': '—'
    };
    const statusLabels = {
      'fired': 'FIRED',
      'partial': 'PARTIAL',
      'no_match': 'NO MATCH',
      'telemetry_missing': 'BLOCKED',
      'not_selected': 'NOT SELECTED',
      'skipped': 'SKIPPED'
    };
    
    const borderColor = statusColors[pb.status] || 'var(--muted)';
    const icon = statusIcons[pb.status] || '?';
    const completionPct = Math.round((pb.completion_ratio || 0) * 100);
    
    // Not selected note
    const notSelectedNote = pb.status === 'not_selected' ? `
      <div style="font-size: 10px; color: var(--muted); margin-top: 4px; font-style: italic;">
        Not included in this run's playbook selection
      </div>
    ` : '';
    
    // Progress bar for partial matches
    const progressBar = pb.total_slots > 0 && pb.status !== 'not_selected' ? `
      <div style="margin-top: 6px; height: 4px; background: var(--panel2); border-radius: 2px; overflow: hidden;">
        <div style="height: 100%; width: ${completionPct}%; background: ${borderColor};"></div>
      </div>
      <div style="font-size: 10px; color: var(--muted); margin-top: 2px;">
        ${pb.matched_slots}/${pb.total_slots} slots filled (${completionPct}%)
      </div>
    ` : '';
    
    // Missing slots detail
    const missingSlotsHtml = (pb.missing_slot_names || []).length > 0 && pb.status !== 'not_selected' ? `
      <div style="font-size: 10px; color: var(--muted); margin-top: 4px;">
        Missing: ${pb.missing_slot_names.slice(0, 3).join(', ')}${pb.missing_slot_names.length > 3 ? '...' : ''}
      </div>
    ` : '';
    
    // Telemetry blocked warning
    const blockedNote = pb.telemetry_blocked ? `
      <div style="font-size: 10px; color: var(--error); margin-top: 4px;">
        ⚠ Blocked: ${pb.requires_sysmon ? 'Sysmon required' : ''}${pb.requires_security_log ? 'Security log required' : ''}
      </div>
    ` : '';
    
    // Evidence pointers for fired playbooks (Part 2 enhancement)
    const evidenceHtml = pb.status === 'fired' && (pb.evidence_ptrs_sample || []).length > 0 ? `
      <div style="font-size: 10px; color: var(--accent); margin-top: 4px;">
        📋 ${pb.evidence_ptrs_sample.length} evidence item(s)
      </div>
    ` : '';
    
    // Why not fired explanation
    const whyNotHtml = pb.why_not_fired && pb.status !== 'fired' && pb.status !== 'not_selected' ? `
      <div style="font-size: 11px; color: var(--muted); margin-top: 4px; font-style: italic;">
        ${escapeHtml(pb.why_not_fired)}
      </div>
    ` : '';
    
    // Status badge text
    const statusLabel = statusLabels[pb.status] || pb.status;
    
    return `
      <div class="playbook-eval-card" data-playbook-id="${escapeHtml(pb.playbook_id)}" 
           style="padding: 10px 12px; background: var(--panel); border: 1px solid var(--border); cursor: pointer;
                  border-left: 3px solid ${borderColor}; border-radius: var(--radius-sm); transition: background 0.15s;
                  ${highlight ? 'box-shadow: 0 1px 3px rgba(0,0,0,0.1);' : ''}
                  ${pb.status === 'not_selected' ? 'opacity: 0.6;' : ''}"
           onmouseover="this.style.background='var(--panel2)'" onmouseout="this.style.background='var(--panel)'">
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
          <div>
            <span style="color: ${borderColor}; font-weight: 600;">${icon}</span>
            <span style="font-size: 13px; font-weight: 500; margin-left: 6px;">${pb.playbook_name}</span>
          </div>
          <div style="display: flex; align-items: center; gap: 6px;">
            <span style="font-size: 10px; padding: 2px 6px; background: var(--panel2); border-radius: 2px; color: var(--muted);">
              ${statusLabel}
            </span>
            <span style="font-size: 12px; color: var(--muted);">›</span>
          </div>
        </div>
        ${pb.category ? `<div style="font-size: 11px; color: var(--muted); margin-top: 2px;">${pb.category}</div>` : ''}
        ${notSelectedNote}
        ${progressBar}
        ${missingSlotsHtml}
        ${blockedNote}
        ${evidenceHtml}
        ${whyNotHtml}
      </div>
    `;
  }
  
  /**
   * Bind click handlers for playbook eval cards after rendering
   * Must be called after rendering the playbooks list
   */
  function bindPlaybookEvalCardClicks() {
    const cards = document.querySelectorAll('.playbook-eval-card[data-playbook-id]');
    cards.forEach(card => {
      card.onclick = () => {
        const playbookId = card.dataset.playbookId;
        // Find in run context first, then fall back to catalog
        let playbook = state.run.playbook_evaluations?.find(p => p.playbook_id === playbookId);
        if (playbook) {
          // Enhance run playbook with catalog data if available
          const catalogPb = detectionPlanCatalog?.find(p => p.playbook_id === playbookId);
          if (catalogPb) {
            playbook = { ...catalogPb, ...playbook };
          }
          openPlaybookDetailDrawer(playbook, 'run');
        } else {
          // Try catalog
          const catalogPb = detectionPlanCatalog?.find(p => p.playbook_id === playbookId);
          if (catalogPb) {
            openPlaybookDetailDrawer(catalogPb, 'catalog');
          }
        }
      };
    });
  }

  /**
   * Render Timeline tab
   */
  function renderTimelineTab() {
    // Check if endpoint available
    if (state.capabilities.signals === false) {
      if (els.timelineEmpty) els.timelineEmpty.classList.add('hidden');
      if (els.timelineContent) els.timelineContent.classList.add('hidden');
      if (els.timelineUnavailable) els.timelineUnavailable.classList.remove('hidden');
      if (els.timelineMissingEndpoint) els.timelineMissingEndpoint.textContent = '(missing: /api/signals)';
      return;
    }
    
    if (els.timelineUnavailable) els.timelineUnavailable.classList.add('hidden');
    
    if (state.signals.length === 0) {
      if (els.timelineContent) els.timelineContent.classList.add('hidden');
      if (els.timelineEmpty) els.timelineEmpty.classList.remove('hidden');
      return;
    }
    
    if (els.timelineEmpty) els.timelineEmpty.classList.add('hidden');
    if (els.timelineContent) els.timelineContent.classList.remove('hidden');
    
    // Sort by timestamp
    const sorted = [...state.signals].sort((a, b) => (a.ts || 0) - (b.ts || 0));
    
    // Render timeline
    if (els.timelineList) {
      els.timelineList.innerHTML = sorted.map(sig => {
        const ts = new Date(sig.ts || 0);
        const timeStr = ts.toLocaleTimeString();
        const severityColor = {
          'critical': 'var(--bad)',
          'high': 'var(--bad)',
          'medium': 'var(--warn)',
          'low': 'var(--muted)'
        }[sig.severity] || 'var(--muted)';
        
        return `
          <div class="timeline-entry" data-signal-id="${sig.signal_id}" style="position: relative; padding: 8px 0; cursor: pointer;">
            <div style="position: absolute; left: -21px; top: 12px; width: 10px; height: 10px; background: ${severityColor}; border-radius: 50%; border: 2px solid var(--panel);"></div>
            <div style="font-size: 11px; color: var(--muted); margin-bottom: 2px;">${timeStr}</div>
            <div style="font-size: 13px; font-weight: 500;">${sig.signal_type || 'Unknown'}</div>
            <div style="font-size: 12px; color: var(--muted);">${sig.host || '—'}</div>
          </div>
        `;
      }).join('');
      
      // Bind click events
      els.timelineList.querySelectorAll('.timeline-entry').forEach(el => {
        el.addEventListener('click', () => {
          selectSignal(el.dataset.signalId);
          switchRunTab('explain');
        });
      });
    }
  }

  /**
   * Select a signal/finding and load explanation
   */
  async function selectSignal(signalId) {
    // Stop any existing explain refresh loop (user selected different signal)
    stopExplainRefresh();
    
    state.selectedSignalId = signalId;
    state.selectedSignal = state.signals.find(s => s.signal_id === signalId);
    state.signalExplanation = null;
    state.signalNarrative = null;
    
    // Re-render findings to show selection
    if (state.currentRunTab === 'findings') {
      renderFindingsTab();
    }
    
    // If on explain tab, render it
    if (state.currentRunTab === 'explain') {
      renderExplainTab();
      // Fetch explanation in background
      loadSignalExplanation(signalId);
    }
    
    // If on raw tab, render it
    if (state.currentRunTab === 'raw') {
      renderRawTab();
    }
  }

  /**
   * Load explanation and narrative for a signal
   * Starts auto-refresh loop if explanation is unavailable during active run.
   */
  async function loadSignalExplanation(signalId) {
    // Fetch explanation
    state.signalExplanation = await fetchSignalExplanation(signalId);
    
    // Fetch narrative
    state.signalNarrative = await fetchSignalNarrative(signalId);
    
    // Re-render explain tab with data
    if (state.currentRunTab === 'explain') {
      renderExplainTab();
      
      // Start auto-refresh if explanation is unavailable
      const explainResp = state.signalExplanation || {};
      if (explainResp.available === false) {
        startExplainRefresh(signalId);
      }
    }
  }

  /**
   * Render Explain tab
   * CONTRACT: Uses canonical ExplainResponse schema from API_CONTRACT_CORE.md
   */
  function renderExplainTab() {
    // No signal selected - show run-level summary instead
    if (!state.selectedSignalId || !state.selectedSignal) {
      if (els.explainContent) els.explainContent.classList.add('hidden');
      if (els.explainUnavailable) els.explainUnavailable.classList.add('hidden');
      if (els.explainUnavailableBanner) els.explainUnavailableBanner.classList.add('hidden');
      if (els.explainSelectPrompt) {
        els.explainSelectPrompt.classList.remove('hidden');
        // Render run-level summary in the prompt area
        renderRunLevelExplain(els.explainSelectPrompt);
      }
      return;
    }
    
    if (els.explainSelectPrompt) els.explainSelectPrompt.classList.add('hidden');
    
    // Check if explain endpoint available
    if (state.capabilities.signalExplain === false) {
      if (els.explainContent) els.explainContent.classList.add('hidden');
      if (els.explainUnavailable) els.explainUnavailable.classList.remove('hidden');
      if (els.explainMissingEndpoint) els.explainMissingEndpoint.textContent = '(missing: /api/signals/:id/explain)';
      return;
    }
    
    if (els.explainUnavailable) els.explainUnavailable.classList.add('hidden');
    
    const sig = state.selectedSignal;
    // CONTRACT: ExplainResponse shape from API_CONTRACT_CORE.md
    const explainResp = state.signalExplanation || {};
    const explainAvailable = explainResp.available !== false;
    const narrative = state.signalNarrative;
    
    // Extract canonical fields per contract
    // source can be a string (e.g., "signal_explanations") or object {kind, id}
    const sourceRaw = explainResp.source;
    const source = typeof sourceRaw === 'object' ? sourceRaw : { kind: 'unknown', id: sourceRaw };
    const evidencePtrs = explainResp.evidence_ptrs || sig.evidence_ptrs || [];
    const evidenceCount = explainResp.evidence_ptrs_count ?? evidencePtrs.length;
    const confidence = explainResp.confidence;
    const signal = explainResp.signal || sig;
    const explanation = explainResp.explanation || {};
    const matchedSlots = explainResp.matched_slots;
    const narrativeText = explainResp.narrative;
    
    // Show unavailable banner if not available
    if (els.explainUnavailableBanner) {
      if (!explainAvailable) {
        els.explainUnavailableBanner.classList.remove('hidden');
        if (els.explainUnavailableReason) {
          els.explainUnavailableReason.textContent = `Explanation unavailable: ${explainResp.reason_code || 'UNKNOWN'}`;
        }
        if (els.explainUnavailableMessage) {
          els.explainUnavailableMessage.textContent = explainResp.message || 'Details not available';
        }
      } else {
        els.explainUnavailableBanner.classList.add('hidden');
      }
    }
    
    // Show content area
    if (els.explainContent) els.explainContent.classList.remove('hidden');
    
    // === EXPLAIN HEADER (canonical summary) ===
    // Source: Playbook <id> / Detector <id> / Unknown
    if (els.explainHeaderSource) {
      // Try to determine source from explanation or signal_type
      const kind = source.kind || (explanation?.playbook_id ? 'playbook' : 'unknown');
      const sourceId = source.id || explanation?.playbook_id || sig.signal_type;
      if (kind === 'playbook' || explanation?.playbook_id) {
        const pbName = explanation?.playbook_title || sourceId?.replace('playbook:', '') || 'unknown';
        els.explainHeaderSource.textContent = `Playbook: ${pbName}`;
      } else if (kind === 'detector') {
        const detName = sourceId?.replace('detector:', '') || 'unknown';
        els.explainHeaderSource.textContent = `Detector: ${detName}`;
      } else {
        els.explainHeaderSource.textContent = sourceId || 'Unknown';
      }
    }
    
    // Evidence count
    if (els.explainHeaderEvidence) {
      els.explainHeaderEvidence.textContent = `${evidenceCount} pointer${evidenceCount !== 1 ? 's' : ''}`;
    }
    
    // Confidence
    if (els.explainHeaderConfidence) {
      if (confidence != null && typeof confidence === 'number') {
        els.explainHeaderConfidence.textContent = `${(confidence * 100).toFixed(0)}%`;
      } else {
        els.explainHeaderConfidence.textContent = '—';
      }
    }
    
    // Run context
    if (els.explainHeaderRun) {
      const runId = signal.run_id || state.selectedRunId || state.signalsRunId;
      const ts = signal.ts_ms || sig.ts;
      const tsFormatted = ts ? new Date(ts).toLocaleString() : '';
      if (runId) {
        els.explainHeaderRun.innerHTML = `<span title="${runId}">${runId.slice(0, 20)}${runId.length > 20 ? '...' : ''}</span>`;
        if (tsFormatted) {
          els.explainHeaderRun.innerHTML += `<div style="font-size: 10px; color: var(--muted); margin-top: 2px;">${tsFormatted}</div>`;
        }
      } else {
        els.explainHeaderRun.textContent = '—';
      }
    }
    
    // === Signal Details Header ===
    if (els.explainSignalType) els.explainSignalType.textContent = sig.signal_type || 'Unknown Signal';
    if (els.explainSignalId) els.explainSignalId.textContent = sig.signal_id || '—';
    if (els.explainSeverity) {
      els.explainSeverity.textContent = sig.severity || 'unknown';
      const severityClass = {
        'critical': 'badge-error',
        'high': 'badge-error',
        'medium': 'badge-running',
        'low': 'badge-stopped'
      }[sig.severity] || 'badge-stopped';
      els.explainSeverity.className = `badge ${severityClass}`;
    }
    
    // === Narrative summary ===
    if (els.explainNarrative) {
      if (!explainAvailable) {
        // Unavailable - show partial context only
        const partial = explainResp.partial_context;
        if (partial) {
          els.explainNarrative.innerHTML = `<span style="color: var(--muted);">Showing partial signal context only.</span>`;
        } else {
          els.explainNarrative.innerHTML = `<span style="color: var(--muted);">No context available.</span>`;
        }
      } else if (narrativeText) {
        // CONTRACT: Use narrative field from response
        els.explainNarrative.textContent = narrativeText;
      } else if (narrative?.sentences?.length > 0) {
        els.explainNarrative.textContent = narrative.sentences.map(s => s.text).join(' ');
      } else if (explanation?.summary) {
        els.explainNarrative.textContent = explanation.summary;
      } else if (explanation?.why_fired) {
        els.explainNarrative.textContent = explanation.why_fired;
      } else {
        els.explainNarrative.textContent = sig.metadata?.description || 'No narrative available.';
      }
    }
    
    // === Detector / Playbook ===
    if (els.explainPlaybook) {
      els.explainPlaybook.textContent = source.id || explanation?.playbook_id || explanation?.playbook || sig.signal_type || '—';
    }
    if (els.explainDetectorVersion) {
      els.explainDetectorVersion.textContent = source.version || explanation?.detector_version || '—';
    }
    
    // === Entities ===
    if (els.explainEntities) {
      const entities = [];
      
      // From signal
      if (sig.proc_key) entities.push({ type: 'process', value: sig.proc_key });
      if (sig.file_key) entities.push({ type: 'file', value: sig.file_key });
      if (sig.identity_key) entities.push({ type: 'user', value: sig.identity_key });
      if (sig.host || signal.host) entities.push({ type: 'host', value: sig.host || signal.host });
      
      // From narrative
      if (narrative?.entities) {
        (narrative.entities.processes || []).forEach(p => entities.push({ type: 'process', value: p }));
        (narrative.entities.users || []).forEach(u => entities.push({ type: 'user', value: u }));
        (narrative.entities.hosts || []).forEach(h => entities.push({ type: 'host', value: h }));
      }
      
      // Dedupe
      const seen = new Set();
      const unique = entities.filter(e => {
        const key = `${e.type}:${e.value}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
      
      if (unique.length === 0) {
        els.explainEntities.innerHTML = '<span style="color: var(--muted);">No entities identified</span>';
      } else {
        els.explainEntities.innerHTML = unique.map(e => {
          const icon = { process: '⚙️', file: '📄', user: '👤', host: '🖥️' }[e.type] || '•';
          const displayVal = e.value.length > 40 ? e.value.slice(0, 40) + '...' : e.value;
          return `<span class="badge badge-stopped" style="font-size: 11px;" title="${e.value}">${icon} ${displayVal}</span>`;
        }).join('');
      }
    }
    
    // === Evidence pointers (CONTRACT: use evidence_ptrs from response) ===
    if (els.explainEvidence) {
      // Get evidence diagnostics from backend
      const evidenceDiag = explainResp.evidence_diagnostics || {};
      const droppedCount = explainResp.dropped_evidence_count || evidenceDiag.dropped_count || 0;
      
      if (evidenceCount === 0) {
        // Show explicit reason for missing evidence
        const evidenceReason = explainResp.evidence_unavailable_reason;
        if (evidenceReason) {
          const reasonCode = evidenceReason.code || 'UNKNOWN';
          const reasonMsg = evidenceReason.message || 'Evidence pointers not available';
          const actionHint = getEvidenceActionHint(reasonCode);
          els.explainEvidence.innerHTML = `
            <div style="padding: 10px; background: rgba(251, 191, 36, 0.1); border: 1px solid var(--warn); border-radius: var(--radius-sm);">
              <div style="font-size: 12px; color: var(--warn); font-weight: 500; margin-bottom: 4px;">⚠️ Evidence Unavailable: ${reasonCode}</div>
              <div style="font-size: 11px; color: var(--muted);">${escapeHtml(reasonMsg)}</div>
              ${actionHint ? `<div style="font-size: 11px; color: var(--accent); margin-top: 6px;">💡 ${escapeHtml(actionHint)}</div>` : ''}
              ${droppedCount > 0 ? `<div style="font-size: 10px; color: var(--error); margin-top: 6px;">📉 ${droppedCount} evidence pointer(s) were dropped</div>` : ''}
            </div>
          `;
        } else {
          els.explainEvidence.innerHTML = `
            <div style="padding: 10px; background: var(--panel2); border-radius: var(--radius-sm);">
              <div style="font-size: 12px; color: var(--muted);">No evidence pointers linked to this finding.</div>
              <div style="font-size: 11px; color: var(--muted); margin-top: 4px;">This may indicate the analysis pipeline did not link raw events to the signal.</div>
              ${droppedCount > 0 ? `<div style="font-size: 10px; color: var(--error); margin-top: 6px;">📉 ${droppedCount} evidence pointer(s) were dropped during pipeline processing</div>` : ''}
            </div>
          `;
        }
      } else {
        // Show pointers header with diagnostics
        const health = evidenceDiag.health || 'unknown';
        const healthIcon = { full: '✅', partial: '⚠️', degraded: '❌', dropped: '📉', none: '—' }[health] || '❓';
        const dereferenceableCount = evidenceDiag.dereferenceable_count ?? evidenceCount;
        
        let headerHtml = `
          <div style="margin-bottom: 10px; padding: 8px; background: var(--panel2); border-radius: var(--radius-sm); display: flex; justify-content: space-between; align-items: center;">
            <div>
              <span style="font-size: 12px;">${healthIcon} <strong>${evidenceCount}</strong> evidence pointer${evidenceCount !== 1 ? 's' : ''}</span>
              ${dereferenceableCount < evidenceCount ? `<span style="font-size: 11px; color: var(--warn); margin-left: 8px;">(${dereferenceableCount} viewable)</span>` : ''}
            </div>
            ${droppedCount > 0 ? `<span style="font-size: 10px; color: var(--error);">📉 ${droppedCount} dropped</span>` : ''}
          </div>
        `;
        
        // Show issues if any
        const issues = evidenceDiag.issues || [];
        if (issues.length > 0) {
          headerHtml += `
            <div style="margin-bottom: 10px; padding: 8px; background: rgba(251, 191, 36, 0.1); border: 1px solid var(--warn); border-radius: var(--radius-sm);">
              <div style="font-size: 11px; color: var(--warn); font-weight: 500; margin-bottom: 4px;">⚠️ Pipeline Issues:</div>
              ${issues.map(issue => `<div style="font-size: 11px; color: var(--muted);">• ${escapeHtml(issue)}</div>`).join('')}
            </div>
          `;
        }
        
        // Show pointers - clickable for segment_record kind
        const currentRunId = state.currentRun?.run_id || sig.run_id;
        let html = evidencePtrs.map((ptr, i) => {
          // Determine if this pointer is dereferenceable
          const kind = ptr.kind || 'segment_record';
          const isDereferenceable = kind === 'segment_record' && 
            ptr.stream_id != null && 
            ptr.segment_id != null && 
            ptr.record_index != null;
          
          const ptrStr = typeof ptr === 'object' ? JSON.stringify(ptr, null, 2) : String(ptr);
          const ptrSummary = ptr.summary || `${ptr.stream_id || '?'}:${ptr.segment_id ?? '?'}:${ptr.record_index ?? '?'}`;
          
          if (isDereferenceable) {
            return `
              <div class="evidence-ptr-item" 
                   data-ptr-index="${i}"
                   data-run-id="${escapeHtml(currentRunId || '')}"
                   data-stream-id="${escapeHtml(ptr.stream_id || '')}"
                   data-segment-id="${escapeHtml(String(ptr.segment_id ?? ''))}"
                   data-record-index="${ptr.record_index ?? ''}"
                   style="margin-bottom: 6px; padding: 8px; background: var(--panel2); border-radius: 4px; cursor: pointer; border: 1px solid var(--border); transition: border-color 0.15s;"
                   onmouseover="this.style.borderColor='var(--accent)'"
                   onmouseout="this.style.borderColor='var(--border)'">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                  <span style="font-family: monospace; font-size: 11px; color: var(--accent);">📋 ${i + 1}. ${escapeHtml(ptrSummary)}</span>
                  <span style="font-size: 10px; color: var(--good);">Click to view</span>
                </div>
              </div>`;
          } else {
            return `<div style="margin-bottom: 4px; font-family: monospace; font-size: 11px; color: var(--muted);">${i + 1}. ${escapeHtml(ptrStr)}</div>`;
          }
        }).join('');
        
        els.explainEvidence.innerHTML = headerHtml + html;
        
        // Bind click handlers for dereferenceable pointers
        const ptrItems = els.explainEvidence.querySelectorAll('.evidence-ptr-item');
        ptrItems.forEach(item => {
          item.addEventListener('click', () => {
            const runId = item.dataset.runId;
            const streamId = item.dataset.streamId;
            const segmentId = item.dataset.segmentId;  // Now a string filename
            const recordIndex = item.dataset.recordIndex;
            
            if (runId && segmentId !== '' && recordIndex !== '') {
              openEvidenceViewer({
                run_id: runId,
                stream_id: streamId || '',
                segment_id: segmentId,  // Keep as string (filename like "evtx_000001.jsonl")
                record_index: parseInt(recordIndex, 10),
                kind: 'segment_record'
              });
            }
          });
        });
      }
    }
    
    // === Scoring breakdown (always show something) ===
    if (els.explainScoring) {
      // Get scoring from response - should always be present now
      const scoring = explainResp.scoring || explanation?.scoring;
      
      if (scoring && (scoring.severity || scoring.confidence || scoring.basis || scoring.risk_score != null)) {
        let html = '';
        
        // Check if this is a detailed backend score or a minimal computed score
        if (scoring.risk_score != null) {
          // Detailed backend scoring
          html += `<div style="margin-bottom: 8px; padding: 4px 8px; background: var(--panel2); border-radius: 4px; font-size: 10px; color: var(--muted);">
            🔒 Backend Score (unmodified)
          </div>`;
          html += `<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">`;
          html += `<div><span style="color: var(--muted);">Risk Score:</span> <strong>${(scoring.risk_score * 100).toFixed(0)}%</strong></div>`;
          html += `<div><span style="color: var(--muted);">Base Severity:</span> ${scoring.base_severity || scoring.severity || sig.severity}</div>`;
          
          if (scoring.mahalanobis_distance != null) {
            html += `<div><span style="color: var(--muted);">Mahalanobis:</span> ${scoring.mahalanobis_distance.toFixed(2)}</div>`;
          }
          if (scoring.elliptic_envelope_score != null) {
            html += `<div><span style="color: var(--muted);">Elliptic Envelope:</span> ${scoring.elliptic_envelope_score.toFixed(2)}</div>`;
          }
          html += `</div>`;
          
          if (scoring.scoring_reasons?.length > 0) {
            html += `<div style="margin-top: 12px;"><span style="color: var(--muted); font-size: 12px;">Scoring Reasons:</span></div>`;
            html += `<div style="margin-top: 4px;">`;
            scoring.scoring_reasons.forEach(r => {
              const pct = (r.weight * 100).toFixed(0);
              html += `<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                <div style="flex: 1; font-size: 12px;">${escapeHtml(r.reason)}</div>
                <div style="width: 60px; height: 6px; background: var(--panel2); border-radius: 3px; overflow: hidden;">
                  <div style="width: ${pct}%; height: 100%; background: var(--accent);"></div>
                </div>
                <div style="width: 32px; font-size: 11px; color: var(--muted); text-align: right;">${pct}%</div>
              </div>`;
            });
            html += `</div>`;
          }
        } else {
          // Minimal/computed scoring with basis array
          html += `<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px;">`;
          html += `<div><span style="color: var(--muted);">Severity:</span> <strong>${escapeHtml(scoring.severity || sig.severity)}</strong></div>`;
          html += `<div><span style="color: var(--muted);">Confidence:</span> <strong>${escapeHtml(scoring.confidence || 'unknown')}</strong></div>`;
          html += `</div>`;
          
          // Render basis list
          if (scoring.basis && scoring.basis.length > 0) {
            html += `<div style="margin-top: 8px;"><span style="color: var(--muted); font-size: 12px;">Scoring Basis:</span></div>`;
            html += `<ul style="margin: 4px 0 0 0; padding-left: 20px; font-size: 12px; color: var(--text);">`;
            scoring.basis.forEach(b => {
              html += `<li style="margin-bottom: 2px;">${escapeHtml(b)}</li>`;
            });
            html += `</ul>`;
          }
        }
        
        els.explainScoring.innerHTML = html;
      } else {
        // Truly no scoring - show fallback with signal severity
        els.explainScoring.innerHTML = `
          <div style="padding: 12px;">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 8px;">
              <div><span style="color: var(--muted);">Severity:</span> <strong>${escapeHtml(sig.severity)}</strong></div>
              <div><span style="color: var(--muted);">Confidence:</span> <strong>unknown</strong></div>
            </div>
            <div style="font-size: 11px; color: var(--muted); padding: 8px; background: var(--panel2); border-radius: var(--radius-sm);">
              ℹ️ Detailed scoring not available. The signal fired based on playbook logic.
            </div>
          </div>
        `;
      }
    }
    
    // === Matched slots and facts (always show something) ===
    if (els.explainSlots) {
      const slots = matchedSlots || explanation?.slots;
      // Get matched_facts from response top-level or from explanation object
      const matchedFacts = explainResp.matched_facts || explanation?.matched_facts || [];
      
      let html = '';
      
      // Slot matches section
      if (matchedSlots) {
        html += '<div style="margin-bottom: 12px;">';
        html += '<div style="font-weight: 500; margin-bottom: 8px;">📋 Slot Matches:</div>';
        html += `<div style="padding: 8px; background: var(--panel2); border-radius: var(--radius-sm);">`;
        html += `<div style="margin-bottom: 4px;"><span style="color: var(--muted);">Filled:</span> <strong>${matchedSlots.filled || 0} / ${matchedSlots.total || 0}</strong></div>`;
        if (matchedSlots.names?.length > 0) {
          html += `<div style="margin-top: 4px;"><span style="color: var(--muted);">Slots:</span> ${matchedSlots.names.map(n => `<span class="badge badge-stopped" style="font-size: 10px;">${escapeHtml(n)}</span>`).join(' ')}</div>`;
        }
        html += '</div></div>';
      } else if (slots && (Array.isArray(slots) ? slots.length > 0 : Object.keys(slots).length > 0)) {
        html += '<div style="margin-bottom: 12px;">';
        html += '<div style="font-weight: 500; margin-bottom: 8px;">📋 Slot Values:</div>';
        html += '<div style="padding: 8px; background: var(--panel2); border-radius: var(--radius-sm);">';
        const entries = Array.isArray(slots) ? slots.map((s, i) => [s.name || `slot_${i}`, s]) : Object.entries(slots);
        entries.forEach(([key, val]) => {
          const displayVal = typeof val === 'object' ? JSON.stringify(val) : String(val);
          html += `<div style="margin-bottom: 4px; font-size: 12px;"><span style="color: var(--muted);">${escapeHtml(key)}:</span> <span style="font-family: monospace;">${escapeHtml(displayVal)}</span></div>`;
        });
        html += '</div></div>';
      }
      
      // Matched facts section
      if (matchedFacts.length > 0) {
        html += '<div style="margin-bottom: 12px;">';
        html += '<div style="font-weight: 500; margin-bottom: 8px;">📊 Matched Facts:</div>';
        html += '<div style="max-height: 200px; overflow-y: auto; padding: 8px; background: var(--panel2); border-radius: var(--radius-sm);">';
        matchedFacts.forEach(fact => {
          const factType = fact.fact_type || 'Unknown';
          const entityKeys = fact.entity_keys || {};
          const procKey = entityKeys.proc_key || entityKeys.process || '';
          const ts = fact.ts ? new Date(fact.ts).toLocaleTimeString() : '';
          html += `<div style="margin-bottom: 6px; padding: 4px 6px; background: var(--panel); border-radius: 2px; font-size: 11px;">
            <span class="badge badge-stopped" style="font-size: 9px;">${escapeHtml(factType)}</span>
            ${procKey ? `<span style="margin-left: 6px; font-family: monospace; color: var(--muted);">${escapeHtml(procKey.length > 40 ? procKey.slice(0, 40) + '...' : procKey)}</span>` : ''}
            ${ts ? `<span style="float: right; color: var(--muted);">${ts}</span>` : ''}
          </div>`;
        });
        html += '</div></div>';
      }
      
      // If nothing to show, display explicit message
      if (!html) {
        html = `
          <div style="padding: 12px; background: rgba(251, 191, 36, 0.1); border: 1px solid var(--warn); border-radius: var(--radius-sm);">
            <div style="font-size: 12px; color: var(--warn); font-weight: 500; margin-bottom: 4px;">⚠️ Explainability Linkage Missing</div>
            <div style="font-size: 11px; color: var(--muted);">This finding lacks linked slots and facts. This indicates the analysis pipeline did not record the reasoning chain.</div>
            <div style="font-size: 11px; color: var(--muted); margin-top: 6px;">
              <strong>Signal ID:</strong> ${escapeHtml(sig.signal_id || '—')}<br>
              <strong>Run ID:</strong> ${escapeHtml(state.selectedRunId || '—')}
            </div>
            <div style="margin-top: 8px;">
              <button onclick="switchRunTab('raw')" style="font-size: 11px; padding: 4px 8px; background: var(--panel2); border: 1px solid var(--border); border-radius: 3px; cursor: pointer; color: var(--text);">View Raw JSON →</button>
            </div>
          </div>
        `;
      }
      
      els.explainSlots.innerHTML = html;
    }
  }
  
  /**
   * Get action hint for evidence unavailable reason
   */
  function getEvidenceActionHint(reasonCode) {
    const hints = {
      'IMPORTED_WITHOUT_SEGMENTS': 'Re-import with full segment data to enable evidence linking.',
      'LINKAGE_MISSING': 'This is a pipeline issue. The analysis did not link raw events to the signal.',
      'SENSOR_BLOCKED': 'Run with elevated privileges (Administrator) to access blocked sensors.',
      'REDACTED': 'Evidence has been redacted for privacy. Check export settings.',
      'SIGNAL_NOT_FOUND': 'The signal may have been deleted or the run database is corrupted.',
      'EVIDENCE_DROPPED': 'Evidence pointers exceeded storage limits. Consider shorter capture windows.',
      'NO_EVIDENCE_GENERATED': 'The detector does not generate evidence links. This is expected for some rule types.',
      'UNKNOWN': 'Check the Raw JSON tab for more details.'
    };
    return hints[reasonCode] || null;
  }

  /**
   * Render run-level explanation when no finding is selected
   * Shows: run summary, coverage checklist, capability gaps, "why no/few findings"
   */
  function renderRunLevelExplain(container) {
    if (!container) return;
    
    const run = state.selectedRun;
    const coverage = state.runCoverage;
    const signals = state.signals || [];
    const selfcheck = state.telemetryReadiness;
    
    let html = `<div style="padding: 16px; text-align: left;">`;
    
    // Header
    html += `<div style="font-size: 16px; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
      <span style="font-size: 20px;">📊</span>
      Run-Level Analysis
    </div>`;
    
    // Run summary metrics
    if (run) {
      const signalCount = run.signal_count ?? signals.length;
      const factsCount = coverage?.facts_total ?? run.facts_extracted ?? 0;
      html += `
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px; padding: 12px; background: var(--panel2); border-radius: var(--radius-sm);">
          <div style="text-align: center;">
            <div style="font-size: 20px; font-weight: 700; color: ${signalCount > 0 ? 'var(--warn)' : 'var(--muted)'}">${signalCount}</div>
            <div style="font-size: 11px; color: var(--muted);">Findings</div>
          </div>
          <div style="text-align: center;">
            <div style="font-size: 20px; font-weight: 700;">${factsCount}</div>
            <div style="font-size: 11px; color: var(--muted);">Facts</div>
          </div>
          <div style="text-align: center;">
            <div style="font-size: 20px; font-weight: 700;">${coverage?.fact_types?.length || 0}</div>
            <div style="font-size: 11px; color: var(--muted);">Fact Types</div>
          </div>
        </div>
      `;
    }
    
    // Coverage checklist
    if (coverage?.fact_types?.length > 0) {
      html += `<div style="margin-bottom: 16px;">
        <div style="font-weight: 500; margin-bottom: 8px;">📋 Fact Types Observed:</div>
        <div style="display: flex; flex-wrap: wrap; gap: 6px;">
          ${coverage.fact_types.slice(0, 10).map(ft => 
            `<span class="badge badge-stopped" style="font-size: 11px;">${escapeHtml(ft.fact_type)} (${ft.count})</span>`
          ).join('')}
        </div>
      </div>`;
    }
    
    // Capability gaps from selfcheck
    if (selfcheck?.channels) {
      const blocked = selfcheck.channels.filter(c => !c.accessible);
      if (blocked.length > 0) {
        html += `<div style="margin-bottom: 16px;">
          <div style="font-weight: 500; margin-bottom: 8px; color: var(--warn);">⚠️ Capability Gaps:</div>
          <ul style="margin: 0; padding-left: 20px; font-size: 12px; color: var(--muted);">
            ${blocked.slice(0, 5).map(c => `<li>${escapeHtml(c.name)}: ${c.reason || 'Not accessible'}</li>`).join('')}
          </ul>
        </div>`;
      }
    }
    
    // "Why nothing found" guidance
    if (signals.length === 0) {
      html += `<div style="padding: 12px; background: rgba(251, 191, 36, 0.1); border-radius: var(--radius-sm); border: 1px solid var(--warn);">
        <div style="font-weight: 500; margin-bottom: 8px;">💡 Why No Findings?</div>
        <ul style="margin: 0; padding-left: 20px; font-size: 12px; color: var(--muted);">
          <li>No suspicious patterns matched during the analysis window</li>
          <li>Telemetry may be limited - check Facts tab for data availability</li>
          <li>Consider running with elevated privileges for full coverage</li>
        </ul>
      </div>`;
    } else {
      html += `<div style="padding: 12px; background: var(--panel2); border-radius: var(--radius-sm);">
        <div style="font-weight: 500; margin-bottom: 8px;">💡 Select a Finding</div>
        <div style="font-size: 12px; color: var(--muted);">
          Click on a finding in the Findings tab to view its detailed explanation,
          including evidence pointers, matched facts, and playbook logic.
        </div>
      </div>`;
    }
    
    html += `</div>`;
    container.innerHTML = html;
  }

  /**
   * Render Explore tab (PRO - Entity Explorer)
   * Fetches entities for the current run and allows pivoting to related data
   */
  async function renderExploreTab() {
    // Hide all sub-states first
    if (els.exploreLoading) els.exploreLoading.classList.add('hidden');
    if (els.exploreProLocked) els.exploreProLocked.classList.add('hidden');
    if (els.exploreEmpty) els.exploreEmpty.classList.add('hidden');
    if (els.exploreContent) els.exploreContent.classList.add('hidden');
    if (els.exploreUnavailable) els.exploreUnavailable.classList.add('hidden');

    const runId = state.selectedRunId;
    if (!runId) {
      if (els.exploreEmpty) {
        els.exploreEmpty.classList.remove('hidden');
        els.exploreEmpty.querySelector('div:last-child').textContent = 'Select a run first';
      }
      return;
    }

    // Check if already cached for this run
    if (state.exploreEntities && state.exploreEntitiesRunId === runId) {
      renderExploreEntities();
      return;
    }

    // Show loading
    if (els.exploreLoading) els.exploreLoading.classList.remove('hidden');

    try {
      const res = await fetch(`${API_BASE}/api/runs/${runId}/entities`);
      
      if (res.status === 403) {
        // Pro feature locked
        const data = await res.json();
        if (data.code === 'FEATURE_LOCKED') {
          if (els.exploreLoading) els.exploreLoading.classList.add('hidden');
          if (els.exploreProLocked) els.exploreProLocked.classList.remove('hidden');
          state.capabilities.runEntities = 'locked';
          return;
        }
      }
      
      if (res.status === 404) {
        if (els.exploreLoading) els.exploreLoading.classList.add('hidden');
        if (els.exploreUnavailable) {
          els.exploreUnavailable.classList.remove('hidden');
          if (els.exploreMissingEndpoint) {
            els.exploreMissingEndpoint.textContent = '(missing: /api/runs/:run_id/entities)';
          }
        }
        state.capabilities.runEntities = false;
        return;
      }

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const data = await res.json();
      state.exploreEntities = data;
      state.exploreEntitiesRunId = runId;
      state.capabilities.runEntities = true;
      
      if (els.exploreLoading) els.exploreLoading.classList.add('hidden');
      renderExploreEntities();
      
    } catch (err) {
      console.error('[Explore] Failed to fetch entities:', err);
      if (els.exploreLoading) els.exploreLoading.classList.add('hidden');
      if (els.exploreUnavailable) {
        els.exploreUnavailable.classList.remove('hidden');
        if (els.exploreMissingEndpoint) {
          els.exploreMissingEndpoint.textContent = `(error: ${err.message})`;
        }
      }
    }
  }

  /**
   * Render the entity list with current filters
   */
  function renderExploreEntities() {
    if (!state.exploreEntities) return;
    
    if (els.exploreContent) els.exploreContent.classList.remove('hidden');
    
    const entities = state.exploreEntities;
    const filter = state.exploreTypeFilter;
    const search = state.exploreSearchQuery.toLowerCase();
    
    // Flatten entities into a unified list
    let items = [];
    const typeConfig = {
      processes: { icon: '⚙️', label: 'Process', kind: 'process' },
      files: { icon: '📄', label: 'File', kind: 'file' },
      ips: { icon: '🌐', label: 'IP', kind: 'ip' },
      users: { icon: '👤', label: 'User', kind: 'user' },
      hosts: { icon: '🖥️', label: 'Host', kind: 'host' }
    };
    
    for (const [typeKey, config] of Object.entries(typeConfig)) {
      if (filter !== 'all' && filter !== typeKey) continue;
      
      const typeEntities = entities[typeKey] || [];
      for (const entity of typeEntities) {
        const value = entity.value || entity.name || entity.key || '';
        if (search && !value.toLowerCase().includes(search)) continue;
        
        items.push({
          kind: config.kind,
          value: value,
          count: entity.count || 1,
          first_seen: entity.first_seen,
          last_seen: entity.last_seen,
          top_signals: entity.top_signals || [],
          icon: config.icon,
          label: config.label
        });
      }
    }
    
    // Sort by count descending
    items.sort((a, b) => (b.count || 0) - (a.count || 0));
    
    // Update count
    if (els.exploreEntityCount) {
      els.exploreEntityCount.textContent = `${items.length} entities`;
    }
    
    // Empty state
    if (items.length === 0) {
      if (els.exploreEntityList) {
        els.exploreEntityList.innerHTML = `
          <div style="text-align: center; padding: 24px; color: var(--muted); font-size: 13px;">
            ${search ? 'No entities match your search' : 'No entities found'}
          </div>
        `;
      }
      return;
    }
    
    // Render list
    if (els.exploreEntityList) {
      els.exploreEntityList.innerHTML = items.map(item => {
        const isSelected = state.exploreSelectedEntity && 
          state.exploreSelectedEntity.kind === item.kind && 
          state.exploreSelectedEntity.value === item.value;
        
        const topSignal = item.top_signals?.[0];
        const signalHint = topSignal ? `<span style="font-size: 9px; color: var(--accent);" title="${topSignal}">🚨</span>` : '';
        
        return `
          <div class="explore-entity-item ${isSelected ? 'selected' : ''}" 
               data-kind="${item.kind}" 
               data-value="${escapeHtml(item.value)}"
               style="padding: 8px 10px; margin-bottom: 4px; background: ${isSelected ? 'var(--accent)' : 'var(--panel2)'}; 
                      border-radius: var(--radius-sm); cursor: pointer; transition: background 0.15s;
                      color: ${isSelected ? 'white' : 'var(--text)'};">
            <div style="display: flex; align-items: center; gap: 6px;">
              <span style="font-size: 12px;">${item.icon}</span>
              <span style="font-size: 12px; font-weight: 500; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" 
                    title="${escapeHtml(item.value)}">${escapeHtml(item.value)}</span>
              ${signalHint}
              <span style="font-size: 10px; color: ${isSelected ? 'rgba(255,255,255,0.7)' : 'var(--muted)'};">${item.count}</span>
            </div>
          </div>
        `;
      }).join('');
      
      // Add click handlers
      els.exploreEntityList.querySelectorAll('.explore-entity-item').forEach(el => {
        el.addEventListener('click', () => {
          const kind = el.dataset.kind;
          const value = el.dataset.value;
          selectExploreEntity(kind, value);
        });
      });
    }
  }

  /**
   * Select an entity and fetch its pivot data
   */
  async function selectExploreEntity(kind, value) {
    state.exploreSelectedEntity = { kind, value };
    state.explorePivotResult = null;
    
    // Re-render list to show selection
    renderExploreEntities();
    
    // Update pivot header
    if (els.explorePivotHeader) {
      els.explorePivotHeader.innerHTML = `
        <div style="font-size: 13px; font-weight: 600; color: var(--text);">
          Pivot: <span style="color: var(--accent);">${escapeHtml(value)}</span>
          <span style="font-size: 11px; color: var(--muted); margin-left: 6px;">(${kind})</span>
        </div>
      `;
    }
    
    // Show loading in pivot panel
    if (els.explorePivotEmpty) els.explorePivotEmpty.classList.add('hidden');
    if (els.explorePivotContent) {
      els.explorePivotContent.classList.remove('hidden');
      // Restore structure and show loading
      els.explorePivotContent.innerHTML = `
        <div style="text-align: center; padding: 40px; color: var(--muted);">
          Loading pivot data...
        </div>
      `;
    }
    if (els.explorePivotActions) els.explorePivotActions.classList.add('hidden');
    
    const runId = state.selectedRunId;
    if (!runId) return;
    
    try {
      const res = await fetch(`${API_BASE}/api/runs/${runId}/pivot?kind=${kind}&value=${encodeURIComponent(value)}`);
      
      if (res.status === 403) {
        const data = await res.json();
        if (data.code === 'FEATURE_LOCKED') {
          if (els.explorePivotContent) {
            els.explorePivotContent.innerHTML = `
              <div style="text-align: center; padding: 40px; color: var(--warn);">
                🔒 Pivot requires Pro tier
              </div>
            `;
          }
          return;
        }
      }
      
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      
      const data = await res.json();
      state.explorePivotResult = data;
      state.capabilities.runPivot = true;
      
      renderExplorePivot();
      
    } catch (err) {
      console.error('[Explore] Pivot query failed:', err);
      if (els.explorePivotContent) {
        els.explorePivotContent.innerHTML = `
          <div style="text-align: center; padding: 40px; color: var(--error);">
            Pivot failed: ${err.message}
          </div>
        `;
      }
    }
  }

  /**
   * Render pivot results panel
   */
  function renderExplorePivot() {
    const pivot = state.explorePivotResult;
    if (!pivot) return;
    
    if (els.explorePivotContent) {
      els.explorePivotContent.classList.remove('hidden');
      // Restore structure that may have been replaced with loading/error message
      els.explorePivotContent.innerHTML = `
        <!-- Related Findings -->
        <div id="explorePivotFindings" style="margin-bottom: 16px;">
          <h5 style="font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin: 0 0 8px 0;">
            🚨 Related Findings <span id="explorePivotFindingsCount" style="color: var(--accent);">(0)</span>
          </h5>
          <div id="explorePivotFindingsList" style="display: flex; flex-direction: column; gap: 6px; max-height: 150px; overflow-y: auto;"></div>
        </div>
        
        <!-- Related Changes -->
        <div id="explorePivotChanges" style="margin-bottom: 16px;">
          <h5 style="font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin: 0 0 8px 0;">
            📊 Related Changes <span id="explorePivotChangesCount" style="color: var(--warn);">(0)</span>
          </h5>
          <div id="explorePivotChangesList" style="display: flex; flex-direction: column; gap: 6px; max-height: 150px; overflow-y: auto;"></div>
        </div>
        
        <!-- Evidence Pointers -->
        <div id="explorePivotEvidence" style="margin-bottom: 16px;">
          <h5 style="font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin: 0 0 8px 0;">
            📎 Evidence <span id="explorePivotEvidenceCount" style="color: var(--good);">(0)</span>
          </h5>
          <div id="explorePivotEvidenceList" style="font-size: 11px; background: var(--panel2); padding: 10px; border-radius: var(--radius-sm); max-height: 120px; overflow-y: auto; font-family: monospace;"></div>
        </div>
        
        <!-- Mini Timeline -->
        <div id="explorePivotTimeline">
          <h5 style="font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin: 0 0 8px 0;">
            ⏱️ Mini Timeline
          </h5>
          <div id="explorePivotTimelineList" style="border-left: 2px solid var(--border); margin-left: 8px; padding-left: 12px; max-height: 180px; overflow-y: auto;"></div>
        </div>
      `;
      
      // Re-grab element references since we recreated them
      els.explorePivotFindingsCount = $('#explorePivotFindingsCount');
      els.explorePivotFindingsList = $('#explorePivotFindingsList');
      els.explorePivotChangesCount = $('#explorePivotChangesCount');
      els.explorePivotChangesList = $('#explorePivotChangesList');
      els.explorePivotEvidenceCount = $('#explorePivotEvidenceCount');
      els.explorePivotEvidenceList = $('#explorePivotEvidenceList');
      els.explorePivotTimelineList = $('#explorePivotTimelineList');
    }
    
    // Related Findings
    const findings = pivot.related_findings || [];
    if (els.explorePivotFindingsCount) {
      els.explorePivotFindingsCount.textContent = `(${findings.length})`;
    }
    if (els.explorePivotFindingsList) {
      if (findings.length === 0) {
        els.explorePivotFindingsList.innerHTML = `<div style="font-size: 12px; color: var(--muted); padding: 8px;">No related findings</div>`;
      } else {
        els.explorePivotFindingsList.innerHTML = findings.map(f => `
          <div class="pivot-finding-item" data-signal-id="${f.signal_id}" 
               style="padding: 6px 10px; background: var(--panel2); border-radius: var(--radius-sm); cursor: pointer; font-size: 12px;">
            <div style="display: flex; align-items: center; gap: 6px;">
              <span class="badge badge-${getSeverityClass(f.severity)}" style="font-size: 9px; padding: 2px 6px;">${f.severity || 'medium'}</span>
              <span style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(f.signal_type || 'Unknown')}</span>
            </div>
          </div>
        `).join('');
        
        // Add click handlers to navigate to Explain tab
        els.explorePivotFindingsList.querySelectorAll('.pivot-finding-item').forEach(el => {
          el.addEventListener('click', () => {
            const signalId = el.dataset.signalId;
            if (signalId) {
              state.selectedSignalId = signalId;
              state.selectedSignal = findings.find(f => f.signal_id === signalId) || null;
              switchRunTab('explain');
            }
          });
        });
      }
    }
    
    // Related Changes
    const changes = pivot.related_changes || [];
    if (els.explorePivotChangesCount) {
      els.explorePivotChangesCount.textContent = `(${changes.length})`;
    }
    if (els.explorePivotChangesList) {
      if (changes.length === 0) {
        els.explorePivotChangesList.innerHTML = `<div style="font-size: 12px; color: var(--muted); padding: 8px;">No related changes</div>`;
      } else {
        els.explorePivotChangesList.innerHTML = changes.slice(0, 10).map(c => {
          const dirIcon = c.direction === 'added' ? '➕' : c.direction === 'removed' ? '➖' : '↔️';
          const noveltyBadge = c.novelty === 'new' ? '<span style="font-size: 9px; background: var(--accent); color: white; padding: 1px 4px; border-radius: 3px; margin-left: 4px;">NEW</span>' : '';
          return `
            <div style="padding: 6px 10px; background: var(--panel2); border-radius: var(--radius-sm); font-size: 11px;">
              <div style="display: flex; align-items: center; gap: 6px;">
                <span>${dirIcon}</span>
                <span style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(c.category || 'Change')}: ${escapeHtml(c.label || c.key || '')}</span>
                ${noveltyBadge}
              </div>
            </div>
          `;
        }).join('');
        if (changes.length > 10) {
          els.explorePivotChangesList.innerHTML += `<div style="font-size: 11px; color: var(--muted); padding: 4px; text-align: center;">+${changes.length - 10} more</div>`;
        }
      }
    }
    
    // Evidence Pointers
    const evidence = pivot.related_evidence_ptrs || [];
    if (els.explorePivotEvidenceCount) {
      els.explorePivotEvidenceCount.textContent = `(${evidence.length})`;
    }
    if (els.explorePivotEvidenceList) {
      if (evidence.length === 0) {
        els.explorePivotEvidenceList.innerHTML = `<span style="color: var(--muted);">No evidence pointers</span>`;
      } else {
        els.explorePivotEvidenceList.innerHTML = evidence.slice(0, 20).map(e => 
          `<div style="padding: 2px 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(e)}">${escapeHtml(e)}</div>`
        ).join('');
        if (evidence.length > 20) {
          els.explorePivotEvidenceList.innerHTML += `<div style="color: var(--muted); padding: 4px 0;">+${evidence.length - 20} more</div>`;
        }
      }
    }
    
    // Mini Timeline
    const timeline = pivot.mini_timeline || [];
    if (els.explorePivotTimelineList) {
      if (timeline.length === 0) {
        els.explorePivotTimelineList.innerHTML = `<div style="font-size: 12px; color: var(--muted); padding: 8px;">No timeline events</div>`;
      } else {
        els.explorePivotTimelineList.innerHTML = timeline.slice(0, 15).map(evt => {
          const ts = evt.ts ? new Date(evt.ts).toLocaleTimeString() : '—';
          const typeIcon = evt.type === 'signal' ? '🚨' : evt.type === 'change' ? '📊' : '📎';
          return `
            <div style="padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 11px;">
              <div style="display: flex; align-items: flex-start; gap: 6px;">
                <span style="color: var(--muted); font-size: 10px; min-width: 60px;">${ts}</span>
                <span>${typeIcon}</span>
                <span style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(evt.label || evt.type)}</span>
              </div>
            </div>
          `;
        }).join('');
      }
    }
    
    // Show actions footer if we have findings
    if (els.explorePivotActions) {
      els.explorePivotActions.classList.toggle('hidden', findings.length === 0);
    }
  }

  /**
   * Handle search input in Explore tab
   */
  function handleExploreSearch(query) {
    state.exploreSearchQuery = query;
    renderExploreEntities();
  }

  /**
   * Handle type filter button click in Explore tab
   */
  function handleExploreTypeFilter(type) {
    state.exploreTypeFilter = type;
    
    // Update button states
    document.querySelectorAll('.explore-type-btn').forEach(btn => {
      const isActive = btn.dataset.type === type;
      btn.classList.toggle('active', isActive);
      btn.style.background = isActive ? 'var(--accent)' : 'var(--panel2)';
      btn.style.color = isActive ? 'white' : 'var(--muted)';
    });
    
    renderExploreEntities();
  }

  /**
   * Export case pack for current run
   */
  async function exportCasePack() {
    const runId = state.selectedRunId;
    if (!runId) {
      showToast('No run selected', 'error');
      return;
    }
    
    showToast('Generating case pack...', 'info');
    
    try {
      const res = await fetch(`${API_BASE}/api/runs/${runId}/export/case_pack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          include: { summary: true, findings: true, changes: true, evidence: true, next_steps: true }
        })
      });
      
      if (res.status === 403) {
        const data = await res.json();
        if (data.code === 'FEATURE_LOCKED') {
          showToast('Case Pack export requires Pro tier', 'error');
          return;
        }
      }
      
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      
      // Download the ZIP
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `case_pack_${runId}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      showToast('Case pack downloaded!', 'success');
      state.capabilities.casePack = true;
      
    } catch (err) {
      console.error('[CasePack] Export failed:', err);
      showToast(`Export failed: ${err.message}`, 'error');
    }
  }

  /**
   * Render Raw JSON tab
   */
  function renderRawTab() {
    // No signal selected
    if (!state.selectedSignalId || !state.selectedSignal) {
      if (els.rawContent) els.rawContent.classList.add('hidden');
      if (els.rawSelectPrompt) els.rawSelectPrompt.classList.remove('hidden');
      return;
    }
    
    if (els.rawSelectPrompt) els.rawSelectPrompt.classList.add('hidden');
    if (els.rawContent) els.rawContent.classList.remove('hidden');
    
    // Combine signal with explanation if available
    const rawData = {
      signal: state.selectedSignal,
      explanation: state.signalExplanation,
      narrative: state.signalNarrative
    };
    
    if (els.rawJson) {
      els.rawJson.textContent = JSON.stringify(rawData, null, 2);
    }
  }

  function switchTab(tabName) {
    // Debug: Log scope transition when leaving run view
    if (DEBUG_MODE) {
      const wasInRunScope = isInRunScope();
      if (wasInRunScope && tabName !== 'runs') {
        console.log(`🟢 [SCOPE] Leaving RUN scope, entering LIVE scope (${tabName} tab)`);
      }
    }
    
    state.currentTab = tabName;
    
    // Update tab buttons
    els.tabs.forEach(tab => {
      tab.classList.toggle('active', tab.dataset.tab === tabName);
    });
    
    // Update content
    els.tabContents.forEach(content => {
      const contentTab = content.id.replace('tab', '').toLowerCase();
      content.classList.toggle('hidden', contentTab !== tabName);
    });
    
    // Refresh data when switching to certain tabs
    if (tabName === 'runs' && !state.importedMode) {
      fetchRuns();
    }
    
    // Refresh Team data when switching to Team tab
    if (tabName === 'team') {
      const isTeamTier = state.tier === 'Team' || state.tier === 'Dev';
      const hasStoreFeature = state.features?.case_store === true;
      if (isTeamTier && hasStoreFeature) {
        fetchTeamStoreStatus();
      }
    }
  }

  // ============ EVENT HANDLERS ============
  function bindEvents() {
    // Tab navigation
    els.tabs.forEach(tab => {
      tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });
    
    // Settings gear -> settings tab
    if (els.settingsGear) {
      els.settingsGear.addEventListener('click', () => switchTab('settings'));
    }
    
    // Error banner dismiss
    if (els.errorBannerDismiss) {
      els.errorBannerDismiss.addEventListener('click', hideError);
    }
    
    // Return to local mode button
    if (els.btnReturnToLocal) {
      els.btnReturnToLocal.addEventListener('click', exitImportedMode);
    }
    
    // Mission controls
    if (els.btnStartRun) {
      els.btnStartRun.addEventListener('click', startRun);
    }
    if (els.btnStopRun) {
      els.btnStopRun.addEventListener('click', stopRun);
    }
    
    // Playbook preset selection dropdown
    if (els.playbookPresetSelect) {
      els.playbookPresetSelect.addEventListener('change', handlePlaybookPresetChange);
    }
    
    // Error action buttons
    if (els.btnCopyBuildCmd) {
      els.btnCopyBuildCmd.addEventListener('click', copyBuildCommands);
    }
    if (els.btnRetryStart) {
      els.btnRetryStart.addEventListener('click', async () => {
        hideError();
        const healthy = await checkHealth();
        if (healthy) {
          await checkReadiness();
          await fetchRunStatus();
        }
      });
    }
    
    // Settings - Run checks button
    if (els.btnRunChecks) {
      els.btnRunChecks.addEventListener('click', () => checkReadiness(true));
    }
    
    // Settings - Detection Plan button
    if (els.btnLoadDetectionPlan) {
      els.btnLoadDetectionPlan.addEventListener('click', loadDetectionPlan);
    }
    
    // Mission - Detection Plan button (same handler)
    if (els.btnMissionLoadPlan) {
      els.btnMissionLoadPlan.addEventListener('click', loadDetectionPlan);
    }
    
    // Mission - System Readiness View button
    if (els.btnMissionViewReadiness) {
      els.btnMissionViewReadiness.addEventListener('click', openReadinessModal);
    }
    
    // Mission - System Readiness Re-run button
    if (els.btnMissionRerunReadiness) {
      els.btnMissionRerunReadiness.addEventListener('click', async () => {
        els.btnMissionRerunReadiness.disabled = true;
        els.btnMissionRerunReadiness.textContent = '⏳';
        try {
          await checkReadiness(true);
        } finally {
          els.btnMissionRerunReadiness.disabled = false;
          els.btnMissionRerunReadiness.textContent = 'Re-run';
        }
      });
    }
    
    // Mission - Restart as Administrator button
    if (els.btnRestartAdmin) {
      els.btnRestartAdmin.addEventListener('click', restartAsAdmin);
    }
    
    // Debug: Validation helper - Copy trigger command
    if (els.btnCopyValidationCmd) {
      els.btnCopyValidationCmd.addEventListener('click', copyValidationCommand);
    }
    
    // Show validation helper in debug mode
    if (state.debugMode && els.validationHelper) {
      els.validationHelper.classList.remove('hidden');
    }
    
    // Settings - Wiring Check button
    const btnWiringCheck = document.getElementById('btnWiringCheck');
    if (btnWiringCheck) {
      btnWiringCheck.addEventListener('click', async () => {
        btnWiringCheck.disabled = true;
        btnWiringCheck.textContent = '⏳ Checking...';
        try {
          await runWiringCheck();
        } finally {
          btnWiringCheck.disabled = false;
          btnWiringCheck.textContent = '🔌 Wiring Check';
        }
      });
    }
    
    // View connection details toggle
    if (els.btnViewConnectionDetails) {
      els.btnViewConnectionDetails.addEventListener('click', () => {
        if (els.connectionDetails) {
          const isHidden = els.connectionDetails.classList.toggle('hidden');
          els.btnViewConnectionDetails.textContent = isHidden 
            ? 'View connection details' 
            : 'Hide connection details';
        }
      });
    }
    
    // Runs tab
    if (els.btnGoToMission) {
      els.btnGoToMission.addEventListener('click', () => switchTab('mission'));
    }
    if (els.btnViewFindings) {
      els.btnViewFindings.addEventListener('click', () => {
        if (state.selectedRunId) {
          switchRunTab('findings');
        }
      });
    }
    if (els.btnExportRun) {
      els.btnExportRun.addEventListener('click', () => {
        if (state.selectedRunId) {
          exportBundle(state.selectedRunId);
        }
      });
    }
    
    // Run detail tabs
    if (els.runTabs) {
      els.runTabs.forEach(tab => {
        tab.addEventListener('click', () => switchRunTab(tab.dataset.runTab));
      });
    }
    
    // Findings severity filter
    if (els.findingsSeverityFilter) {
      els.findingsSeverityFilter.addEventListener('change', () => renderFindingsTab());
    }
    
    // Copy raw JSON button
    if (els.btnCopyRawJson) {
      els.btnCopyRawJson.addEventListener('click', () => {
        if (els.rawJson) {
          navigator.clipboard.writeText(els.rawJson.textContent).then(() => {
            const orig = els.btnCopyRawJson.textContent;
            els.btnCopyRawJson.textContent = '✅ Copied!';
            setTimeout(() => { els.btnCopyRawJson.textContent = orig; }, 2000);
          }).catch((err) => {
            console.warn('[copyRawJson] Failed:', err);
          });
        }
      });
    }
    
    // Explore tab - Search input
    if (els.exploreSearchInput) {
      let searchDebounce = null;
      els.exploreSearchInput.addEventListener('input', (e) => {
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => {
          handleExploreSearch(e.target.value);
        }, 200);
      });
    }
    
    // Explore tab - Type filter buttons
    document.querySelectorAll('.explore-type-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        handleExploreTypeFilter(btn.dataset.type);
      });
    });
    
    // Explore tab - Open top finding explain button
    if (els.btnPivotOpenExplain) {
      els.btnPivotOpenExplain.addEventListener('click', () => {
        const pivot = state.explorePivotResult;
        if (pivot && pivot.related_findings && pivot.related_findings.length > 0) {
          const topFinding = pivot.related_findings[0];
          state.selectedSignalId = topFinding.signal_id;
          state.selectedSignal = topFinding;
          switchRunTab('explain');
        } else {
          showToast('No findings to explain', 'info');
        }
      });
    }
    
    // Explore tab - Export case pack button
    if (els.btnPivotExportCasePack) {
      els.btnPivotExportCasePack.addEventListener('click', exportCasePack);
    }
    
    // Import drop zone
    if (els.importDropZone) {
      els.importDropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        els.importDropZone.style.borderColor = 'var(--accent)';
      });
      els.importDropZone.addEventListener('dragleave', () => {
        els.importDropZone.style.borderColor = 'var(--border)';
      });
      els.importDropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        els.importDropZone.style.borderColor = 'var(--border)';
        const files = e.dataTransfer.files;
        if (files.length > 0) {
          importBundle(files[0]);
        }
      });
    }
    if (els.importFileInput) {
      els.importFileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
          importBundle(e.target.files[0]);
        }
      });
    }
    
    // Export bundle
    if (els.btnExportBundle) {
      els.btnExportBundle.addEventListener('click', () => exportBundle());
    }
    
    // Debug panel clear button
    const btnClearDebugLog = document.getElementById('btnClearDebugLog');
    if (btnClearDebugLog) {
      btnClearDebugLog.addEventListener('click', () => {
        apiCallLog.length = 0;
        renderDebugPanel();
      });
    }
  }

  // ============ POLLING ============
  // CRITICAL: Single polling loop, no duplicates
  
  function startPolling() {
    // Prevent duplicate polling
    if (pollTimeoutId !== null) {
      console.warn('[startPolling] Polling already running, skipping');
      return;
    }
    
    pollingStopped = false;
    console.log('[startPolling] Starting polling loop');
    
    function schedulePoll() {
      if (pollingStopped) {
        console.log('[schedulePoll] Polling stopped, not scheduling');
        return;
      }
      
      // Determine poll interval
      let interval;
      if (!isPageVisible) {
        interval = 20000; // 20s when hidden
      } else if (state.isRunning) {
        interval = 1000;  // 1s when running
      } else {
        interval = 5000;  // 5s when stopped
      }
      
      pollTimeoutId = setTimeout(async () => {
        pollTimeoutId = null;
        
        if (pollingStopped || state.importedMode) {
          console.log('[poll] Skipped: stopped or imported mode');
          return;
        }
        
        if (isPageVisible || state.isRunning) {
          await fetchRunStatus();
          if (state.isRunning) {
            await fetchMetrics();
            // LIVE FINDINGS: Poll signals while run is active
            await pollLiveSignals();
          }
        }
        
        schedulePoll();
      }, interval);
    }
    
    schedulePoll();
    
    // Health check every 30 seconds (separate interval)
    if (healthIntervalId === null) {
      healthIntervalId = setInterval(() => {
        if (isPageVisible && !state.importedMode) {
          checkHealth();
        }
      }, 30000);
    }
  }
  
  function stopPolling() {
    console.log('[stopPolling] Stopping polling loop');
    pollingStopped = true;
    
    if (pollTimeoutId !== null) {
      clearTimeout(pollTimeoutId);
      pollTimeoutId = null;
    }
    
    if (healthIntervalId !== null) {
      clearInterval(healthIntervalId);
      healthIntervalId = null;
    }
  }
  
  function setupVisibilityHandling() {
    document.addEventListener('visibilitychange', () => {
      isPageVisible = !document.hidden;
      
      if (isPageVisible) {
        console.log('[Visibility] Tab visible, refreshing...');
        // Immediate refresh when becoming visible
        if (!state.importedMode) {
          fetchRunStatus();
          if (state.isRunning) {
            fetchMetrics();
          }
        }
      } else {
        console.log('[Visibility] Tab hidden, slowing polls...');
      }
    });
  }

  // ============ INIT ============
  async function init() {
    console.log('[Init] Incident Compiler UI starting...', BUILD_STAMP);
    
    bindEvents();
    bindTeamEvents();
    setupVisibilityHandling();
    initDiffV2Controls();
    initInfoBubbles(); // Initialize glossary-driven info bubbles
    
    // Initial state: show stopped UI with null counters (shows "—")
    state.counters = { events: null, segments: null, facts: null, signals: null };
    updateStoppedUI();
    updateCountersUI();
    
    // Check backend health first
    const healthy = await checkHealth();
    
    if (healthy) {
      hideError();
      
      // Probe backend capabilities (which endpoints exist)
      await probeCapabilities();
      
      // Load playbook selection defaults before readiness check
      await loadPlaybookSelectionDefault();
      
      // Fetch all initial data in parallel
      await Promise.all([
        checkReadiness(),
        fetchRunStatus(),
        fetchRuns()
      ]);
      
      // Load playbook presets (depends on readiness for capability data)
      await loadPlaybookPresets();
      
      // If running, fetch initial metrics
      if (state.isRunning) {
        await fetchMetrics();
      }
    }
    
    // Start polling (only if not imported mode)
    if (!state.importedMode) {
      startPolling();
    }
    
    console.log('[Init] Incident Compiler UI ready');
    console.log('[Init] Capabilities:', state.capabilities);
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

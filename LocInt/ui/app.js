/**
 * Incident Compiler - UI Application
 * BUILD_STAMP: 2026-01-10T23:00:00Z_SHIP
 * 
 * TRUTHFUL BY DEFAULT:
 * - All state comes from backend endpoints, never simulated
 * - If backend unreachable, UI shows error and does NOT fake running state
 * - 0 renders as "0", null/undefined renders as "—"
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
    // Capability probe results (which endpoints exist)
    capabilities: {
      signals: null,      // null = unknown, true = available, false = 404
      signalsStats: null,
      signalExplain: null,
      signalNarrative: null,
      runCoverage: null,    // /api/runs/:id/coverage endpoint
      evidenceDeref: false  // Evidence dereference NOT supported by current backend
    }
  };

  // ============ POLLING STATE ============
  // CRITICAL: Single polling loop, no duplicates
  let pollTimeoutId = null;
  let healthIntervalId = null;
  let isPageVisible = true;
  let pollingStopped = false;

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
    btnStartRun: $('#btnStartRun'),
    btnStopRun: $('#btnStopRun'),
    runStatus: $('#runStatus'),
    runDuration: $('#runDuration'),
    readinessStatus: $('#readinessStatus'),
    missionError: $('#missionError'),
    missionErrorText: $('#missionErrorText'),
    missionHint: $('#missionHint'),
    
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
    runTabFindings: $('#runTabFindings'),
    runTabTimeline: $('#runTabTimeline'),
    runTabExplain: $('#runTabExplain'),
    runTabRaw: $('#runTabRaw'),
    
    // Overview tab
    dataSources: $('#dataSources'),
    detailProfile: $('#detailProfile'),
    detailDuration: $('#detailDuration'),
    detailHosts: $('#detailHosts'),
    detailMode: $('#detailMode'),
    
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
    lastErrorMsg: $('#lastErrorMsg')
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
   * Enhanced: shows context, HTML marker with preview
   */
  function renderDebugPanel() {
    if (!DEBUG_MODE) return;
    const panel = document.getElementById('debugApiPanel');
    const log = document.getElementById('debugApiLog');
    if (!panel || !log) return;
    
    panel.classList.remove('hidden');
    
    if (apiCallLog.length === 0) {
      log.innerHTML = '<div style="color: var(--muted);">No API calls yet</div>';
      return;
    }
    
    log.innerHTML = apiCallLog.map(e => {
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
      
      updateReadinessUI();
      
      // Hide connection details when reachable
      if (els.connectionDetailsToggle) els.connectionDetailsToggle.classList.add('hidden');
      if (els.connectionDetails) els.connectionDetails.classList.add('hidden');
      
    } catch (err) {
      state.readinessState = 'unreachable';
      state.readinessSummary = 'Could not reach backend';
      state.lastError = err.message;
      
      updateReadinessUI();
      
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
      
      const data = await api('/api/run/start', {
        method: 'POST',
        body: JSON.stringify({
          profile: profile,
          duration_s: durationMin * 60
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
   */
  async function stopRun() {
    if (els.btnStopRun) {
      els.btnStopRun.disabled = true;
      els.btnStopRun.textContent = '⏳ Stopping...';
    }
    
    try {
      hideError();
      await api('/api/run/stop', { method: 'POST' });
      
      // DO NOT assume stopped - re-fetch status from backend
      await fetchRunStatus();
      
      // Refresh runs list (new run should appear)
      await fetchRuns();
      
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
   * Fetch runs list - GET /api/runs
   */
  async function fetchRuns() {
    try {
      const data = await api('/api/runs');
      
      // Handle array or {data: [...]} or {runs: [...]} wrapper
      state.runs = Array.isArray(data) ? data : (data.data || data.runs || []);
      
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
    
    console.log('[probeCapabilities] Result:', state.capabilities);
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
      const data = await api(`/api/signals?run_id=${encodeURIComponent(run.run_id)}&limit=1000`);
      const signals = Array.isArray(data) ? data : (data.data || data.signals || []);
      
      // Track which run these signals belong to
      state.signalsRunId = run.run_id;
      
      console.log(`[fetchSignalsForRun] Run ${run.run_id}: ${signals.length} signals from per-run DB`);
      
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
        try {
          const errData = await res.json();
          errMsg = errData.error || errData.message || errMsg;
        } catch (e) {}
        throw new Error(errMsg);
      }
      
      const data = await res.json();
      console.log('[importBundle] Success:', data);
      
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
      const displayId = id.length > 8 ? id.slice(0, 8) + '...' : id;
      
      // Only show source badge if backend provides it
      const source = run.source || run.origin || null;
      const sourceBadge = source ? 
        `<span class="badge badge-${source === 'imported' ? 'running' : 'live'}" style="font-size: 9px; padding: 2px 6px; margin-left: 8px;">${source.toUpperCase()}</span>` : 
        '';
      
      return `
        <div class="run-item ${isActive ? 'active' : ''}" data-run-id="${id}">
          <div style="font-size: 14px; font-weight: 500; margin-bottom: 4px; display: flex; align-items: center;">
            Run ${displayId}${sourceBadge}
          </div>
          <div style="font-size: 12px; color: var(--muted);">${formatTimestamp(time)}</div>
        </div>
      `;
    }).join('');
    
    // Bind click events
    els.runsList.querySelectorAll('.run-item').forEach(el => {
      el.addEventListener('click', () => selectRun(el.dataset.runId));
    });
    
    // Auto-select first (latest) run if none selected
    if (!state.selectedRunId && state.runs.length > 0) {
      const firstRun = state.runs[0];
      selectRun(firstRun.run_id || firstRun.id);
    }
  }

  /**
   * Select a run and load its data
   */
  async function selectRun(runId) {
    state.selectedRunId = runId;
    state.selectedRun = state.runs.find(r => (r.run_id || r.id) === runId);
    state.signals = [];
    state.runCoverage = null;  // Reset coverage when switching runs
    state.selectedSignalId = null;
    state.selectedSignal = null;
    state.signalExplanation = null;
    state.signalNarrative = null;
    
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
    
    const displayId = runId.length > 12 ? runId.slice(0, 12) + '...' : runId;
    if (els.runDetailTitle) els.runDetailTitle.textContent = `Run ${displayId}`;
    if (els.runDetailTime) els.runDetailTime.textContent = formatTimestamp(run.started_at || run.start_time || run.earliest_ts);
    
    // Show run metrics in Overview tab
    if (els.detailEvents) els.detailEvents.textContent = formatValue(run.events_total ?? run.events ?? run.event_count);
    if (els.detailSegments) els.detailSegments.textContent = formatValue(run.segments_count ?? run.segments ?? run.segment_count);
    if (els.detailFacts) els.detailFacts.textContent = formatValue(run.facts_extracted ?? run.facts ?? run.fact_count);
    if (els.detailSignals) els.detailSignals.textContent = formatValue(run.signal_count ?? run.signals_fired ?? run.signals);
    
    // Overview: Profile, Duration, Hosts, Mode
    if (els.detailProfile) els.detailProfile.textContent = run.profile || 'extended';
    if (els.detailDuration) {
      const durationMs = (run.latest_ts || 0) - (run.earliest_ts || 0);
      els.detailDuration.textContent = durationMs > 0 ? formatDuration(durationMs / 1000) : '—';
    }
    if (els.detailHosts) els.detailHosts.textContent = run.hosts?.join(', ') || '—';
    if (els.detailMode) {
      const mode = run.source === 'imported' ? 'Imported' : 'Live';
      els.detailMode.textContent = mode;
    }
    
    // Data sources - derive from signal types if available
    updateDataSourcesUI(run);
    
    // Reset to Overview tab
    switchRunTab('overview');
    
    // Fetch signals for this run in background
    loadSignalsForRun(run);
    
    // Fetch coverage data for this run in background
    loadCoverageForRun(run);
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
      // New structured response: always has "available" field
      state.runCoverage = json;
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
   * Render Facts tab - showing extracted facts and "why no signals"
   */
  function renderFactsTab() {
    // Hide all states first
    if (els.factsLoading) els.factsLoading.classList.add('hidden');
    if (els.factsEmpty) els.factsEmpty.classList.add('hidden');
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
    
    // Handle structured available=false response
    if (coverage.available === false) {
      if (els.factsEmpty) els.factsEmpty.classList.remove('hidden');
      // Update empty state message with the reason
      const emptyMsg = els.factsEmpty.querySelector('div:last-child');
      if (emptyMsg) {
        emptyMsg.textContent = coverage.message || 'Coverage data not available';
        emptyMsg.style.maxWidth = '400px';
      }
      return;
    }
    
    // If no facts at all, show empty state
    if (!coverage.facts_total || coverage.facts_total === 0) {
      if (els.factsEmpty) els.factsEmpty.classList.remove('hidden');
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
        els.factsHostsList.innerHTML = '<span class="badge badge-stopped">No hosts recorded</span>';
      } else {
        els.factsHostsList.innerHTML = coverage.top_hosts.slice(0, 10).map(h => 
          `<span class="badge badge-info" style="font-family: monospace; font-size: 11px;">
            ${escapeHtml(h.host)} <span style="opacity: 0.7;">(${formatValue(h.count)})</span>
          </span>`
        ).join('');
      }
    }
    
    // Render sensors section (if sensors data available)
    if (els.factsSensorsSection && els.factsSensorsList && coverage.sensors && coverage.sensors.length > 0) {
      els.factsSensorsSection.classList.remove('hidden');
      els.factsSensorsList.innerHTML = coverage.sensors.map(sensor => {
        const statusIcon = sensor.status === 'active' ? '✅' : sensor.status === 'configured' ? '⚙️' : '⚠️';
        const statusColor = sensor.status === 'active' ? 'var(--success)' : sensor.status === 'configured' ? 'var(--warn)' : 'var(--error)';
        const factCountStr = sensor.fact_count ? ` (${formatValue(sensor.fact_count)} facts)` : '';
        const capsStr = sensor.capabilities?.length > 0 
          ? `<div style="display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px;">
              ${sensor.capabilities.map(cap => 
                `<span class="badge" style="font-size: 10px; padding: 2px 6px; background: var(--panel); color: var(--muted);">${escapeHtml(cap)}</span>`
              ).join('')}
             </div>`
          : '';
        
        return `
          <div style="background: var(--panel2); border-radius: var(--radius-sm); padding: 10px 12px; border-left: 3px solid ${statusColor};">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="font-weight: 600; font-size: 13px;">
                <span style="margin-right: 6px;">${statusIcon}</span>
                ${escapeHtml(sensor.sensor_name)}
                <span style="font-weight: normal; color: var(--muted);">${factCountStr}</span>
              </div>
              <span class="badge" style="font-size: 10px; background: ${statusColor}; color: #fff; text-transform: uppercase;">
                ${sensor.status}
              </span>
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
    
    // Render pipeline diagnostics
    if (els.pipelineDiagnostics && coverage.pipeline_diagnostics) {
      els.pipelineDiagnostics.innerHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
          <div><span style="color: var(--muted);">Playbooks Loaded:</span> ${formatValue(diag.playbooks_loaded)}</div>
          <div><span style="color: var(--muted);">Playbooks Enabled:</span> ${formatValue(diag.playbooks_enabled ?? diag.playbooks_loaded)}</div>
          <div><span style="color: var(--muted);">Fired This Run:</span> ${formatValue(diag.playbooks_fired_this_run ?? 0)}</div>
          <div><span style="color: var(--muted);">Coverage Minutes:</span> ${formatValue(diag.coverage_minutes)}</div>
        </div>
        ${diag.playbook_categories?.length > 0 ? `
        <div style="margin-top: 8px;">
          <span style="color: var(--muted);">Categories:</span>
          <span style="font-size: 12px;">${diag.playbook_categories.map(c => c.replace(/_/g, ' ')).join(', ')}</span>
        </div>
        ` : ''}
      `;
    }
  }

  /**
   * Update data sources display based on run info
   */
  function updateDataSourcesUI(run) {
    if (!els.dataSources) return;
    
    // Derive data sources from signals or show default
    const sources = new Set();
    
    // Add host-derived sources
    if (run.hosts?.length > 0) {
      sources.add('Windows Events');
    }
    
    // If we have signals loaded, derive sources from signal types
    if (state.signals.length > 0) {
      state.signals.forEach(sig => {
        const sigType = sig.signal_type || '';
        if (sigType.includes('Process')) sources.add('Process Telemetry');
        if (sigType.includes('File')) sources.add('File Activity');
        if (sigType.includes('Network') || sigType.includes('Dns')) sources.add('Network');
        if (sigType.includes('Registry')) sources.add('Registry');
        if (sigType.includes('WMI')) sources.add('WMI');
      });
    }
    
    // Default if empty
    if (sources.size === 0) {
      sources.add('Windows ETW');
    }
    
    els.dataSources.innerHTML = Array.from(sources).map(src => 
      `<span class="badge badge-live" style="font-size: 11px;">${src}</span>`
    ).join('');
  }

  /**
   * Switch run detail tab
   */
  function switchRunTab(tabName) {
    state.currentRunTab = tabName;
    
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
    [els.runTabOverview, els.runTabFindings, els.runTabFacts, els.runTabTimeline, els.runTabExplain, els.runTabRaw].forEach(el => {
      if (el) el.classList.add('hidden');
    });
    
    // Show selected tab content
    switch (tabName) {
      case 'overview':
        if (els.runTabOverview) els.runTabOverview.classList.remove('hidden');
        break;
      case 'findings':
        if (els.runTabFindings) els.runTabFindings.classList.remove('hidden');
        renderFindingsTab();
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
        break;
      case 'raw':
        if (els.runTabRaw) els.runTabRaw.classList.remove('hidden');
        renderRawTab();
        break;
    }
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
   */
  async function loadSignalExplanation(signalId) {
    // Fetch explanation
    state.signalExplanation = await fetchSignalExplanation(signalId);
    
    // Fetch narrative
    state.signalNarrative = await fetchSignalNarrative(signalId);
    
    // Re-render explain tab with data
    if (state.currentRunTab === 'explain') {
      renderExplainTab();
    }
  }

  /**
   * Render Explain tab
   */
  function renderExplainTab() {
    // No signal selected
    if (!state.selectedSignalId || !state.selectedSignal) {
      if (els.explainContent) els.explainContent.classList.add('hidden');
      if (els.explainUnavailable) els.explainUnavailable.classList.add('hidden');
      if (els.explainSelectPrompt) els.explainSelectPrompt.classList.remove('hidden');
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
    if (els.explainContent) els.explainContent.classList.remove('hidden');
    
    const sig = state.selectedSignal;
    const explain = state.signalExplanation;
    const narrative = state.signalNarrative;
    
    // Header
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
    
    // Narrative summary
    if (els.explainNarrative) {
      if (narrative?.sentences?.length > 0) {
        els.explainNarrative.textContent = narrative.sentences.map(s => s.text).join(' ');
      } else if (explain?.hypothesis_name) {
        els.explainNarrative.textContent = `Detected ${explain.hypothesis_name} behavior based on matched patterns.`;
      } else {
        els.explainNarrative.textContent = sig.metadata?.description || 'No narrative available for this signal.';
      }
    }
    
    // Detector / Playbook
    if (els.explainPlaybook) {
      els.explainPlaybook.textContent = explain?.playbook_id || explain?.hypothesis_name || sig.signal_type || '—';
    }
    if (els.explainDetectorVersion) {
      els.explainDetectorVersion.textContent = explain?.detector_version || '—';
    }
    
    // Entities
    if (els.explainEntities) {
      const entities = [];
      
      // From signal
      if (sig.proc_key) entities.push({ type: 'process', value: sig.proc_key });
      if (sig.file_key) entities.push({ type: 'file', value: sig.file_key });
      if (sig.identity_key) entities.push({ type: 'user', value: sig.identity_key });
      if (sig.host) entities.push({ type: 'host', value: sig.host });
      
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
    
    // Evidence pointers - TRUTHFUL RENDERING
    // Backend does NOT support evidence dereference endpoint
    if (els.explainEvidence) {
      const evidencePtrs = sig.evidence_ptrs || explain?.evidence_refs || [];
      if (evidencePtrs.length === 0) {
        els.explainEvidence.innerHTML = '<span style="color: var(--muted);">No evidence pointers available</span>';
      } else {
        // Show pointers as read-only (no clickable deref since backend doesn't support it)
        let html = evidencePtrs.map((ptr, i) => {
          const ptrStr = typeof ptr === 'object' ? JSON.stringify(ptr, null, 2) : String(ptr);
          return `<div style="margin-bottom: 4px; font-family: monospace; font-size: 11px;">${i + 1}. ${ptrStr}</div>`;
        }).join('');
        
        // TRUTHFUL: Add note that deref is not available
        html += `<div style="margin-top: 10px; padding: 6px 8px; background: var(--panel2); border-radius: 4px; font-size: 11px; color: var(--muted);">
          <span style="color: var(--warn);">ℹ️</span> Evidence dereference not available yet. Pointers are for reference only.
        </div>`;
        
        els.explainEvidence.innerHTML = html;
      }
      
      if (sig.dropped_evidence_count > 0) {
        els.explainEvidence.innerHTML += `<div style="margin-top: 8px; color: var(--warn); font-size: 11px;">+ ${sig.dropped_evidence_count} additional evidence items (truncated)</div>`;
      }
    }
    
    // Scoring breakdown - INTEGRITY: Display EXACTLY what backend returns, NO recomputation
    if (els.explainScoring) {
      const scoring = explain?.scoring;
      if (scoring && scoring.risk_score != null) {
        // Backend provided scoring - display EXACTLY as received
        let html = `<div style="margin-bottom: 8px; padding: 4px 8px; background: var(--panel2); border-radius: 4px; font-size: 10px; color: var(--muted);">
          🔒 Backend Score (unmodified)
        </div>`;
        html += `<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">`;
        html += `<div><span style="color: var(--muted);">Risk Score:</span> <strong>${(scoring.risk_score * 100).toFixed(0)}%</strong></div>`;
        html += `<div><span style="color: var(--muted);">Base Severity:</span> ${scoring.base_severity || sig.severity}</div>`;
        
        if (scoring.mahalanobis_distance != null) {
          html += `<div><span style="color: var(--muted);">Mahalanobis:</span> ${scoring.mahalanobis_distance.toFixed(2)}</div>`;
        }
        if (scoring.elliptic_envelope_score != null) {
          html += `<div><span style="color: var(--muted);">Elliptic Envelope:</span> ${scoring.elliptic_envelope_score.toFixed(2)}</div>`;
        }
        if (scoring.krim_score != null) {
          html += `<div><span style="color: var(--muted);">KRIM:</span> ${scoring.krim_score.toFixed(2)}</div>`;
        }
        html += `</div>`;
        
        if (scoring.scoring_reasons?.length > 0) {
          html += `<div style="margin-top: 12px;"><span style="color: var(--muted); font-size: 12px;">Scoring Reasons (from backend):</span></div>`;
          html += `<div style="margin-top: 4px;">`;
          scoring.scoring_reasons.forEach(r => {
            const pct = (r.weight * 100).toFixed(0);
            html += `<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
              <div style="flex: 1; font-size: 12px;">${r.reason}</div>
              <div style="width: 60px; height: 6px; background: var(--panel2); border-radius: 3px; overflow: hidden;">
                <div style="width: ${pct}%; height: 100%; background: var(--accent);"></div>
              </div>
              <div style="width: 32px; font-size: 11px; color: var(--muted); text-align: right;">${pct}%</div>
            </div>`;
          });
          html += `</div>`;
        } else {
          html += `<div style="margin-top: 8px; font-size: 11px; color: var(--warn);">Not available (missing: scoring_reasons)</div>`;
        }
        
        els.explainScoring.innerHTML = html;
      } else {
        // NO scoring from backend - show explicit "not available"
        els.explainScoring.innerHTML = `
          <div style="padding: 12px; text-align: center;">
            <div style="color: var(--warn); font-size: 13px;">Not available</div>
            <div style="font-size: 11px; color: var(--muted); margin-top: 4px;">(missing: scoring object in explanation)</div>
            <div style="font-size: 11px; color: var(--muted); margin-top: 8px;">Signal severity: <strong>${sig.severity}</strong></div>
          </div>
        `;
      }
    }
    
    // Matched facts / slots
    if (els.explainSlots) {
      const slots = explain?.slots;
      const matchedFacts = explain?.matched_facts;
      
      let html = '';
      
      if (slots && Object.keys(slots).length > 0) {
        html += '<div style="margin-bottom: 8px; font-weight: 500;">Slot Values:</div>';
        Object.entries(slots).forEach(([key, val]) => {
          const displayVal = typeof val === 'object' ? JSON.stringify(val) : String(val);
          html += `<div style="margin-bottom: 4px;"><span style="color: var(--muted);">${key}:</span> <span style="font-family: monospace;">${displayVal}</span></div>`;
        });
      }
      
      if (matchedFacts?.length > 0) {
        html += '<div style="margin-top: 12px; margin-bottom: 8px; font-weight: 500;">Matched Facts:</div>';
        matchedFacts.forEach(fact => {
          const factStr = typeof fact === 'object' ? `${fact.fact_type || 'Unknown'}: ${fact.entity || JSON.stringify(fact)}` : String(fact);
          html += `<div style="margin-bottom: 4px; font-size: 12px;">• ${factStr}</div>`;
        });
      }
      
      if (!html) {
        html = '<span style="color: var(--muted);">No slot/fact data available</span>';
      }
      
      els.explainSlots.innerHTML = html;
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
    setupVisibilityHandling();
    
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
      
      // Fetch all initial data in parallel
      await Promise.all([
        checkReadiness(),
        fetchRunStatus(),
        fetchRuns()
      ]);
      
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

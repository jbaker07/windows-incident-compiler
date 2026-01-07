/* app.js — hardened + with health + incidents + playbooks (safe if elements missing) */

(() => {
  "use strict";

  // ============================================================================
  // TAURI DESKTOP INTEGRATION
  // ============================================================================
  // This section provides Tauri desktop app integration when running inside Tauri.
  // When running in browser (dev mode), these functions are no-ops or use fallbacks.

  const isTauri = !!(window.__TAURI__ || window.__TAURI_INTERNALS__);
  let tauriInvoke = null;
  let tauriListen = null;

  // Initialize Tauri APIs if available
  if (isTauri) {
    // Tauri v2 API
    const tauri = window.__TAURI__;
    if (tauri?.core?.invoke) {
      tauriInvoke = tauri.core.invoke;
    }
    if (tauri?.event?.listen) {
      tauriListen = tauri.event.listen;
    }
  }

  // Desktop app state
  const desktopState = {
    isRunning: false,
    isAdmin: false,
    limitedMode: false,
    lastStatus: null,
    statusPollInterval: null,
    lastMetrics: null,
  };

  // Expose desktop API globally for onclick handlers
  window.__edrDesktop = {
    startRun,
    stopRun,
    openTelemetryFolder,
    openLogsFolder,
    showMetrics,
    runE2ECheck,
    generateActivity,
  };

  // Initialize desktop UI on load
  document.addEventListener('DOMContentLoaded', initDesktopUI);

  async function initDesktopUI() {
    if (!isTauri) {
      console.log('[Desktop] Not running in Tauri, desktop controls hidden');
      return;
    }

    console.log('[Desktop] Initializing Tauri desktop UI');

    // Show the run control panel
    const runPanel = document.getElementById('runControlPanel');
    if (runPanel) runPanel.classList.remove('hidden');

    // Check admin status
    try {
      desktopState.isAdmin = await tauriInvoke('is_admin');
      updateAdminBadge();
    } catch (e) {
      console.error('[Desktop] Failed to check admin status:', e);
    }

    // Load available playbooks
    await loadPlaybooks();

    // Get initial status
    await refreshStatus();

    // Start polling for status
    desktopState.statusPollInterval = setInterval(refreshStatus, 3000);

    // Listen for run-complete event from Tauri
    if (tauriListen) {
      tauriListen('run-complete', () => {
        console.log('[Desktop] Run complete event received');
        desktopState.isRunning = false;
        updateRunUI();
        showNotification('Run Complete', 'Capture has finished. Check metrics for results.');
      });
    }

    // Wire up modal close buttons
    document.getElementById('closeMetricsModal')?.addEventListener('click', () => {
      document.getElementById('metricsModal')?.close();
    });
    document.getElementById('closeE2EModal')?.addEventListener('click', () => {
      document.getElementById('e2eCheckModal')?.close();
    });
    document.getElementById('btnOpenMetricsFolder')?.addEventListener('click', async () => {
      if (tauriInvoke) await tauriInvoke('open_metrics_folder');
    });
    document.getElementById('btnRunE2EAgain')?.addEventListener('click', runE2ECheck);
  }

  function updateAdminBadge() {
    const badge = document.getElementById('adminBadge');
    const banner = document.getElementById('adminWarningBanner');
    
    if (desktopState.isAdmin) {
      if (badge) {
        badge.textContent = 'Admin';
        badge.className = 'px-2 py-1 rounded text-xs bg-emerald-700 text-emerald-200';
      }
      if (banner) banner.classList.add('hidden');
    } else {
      if (badge) {
        badge.textContent = 'Limited';
        badge.className = 'px-2 py-1 rounded text-xs bg-amber-700 text-amber-200';
      }
      if (banner) banner.classList.remove('hidden');
    }
  }

  async function loadPlaybooks() {
    if (!tauriInvoke) return;
    
    const container = document.getElementById('playbookSelector');
    if (!container) return;

    try {
      const playbooks = await tauriInvoke('get_available_playbooks');
      
      if (!playbooks || playbooks.length === 0) {
        container.innerHTML = '<span class="text-xs text-slate-500">No playbooks found (all will be used)</span>';
        return;
      }

      container.innerHTML = playbooks.map(pb => `
        <label class="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-700 hover:bg-slate-600 cursor-pointer text-xs">
          <input type="checkbox" class="playbook-checkbox rounded border-slate-600" value="${pb}" />
          <span>${pb}</span>
        </label>
      `).join('');
    } catch (e) {
      console.error('[Desktop] Failed to load playbooks:', e);
      container.innerHTML = '<span class="text-xs text-red-400">Failed to load playbooks</span>';
    }
  }

  async function startRun() {
    if (!tauriInvoke) return;
    if (desktopState.isRunning) return;

    const durationSelect = document.getElementById('runDuration');
    const duration = parseInt(durationSelect?.value || '10', 10);

    // Get selected playbooks
    const checkboxes = document.querySelectorAll('.playbook-checkbox:checked');
    const selectedPlaybooks = Array.from(checkboxes).map(cb => cb.value);

    const btnStart = document.getElementById('btnStartRun');
    const btnStop = document.getElementById('btnStopRun');
    const errorBox = document.getElementById('runErrorBox');

    try {
      if (btnStart) btnStart.disabled = true;
      if (errorBox) errorBox.classList.add('hidden');

      console.log('[Desktop] Starting run:', { duration, selectedPlaybooks });
      
      await tauriInvoke('start_run', {
        durationMinutes: duration,
        selectedPlaybooks: selectedPlaybooks.length > 0 ? selectedPlaybooks : null,
      });

      desktopState.isRunning = true;
      updateRunUI();
      
    } catch (e) {
      console.error('[Desktop] Failed to start run:', e);
      if (errorBox) {
        errorBox.textContent = `Failed to start: ${e}`;
        errorBox.classList.remove('hidden');
      }
    } finally {
      if (btnStart) btnStart.disabled = false;
    }
  }

  async function stopRun() {
    if (!tauriInvoke) return;
    if (!desktopState.isRunning) return;

    const btnStop = document.getElementById('btnStopRun');
    const errorBox = document.getElementById('runErrorBox');

    try {
      if (btnStop) btnStop.disabled = true;
      if (errorBox) errorBox.classList.add('hidden');

      console.log('[Desktop] Stopping run');
      await tauriInvoke('stop_all');
      
      desktopState.isRunning = false;
      updateRunUI();
      
    } catch (e) {
      console.error('[Desktop] Failed to stop run:', e);
      if (errorBox) {
        errorBox.textContent = `Failed to stop: ${e}`;
        errorBox.classList.remove('hidden');
      }
    } finally {
      if (btnStop) btnStop.disabled = false;
    }
  }

  async function refreshStatus() {
    if (!tauriInvoke) return;

    try {
      const status = await tauriInvoke('get_status');
      desktopState.lastStatus = status;
      desktopState.isRunning = status.running;
      desktopState.limitedMode = status.limited_mode;

      // Update UI elements
      const segmentsEl = document.getElementById('runSegments');
      const signalsEl = document.getElementById('runSignals');
      const remainingEl = document.getElementById('runRemaining');
      const errorBox = document.getElementById('runErrorBox');

      if (segmentsEl) segmentsEl.textContent = status.segments_count ?? '--';
      if (signalsEl) signalsEl.textContent = status.signals_count ?? '--';
      
      if (remainingEl) {
        if (status.run_remaining_seconds != null) {
          const mins = Math.floor(status.run_remaining_seconds / 60);
          const secs = status.run_remaining_seconds % 60;
          remainingEl.textContent = `${mins}:${String(secs).padStart(2, '0')}`;
        } else {
          remainingEl.textContent = '--';
        }
      }

      // Show crash error if detected
      if (status.crashed_process && status.last_error && errorBox) {
        errorBox.innerHTML = `<strong>${status.crashed_process} crashed:</strong><br><pre class="mt-1 text-xs overflow-auto max-h-20">${status.last_error}</pre>`;
        errorBox.classList.remove('hidden');
      } else if (errorBox && !desktopState.isRunning) {
        // Clear error when not running (unless just crashed)
        // Keep error visible if it was a crash
      }

      updateRunUI();
    } catch (e) {
      console.error('[Desktop] Failed to refresh status:', e);
    }
  }

  function updateRunUI() {
    const icon = document.getElementById('runStatusIcon');
    const text = document.getElementById('runStatusText');
    const sub = document.getElementById('runStatusSub');
    const btnStart = document.getElementById('btnStartRun');
    const btnStop = document.getElementById('btnStopRun');
    const status = desktopState.lastStatus;

    if (desktopState.isRunning) {
      if (icon) icon.textContent = '🟢';
      if (text) text.textContent = 'Stack Running';
      if (sub) sub.textContent = status?.run_id || 'Capturing telemetry...';
      if (btnStart) btnStart.classList.add('hidden');
      if (btnStop) btnStop.classList.remove('hidden');
    } else if (status?.crashed_process) {
      if (icon) icon.textContent = '🔴';
      if (text) text.textContent = 'Stack Crashed';
      if (sub) sub.textContent = `${status.crashed_process} exited unexpectedly`;
      if (btnStart) btnStart.classList.remove('hidden');
      if (btnStop) btnStop.classList.add('hidden');
    } else {
      if (icon) icon.textContent = '⏹️';
      if (text) text.textContent = 'Stack Stopped';
      if (sub) sub.textContent = 'Ready to start capture';
      if (btnStart) btnStart.classList.remove('hidden');
      if (btnStop) btnStop.classList.add('hidden');
    }
  }

  async function openTelemetryFolder() {
    if (!tauriInvoke) return;
    try {
      await tauriInvoke('open_telemetry_folder');
    } catch (e) {
      console.error('[Desktop] Failed to open telemetry folder:', e);
    }
  }

  async function openLogsFolder() {
    if (!tauriInvoke) return;
    try {
      await tauriInvoke('open_logs_folder');
    } catch (e) {
      console.error('[Desktop] Failed to open logs folder:', e);
    }
  }

  async function showMetrics() {
    const modal = document.getElementById('metricsModal');
    const content = document.getElementById('metricsContent');
    if (!modal || !content) return;

    modal.showModal();

    if (!desktopState.lastStatus) {
      content.innerHTML = '<div class="text-slate-400 text-center py-4">No status available</div>';
      return;
    }

    const s = desktopState.lastStatus;
    content.innerHTML = `
      <div class="grid grid-cols-2 gap-4 text-sm">
        <div class="bg-slate-800 rounded p-3">
          <div class="text-slate-400 text-xs mb-1">Run ID</div>
          <div class="font-mono text-slate-200">${s.run_id || '--'}</div>
        </div>
        <div class="bg-slate-800 rounded p-3">
          <div class="text-slate-400 text-xs mb-1">Admin Mode</div>
          <div class="${s.is_admin ? 'text-emerald-400' : 'text-amber-400'}">${s.is_admin ? 'Yes' : 'No (Limited)'}</div>
        </div>
        <div class="bg-slate-800 rounded p-3">
          <div class="text-slate-400 text-xs mb-1">Segments</div>
          <div class="text-2xl font-bold text-slate-100">${s.segments_count}</div>
        </div>
        <div class="bg-slate-800 rounded p-3">
          <div class="text-slate-400 text-xs mb-1">Signals</div>
          <div class="text-2xl font-bold text-emerald-400">${s.signals_count}</div>
        </div>
        <div class="bg-slate-800 rounded p-3 col-span-2">
          <div class="text-slate-400 text-xs mb-1">Telemetry Root</div>
          <div class="font-mono text-xs text-slate-300 break-all">${s.telemetry_root}</div>
        </div>
        <div class="bg-slate-800 rounded p-3 col-span-2">
          <div class="text-slate-400 text-xs mb-1">API</div>
          <div class="font-mono text-xs text-sky-400">${s.api_base_url}</div>
        </div>
      </div>
    `;
  }

  async function runE2ECheck() {
    const modal = document.getElementById('e2eCheckModal');
    const content = document.getElementById('e2eCheckList');
    const summary = document.getElementById('e2eCheckSummary');
    if (!modal || !content) return;

    modal.showModal();
    content.innerHTML = '<div class="text-slate-400 text-center py-4">Running checks...</div>';
    if (summary) summary.classList.add('hidden');

    const checks = [];
    const API_BASE = 'http://127.0.0.1:3000';

    // Check 1: Segments exist
    try {
      if (desktopState.lastStatus?.segments_count > 0) {
        checks.push({ name: 'Segments exist', pass: true, detail: `${desktopState.lastStatus.segments_count} segments found` });
      } else {
        checks.push({ name: 'Segments exist', pass: false, detail: 'No segments found' });
      }
    } catch (e) {
      checks.push({ name: 'Segments exist', pass: false, detail: e.message });
    }

    // Check 2: API Health
    try {
      const resp = await fetch(`${API_BASE}/api/health`, { timeout: 5000 });
      checks.push({ name: 'API /health', pass: resp.ok, detail: resp.ok ? 'Server responding' : `Status ${resp.status}` });
    } catch (e) {
      checks.push({ name: 'API /health', pass: false, detail: e.message || 'Connection failed' });
    }

    // Check 3: Signals endpoint
    try {
      const resp = await fetch(`${API_BASE}/api/signals`);
      const data = await resp.json();
      const count = data.data?.length ?? 0;
      checks.push({ name: 'API /signals', pass: resp.ok, detail: `${count} signals` });
    } catch (e) {
      checks.push({ name: 'API /signals', pass: false, detail: e.message });
    }

    // Check 4: Explain endpoint (if signals exist)
    if (desktopState.lastStatus?.signals_count > 0) {
      try {
        const sigResp = await fetch(`${API_BASE}/api/signals?limit=1`);
        const sigData = await sigResp.json();
        const firstSig = sigData.data?.[0];
        if (firstSig?.signal_id) {
          const expResp = await fetch(`${API_BASE}/api/signals/${firstSig.signal_id}/explain`);
          checks.push({ name: 'Explain endpoint', pass: expResp.ok, detail: expResp.ok ? 'Working' : `Status ${expResp.status}` });
        } else {
          checks.push({ name: 'Explain endpoint', pass: true, detail: 'No signals to explain' });
        }
      } catch (e) {
        checks.push({ name: 'Explain endpoint', pass: false, detail: e.message });
      }
    } else {
      checks.push({ name: 'Explain endpoint', pass: true, detail: 'Skipped (no signals)' });
    }

    // Render results
    const passed = checks.filter(c => c.pass).length;
    const total = checks.length;

    content.innerHTML = checks.map(c => `
      <div class="flex items-center gap-3 p-2 rounded ${c.pass ? 'bg-emerald-900/30' : 'bg-red-900/30'}">
        <span class="text-lg">${c.pass ? '✅' : '❌'}</span>
        <div class="flex-1">
          <div class="font-medium text-sm">${c.name}</div>
          <div class="text-xs text-slate-400">${c.detail}</div>
        </div>
      </div>
    `).join('');

    if (summary) {
      summary.classList.remove('hidden');
      summary.className = `mt-4 p-3 rounded text-sm ${passed === total ? 'bg-emerald-900/50 text-emerald-200' : 'bg-amber-900/50 text-amber-200'}`;
      summary.textContent = `${passed}/${total} checks passed`;
    }
  }

  /**
   * Generate safe test activity to trigger playbook detections.
   * These are REAL OS activities that produce legitimate Windows telemetry:
   * - Benign PowerShell command (echo)
   * - Scheduled task query (schtasks)
   * - Temp file creation
   * - Registry read (non-destructive)
   * - Network check (localhost)
   * 
   * Admin vs non-admin: Some activities require admin (service query).
   * Gracefully degrades in non-admin mode.
   */
  async function generateActivity() {
    if (!tauriInvoke) {
      console.warn('[Desktop] generateActivity called but Tauri not available');
      return;
    }

    const statusBox = document.getElementById('activityStatusBox');
    if (statusBox) {
      statusBox.classList.remove('hidden');
      statusBox.innerHTML = '🔄 Generating test activity...';
    }

    const results = [];
    const isAdmin = desktopState.isAdmin;

    try {
      // Activity 1: PowerShell echo (LOLBin activity for signal_lolbin_abuse)
      results.push(await runActivityCommand(
        'powershell.exe',
        ['-NoProfile', '-Command', 'Write-Host "EDR-TEST-ACTIVITY"'],
        'PowerShell echo'
      ));

      // Activity 2: Query scheduled tasks (schtasks - another LOLBin)
      results.push(await runActivityCommand(
        'schtasks.exe',
        ['/Query', '/TN', '\\Microsoft\\Windows\\Shell\\CreateObjectTask'],
        'Scheduled task query'
      ));

      // Activity 3: WMIC query (LOLBin)
      results.push(await runActivityCommand(
        'wmic.exe',
        ['os', 'get', 'caption'],
        'WMIC OS query'
      ));

      // Activity 4: Query services (may trigger service persistence playbook)
      if (isAdmin) {
        results.push(await runActivityCommand(
          'sc.exe',
          ['query', 'wuauserv'],
          'Service query (admin)'
        ));
      }

      // Activity 5: Certutil URL decode (benign, triggers certutil LOLBin detection)
      results.push(await runActivityCommand(
        'certutil.exe',
        ['-hashfile', 'C:\\Windows\\System32\\cmd.exe', 'MD5'],
        'Certutil hash'
      ));

      // Activity 6: Registry query (non-destructive, may trigger registry playbook)
      results.push(await runActivityCommand(
        'reg.exe',
        ['query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'],
        'Registry Run key query'
      ));

      // Summary
      const succeeded = results.filter(r => r.success).length;
      const total = results.length;

      if (statusBox) {
        const summary = results.map(r => 
          `<div class="flex items-center gap-2">
            <span>${r.success ? '✅' : '⚠️'}</span>
            <span>${r.name}</span>
          </div>`
        ).join('');

        statusBox.innerHTML = `
          <div class="font-medium mb-2">🧪 Activity Generated: ${succeeded}/${total} commands</div>
          <div class="text-xs space-y-1">${summary}</div>
          <div class="text-xs text-amber-300 mt-2">
            Note: Detection depends on playbook configuration and Windows event channel availability.
            ${!isAdmin ? '<br>⚠️ Running without admin - some event channels may be unavailable.' : ''}
          </div>
        `;

        // Hide after 10 seconds
        setTimeout(() => {
          statusBox.classList.add('hidden');
        }, 10000);
      }

    } catch (e) {
      console.error('[Desktop] Activity generation failed:', e);
      if (statusBox) {
        statusBox.innerHTML = `<span class="text-red-300">❌ Activity generation failed: ${e}</span>`;
      }
    }
  }

  async function runActivityCommand(exe, args, name) {
    try {
      // Use Tauri shell plugin to run command
      const result = await tauriInvoke('run_activity_command', { exe, args });
      return { name, success: true, output: result };
    } catch (e) {
      console.warn(`[Desktop] Activity ${name} failed:`, e);
      return { name, success: false, error: String(e) };
    }
  }

  function showNotification(title, body) {
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(title, { body });
    }
  }

  // ============================================================================
  // END TAURI DESKTOP INTEGRATION
  // ============================================================================

  // ---------- DOM ----------
  const rowsEl      = document.getElementById('rows');
  const detailEl    = document.getElementById('detail');
  const sevEl       = document.getElementById('sevFilter');
  const searchEl    = document.getElementById('search');

  // Header stats (all optional)
  const statEvents  = document.getElementById('statEvents');
  const statAlerts  = document.getElementById('statAlerts');
  const statNodes   = document.getElementById('statNodes');
  const statEdges   = document.getElementById('statEdges');
  const statDrops   = document.getElementById('statDrops');

  // Tabs / screens (optional)
  const screenDash  = document.getElementById('screenDash');
  const screenInt   = document.getElementById('screenIntegrations');
  const screenImport = document.getElementById('screenImport');
  const screenCompare = document.getElementById('screenCompare');
  const screenLicense = document.getElementById('screenLicense');
  const tabDash     = document.getElementById('tabDash');
  const tabInt      = document.getElementById('tabIntegrations');
  const tabImport   = document.getElementById('tabImport');
  const tabCompare  = document.getElementById('tabCompare');
  const tabLicense  = document.getElementById('tabLicense');

  // Integrations pane (optional)
  const addDlg      = document.getElementById('addDlg');
  const vendorSel   = document.getElementById('vendorSel');
  const credFields  = document.getElementById('credFields');
  const tilesGrid   = document.getElementById('tiles');
  const btnAdd      = document.getElementById('btnAdd');
  const saveIntegrationBtn = document.getElementById('saveIntegration');

  // Explain drawer (optional)
  const drawer      = document.getElementById('drawer');
  const exCloseBtn  = document.getElementById('ex_close');

  // Timeline canvas (optional)
  const timelineCanvas = document.getElementById('timeline');

  // Playbooks UI (optional; renders only if present)
  const pbFeedEl    = document.getElementById('pb-feed');
  const pbHitsEl    = document.getElementById('pb-hits');
  const pbPendingEl = document.getElementById('pb-pending');

  // Incidents (DecisionEngine rollups) — optional UI
  const incWrap     = document.getElementById('incidents');
  const incListEl   = document.getElementById('incList');

  // ---------- State ----------
  const MAX_ALERTS = 2000;
  let alerts   = [];
  let eventsIn = 0;
  let catalog  = { vendors: [] };
  const incidents = new Map(); // id -> incident json

  // ---------- Helpers ----------
  const nowSec = () => Math.floor(Date.now() / 1000);
  const setText = (el, s) => { if (el) el.textContent = s; };
  const safeAdd = (el, child) => { if (el && child) el.appendChild(child); };

  function parseTs(x) {
    if (x == null) return nowSec();
    if (typeof x === 'number') return x > 2_000_000_000 ? Math.floor(x/1000) : x; // ms→s
    const s = String(x);
    const t = Date.parse(s);
    if (!Number.isNaN(t)) return Math.floor(t/1000);
    const n = Number(s);
    if (!Number.isNaN(n)) return n > 2_000_000_000 ? Math.floor(n/1000) : n;
    return nowSec();
  }

  const tsOf = (a) => parseTs(a?.ts ?? a?.time ?? a?.timestamp);
  const fmt  = (ts) => new Date(Number(ts) * 1000).toLocaleString();

  function severityCategory(a) {
    const s = a?.severity;
    if (typeof s === 'number') {
      if (s >= 0.80) return 'high';
      if (s >= 0.55) return 'medium';
      if (s > 0)     return 'low';
      return 'none';
    }
    return (String(s || '').toLowerCase());
  }
  const sevOf  = (a) => severityCategory(a);
  const riskOf = (a) => Number(a?.risk ?? a?.score ?? 0);

  function extractText(a) {
    const exe  = a?.event?.exe ?? a?.event?.binary_path ?? a?.event?.category ?? '';
    const cmd  = a?.event?.cmdline ?? a?.event?.command_line ?? '';
    const tags = (Array.isArray(a?.findings) ? a.findings : [])
      .map(f => (f && (f.label || f.rule || f.source)) || '')
      .join(' ');
    return { exe, cmd, tags };
  }

  function badgeClass(a) {
    const s = severityCategory(a);
    if (s === 'high')   return 'bg-rose-700/80';
    if (s === 'medium') return 'bg-amber-600/80';
    if (s === 'low')    return 'bg-emerald-700/80';
    return 'bg-slate-700/80';
  }

  function shortWhy(a) {
    if (!a) return '';
    if (a.explanation && (a.explanation.summary || a.explanation.short)) {
      return a.explanation.summary || a.explanation.short;
    }
    const sev = (severityCategory(a) || 'none').toUpperCase();
    const f = Array.isArray(a.findings) ? a.findings.slice() : [];
    f.sort((x, y) => (y?.score || 0) - (x?.score || 0));
    const top = f[0] || {};
    const technique =
      a.technique ||
      (top.label && /^T\d{4}(\.\d{3})?$/.test(top.label) ? top.label : null);
    const who = (top.source ? `${top.source}${top.rule ? ':'+top.rule : ''}` :
                (top.rule || top.id || top.label || null));
    const exe = a?.event?.exe || a?.event?.binary_path || a?.event?.category || '';
    const cmd = a?.event?.cmdline || a?.event?.command_line || '';
    const parts = [
      sev + (technique ? ` · ${technique}` : ''),
      who ? `by ${who}` : '',
      exe,
      cmd,
    ].filter(Boolean);
    const line = parts.join(' — ');
    return line.length > 240 ? (line.slice(0, 237) + '…') : line;
  }

  function synthIdFor(a) {
    const key = `${tsOf(a)}${a?.event?.exe || a?.event?.binary_path || '-'}${a?.event?.cmdline || a?.event?.command_line || '-'}`;
    let h = 0; for (let i = 0; i < key.length; i++) h = ((h << 5) - h) + key.charCodeAt(i) | 0;
    return String(h >>> 0);
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }

  // ---------- Tabs ----------
  function activateTab(which) {
    if (!screenDash || !screenInt || !tabDash || !tabInt) return;
    const onDash = which === 'dash';
    const onInt = which === 'int';
    const onImport = which === 'import';
    const onCompare = which === 'compare';
    const onLicense = which === 'license';
    
    screenDash.classList.toggle('hidden', !onDash);
    screenInt.classList.toggle('hidden', !onInt);
    if (screenImport) screenImport.classList.toggle('hidden', !onImport);
    if (screenCompare) screenCompare.classList.toggle('hidden', !onCompare);
    if (screenLicense) screenLicense.classList.toggle('hidden', !onLicense);
    
    tabDash.className = onDash
      ? 'px-3 py-1 rounded bg-sky-600 text-white'
      : 'px-3 py-1 rounded bg-slate-800 text-slate-200';
    tabInt.className = onInt
      ? 'px-3 py-1 rounded bg-sky-600 text-white'
      : 'px-3 py-1 rounded bg-slate-800 text-slate-200';
    if (tabImport) {
      tabImport.className = onImport
        ? 'px-3 py-1 rounded bg-sky-600 text-white'
        : 'px-3 py-1 rounded bg-slate-800 text-slate-200';
    }
    if (tabCompare) {
      tabCompare.className = onCompare
        ? 'px-3 py-1 rounded bg-sky-600 text-white'
        : 'px-3 py-1 rounded bg-slate-800 text-slate-200';
    }
    if (tabLicense) {
      tabLicense.className = onLicense
        ? 'px-3 py-1 rounded bg-sky-600 text-white'
        : 'px-3 py-1 rounded bg-slate-800 text-slate-200';
    }
    
    if (onInt) loadIntegrations();
    if (onImport) loadImportedCases();
    if (onCompare) loadRunsForCompare();
    if (onLicense) loadLicenseStatus();
  }
  if (tabDash) tabDash.onclick = () => activateTab('dash');
  if (tabInt)  tabInt.onclick  = () => activateTab('int');
  if (tabImport) tabImport.onclick = () => activateTab('import');
  if (tabCompare) tabCompare.onclick = () => activateTab('compare');
  if (tabLicense) tabLicense.onclick = () => activateTab('license');
  activateTab('dash');

  // ---------- SSE Alerts ----------
  const es = new EventSource('/alerts');
  es.onmessage = (ev) => {
    try {
      const a = JSON.parse(ev.data);
      alerts.push(a);
      if (alerts.length > MAX_ALERTS) alerts.splice(0, alerts.length - MAX_ALERTS);
      setText(statAlerts, `alerts: ${alerts.length}`);
      renderTable();
      pushTimelinePoint(a);
    } catch { /* ignore */ }
  };
  es.onerror = () => { /* browser auto-retries SSE */ };

  // ---------- Incidents SSE (DecisionEngine rollups) ----------
  if (incListEl) {
    const esInc = new EventSource('/incidents/stream');
    esInc.onmessage = (ev) => {
      try {
        const it = JSON.parse(ev.data);
        if (it && it.id) {
          incidents.set(it.id, it);
          renderIncidents();
        }
      } catch {}
    };
  }

  function renderIncidents() {
    if (!incListEl) return;
    const items = Array.from(incidents.values())
      .sort((a,b) => (b.last_ts||0) - (a.last_ts||0))
      .slice(0, 40);
    incListEl.textContent = '';
    if (!items.length) {
      const p = incWrap?.querySelector('.text-slate-400');
      if (p) p.classList.remove('hidden');
      return;
    } else {
      const p = incWrap?.querySelector('.text-slate-400');
      if (p) p.classList.add('hidden');
    }
    for (const x of items) {
      const li = el('li','py-2 flex items-start justify-between gap-2');
      const left = el('div','min-w-0');
      const sevColor =
        x.severity_max === 'high' ? 'bg-rose-700/80' :
        x.severity_max === 'medium' ? 'bg-amber-600/80' :
        x.severity_max === 'low' ? 'bg-emerald-700/80' : 'bg-slate-700/80';
      const sev = el('span',`inline-block px-2 py-0.5 rounded text-xs mr-2 ${sevColor}`, (x.severity_max || 'none'));
      const head = el('div','font-medium truncate');
      head.appendChild(sev);
      head.appendChild(document.createTextNode(`${x.exe || '-'} · ${x.primary_technique || '-'}`));
      const sub = el('div','text-xs text-slate-400 mt-0.5',
        `alerts: ${x.alerts_count ?? 0} · risk_max: ${(x.risk_max ?? 0).toFixed(2)} · rgcn: ${(x.rgcn_score ?? 0).toFixed(2)} · ${new Date((x.last_ts||0)*1000).toLocaleString()}`);
      left.appendChild(head); left.appendChild(sub);
      const techs = Array.isArray(x.techniques) ? x.techniques.slice(0,6) : [];
      const chips = el('div','mt-1 flex flex-wrap gap-1 text-[11px]');
      for (const t of techs) chips.appendChild(el('span','px-1.5 py-0.5 rounded bg-slate-800', t));
      left.appendChild(chips);
      li.appendChild(left);
      incListEl.appendChild(li);
    }
  }

  // ---------- Signals Panel (Playbook-based) ----------
  const signalsList = document.getElementById('signalsList');
  const signalsEmpty = document.getElementById('signalsEmpty');
  const refreshSignalsBtn = document.getElementById('refreshSignalsBtn');
  const explainModal = document.getElementById('explainModal');

  async function loadSignals() {
    if (!signalsList) return;
    try {
      const r = await fetch('/api/signals?limit=50');
      const result = await r.json();
      if (!result.success || !result.data) return;
      
      const signals = result.data;
      signalsList.textContent = '';
      
      if (signals.length === 0) {
        if (signalsEmpty) signalsEmpty.classList.remove('hidden');
        return;
      }
      if (signalsEmpty) signalsEmpty.classList.add('hidden');
      
      for (const sig of signals) {
        const li = el('li', 'py-2 flex items-start justify-between gap-2');
        
        // Left side: signal info
        const left = el('div', 'min-w-0 flex-1');
        const sevColor = 
          sig.severity === 'Critical' ? 'bg-rose-700/80' :
          sig.severity === 'High' ? 'bg-amber-600/80' :
          sig.severity === 'Medium' ? 'bg-yellow-600/80' :
          'bg-emerald-700/80';
        
        const head = el('div', 'font-medium truncate flex items-center gap-2');
        const sev = el('span', `inline-block px-2 py-0.5 rounded text-xs ${sevColor}`, sig.severity);
        head.appendChild(sev);
        head.appendChild(document.createTextNode(sig.signal_type || 'unknown'));
        
        const sub = el('div', 'text-xs text-slate-400 mt-0.5',
          `${sig.signal_id.slice(0, 16)}... · ${sig.host} · ${new Date(sig.ts).toLocaleString()}`);
        
        left.appendChild(head);
        left.appendChild(sub);
        
        // Evidence count
        const evCount = Array.isArray(sig.evidence_ptrs) ? sig.evidence_ptrs.length : 0;
        const evBadge = el('span', 'text-xs text-slate-500', `${evCount} evidence`);
        left.appendChild(evBadge);
        
        // Right side: Explain button + Narrative button
        const right = el('div', 'flex items-center gap-1');
        const explainBtn = el('button', 
          'px-2 py-1 rounded bg-sky-600 hover:bg-sky-500 text-xs font-medium',
          '🔍 Explain');
        explainBtn.onclick = (e) => {
          e.stopPropagation();
          showExplanation(sig.signal_id);
        };
        right.appendChild(explainBtn);
        
        // Narrative button
        const narrativeBtn = el('button',
          'px-2 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-xs font-medium',
          '📜 Narrative');
        narrativeBtn.onclick = (e) => {
          e.stopPropagation();
          showNarrative(sig.signal_id);
        };
        right.appendChild(narrativeBtn);
        
        li.appendChild(left);
        li.appendChild(right);
        signalsList.appendChild(li);
      }
    } catch (err) {
      console.error('Failed to load signals:', err);
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  async function showExplanation(signalId) {
    if (!explainModal) return;
    
    // Show modal
    explainModal.showModal();
    document.getElementById('explainModalTitle').textContent = 'Loading...';
    document.getElementById('explainModalSubtitle').textContent = signalId;
    document.getElementById('explainSummary').textContent = '';
    document.getElementById('explainSlotsBody').innerHTML = '';
    document.getElementById('explainEvidence').innerHTML = '';
    document.getElementById('explainEntitiesBundle').innerHTML = '';
    document.getElementById('explainLimitations').classList.add('hidden');
    
    try {
      const r = await fetch(`/api/signals/${signalId}/explain`);
      const result = await r.json();
      
      if (!result.success || !result.data) {
        document.getElementById('explainModalTitle').textContent = 'Explanation Not Found';
        document.getElementById('explainSummary').textContent = result.error || 'No explanation available for this signal.';
        return;
      }
      
      const exp = result.data;
      
      // Title
      document.getElementById('explainModalTitle').textContent = exp.playbook_title || exp.playbook_id;
      document.getElementById('explainModalSubtitle').textContent = `${exp.family} · ${signalId}`;
      
      // Summary
      document.getElementById('explainSummary').textContent = exp.summary || 'No summary available.';
      
      // Slots table
      const slotsBody = document.getElementById('explainSlotsBody');
      slotsBody.innerHTML = '';
      for (const slot of (exp.slots || [])) {
        const tr = document.createElement('tr');
        
        const statusColor = 
          slot.status === 'filled' ? 'text-emerald-400' :
          slot.status === 'partial' ? 'text-amber-400' :
          slot.status === 'expired' ? 'text-slate-500' :
          'text-rose-400';
        
        tr.innerHTML = `
          <td class="py-1 px-2">${escapeHtml(slot.name)}</td>
          <td class="py-1 px-2">${slot.required ? '✓' : ''}</td>
          <td class="py-1 px-2 ${statusColor}">${slot.status}</td>
          <td class="py-1 px-2 text-slate-400 truncate max-w-[150px]" title="${escapeHtml(slot.predicate_desc)}">${escapeHtml(slot.predicate_desc)}</td>
          <td class="py-1 px-2">${(slot.matched_facts || []).length}</td>
        `;
        slotsBody.appendChild(tr);
      }
      
      // Evidence
      const evidenceEl = document.getElementById('explainEvidence');
      evidenceEl.innerHTML = '';
      for (const ev of (exp.evidence || [])) {
        const div = document.createElement('div');
        div.className = 'p-2 bg-slate-800/50 rounded';
        const ptr = ev.ptr;
        div.innerHTML = `
          <div class="text-sky-400">${ptr.stream_id}:${ptr.segment_id}:${ptr.record_index}</div>
          <div class="text-slate-500 text-[10px]">${ev.source} · ${new Date(ev.ts_ms).toLocaleString()}</div>
          ${ev.excerpt ? `<div class="text-slate-300 mt-1 text-[10px] break-all">${escapeHtml(ev.excerpt)}</div>` : ''}
        `;
        evidenceEl.appendChild(div);
      }
      if ((exp.evidence || []).length === 0) {
        evidenceEl.innerHTML = '<div class="text-slate-500">No evidence excerpts available</div>';
      }
      
      // Entities
      const entitiesEl = document.getElementById('explainEntitiesBundle');
      entitiesEl.innerHTML = '';
      const entities = exp.entities || {};
      const entityTypes = [
        ['proc_keys', 'Processes'],
        ['file_keys', 'Files'],
        ['identity_keys', 'Users'],
        ['net_keys', 'Network'],
        ['registry_keys', 'Registry']
      ];
      for (const [key, label] of entityTypes) {
        const vals = entities[key] || [];
        if (vals.length > 0) {
          const div = document.createElement('div');
          div.innerHTML = `
            <div class="text-slate-400 text-[10px]">${label}</div>
            <div class="text-slate-200">${vals.slice(0,3).map(v => escapeHtml(v.slice(0,30))).join(', ')}${vals.length > 3 ? '...' : ''}</div>
          `;
          entitiesEl.appendChild(div);
        }
      }
      
      // Limitations
      const limitations = exp.limitations || [];
      if (limitations.length > 0) {
        document.getElementById('explainLimitations').classList.remove('hidden');
        const limList = document.getElementById('explainLimitationsList');
        limList.innerHTML = limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('');
      }
      
      // Counters
      const counters = exp.counters || {};
      document.getElementById('counterReqFilled').textContent = counters.required_slots_filled ?? 0;
      document.getElementById('counterReqTotal').textContent = counters.required_slots_total ?? 0;
      document.getElementById('counterOptFilled').textContent = counters.optional_slots_filled ?? 0;
      document.getElementById('counterOptTotal').textContent = counters.optional_slots_total ?? 0;
      document.getElementById('counterFacts').textContent = counters.facts_emitted ?? 0;
      
    } catch (err) {
      console.error('Failed to load explanation:', err);
      document.getElementById('explainModalTitle').textContent = 'Error';
      document.getElementById('explainSummary').textContent = 'Failed to load explanation: ' + err.message;
    }
  }

  // ========== Narrative Modal ==========
  const narrativeModal = document.getElementById('narrativeModal');
  let currentNarrativeSignalId = null;
  let currentNarrative = null;

  async function showNarrative(signalId) {
    if (!narrativeModal) return;
    
    currentNarrativeSignalId = signalId;
    narrativeModal.showModal();
    document.getElementById('narrativeModalTitle').textContent = '📜 Loading...';
    document.getElementById('narrativeModalSubtitle').textContent = signalId;
    document.getElementById('narrativeSentences').innerHTML = '<div class="text-slate-400">Loading narrative...</div>';
    
    try {
      const r = await fetch(`/api/signals/${signalId}/narrative`);
      const result = await r.json();
      
      if (!result.success || !result.data) {
        document.getElementById('narrativeModalTitle').textContent = '📜 Narrative Not Available';
        document.getElementById('narrativeSentences').innerHTML = `<div class="text-rose-400">${result.error || 'Could not generate narrative'}</div>`;
        return;
      }
      
      currentNarrative = result.data;
      renderNarrative(currentNarrative);
      
    } catch (err) {
      console.error('Failed to load narrative:', err);
      document.getElementById('narrativeModalTitle').textContent = '📜 Error';
      document.getElementById('narrativeSentences').innerHTML = `<div class="text-rose-400">Failed to load narrative: ${err.message}</div>`;
    }
  }

  function renderNarrative(narrative) {
    // Title & mode
    document.getElementById('narrativeModalTitle').textContent = '📜 Signal Narrative';
    document.getElementById('narrativeModalSubtitle').textContent = `${narrative.signal_id} · v${narrative.version}`;
    
    const mode = narrative.mode_context?.mode || 'Discovery';
    const modeTag = document.getElementById('narrativeModeTag');
    modeTag.textContent = mode;
    modeTag.className = mode === 'Mission' 
      ? 'px-2 py-0.5 text-xs rounded bg-sky-600/20 text-sky-400'
      : 'px-2 py-0.5 text-xs rounded bg-emerald-600/20 text-emerald-400';
    
    // Validation badge
    const validationBadge = document.getElementById('narrativeValidation');
    const isValid = validateNarrativeClient(narrative);
    validationBadge.textContent = isValid ? '✓ Valid' : '⚠ Issues';
    validationBadge.className = isValid 
      ? 'text-xs px-2 py-0.5 rounded bg-emerald-600/20 text-emerald-400'
      : 'text-xs px-2 py-0.5 rounded bg-amber-600/20 text-amber-400';
    
    // Render sentences
    const sentencesEl = document.getElementById('narrativeSentences');
    sentencesEl.innerHTML = '';
    
    for (const sentence of (narrative.sentences || [])) {
      const div = document.createElement('div');
      div.className = 'p-3 rounded border border-slate-700 hover:border-slate-500 cursor-pointer transition-colors';
      div.dataset.sentenceId = sentence.sentence_id;
      
      const typeColors = {
        'Observation': 'text-emerald-400',
        'Inference': 'text-amber-400',
        'Context': 'text-slate-400',
        'Summary': 'text-sky-400'
      };
      const typeColor = typeColors[sentence.sentence_type] || 'text-slate-300';
      
      // Type badge
      const typeBadge = sentence.sentence_type === 'Inference' && sentence.inference_label
        ? `<span class="text-xs ${typeColor} font-medium">${sentence.sentence_type}:${sentence.inference_label}</span>`
        : `<span class="text-xs ${typeColor} font-medium">${sentence.sentence_type}</span>`;
      
      // Evidence count
      const receipts = sentence.receipts || {};
      const evCount = (receipts.evidence_ptrs || []).length;
      const factCount = (receipts.supporting_facts || []).length;
      
      // Build receipt indicators
      let receiptIndicators = '';
      if (evCount > 0) {
        receiptIndicators += `<button class="receipt-btn px-1.5 py-0.5 rounded bg-sky-700/50 hover:bg-sky-600/70 text-[10px]" data-type="evidence" data-sentence="${sentence.sentence_id}">📄 ${evCount} evidence</button>`;
      }
      if (factCount > 0) {
        receiptIndicators += `<button class="receipt-btn px-1.5 py-0.5 rounded bg-amber-700/50 hover:bg-amber-600/70 text-[10px]" data-type="facts" data-sentence="${sentence.sentence_id}">🔗 ${factCount} facts</button>`;
      }
      
      // Confidence
      const conf = sentence.confidence ?? 1.0;
      const confColor = conf >= 0.8 ? 'text-emerald-400' : conf >= 0.5 ? 'text-amber-400' : 'text-rose-400';
      
      div.innerHTML = `
        <div class="flex items-center justify-between mb-1">
          ${typeBadge}
          <span class="${confColor} text-[10px]">${(conf * 100).toFixed(0)}% conf</span>
        </div>
        <div class="text-sm text-slate-200 mb-2">${escapeHtml(sentence.text)}</div>
        <div class="flex items-center gap-2">
          ${receiptIndicators}
        </div>
      `;
      
      sentencesEl.appendChild(div);
    }
    
    // Wire receipt buttons
    sentencesEl.querySelectorAll('.receipt-btn').forEach(btn => {
      btn.onclick = (e) => {
        e.stopPropagation();
        const sentenceId = btn.dataset.sentence;
        const type = btn.dataset.type;
        const sentence = narrative.sentences.find(s => s.sentence_id === sentenceId);
        if (sentence) {
          showEvidenceReceipt(btn, sentence.receipts, type);
        }
      };
    });
    
    // Render arbitration
    renderArbitration(narrative.arbitration);
    
    // Render disambiguation
    renderDisambiguation(narrative.disambiguation);
  }

  function validateNarrativeClient(narrative) {
    // Check observations have evidence
    for (const s of (narrative.sentences || [])) {
      if (s.sentence_type === 'Observation') {
        const evPtrs = s.receipts?.evidence_ptrs || [];
        if (evPtrs.length === 0) return false;
      }
      if (s.sentence_type === 'Inference') {
        const facts = s.receipts?.supporting_facts || [];
        const slots = s.receipts?.supporting_slots || [];
        if (facts.length === 0 && slots.length === 0) return false;
      }
    }
    return true;
  }

  function showEvidenceReceipt(anchorEl, receipts, type) {
    const tooltip = document.getElementById('evidenceReceiptTooltip');
    if (!tooltip) return;
    
    const content = document.getElementById('receiptContent');
    content.innerHTML = '';
    
    if (type === 'evidence') {
      const ptrs = receipts.evidence_ptrs || [];
      const excerpts = receipts.excerpts || [];
      
      for (let i = 0; i < ptrs.length; i++) {
        const ptr = ptrs[i];
        const excerpt = excerpts[i] || '';
        const div = document.createElement('div');
        div.className = 'p-2 bg-slate-900 rounded border border-slate-700';
        div.innerHTML = `
          <div class="text-sky-400 font-mono text-[10px]">${ptr.stream_id || ''}:${ptr.segment_id || ''}:${ptr.record_index || ''}</div>
          ${ptr.source ? `<div class="text-slate-500 text-[10px]">${ptr.source}</div>` : ''}
          ${excerpt ? `<div class="text-slate-300 mt-1 break-all">${escapeHtml(excerpt)}</div>` : ''}
        `;
        content.appendChild(div);
      }
      
      if (ptrs.length === 0) {
        content.innerHTML = '<div class="text-slate-400">No evidence pointers</div>';
      }
    } else if (type === 'facts') {
      const facts = receipts.supporting_facts || [];
      const slots = receipts.supporting_slots || [];
      
      for (const fact of facts) {
        const div = document.createElement('div');
        div.className = 'p-2 bg-slate-900 rounded border border-slate-700';
        div.innerHTML = `
          <div class="text-amber-400 text-[10px]">Fact: ${escapeHtml(fact.fact_type || fact)}</div>
          ${fact.summary ? `<div class="text-slate-300 mt-1">${escapeHtml(fact.summary)}</div>` : ''}
        `;
        content.appendChild(div);
      }
      
      if (slots.length > 0) {
        const slotsDiv = document.createElement('div');
        slotsDiv.className = 'p-2 bg-slate-900 rounded border border-slate-700';
        slotsDiv.innerHTML = `
          <div class="text-purple-400 text-[10px]">Supporting slots</div>
          <div class="text-slate-300">${slots.join(', ')}</div>
        `;
        content.appendChild(slotsDiv);
      }
      
      if (facts.length === 0 && slots.length === 0) {
        content.innerHTML = '<div class="text-slate-400">No supporting facts or slots</div>';
      }
    }
    
    // Position tooltip near anchor
    const rect = anchorEl.getBoundingClientRect();
    tooltip.style.left = `${rect.left}px`;
    tooltip.style.top = `${rect.bottom + 5}px`;
    tooltip.classList.remove('hidden');
    
    // Close on click outside
    const closeHandler = (e) => {
      if (!tooltip.contains(e.target) && e.target !== anchorEl) {
        tooltip.classList.add('hidden');
        document.removeEventListener('click', closeHandler);
      }
    };
    setTimeout(() => document.addEventListener('click', closeHandler), 0);
  }

  function renderArbitration(arb) {
    if (!arb) {
      document.getElementById('arbitrationSection').innerHTML = '<div class="text-slate-400">No arbitration data</div>';
      return;
    }
    
    // Winner
    const winner = arb.winner;
    if (winner) {
      document.getElementById('arbWinnerName').textContent = winner.hypothesis_name || 'Unknown';
      const slots = winner.slot_status || {};
      document.getElementById('arbWinnerSlots').textContent = `${slots.filled_count || 0}/${slots.total_count || 0} filled`;
      
      const winReasons = document.getElementById('arbWinReasons');
      winReasons.innerHTML = '';
      for (const reason of (arb.win_reasons || ['Higher confidence'])) {
        const li = document.createElement('li');
        li.textContent = reason;
        winReasons.appendChild(li);
      }
    }
    
    // Runner up
    const runnerUp = arb.runner_up;
    const runnerUpSection = document.getElementById('arbRunnerUpSection');
    if (runnerUp) {
      runnerUpSection.classList.remove('hidden');
      document.getElementById('arbRunnerUpName').textContent = runnerUp.hypothesis_name || 'Unknown';
      const slots = runnerUp.slot_status || {};
      document.getElementById('arbRunnerUpSlots').textContent = `${slots.filled_count || 0}/${slots.total_count || 0} filled`;
      
      const lossReasons = document.getElementById('arbRunnerUpLoss');
      lossReasons.innerHTML = '';
      for (const reason of (arb.runner_up_loss_reasons || ['Lower slot fill'])) {
        const li = document.createElement('li');
        li.textContent = reason;
        lossReasons.appendChild(li);
      }
    } else {
      runnerUpSection.classList.add('hidden');
    }
    
    // Third
    const third = arb.third;
    const thirdSection = document.getElementById('arbThirdSection');
    if (third) {
      thirdSection.classList.remove('hidden');
      document.getElementById('arbThirdName').textContent = third.hypothesis_name || 'Unknown';
      
      const lossReasons = document.getElementById('arbThirdLoss');
      lossReasons.innerHTML = '';
      for (const reason of (arb.third_loss_reasons || ['Further from threshold'])) {
        const li = document.createElement('li');
        li.textContent = reason;
        lossReasons.appendChild(li);
      }
    } else {
      thirdSection.classList.add('hidden');
    }
  }

  function renderDisambiguation(disamb) {
    if (!disamb) {
      document.getElementById('disambiguationSection').classList.add('hidden');
      return;
    }
    
    document.getElementById('disambiguationSection').classList.remove('hidden');
    
    // Ambiguity score
    const scoreEl = document.getElementById('ambiguityScore');
    const score = disamb.ambiguity_score || 0;
    if (score < 0.3) {
      scoreEl.textContent = 'Low ambiguity';
      scoreEl.className = 'text-xs px-2 py-0.5 rounded bg-emerald-600/20 text-emerald-300';
    } else if (score < 0.6) {
      scoreEl.textContent = 'Moderate ambiguity';
      scoreEl.className = 'text-xs px-2 py-0.5 rounded bg-amber-600/20 text-amber-300';
    } else {
      scoreEl.textContent = 'High ambiguity';
      scoreEl.className = 'text-xs px-2 py-0.5 rounded bg-rose-600/20 text-rose-300';
    }
    
    // Questions
    const questionsEl = document.getElementById('disambiguationQuestions');
    questionsEl.innerHTML = '';
    for (const q of (disamb.questions || [])) {
      const div = document.createElement('div');
      div.className = 'p-2 rounded bg-slate-700/50';
      div.innerHTML = `
        <div class="text-sm text-slate-200 mb-1">❓ ${escapeHtml(q.text)}</div>
        <div class="text-xs text-slate-400">${escapeHtml(q.reason)}</div>
      `;
      questionsEl.appendChild(div);
    }
    
    // Pivot actions
    const pivotEl = document.getElementById('pivotActions');
    pivotEl.innerHTML = '';
    for (const p of (disamb.pivot_actions || [])) {
      const div = document.createElement('div');
      div.className = 'p-2 rounded bg-sky-900/30 border border-sky-700/50';
      div.innerHTML = `
        <div class="text-sm text-sky-300 mb-1">🔄 ${escapeHtml(p.description)}</div>
        <div class="text-xs text-slate-400">Target: ${p.target_slot || 'general'} · Impact: ${p.estimated_impact || 'unknown'}</div>
      `;
      pivotEl.appendChild(div);
    }
    
    // Capability suggestions
    const capEl = document.getElementById('capabilitySuggestions');
    capEl.innerHTML = '';
    if ((disamb.capability_suggestions || []).length > 0) {
      capEl.innerHTML = '<div class="text-xs text-slate-400 mb-2">💡 Missing capabilities:</div>';
      for (const cap of disamb.capability_suggestions) {
        const div = document.createElement('div');
        div.className = 'p-2 rounded bg-purple-900/30 border border-purple-700/50 mb-1';
        div.innerHTML = `
          <div class="text-sm text-purple-300">${escapeHtml(cap.capability_name)}</div>
          <div class="text-xs text-slate-400">${escapeHtml(cap.reason)}</div>
        `;
        capEl.appendChild(div);
      }
    }
  }

  // Wire up narrative UI
  if (narrativeModal) {
    document.getElementById('closeNarrativeModal').onclick = () => narrativeModal.close();
    document.getElementById('narrativeDoneBtn').onclick = () => narrativeModal.close();
    narrativeModal.onclick = (e) => {
      if (e.target === narrativeModal) narrativeModal.close();
    };
    
    // User action buttons
    document.getElementById('btnPinSentence')?.addEventListener('click', async () => {
      const selected = document.querySelector('#narrativeSentences [data-selected]');
      if (selected && currentNarrative) {
        await saveNarrativeAction('pin', selected.dataset.sentenceId);
      }
    });
    
    document.getElementById('btnHideSentence')?.addEventListener('click', async () => {
      const selected = document.querySelector('#narrativeSentences [data-selected]');
      if (selected && currentNarrative) {
        await saveNarrativeAction('hide', selected.dataset.sentenceId);
      }
    });
    
    document.getElementById('btnVerifyEvidence')?.addEventListener('click', async () => {
      if (currentNarrative) {
        await saveNarrativeAction('verify', null, 'User verified evidence');
        alert('Evidence marked as verified');
      }
    });
    
    document.getElementById('btnExportNarrative')?.addEventListener('click', () => {
      if (currentNarrative) {
        const blob = new Blob([JSON.stringify(currentNarrative, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `narrative_${currentNarrative.signal_id}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
    });
  }

  async function saveNarrativeAction(actionType, sentenceId, notes) {
    if (!currentNarrative) return;
    
    try {
      await fetch(`/api/narratives/${currentNarrative.narrative_id}/actions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sentence_id: sentenceId,
          action_type: actionType,
          notes: notes
        })
      });
    } catch (err) {
      console.error('Failed to save narrative action:', err);
    }
  }

  // Wire up UI
  if (refreshSignalsBtn) {
    refreshSignalsBtn.onclick = loadSignals;
  }
  if (explainModal) {
    document.getElementById('closeExplainModal').onclick = () => explainModal.close();
    document.getElementById('explainDoneBtn').onclick = () => explainModal.close();
    explainModal.onclick = (e) => {
      if (e.target === explainModal) explainModal.close();
    };
  }

  // Load signals on startup and every 30s
  loadSignals();
  setInterval(loadSignals, 30000);

  // ---------- Metrics poll ----------
  async function pollMetrics() {
    try {
      const r = await fetch('/metrics');
      if (!r.ok) return;
      const m = await r.json();
      eventsIn = m.events_in || 0;
      setText(statEvents, `events: ${eventsIn}`);
      setText(statNodes,  `nodes: ${m.nodes_count ?? 0}`);
      setText(statEdges,  `edges: ${m.edges_count ?? 0}`);
      setText(statDrops,  `bpf_drops: ${m.bpf_drops_total ?? 0}`);
    } catch { /* ignore */ }
  }
  setInterval(pollMetrics, 5000); pollMetrics();

  // ---------- Alerts table ----------
  if (sevEl)   sevEl.onchange   = renderTable;
  if (searchEl) searchEl.oninput = renderTable;

  function renderTable() {
    if (!rowsEl) return;
    const sevFilter = (sevEl && sevEl.value || '').toLowerCase();
    const q = (searchEl && searchEl.value || '').toLowerCase();
    rowsEl.textContent = ''; // clear safely

    // newest first
    for (let i = alerts.length - 1; i >= 0; i--) {
      const a = alerts[i];
      if (sevFilter && sevOf(a) !== sevFilter) continue;

      const { exe, cmd, tags } = extractText(a);
      const hay = (exe + ' ' + cmd + ' ' + tags).toLowerCase();
      if (q && !hay.includes(q)) continue;

      const tr = el('tr', 'hover:bg-slate-900 cursor-pointer');
      tr.title = shortWhy(a);
      tr.onclick = () => selectAlert(a);

      const findings = (a.findings || [])
        .map(f => `${f?.source ?? 'detector'}:${Number(f?.score || 0).toFixed(2)}${f?.label ? `(${f.label})` : ''}`)
        .join(', ');
      const risk = riskOf(a).toFixed(2);
      const ts = tsOf(a);

      const tdTime = el('td', 'px-3 py-2', fmt(ts));

      const tdSev = el('td', 'px-3 py-2');
      const sevBadge = el('span', `px-2 py-1 rounded text-xs ${badgeClass(a)}`, severityCategory(a) || 'none');
      tdSev.appendChild(sevBadge);

      const tdRisk = el('td', 'px-3 py-2', risk);

      const tdEvent = el('td', 'px-3 py-2 truncate max-w-[520px]');
      const exeDiv  = el('div', 'text-slate-200', exe || '-');
      const cmdDiv  = el('div', 'text-slate-400', cmd || '');
      tdEvent.appendChild(exeDiv); tdEvent.appendChild(cmdDiv);

      const tdFind = el('td', 'px-3 py-2', findings);

      tr.appendChild(tdTime);
      tr.appendChild(tdSev);
      tr.appendChild(tdRisk);
      tr.appendChild(tdEvent);
      tr.appendChild(tdFind);
      rowsEl.appendChild(tr);
    }
  }

  // ---------- Timeline chart ----------
  const timelineData = { datasets: [{ label: 'alerts', data: [], pointRadius: 4 }] };
  let timelineChart = null;

  if (timelineCanvas && window.Chart) {
    const timelineCtx = timelineCanvas.getContext('2d');
    const hasTimeScale = !!(Chart?.registry?.getScale?.('time'));
    const xScale = hasTimeScale
      ? { type: 'time', time: { unit: 'minute' }, ticks: { color: '#cbd5e1' }, grid: { color: '#334155' } }
      : { type: 'linear', ticks: { color: '#cbd5e1' }, grid: { color: '#334155' } };

    timelineChart = new Chart(timelineCtx, {
      type: 'scatter',
      data: timelineData,
      options: {
        animation: false,
        plugins: {
          legend: { labels: { color: '#cbd5e1' } },
          tooltip: { callbacks: { label: (ctx) => shortWhy(ctx.raw?.__alert) } }
        },
        scales: {
          x: xScale,
          y: { display: false }
        },
        onClick: (_, elems) => {
          if (elems?.length) {
            const idx = elems[0].index;
            const obj = timelineData.datasets[0].data[idx].__alert;
            selectAlert(obj);
          }
        }
      }
    });
  }

  function pushTimelinePoint(a) {
    if (!timelineChart) return;
    const t = tsOf(a) * 1000;
    timelineData.datasets[0].data.push({ x: t, y: 1, __alert: a });
    if (timelineData.datasets[0].data.length > 400) timelineData.datasets[0].data.shift();
    timelineChart.update('none');
  }

  // ---------- Explain drawer ----------
  if (exCloseBtn) exCloseBtn.onclick = () => drawer && drawer.classList.add('hidden');

  async function openExplain(id) {
    try {
      const r = await fetch(`/alerts/${encodeURIComponent(id)}/explain`);
      if (!r.ok) return;
      const ex = await r.json();
      renderExplain(ex);
      if (drawer) drawer.classList.remove('hidden');
    } catch { /* ignore */ }
  }

  function renderExplain(ex) {
    if (!ex) return;
    const H = (id, v) => { const n = document.getElementById(id); if (n) n.textContent = v; };

    // headline + scores
    H('ex_head', ex.headline || 'Explain');
    H('ex_risk', Number(ex.risk || 0).toFixed(2));
    H('ex_rgcn', Number(ex.rgcn_score || 0).toFixed(2));

    // entities
    H('ex_entities', JSON.stringify(ex.entities || {}, null, 2));

    // findings
    const whyUl = document.getElementById('ex_why');
    if (whyUl) {
      whyUl.textContent = '';
      (ex.why || []).forEach(w => {
        const li  = el('li', null,
          `${w?.source || 'detector'} · ${Number(w?.score || 0).toFixed(2)}${w?.label ? ` · ${w.label}` : ''}`
        );
        whyUl.appendChild(li);
      });
    }
    H('ex_anoms', (ex.anomalies || []).join(', ') || '—');

    // graph
    const g = ex.graph || { nodes: [], edges: [], links: [] };
    const edges = Array.isArray(g.edges) && g.edges.length ? g.edges : (g.links || []);
    const graphDiv = document.getElementById('ex_graph');
    if (graphDiv) {
      graphDiv.innerHTML = '';
      if ((g.nodes || []).length) {
        ensureCytoscape().then(() => {
          graphDiv.innerHTML = '';
          cytoscape({
            container: graphDiv,
            elements: {
              nodes: g.nodes.map(n => ({ data: { id: n.id, label: (n.binary_path || n.id) } })),
              edges: edges.map(e => ({ data: { source: e.source, target: e.target } }))
            },
            style: [
              { selector: 'node', style: { 'background-color': '#22d3ee', 'label': 'data(label)', 'font-size': '10px', 'color': '#0f172a', 'shape': 'round-rectangle', 'padding': '5px' } },
              { selector: 'edge', style: { 'line-color': '#64748b', 'target-arrow-color': '#64748b', 'target-arrow-shape': 'triangle' } }
            ],
            layout: { name: 'breadthfirst', directed: true, padding: 8 }
          });
        });
      }
    }

    // timeline (explain window)
    const tlWrap = document.getElementById('ex_timeline');
    if (tlWrap) {
      tlWrap.textContent = '';
      const frag = document.createDocumentFragment();
      (ex.timeline || []).slice(0, 120).forEach(e => {
        const line = el('div', null, `${new Date(parseTs(e.ts ?? e.time ?? e.timestamp) * 1000).toLocaleTimeString()} — pid ${e.pid ?? '—'} → ${e.exe || ''} `);
        const span = el('span', 'text-slate-500', e.cmd || '');
        line.appendChild(span);
        frag.appendChild(line);
      });
      tlWrap.appendChild(frag);
      if (!(ex.timeline || []).length) tlWrap.textContent = '—';
    }

    // enrichment
    H('ex_enrich', JSON.stringify(ex.enrichment || {}, null, 2));

    // actions
    const actionsUl = document.getElementById('ex_actions');
    if (actionsUl) {
      actionsUl.textContent = '';
      (ex.recommendations || []).forEach(a => actionsUl.appendChild(el('li', null, a)));
    }
  }

  function selectAlert(a) {
    if (detailEl) detailEl.textContent = JSON.stringify(a, null, 2);
    const id = a.id || synthIdFor(a);
    openExplain(id);
  }

  // ---------- Integrations ----------
  async function loadCatalog() {
    try {
      const r = await fetch('/integrations/catalog');
      if (!r.ok) return;
      const cat = await r.json();
      catalog.vendors = Array.isArray(cat?.vendors) ? cat.vendors : (Array.isArray(cat?.items) ? cat.items : []);
      if (vendorSel) {
        vendorSel.innerHTML = (catalog.vendors || []).map(v => `<option value="${String(v.id)}">${String(v.name || v.id)}</option>`).join('');
        vendorSel.onchange = renderCredFields;
      }
      renderCredFields();
    } catch { /* ignore */ }
  }

  function renderCredFields() {
    if (!credFields || !vendorSel) return;
    const v = (catalog.vendors || []).find(x => String(x.id) === String(vendorSel.value));
    const fields = (v?.auth?.fields || v?.required_fields || []);
    credFields.textContent = '';
    const frag = document.createDocumentFragment();
    for (const f of fields) {
      const lab = el('label', 'block text-sm capitalize', String(f).replace('_',' '));
      const inp = el('input', 'w-full bg-slate-900 border border-slate-700 rounded px-2 py-1');
      inp.id = `field_${f}`;
      inp.placeholder = String(f);
      frag.appendChild(lab);
      frag.appendChild(inp);
    }
    credFields.appendChild(frag);
  }

  if (btnAdd) btnAdd.onclick = async () => { await loadCatalog(); addDlg?.showModal?.(); };

  if (saveIntegrationBtn) saveIntegrationBtn.onclick = async (e) => {
    e.preventDefault();
    if (!vendorSel) return;
    const id = vendorSel.value;
    const v  = (catalog.vendors || []).find(x => String(x.id) === String(id));
    const fields = (v?.auth?.fields || v?.required_fields || []);
    const creds = {};
    for (const f of fields) {
      const elv = document.getElementById(`field_${f}`);
      creds[f] = elv ? (elv.value || '') : '';
    }
    try {
      await fetch('/integrations', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id, kind: id, name: v?.name || id, creds })
      });
    } catch {}
    addDlg?.close?.();
    loadIntegrations();
  };

  async function loadIntegrations() {
    try {
      const r = await fetch('/integrations');
      if (!r.ok) return;
      const data = await r.json();

      // normalize items
      let items = [];
      if (Array.isArray(data)) {
        if (data.length && data[0]?.cfg) {
          items = data.map(x => ({
            id: x.cfg.id,
            name: x.cfg.name,
            status: x.rt?.status || 'unknown',
            last_ok: x.cfg?.last_ok || null
          }));
        } else {
          items = data;
        }
      } else {
        items = data.items || [];
      }

      if (!tilesGrid) return;
      tilesGrid.textContent = '';
      const frag = document.createDocumentFragment();

      for (const it of items) {
        const card = el('div', 'rounded border border-slate-800 p-3 bg-slate-900/50');

        const row1 = el('div', 'flex items-center justify-between');
        row1.appendChild(el('div', 'font-medium', it.name || it.id));
        row1.appendChild(el('span', 'text-xs text-slate-400', it.status || 'unknown'));
        card.appendChild(row1);

        card.appendChild(el('div', 'text-xs text-slate-400 mt-1', `last ok: ${it.last_ok || '—'}`));

        const btnRow = el('div', 'mt-2 flex gap-2');
        const bGraph = el('button', 'btnGraph px-2 py-1 rounded bg-slate-800 text-xs', 'Graph');
        const bDel   = el('button', 'btnDel px-2 py-1 rounded bg-rose-700/80 text-xs', 'Remove');
        bGraph.dataset.id = it.id; bDel.dataset.id = it.id;
        btnRow.appendChild(bGraph); btnRow.appendChild(bDel);
        card.appendChild(btnRow);

        const wrap = el('div', 'mt-2 hidden'); wrap.id = `graph_${it.id}`;
        wrap.appendChild(el('div', 'text-xs text-slate-400 mb-1', 'Endpoint R-GCN score (approx.): '));
        const rg = el('span'); rg.id = `rg_${it.id}`; wrap.firstChild.appendChild(rg);
        const cy = el('div'); cy.id = `cy_${it.id}`; cy.style.height = '180px';
        wrap.appendChild(cy);
        card.appendChild(wrap);

        frag.appendChild(card);
      }
      tilesGrid.appendChild(frag);

      for (const b of tilesGrid.querySelectorAll('.btnDel')) {
        b.onclick = async () => {
          try { await fetch(`/integrations/${encodeURIComponent(b.dataset.id)}`, { method: 'DELETE' }); } catch {}
          loadIntegrations();
        };
      }

      for (const b of tilesGrid.querySelectorAll('.btnGraph')) {
        b.onclick = async () => {
          const id = b.dataset.id;
          try {
            const r = await fetch(`/graph/${encodeURIComponent(id)}?window_sec=900`);
            if (!r.ok) return;
            const g = await r.json();
            const rgEl = document.getElementById(`rg_${id}`);
            if (rgEl) rgEl.textContent = Number(g.rgcn_score || 0).toFixed(2);
            const wrap = document.getElementById(`graph_${id}`); if (wrap) wrap.classList.remove('hidden');

            await ensureCytoscape();
            const container = document.getElementById(`cy_${id}`);
            if (container) {
              container.innerHTML = ''; // idempotent
              const edges = Array.isArray(g.edges) && g.edges.length ? g.edges : (g.links || []);
              cytoscape({
                container,
                elements: {
                  nodes: (g.nodes || []).map(n => ({ data: { id: n.id, label: (n.binary_path || n.id) } })),
                  edges: edges.map(e => ({ data: { source: e.source, target: e.target } }))
                },
                style: [
                  { selector: 'node', style: { 'background-color': '#22d3ee', 'label': 'data(label)', 'font-size': '10px', 'color': '#0f172a', 'shape': 'round-rectangle', 'padding': '5px' } },
                  { selector: 'edge', style: { 'line-color': '#64748b', 'target-arrow-color': '#64748b', 'target-arrow-shape': 'triangle' } }
                ],
                layout: { name: 'breadthfirst', directed: true, padding: 8 }
              });
            }
          } catch { /* ignore */ }
        };
      }
    } catch { /* ignore */ }
  }
  loadIntegrations();

  // ---------- Integration Profiles & Capabilities API ----------
  const integrationRowsEl = document.getElementById('integrationRows');
  const integrationCountEl = document.getElementById('integrationCount');
  const capabilitiesMatrixEl = document.getElementById('capabilitiesMatrix');
  const joinKeyMatrixEl = document.getElementById('joinKeyMatrix');
  const integrationModeFilter = document.getElementById('integrationModeFilter');
  const showCollectorsCheckbox = document.getElementById('showCollectors');
  const btnRefreshIntegrations = document.getElementById('btnRefreshIntegrations');
  const btnRefreshCapabilities = document.getElementById('btnRefreshCapabilities');
  const sampleEventModal = document.getElementById('sampleEventModal');
  const sampleEventContent = document.getElementById('sampleEventContent');
  const sampleModalTitle = document.getElementById('sampleModalTitle');

  // Health status badge helper
  function healthStatusBadge(status) {
    const colors = {
      healthy: 'bg-emerald-700/70 text-emerald-200',
      warning: 'bg-amber-600/70 text-amber-200',
      error: 'bg-rose-700/70 text-rose-200',
      unknown: 'bg-slate-600/70 text-slate-300'
    };
    const colorClass = colors[status] || colors.unknown;
    return `<span class="px-1.5 py-0.5 rounded text-xs ${colorClass}">${status || 'unknown'}</span>`;
  }

  // Mode badge helper
  function modeBadge(mode) {
    const colors = {
      export: 'bg-violet-700/70',
      ingest: 'bg-sky-700/70',
      both: 'bg-emerald-700/70'
    };
    return `<span class="px-1.5 py-0.5 rounded text-xs ${colors[mode] || 'bg-slate-700'}">${mode || 'unknown'}</span>`;
  }

  // Fidelity cell helper
  function fidelityCell(fidelity) {
    const colors = {
      hard: 'bg-emerald-500',
      soft: 'bg-amber-500',
      none: 'bg-slate-700'
    };
    const label = {
      hard: 'HARD',
      soft: 'SOFT',
      none: '—'
    };
    return `<span class="inline-block w-3 h-3 rounded ${colors[fidelity] || colors.none}" title="${label[fidelity] || '—'}"></span>`;
  }

  // Load integration profiles
  async function loadIntegrationProfiles() {
    if (!integrationRowsEl) return;
    
    const mode = integrationModeFilter?.value || '';
    try {
      const url = mode ? `/api/integrations?mode=${mode}` : '/api/integrations';
      const resp = await fetch(url);
      if (!resp.ok) {
        // Fall back to demo data if API not available
        renderDemoIntegrationProfiles();
        return;
      }
      
      const data = await resp.json();
      const integrations = data.integrations || [];
      
      if (integrationCountEl) {
        integrationCountEl.textContent = `${integrations.length} integration${integrations.length === 1 ? '' : 's'}`;
      }
      
      integrationRowsEl.innerHTML = integrations.map(int => `
        <tr class="border-t border-slate-800 hover:bg-slate-900/50">
          <td class="px-3 py-2">${healthStatusBadge(int.health_status)}</td>
          <td class="px-3 py-2 font-medium">${int.name}</td>
          <td class="px-3 py-2 text-slate-400">${int.integration_type}</td>
          <td class="px-3 py-2">${modeBadge(int.mode)}</td>
          <td class="px-3 py-2 text-slate-300">${int.eps?.toFixed(1) || '0.0'}</td>
          <td class="px-3 py-2 ${int.parse_error_rate > 0.05 ? 'text-rose-400' : 'text-slate-400'}">${(int.parse_error_rate * 100).toFixed(2)}%</td>
          <td class="px-3 py-2 text-slate-300">${int.facts_supported_count || 0}</td>
          <td class="px-3 py-2 text-slate-300">${int.join_keys_supported_count || 0}</td>
          <td class="px-3 py-2 text-slate-400 text-xs">${int.last_seen_ts ? new Date(int.last_seen_ts).toLocaleString() : '—'}</td>
          <td class="px-3 py-2">
            <button data-id="${int.integration_id}" class="btnViewSamples px-2 py-0.5 rounded bg-slate-700 hover:bg-slate-600 text-xs">Samples</button>
          </td>
        </tr>
      `).join('');
      
      // Bind sample buttons
      for (const btn of integrationRowsEl.querySelectorAll('.btnViewSamples')) {
        btn.onclick = () => showSampleEvents(btn.dataset.id);
      }
    } catch (e) {
      console.error('Failed to load integration profiles:', e);
      renderDemoIntegrationProfiles();
    }
  }

  // Demo data for when API not available
  function renderDemoIntegrationProfiles() {
    if (!integrationRowsEl) return;
    
    const demo = [
      { integration_id: 'wazuh_main', name: 'Wazuh HIDS', integration_type: 'wazuh', mode: 'both', health_status: 'healthy', eps: 42.5, parse_error_rate: 0.002, facts_supported_count: 7, join_keys_supported_count: 4, last_seen_ts: new Date().toISOString() },
      { integration_id: 'zeek_network', name: 'Zeek Network Monitor', integration_type: 'zeek', mode: 'ingest', health_status: 'healthy', eps: 1250.0, parse_error_rate: 0.0001, facts_supported_count: 4, join_keys_supported_count: 2, last_seen_ts: new Date().toISOString() },
      { integration_id: 'jsonl_export', name: 'JSONL File Export', integration_type: 'jsonl_file', mode: 'export', health_status: 'healthy', eps: 0, parse_error_rate: 0, facts_supported_count: 13, join_keys_supported_count: 0, last_seen_ts: null }
    ];
    
    if (integrationCountEl) {
      integrationCountEl.textContent = `${demo.length} integrations (demo)`;
    }
    
    integrationRowsEl.innerHTML = demo.map(int => `
      <tr class="border-t border-slate-800 hover:bg-slate-900/50">
        <td class="px-3 py-2">${healthStatusBadge(int.health_status)}</td>
        <td class="px-3 py-2 font-medium">${int.name}</td>
        <td class="px-3 py-2 text-slate-400">${int.integration_type}</td>
        <td class="px-3 py-2">${modeBadge(int.mode)}</td>
        <td class="px-3 py-2 text-slate-300">${int.eps?.toFixed(1) || '0.0'}</td>
        <td class="px-3 py-2 ${int.parse_error_rate > 0.05 ? 'text-rose-400' : 'text-slate-400'}">${(int.parse_error_rate * 100).toFixed(2)}%</td>
        <td class="px-3 py-2 text-slate-300">${int.facts_supported_count || 0}</td>
        <td class="px-3 py-2 text-slate-300">${int.join_keys_supported_count || 0}</td>
        <td class="px-3 py-2 text-slate-400 text-xs">${int.last_seen_ts ? new Date(int.last_seen_ts).toLocaleString() : '—'}</td>
        <td class="px-3 py-2">
          <button data-id="${int.integration_id}" class="btnViewSamples px-2 py-0.5 rounded bg-slate-700 hover:bg-slate-600 text-xs">Samples</button>
        </td>
      </tr>
    `).join('');
    
    for (const btn of integrationRowsEl.querySelectorAll('.btnViewSamples')) {
      btn.onclick = () => showSampleEvents(btn.dataset.id);
    }
  }

  // Load capabilities matrix
  async function loadCapabilitiesMatrix() {
    if (!capabilitiesMatrixEl) return;
    
    const includeCollectors = showCollectorsCheckbox?.checked !== false;
    
    try {
      const resp = await fetch(`/api/capabilities?include_collectors=${includeCollectors}`);
      if (!resp.ok) {
        renderDemoCapabilitiesMatrix();
        return;
      }
      
      const data = await resp.json();
      renderCapabilitiesMatrix(data);
    } catch (e) {
      console.error('Failed to load capabilities:', e);
      renderDemoCapabilitiesMatrix();
    }
  }

  // Render capabilities matrix
  function renderCapabilitiesMatrix(data) {
    if (!capabilitiesMatrixEl) return;
    
    const sources = data.sources || [];
    const factSupport = data.fact_support || {};
    const joinKeySupport = data.join_key_support || {};
    
    // Get unique fact types
    const factTypes = Object.keys(factSupport).sort();
    const sourceIds = sources.map(s => s.id);
    
    // Build table header
    let html = '<table class="w-full border-collapse"><thead><tr>';
    html += '<th class="text-left px-2 py-1 border border-slate-700 bg-slate-900 sticky left-0">Fact Type</th>';
    for (const source of sources) {
      const icon = source.source_type === 'collector' ? '🔬' : '🔗';
      const healthDot = source.health_status === 'healthy' ? '🟢' : source.health_status === 'warning' ? '🟡' : '🔴';
      html += `<th class="px-2 py-1 border border-slate-700 bg-slate-900" title="${source.name}">${icon} ${source.id.slice(0, 12)}... ${healthDot}</th>`;
    }
    html += '</tr></thead><tbody>';
    
    // Build rows
    for (const factType of factTypes) {
      html += '<tr>';
      html += `<td class="px-2 py-1 border border-slate-700 font-medium sticky left-0 bg-slate-950">${factType}</td>`;
      for (const source of sources) {
        const fidelity = factSupport[factType]?.[source.id] || 'none';
        html += `<td class="px-2 py-1 border border-slate-700 text-center">${fidelityCell(fidelity)}</td>`;
      }
      html += '</tr>';
    }
    html += '</tbody></table>';
    
    capabilitiesMatrixEl.innerHTML = html;
    
    // Render join key matrix
    if (joinKeyMatrixEl) {
      const joinKeys = Object.keys(joinKeySupport).sort();
      let jkHtml = '<table class="w-full border-collapse"><thead><tr>';
      jkHtml += '<th class="text-left px-2 py-1 border border-slate-700 bg-slate-900 sticky left-0">Join Key</th>';
      for (const source of sources) {
        jkHtml += `<th class="px-2 py-1 border border-slate-700 bg-slate-900" title="${source.name}">${source.id.slice(0, 12)}...</th>`;
      }
      jkHtml += '</tr></thead><tbody>';
      
      for (const jk of joinKeys) {
        jkHtml += '<tr>';
        jkHtml += `<td class="px-2 py-1 border border-slate-700 font-medium sticky left-0 bg-slate-950">${jk}</td>`;
        for (const source of sources) {
          const supported = joinKeySupport[jk]?.[source.id];
          jkHtml += `<td class="px-2 py-1 border border-slate-700 text-center">${supported ? '✅' : '—'}</td>`;
        }
        jkHtml += '</tr>';
      }
      jkHtml += '</tbody></table>';
      
      joinKeyMatrixEl.innerHTML = jkHtml;
    }
  }

  // Demo capabilities matrix
  function renderDemoCapabilitiesMatrix() {
    const demoSources = [
      { id: 'macos_endpoint_security', name: 'macOS ES', source_type: 'collector', health_status: 'healthy' },
      { id: 'wazuh_main', name: 'Wazuh', source_type: 'integration', health_status: 'healthy' },
      { id: 'zeek_network', name: 'Zeek', source_type: 'integration', health_status: 'healthy' }
    ];
    
    const demoFactSupport = {
      exec: { macos_endpoint_security: 'hard', wazuh_main: 'soft' },
      proc_spawn: { macos_endpoint_security: 'hard', wazuh_main: 'soft' },
      write_path: { macos_endpoint_security: 'hard', wazuh_main: 'soft' },
      outbound_connect: { macos_endpoint_security: 'hard', wazuh_main: 'soft', zeek_network: 'soft' },
      dns_resolve: { macos_endpoint_security: 'hard', zeek_network: 'hard' },
      vendor_alert: { wazuh_main: 'hard', zeek_network: 'hard' }
    };
    
    const demoJoinKeySupport = {
      proc_key: { macos_endpoint_security: true, wazuh_main: true },
      file_key: { macos_endpoint_security: true, wazuh_main: true },
      socket_key: { macos_endpoint_security: true, wazuh_main: true, zeek_network: true },
      dns_attribution: { macos_endpoint_security: true, zeek_network: true }
    };
    
    renderCapabilitiesMatrix({
      sources: demoSources,
      fact_support: demoFactSupport,
      join_key_support: demoJoinKeySupport
    });
  }

  // Show sample events modal
  async function showSampleEvents(integrationId) {
    if (!sampleEventModal) return;
    
    if (sampleModalTitle) sampleModalTitle.textContent = `Sample Events: ${integrationId}`;
    if (sampleEventContent) sampleEventContent.innerHTML = '<div class="text-slate-400">Loading...</div>';
    sampleEventModal.showModal();
    
    try {
      const resp = await fetch(`/api/integrations/${encodeURIComponent(integrationId)}/sample?limit=5`);
      if (!resp.ok) {
        // Show demo data
        showDemoSampleEvents(integrationId);
        return;
      }
      
      const data = await resp.json();
      renderSampleEvents(data.samples || []);
    } catch (e) {
      console.error('Failed to load samples:', e);
      showDemoSampleEvents(integrationId);
    }
  }

  // Demo sample events
  function showDemoSampleEvents(integrationId) {
    const demo = [
      {
        raw_event_id: `${integrationId}_sample_001`,
        raw_json_hash: 'a1b2c3d4e5',
        mapping_version: '1.0',
        mapped_at: new Date().toISOString(),
        raw_event_summary: '{"type":"alert","data":"..."}',
        mapped_event: { fact_type: 'vendor_alert', vendor: integrationId },
        derived_scope_keys: [
          { key: 'proc:1234', key_type: 'process', fidelity: 'hard', join_confidence: 1.0 }
        ]
      }
    ];
    renderSampleEvents(demo);
  }

  // Render sample events
  function renderSampleEvents(samples) {
    if (!sampleEventContent) return;
    
    if (samples.length === 0) {
      sampleEventContent.innerHTML = '<div class="text-slate-400">No sample events available.</div>';
      return;
    }
    
    sampleEventContent.innerHTML = samples.map((s, i) => `
      <div class="border border-slate-700 rounded p-3">
        <div class="flex items-center justify-between mb-2">
          <span class="font-medium">Sample ${i + 1}</span>
          <span class="text-xs text-slate-400">${new Date(s.mapped_at).toLocaleString()}</span>
        </div>
        <div class="grid grid-cols-2 gap-3 text-xs">
          <div>
            <div class="font-medium text-slate-300 mb-1">Raw Event</div>
            <pre class="bg-slate-950 p-2 rounded overflow-auto max-h-24 text-slate-400">${s.raw_event_summary || '(not available)'}</pre>
            <div class="mt-1 text-slate-500">Hash: ${s.raw_json_hash} • Version: ${s.mapping_version}</div>
          </div>
          <div>
            <div class="font-medium text-slate-300 mb-1">Mapped Event</div>
            <pre class="bg-slate-950 p-2 rounded overflow-auto max-h-24 text-emerald-300">${JSON.stringify(s.mapped_event, null, 2)}</pre>
          </div>
        </div>
        ${s.derived_scope_keys?.length ? `
          <div class="mt-2">
            <div class="font-medium text-slate-300 mb-1 text-xs">Derived Scope Keys (Provenance)</div>
            <div class="flex flex-wrap gap-1">
              ${s.derived_scope_keys.map(k => `
                <span class="px-1.5 py-0.5 rounded text-xs ${k.fidelity === 'hard' ? 'bg-emerald-700/50 text-emerald-200' : 'bg-amber-700/50 text-amber-200'}">
                  ${k.key_type}: ${k.key.slice(0, 20)}... (${(k.join_confidence * 100).toFixed(0)}%)
                </span>
              `).join('')}
            </div>
          </div>
        ` : ''}
      </div>
    `).join('');
  }

  // Wire up refresh buttons
  if (btnRefreshIntegrations) {
    btnRefreshIntegrations.onclick = loadIntegrationProfiles;
  }
  if (btnRefreshCapabilities) {
    btnRefreshCapabilities.onclick = loadCapabilitiesMatrix;
  }
  if (integrationModeFilter) {
    integrationModeFilter.onchange = loadIntegrationProfiles;
  }
  if (showCollectorsCheckbox) {
    showCollectorsCheckbox.onchange = loadCapabilitiesMatrix;
  }

  // Load on tab switch to Integrations
  if (tabInt) {
    const origClick = tabInt.onclick;
    tabInt.onclick = function(e) {
      if (origClick) origClick.call(this, e);
      loadIntegrationProfiles();
      loadCapabilitiesMatrix();
    };
  }

  // ---------- Playbooks wiring (SSE + snapshots; optional) ----------
  function renderPbItem(item) {
    const ts = (item?.ts || item?.time || 0) * 1000;
    const when = ts ? new Date(ts).toLocaleString() : '';
    const title = item?.playbook_name || item?.playbook_id || 'playbook';
    const sev = (item?.severity || '').toString().toUpperCase();
    const rationale = Array.isArray(item?.rationale) ? item.rationale.join(' | ') : '';
    const tags = Array.isArray(item?.tags) ? item.tags.join(', ') : '';

    const li = el('li', 'text-sm');
    if (when) li.appendChild(el('span', 'text-slate-400 mr-2', `[${when}]`));
    li.appendChild(el('span', 'font-medium mr-2', title));
    if (sev) li.appendChild(el('span', 'px-1 py-0.5 rounded bg-slate-700/70 text-xs mr-2', sev));
    if (tags) li.appendChild(el('span', 'text-slate-400 mr-2', tags));
    if (rationale) li.appendChild(el('span', 'text-slate-300', rationale));
    return li;
  }

  function appendPbFeed(item) {
    if (!pbFeedEl) return;
    const li = renderPbItem(item);
    pbFeedEl.prepend(li);
    while (pbFeedEl.children.length > 200) pbFeedEl.removeChild(pbFeedEl.lastChild);
  }

  async function loadPlaybooksSnapshots() {
    try {
      const [hitsR, pendR] = await Promise.all([
        fetch('/playbooks/hits'),
        fetch('/playbooks/pending')
      ]);
      if (hitsR.ok) {
        const hits = await hitsR.json();
        if (pbHitsEl) {
          pbHitsEl.textContent = '';
          (Array.isArray(hits) ? hits : []).slice(-200).forEach(h => safeAdd(pbHitsEl, renderPbItem(h)));
        }
      }
      if (pendR.ok) {
        const pending = await pendR.json();
        if (pbPendingEl) {
          pbPendingEl.textContent = '';
          (Array.isArray(pending) ? pending : []).slice(-200).forEach(p => safeAdd(pbPendingEl, renderPbItem(p)));
        }
      }
    } catch { /* ignore */ }
  }

  (function mountPlaybooksSSE() {
    if (!pbFeedEl && !pbHitsEl && !pbPendingEl) return; // nothing to render
    try {
      const esPB = new EventSource('/playbooks/stream');
      esPB.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          const item = msg.item || msg; // tolerate either {kind,item} or direct item
          appendPbFeed(item);
        } catch (e) {
          console.warn('PB stream parse error', e);
        }
      };
      esPB.onerror = (e) => console.warn('PB stream error', e);
      loadPlaybooksSnapshots();
      setInterval(loadPlaybooksSnapshots, 30000);
    } catch (e) {
      console.warn('PB SSE init failed', e);
    }
  })();

  // ---------- Lazy loader for Cytoscape ----------
  function ensureCytoscape() {
    if (window.cytoscape) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://cdn.jsdelivr.net/npm/cytoscape@3.26.0/dist/cytoscape.min.js';
      s.onload = () => resolve();
      s.onerror = reject;
      document.head.appendChild(s);
    });
  }
  /* ===================== Explain verdict + KPI row (additive) ===================== */

/** Renders verdict badge + confidence + reasons inside an element with id="explainHeader".
 *  Call this after you open the Explain drawer. Safe if header is missing.
 */
async function attachExplainSummary(alertId) {
  try {
    const res = await fetch(`/alerts/${encodeURIComponent(alertId)}/explain`, { cache: "no-store" });
    const data = await res.json();
    const hdr = document.querySelector("#explainHeader");
    if (!hdr || !data || !data.summary) return;

    const verdict = (data.summary.verdict || "unknown").toString().toLowerCase();
    const conf = typeof data.summary.confidence === "number" ? Math.round(data.summary.confidence * 100) : null;
    const reasons = Array.isArray(data.summary.reason_codes) ? data.summary.reason_codes.join(", ") : "";

    hdr.innerHTML = `
      <span class="badge verdict-${verdict}">${verdict.toUpperCase()}</span>
      ${conf !== null ? `<span class="pill">${conf}%</span>` : ""}
      ${reasons ? `<span class="muted">${reasons}</span>` : ""}
    `;
  } catch (e) {
    console.warn("attachExplainSummary failed", e);
  }
}

/** Lightweight KPI row pulling /hosts/self/health every 2s.
 *  Put a <div id="kpis"></div> somewhere in index.html (see section 3).
 */
async function refreshKPIs() {
  try {
    const res = await fetch("/hosts/self/health", { cache: "no-store" });
    const h = await res.json();
    const el = document.querySelector("#kpis");
    if (!el) return;
    const safe = (v) => (v === null || v === undefined ? "-" : v);
    // Display 9 canonical event types from health response
    el.innerHTML = `
      <div class="kpi">Credential Access: <b>${safe(h.credential_access_count)}</b></div>
      <div class="kpi">Discovery: <b>${safe(h.discovery_count)}</b></div>
      <div class="kpi">Exfiltration: <b>${safe(h.exfiltration_count)}</b></div>
      <div class="kpi">Network: <b>${safe(h.network_connection_count)}</b></div>
      <div class="kpi">Persistence: <b>${safe(h.persistence_change_count)}</b></div>
      <div class="kpi">Evasion: <b>${safe(h.defense_evasion_count)}</b></div>
      <div class="kpi">Injection: <b>${safe(h.process_injection_count)}</b></div>
      <div class="kpi">Auth: <b>${safe(h.auth_event_count)}</b></div>
      <div class="kpi">Scripts: <b>${safe(h.script_exec_count)}</b></div>
    `;
  } catch (_) {}
}

if (!window.__kpiPoll) {
  window.__kpiPoll = setInterval(refreshKPIs, 2000);
  refreshKPIs();
}

/* Optional helper to use from elsewhere */
window.attachExplainSummary = attachExplainSummary;

/* Minimal styles if you don’t already have them */
(function injectExplainStyles(){
  if (document.getElementById("verdict-style")) return;
  const css = `
    .badge{display:inline-block;padding:2px 6px;border-radius:6px;font-weight:600;font-size:12px}
    .pill{display:inline-block;margin-left:6px;padding:2px 6px;border:1px solid #ccc;border-radius:999px;font-size:12px}
    .muted{margin-left:6px;color:#888;font-size:12px}
    .verdict-benign{background:#e8f7ee;color:#107b3e;border:1px solid #bce3cd}
    .verdict-leaning{background:#fff4e5;color:#9a6d00;border:1px solid #f3d1a6}
    .verdict-malicious{background:#fde8e8;color:#a31d1d;border:1px solid #f2b8b8}
    .kpi-row{display:flex;gap:14px;align-items:center;margin:6px 0 10px 0;flex-wrap:wrap}
    .kpi{font-size:13px;color:#444}
  `;
  const style = document.createElement("style");
  style.id = "verdict-style";
  style.textContent = css;
  document.head.appendChild(style);
})();

// ============================================================================
// ANALYST WORKFLOW MODULE
// ============================================================================

(function initAnalystWorkflow() {
  const API_BASE = '/api';

  // DOM elements
  const focusFrom = document.getElementById('focusFrom');
  const focusTo = document.getElementById('focusTo');
  const btnSetFocus = document.getElementById('btnSetFocus');
  const focusStatus = document.getElementById('focusStatus');
  
  const checkpointLabel = document.getElementById('checkpointLabel');
  const btnCreateCheckpoint = document.getElementById('btnCreateCheckpoint');
  const checkpointList = document.getElementById('checkpointList');
  const btnRestoreCheckpoint = document.getElementById('btnRestoreCheckpoint');
  
  const btnShowDiff = document.getElementById('btnShowDiff');
  const diffSummary = document.getElementById('diffSummary');
  
  const disambiguatorList = document.getElementById('disambiguatorList');
  const btnApplyDisambiguator = document.getElementById('btnApplyDisambiguator');
  const disambiguatorResult = document.getElementById('disambiguatorResult');
  
  const visibilityBadge = document.getElementById('visibilityBadge');

  // Initialize datetime inputs to last hour
  function initFocusDefaults() {
    if (!focusFrom || !focusTo) return;
    const now = new Date();
    const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    focusFrom.value = hourAgo.toISOString().slice(0, 16);
    focusTo.value = now.toISOString().slice(0, 16);
  }
  initFocusDefaults();

  // ---------- Focus Window ----------
  async function setFocusWindow() {
    if (!focusFrom || !focusTo) return;
    try {
      const t_min = new Date(focusFrom.value).toISOString();
      const t_max = new Date(focusTo.value).toISOString();
      
      const resp = await fetch(`${API_BASE}/session/focus`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ t_min, t_max, entities: [] })
      });
      
      if (resp.ok) {
        const data = await resp.json();
        if (focusStatus) {
          focusStatus.textContent = `✓ ${data.affected_count} events in window`;
          focusStatus.className = 'text-emerald-400 text-[10px]';
        }
      } else {
        if (focusStatus) {
          focusStatus.textContent = '✗ Failed to set focus';
          focusStatus.className = 'text-rose-400 text-[10px]';
        }
      }
    } catch (e) {
      if (focusStatus) focusStatus.textContent = `Error: ${e.message}`;
    }
  }
  
  async function loadFocusWindow() {
    try {
      const resp = await fetch(`${API_BASE}/session/focus`);
      if (resp.ok) {
        const data = await resp.json();
        if (data.focus_window && focusFrom && focusTo) {
          focusFrom.value = data.focus_window.t_min.slice(0, 16);
          focusTo.value = data.focus_window.t_max.slice(0, 16);
          if (focusStatus) {
            focusStatus.textContent = `Duration: ${data.focus_window.duration_seconds}s`;
          }
        }
      }
    } catch { /* ignore */ }
  }
  
  if (btnSetFocus) btnSetFocus.onclick = setFocusWindow;

  // ---------- Checkpoints ----------
  async function createCheckpoint() {
    if (!checkpointLabel) return;
    const label = checkpointLabel.value.trim() || `Checkpoint ${new Date().toLocaleTimeString()}`;
    
    try {
      const resp = await fetch(`${API_BASE}/checkpoints`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label, notes: null })
      });
      
      if (resp.ok) {
        const data = await resp.json();
        checkpointLabel.value = '';
        await loadCheckpoints();
        console.log(`Checkpoint created: ${data.checkpoint_id}`);
      }
    } catch (e) {
      console.error(`Checkpoint error: ${e.message}`);
    }
  }
  
  async function loadCheckpoints() {
    if (!checkpointList) return;
    try {
      const resp = await fetch(`${API_BASE}/checkpoints`);
      if (resp.ok) {
        const data = await resp.json();
        checkpointList.innerHTML = '<option value="">-- select checkpoint --</option>';
        for (const ckpt of (data.checkpoints || [])) {
          const opt = document.createElement('option');
          opt.value = ckpt.checkpoint_id;
          opt.textContent = `${ckpt.label} (${new Date(ckpt.ts).toLocaleString()})`;
          checkpointList.appendChild(opt);
        }
      }
    } catch { /* ignore */ }
  }
  
  async function restoreCheckpoint() {
    if (!checkpointList || !checkpointList.value) {
      console.warn('Select a checkpoint first');
      return;
    }
    
    try {
      const resp = await fetch(`${API_BASE}/checkpoints/restore`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ checkpoint_id: checkpointList.value })
      });
      
      if (resp.ok) {
        const data = await resp.json();
        console.log(`Restored: ${data.checkpoint.label}`);
        await loadFocusWindow();
      }
    } catch (e) {
      console.error(`Restore error: ${e.message}`);
    }
  }
  
  if (btnCreateCheckpoint) btnCreateCheckpoint.onclick = createCheckpoint;
  if (btnRestoreCheckpoint) btnRestoreCheckpoint.onclick = restoreCheckpoint;

  // ---------- Diff View ----------
  async function showDiff() {
    if (!focusFrom || !focusTo || !diffSummary) return;
    
    try {
      const from_ts = new Date(focusFrom.value).toISOString();
      const to_ts = new Date(focusTo.value).toISOString();
      
      const resp = await fetch(`${API_BASE}/diff`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ from_ts, to_ts, domains: [] })
      });
      
      if (resp.ok) {
        const data = await resp.json();
        const stats = data.stats || {};
        let html = `<div class="text-emerald-400">Total: ${stats.total_changes || 0} changes</div>`;
        html += `<div>High significance: ${stats.high_significance_count || 0}</div>`;
        
        if (data.changes && data.changes.length > 0) {
          html += '<ul class="mt-1 space-y-0.5">';
          for (const c of data.changes.slice(0, 5)) {
            const sigColor = c.significance === 'high' ? 'text-rose-400' : 
                            c.significance === 'medium' ? 'text-amber-400' : 'text-slate-400';
            html += `<li class="${sigColor}">• ${c.domain}: ${c.entity}</li>`;
          }
          if (data.changes.length > 5) {
            html += `<li class="text-slate-500">... and ${data.changes.length - 5} more</li>`;
          }
          html += '</ul>';
        }
        
        diffSummary.innerHTML = html;
      }
    } catch (e) {
      diffSummary.textContent = `Error: ${e.message}`;
    }
  }
  
  if (btnShowDiff) btnShowDiff.onclick = showDiff;

  // ---------- Disambiguators ----------
  async function loadDisambiguators() {
    if (!disambiguatorList) return;
    try {
      const resp = await fetch(`${API_BASE}/disambiguators`);
      if (resp.ok) {
        const data = await resp.json();
        disambiguatorList.innerHTML = '<option value="">-- select action --</option>';
        for (const d of (data.disambiguators || [])) {
          const opt = document.createElement('option');
          opt.value = d.id;
          opt.textContent = `[${d.priority}] ${d.question_text.slice(0, 40)}...`;
          opt.title = d.question_text;
          disambiguatorList.appendChild(opt);
        }
      }
    } catch { /* ignore */ }
  }
  
  async function applyDisambiguator() {
    if (!disambiguatorList || !disambiguatorList.value) {
      console.warn('Select a disambiguator first');
      return;
    }
    
    try {
      const resp = await fetch(`${API_BASE}/disambiguators/apply`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          disambiguator_id: disambiguatorList.value,
          parameters_override: null 
        })
      });
      
      if (resp.ok) {
        const data = await resp.json();
        const result = data.result || {};
        let html = `<div class="${result.evidence_found ? 'text-emerald-400' : 'text-amber-400'}">`;
        html += result.evidence_found ? '✓ Evidence found' : '○ No new evidence';
        html += `</div>`;
        html += `<div>New items: ${result.new_evidence_count || 0}</div>`;
        if (result.confidence_delta) {
          html += `<div>Confidence Δ: ${(result.confidence_delta * 100).toFixed(1)}%</div>`;
        }
        
        if (disambiguatorResult) disambiguatorResult.innerHTML = html;
      }
    } catch (e) {
      if (disambiguatorResult) disambiguatorResult.textContent = `Error: ${e.message}`;
    }
  }
  
  if (btnApplyDisambiguator) btnApplyDisambiguator.onclick = applyDisambiguator;

  // ---------- Entity Filter ----------
  const entityFilterPanel = document.getElementById('entityFilterPanel');
  const btnClearEntityFilter = document.getElementById('btnClearEntityFilter');
  const entityFilterActiveLabel = document.getElementById('entityFilterActiveLabel');
  const entityFilterActiveValue = document.getElementById('entityFilterActiveValue');
  
  // Entity filter state
  let currentIncidentId = null;
  let currentEntityFilter = null; // { type, id, displayName }
  
  // Make incidents clickable and load entities
  function makeIncidentsClickable() {
    const incItems = incListEl?.querySelectorAll('li');
    if (!incItems) return;
    
    for (const li of incItems) {
      li.style.cursor = 'pointer';
      li.classList.add('hover:bg-slate-800/50', 'transition-colors');
      li.onclick = async (e) => {
        e.stopPropagation();
        
        // Extract incident ID from the item (find in incidents map)
        const text = li.textContent;
        let incId = null;
        for (const [id, inc] of incidents.entries()) {
          if (inc.exe && text.includes(inc.exe)) {
            incId = id;
            break;
          }
        }
        
        if (!incId) return;
        currentIncidentId = incId;
        currentEntityFilter = null;
        
        // Load and display entities
        await loadIncidentEntities(incId);
        
        // Load and display explanation
        await loadExplanation(incId);
      };
    }
  }
  
  async function loadIncidentEntities(incId) {
    if (!entityFilterPanel) return;
    
    try {
      const resp = await fetch(`${API_BASE}/api/incidents/${incId}/entities`);
      if (!resp.ok) return;
      
      const data = await resp.json();
      renderEntityFilter(data.entities || []);
      entityFilterPanel.classList.remove('hidden');
    } catch (e) {
      console.warn('Failed to load entities:', e);
    }
  }
  
  function renderEntityFilter(entities) {
    // Group entities by type
    const byType = {};
    for (const ent of entities) {
      if (!byType[ent.entity_type]) byType[ent.entity_type] = [];
      byType[ent.entity_type].push(ent);
    }
    
    const types = ['executable', 'user', 'process', 'file', 'socket'];
    for (const type of types) {
      const listEl = document.getElementById(`entityList${type.charAt(0).toUpperCase() + type.slice(1)}`);
      if (!listEl) continue;
      
      listEl.textContent = '';
      const items = byType[type] || [];
      
      for (const ent of items) {
        const li = el('li', 'hover:bg-slate-700/70 px-1 py-0.5 rounded cursor-pointer transition-colors text-slate-300');
        const label = `${ent.display_name} (${ent.count})`;
        li.textContent = label;
        li.title = label;
        li.onclick = (e) => {
          e.stopPropagation();
          selectEntityFilter(ent);
        };
        listEl.appendChild(li);
      }
    }
  }
  
  function selectEntityFilter(entity) {
    currentEntityFilter = {
      type: entity.entity_type,
      id: entity.entity_id,
      displayName: entity.display_name
    };
    
    // Show active filter label
    if (entityFilterActiveLabel && entityFilterActiveValue) {
      entityFilterActiveLabel.classList.remove('hidden');
      entityFilterActiveValue.textContent = `${entity.entity_type}: ${entity.display_name}`;
    }
    
    // TODO: Filter timeline/incidents by this entity
    console.log('Entity filter selected:', currentEntityFilter);
  }
  
  if (btnClearEntityFilter) {
    btnClearEntityFilter.onclick = () => {
      currentEntityFilter = null;
      if (entityFilterActiveLabel) entityFilterActiveLabel.classList.add('hidden');
      console.log('Entity filter cleared');
      // TODO: Re-render unfiltered timeline/incidents
    };
  }
  
  // Re-render incidents clickable after incidents are rendered
  const origRenderIncidents = window.renderIncidents || renderIncidents;
  window.renderIncidents = function() {
    origRenderIncidents.call(this);
    makeIncidentsClickable();
  };

  // ---------- Why This Hypothesis Panel ----------
  const whyHypothesisPanel = document.getElementById('whyHypothesisPanel');
  const top3HypothesesList = document.getElementById('top3HypothesesList');
  const keyClaimsList = document.getElementById('keyClaimsList');
  const evidencePointersList = document.getElementById('evidencePointersList');
  const visibilityStateSummary = document.getElementById('visibilityStateSummary');
  
  async function loadExplanation(incidentId) {
    if (!whyHypothesisPanel) return;
    
    try {
      const resp = await fetch(`${API_BASE}/api/incidents/${incidentId}/explain`);
      if (!resp.ok) return;
      
      const data = await resp.json();
      renderWhyHypothesis(data);
    } catch (e) {
      console.warn('Failed to load explanation:', e);
    }
  }
  
  function renderWhyHypothesis(explanation) {
    if (!whyHypothesisPanel) return;
    
    // Show the panel
    whyHypothesisPanel.classList.remove('hidden');
    
    // Render top 3 hypotheses
    if (top3HypothesesList) {
      top3HypothesesList.textContent = '';
      if (explanation.top3_hypotheses && explanation.top3_hypotheses.top3) {
        for (let i = 0; i < Math.min(3, explanation.top3_hypotheses.top3.length); i++) {
          const hyp = explanation.top3_hypotheses.top3[i];
          const div = document.createElement('div');
          div.className = 'p-2 rounded bg-slate-800/50 hover:bg-slate-800 transition-colors cursor-pointer';
          
          const severity = hyp.severity || 'unknown';
          const sevColor = severity === 'high' ? 'text-rose-400' : severity === 'medium' ? 'text-amber-400' : 'text-sky-400';
          
          const confidence = Math.round((hyp.confidence || 0) * 100);
          const title = document.createElement('div');
          title.className = `font-semibold ${sevColor}`;
          title.innerHTML = `${i+1}. ${hyp.family} (${hyp.template_id})`;
          
          const stats = document.createElement('div');
          stats.className = 'text-[11px] text-slate-400 mt-1';
          stats.innerHTML = `
            Confidence: ${confidence}% &middot;
            Rank: ${(hyp.rank_score || 0).toFixed(2)} &middot;
            Required: ${hyp.required_satisfied}/${hyp.required_total}
          `;
          
          div.appendChild(title);
          div.appendChild(stats);
          top3HypothesesList.appendChild(div);
        }
      }
    }
    
    // Render key claims (observed, inferred, unknown)
    if (keyClaimsList) {
      keyClaimsList.textContent = '';
      if (explanation.observed_claims && explanation.observed_claims.length > 0) {
        for (const claim of explanation.observed_claims.slice(0, 5)) {
          const div = document.createElement('div');
          const certColor = 
            claim.certainty === 'Observed' ? 'text-emerald-400' :
            claim.certainty === 'InferredFromRules' ? 'text-amber-400' :
            'text-slate-400';
          
          div.className = `${certColor} px-1 py-0.5`;
          div.innerHTML = `<strong>${claim.certainty}:</strong> ${claim.text}`;
          keyClaimsList.appendChild(div);
        }
      }
    }
    
    // Render evidence pointers
    if (evidencePointersList) {
      evidencePointersList.textContent = '';
      const evidencePtrs = new Set();
      
      // Collect evidence pointers from claims
      if (explanation.observed_claims) {
        for (const claim of explanation.observed_claims) {
          if (claim.evidence_ptrs) {
            for (const ptr of claim.evidence_ptrs) {
              if (ptr) evidencePtrs.add(JSON.stringify(ptr));
            }
          }
        }
      }
      
      // Render up to 10 evidence pointers
      let count = 0;
      for (const ptrStr of evidencePtrs) {
        if (count++ >= 10) break;
        const div = document.createElement('div');
        div.className = 'text-slate-400 truncate';
        try {
          const ptr = JSON.parse(ptrStr);
          const label = `${ptr.stream_id || '?'}:${ptr.segment_id || '?'}#${ptr.record_index || 0}`;
          div.textContent = label;
          div.title = ptrStr;
        } catch {
          div.textContent = ptrStr;
        }
        evidencePointersList.appendChild(div);
      }
    }
    
    // Render visibility state
    if (visibilityStateSummary) {
      if (explanation.visibility_state) {
        const vis = explanation.visibility_state;
        const present = (vis.streams_present || []).join(', ') || 'none';
        const missing = (vis.streams_missing || []).join(', ') || 'none';
        const degradedMsg = vis.degraded ? ` (degraded: ${(vis.degraded_reasons || []).join('; ')})` : '';
        
        visibilityStateSummary.innerHTML = `
          <div class="text-slate-400">
            <div>Present: <span class="text-slate-300">${present}</span></div>
            <div>Missing: <span class="text-slate-300">${missing}</span>${degradedMsg}</div>
          </div>
        `;
      }
    }
  }
  
  // Make explanations load when an incident is selected
  window.loadExplanation = loadExplanation;

  // ---------- Support Bundle Export ----------
  const exportSupportBundleBtn = document.getElementById('exportSupportBundleBtn');
  
  if (exportSupportBundleBtn) {
    exportSupportBundleBtn.onclick = async () => {
      try {
        exportSupportBundleBtn.disabled = true;
        exportSupportBundleBtn.textContent = '⏳ Generating...';
        
        const resp = await fetch('/api/support/bundle', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            include_latest_incident: true,
            include_recompute_inputs: false,
            max_logs_kb: 512,
            redact: true
          })
        });
        
        if (resp.ok) {
          // Get the ZIP blob
          const blob = await resp.blob();
          // Create a download link
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `support_bundle_${new Date().toISOString().split('T')[0]}.zip`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          
          // Show success toast
          showToast(`✅ Support bundle exported (${(blob.size / 1024).toFixed(1)} KB)`, 'success');
        } else {
          const errData = await resp.json();
          showToast(`❌ Failed to export: ${errData.error || 'Unknown error'}`, 'error');
        }
      } catch (e) {
        showToast(`❌ Error: ${e.message}`, 'error');
      } finally {
        exportSupportBundleBtn.disabled = false;
        exportSupportBundleBtn.textContent = '🆘 Export Support Bundle';
      }
    };
  }
  
  function showToast(msg, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `fixed bottom-4 right-4 px-4 py-2 rounded text-sm ${
      type === 'success' ? 'bg-emerald-700 text-emerald-100' :
      type === 'error' ? 'bg-rose-700 text-rose-100' :
      'bg-slate-700 text-slate-100'
    }`;
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.3s';
      setTimeout(() => document.body.removeChild(toast), 300);
    }, 3000);
  }

  // ---------- Visibility Panel ----------
  async function refreshVisibility() {
    if (!visibilityBadge) return;
    try {
      const resp = await fetch(`${API_BASE}/visibility`);
      if (resp.ok) {
        const data = await resp.json();
        const health = data.overall_health || 'unknown';
        
        let bgClass = 'bg-emerald-700/70';
        if (health === 'degraded') bgClass = 'bg-amber-600/70';
        else if (health === 'unhealthy') bgClass = 'bg-rose-700/70';
        else if (health === 'unknown') bgClass = 'bg-slate-600/70';
        
        visibilityBadge.className = `text-xs px-2 py-0.5 rounded ${bgClass}`;
        visibilityBadge.textContent = `visibility: ${health}`;
        
        if (data.degraded_reasons && data.degraded_reasons.length > 0) {
          visibilityBadge.title = data.degraded_reasons.join('; ');
        }
      }
    } catch { /* ignore */ }
  }

  // ---------- Initialize ----------
  async function initWorkflow() {
    await loadFocusWindow();
    await loadCheckpoints();
    await loadDisambiguators();
    await refreshVisibility();
  }
  
  // Poll visibility every 10 seconds
  setInterval(refreshVisibility, 10000);
  
  // ---------- Run Metrics Panel ----------
  const metricsEmpty = document.getElementById('metricsEmpty');
  const metricsContent = document.getElementById('metricsContent');
  const btnRefreshMetrics = document.getElementById('btnRefreshMetrics');
  const btnLoadMetricsFile = document.getElementById('btnLoadMetricsFile');
  const metricsFileInput = document.getElementById('metricsFileInput');
  
  // Metrics display elements
  const metricsRunId = document.getElementById('metricsRunId');
  const metricsTimestamp = document.getElementById('metricsTimestamp');
  const metricsDuration = document.getElementById('metricsDuration');
  const metricsStatus = document.getElementById('metricsStatus');
  const metricsSignals = document.getElementById('metricsSignals');
  const metricsExplained = document.getElementById('metricsExplained');
  const metricsPlaybooksHit = document.getElementById('metricsPlaybooksHit');
  const metricsFalsePos = document.getElementById('metricsFalsePos');
  const metricsEvents = document.getElementById('metricsEvents');
  const metricsSegments = document.getElementById('metricsSegments');
  const metricsChannels = document.getElementById('metricsChannels');
  const metricsEps = document.getElementById('metricsEps');
  const metricsDetails = document.getElementById('metricsDetails');
  
  // Verdict elements
  const verdictTelemetry = document.getElementById('verdictTelemetry');
  const verdictDetections = document.getElementById('verdictDetections');
  const verdictExplain = document.getElementById('verdictExplain');
  const verdictNoFake = document.getElementById('verdictNoFake');
  
  function setVerdict(el, pass, label) {
    if (!el) return;
    const icon = pass ? '✅' : '❌';
    const color = pass ? 'text-emerald-400' : 'text-rose-400';
    el.innerHTML = `<span class="w-4">${icon}</span><span class="${color}">${label}</span>`;
  }
  
  function renderMetrics(data) {
    if (!metricsContent || !metricsEmpty) return;
    
    metricsEmpty.classList.add('hidden');
    metricsContent.classList.remove('hidden');
    
    // Summary
    if (metricsRunId) metricsRunId.textContent = data.run_id || data.runId || '--';
    if (metricsTimestamp) metricsTimestamp.textContent = data.timestamp || data.start_time || '--';
    if (metricsDuration) metricsDuration.textContent = data.duration_ms ? `${data.duration_ms}ms` : (data.duration || '--');
    if (metricsStatus) {
      const status = data.status || data.result || 'unknown';
      metricsStatus.textContent = status;
      metricsStatus.className = status === 'pass' || status === 'success' ? 'text-emerald-400' : 
                                status === 'fail' || status === 'error' ? 'text-rose-400' : 'text-amber-400';
    }
    
    // Detections
    const detections = data.detections || data.detection_stats || {};
    if (metricsSignals) metricsSignals.textContent = detections.signals_count ?? data.signals_count ?? 0;
    if (metricsExplained) metricsExplained.textContent = detections.explained_count ?? data.explained_count ?? 0;
    if (metricsPlaybooksHit) metricsPlaybooksHit.textContent = detections.playbooks_hit ?? data.playbooks_hit ?? 0;
    if (metricsFalsePos) metricsFalsePos.textContent = detections.false_positives ?? data.false_positives ?? 0;
    
    // Telemetry
    const telemetry = data.telemetry || data.telemetry_stats || {};
    if (metricsEvents) metricsEvents.textContent = telemetry.events_count ?? data.events_count ?? 0;
    if (metricsSegments) metricsSegments.textContent = telemetry.segments_count ?? data.segments_count ?? 0;
    if (metricsChannels) metricsChannels.textContent = telemetry.channels_count ?? data.channels?.length ?? 0;
    if (metricsEps) metricsEps.textContent = telemetry.eps ?? data.eps ?? '--';
    
    // Verdicts
    const verdicts = data.verdicts || data.checks || {};
    const eventsOk = (telemetry.events_count ?? data.events_count ?? 0) > 0;
    const detectionsOk = (detections.signals_count ?? data.signals_count ?? 0) > 0;
    const explainOk = (detections.explained_count ?? data.explained_count ?? 0) > 0;
    const noFake = verdicts.no_fake_detections !== false && (detections.false_positives ?? data.false_positives ?? 0) === 0;
    
    setVerdict(verdictTelemetry, verdicts.telemetry_flowing ?? eventsOk, 'Telemetry flowing');
    setVerdict(verdictDetections, verdicts.detections_fired ?? detectionsOk, 'Detections fired');
    setVerdict(verdictExplain, verdicts.explanations_valid ?? explainOk, 'Explanations valid');
    setVerdict(verdictNoFake, noFake, 'No fake detections');
    
    // Details (raw JSON)
    if (metricsDetails) {
      metricsDetails.textContent = JSON.stringify(data, null, 2);
    }
  }
  
  // Load from file picker
  if (btnLoadMetricsFile && metricsFileInput) {
    btnLoadMetricsFile.onclick = () => metricsFileInput.click();
    metricsFileInput.onchange = async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        renderMetrics(data);
        showToast(`✅ Loaded metrics: ${file.name}`, 'success');
      } catch (err) {
        showToast(`❌ Failed to parse metrics file: ${err.message}`, 'error');
      }
    };
  }
  
  // Refresh from server (try to fetch latest metrics)
  if (btnRefreshMetrics) {
    btnRefreshMetrics.onclick = async () => {
      try {
        // Try /api/eval/metrics endpoint first
        let resp = await fetch('/api/eval/metrics');
        if (resp.ok) {
          const data = await resp.json();
          if (data && (data.run_id || data.runId || data.timestamp)) {
            renderMetrics(data);
            showToast('✅ Metrics refreshed from server', 'success');
            return;
          }
        }
        // Fall back to /api/signals/stats for basic metrics
        resp = await fetch('/api/signals/stats');
        if (resp.ok) {
          const stats = await resp.json();
          if (stats.data) {
            renderMetrics({
              run_id: 'live',
              timestamp: new Date().toISOString(),
              signals_count: stats.data.total || 0,
              playbooks_hit: stats.data.by_playbook ? Object.keys(stats.data.by_playbook).length : 0,
              status: 'live'
            });
            showToast('✅ Live stats refreshed', 'success');
            return;
          }
        }
        showToast('ℹ️ No metrics available - run eval_windows.ps1 first', 'info');
      } catch (err) {
        showToast(`❌ Failed to refresh metrics: ${err.message}`, 'error');
      }
    };
  }
  
  // ---------- Pivot & Search Controls ----------
  const pivotSearchInput = document.getElementById('pivotSearchInput');
  const btnSearchEvents = document.getElementById('btnSearchEvents');
  const btnSearchSignals = document.getElementById('btnSearchSignals');
  const btnSearchFacts = document.getElementById('btnSearchFacts');
  const pivotEntityType = document.getElementById('pivotEntityType');
  const pivotEntityValue = document.getElementById('pivotEntityValue');
  const btnPivotEntity = document.getElementById('btnPivotEntity');
  const pivotResults = document.getElementById('pivotResults');
  
  async function doSearch(type) {
    const query = pivotSearchInput?.value?.trim();
    if (!query) {
      showToast('Enter a search term', 'info');
      return;
    }
    
    if (!pivotResults) return;
    pivotResults.textContent = 'Searching...';
    
    try {
      let endpoint = '/api/signals';
      let params = new URLSearchParams();
      
      if (type === 'events') {
        // For events, we search via telemetry or just show a message
        pivotResults.innerHTML = `<div class="text-slate-400">Event search for "${query}" - check Timeline panel</div>`;
        return;
      } else if (type === 'signals') {
        params.set('query', query);
        params.set('limit', '20');
      } else if (type === 'facts') {
        endpoint = '/api/facts/search';
        params.set('q', query);
        params.set('limit', '20');
      }
      
      const resp = await fetch(`${endpoint}?${params}`);
      if (resp.ok) {
        const data = await resp.json();
        const items = data.data || data.signals || data.facts || [];
        
        if (items.length === 0) {
          pivotResults.innerHTML = `<div class="text-slate-400">No results for "${query}"</div>`;
        } else {
          pivotResults.innerHTML = items.slice(0, 10).map(item => {
            const id = item.id || item.signal_id || '--';
            const label = item.playbook_id || item.label || item.type || 'signal';
            return `<div class="truncate"><span class="text-cyan-400">${id.substring(0,8)}</span> ${label}</div>`;
          }).join('');
          if (items.length > 10) {
            pivotResults.innerHTML += `<div class="text-slate-500">... and ${items.length - 10} more</div>`;
          }
        }
      } else {
        pivotResults.innerHTML = `<div class="text-rose-400">Search failed: ${resp.status}</div>`;
      }
    } catch (err) {
      pivotResults.innerHTML = `<div class="text-rose-400">Error: ${err.message}</div>`;
    }
  }
  
  if (btnSearchEvents) btnSearchEvents.onclick = () => doSearch('events');
  if (btnSearchSignals) btnSearchSignals.onclick = () => doSearch('signals');
  if (btnSearchFacts) btnSearchFacts.onclick = () => doSearch('facts');
  
  // Pivot by entity
  if (btnPivotEntity) {
    btnPivotEntity.onclick = async () => {
      const entityType = pivotEntityType?.value;
      const entityValue = pivotEntityValue?.value?.trim();
      
      if (!entityType || !entityValue) {
        showToast('Select entity type and enter value', 'info');
        return;
      }
      
      if (!pivotResults) return;
      pivotResults.textContent = 'Pivoting...';
      
      try {
        const params = new URLSearchParams();
        params.set('entity_type', entityType);
        params.set('entity_value', entityValue);
        params.set('limit', '20');
        
        const resp = await fetch(`/api/signals?${params}`);
        if (resp.ok) {
          const data = await resp.json();
          const items = data.data || data.signals || [];
          
          if (items.length === 0) {
            pivotResults.innerHTML = `<div class="text-slate-400">No ${entityType} matches for "${entityValue}"</div>`;
          } else {
            pivotResults.innerHTML = items.slice(0, 10).map(item => {
              const id = item.id || item.signal_id || '--';
              const label = item.playbook_id || item.label || 'signal';
              const ts = item.ts ? new Date(item.ts * 1000).toLocaleTimeString() : '';
              return `<div class="truncate"><span class="text-cyan-400">${id.substring(0,8)}</span> ${label} <span class="text-slate-500">${ts}</span></div>`;
            }).join('');
          }
        } else {
          pivotResults.innerHTML = `<div class="text-rose-400">Pivot failed: ${resp.status}</div>`;
        }
      } catch (err) {
        pivotResults.innerHTML = `<div class="text-rose-400">Error: ${err.message}</div>`;
      }
    };
  }
  
  // ============================================================================
  // IMPORT CASES FUNCTIONALITY
  // ============================================================================
  
  // Import state
  let importedCases = [];
  let selectedCaseId = null;
  let selectedCase = null;
  
  // DOM elements for import
  const importDropZone = document.getElementById('importDropZone');
  const importFilePicker = document.getElementById('importFilePicker');
  const importFolderPicker = document.getElementById('importFolderPicker');
  const importFolderBtn = document.getElementById('importFolderBtn');
  const importProgress = document.getElementById('importProgress');
  const importProgressBar = document.getElementById('importProgressBar');
  const importProgressPercent = document.getElementById('importProgressPercent');
  const importProgressStatus = document.getElementById('importProgressStatus');
  const casesList = document.getElementById('casesList');
  const caseHeader = document.getElementById('caseHeader');
  const caseTabs = document.getElementById('caseTabs');
  const caseEmptyState = document.getElementById('caseEmptyState');
  
  // Case detail elements
  const caseTitle = document.getElementById('caseTitle');
  const caseFileCount = document.getElementById('caseFileCount');
  const caseEventCount = document.getElementById('caseEventCount');
  const caseSignalCount = document.getElementById('caseSignalCount');
  const caseTimeRange = document.getElementById('caseTimeRange');
  
  // Case views
  const caseTimelineView = document.getElementById('caseTimelineView');
  const caseSignalsView = document.getElementById('caseSignalsView');
  const caseEntitiesView = document.getElementById('caseEntitiesView');
  const caseManifestView = document.getElementById('caseManifestView');
  const caseNarrativeView = document.getElementById('caseNarrativeView');
  
  // Case sub-tabs
  const caseTabTimeline = document.getElementById('caseTabTimeline');
  const caseTabSignals = document.getElementById('caseTabSignals');
  const caseTabEntities = document.getElementById('caseTabEntities');
  const caseTabManifest = document.getElementById('caseTabManifest');
  const caseTabNarrative = document.getElementById('caseTabNarrative');
  
  // Drag and drop handlers
  if (importDropZone) {
    importDropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      importDropZone.classList.add('border-violet-500', 'bg-violet-500/10');
    });
    
    importDropZone.addEventListener('dragleave', (e) => {
      e.preventDefault();
      importDropZone.classList.remove('border-violet-500', 'bg-violet-500/10');
    });
    
    importDropZone.addEventListener('drop', async (e) => {
      e.preventDefault();
      importDropZone.classList.remove('border-violet-500', 'bg-violet-500/10');
      
      const items = e.dataTransfer.items;
      if (items && items.length > 0) {
        // Check for folder
        const item = items[0];
        if (item.webkitGetAsEntry) {
          const entry = item.webkitGetAsEntry();
          if (entry && entry.isDirectory) {
            await importFolder(entry);
            return;
          }
        }
        
        // Handle files
        const files = e.dataTransfer.files;
        if (files.length > 0) {
          await importFiles(files);
        }
      }
    });
  }
  
  // File picker handlers
  if (importFilePicker) {
    importFilePicker.addEventListener('change', async (e) => {
      const files = e.target.files;
      if (files && files.length > 0) {
        await importFiles(files);
      }
      importFilePicker.value = '';
    });
  }
  
  if (importFolderBtn && importFolderPicker) {
    importFolderBtn.addEventListener('click', () => {
      importFolderPicker.click();
    });
    
    importFolderPicker.addEventListener('change', async (e) => {
      const files = e.target.files;
      if (files && files.length > 0) {
        await importFiles(files);
      }
      importFolderPicker.value = '';
    });
  }
  
  // Import files function
  async function importFiles(files) {
    showImportProgress();
    updateImportProgress(10, 'Preparing files...');
    
    try {
      // Create FormData with files
      const formData = new FormData();
      for (let i = 0; i < files.length; i++) {
        formData.append('files', files[i]);
      }
      
      updateImportProgress(30, 'Uploading files...');
      
      const response = await fetch('/api/import/bundle', {
        method: 'POST',
        body: formData
      });
      
      updateImportProgress(60, 'Processing...');
      
      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(error.error || 'Import failed');
      }
      
      const result = await response.json();
      
      updateImportProgress(80, 'Analyzing events...');
      
      // Add to cases list
      importedCases.unshift(result);
      
      updateImportProgress(100, 'Complete!');
      
      setTimeout(() => {
        hideImportProgress();
        renderCasesList();
        selectCase(result.bundle_id);
        showToast('Import successful', `${result.files_count} files, ${result.events_count} events`);
      }, 500);
      
    } catch (err) {
      hideImportProgress();
      showToast('Import failed', err.message, 'error');
      console.error('Import error:', err);
    }
  }
  
  // Import folder (from drag-drop DirectoryEntry)
  async function importFolder(entry) {
    showImportProgress();
    updateImportProgress(10, 'Reading folder...');
    
    try {
      const files = [];
      await readDirectoryRecursive(entry, files);
      
      if (files.length === 0) {
        throw new Error('No files found in folder');
      }
      
      updateImportProgress(20, `Found ${files.length} files...`);
      await importFiles(files);
      
    } catch (err) {
      hideImportProgress();
      showToast('Import failed', err.message, 'error');
      console.error('Folder import error:', err);
    }
  }
  
  // Recursively read directory entries
  async function readDirectoryRecursive(entry, files, path = '') {
    return new Promise((resolve, reject) => {
      if (entry.isFile) {
        entry.file(file => {
          // Add path info
          file.relativePath = path + file.name;
          files.push(file);
          resolve();
        }, reject);
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        reader.readEntries(async (entries) => {
          for (const e of entries) {
            await readDirectoryRecursive(e, files, path + entry.name + '/');
          }
          resolve();
        }, reject);
      } else {
        resolve();
      }
    });
  }
  
  // Progress UI functions
  function showImportProgress() {
    if (importProgress) importProgress.classList.remove('hidden');
  }
  
  function hideImportProgress() {
    if (importProgress) importProgress.classList.add('hidden');
  }
  
  function updateImportProgress(percent, status) {
    if (importProgressBar) importProgressBar.style.width = `${percent}%`;
    if (importProgressPercent) importProgressPercent.textContent = `${percent}%`;
    if (importProgressStatus) importProgressStatus.textContent = status;
  }
  
  // Load imported cases from server
  async function loadImportedCases() {
    try {
      const response = await fetch('/api/import/cases');
      if (response.ok) {
        importedCases = await response.json();
        renderCasesList();
      }
    } catch (err) {
      console.error('Failed to load cases:', err);
    }
  }
  
  // Render cases list
  function renderCasesList() {
    if (!casesList) return;
    
    if (importedCases.length === 0) {
      casesList.innerHTML = `
        <div class="p-4 text-center text-xs text-slate-500">
          No cases imported yet.<br/>
          Import a bundle to get started.
        </div>
      `;
      return;
    }
    
    casesList.innerHTML = importedCases.map(c => `
      <div class="case-item p-3 border-b border-slate-700 hover:bg-slate-800/50 cursor-pointer ${c.bundle_id === selectedCaseId ? 'bg-slate-800' : ''}" 
           data-case-id="${c.bundle_id}">
        <div class="flex items-center justify-between mb-1">
          <div class="font-medium text-sm text-slate-200 truncate">${c.name || c.bundle_id}</div>
          <div class="text-xs px-1.5 py-0.5 rounded ${c.signals_count > 0 ? 'bg-amber-700' : 'bg-slate-700'}">${c.signals_count || 0}</div>
        </div>
        <div class="flex items-center gap-2 text-xs text-slate-400">
          <span>${c.files_count || 0} files</span>
          <span>•</span>
          <span>${c.events_count || 0} events</span>
        </div>
        <div class="text-xs text-slate-500 mt-1">${c.imported_at ? new Date(c.imported_at).toLocaleString() : '--'}</div>
      </div>
    `).join('');
    
    // Add click handlers
    casesList.querySelectorAll('.case-item').forEach(item => {
      item.addEventListener('click', () => {
        selectCase(item.dataset.caseId);
      });
    });
  }
  
  // Select a case
  async function selectCase(caseId) {
    selectedCaseId = caseId;
    selectedCase = importedCases.find(c => c.bundle_id === caseId);
    
    if (!selectedCase) {
      // Try to fetch from server
      try {
        const response = await fetch(`/api/import/cases/${caseId}`);
        if (response.ok) {
          selectedCase = await response.json();
        }
      } catch (err) {
        console.error('Failed to load case:', err);
      }
    }
    
    renderCasesList();
    renderCaseHeader();
    showCaseTab('timeline');
  }
  
  // Render case header
  function renderCaseHeader() {
    if (!selectedCase) {
      if (caseHeader) caseHeader.classList.add('hidden');
      if (caseTabs) caseTabs.classList.add('hidden');
      if (caseEmptyState) caseEmptyState.classList.remove('hidden');
      return;
    }
    
    if (caseHeader) caseHeader.classList.remove('hidden');
    if (caseTabs) caseTabs.classList.remove('hidden');
    if (caseEmptyState) caseEmptyState.classList.add('hidden');
    
    if (caseTitle) caseTitle.textContent = `Case: ${selectedCase.name || selectedCase.bundle_id}`;
    if (caseFileCount) caseFileCount.textContent = `${selectedCase.files_count || 0} files`;
    if (caseEventCount) caseEventCount.textContent = `${selectedCase.events_count || 0} events`;
    if (caseSignalCount) caseSignalCount.textContent = `${selectedCase.signals_count || 0} signals`;
    if (caseTimeRange) caseTimeRange.textContent = selectedCase.time_range || '--';
  }
  
  // Show case sub-tab
  function showCaseTab(tab) {
    // Hide all views
    [caseTimelineView, caseSignalsView, caseEntitiesView, caseManifestView, caseNarrativeView].forEach(v => {
      if (v) v.classList.add('hidden');
    });
    
    // Update tab styles
    [caseTabTimeline, caseTabSignals, caseTabEntities, caseTabManifest, caseTabNarrative].forEach(t => {
      if (t) t.className = 'px-3 py-1 rounded bg-slate-800 text-slate-200';
    });
    
    // Show selected view
    switch (tab) {
      case 'timeline':
        if (caseTimelineView) caseTimelineView.classList.remove('hidden');
        if (caseTabTimeline) caseTabTimeline.className = 'px-3 py-1 rounded bg-sky-600 text-white';
        loadCaseTimeline();
        break;
      case 'signals':
        if (caseSignalsView) caseSignalsView.classList.remove('hidden');
        if (caseTabSignals) caseTabSignals.className = 'px-3 py-1 rounded bg-sky-600 text-white';
        loadCaseSignals();
        break;
      case 'entities':
        if (caseEntitiesView) caseEntitiesView.classList.remove('hidden');
        if (caseTabEntities) caseTabEntities.className = 'px-3 py-1 rounded bg-sky-600 text-white';
        loadCaseEntities();
        break;
      case 'manifest':
        if (caseManifestView) caseManifestView.classList.remove('hidden');
        if (caseTabManifest) caseTabManifest.className = 'px-3 py-1 rounded bg-sky-600 text-white';
        loadCaseManifest();
        break;
      case 'narrative':
        if (caseNarrativeView) caseNarrativeView.classList.remove('hidden');
        if (caseTabNarrative) caseTabNarrative.className = 'px-3 py-1 rounded bg-sky-600 text-white';
        break;
    }
  }
  
  // Tab click handlers
  if (caseTabTimeline) caseTabTimeline.onclick = () => showCaseTab('timeline');
  if (caseTabSignals) caseTabSignals.onclick = () => showCaseTab('signals');
  if (caseTabEntities) caseTabEntities.onclick = () => showCaseTab('entities');
  if (caseTabManifest) caseTabManifest.onclick = () => showCaseTab('manifest');
  if (caseTabNarrative) caseTabNarrative.onclick = () => showCaseTab('narrative');
  
  // Load case timeline
  async function loadCaseTimeline() {
    if (!selectedCaseId) return;
    const content = document.getElementById('timelineContent');
    if (!content) return;
    
    content.innerHTML = '<div class="text-center text-xs text-slate-500 py-4">Loading timeline...</div>';
    
    try {
      const response = await fetch(`/api/import/cases/${selectedCaseId}/timeline`);
      if (!response.ok) throw new Error('Failed to load timeline');
      
      const events = await response.json();
      
      if (events.length === 0) {
        content.innerHTML = '<div class="text-center text-xs text-slate-500 py-4">No events found</div>';
        return;
      }
      
      content.innerHTML = events.map(e => `
        <div class="p-2 border-b border-slate-800 hover:bg-slate-800/50">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="text-xs text-slate-500">${e.timestamp ? new Date(e.timestamp).toLocaleString() : '--'}</span>
              <span class="text-xs px-1.5 py-0.5 rounded bg-slate-700">${e.event_type || 'event'}</span>
            </div>
            <div class="flex gap-1">
              ${(e.tags || []).slice(0, 3).map(t => `<span class="text-xs px-1 rounded bg-violet-700/50">${t}</span>`).join('')}
            </div>
          </div>
          <div class="text-xs text-slate-300 mt-1 truncate">${summarizeEvent(e)}</div>
          <div class="text-xs text-slate-500 mt-1">
            <span class="font-mono">${e.source_file || '--'}</span>
            ${e.source_line ? `<span class="ml-1">:${e.source_line}</span>` : ''}
          </div>
        </div>
      `).join('');
      
    } catch (err) {
      content.innerHTML = `<div class="text-center text-xs text-rose-400 py-4">Error: ${err.message}</div>`;
    }
  }
  
  // Load case signals
  async function loadCaseSignals() {
    if (!selectedCaseId) return;
    const content = document.getElementById('signalsContent');
    if (!content) return;
    
    content.innerHTML = '<div class="text-center text-xs text-slate-500 py-4">Loading signals...</div>';
    
    try {
      const response = await fetch(`/api/import/cases/${selectedCaseId}/signals`);
      if (!response.ok) throw new Error('Failed to load signals');
      
      const signals = await response.json();
      
      if (signals.length === 0) {
        content.innerHTML = '<div class="text-center text-xs text-slate-500 py-4">No signals generated</div>';
        return;
      }
      
      content.innerHTML = signals.map(s => `
        <div class="p-3 border-b border-slate-700 hover:bg-slate-800/50">
          <div class="flex items-center justify-between mb-1">
            <div class="flex items-center gap-2">
              <span class="text-xs px-1.5 py-0.5 rounded ${severityBadgeClass(s.severity)}">${s.severity || 'info'}</span>
              <span class="font-medium text-sm text-slate-200">${s.title || s.playbook_id || 'Signal'}</span>
            </div>
            <span class="text-xs text-slate-500">${s.timestamp ? new Date(s.timestamp).toLocaleString() : '--'}</span>
          </div>
          <div class="text-xs text-slate-400 mb-2">${s.description || '--'}</div>
          <div class="flex gap-1 flex-wrap">
            ${(s.tags || []).map(t => `<span class="text-xs px-1 rounded bg-slate-700">${t}</span>`).join('')}
          </div>
          ${s.evidence_ptr ? `
            <div class="text-xs text-slate-500 mt-2 font-mono">
              Evidence: ${s.evidence_ptr.rel_path}${s.evidence_ptr.line_no ? `:${s.evidence_ptr.line_no}` : ''}
            </div>
          ` : ''}
        </div>
      `).join('');
      
    } catch (err) {
      content.innerHTML = `<div class="text-center text-xs text-rose-400 py-4">Error: ${err.message}</div>`;
    }
  }
  
  // Load case entities
  async function loadCaseEntities() {
    if (!selectedCaseId) return;
    
    try {
      const response = await fetch(`/api/import/cases/${selectedCaseId}/entities`);
      if (!response.ok) throw new Error('Failed to load entities');
      
      const entities = await response.json();
      
      const domainsEl = document.getElementById('entitiesDomains');
      const ipsEl = document.getElementById('entitiesIPs');
      const urlsEl = document.getElementById('entitiesURLs');
      const hashesEl = document.getElementById('entitiesHashes');
      
      if (domainsEl) {
        domainsEl.innerHTML = (entities.domains || []).length > 0
          ? entities.domains.map(d => `<div class="text-slate-200">${d}</div>`).join('')
          : '<div class="text-slate-500">None</div>';
      }
      if (ipsEl) {
        ipsEl.innerHTML = (entities.ips || []).length > 0
          ? entities.ips.map(ip => `<div class="text-slate-200 font-mono">${ip}</div>`).join('')
          : '<div class="text-slate-500">None</div>';
      }
      if (urlsEl) {
        urlsEl.innerHTML = (entities.urls || []).length > 0
          ? entities.urls.slice(0, 20).map(u => `<div class="text-slate-200 truncate" title="${u}">${u}</div>`).join('')
          : '<div class="text-slate-500">None</div>';
      }
      if (hashesEl) {
        hashesEl.innerHTML = (entities.hashes || []).length > 0
          ? entities.hashes.map(h => `<div class="text-slate-200 font-mono text-xs">${h}</div>`).join('')
          : '<div class="text-slate-500">None</div>';
      }
      
    } catch (err) {
      console.error('Failed to load entities:', err);
    }
  }
  
  // Load case manifest
  async function loadCaseManifest() {
    if (!selectedCaseId) return;
    const content = document.getElementById('manifestContent');
    if (!content) return;
    
    try {
      const response = await fetch(`/api/import/cases/${selectedCaseId}/manifest`);
      if (!response.ok) throw new Error('Failed to load manifest');
      
      const manifest = await response.json();
      
      content.innerHTML = (manifest.files || []).map(f => `
        <tr class="hover:bg-slate-800/50">
          <td class="px-3 py-2 text-slate-200 truncate max-w-[200px]" title="${f.rel_path}">${f.rel_path}</td>
          <td class="px-3 py-2 text-slate-400">${f.kind || '--'}</td>
          <td class="px-3 py-2 text-slate-400">${formatBytes(f.size_bytes)}</td>
          <td class="px-3 py-2 text-slate-500 font-mono truncate max-w-[100px]" title="${f.sha256}">${f.sha256?.substring(0, 16) || '--'}...</td>
          <td class="px-3 py-2">
            <span class="px-1.5 py-0.5 rounded text-xs ${f.parsed ? 'bg-emerald-700' : 'bg-slate-700'}">${f.parsed ? '✓' : '-'}</span>
          </td>
          <td class="px-3 py-2 text-slate-400">${f.events_extracted || 0}</td>
        </tr>
      `).join('');
      
    } catch (err) {
      content.innerHTML = `<tr><td colspan="6" class="text-center text-rose-400 py-4">Error: ${err.message}</td></tr>`;
    }
  }
  
  // Helper: summarize event
  function summarizeEvent(e) {
    const fields = e.fields || {};
    if (fields.url) return fields.url;
    if (fields.query) return `DNS: ${fields.query}`;
    if (fields.domain) return fields.domain;
    if (fields.method && fields.url) return `${fields.method} ${fields.url}`;
    if (e.event_type === 'zeek_conn') {
      return `${fields['id.orig_h'] || '--'} → ${fields['id.resp_h'] || '--'}:${fields['id.resp_p'] || '--'}`;
    }
    return e.event_type || 'Event';
  }
  
  // Helper: severity badge class
  function severityBadgeClass(sev) {
    switch ((sev || '').toLowerCase()) {
      case 'critical': return 'bg-rose-700';
      case 'high': return 'bg-rose-600';
      case 'medium': return 'bg-amber-600';
      case 'low': return 'bg-emerald-700';
      default: return 'bg-slate-700';
    }
  }
  
  // Helper: format bytes
  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }
  
  // Refresh cases button
  const refreshCasesBtn = document.getElementById('refreshCasesBtn');
  if (refreshCasesBtn) {
    refreshCasesBtn.addEventListener('click', loadImportedCases);
  }
  
  // Delete case button
  const deleteCaseBtn = document.getElementById('deleteCaseBtn');
  if (deleteCaseBtn) {
    deleteCaseBtn.addEventListener('click', async () => {
      if (!selectedCaseId) return;
      if (!confirm('Delete this case? This cannot be undone.')) return;
      
      try {
        const response = await fetch(`/api/import/cases/${selectedCaseId}`, { method: 'DELETE' });
        if (response.ok) {
          importedCases = importedCases.filter(c => c.bundle_id !== selectedCaseId);
          selectedCaseId = null;
          selectedCase = null;
          renderCasesList();
          renderCaseHeader();
          showToast('Case deleted', 'success');
        }
      } catch (err) {
        showToast('Delete failed', err.message, 'error');
      }
    });
  }
  
  // Reprocess case button
  const reprocessCaseBtn = document.getElementById('reprocessCaseBtn');
  if (reprocessCaseBtn) {
    reprocessCaseBtn.addEventListener('click', async () => {
      if (!selectedCaseId) return;
      
      reprocessCaseBtn.disabled = true;
      reprocessCaseBtn.textContent = 'Processing...';
      
      try {
        const response = await fetch(`/api/import/cases/${selectedCaseId}/reprocess`, { method: 'POST' });
        if (response.ok) {
          const result = await response.json();
          selectedCase = result;
          renderCaseHeader();
          showCaseTab('signals');
          showToast('Reprocessed', `${result.signals_count} signals generated`);
        }
      } catch (err) {
        showToast('Reprocess failed', err.message, 'error');
      } finally {
        reprocessCaseBtn.disabled = false;
        reprocessCaseBtn.textContent = '🔄 Reprocess';
      }
    });
  }
  
  // Export case button
  const exportCaseBtn = document.getElementById('exportCaseBtn');
  if (exportCaseBtn) {
    exportCaseBtn.addEventListener('click', async () => {
      if (!selectedCaseId) return;
      
      try {
        const response = await fetch(`/api/import/cases/${selectedCaseId}/export`);
        if (response.ok) {
          const blob = await response.blob();
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `case_${selectedCaseId}.zip`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);
        }
      } catch (err) {
        showToast('Export failed', err.message, 'error');
      }
    });
  }
  
  // Generate narrative button
  const generateNarrativeBtn = document.getElementById('generateNarrativeBtn');
  if (generateNarrativeBtn) {
    generateNarrativeBtn.addEventListener('click', async () => {
      if (!selectedCaseId) return;
      
      const narrativeContent = document.getElementById('narrativeContent');
      if (narrativeContent) {
        narrativeContent.innerHTML = '<div class="text-center text-slate-400 py-4">Generating narrative...</div>';
      }
      
      try {
        const response = await fetch(`/api/import/cases/${selectedCaseId}/narrative`, { method: 'POST' });
        if (response.ok) {
          const result = await response.json();
          if (narrativeContent) {
            narrativeContent.innerHTML = `
              <h3 class="text-lg font-semibold mb-3">${result.title || 'Investigation Summary'}</h3>
              <div class="text-slate-300 whitespace-pre-wrap">${result.narrative || 'No narrative generated.'}</div>
              ${result.recommendations ? `
                <h4 class="text-md font-medium mt-4 mb-2">Recommendations</h4>
                <ul class="list-disc list-inside text-slate-400">
                  ${result.recommendations.map(r => `<li>${r}</li>`).join('')}
                </ul>
              ` : ''}
            `;
          }
        }
      } catch (err) {
        if (narrativeContent) {
          narrativeContent.innerHTML = `<div class="text-center text-rose-400 py-4">Error: ${err.message}</div>`;
        }
      }
    });
  }
  
  // Initialize on load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initWorkflow);
  } else {
    initWorkflow();
  }

  // ============================================================================
  // Compare Runs (Pro Feature)
  // ============================================================================
  
  const diffLeftRun = document.getElementById('diffLeftRun');
  const diffRightRun = document.getElementById('diffRightRun');
  const runDiffBtn = document.getElementById('runDiffBtn');
  const diffSummaryCard = document.getElementById('diffSummaryCard');
  const diffProBanner = document.getElementById('diffProBanner');
  const diffLoading = document.getElementById('diffLoading');
  const diffEmpty = document.getElementById('diffEmpty');
  const diffResults = document.getElementById('diffResults');
  
  // Update Compare button state
  function updateDiffButton() {
    if (runDiffBtn && diffLeftRun && diffRightRun) {
      const canCompare = diffLeftRun.value && diffRightRun.value && diffLeftRun.value !== diffRightRun.value;
      runDiffBtn.disabled = !canCompare;
    }
  }
  
  if (diffLeftRun) diffLeftRun.addEventListener('change', updateDiffButton);
  if (diffRightRun) diffRightRun.addEventListener('change', updateDiffButton);
  
  // Load available runs for comparison
  async function loadRunsForCompare() {
    try {
      const response = await fetch('/api/runs');
      if (!response.ok) {
        console.error('Failed to load runs');
        return;
      }
      const data = await response.json();
      if (!data.success || !data.data) return;
      
      const runs = data.data;
      const options = runs.map(r => {
        const date = new Date(r.earliest_ts).toLocaleString();
        return `<option value="${r.run_id}">${r.run_id} (${r.signal_count} signals, ${date})</option>`;
      }).join('');
      
      const emptyOption = '<option value="">Select run...</option>';
      if (diffLeftRun) diffLeftRun.innerHTML = emptyOption + options;
      if (diffRightRun) diffRightRun.innerHTML = emptyOption + options;
    } catch (err) {
      console.error('Failed to load runs:', err);
    }
  }
  
  // Run the diff comparison
  async function runDiffComparison() {
    if (!diffLeftRun || !diffRightRun) return;
    
    const leftId = diffLeftRun.value;
    const rightId = diffRightRun.value;
    if (!leftId || !rightId) return;
    
    // Show loading
    if (diffLoading) diffLoading.classList.remove('hidden');
    if (diffEmpty) diffEmpty.classList.add('hidden');
    if (diffResults) diffResults.classList.add('hidden');
    if (diffProBanner) diffProBanner.classList.add('hidden');
    if (diffSummaryCard) diffSummaryCard.classList.add('hidden');
    
    try {
      const response = await fetch(`/api/diff?left=${encodeURIComponent(leftId)}&right=${encodeURIComponent(rightId)}`);
      const data = await response.json();
      
      if (diffLoading) diffLoading.classList.add('hidden');
      
      // Check for Pro feature gate (license required)
      if (response.status === 402) {
        if (diffProBanner) {
          diffProBanner.classList.remove('hidden');
          // Update banner with install_id if available
          const installId = data.install_id;
          const reason = data.reason || 'No valid license with diff_mode entitlement';
          diffProBanner.innerHTML = `
            <div class="flex items-start gap-3">
              <span class="text-2xl">🔒</span>
              <div class="flex-1">
                <h4 class="font-medium text-amber-300">Pro License Required</h4>
                <p class="text-sm text-amber-200/80 mt-1">${reason}</p>
                ${installId ? `
                  <div class="mt-3 p-2 rounded bg-slate-900/50">
                    <div class="text-xs text-slate-400 mb-1">Your Installation ID:</div>
                    <code class="text-xs font-mono text-sky-300 select-all">${installId}</code>
                  </div>
                  <p class="text-xs text-slate-400 mt-2">Include this ID when purchasing a license.</p>
                ` : ''}
                <button onclick="activateTab('license')" class="mt-3 px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-sm font-medium">
                  Go to License Panel →
                </button>
              </div>
            </div>
          `;
        }
        if (diffEmpty) diffEmpty.classList.add('hidden');
        return;
      }
      
      // Check for fingerprint mismatch (license bound to different machine)
      if (response.status === 403) {
        if (diffProBanner) {
          diffProBanner.classList.remove('hidden');
          const installId = data.install_id;
          const reason = data.reason || 'License is bound to a different machine';
          diffProBanner.innerHTML = `
            <div class="flex items-start gap-3">
              <span class="text-2xl">🔄</span>
              <div class="flex-1">
                <h4 class="font-medium text-red-300">Machine Binding Error</h4>
                <p class="text-sm text-red-200/80 mt-1">${reason}</p>
                <p class="text-sm text-slate-300 mt-2">Your license is bound to a different machine. If you've upgraded hardware or reinstalled, please contact support with your Installation ID.</p>
                ${installId ? `
                  <div class="mt-3 p-2 rounded bg-slate-900/50">
                    <div class="text-xs text-slate-400 mb-1">Your Installation ID:</div>
                    <code class="text-xs font-mono text-sky-300 select-all">${installId}</code>
                    <button onclick="navigator.clipboard.writeText('${installId}')" class="ml-2 px-1.5 py-0.5 rounded bg-slate-700 hover:bg-slate-600 text-xs" title="Copy">📋</button>
                  </div>
                ` : ''}
                <button onclick="activateTab('license')" class="mt-3 px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-sm font-medium">
                  Check License Status →
                </button>
              </div>
            </div>
          `;
        }
        if (diffEmpty) diffEmpty.classList.add('hidden');
        return;
      }
      
      if (!data.success) {
        showToast('Diff failed', data.error || 'Unknown error', 'error');
        if (diffEmpty) diffEmpty.classList.remove('hidden');
        return;
      }
      
      // Show results
      renderDiffResults(data.data);
    } catch (err) {
      if (diffLoading) diffLoading.classList.add('hidden');
      showToast('Diff failed', err.message, 'error');
      if (diffEmpty) diffEmpty.classList.remove('hidden');
    }
  }
  
  // Render diff results
  function renderDiffResults(data) {
    if (!data || !data.diff) return;
    
    const { diff, meta } = data;
    
    // Show summary card
    if (diffSummaryCard) {
      diffSummaryCard.classList.remove('hidden');
      const el = (id) => document.getElementById(id);
      if (el('diffAddedCount')) el('diffAddedCount').textContent = diff.summary.added_count;
      if (el('diffRemovedCount')) el('diffRemovedCount').textContent = diff.summary.removed_count;
      if (el('diffChangedCount')) el('diffChangedCount').textContent = diff.summary.changed_count;
      if (el('diffUnchangedCount')) el('diffUnchangedCount').textContent = diff.summary.unchanged_count;
    }
    
    // Show results container
    if (diffResults) diffResults.classList.remove('hidden');
    if (diffEmpty) diffEmpty.classList.add('hidden');
    
    // Render added signals
    const addedList = document.getElementById('diffAddedList');
    const addedBadge = document.getElementById('diffAddedBadge');
    if (addedList && addedBadge) {
      addedBadge.textContent = diff.added.length;
      addedList.innerHTML = diff.added.length === 0 
        ? '<div class="text-xs text-slate-500">No signals added</div>'
        : diff.added.map(s => `
          <div class="p-2 rounded bg-slate-800/50 border border-emerald-700/30">
            <div class="flex items-center gap-2">
              <span class="px-1.5 py-0.5 rounded text-xs ${getSeverityClass(s.severity)}">${s.severity}</span>
              <span class="text-sm font-medium text-slate-200">${s.signal_type}</span>
            </div>
            <div class="text-xs text-slate-400 mt-1">Host: ${s.host}</div>
          </div>
        `).join('');
    }
    
    // Render removed signals
    const removedList = document.getElementById('diffRemovedList');
    const removedBadge = document.getElementById('diffRemovedBadge');
    if (removedList && removedBadge) {
      removedBadge.textContent = diff.removed.length;
      removedList.innerHTML = diff.removed.length === 0 
        ? '<div class="text-xs text-slate-500">No signals removed</div>'
        : diff.removed.map(s => `
          <div class="p-2 rounded bg-slate-800/50 border border-rose-700/30">
            <div class="flex items-center gap-2">
              <span class="px-1.5 py-0.5 rounded text-xs ${getSeverityClass(s.severity)}">${s.severity}</span>
              <span class="text-sm font-medium text-slate-200">${s.signal_type}</span>
            </div>
            <div class="text-xs text-slate-400 mt-1">Host: ${s.host}</div>
          </div>
        `).join('');
    }
    
    // Render changed signals
    const changedList = document.getElementById('diffChangedList');
    const changedBadge = document.getElementById('diffChangedBadge');
    if (changedList && changedBadge) {
      changedBadge.textContent = diff.changed.length;
      changedList.innerHTML = diff.changed.length === 0 
        ? '<div class="text-xs text-slate-500">No signals changed</div>'
        : diff.changed.map(s => `
          <div class="p-2 rounded bg-slate-800/50 border border-amber-700/30">
            <div class="text-sm font-medium text-slate-200 mb-2">${s.stable_key}</div>
            <div class="space-y-1">
              ${s.changes.map(c => `
                <div class="flex items-center gap-2 text-xs">
                  <span class="text-slate-400">${c.field}:</span>
                  <span class="text-rose-400 line-through">${c.left_value}</span>
                  <span class="text-slate-500">→</span>
                  <span class="text-emerald-400">${c.right_value}</span>
                </div>
              `).join('')}
            </div>
          </div>
        `).join('');
    }
  }
  
  // Helper for severity colors
  function getSeverityClass(sev) {
    switch ((sev || '').toLowerCase()) {
      case 'critical': return 'bg-rose-700';
      case 'high': return 'bg-orange-700';
      case 'medium': return 'bg-amber-700';
      case 'low': return 'bg-emerald-700';
      default: return 'bg-slate-700';
    }
  }
  
  // Attach Compare button handler
  if (runDiffBtn) {
    runDiffBtn.addEventListener('click', runDiffComparison);
  }

  // ============================================================================
  // LICENSE MANAGEMENT
  // ============================================================================

  // License UI elements
  const licenseStatusIcon = document.getElementById('licenseStatusIcon');
  const licenseStatusText = document.getElementById('licenseStatusText');
  const licenseStatusDetail = document.getElementById('licenseStatusDetail');
  const licenseDetailsCard = document.getElementById('licenseDetailsCard');
  const licenseLicenseId = document.getElementById('licenseLicenseId');
  const licenseCustomer = document.getElementById('licenseCustomer');
  const licenseEdition = document.getElementById('licenseEdition');
  const licenseExpires = document.getElementById('licenseExpires');
  const licenseEntitlementsCard = document.getElementById('licenseEntitlementsCard');
  const licenseEntitlementsList = document.getElementById('licenseEntitlementsList');
  const licenseInstallId = document.getElementById('licenseInstallId');
  const copyInstallIdBtn = document.getElementById('copyInstallIdBtn');
  const licenseDropZone = document.getElementById('licenseDropZone');
  const licenseFileInput = document.getElementById('licenseFileInput');
  const licensePasteArea = document.getElementById('licensePasteArea');
  const installLicenseBtn = document.getElementById('installLicenseBtn');
  const licenseImportResult = document.getElementById('licenseImportResult');
  const featureDiffStatus = document.getElementById('featureDiffStatus');
  const featureReportsStatus = document.getElementById('featureReportsStatus');
  const featureTeamStatus = document.getElementById('featureTeamStatus');

  // Track current license state
  let currentLicenseStatus = null;

  async function loadLicenseStatus() {
    try {
      const response = await fetch('/api/license/status');
      const data = await response.json();
      currentLicenseStatus = data;
      renderLicenseStatus(data);
    } catch (err) {
      console.error('Failed to load license status:', err);
      renderLicenseError('Failed to check license status');
    }
  }

  function renderLicenseStatus(data) {
    if (!licenseStatusIcon || !licenseStatusText) return;

    // Update install ID
    if (licenseInstallId && data.install_id) {
      licenseInstallId.textContent = data.install_id;
    }

    // Determine status
    const status = data.status;
    const license = data.license;

    // Update status badge
    switch (status) {
      case 'valid':
        licenseStatusIcon.textContent = '✅';
        licenseStatusText.textContent = 'License Valid';
        licenseStatusDetail.textContent = license?.edition ? `${license.edition.toUpperCase()} Edition` : 'Active';
        break;
      case 'not_installed':
        licenseStatusIcon.textContent = '🔒';
        licenseStatusText.textContent = 'No License Installed';
        licenseStatusDetail.textContent = 'Import a license to unlock Pro features';
        break;
      case 'expired':
        licenseStatusIcon.textContent = '⏰';
        licenseStatusText.textContent = 'License Expired';
        licenseStatusDetail.textContent = 'Please renew your license';
        break;
      case 'invalid':
        licenseStatusIcon.textContent = '❌';
        licenseStatusText.textContent = 'Invalid License';
        licenseStatusDetail.textContent = 'License verification failed';
        break;
      case 'wrong_installation':
        licenseStatusIcon.textContent = '🔄';
        licenseStatusText.textContent = 'Wrong Installation';
        licenseStatusDetail.textContent = 'License bound to different installation';
        break;
      case 'not_configured':
        licenseStatusIcon.textContent = '⚙️';
        licenseStatusText.textContent = 'Not Configured';
        licenseStatusDetail.textContent = 'Development build - license system not configured';
        break;
      default:
        licenseStatusIcon.textContent = '❓';
        licenseStatusText.textContent = 'Unknown Status';
        licenseStatusDetail.textContent = '';
    }

    // Show/hide license details card
    if (licenseDetailsCard) {
      if (status === 'valid' && license) {
        licenseDetailsCard.classList.remove('hidden');
        if (licenseLicenseId) licenseLicenseId.textContent = license.license_id || '—';
        if (licenseCustomer) licenseCustomer.textContent = license.customer || '—';
        if (licenseEdition) licenseEdition.textContent = license.edition || '—';
        if (licenseExpires) {
          if (license.expires_at) {
            const expDate = new Date(license.expires_at);
            licenseExpires.textContent = expDate.toLocaleDateString();
          } else {
            licenseExpires.textContent = 'Perpetual';
          }
        }
      } else {
        licenseDetailsCard.classList.add('hidden');
      }
    }

    // Show/hide entitlements
    if (licenseEntitlementsCard && licenseEntitlementsList) {
      if (status === 'valid' && license?.entitlements?.length > 0) {
        licenseEntitlementsCard.classList.remove('hidden');
        licenseEntitlementsList.innerHTML = license.entitlements.map(ent => `
          <div class="flex items-center gap-2 text-emerald-400">
            <span>✓</span>
            <span>${formatEntitlement(ent)}</span>
          </div>
        `).join('');
      } else {
        licenseEntitlementsCard.classList.add('hidden');
      }
    }

    // Update feature status icons
    const entitlements = license?.entitlements || [];
    if (featureDiffStatus) {
      featureDiffStatus.textContent = entitlements.includes('diff_mode') ? '✅' : '🔒';
    }
    if (featureReportsStatus) {
      featureReportsStatus.textContent = entitlements.includes('pro_reports') ? '✅' : '🔒';
    }
    if (featureTeamStatus) {
      featureTeamStatus.textContent = entitlements.includes('team_features') ? '✅' : '🔒';
    }
    
    // Update fingerprint/machine binding status
    renderFingerprintStatus(data.fingerprint);
  }
  
  function renderFingerprintStatus(fingerprint) {
    const fingerprintStatusIcon = document.getElementById('fingerprintStatusIcon');
    const fingerprintStatusText = document.getElementById('fingerprintStatusText');
    const fingerprintDetail = document.getElementById('fingerprintDetail');
    const fingerprintCard = document.getElementById('fingerprintCard');
    
    if (!fingerprintStatusIcon || !fingerprintStatusText) return;
    
    if (!fingerprint || !fingerprint.available) {
      // Fingerprint not available (likely dev mode)
      fingerprintStatusIcon.textContent = '❓';
      fingerprintStatusText.textContent = 'Not Available';
      fingerprintDetail.textContent = 'Machine binding not configured';
      return;
    }
    
    const status = fingerprint.status;
    
    switch (status) {
      case 'bound':
        fingerprintStatusIcon.textContent = '🔐';
        fingerprintStatusText.textContent = 'Bound to this machine';
        fingerprintDetail.textContent = `Fingerprint: ${fingerprint.value || '—'}`;
        if (fingerprintCard) fingerprintCard.classList.remove('border-red-500', 'border-amber-500');
        break;
      case 'mismatch':
        fingerprintStatusIcon.textContent = '⚠️';
        fingerprintStatusText.textContent = 'Machine Mismatch';
        fingerprintDetail.textContent = 'License was activated on a different machine. Please contact support.';
        if (fingerprintCard) {
          fingerprintCard.classList.remove('border-slate-700');
          fingerprintCard.classList.add('border-red-500');
        }
        break;
      case 'unavailable':
        fingerprintStatusIcon.textContent = '❓';
        fingerprintStatusText.textContent = 'Cannot verify';
        fingerprintDetail.textContent = 'Unable to read machine fingerprint';
        if (fingerprintCard) {
          fingerprintCard.classList.remove('border-slate-700');
          fingerprintCard.classList.add('border-amber-500');
        }
        break;
      case 'not_checked':
      default:
        fingerprintStatusIcon.textContent = '⏳';
        fingerprintStatusText.textContent = 'Not Checked';
        fingerprintDetail.textContent = 'No valid license to verify against';
        break;
    }
  }

  function formatEntitlement(ent) {
    const names = {
      'diff_mode': 'Diff Mode',
      'pro_reports': 'Pro Reports',
      'team_features': 'Team Features'
    };
    return names[ent] || ent;
  }

  function renderLicenseError(message) {
    if (licenseStatusIcon) licenseStatusIcon.textContent = '⚠️';
    if (licenseStatusText) licenseStatusText.textContent = 'Error';
    if (licenseStatusDetail) licenseStatusDetail.textContent = message;
  }

  // Copy Install ID to clipboard
  if (copyInstallIdBtn && licenseInstallId) {
    copyInstallIdBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(licenseInstallId.textContent);
        copyInstallIdBtn.textContent = '✓';
        setTimeout(() => { copyInstallIdBtn.textContent = '📋'; }, 1500);
      } catch (err) {
        console.error('Failed to copy:', err);
      }
    });
  }

  // File drop zone
  if (licenseDropZone && licenseFileInput) {
    licenseDropZone.addEventListener('click', () => licenseFileInput.click());
    
    licenseDropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      licenseDropZone.classList.add('border-sky-500');
    });
    
    licenseDropZone.addEventListener('dragleave', () => {
      licenseDropZone.classList.remove('border-sky-500');
    });
    
    licenseDropZone.addEventListener('drop', async (e) => {
      e.preventDefault();
      licenseDropZone.classList.remove('border-sky-500');
      
      const file = e.dataTransfer.files[0];
      if (file) {
        const content = await file.text();
        if (licensePasteArea) licensePasteArea.value = content;
      }
    });
    
    licenseFileInput.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (file) {
        const content = await file.text();
        if (licensePasteArea) licensePasteArea.value = content;
      }
    });
  }

  // Install license button
  if (installLicenseBtn) {
    installLicenseBtn.addEventListener('click', async () => {
      const content = licensePasteArea?.value?.trim();
      if (!content) {
        showLicenseResult('error', 'Please paste or drop a license file first');
        return;
      }

      // Validate JSON
      try {
        JSON.parse(content);
      } catch (err) {
        showLicenseResult('error', 'Invalid JSON format');
        return;
      }

      installLicenseBtn.disabled = true;
      installLicenseBtn.textContent = 'Installing...';

      try {
        const response = await fetch('/api/license/install', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ license_content: content })
        });
        
        const data = await response.json();
        
        if (data.success) {
          showLicenseResult('success', 'License installed successfully!');
          if (licensePasteArea) licensePasteArea.value = '';
          // Reload status
          await loadLicenseStatus();
        } else {
          showLicenseResult('error', data.error || 'Installation failed');
        }
      } catch (err) {
        showLicenseResult('error', `Error: ${err.message}`);
      } finally {
        installLicenseBtn.disabled = false;
        installLicenseBtn.textContent = 'Install License';
      }
    });
  }

  function showLicenseResult(type, message) {
    if (!licenseImportResult) return;
    
    licenseImportResult.classList.remove('hidden', 'bg-emerald-900/50', 'text-emerald-200', 'bg-rose-900/50', 'text-rose-200');
    
    if (type === 'success') {
      licenseImportResult.classList.add('bg-emerald-900/50', 'text-emerald-200');
    } else {
      licenseImportResult.classList.add('bg-rose-900/50', 'text-rose-200');
    }
    
    licenseImportResult.textContent = message;
    
    setTimeout(() => {
      licenseImportResult.classList.add('hidden');
    }, 5000);
  }

  // Check license status on page load (for diff gating)
  loadLicenseStatus();

  // Update diff UI to handle 402 responses
  const originalRunDiffComparison = runDiffComparison;
  // Note: The runDiffComparison function already handles errors gracefully

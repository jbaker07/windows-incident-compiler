/* app.js — hardened + with health + incidents + playbooks (safe if elements missing) */

(() => {
  "use strict";

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
  const tabDash     = document.getElementById('tabDash');
  const tabInt      = document.getElementById('tabIntegrations');

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
    screenDash.classList.toggle('hidden', !onDash);
    screenInt.classList.toggle('hidden', onDash);
    tabDash.className = onDash
      ? 'px-3 py-1 rounded bg-sky-600 text-white'
      : 'px-3 py-1 rounded bg-slate-800 text-slate-200';
    tabInt.className = !onDash
      ? 'px-3 py-1 rounded bg-sky-600 text-white'
      : 'px-3 py-1 rounded bg-slate-800 text-slate-200';
    if (!onDash) loadIntegrations();
  }
  if (tabDash) tabDash.onclick = () => activateTab('dash');
  if (tabInt)  tabInt.onclick  = () => activateTab('int');
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
  
  // Initialize on load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initWorkflow);
  } else {
    initWorkflow();
  }
})();

})();

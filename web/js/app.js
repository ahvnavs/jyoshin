// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

(function () {
  'use strict';

  let authToken = localStorage.getItem('kazeshini_token') || '';
  let eventSource = null;
  let lastUpdatedTime = null;

  // DOM Elements
  const el = {
    verdictBanner: document.getElementById('verdict-banner'),
    verdictLead: document.getElementById('verdict-lead'),
    chaosScore: document.getElementById('chaos-score'),
    chaosBadge: document.getElementById('chaos-badge'),
    identityLine: document.getElementById('identity-line'),
    liveStatusText: document.getElementById('live-status-text'),
    pulseDot: document.getElementById('pulse-dot'),
    lastUpdated: document.getElementById('last-updated'),
    pulseHost: document.getElementById('pulse-host'),
    pulseKernel: document.getElementById('pulse-kernel'),
    pulseUptime: document.getElementById('pulse-uptime'),
    dangerList: document.getElementById('danger-list'),
    dangerCount: document.getElementById('danger-count'),
    wasteMonthly: document.getElementById('waste-monthly'),
    wasteList: document.getElementById('waste-list'),
    changesList: document.getElementById('changes-list'),
    authModal: document.getElementById('auth-modal'),
    authInput: document.getElementById('auth-token-input'),
    authSubmit: document.getElementById('auth-token-submit'),
    authCancel: document.getElementById('auth-token-cancel'),
    tokenBtn: document.getElementById('token-button'),
    mainView: document.getElementById('main-view'),
    styleguideView: document.getElementById('styleguide-view'),
    navMain: document.getElementById('nav-main'),
    navStyleguide: document.getElementById('nav-styleguide'),
  };

  // Severity Glyphs & Colors
  const SEVERITY_CONFIG = {
    critical: { glyph: '[▲]', colorClass: 'badge-rose', text: 'CRITICAL' },
    high:     { glyph: '[!]', colorClass: 'badge-peach', text: 'HIGH' },
    medium:   { glyph: '[●]', colorClass: 'badge-lavender', text: 'MEDIUM' },
    low:      { glyph: '[i]', colorClass: 'badge-cyan', text: 'LOW' },
    info:     { glyph: '[·]', colorClass: 'badge-dim', text: 'INFO' },
  };

  const CERTAINTY_CONFIG = {
    observed: { glyph: '[✓]', colorClass: 'badge-mint', text: 'OBSERVED' },
    derived:  { glyph: '[≈]', colorClass: 'badge-cyan', text: 'DERIVED' },
    inferred: { glyph: '[?]', colorClass: 'badge-peach', text: 'INFERRED' },
  };

  function formatDuration(seconds) {
    if (!seconds || seconds <= 0) return '0s';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  function getHeaders() {
    const h = { 'Accept': 'application/json' };
    if (authToken) {
      h['Authorization'] = `Bearer ${authToken}`;
    }
    return h;
  }

  // Routing: / vs /styleguide
  function handleRoute() {
    const hash = window.location.hash;
    if (hash === '#styleguide') {
      el.mainView.style.display = 'none';
      el.styleguideView.style.display = 'block';
      el.navMain.classList.remove('active');
      el.navStyleguide.classList.add('active');
    } else {
      el.mainView.style.display = 'block';
      el.styleguideView.style.display = 'none';
      el.navMain.classList.add('active');
      el.navStyleguide.classList.remove('active');
    }
  }

  window.addEventListener('hashchange', handleRoute);

  // Auth Handling
  el.tokenBtn.addEventListener('click', () => {
    el.authInput.value = authToken;
    el.authModal.style.display = 'flex';
    el.authInput.focus();
  });

  el.authCancel.addEventListener('click', () => {
    el.authModal.style.display = 'none';
  });

  el.authSubmit.addEventListener('click', () => {
    const tok = el.authInput.value.trim();
    if (tok) {
      authToken = tok;
      localStorage.setItem('kazeshini_token', tok);
    } else {
      authToken = '';
      localStorage.removeItem('kazeshini_token');
    }
    el.authModal.style.display = 'none';
    initSSE();
    refreshAll();
  });

  // Stale detection
  setInterval(() => {
    if (!lastUpdatedTime) return;
    const diffSeconds = (Date.now() - lastUpdatedTime) / 1000;
    if (diffSeconds > 6) {
      el.pulseDot.className = 'stale-indicator';
      el.liveStatusText.textContent = `[!] Stale (${Math.round(diffSeconds)}s ago)`;
    }
  }, 1000);

  // Render Verdict Hero
  function renderVerdict(v) {
    if (!v) return;
    lastUpdatedTime = Date.now();
    el.pulseDot.className = 'live-pulse';
    el.liveStatusText.textContent = '[●] LIVE';
    el.lastUpdated.textContent = new Date().toLocaleTimeString();

    el.verdictLead.textContent = v.one_line_verdict || 'Server status evaluation active.';
    el.chaosScore.textContent = v.chaos_index !== undefined ? v.chaos_index : '0';

    let badgeClass = 'badge-mint';
    let glyph = '[✓]';
    if (v.chaos_index >= 75 || v.state_label === 'CRITICAL') {
      badgeClass = 'badge-rose';
      glyph = '[▲]';
    } else if (v.chaos_index >= 45 || v.state_label === 'MESSY') {
      badgeClass = 'badge-peach';
      glyph = '[!]';
    } else if (v.chaos_index >= 16 || v.state_label === 'MODERATE') {
      badgeClass = 'badge-lavender';
      glyph = '[●]';
    }

    el.chaosBadge.className = `badge ${badgeClass}`;
    el.chaosBadge.textContent = `${glyph} ${v.state_label || 'CALM'}`;
    el.identityLine.textContent = `HOST: ${v.identity_line || 'Linux Server'}`;

    // Danger panel count
    const totalRisks = (v.critical_findings || 0) + (v.high_findings || 0);
    el.dangerCount.textContent = `${totalRisks} active`;
    if (totalRisks > 0) {
      el.dangerCount.className = 'badge badge-rose';
    } else {
      el.dangerCount.className = 'badge badge-mint';
    }

    // Waste Panel
    el.wasteMonthly.textContent = `$${(v.estimated_waste_usd_monthly || 0).toFixed(2)} / month`;
  }

  // Create a Finding Card component
  function createFindingCard(finding) {
    const card = document.createElement('details');
    const sev = (finding.severity || 'info').toLowerCase();
    card.className = `finding-card ${sev}`;

    const sevConf = SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.info;
    const cert = (finding.proof && finding.proof.certainty ? finding.proof.certainty : 'derived').toLowerCase();
    const certConf = CERTAINTY_CONFIG[cert] || CERTAINTY_CONFIG.derived;

    const summary = document.createElement('summary');
    summary.className = 'finding-summary';
    summary.tabIndex = 0;

    const titleGroup = document.createElement('div');
    titleGroup.className = 'finding-title-group';

    const sevBadge = document.createElement('span');
    sevBadge.className = `badge ${sevConf.colorClass}`;
    sevBadge.textContent = `${sevConf.glyph} ${sevConf.text}`;

    const titleText = document.createElement('span');
    titleText.textContent = finding.what || finding.id;

    titleGroup.appendChild(sevBadge);
    titleGroup.appendChild(titleText);

    const rightGroup = document.createElement('div');
    rightGroup.style.display = 'flex';
    rightGroup.style.alignItems = 'center';
    rightGroup.style.gap = '8px';

    const certBadge = document.createElement('span');
    certBadge.className = `badge ${certConf.colorClass}`;
    certBadge.textContent = `${certConf.glyph} ${certConf.text}`;

    rightGroup.appendChild(certBadge);
    summary.appendChild(titleGroup);
    summary.appendChild(rightGroup);

    // Disclosure Quad: What / So What / Now What / Proof
    const details = document.createElement('div');
    details.className = 'finding-details';

    // What
    const secWhat = document.createElement('div');
    secWhat.className = 'quad-section';
    secWhat.innerHTML = `<span class="quad-label">WHAT</span><div>${finding.what || 'No explanation'}</div>`;

    // So What
    const secSoWhat = document.createElement('div');
    secSoWhat.className = 'quad-section';
    secSoWhat.innerHTML = `<span class="quad-label">SO WHAT</span><div style="color: var(--peach);">${finding.so_what || 'N/A'}</div>`;

    // Now What
    const secNowWhat = document.createElement('div');
    secNowWhat.className = 'quad-section';
    const action = (finding.now_what && finding.now_what.action) || 'Review configuration';
    const risk = (finding.now_what && finding.now_what.risk_level) || 'none';
    const rev = (finding.now_what && finding.now_what.reversible) ? 'Reversible: YES' : 'Reversible: NO';
    secNowWhat.innerHTML = `<span class="quad-label">NOW WHAT (RECOMMENDATION)</span>
      <div>${action}</div>
      <div style="font-size: 12px; color: var(--dim); margin-top: 4px;">Risk Level: ${risk.toUpperCase()} · ${rev}</div>`;

    // Proof
    const secProof = document.createElement('div');
    secProof.className = 'quad-section';
    let proofHTML = `<span class="quad-label">PROOF & EVIDENCE</span>`;
    if (finding.proof && finding.proof.evidence && finding.proof.evidence.length > 0) {
      proofHTML += `<ul style="list-style: none; padding-left: 0; font-size: 12px; color: var(--cyan);">`;
      finding.proof.evidence.forEach(ev => {
        proofHTML += `<li>└─ [${ev.source}] ${ev.description}</li>`;
      });
      proofHTML += `</ul>`;
    } else {
      proofHTML += `<div style="font-size: 12px; color: var(--dim);">Deterministic graph rule evaluation.</div>`;
    }
    secProof.innerHTML = proofHTML;

    details.appendChild(secWhat);
    details.appendChild(secSoWhat);
    details.appendChild(secNowWhat);
    details.appendChild(secProof);

    card.appendChild(summary);
    card.appendChild(details);
    return card;
  }

  // Fetch Findings and populate Danger/Waste panels
  async function refreshFindings() {
    try {
      const res = await fetch('/api/v1/findings', { headers: getHeaders() });
      if (!res.ok) return;
      const findings = await res.json();

      el.dangerList.innerHTML = '';
      el.wasteList.innerHTML = '';

      if (!findings || findings.length === 0) {
        el.dangerList.innerHTML = '<div style="color: var(--mint);">[✓] No danger or high-severity exposures identified.</div>';
        el.wasteList.innerHTML = '<div style="color: var(--mint);">[✓] No idle or wasteful resources identified.</div>';
        return;
      }

      let dangerCount = 0;
      let wasteCount = 0;

      findings.forEach(f => {
        const sev = (f.severity || '').toLowerCase();
        const cat = (f.category || '').toLowerCase();

        if (sev === 'critical' || sev === 'high' || cat === 'security') {
          el.dangerList.appendChild(createFindingCard(f));
          dangerCount++;
        }
        if (cat === 'cost' || cat === 'efficiency' || sev === 'medium' || sev === 'low') {
          el.wasteList.appendChild(createFindingCard(f));
          wasteCount++;
        }
      });

      if (dangerCount === 0) {
        el.dangerList.innerHTML = '<div style="color: var(--mint);">[✓] No security vulnerabilities or dangerous listeners found.</div>';
      }
      if (wasteCount === 0) {
        el.wasteList.innerHTML = '<div style="color: var(--mint);">[✓] Resource consumption is compact and proportional.</div>';
      }
    } catch (err) {
      console.error('failed fetching findings:', err);
    }
  }

  // Fetch Host & Sensor identity
  async function refreshPulse() {
    try {
      const res = await fetch('/api/v1/observations/host', { headers: getHeaders() });
      if (!res.ok) return;
      const obs = await res.json();
      if (obs && obs.data) {
        const d = obs.data;
        if (d.hostname) el.pulseHost.textContent = d.hostname;
        if (d.kernel) el.pulseKernel.textContent = d.kernel;
        if (d.uptime_seconds) el.pulseUptime.textContent = formatDuration(d.uptime_seconds);
      }
    } catch (err) {
      console.error('failed fetching pulse:', err);
    }
  }

  // Fetch Changes diff from /api/v1/changes
  async function refreshChanges() {
    try {
      const res = await fetch('/api/v1/changes', { headers: getHeaders() });
      if (!res.ok) return;
      const cs = await res.json();
      el.changesList.innerHTML = '';

      if (!cs.changes || cs.changes.length === 0) {
        el.changesList.innerHTML = `
          <div style="color: var(--dim); font-size: 12px; line-height: 1.6;">
            <div>[·] First baseline snapshot captured.</div>
            <div>[·] Provenance graph differential tracking active.</div>
            <div style="color: var(--mint); margin-top: 4px;">${cs.summary || 'History builds over time.'}</div>
          </div>
        `;
        return;
      }

      const badge = document.getElementById('changes-badge');
      if (badge) {
        badge.textContent = `${cs.total_changes} CHANGES`;
        badge.className = cs.total_changes > 0 ? 'badge badge-peach' : 'badge badge-cyan';
      }

      cs.changes.slice(0, 8).forEach(ch => {
        const item = document.createElement('div');
        item.style.fontSize = '12px';
        item.style.padding = '6px';
        item.style.borderBottom = '1px dashed var(--panel-border)';
        item.style.backgroundColor = '#131620';

        let glyph = '[·]';
        let color = 'var(--cyan)';
        if (ch.kind === 'newly_exposed') { glyph = '[▲]'; color = 'var(--rose)'; }
        else if (ch.kind === 'new_manual_binary') { glyph = '[!]'; color = 'var(--peach)'; }
        else if (ch.kind === 'version_changed') { glyph = '[≈]'; color = 'var(--lavender)'; }
        else if (ch.kind === 'new_listener') { glyph = '[●]'; color = 'var(--mint)'; }

        item.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: baseline;">
            <span style="color: ${color}; font-weight: bold;">${glyph} ${ch.kind.toUpperCase()}</span>
            <span style="color: var(--dim);">${new Date(ch.timestamp).toLocaleTimeString()}</span>
          </div>
          <div style="margin-top: 2px; color: var(--text);">${ch.description}</div>
          ${ch.probable_cause ? `<div style="color: var(--dim); font-size: 11px;">Cause: ${ch.probable_cause}</div>` : ''}
        `;
        el.changesList.appendChild(item);
      });
    } catch (err) {
      console.error('failed fetching changes:', err);
    }
  }

  // Fetch Forecasts and render sparklines
  async function refreshForecasts() {
    try {
      const res = await fetch('/api/v1/forecasts', { headers: getHeaders() });
      if (!res.ok) return;
      const forecasts = await res.json();
      const sparkContainer = document.getElementById('forecast-sparklines');
      if (!sparkContainer || !forecasts || forecasts.length === 0) return;

      sparkContainer.innerHTML = '';
      forecasts.slice(0, 4).forEach(f => {
        const line = document.createElement('div');
        let statusColor = 'var(--cyan)';
        let statusText = f.state;
        if (f.state === 'not_enough_data') {
          statusColor = 'var(--dim)';
          statusText = 'learning baseline...';
        } else if (f.state === 'exhaustion_risk') {
          statusColor = 'var(--rose)';
          statusText = `exhaustion in ${Math.round(f.time_to_exhaustion / 3600000000000)}h`;
        } else if (f.is_leak) {
          statusColor = 'var(--peach)';
          statusText = 'potential leak detected';
        }

        const sparklineChars = [' ', '▂', '▃', '▄', '▅', '▆', '▇'];
        const spark = f.is_leak ? '[ ▂▃▄▅▆▇]' : '[ ▂▄▅▄▅▅]';

        line.innerHTML = `<span style="color: var(--dim);">${f.resource.toUpperCase()} (${f.target}):</span> ${spark} <span style="color: ${statusColor};">${statusText}</span>`;
        sparkContainer.appendChild(line);
      });
    } catch (err) {
      console.error('failed fetching forecasts:', err);
    }
  }

  // Fetch Initial Verdict
  async function refreshVerdict() {
    try {
      const res = await fetch('/api/v1/verdict', { headers: getHeaders() });
      if (!res.ok) return;
      const v = await res.json();
      renderVerdict(v);
    } catch (err) {
      console.error('failed fetching verdict:', err);
    }
  }

  // SSE Real-Time Stream via fetch streaming with Authorization header
  let streamAbortController = null;

  async function initSSE() {
    if (streamAbortController) {
      streamAbortController.abort();
    }
    streamAbortController = new AbortController();

    try {
      const res = await fetch('/api/v1/stream', {
        headers: getHeaders(),
        signal: streamAbortController.signal
      });

      if (!res.ok) {
        el.pulseDot.className = 'stale-indicator';
        el.liveStatusText.textContent = '[!] Auth/Stream Error';
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop(); // keep trailing partial chunk

        for (const block of lines) {
          const parts = block.split('\n');
          let eventType = 'message';
          let eventData = '';
          for (const line of parts) {
            if (line.startsWith('event:')) {
              eventType = line.slice(6).trim();
            } else if (line.startsWith('data:')) {
              eventData = line.slice(5).trim();
            }
          }
          if (eventType === 'verdict' && eventData) {
            try {
              const v = JSON.parse(eventData);
              renderVerdict(v);
            } catch (err) {
              console.error('failed parsing streamed verdict:', err);
            }
          }
        }
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        el.pulseDot.className = 'stale-indicator';
        el.liveStatusText.textContent = '[!] Reconnecting...';
        setTimeout(initSSE, 3000);
      }
    }
  }

  // Dependencies Topology Map
  async function refreshDependencies() {
    try {
      const res = await fetch('/api/v1/dependencies', { headers: getHeaders() });
      if (!res.ok) return;
      const deps = await res.json();
      const mapEl = document.getElementById('deps-ascii-map');
      if (mapEl && deps.ascii_map) {
        mapEl.textContent = deps.ascii_map;
      }
    } catch (err) {
      console.error('failed fetching dependencies:', err);
    }
  }

  // Populate Blast Radius selector with current graph nodes
  async function refreshBlastRadiusNodes() {
    try {
      const res = await fetch('/api/v1/graph', { headers: getHeaders() });
      if (!res.ok) return;
      const graphData = await res.json();
      const sel = document.getElementById('blast-select');
      if (!sel || !graphData || !graphData.nodes) return;

      const currentVal = sel.value;
      sel.innerHTML = '<option value="">-- Choose node to compute downstream impact --</option>';

      graphData.nodes.forEach(n => {
        if (n.type === 'service' || n.type === 'port' || n.type === 'process' || n.type === 'file') {
          const opt = document.createElement('option');
          opt.value = n.id;
          opt.textContent = `[${n.type.toUpperCase()}] ${n.label}`;
          sel.appendChild(opt);
        }
      });
      if (currentVal) sel.value = currentVal;
    } catch (err) {
      console.error('failed fetching graph for blast radius:', err);
    }
  }

  // Calculate and render Blast Radius for selected node
  async function calculateBlastRadius() {
    const sel = document.getElementById('blast-select');
    if (!sel || !sel.value) return;

    try {
      const res = await fetch(`/api/v1/blastradius/${encodeURIComponent(sel.value)}`, { headers: getHeaders() });
      if (!res.ok) return;
      const rep = await res.json();

      const badge = document.getElementById('blast-verdict-badge');
      const sum = document.getElementById('blast-result-summary');
      const reasonsEl = document.getElementById('blast-reasons');
      const listEl = document.getElementById('blast-impacted-list');

      let badgeClass = 'badge-mint';
      let glyph = '[✓]';
      if (rep.verdict === 'DANGEROUS') { badgeClass = 'badge-rose'; glyph = '[▲]'; }
      else if (rep.verdict === 'CAREFUL') { badgeClass = 'badge-peach'; glyph = '[!]'; }

      badge.className = `badge ${badgeClass}`;
      badge.textContent = `${glyph} ${rep.verdict}`;

      sum.textContent = rep.verdict_summary;
      reasonsEl.innerHTML = (rep.reasons || []).map(r => `<div>└─ ${r}</div>`).join('');

      listEl.innerHTML = '';
      if (!rep.impacted_list || rep.impacted_list.length === 0) {
        listEl.innerHTML = '<div style="color: var(--mint);">[✓] No downstream dependencies or outage risks identified.</div>';
      } else {
        rep.impacted_list.forEach(item => {
          const row = document.createElement('div');
          row.style.fontSize = '12px';
          row.style.display = 'flex';
          row.style.justifyContent = 'space-between';
          row.style.borderBottom = '1px dashed var(--panel-border)';
          row.style.padding = '3px 0';

          let sevClass = 'badge-cyan';
          if (item.impact_level === 'critical') sevClass = 'badge-rose';
          else if (item.impact_level === 'high') sevClass = 'badge-peach';

          row.innerHTML = `
            <span><strong style="color: var(--text);">[${item.node_type}]</strong> ${item.label} (${item.reason})</span>
            <span class="badge ${sevClass}">${item.impact_level.toUpperCase()}</span>
          `;
          listEl.appendChild(row);
        });
      }
    } catch (err) {
      console.error('failed calculating blast radius:', err);
    }
  }

  const blastBtn = document.getElementById('blast-inspect-btn');
  if (blastBtn) {
    blastBtn.addEventListener('click', calculateBlastRadius);
  }

  function refreshAll() {
    refreshVerdict();
    refreshFindings();
    refreshPulse();
    refreshChanges();
    refreshForecasts();
    refreshDependencies();
    refreshBlastRadiusNodes();
  }

  // Initial startup
  handleRoute();
  refreshAll();
  initSSE();

  // Periodic poll fallback every 5s for findings, pulse, changes & forecasts
  setInterval(() => {
    refreshFindings();
    refreshPulse();
    refreshChanges();
    refreshForecasts();
    refreshDependencies();
  }, 5000);

})();


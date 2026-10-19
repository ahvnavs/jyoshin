// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

(function () {
  'use strict';

  let authToken = localStorage.getItem('kazeshini_token') || '';
  let eventSource = null;
  let lastSuccessfulFetch = Date.now();
  let checksCache = [];
  let filterQuery = '';

  function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // DOM Elements cache
  const el = {
    verdictBanner: document.getElementById('verdict-banner'),
    verdictLead: document.getElementById('verdict-lead'),
    riskScore: document.getElementById('risk-score'),
    riskBadge: document.getElementById('risk-badge'),
    identityLine: document.getElementById('identity-line'),
    topHostBadge: document.getElementById('top-host-badge'),
    topVerdictBadge: document.getElementById('top-verdict-badge'),
    topCoverageBadge: document.getElementById('top-coverage-badge'),
    pulseDot: document.getElementById('pulse-dot'),
    liveStatusText: document.getElementById('live-status-text'),
    lastUpdated: document.getElementById('last-updated'),
    pulseHost: document.getElementById('pulse-host'),
    pulseKernel: document.getElementById('pulse-kernel'),
    pulseUptime: document.getElementById('pulse-uptime'),
    topFindingsList: document.getElementById('top-findings-list'),
    topFindingsCount: document.getElementById('top-findings-count'),
    dangerList: document.getElementById('danger-list'),
    dangerCount: document.getElementById('danger-count'),
    wasteMonthly: document.getElementById('waste-monthly'),
    wasteList: document.getElementById('waste-list'),
    changesList: document.getElementById('changes-list'),
    quickFilter: document.getElementById('quick-filter'),
    helpBtn: document.getElementById('help-btn'),
    helpModal: document.getElementById('help-modal'),
    helpCloseBtn: document.getElementById('help-close-btn'),
    commandPaletteModal: document.getElementById('command-palette-modal'),
    paletteInput: document.getElementById('palette-input'),
    paletteResults: document.getElementById('palette-results'),
    authModal: document.getElementById('auth-modal'),
    authInput: document.getElementById('auth-token-input'),
    authSubmit: document.getElementById('auth-token-submit'),
    authCancel: document.getElementById('auth-token-cancel'),
    tokenBtn: document.getElementById('token-button'),
    triageResultPanel: document.getElementById('triage-result-panel'),
    triageResultTitle: document.getElementById('triage-result-title'),
    triageResultContent: document.getElementById('triage-result-content'),
    triageCloseBtn: document.getElementById('triage-close-btn'),
    activityTbody: document.getElementById('activity-tbody'),
    refreshActivityBtn: document.getElementById('refresh-activity-btn'),
  };

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

  function getHeaders() {
    const h = { 'Accept': 'application/json' };
    if (authToken) {
      h['Authorization'] = `Bearer ${authToken}`;
    }
    return h;
  }

  function formatDuration(seconds) {
    if (!seconds || seconds <= 0) return '0s';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    if (d > 0) return `${d}d ${h}m`;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  // Stale state supervisor check (if > 60s without updates, show UNKNOWN, never healthy)
  function checkStaleness() {
    const elapsedMs = Date.now() - lastSuccessfulFetch;
    if (elapsedMs > 60000) {
      if (el.topVerdictBadge) {
        el.topVerdictBadge.className = 'badge badge-rose';
        el.topVerdictBadge.textContent = '[?] UNKNOWN (STALE)';
      }
      if (el.liveStatusText) {
        el.liveStatusText.textContent = '[?] STALE (>60s)';
        el.liveStatusText.style.color = 'var(--peach)';
      }
      if (el.pulseDot) {
        el.pulseDot.style.color = 'var(--peach)';
      }
    }
  }

  setInterval(checkStaleness, 5000);

  // Left Rail View Switching & Hash Routing (Exact 11 Domains)
  const views = [
    'overview', 'software', 'services', 'network', 'storage',
    'security', 'logs', 'platforms', 'drift', 'audit-log', 'settings'
  ];

  function switchView(target) {
    views.forEach(v => {
      const panel = document.getElementById(`view-${v}`);
      const navItem = document.getElementById(`nav-${v}`);
      if (panel) {
        panel.style.display = (v === target) ? 'block' : 'none';
      }
      if (navItem) {
        if (v === target) navItem.classList.add('active');
        else navItem.classList.remove('active');
      }
    });

    if (target === 'drift') {
      refreshDesiredView();
    } else if (target === 'software') {
      refreshSoftwareView();
    } else if (target === 'platforms') {
      refreshPlatformsView();
    } else if (target === 'audit-log') {
      refreshActivityLog();
    } else if (['services', 'network', 'storage', 'security', 'logs'].includes(target)) {
      renderDomainChecks(target);
    }
  }

  function handleRoute() {
    let hash = window.location.hash.replace(/^#/, '');
    if (!views.includes(hash)) {
      hash = 'overview';
    }
    switchView(hash);
  }

  window.addEventListener('hashchange', handleRoute);

  // Auth Handling
  if (el.tokenBtn) {
    el.tokenBtn.addEventListener('click', () => {
      el.authInput.value = authToken;
      el.authModal.style.display = 'flex';
      el.authInput.focus();
    });
  }

  const settingsTokenBtn = document.getElementById('settings-token-btn');
  if (settingsTokenBtn) {
    settingsTokenBtn.addEventListener('click', () => {
      if (el.tokenBtn) el.tokenBtn.click();
    });
  }

  const petOnBtn = document.getElementById('settings-pet-on');
  if (petOnBtn) {
    petOnBtn.addEventListener('click', () => {
      if (window.Tsumuji) window.Tsumuji.set(true);
    });
  }

  const petOffBtn = document.getElementById('settings-pet-off');
  if (petOffBtn) {
    petOffBtn.addEventListener('click', () => {
      if (window.Tsumuji) window.Tsumuji.set(false);
    });
  }

  if (el.authCancel) {
    el.authCancel.addEventListener('click', () => {
      el.authModal.style.display = 'none';
    });
  }

  if (el.authSubmit) {
    el.authSubmit.addEventListener('click', () => {
      authToken = el.authInput.value.trim();
      localStorage.setItem('kazeshini_token', authToken);
      el.authModal.style.display = 'none';
      refreshAll();
    });
  }

  // Modals (Help & Command Palette)
  if (el.helpBtn) {
    el.helpBtn.addEventListener('click', () => {
      el.helpModal.style.display = 'flex';
    });
  }
  if (el.helpCloseBtn) {
    el.helpCloseBtn.addEventListener('click', () => {
      el.helpModal.style.display = 'none';
    });
  }

  function openCommandPalette() {
    el.commandPaletteModal.style.display = 'flex';
    el.paletteInput.value = '';
    renderPaletteResults('');
    el.paletteInput.focus();
  }

  function closeModals() {
    if (el.commandPaletteModal) el.commandPaletteModal.style.display = 'none';
    if (el.helpModal) el.helpModal.style.display = 'none';
    if (el.authModal) el.authModal.style.display = 'none';
  }

  const commandsList = [
    { name: 'Overview', desc: 'Jump to Overview verdict screen', action: () => { window.location.hash = '#overview'; } },
    { name: 'Software', desc: 'Jump to Software inventory and packages', action: () => { window.location.hash = '#software'; } },
    { name: 'Services', desc: 'Jump to Services and process health checks', action: () => { window.location.hash = '#services'; } },
    { name: 'Network', desc: 'Jump to Network sockets and routing checks', action: () => { window.location.hash = '#network'; } },
    { name: 'Storage', desc: 'Jump to Storage and filesystem checks', action: () => { window.location.hash = '#storage'; } },
    { name: 'Security', desc: 'Jump to Security and authentication checks', action: () => { window.location.hash = '#security'; } },
    { name: 'Logs', desc: 'Jump to Logs and agent stream checks', action: () => { window.location.hash = '#logs'; } },
    { name: 'Platforms', desc: 'Jump to Platform signature catalog', action: () => { window.location.hash = '#platforms'; } },
    { name: 'Drift', desc: 'Jump to Desired vs actual drift audit', action: () => { window.location.hash = '#drift'; } },
    { name: 'Audit Log', desc: 'Jump to Audit Log execution history', action: () => { window.location.hash = '#audit-log'; } },
    { name: 'Settings', desc: 'Jump to node configuration and auth', action: () => { window.location.hash = '#settings'; } },
    { name: ':pet off', desc: 'Turn off wind-wisp idle pet', action: () => { if (window.Tsumuji) window.Tsumuji.set(false); } },
    { name: ':pet on', desc: 'Turn on wind-wisp idle pet', action: () => { if (window.Tsumuji) window.Tsumuji.set(true); } },
    { name: 'Token', desc: 'Configure API bearer token', action: () => { el.tokenBtn.click(); } },
    { name: 'Refresh', desc: 'Trigger immediate refresh', action: () => { refreshAll(); } },
  ];

  function renderPaletteResults(query) {
    if (!el.paletteResults) return;
    el.paletteResults.innerHTML = '';
    const q = query.toLowerCase().trim();

    const matches = commandsList.filter(c => c.name.toLowerCase().includes(q) || c.desc.toLowerCase().includes(q));
    if (matches.length === 0) {
      el.paletteResults.innerHTML = '<div style="padding: 8px; color: var(--dim);">No matching commands.</div>';
      return;
    }

    matches.forEach((c, idx) => {
      const item = document.createElement('div');
      item.className = `palette-item ${idx === 0 ? 'selected' : ''}`;
      item.innerHTML = `<span><strong>${c.name}</strong></span><span style="font-size: 11px; color: var(--dim);">${c.desc}</span>`;
      item.addEventListener('click', () => {
        closeModals();
        c.action();
      });
      el.paletteResults.appendChild(item);
    });
  }

  if (el.paletteInput) {
    el.paletteInput.addEventListener('input', (e) => {
      renderPaletteResults(e.target.value);
    });
    el.paletteInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const first = el.paletteResults.querySelector('.palette-item');
        if (first) first.click();
      }
    });
  }

  // Keyboard Navigation Listeners
  window.addEventListener('keydown', (e) => {
    // If typing in input, ignore global shortcuts except Escape and Palette Enter
    const inInput = e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA';

    if (e.key === 'Escape') {
      closeModals();
      return;
    }

    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      openCommandPalette();
      return;
    }

    if (inInput) return;

    if (e.key === '/') {
      e.preventDefault();
      if (el.quickFilter) {
        el.quickFilter.focus();
        el.quickFilter.select();
      }
    } else if (e.key === '?') {
      e.preventDefault();
      if (el.helpModal) el.helpModal.style.display = 'flex';
    } else if (e.key === 'r' || e.key === 'R') {
      e.preventDefault();
      refreshAll();
    }
  });

  // Quick Filter listener
  if (el.quickFilter) {
    el.quickFilter.addEventListener('input', (e) => {
      filterQuery = e.target.value.toLowerCase().trim();
      const currentHash = window.location.hash.replace(/^#/, '');
      if (['services', 'network', 'storage', 'security', 'logs'].includes(currentHash)) {
        renderDomainChecks(currentHash);
      }
    });
  }

  // Render Check Card (Canonical 8-field layout)
  function renderCheckCard(check, resultData) {
    const card = document.createElement('details');
    const status = (resultData ? resultData.status : 'unknown').toLowerCase();
    card.className = `check-card ${status}`;

    const summary = document.createElement('summary');
    summary.className = 'check-summary';

    let glyph = '[·]';
    let badgeClass = 'badge-dim';
    let statusText = 'READY';

    if (resultData) {
      switch (resultData.status) {
        case 'OK': glyph = '[✓]'; badgeClass = 'badge-mint'; statusText = 'OK'; break;
        case 'WARN': glyph = '[!]'; badgeClass = 'badge-peach'; statusText = 'WARN'; break;
        case 'CRIT': glyph = '[▲]'; badgeClass = 'badge-rose'; statusText = 'CRIT'; break;
        case 'NOT_APPLICABLE': glyph = '[·]'; badgeClass = 'badge-dim'; statusText = 'N/A'; break;
        default: glyph = '[?]'; badgeClass = 'badge-cyan'; statusText = 'UNKNOWN'; break;
      }
    }

    const titleGroup = document.createElement('div');
    titleGroup.className = 'check-title-group';
    titleGroup.innerHTML = `
      <span class="badge ${badgeClass}">${glyph} ${statusText}</span>
      <strong>${check.title}</strong>
      <span style="font-size: 12px; color: var(--dim); margin-left: 8px;">${resultData ? resultData.summary_plain : check.description}</span>
    `;

    const actions = document.createElement('div');
    actions.className = 'check-actions';

    const runBtn = document.createElement('button');
    runBtn.className = 'btn';
    runBtn.textContent = 'Run check';
    runBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      runBtn.textContent = 'Running...';
      runBtn.disabled = true;
      try {
        const res = await fetch(`/api/v1/checks/${encodeURIComponent(check.id)}/run`, {
          method: 'POST',
          headers: getHeaders(),
        });
        if (res.ok) {
          const runRes = await res.json();
          const parent = card.parentElement;
          const newCard = renderCheckCard(check, runRes);
          newCard.open = true;
          parent.replaceChild(newCard, card);
        } else {
          runBtn.textContent = 'Error';
        }
      } catch (err) {
        runBtn.textContent = 'Failed';
      } finally {
        runBtn.disabled = false;
      }
    });

    actions.appendChild(runBtn);
    summary.appendChild(titleGroup);
    summary.appendChild(actions);
    card.appendChild(summary);

    // Expandable Details (8 Canonical Fields)
    const details = document.createElement('div');
    details.className = 'check-details';

    const resultSentence = resultData && resultData.explain_levels && resultData.explain_levels[0] ? resultData.explain_levels[0] : (resultData ? resultData.summary_plain : check.description);
    const impactSentence = resultData && resultData.explain_levels && resultData.explain_levels[1] ? resultData.explain_levels[1] : 'Host operation impact evaluated deterministically.';
    const recSentence = resultData && resultData.explain_levels && resultData.explain_levels[2] ? resultData.explain_levels[2] : (resultData && resultData.recommendation ? resultData.recommendation : 'No immediate remediation required.');
    const confidenceText = resultData ? (resultData.certainty || 'OBSERVED') : 'OBSERVED';
    const evidenceList = resultData && resultData.evidence ? resultData.evidence : [];

    details.innerHTML = `
      <div class="check-read-banner">
        <span>ℹ This only reads; it changes nothing. Read-only host safety guarantee.</span>
      </div>
      <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 8px;">
        <div><strong style="color: var(--dim); font-size: 11px;">[RESULT]</strong> <div>${resultSentence}</div></div>
        <div><strong style="color: var(--peach); font-size: 11px;">[IMPACT]</strong> <div>${impactSentence}</div></div>
        <div><strong style="color: var(--mint); font-size: 11px;">[RECOMMENDED ACTION (SHOWN ONLY, NEVER RUN)]</strong> <div>${recSentence}</div></div>
      </div>

      ${resultData && resultData.equivalent_command ? `
        <div style="margin-top: 6px;">
          <div style="font-size: 11px; color: var(--dim);">EQUIVALENT SHELL INSPECTION:</div>
          <code style="background-color: #07080b; color: var(--cyan); padding: 4px 8px; display: block; border: 1px solid var(--panel-border);">${resultData.equivalent_command}</code>
        </div>
      ` : ''}

      <div style="margin-top: 6px;">
        <div style="font-size: 11px; color: var(--dim);">CONFIDENCE & CERTAINTY: <span style="color: var(--mint); font-weight: bold;">[✓] ${confidenceText.toUpperCase()}</span></div>
        ${evidenceList.length > 0 ? `
          <ul style="list-style: none; padding-left: 0; font-size: 12px; color: var(--cyan); margin-top: 4px;">
            ${evidenceList.map(ev => `<li>└─ [${ev.source}] ${ev.description}</li>`).join('')}
          </ul>
        ` : '<div style="font-size: 11px; color: var(--dim);">Direct kernel /proc /sys fact provenance.</div>'}
      </div>

      ${resultData && resultData.raw_redacted ? `
        <details style="margin-top: 6px;">
          <summary style="cursor: pointer; font-size: 11px; color: var(--dim);">View Redacted Raw Output</summary>
          <pre style="background-color: #06070a; color: var(--dim); padding: 8px; font-size: 11px; overflow-x: auto; max-height: 200px; margin-top: 4px; border: 1px solid var(--panel-border);">${resultData.raw_redacted}</pre>
        </details>
      ` : ''}
    `;

    card.appendChild(details);
    return card;
  }

  // Load and Render Domain Checks
  async function loadChecks() {
    try {
      const res = await fetch('/api/v1/checks', { headers: getHeaders() });
      if (res.ok) {
        checksCache = await res.json();
        updateDomainCounts();
      }
    } catch (err) {
      console.error('failed fetching checks list:', err);
    }
  }

  function updateDomainCounts() {
    const domains = ['services', 'network', 'storage', 'security', 'logs'];
    domains.forEach(d => {
      const elCount = document.getElementById(`count-${d}`);
      if (elCount) {
        const count = checksCache.filter(c => (c.domain || '').toLowerCase() === d || (c.role || '').toLowerCase() === d).length;
        elCount.textContent = count;
      }
    });
  }

  function renderDomainChecks(domain) {
    const container = document.getElementById(`checks-list-${domain}`);
    if (!container) return;
    container.innerHTML = '';

    const dTarget = domain.toLowerCase();
    const domainChecks = checksCache.filter(c => (c.domain || '').toLowerCase() === dTarget || (c.role || '').toLowerCase() === dTarget);
    const filtered = filterQuery ? domainChecks.filter(c => c.title.toLowerCase().includes(filterQuery) || c.id.toLowerCase().includes(filterQuery) || c.description.toLowerCase().includes(filterQuery)) : domainChecks;

    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state">No checks found for this domain matching filter criteria.</div>';
      return;
    }

    filtered.forEach(c => {
      container.appendChild(renderCheckCard(c, null));
    });
  }

  // Activity Log
  async function refreshActivityLog() {
    if (!el.activityTbody) return;
    try {
      const res = await fetch('/api/v1/activity', { headers: getHeaders() });
      if (!res.ok) return;
      const entries = await res.json();
      el.activityTbody.innerHTML = '';

      const countEl = document.getElementById('count-audit-log');
      if (countEl) countEl.textContent = entries.length;

      if (entries.length === 0) {
        el.activityTbody.innerHTML = '<tr><td colspan="6" class="empty-state" style="text-align: center;">No checks executed yet.</td></tr>';
        return;
      }

      entries.forEach(entry => {
        const tr = document.createElement('tr');
        let stClass = 'badge-mint';
        if (entry.status === 'CRIT') stClass = 'badge-rose';
        else if (entry.status === 'WARN') stClass = 'badge-peach';

        const tStr = new Date(entry.timestamp).toLocaleTimeString();
        tr.innerHTML = `
          <td>${tStr}</td>
          <td><strong style="color: var(--cyan);">${entry.check_id}</strong></td>
          <td>${entry.domain || entry.role || 'general'}</td>
          <td><span class="badge ${stClass}">${entry.status}</span></td>
          <td>${entry.token_holder || 'system'}</td>
          <td>${entry.summary}</td>
        `;
        el.activityTbody.appendChild(tr);
      });
    } catch (err) {
      console.error('failed refreshing activity log:', err);
    }
  }

  if (el.refreshActivityBtn) {
    el.refreshActivityBtn.addEventListener('click', refreshActivityLog);
  }

  // Guided Triage Picker
  const triageButtons = document.querySelectorAll('.triage-btn');
  triageButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
      const trg = btn.getAttribute('data-triage');
      if (!trg) return;
      if (el.triageResultPanel) {
        el.triageResultPanel.style.display = 'block';
      }
      if (el.triageResultTitle) {
        el.triageResultTitle.textContent = `[?] GUIDED TRIAGE: ${btn.textContent.trim().toUpperCase()}`;
      }
      if (el.triageResultContent) {
        el.triageResultContent.innerHTML = '<div style="color: var(--dim);">Running targeted diagnostic checks...</div>';
      }

      try {
        const checksToRun = [];
        if (trg === 'slow') checksToRun.push('cpu-memory', 'disk-inodes', 'app-health', 'time-sync');
        else if (trg === 'service-down') checksToRun.push('failed-services', 'app-health', 'app-logs', 'service-permissions');
        else if (trg === 'cant-connect') checksToRun.push('listening-ports', 'dns-config', 'interfaces-routes', 'app-health');
        else if (trg === 'disk-full') checksToRun.push('disk-inodes', 'container-storage', 'attached-storage', 'app-logs');
        else if (trg === 'looks-hacked') checksToRun.push('users-sudo', 'ssh-settings', 'auth-logs', 'listening-ports');

        if (el.triageResultContent) el.triageResultContent.innerHTML = '';
        for (const cid of checksToRun) {
          const cDef = checksCache.find(c => c.id === cid) || { id: cid, title: cid, domain: 'services', description: cid };
          const res = await fetch(`/api/v1/checks/${encodeURIComponent(cid)}/run`, {
            method: 'POST',
            headers: getHeaders(),
          });
          if (res.ok) {
            const data = await res.json();
            const card = renderCheckCard(cDef, data);
            card.open = true;
            if (el.triageResultContent) el.triageResultContent.appendChild(card);
          }
        }
      } catch (err) {
        if (el.triageResultContent) el.triageResultContent.innerHTML = `<div style="color: var(--rose);">Guided triage failed: ${err.message}</div>`;
      }
    });
  });

  if (el.triageCloseBtn) {
    el.triageCloseBtn.addEventListener('click', () => {
      if (el.triageResultPanel) el.triageResultPanel.style.display = 'none';
    });
  }

  // Refresh Verdict
  async function refreshVerdict() {
    try {
      const res = await fetch('/api/v1/verdict', { headers: getHeaders() });
      if (!res.ok) return;
      const v = await res.json();
      lastSuccessfulFetch = Date.now();

      updateVerdictUI(v);
      updateTopBar(v);
    } catch (err) {
      console.error('failed fetching verdict:', err);
    }
  }

  function updateTopBar(v) {
    if (el.topHostBadge && v.identity_line) {
      el.topHostBadge.innerHTML = `HOST: <span style="color: var(--cyan);">${escapeHTML(v.identity_line)}</span>`;
    }
    if (el.topVerdictBadge) {
      let bClass = 'badge-mint';
      let glyph = '[✓]';
      const label = v.state_label || 'HEALTHY';
      if (label === 'CRITICAL') { bClass = 'badge-rose'; glyph = '[▲]'; }
      else if (label === 'DEGRADED' || label === 'WARN' || label === 'MESSY') { bClass = 'badge-peach'; glyph = '[!]'; }
      else if (label === 'PARTIAL' || label === 'PARTIAL VISIBILITY' || label === 'UNKNOWN') { bClass = 'badge-lavender'; glyph = '[?]'; }

      el.topVerdictBadge.className = `badge ${bClass}`;
      el.topVerdictBadge.textContent = `${glyph} ${label}`;
    }
    if (el.lastUpdated) {
      el.lastUpdated.textContent = new Date().toLocaleTimeString();
    }
    if (el.liveStatusText) {
      el.liveStatusText.textContent = '[●] LIVE';
      el.liveStatusText.style.color = 'var(--mint)';
    }
    if (el.pulseDot) {
      el.pulseDot.style.color = 'var(--mint)';
    }
  }

  function updateVerdictUI(v) {
    if (el.verdictLead) {
      el.verdictLead.textContent = v.plain_verdict || 'Server is operating within normal parameters.';
    }
    const score = v.risk_score !== undefined ? v.risk_score : (v.chaos_index !== undefined ? v.chaos_index : 0);
    if (el.riskScore) {
      el.riskScore.textContent = score;
    }

    let badgeClass = 'badge-mint';
    let glyph = '[✓]';
    const label = v.state_label || 'HEALTHY';
    if (label === 'CRITICAL' || score >= 70) {
      badgeClass = 'badge-rose'; glyph = '[▲]';
    } else if (label === 'DEGRADED' || label === 'MESSY' || score >= 45) {
      badgeClass = 'badge-peach'; glyph = '[!]';
    } else if (label === 'PARTIAL VISIBILITY' || label === 'PARTIAL' || label === 'UNKNOWN') {
      badgeClass = 'badge-cyan'; glyph = '[?]';
    }

    if (el.riskBadge) {
      el.riskBadge.className = `badge ${badgeClass}`;
      el.riskBadge.textContent = `${glyph} ${label}`;
    }
    if (el.identityLine) {
      el.identityLine.textContent = `HOST: ${v.identity_line || 'Linux Server'}`;
    }

    if (el.dangerCount) {
      const totalRisks = (v.critical_findings || 0) + (v.high_findings || 0);
      el.dangerCount.textContent = `${totalRisks} ACTIVE`;
      el.dangerCount.className = totalRisks > 0 ? 'badge badge-rose' : 'badge badge-mint';
    }

    // Populate Risk Contributors
    if (el.dangerList) {
      const contribs = v.risk_contributors || v.chaos_contributors || [];
      if (contribs.length === 0) {
        el.dangerList.innerHTML = '<div class="empty-state">[✓] No active risk contributors identified.</div>';
      } else {
        el.dangerList.innerHTML = '';
        contribs.forEach(c => {
          const row = document.createElement('div');
          row.style.fontSize = '12px';
          row.style.display = 'flex';
          row.style.justifyContent = 'space-between';
          row.style.borderBottom = '1px dashed var(--panel-border)';
          row.style.padding = '4px 0';
          row.innerHTML = `
            <span><strong>${escapeHTML(c.title || c.source || c.label)}</strong>: ${escapeHTML(c.reason || '')}</span>
            <span class="badge badge-peach">+${c.weight || c.points || 0} pts</span>
          `;
          el.dangerList.appendChild(row);
        });
      }
    }
      el.dangerCount.className = totalRisks > 0 ? 'badge badge-rose' : 'badge badge-mint';
    }

    if (el.wasteMonthly) {
      el.wasteMonthly.textContent = `$${(v.estimated_waste_usd_monthly || 0).toFixed(2)} / month`;
    }
  }

  // Refresh Overview Summary & Coverage
  async function refreshOverviewSummary() {
    try {
      const res = await fetch('/api/v1/overview', { headers: getHeaders() });
      if (!res.ok) return;
      const b = await res.json();

      const badge = document.getElementById('coverage-badge');
      if (badge && b.coverage) {
        badge.textContent = `COVERAGE ${b.coverage.overall_coverage.toFixed(0)}%`;
        if (b.coverage.is_adequate) badge.className = 'badge badge-mint';
        else badge.className = 'badge badge-peach';
      }

      if (el.topCoverageBadge && b.coverage) {
        el.topCoverageBadge.textContent = `COVERAGE ${b.coverage.overall_coverage.toFixed(0)}%`;
        el.topCoverageBadge.className = b.coverage.is_adequate ? 'badge badge-mint' : 'badge badge-peach';
      }

      const content = document.getElementById('overview-summary-content');
      if (content) {
        content.innerHTML = `
          <div style="font-weight: bold; font-size: 14px; margin-bottom: 8px;">${escapeHTML(b.summary_sentence || '')}</div>
          <div style="display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--dim);">
            ${(b.bullet_points || []).map(bp => `<div>• ${escapeHTML(bp)}</div>`).join('')}
          </div>
          <div style="margin-top: 12px; font-size: 12px; color: var(--cyan); border-top: 1px dashed var(--panel-border); padding-top: 8px;">
            <div><strong>PROVENANCE & INTEGRITY:</strong> ${escapeHTML(b.untracked_surface || '')}</div>
            <div style="margin-top: 4px;"><strong>CAPACITY FORECAST:</strong> ${escapeHTML(b.exhaustion_headline || '')}</div>
          </div>
        `;
      }
    } catch (err) {
      console.error('failed fetching overview summary:', err);
    }
  }

  // Refresh Pulse
  async function refreshPulse() {
    try {
      const resHost = await fetch('/api/v1/observations/host', { headers: getHeaders() });
      if (resHost.ok) {
        const obs = await resHost.json();
        if (obs.items && obs.items.length > 0 && obs.items[0].data) {
          const d = obs.items[0].data;
          if (el.pulseHost) el.pulseHost.textContent = d.hostname || 'server';
          if (el.pulseKernel) el.pulseKernel.textContent = `${d.kernel_name || 'Linux'} ${d.kernel_release || ''}`;
          if (el.pulseUptime) el.pulseUptime.textContent = formatDuration(d.uptime_seconds);
        }
      }

      const resRes = await fetch('/api/v1/observations/resources', { headers: getHeaders() });
      if (resRes.ok) {
        const rObs = await resRes.json();
        if (rObs.items && rObs.items.length > 0 && rObs.items[0].data) {
          const r = rObs.items[0].data;
          const cpuVal = document.getElementById('meter-cpu-val');
          const cpuBar = document.getElementById('meter-cpu-bar');
          if (cpuVal && cpuBar) {
            cpuVal.textContent = `${r.load1 ? r.load1.toFixed(2) : '0.00'}`;
            cpuBar.style.width = `${Math.min(100, (r.load1 || 0) * 25)}%`;
          }

          const ramVal = document.getElementById('meter-ram-val');
          const ramBar = document.getElementById('meter-ram-bar');
          if (ramVal && ramBar) {
            const pct = Math.round((r.mem_usage_ratio || 0) * 100);
            ramVal.textContent = `${pct}%`;
            ramBar.style.width = `${pct}%`;
          }
        }
      }
    } catch (err) {
      console.error('failed fetching pulse data:', err);
    }
  }

  // Refresh Findings
  async function refreshFindings() {
    try {
      const res = await fetch('/api/v1/findings', { headers: getHeaders() });
      if (!res.ok) return;
      const findings = await res.json();

      if (el.topFindingsCount) {
        el.topFindingsCount.textContent = `${(findings || []).length} ACTIVE`;
      }

      if (el.topFindingsList) {
        el.topFindingsList.innerHTML = '';
        if (!findings || findings.length === 0) {
          el.topFindingsList.innerHTML = '<div class="empty-state">No critical or high severity findings detected on this host.</div>';
        } else {
          const top5 = findings.slice(0, 5);
          top5.forEach(f => {
            const cDef = checksCache.find(c => c.id === f.rule_id || c.id === f.id) || {
              id: f.id,
              title: f.title || f.what || f.id,
              description: f.so_what || f.what,
            };
            const mockRes = {
              status: f.severity === 'critical' ? 'CRIT' : (f.severity === 'high' ? 'WARN' : 'INFO'),
              summary_plain: f.what,
              explain_levels: [f.what, f.so_what, f.now_what ? f.now_what.action : ''],
              certainty: f.certainty || 'OBSERVED',
              evidence: f.evidence || [],
            };
            const card = renderCheckCard(cDef, mockRes);
            el.topFindingsList.appendChild(card);
          });
        }
      }
    } catch (err) {
      console.error('failed fetching findings:', err);
    }
  }

  // Topological Dependencies Map
  async function refreshDependencies() {
    try {
      const res = await fetch('/api/v1/dependencies', { headers: getHeaders() });
      if (!res.ok) return;
      const depMap = await res.json();
      const mapEl = document.getElementById('deps-ascii-map');
      if (!mapEl) return;

      let ascii = 'NODE IDENTIFIER           | DEPENDS ON               | DEPENDENTS (OUTAGES)\n';
      ascii += '--------------------------+--------------------------+-------------------------\n';

      for (const [id, rels] of Object.entries(depMap)) {
        const shortID = id.length > 24 ? id.substring(0, 21) + '...' : id;
        const deps = (rels.depends_on || []).join(', ') || 'none';
        const callers = (rels.dependents || []).join(', ') || 'none';
        ascii += `${shortID.padEnd(25)} | ${deps.padEnd(24)} | ${callers}\n`;
      }

      mapEl.textContent = ascii;
    } catch (err) {
      console.error('failed fetching dependencies:', err);
    }
  }

  // Blast Radius Analyzer
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

      if (badge) {
        badge.className = `badge ${badgeClass}`;
        badge.textContent = `${glyph} ${rep.verdict}`;
      }
      if (sum) sum.textContent = rep.verdict_summary;
      if (reasonsEl) {
        reasonsEl.innerHTML = (rep.reasons || []).map(r => `<div>└─ ${r}</div>`).join('');
      }

      if (listEl) {
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
      }
    } catch (err) {
      console.error('failed calculating blast radius:', err);
    }
  }

  const blastBtn = document.getElementById('blast-inspect-btn');
  if (blastBtn) {
    blastBtn.addEventListener('click', calculateBlastRadius);
  }

  // Server-Sent Events (SSE) Live Feed
  function initSSE() {
    if (eventSource) {
      eventSource.close();
    }
    const url = authToken ? `/api/v1/events?token=${encodeURIComponent(authToken)}` : '/api/v1/events';
    eventSource = new EventSource(url);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        lastSuccessfulFetch = Date.now();
        if (data.verdict) {
          updateVerdictUI(data.verdict);
          updateTopBar(data.verdict);
        }
      } catch (err) {
        // Safe fallback on parse error
      }
    };

    eventSource.onerror = () => {
      // Reconnection managed automatically by browser
    };
  }

  // Refresh Desired vs Actual (Drift & Plans)
  async function refreshDesiredView() {
    const driftContainer = document.getElementById('drift-items-container');
    const planContainer = document.getElementById('plan-steps-container');
    const driftBadge = document.getElementById('drift-summary-badge');
    const planBadge = document.getElementById('plan-policy-badge');

    if (!driftContainer || !planContainer) return;

    try {
      // 1. Fetch Drift
      const dRes = await fetch('/api/v1/drift', { headers: getHeaders() });
      if (dRes.ok) {
        const dData = await dRes.json();
        driftContainer.innerHTML = '';

        if (dData.status === 'no_desired_state') {
          if (driftBadge) {
            driftBadge.className = 'badge badge-lavender';
            driftBadge.textContent = '[?] NO MANIFEST';
          }
          driftContainer.innerHTML = `
            <div style="color: var(--dim); font-size: 13px; line-height: 1.5;">
              <div>${dData.message || 'No desired state manifest configured.'}</div>
              <div style="margin-top: 6px; font-size: 12px; color: var(--cyan);">
                Configure desired state via <code>--desired &lt;path&gt;</code> or <code>kazeshini.desired.yaml</code> to enable automated drift audit.
              </div>
            </div>
          `;
        } else if (!dData.items || dData.items.length === 0) {
          if (driftBadge) {
            driftBadge.className = 'badge badge-mint';
            driftBadge.textContent = '[✓] ZERO DRIFT';
          }
          driftContainer.innerHTML = `
            <div style="color: var(--mint); font-size: 13px;">
              [✓] Observed host state is completely compliant with desired specifications. No drift detected.
            </div>
          `;
        } else {
          const count = dData.items.length;
          const unknownCount = dData.summary ? (dData.summary.unknown || 0) : 0;
          if (driftBadge) {
            if (unknownCount > 0) {
              driftBadge.className = 'badge badge-peach';
              driftBadge.textContent = `[!] ${count} DRIFT (${unknownCount} UNKNOWN)`;
            } else {
              driftBadge.className = 'badge badge-rose';
              driftBadge.textContent = `[▲] ${count} DRIFT DETECTED`;
            }
          }

          dData.items.forEach(item => {
            const card = document.createElement('div');
            card.style.backgroundColor = '#0E1017';
            card.style.border = '1px solid var(--panel-border)';
            card.style.padding = '10px 14px';
            card.style.display = 'flex';
            card.style.flexDirection = 'column';
            card.style.gap = '6px';

            let badgeClass = 'badge-rose';
            let glyph = '[▲]';
            if (item.kind === 'unknown') {
              badgeClass = 'badge-lavender';
              glyph = '[?]';
            } else if (item.kind === 'unexpected-port' || item.kind === 'extra') {
              badgeClass = 'badge-peach';
              glyph = '[!]';
            }

            const headerRow = document.createElement('div');
            headerRow.style.display = 'flex';
            headerRow.style.justifyContent = 'space-between';
            headerRow.style.alignItems = 'center';
            headerRow.innerHTML = `
              <div style="font-weight: bold; color: var(--text);">
                <span>[${item.resource_type.toUpperCase()}]</span> <span>${item.resource_id}</span>
              </div>
              <span class="badge ${badgeClass}">${glyph} ${item.kind.toUpperCase()}</span>
            `;

            const descRow = document.createElement('div');
            descRow.style.fontSize = '12px';
            descRow.style.color = 'var(--dim)';
            descRow.textContent = item.description;

            const evidenceRow = document.createElement('div');
            evidenceRow.style.fontSize = '11px';
            evidenceRow.style.display = 'flex';
            evidenceRow.style.gap = '16px';
            evidenceRow.style.color = 'var(--cyan)';
            evidenceRow.innerHTML = `
              <div><strong>DESIRED:</strong> ${item.desired_value || 'none'}</div>
              <div><strong>ACTUAL:</strong> ${item.actual_value || 'none'}</div>
              <div><strong>CERTAINTY:</strong> ${item.certainty || 'OBSERVED'}</div>
            `;

            card.appendChild(headerRow);
            card.appendChild(descRow);
            card.appendChild(evidenceRow);
            driftContainer.appendChild(card);
          });
        }
      }

      // 2. Fetch Plans
      const pRes = await fetch('/api/v1/plans', { headers: getHeaders() });
      if (pRes.ok) {
        const pData = await pRes.json();
        planContainer.innerHTML = '';

        if (pData.status === 'no_desired_state' || !pData.plan || !pData.plan.steps || pData.plan.steps.length === 0) {
          if (planBadge) {
            planBadge.className = 'badge badge-mint';
            planBadge.textContent = '[✓] NO PLAN NEEDED';
          }
          planContainer.innerHTML = `
            <div style="color: var(--mint); font-size: 13px;">
              [✓] No changes needed. All resources align with desired manifest.
            </div>
          `;
        } else {
          const plan = pData.plan;
          const decision = pData.decision;

          if (planBadge) {
            if (decision && !decision.allowed) {
              planBadge.className = 'badge badge-rose';
              planBadge.textContent = `[▲] BLOCKED BY POLICY`;
            } else if (decision && decision.requires_approval) {
              planBadge.className = 'badge badge-peach';
              planBadge.textContent = `[!] APPROVAL REQUIRED`;
            } else {
              planBadge.className = 'badge badge-cyan';
              planBadge.textContent = `[≈] ${plan.steps.length} STEPS (READ-ONLY)`;
            }
          }

          if (decision && decision.reasons && decision.reasons.length > 0) {
            const polWarning = document.createElement('div');
            polWarning.style.padding = '8px 12px';
            polWarning.style.border = '1px dashed var(--rose)';
            polWarning.style.color = 'var(--rose)';
            polWarning.style.fontSize = '12px';
            polWarning.innerHTML = `<strong>POLICY GATE:</strong> ${decision.reasons.join('; ')}`;
            planContainer.appendChild(polWarning);
          }

          plan.steps.forEach((s, idx) => {
            const stepEl = document.createElement('div');
            stepEl.style.backgroundColor = '#0E1017';
            stepEl.style.border = '1px solid var(--panel-border)';
            stepEl.style.padding = '12px';
            stepEl.style.display = 'flex';
            stepEl.style.flexDirection = 'column';
            stepEl.style.gap = '8px';

            let riskClass = 'badge-mint';
            if (s.risk === 'high' || s.risk === 'critical') riskClass = 'badge-rose';
            else if (s.risk === 'medium') riskClass = 'badge-peach';

            const topRow = document.createElement('div');
            topRow.style.display = 'flex';
            topRow.style.justifyContent = 'space-between';
            topRow.style.alignItems = 'center';
            topRow.innerHTML = `
              <div style="font-weight: bold; color: var(--text);">
                <span style="color: var(--cyan);">Step ${idx + 1}.</span> [${s.action.toUpperCase()}] ${s.resource_id}
              </div>
              <div style="display: flex; gap: 8px;">
                <span class="badge ${riskClass}">RISK: ${s.risk.toUpperCase()}</span>
                ${s.requires_reboot ? '<span class="badge badge-peach">REBOOT REQ</span>' : ''}
              </div>
            `;

            const descRow = document.createElement('div');
            descRow.style.fontSize = '12px';
            descRow.style.color = 'var(--dim)';
            descRow.textContent = s.description;

            // Equivalent commands with Copy button
            const cmdBox = document.createElement('div');
            cmdBox.style.backgroundColor = '#07080B';
            cmdBox.style.border = '1px solid var(--panel-border)';
            cmdBox.style.padding = '8px 10px';
            cmdBox.style.position = 'relative';

            const cmdHeader = document.createElement('div');
            cmdHeader.style.display = 'flex';
            cmdHeader.style.justifyContent = 'space-between';
            cmdHeader.style.alignItems = 'center';
            cmdHeader.style.marginBottom = '6px';

            const cmdLabel = document.createElement('span');
            cmdLabel.style.fontSize = '11px';
            cmdLabel.style.color = 'var(--dim)';
            cmdLabel.textContent = 'EQUIVALENT HOST COMMANDS (NOT RUN AUTOMATICALLY):';

            const copyBtn = document.createElement('button');
            copyBtn.className = 'btn';
            copyBtn.style.padding = '2px 8px';
            copyBtn.style.fontSize = '11px';
            copyBtn.textContent = 'COPY';

            const cmdText = (s.equivalent_commands || []).join('\n');
            copyBtn.addEventListener('click', () => {
              navigator.clipboard.writeText(cmdText).then(() => {
                copyBtn.textContent = 'COPIED!';
                setTimeout(() => { copyBtn.textContent = 'COPY'; }, 2000);
              });
            });

            cmdHeader.appendChild(cmdLabel);
            cmdHeader.appendChild(copyBtn);

            const pre = document.createElement('pre');
            pre.style.margin = '0';
            pre.style.color = 'var(--mint)';
            pre.style.fontSize = '12px';
            pre.style.fontFamily = 'monospace';
            pre.textContent = cmdText;

            cmdBox.appendChild(cmdHeader);
            cmdBox.appendChild(pre);

            stepEl.appendChild(topRow);
            stepEl.appendChild(descRow);
            stepEl.appendChild(cmdBox);
            planContainer.appendChild(stepEl);
          });
        }
      }
    } catch (err) {
      console.error('failed fetching desired vs actual state:', err);
    }
  }

  // --- Phase 26: Software Inventory & Dry-Run Planning View ---
  let cachedSoftwarePackages = [];

  async function refreshSoftwareView() {
    const tableBody = document.getElementById('software-table-body');
    const metaText = document.getElementById('software-meta-text');
    const metaBadge = document.getElementById('software-meta-badge');
    const upgBadge = document.getElementById('software-upgradable-badge');
    const railCount = document.getElementById('count-software');

    if (!tableBody) return;

    try {
      const res = await fetch('/api/v1/software', { headers: getHeaders() });
      if (!res.ok) {
        tableBody.innerHTML = `<tr><td colspan="5" style="padding: 12px; color: var(--rose); text-align: center;">Error loading software: ${res.statusText}</td></tr>`;
        return;
      }
      const data = await res.json();
      cachedSoftwarePackages = data.packages || [];

      if (railCount) railCount.textContent = data.total_upgradable || 0;
      if (upgBadge) upgBadge.textContent = `${data.total_upgradable || 0} UPGRADABLE`;

      if (metaBadge && metaText && data.metadata) {
        if (data.metadata.is_stale) {
          metaBadge.className = 'badge badge-peach';
          metaBadge.textContent = '[!] STALE CACHE';
        } else if (data.metadata.available) {
          metaBadge.className = 'badge badge-mint';
          metaBadge.textContent = '[✓] FRESH';
        } else {
          metaBadge.className = 'badge badge-lavender';
          metaBadge.textContent = '[?] UNKNOWN';
        }
        metaText.textContent = `Cache age: ${data.metadata.age_human || 'unknown'}`;
      }

      renderSoftwareTable();
    } catch (err) {
      console.error('failed fetching software inventory:', err);
      tableBody.innerHTML = `<tr><td colspan="5" style="padding: 12px; color: var(--rose); text-align: center;">Failed to connect to software API</td></tr>`;
    }
  }

  function renderSoftwareTable() {
    const tableBody = document.getElementById('software-table-body');
    const searchInput = document.getElementById('software-search');
    const filterUpg = document.getElementById('software-filter-upgradable');
    const filterSec = document.getElementById('software-filter-security');

    if (!tableBody) return;

    const query = (searchInput?.value || '').toLowerCase().trim();
    const upgOnly = filterUpg?.checked || false;
    const secOnly = filterSec?.checked || false;

    const filtered = cachedSoftwarePackages.filter(p => {
      if (query && !p.name.toLowerCase().includes(query)) return false;
      if (upgOnly && !p.is_upgradable) return false;
      if (secOnly && (!p.candidate || p.candidate.upgrade_kind !== 'security')) return false;
      return true;
    });

    if (filtered.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="5" style="padding: 12px; color: var(--dim); text-align: center;">No matching packages found.</td></tr>`;
      return;
    }

    tableBody.innerHTML = '';
    filtered.slice(0, 100).forEach(p => {
      const row = document.createElement('tr');
      row.style.borderBottom = '1px solid var(--surface-2)';

      let candText = '-';
      if (p.candidate) {
        candText = p.candidate.version;
        if (p.candidate.upgrade_kind === 'security') {
          candText += ` <span class="badge badge-peach" style="font-size: 10px;">sec</span>`;
        }
      }

      let statusBadge = `<span class="badge badge-dim">${p.status}</span>`;
      if (p.status === 'upgradable') {
        statusBadge = `<span class="badge badge-cyan">[↑] upgradable</span>`;
      } else if (p.status === 'held' || p.status === 'pinned') {
        statusBadge = `<span class="badge badge-peach">[🔒] ${p.status}</span>`;
      }

      row.innerHTML = `
        <td style="padding: 6px 8px; font-weight: bold; color: var(--cyan);">${p.name}</td>
        <td style="padding: 6px 8px; color: var(--fg);">${p.version}</td>
        <td style="padding: 6px 8px;">${candText}</td>
        <td style="padding: 6px 8px;">${statusBadge}</td>
        <td style="padding: 6px 8px; text-align: right;">
          <button class="plan-update-btn" data-pkg="${p.name}" style="background: var(--surface-2); border: 1px solid var(--border); color: var(--fg); cursor: pointer; padding: 2px 8px; font-family: monospace; border-radius: 3px; font-size: 12px;">Plan update</button>
        </td>
      `;

      row.querySelector('.plan-update-btn').addEventListener('click', () => {
        showSoftwarePlan(p.name, 'upgrade');
      });

      tableBody.appendChild(row);
    });
  }

  // Hook up filter listeners
  document.getElementById('software-search')?.addEventListener('input', renderSoftwareTable);
  document.getElementById('software-filter-upgradable')?.addEventListener('change', renderSoftwareTable);
  document.getElementById('software-filter-security')?.addEventListener('change', renderSoftwareTable);
  document.getElementById('software-plan-close')?.addEventListener('click', () => {
    const modal = document.getElementById('software-plan-modal');
    if (modal) modal.style.display = 'none';
  });

  async function showSoftwarePlan(pkgName, kind) {
    const modal = document.getElementById('software-plan-modal');
    const content = document.getElementById('software-plan-content');
    const title = document.getElementById('software-plan-title');

    if (!modal || !content) return;

    modal.style.display = 'block';
    if (title) title.textContent = `[🛠] DRY-RUN PLAN: ${kind.toUpperCase()} ${pkgName}`;
    content.innerHTML = `<div style="color: var(--dim);">Generating deterministic dry-run plan &amp; safety analysis for ${pkgName}...</div>`;

    try {
      const res = await fetch('/api/v1/software/plan', {
        method: 'POST',
        headers: { ...getHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ package: pkgName, kind: kind })
      });
      if (!res.ok) {
        content.innerHTML = `<div style="color: var(--rose);">Failed to generate plan: ${res.statusText}</div>`;
        return;
      }
      const p = await res.json();

      let safetyBadgeClass = 'badge-mint';
      let safetyLabel = '[✓] SAFE';
      if (p.safety.blocked) {
        safetyBadgeClass = 'badge-rose';
        safetyLabel = '[▲] BLOCKED';
      } else if (!p.safety.safe) {
        safetyBadgeClass = 'badge-peach';
        safetyLabel = '[!] WARNING';
      }

      content.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 8px;">
          <div>
            <strong>From:</strong> <code>${p.from_version}</code> &rarr; <strong>To:</strong> <code>${p.to_version || 'n/a'}</code>
          </div>
          <span class="badge ${safetyBadgeClass}">${safetyLabel}</span>
        </div>

        <div>
          <strong>Safety Analysis:</strong> ${p.safety.summary}
          ${(p.safety.flags || []).map(f => `
            <div style="margin-top: 4px; padding: 4px 8px; background: var(--surface-2); border-left: 3px solid ${f.severity === 'critical' ? 'var(--rose)' : 'var(--peach)'};">
              <span class="badge badge-dim" style="font-size: 10px;">${f.code}</span> ${f.plain_reason}
            </div>
          `).join('')}
        </div>

        <div>
          <strong>Equivalent Command (SHOWN ONLY):</strong>
          <pre style="background: var(--surface-1); border: 1px solid var(--border); padding: 8px; border-radius: 4px; font-family: monospace; color: var(--mint); margin-top: 4px;">${p.equivalent_command}</pre>
        </div>

        <div>
          <strong>Package Manager Raw Simulation (Fact, not inference):</strong>
          <pre style="background: var(--surface-1); border: 1px solid var(--border); padding: 8px; border-radius: 4px; font-family: monospace; font-size: 11px; max-height: 160px; overflow-y: auto; margin-top: 4px; color: var(--dim);">${p.raw_simulation || '(no output)'}</pre>
        </div>
      `;
    } catch (err) {
      content.innerHTML = `<div style="color: var(--rose);">Error: ${err.message}</div>`;
    }
  }

  async function refreshPlatformsView() {
    const container = document.getElementById('platforms-container');
    const railCount = document.getElementById('count-platforms');
    if (!container) return;

    try {
      const res = await fetch('/api/v1/platforms', { headers: getHeaders() });
      if (!res.ok) {
        container.innerHTML = `<div class="panel" style="color: var(--rose);">Failed loading platforms: ${res.statusText}</div>`;
        return;
      }
      const platforms = await res.json();

      let detectedCount = 0;
      const categories = {};

      platforms.forEach(p => {
        if (p.present) detectedCount++;
        if (!categories[p.category]) categories[p.category] = [];
        categories[p.category].push(p);
      });

      if (railCount) railCount.textContent = detectedCount;

      let html = '';
      for (const [catName, list] of Object.entries(categories)) {
        html += `
          <div class="panel">
            <h2 class="panel-title" style="text-transform: uppercase;">[◈] ${catName}</h2>
            <div style="display: flex; flex-direction: column; gap: 12px; margin-top: 10px;">
        `;

        list.forEach(p => {
          let badgeClass = 'badge-dim';
          let badgeText = 'NOT DETECTED';
          if (p.present) {
            if (p.support === 'adapter') {
              badgeClass = 'badge-mint';
              badgeText = '[✓] DEEP (ADAPTER)';
            } else {
              badgeClass = 'badge-cyan';
              badgeText = '[≈] DETECTED';
            }
          } else if (p.support === 'cloud-side-not-supported' || p.support === 'unsupported (Windows)') {
            badgeClass = 'badge-peach';
            badgeText = `[!] NOT SUPPORTED HERE`;
          }

          let statusText = p.running ? '<span style="color: var(--mint);">RUNNING</span>' : (p.present ? '<span style="color: var(--dim);">STOPPED</span>' : '<span style="color: var(--dim);">NOT FOUND</span>');

          html += `
            <div style="border: 1px solid var(--border); padding: 10px; border-radius: 4px; background: var(--surface-1);">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <div style="font-weight: bold; color: var(--text); font-size: 14px;">${p.name} <span style="font-size: 11px; color: var(--dim);">(${p.id})</span></div>
                <div style="display: flex; gap: 8px; align-items: center;">
                  <span class="badge ${badgeClass}">${badgeText}</span>
                  <span style="font-size: 11px; font-weight: bold;">${statusText}</span>
                </div>
              </div>
              <div style="font-size: 12px; display: flex; flex-direction: column; gap: 4px;">
                <div><span style="color: var(--mint); font-weight: bold;">WHAT KAZE SHINI CAN SEE:</span> <span style="color: var(--fg);">${p.what_can_see}</span></div>
                <div><span style="color: var(--peach); font-weight: bold;">WHAT KAZE SHINI CANNOT SEE:</span> <span style="color: var(--dim);">${p.what_cannot_see}</span></div>
              </div>
          `;

          if (p.configs && p.configs.length > 0) {
            html += `<div style="margin-top: 4px; font-size: 11px; color: var(--cyan);">Configs: ${p.configs.join(', ')}</div>`;
          }
          if (p.ports && p.ports.length > 0) {
            html += `<div style="margin-top: 2px; font-size: 11px; color: var(--cyan);">Ports: ${p.ports.join(', ')}</div>`;
          }
          if (p.adapter_data) {
            html += `<div style="margin-top: 6px; padding: 6px; background: var(--bg); border: 1px dashed var(--border); font-size: 11px; color: var(--fg); border-radius: 3px;">
              <span style="color: var(--mint); font-weight: bold;">Adapter Telemetry:</span> ${JSON.stringify(p.adapter_data)}
            </div>`;
          }

          html += `</div>`;
        });

        html += `
            </div>
          </div>
        `;
      }

      container.innerHTML = html;
    } catch (err) {
      container.innerHTML = `<div class="panel" style="color: var(--rose);">Failed fetching platforms: ${err.message}</div>`;
    }
  }

  const refreshPlatformsBtn = document.getElementById('refresh-platforms-btn');
  refreshPlatformsBtn?.addEventListener('click', refreshPlatformsView);

  function refreshAll() {
    refreshVerdict();
    refreshOverviewSummary();
    refreshPulse();
    refreshFindings();
    refreshDependencies();
    refreshBlastRadiusNodes();
    refreshActivityLog();
    refreshDesiredView();
    refreshSoftwareView();
    refreshPlatformsView();
    loadChecks();
  }

  // Table column sorting support
  let currentSort = { col: '', asc: true };
  document.querySelectorAll('.sortable-th').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.getAttribute('data-sort');
      if (currentSort.col === col) {
        currentSort.asc = !currentSort.asc;
      } else {
        currentSort.col = col;
        currentSort.asc = true;
      }
      if (th.closest('#software-table')) {
        cachedSoftwarePackages.sort((a, b) => {
          let valA = a[col] || '';
          let valB = b[col] || '';
          if (col === 'candidate') {
            valA = a.candidate ? a.candidate.version : '';
            valB = b.candidate ? b.candidate.version : '';
          }
          if (valA < valB) return currentSort.asc ? -1 : 1;
          if (valA > valB) return currentSort.asc ? 1 : -1;
          return 0;
        });
        renderSoftwareTable();
      }
    });
  });

  // Guidance Panel & Ask Technical Modal Handlers
  const btnAskTechnical = document.getElementById('btn-ask-technical');
  const technicalModal = document.getElementById('technical-modal');
  const techCloseBtn = document.getElementById('tech-close-btn');
  const techCopyBtn = document.getElementById('tech-copy-btn');
  const techPrintBtn = document.getElementById('tech-print-btn');
  const techSummaryText = document.getElementById('tech-summary-text');
  const btnCopyCommand = document.getElementById('btn-copy-command');
  const guidanceCommand = document.getElementById('guidance-command');

  if (btnCopyCommand && guidanceCommand) {
    btnCopyCommand.addEventListener('click', () => {
      navigator.clipboard.writeText(guidanceCommand.textContent.trim()).then(() => {
        const orig = btnCopyCommand.textContent;
        btnCopyCommand.textContent = 'Copied!';
        setTimeout(() => { btnCopyCommand.textContent = orig; }, 2000);
      });
    });
  }

  if (btnAskTechnical && technicalModal && techSummaryText) {
    btnAskTechnical.addEventListener('click', () => {
      const hostName = el.pulseHost ? el.pulseHost.textContent : 'Linux Server';
      const risk = el.riskScore ? el.riskScore.textContent : '0';
      const status = el.riskBadge ? el.riskBadge.textContent : '[✓] HEALTHY';
      const dateStr = new Date().toISOString();

      let summaryContent = `======================================================================\n`;
      summaryContent += `KAZESHINI SYSTEM SUMMARY (TECHNICAL SHAREABLE)\n`;
      summaryContent += `Generated: ${dateStr}\n`;
      summaryContent += `Host: ${hostName} | Status: ${status} | Risk Score: ${risk}/100\n`;
      summaryContent += `Confidentiality: Secret-free sanitized diagnostic record\n`;
      summaryContent += `======================================================================\n\n`;
      summaryContent += `1. OVERVIEW & HEALTH:\n`;
      summaryContent += `   Lead: ${el.verdictLead ? el.verdictLead.textContent : 'Normal operation'}\n\n`;
      summaryContent += `2. PRIMARY ACTION TO RESOLVE:\n`;
      const actionTxt = document.getElementById('guidance-action-text');
      summaryContent += `   ${actionTxt ? actionTxt.textContent.trim() : 'No critical action'}\n`;
      summaryContent += `   Command: ${guidanceCommand ? guidanceCommand.textContent.trim() : 'kazeshini --once'}\n\n`;
      summaryContent += `3. RUNTIME METRICS:\n`;
      summaryContent += `   Kernel: ${el.pulseKernel ? el.pulseKernel.textContent : 'Linux'}\n`;
      summaryContent += `   Uptime: ${el.pulseUptime ? el.pulseUptime.textContent : '0s'}\n\n`;
      summaryContent += `4. REPRODUCIBLE HOST QUERY:\n`;
      summaryContent += `   kazeshini --once --json\n`;
      summaryContent += `======================================================================\n`;

      techSummaryText.value = summaryContent;
      technicalModal.style.display = 'flex';
    });
  }

  if (techCloseBtn && technicalModal) {
    techCloseBtn.addEventListener('click', () => {
      technicalModal.style.display = 'none';
    });
  }

  if (techCopyBtn && techSummaryText) {
    techCopyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(techSummaryText.value).then(() => {
        const orig = techCopyBtn.textContent;
        techCopyBtn.textContent = 'Copied!';
        setTimeout(() => { techCopyBtn.textContent = orig; }, 2000);
      });
    });
  }

  if (techPrintBtn && techSummaryText) {
    techPrintBtn.addEventListener('click', () => {
      window.print();
    });
  }

  // Glossary Lookup Modal
  const glossaryModal = document.getElementById('glossary-modal');
  const glossaryCloseBtn = document.getElementById('glossary-close-btn');
  const glossaryTitle = document.getElementById('glossary-modal-title');
  const glossarySummary = document.getElementById('glossary-summary');
  const glossaryDetails = document.getElementById('glossary-details');

  const GLOSSARY_TERMS = {
    'port': {
      summary: 'A port is like a door for network traffic. Programs use it to talk to other computers.',
      details: 'When a program wants to communicate over the network, it opens a port (e.g. 80 for websites, 22 for remote login). Listening ports reachable on all interfaces are accessible to outside callers.'
    },
    'service': {
      summary: 'A service is a background program. It starts up and runs tasks for the server.',
      details: 'Services manage web servers, databases, and system tasks. If a service crashes or enters a degraded state, users or other applications may be unable to connect.'
    },
    'package': {
      summary: 'A package is a bundle of software files. The system installs and tracks it safely.',
      details: 'Using packages ensures programs receive security updates, can be uninstalled safely, and do not leave behind orphan files.'
    },
    'kernel': {
      summary: 'The kernel is the main engine of the server. It manages the hardware, memory, and disks.',
      details: 'All applications ask the kernel to access disks, network connections, or memory. Kazeshini reads kernel status files directly without changing them.'
    },
    'inode': {
      summary: 'An inode is an index number for a file. The disk uses it to track each item.',
      details: 'Even if a disk has free gigabytes left, running out of inodes prevents creating any new files (such as log entries or user uploads).'
    },
    'unmanaged software': {
      summary: 'This is software put on the machine by hand. The system package tool does not track it.',
      details: 'Because the operating system does not know about it, it will not receive automated security patches and may be forgotten over time.'
    },
    'risk score': {
      summary: 'A score from 0 to 100. Lower numbers mean the server is safe, while high numbers show problems.',
      details: 'Points are added when critical security flaws, failed services, or unprotected network ports are detected.'
    },
    'drift': {
      summary: 'Drift means settings have changed. The server does not match what you expected.',
      details: 'For example, if a package was accidentally installed or removed outside of configuration management, Kazeshini points out the difference.'
    },
    'visibility': {
      summary: 'Visibility is how much of the server was seen. It tells you what could be checked.',
      details: 'If running without administrator (root) rights, some security files cannot be read. Kazeshini is always honest about what it could not inspect.'
    }
  };

  document.addEventListener('click', (e) => {
    const target = e.target.closest('[data-glossary]');
    if (target && glossaryModal) {
      const termKey = target.getAttribute('data-glossary').toLowerCase().trim();
      const def = GLOSSARY_TERMS[termKey];
      if (def) {
        glossaryTitle.textContent = `Term: ${termKey.toUpperCase()}`;
        glossarySummary.textContent = def.summary;
        glossaryDetails.textContent = def.details;
        glossaryModal.style.display = 'flex';
      }
    }
  });

  if (glossaryCloseBtn && glossaryModal) {
    glossaryCloseBtn.addEventListener('click', () => {
      glossaryModal.style.display = 'none';
    });
  }

  // =========================================================================
  // Phase 42: Visual Views (Space Colonization Growth Map, Treemap, Matrix, Exports)
  // Adheres strictly to Principle 18: No guesses, deterministic, table equivalent,
  // text description for screen readers, visibility note.
  // =========================================================================

  // Export Menu Handling
  const exportBtn = document.getElementById('export-btn');
  const exportMenu = document.getElementById('export-menu');

  if (exportBtn && exportMenu) {
    exportBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      exportMenu.style.display = (exportMenu.style.display === 'none' || !exportMenu.style.display) ? 'flex' : 'none';
    });

    document.addEventListener('click', () => {
      if (exportMenu) exportMenu.style.display = 'none';
    });

    exportMenu.querySelectorAll('button[data-export]').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const fmt = btn.getAttribute('data-export');
        exportMenu.style.display = 'none';
        try {
          const res = await fetch(`/api/v1/export?format=${encodeURIComponent(fmt)}`, { headers: getHeaders() });
          if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `kazeshini-export.${fmt === 'markdown' ? 'md' : fmt}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
          } else {
            alert(`Export failed: HTTP ${res.status}`);
          }
        } catch (err) {
          alert(`Export error: ${err.message}`);
        }
      });
    });
  }

  // View Switcher Persistence (localStorage with try/catch)
  function getViewPreference(domain, defaultView) {
    try {
      return localStorage.getItem(`kazeshini_view_${domain}`) || defaultView;
    } catch (_) {
      return defaultView;
    }
  }

  function setViewPreference(domain, viewType) {
    try {
      localStorage.setItem(`kazeshini_view_${domain}`, viewType);
    } catch (_) {}
  }

  // Wire View Switchers across domains
  document.querySelectorAll('.view-switcher-bar').forEach(bar => {
    const domain = bar.getAttribute('data-domain');
    if (!domain) return;
    const defaultView = domain === 'overview' ? 'tree' : 'table';
    const activeView = getViewPreference(domain, defaultView);

    bar.querySelectorAll('.view-tab-btn').forEach(btn => {
      const vType = btn.getAttribute('data-view');
      if (vType === activeView) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }

      btn.addEventListener('click', () => {
        bar.querySelectorAll('.view-tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        setViewPreference(domain, vType);
        applyDomainView(domain, vType);
      });
    });

    applyDomainView(domain, activeView);
  });

  function applyDomainView(domain, viewType) {
    if (domain === 'overview') {
      const asciiMap = document.getElementById('deps-ascii-map');
      const visualMap = document.getElementById('visual-overview-map');
      if (viewType === 'map') {
        if (asciiMap) asciiMap.style.display = 'none';
        if (visualMap) {
          visualMap.style.display = 'block';
          renderClientGrowthMap();
        }
      } else {
        if (visualMap) visualMap.style.display = 'none';
        if (asciiMap) asciiMap.style.display = 'block';
      }
    } else if (domain === 'storage') {
      const tableList = document.getElementById('checks-list-storage');
      const visualStorage = document.getElementById('visual-storage');
      if (viewType === 'chart') {
        if (tableList) tableList.style.display = 'none';
        if (visualStorage) {
          visualStorage.style.display = 'flex';
          renderStorageTreemap();
        }
      } else {
        if (visualStorage) visualStorage.style.display = 'none';
        if (tableList) tableList.style.display = 'grid';
      }
    } else if (domain === 'network') {
      const tableList = document.getElementById('checks-list-network');
      const visualNetwork = document.getElementById('visual-network');
      if (viewType === 'chart') {
        if (tableList) tableList.style.display = 'none';
        if (visualNetwork) {
          visualNetwork.style.display = 'block';
          renderNetworkMatrix();
        }
      } else {
        if (visualNetwork) visualNetwork.style.display = 'none';
        if (tableList) tableList.style.display = 'grid';
      }
    } else if (domain === 'services') {
      const tableList = document.getElementById('checks-list-services');
      const visualServices = document.getElementById('visual-services');
      if (viewType === 'tree') {
        if (tableList) tableList.style.display = 'none';
        if (visualServices) {
          visualServices.style.display = 'block';
          renderServicesTree();
        }
      } else {
        if (visualServices) visualServices.style.display = 'none';
        if (tableList) tableList.style.display = 'grid';
      }
    }
  }

  // Client-Side Space Colonization Growth Map Renderer
  async function renderClientGrowthMap() {
    const container = document.getElementById('growth-map-svg-wrap');
    const srTable = document.getElementById('growth-sr-table');
    if (!container) return;

    try {
      const res = await fetch('/api/v1/graph', { headers: getHeaders() });
      if (!res.ok) return;
      const gData = await res.json();
      const nodes = gData.nodes || [];
      const edges = gData.edges || [];

      // Build Screen Reader Accessible Table
      if (srTable) {
        let srHTML = '<table><caption>Host Provenance Entities and Provenance Topology</caption><thead><tr><th>ID</th><th>Type</th><th>Label</th><th>Certainty</th></tr></thead><tbody>';
        nodes.forEach(n => {
          srHTML += `<tr><td>${escapeHTML(n.id)}</td><td>${escapeHTML(n.type)}</td><td>${escapeHTML(n.label)}</td><td>${escapeHTML(n.certainty)}</td></tr>`;
        });
        srHTML += '</tbody></table>';
        srTable.innerHTML = srHTML;
      }

      // Space Colonization parameters matching Go viz exactly
      const width = 960;
      const height = 600;
      const root = { x: width / 2, y: height - 50 };
      const attractionRadius = 150.0;
      const killDistance = 25.0;
      const stepLength = 15.0;
      const maxIterations = 50;
      const nodeCap = 2000;

      // Filter candidate entities
      const candidateNodes = nodes.filter(n => ['process', 'service', 'port', 'unmanaged', 'package', 'container'].includes(n.type));
      candidateNodes.sort((a, b) => a.id.localeCompare(b.id));

      const drawnCount = Math.min(candidateNodes.length, nodeCap);
      const notDrawnCount = candidateNodes.length - drawnCount;

      // Seed positions deterministically
      const attractors = [];
      const goldenRatio = 1.618033988749895;
      for (let i = 0; i < drawnCount; i++) {
        const node = candidateNodes[i];
        const theta = 2.0 * Math.PI * i / goldenRatio;
        const norm = (i + 1) / drawnCount;
        const r = 80.0 + Math.sqrt(norm) * (Math.min(width, height) * 0.42);
        const ax = root.x + r * Math.cos(theta);
        const ay = Math.max(40, (root.y - 100) - Math.abs(r * Math.sin(theta)));
        attractors.push({
          id: node.id,
          type: node.type,
          label: node.label,
          severity: node.severity || 'ok',
          pos: { x: ax, y: ay },
          reached: false,
          isUnknown: (node.certainty || '').toLowerCase() === 'inferred' || (node.certainty || '').toLowerCase() === 'unknown',
        });
      }

      // Initial root branch
      let branches = [{
        id: 'branch-0',
        parent_id: '',
        start: { x: root.x, y: root.y },
        end: { x: root.x, y: root.y - 30 },
        thickness: 4.0,
      }];

      // Space colonization iterations (chunked <50ms per frame or instant if prefers-reduced-motion)
      const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

      function renderSVGContent() {
        let svg = `<svg viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Kazeshini Space Colonization Provenance Map" style="background:#07080b; border:1px solid #1e2230; width:100%; height:auto;">\n`;
        svg += `  <title>Kazeshini Growth Map: ${nodes.length} Entities</title>\n`;
        svg += `  <desc>Deterministic space colonization branching showing entity provenance. Showing ${drawnCount} of ${candidateNodes.length} entities.</desc>\n`;

        // Draw branches
        branches.forEach(b => {
          svg += `  <line x1="${b.start.x.toFixed(1)}" y1="${b.start.y.toFixed(1)}" x2="${b.end.x.toFixed(1)}" y2="${b.end.y.toFixed(1)}" stroke="#1e2230" stroke-width="${b.thickness.toFixed(1)}" stroke-linecap="round" />\n`;
        });

        // Draw host root
        svg += `  <circle cx="${root.x.toFixed(1)}" cy="${root.y.toFixed(1)}" r="8" fill="#8fffc8" stroke="#11131a" stroke-width="2" />\n`;
        svg += `  <text x="${root.x.toFixed(1)}" y="${(root.y + 20).toFixed(1)}" fill="#8fffc8" font-size="11" font-family="monospace" text-anchor="middle">HOST ROOT</text>\n`;

        // Draw attractors
        attractors.forEach(a => {
          let col = '#8fe9ff';
          if (a.severity === 'critical') col = '#ff9ec7';
          else if (a.severity === 'high') col = '#ffb89a';
          else if (a.type === 'service') col = '#b9a7ff';

          if (a.isUnknown) {
            svg += `  <rect x="${(a.pos.x - 5).toFixed(1)}" y="${(a.pos.y - 5).toFixed(1)}" width="10" height="10" fill="none" stroke="${col}" stroke-width="1.5" stroke-dasharray="3,2" />\n`;
          } else {
            svg += `  <circle cx="${a.pos.x.toFixed(1)}" cy="${a.pos.y.toFixed(1)}" r="4.5" fill="${col}" stroke="#07080b" stroke-width="1" />\n`;
          }
          svg += `  <text x="${(a.pos.x + 8).toFixed(1)}" y="${(a.pos.y + 3).toFixed(1)}" fill="#d8dee9" font-size="9" font-family="monospace">${escapeHTML(a.label)}</text>\n`;
        });

        // Visibility note
        svg += `  <text x="16" y="24" fill="#7d8597" font-size="11" font-family="monospace">Visibility: ${drawnCount} of ${candidateNodes.length} entities (Deterministic Seed)</text>\n`;
        if (notDrawnCount > 0) {
          svg += `  <text x="16" y="40" fill="#ffb89a" font-size="10" font-family="monospace">[!] Capped at ${nodeCap} nodes to prevent browser starvation</text>\n`;
        }
        svg += '</svg>';
        container.innerHTML = svg;
      }

      // Execute colonization steps
      let iter = 0;
      function step() {
        const startTime = performance.now();
        while (iter < maxIterations) {
          iter++;
          // Influence accumulation
          const branchDirs = {};
          const branchCounts = {};

          attractors.forEach(att => {
            if (att.reached) return;
            let closestDist = attractionRadius;
            let closestIdx = -1;

            branches.forEach((b, idx) => {
              const dx = att.pos.x - b.end.x;
              const dy = att.pos.y - b.end.y;
              const d = Math.sqrt(dx * dx + dy * dy);
              if (d < killDistance) {
                att.reached = true;
              } else if (d < closestDist) {
                closestDist = d;
                closestIdx = idx;
              }
            });

            if (closestIdx >= 0 && !att.reached) {
              const b = branches[closestIdx];
              const dx = (att.pos.x - b.end.x) / closestDist;
              const dy = (att.pos.y - b.end.y) / closestDist;
              if (!branchDirs[closestIdx]) {
                branchDirs[closestIdx] = { x: 0, y: 0 };
                branchCounts[closestIdx] = 0;
              }
              branchDirs[closestIdx].x += dx;
              branchDirs[closestIdx].y += dy;
              branchCounts[closestIdx]++;
            }
          });

          // Generate new branch tips
          let grew = false;
          Object.keys(branchDirs).forEach(idxStr => {
            const idx = parseInt(idxStr, 10);
            const count = branchCounts[idx];
            if (count > 0) {
              const b = branches[idx];
              const dir = branchDirs[idx];
              const norm = Math.sqrt(dir.x * dir.x + dir.y * dir.y);
              if (norm > 0.0001) {
                const nx = dir.x / norm;
                const ny = dir.y / norm;
                branches.push({
                  id: `branch-${branches.length}`,
                  parent_id: b.id,
                  start: { x: b.end.x, y: b.end.y },
                  end: { x: b.end.x + nx * stepLength, y: b.end.y + ny * stepLength },
                  thickness: Math.max(1.0, b.thickness * 0.95),
                });
                grew = true;
              }
            }
          });

          if (!grew || prefersReduced) {
            if (prefersReduced && iter < maxIterations) continue;
            break;
          }

          // Bound frame computation to < 40ms
          if (performance.now() - startTime > 40) {
            renderSVGContent();
            requestAnimationFrame(step);
            return;
          }
        }
        renderSVGContent();
      }

      step();
    } catch (err) {
      console.error('failed client growth map render:', err);
    }
  }

  // Storage Treemap Renderer
  async function renderStorageTreemap() {
    const container = document.getElementById('storage-treemap-content');
    if (!container) return;

    try {
      const res = await fetch('/api/v1/observations/storage', { headers: getHeaders() });
      if (!res.ok) {
        container.innerHTML = '<div class="empty-state">No storage telemetry available.</div>';
        return;
      }
      const sObs = await res.json();
      const mounts = (sObs.items || []).filter(it => it.data && it.data.mount_point).map(it => it.data);
      if (mounts.length === 0) {
        container.innerHTML = '<div class="empty-state">No mounted filesystems detected.</div>';
        return;
      }

      let html = '';
      mounts.forEach(m => {
        const totalGB = (m.total_bytes / (1024 * 1024 * 1024)).toFixed(1);
        const usedGB = (m.used_bytes / (1024 * 1024 * 1024)).toFixed(1);
        const ratioPct = Math.round(m.usage_ratio * 100);
        const isHigh = ratioPct >= 85;

        html += `
          <div class="treemap-bar-wrap">
            <div style="display:flex; justify-content:space-between; font-size:12px;">
              <span style="color:var(--text); font-weight:bold;">${escapeHTML(m.mount_point)} <span style="color:var(--dim); font-size:11px;">(${escapeHTML(m.device)} · ${escapeHTML(m.fs_type)})</span></span>
              <span style="color:${isHigh ? 'var(--rose)' : 'var(--mint)'}; font-weight:bold;">${ratioPct}% (${usedGB} GB / ${totalGB} GB)</span>
            </div>
            <div class="treemap-bar-track" role="progressbar" aria-valuenow="${ratioPct}" aria-valuemin="0" aria-valuemax="100" aria-label="Filesystem usage on ${escapeHTML(m.mount_point)}">
              <div class="treemap-bar-used ${isHigh ? 'high-usage' : ''}" style="width: ${ratioPct}%;"></div>
            </div>
          </div>
        `;
      });

      container.innerHTML = html;
    } catch (err) {
      container.innerHTML = `<div style="color:var(--rose);">Failed loading storage: ${err.message}</div>`;
    }
  }

  // Network Matrix Renderer
  async function renderNetworkMatrix() {
    const container = document.getElementById('network-matrix-content');
    if (!container) return;

    try {
      const res = await fetch('/api/v1/observations/network', { headers: getHeaders() });
      if (!res.ok) {
        container.innerHTML = '<div class="empty-state">No network socket telemetry available.</div>';
        return;
      }
      const nObs = await res.json();
      const sockets = (nObs.items || []).filter(it => it.data && it.data.protocol).map(it => it.data);
      if (sockets.length === 0) {
        container.innerHTML = '<div class="empty-state">No listening or active sockets observed.</div>';
        return;
      }

      let html = '<table class="matrix-table"><thead><tr><th>PROCESS</th><th>PID</th><th>PROTO</th><th>LOCAL PORT</th><th>REMOTE ENDPOINT</th><th>STATE</th></tr></thead><tbody>';
      sockets.forEach(s => {
        const proc = s.process_name || 'kernel';
        const rem = s.remote_ip ? `${s.remote_ip}:${s.remote_port}` : '*:*';
        html += `<tr><td><strong style="color:var(--cyan);">${escapeHTML(proc)}</strong></td><td>${s.pid || '-'}</td><td>${escapeHTML(s.protocol)}</td><td>:${s.local_port}</td><td>${escapeHTML(rem)}</td><td><span class="badge ${s.state === 'LISTEN' ? 'badge-mint' : 'badge-dim'}">${escapeHTML(s.state || 'LISTEN')}</span></td></tr>`;
      });
      html += '</tbody></table>';

      container.innerHTML = html;
    } catch (err) {
      container.innerHTML = `<div style="color:var(--rose);">Failed loading network matrix: ${err.message}</div>`;
    }
  }

  // Services Tree Renderer
  async function renderServicesTree() {
    const container = document.getElementById('services-tree-content');
    if (!container) return;

    try {
      const res = await fetch('/api/v1/observations/service', { headers: getHeaders() });
      if (!res.ok) {
        container.textContent = 'No services telemetry available.';
        return;
      }
      const sObs = await res.json();
      const services = (sObs.items || []).filter(it => it.data && it.data.name).map(it => it.data);
      if (services.length === 0) {
        container.textContent = 'No services observed on host.';
        return;
      }

      let tree = 'HOST ROOT (init / systemd)\n';
      services.forEach((s, idx) => {
        const isLast = idx === services.length - 1;
        const branch = isLast ? '└── ' : '├── ';
        const st = s.status || s.sub_state || 'active';
        tree += `${branch}[${st.toUpperCase()}] ${s.name} (${s.description || 'system service'})\n`;
      });

      container.textContent = tree;
    } catch (err) {
      container.textContent = `Failed loading services: ${err.message}`;
    }
  }

  // Startup Initializer
  handleRoute();
  loadChecks();
  refreshAll();
  initSSE();

  setInterval(() => {
    refreshVerdict();
    refreshPulse();
    refreshOverviewSummary();
  }, 5000);

})();


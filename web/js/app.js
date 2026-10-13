// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

(function () {
  'use strict';

  let authToken = localStorage.getItem('kazeshini_token') || '';
  let eventSource = null;
  let lastSuccessfulFetch = Date.now();
  let checksCache = [];
  let filterQuery = '';

  // DOM Elements cache
  const el = {
    verdictBanner: document.getElementById('verdict-banner'),
    verdictLead: document.getElementById('verdict-lead'),
    chaosScore: document.getElementById('chaos-score'),
    chaosBadge: document.getElementById('chaos-badge'),
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
    symptomResultPanel: document.getElementById('symptom-result-panel'),
    symptomResultTitle: document.getElementById('symptom-result-title'),
    symptomResultContent: document.getElementById('symptom-result-content'),
    symptomCloseBtn: document.getElementById('symptom-close-btn'),
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
    if (d > 0) return `${d}d ${h}h ${m}m`;
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

  // Left Rail View Switching & Hash Routing
  const views = [
    'overview', 'briefing', 'devops', 'cloud', 'cloud-platform',
    'infrastructure', 'devsecops', 'platform', 'network', 'desired', 'software', 'platforms', 'activity'
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

    if (target === 'desired') {
      refreshDesiredView();
    } else if (target === 'software') {
      refreshSoftwareView();
    } else if (target === 'platforms') {
      refreshPlatformsView();
    } else if (target === 'activity') {
      refreshActivityLog();
    } else if (['devops', 'cloud', 'cloud-platform', 'infrastructure', 'devsecops', 'platform', 'network'].includes(target)) {
      renderRoleChecks(target);
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
    { name: 'Briefing', desc: 'Jump to plain-English Server Truth Briefing', action: () => { window.location.hash = '#briefing'; } },
    { name: 'DevOps Checks', desc: 'Jump to DevOps checks & metrics', action: () => { window.location.hash = '#devops'; } },
    { name: 'Cloud Checks', desc: 'Jump to Cloud provider & storage checks', action: () => { window.location.hash = '#cloud'; } },
    { name: 'Cloud Platform Checks', desc: 'Jump to Kubernetes & container checks', action: () => { window.location.hash = '#cloud-platform'; } },
    { name: 'Infrastructure Checks', desc: 'Jump to Disk, systemd & timesync checks', action: () => { window.location.hash = '#infrastructure'; } },
    { name: 'DevSecOps Checks', desc: 'Jump to Sudoers, SSH & auth checks', action: () => { window.location.hash = '#devsecops'; } },
    { name: 'Platform Checks', desc: 'Jump to Tooling, config & permission checks', action: () => { window.location.hash = '#platform'; } },
    { name: 'Network Checks', desc: 'Jump to Sockets, DNS & probe checks', action: () => { window.location.hash = '#network'; } },
    { name: 'Desired vs Actual', desc: 'Jump to Desired vs Actual drift audit & plan', action: () => { window.location.hash = '#desired'; } },
    { name: 'Activity Log', desc: 'Jump to local audit execution log', action: () => { window.location.hash = '#activity'; } },
    { name: ':pet off', desc: 'Turn off TSUMUJI wind-wisp idle pet', action: () => { if (window.Tsumuji) window.Tsumuji.set(false); } },
    { name: ':pet on', desc: 'Turn on TSUMUJI wind-wisp idle pet', action: () => { if (window.Tsumuji) window.Tsumuji.set(true); } },
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
      if (['devops', 'cloud', 'cloud-platform', 'infrastructure', 'devsecops', 'platform', 'network'].includes(currentHash)) {
        renderRoleChecks(currentHash);
      }
    });
  }

  // Render Check Card
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
          // Update check card in-place
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

    // Expandable Details
    const details = document.createElement('div');
    details.className = 'check-details';

    details.innerHTML = `
      <div class="check-read-banner">
        <span>ℹ This only reads; it changes nothing. Read-only host safety guarantee.</span>
      </div>
      ${resultData && resultData.explain_levels ? `
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <div><strong style="color: var(--dim); font-size: 11px;">[WHAT]</strong> <div>${resultData.explain_levels[0] || 'N/A'}</div></div>
          <div><strong style="color: var(--peach); font-size: 11px;">[SO WHAT]</strong> <div>${resultData.explain_levels[1] || 'N/A'}</div></div>
          <div><strong style="color: var(--mint); font-size: 11px;">[NOW WHAT (RECOMMENDATION)]</strong> <div>${resultData.explain_levels[2] || 'N/A'}</div></div>
        </div>
      ` : `<div>${check.description}</div>`}

      ${resultData && resultData.equivalent_command ? `
        <div style="margin-top: 6px;">
          <div style="font-size: 11px; color: var(--dim);">EQUIVALENT SHELL INSPECTION:</div>
          <code style="background-color: #07080b; color: var(--cyan); padding: 4px 8px; display: block; border: 1px solid var(--panel-border);">${resultData.equivalent_command}</code>
        </div>
      ` : ''}

      ${resultData && resultData.evidence && resultData.evidence.length > 0 ? `
        <div style="margin-top: 6px;">
          <div style="font-size: 11px; color: var(--dim);">EVIDENCE & CERTAINTY ([✓] ${resultData.certainty || 'OBSERVED'}):</div>
          <ul style="list-style: none; padding-left: 0; font-size: 12px; color: var(--cyan);">
            ${resultData.evidence.map(ev => `<li>└─ [${ev.source}] ${ev.description}</li>`).join('')}
          </ul>
        </div>
      ` : ''}

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

  // Load and Render Role Checks
  async function loadChecks() {
    try {
      const res = await fetch('/api/v1/checks', { headers: getHeaders() });
      if (res.ok) {
        checksCache = await res.json();
      }
    } catch (err) {
      console.error('failed fetching checks list:', err);
    }
  }

  function renderRoleChecks(role) {
    const container = document.getElementById(`checks-list-${role}`);
    if (!container) return;
    container.innerHTML = '';

    const roleChecks = checksCache.filter(c => c.role === role);
    const filtered = filterQuery ? roleChecks.filter(c => c.title.toLowerCase().includes(filterQuery) || c.id.toLowerCase().includes(filterQuery) || c.description.toLowerCase().includes(filterQuery)) : roleChecks;

    if (filtered.length === 0) {
      container.innerHTML = '<div style="color: var(--dim); padding: 12px;">No checks match filter criteria.</div>';
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

      const countEl = document.getElementById('count-activity');
      if (countEl) countEl.textContent = entries.length;

      if (entries.length === 0) {
        el.activityTbody.innerHTML = '<tr><td colspan="6" style="color: var(--dim);">No checks executed yet.</td></tr>';
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
          <td>${entry.role}</td>
          <td><span class="badge ${stClass}">${entry.status}</span></td>
          <td>${entry.token_holder}</td>
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

  // Symptom Picker
  const symptomButtons = document.querySelectorAll('.symptom-btn');
  symptomButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
      const sym = btn.getAttribute('data-symptom');
      if (!sym) return;
      el.symptomResultPanel.style.display = 'block';
      el.symptomResultTitle.textContent = `[?] INVESTIGATING SYMPTOM: ${btn.textContent.trim().toUpperCase()}`;
      el.symptomResultContent.innerHTML = '<div style="color: var(--dim);">Running targeted checks...</div>';

      try {
        // Query check definitions matching symptom
        const checksToRun = [];
        if (sym === 'slow') checksToRun.push('cpu-memory', 'disk-inodes', 'app-health', 'time-sync');
        else if (sym === 'service-down') checksToRun.push('failed-services', 'app-health', 'app-logs', 'service-permissions');
        else if (sym === 'cant-connect') checksToRun.push('listening-ports', 'dns-config', 'interfaces-routes', 'app-health');
        else if (sym === 'disk-full') checksToRun.push('disk-inodes', 'container-storage', 'attached-storage', 'app-logs');
        else if (sym === 'looks-hacked') checksToRun.push('users-sudo', 'ssh-settings', 'auth-logs', 'listening-ports');

        el.symptomResultContent.innerHTML = '';
        for (const cid of checksToRun) {
          const cDef = checksCache.find(c => c.id === cid) || { id: cid, title: cid, role: 'investigation', description: cid };
          const res = await fetch(`/api/v1/checks/${encodeURIComponent(cid)}/run`, {
            method: 'POST',
            headers: getHeaders(),
          });
          if (res.ok) {
            const data = await res.json();
            const card = renderCheckCard(cDef, data);
            card.open = true;
            el.symptomResultContent.appendChild(card);
          }
        }
      } catch (err) {
        el.symptomResultContent.innerHTML = `<div style="color: var(--rose);">Symptom investigation failed: ${err.message}</div>`;
      }
    });
  });

  if (el.symptomCloseBtn) {
    el.symptomCloseBtn.addEventListener('click', () => {
      el.symptomResultPanel.style.display = 'none';
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
      el.topHostBadge.innerHTML = `HOST: <span style="color: var(--cyan);">${v.identity_line}</span>`;
    }
    if (el.topVerdictBadge) {
      let bClass = 'badge-mint';
      let glyph = '[✓]';
      if (v.state_label === 'CRITICAL') { bClass = 'badge-rose'; glyph = '[▲]'; }
      else if (v.state_label === 'MESSY' || v.state_label === 'WARN') { bClass = 'badge-peach'; glyph = '[!]'; }
      else if (v.state_label === 'PARTIAL' || v.state_label === 'UNKNOWN') { bClass = 'badge-lavender'; glyph = '[?]'; }

      el.topVerdictBadge.className = `badge ${bClass}`;
      el.topVerdictBadge.textContent = `${glyph} ${v.state_label || 'CALM'}`;
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
    if (el.chaosScore) {
      el.chaosScore.textContent = v.chaos_index !== undefined ? v.chaos_index : 0;
    }

    let badgeClass = 'badge-mint';
    let glyph = '[✓]';
    if (v.state_label === 'CRITICAL' || v.chaos_index >= 70) {
      badgeClass = 'badge-rose'; glyph = '[▲]';
    } else if (v.state_label === 'MESSY' || v.chaos_index >= 45) {
      badgeClass = 'badge-peach'; glyph = '[!]';
    } else if (v.state_label === 'MODERATE' || v.chaos_index >= 16) {
      badgeClass = 'badge-lavender'; glyph = '[●]';
    } else if (v.state_label === 'PARTIAL' || v.state_label === 'UNKNOWN') {
      badgeClass = 'badge-cyan'; glyph = '[?]';
    }

    if (el.chaosBadge) {
      el.chaosBadge.className = `badge ${badgeClass}`;
      el.chaosBadge.textContent = `${glyph} ${v.state_label || 'CALM'}`;
    }
    if (el.identityLine) {
      el.identityLine.textContent = `HOST: ${v.identity_line || 'Linux Server'}`;
    }

    if (el.dangerCount) {
      const totalRisks = (v.critical_findings || 0) + (v.high_findings || 0);
      el.dangerCount.textContent = `${totalRisks} active`;
      el.dangerCount.className = totalRisks > 0 ? 'badge badge-rose' : 'badge badge-mint';
    }

    if (el.wasteMonthly) {
      el.wasteMonthly.textContent = `$${(v.estimated_waste_usd_monthly || 0).toFixed(2)} / month`;
    }
  }

  // Refresh Briefing & Coverage
  async function refreshBriefing() {
    try {
      const res = await fetch('/api/v1/briefing', { headers: getHeaders() });
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

      const content = document.getElementById('briefing-content');
      if (content) {
        content.innerHTML = `
          <div style="font-weight: bold; font-size: 14px; margin-bottom: 8px;">${b.summary_sentence || ''}</div>
          <div style="display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--dim);">
            ${(b.bullet_points || []).map(bp => `<div>• ${bp}</div>`).join('')}
          </div>
          <div style="margin-top: 12px; font-size: 12px; color: var(--cyan); border-top: 1px dashed var(--panel-border); padding-top: 8px;">
            <div><strong>PROVENANCE & INTEGRITY:</strong> ${b.untracked_surface || ''}</div>
            <div style="margin-top: 4px;"><strong>CAPACITY FORECAST:</strong> ${b.exhaustion_headline || ''}</div>
          </div>
        `;
      }
    } catch (err) {
      console.error('failed fetching briefing:', err);
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
      if (!el.dangerList) return;

      el.dangerList.innerHTML = '';
      if (!findings || findings.length === 0) {
        el.dangerList.innerHTML = '<div style="color: var(--mint);">[✓] No critical exposures detected.</div>';
        return;
      }

      findings.forEach(f => {
        const row = document.createElement('div');
        row.style.fontSize = '12px';
        row.style.display = 'flex';
        row.style.justifyContent = 'space-between';
        row.style.borderBottom = '1px dashed var(--panel-border)';
        row.style.padding = '4px 0';
        row.innerHTML = `
          <span><strong>${f.id}</strong>: ${f.what}</span>
          <span class="badge ${f.severity === 'critical' ? 'badge-rose' : 'badge-peach'}">${f.severity.toUpperCase()}</span>
        `;
        el.dangerList.appendChild(row);
      });
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

        <div id="actuator-action-box" style="margin-top: 8px; padding: 12px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 4px;">
          <div style="color: var(--dim); font-size: 12px;">Checking for host actuator daemon...</div>
        </div>
      `;

      // Query Actuator daemon status
      try {
        const actRes = await fetch('/api/v1/actuator/status', { headers: getHeaders() });
        const actData = await actRes.json();
        const actionBox = document.getElementById('actuator-action-box');
        if (!actionBox) return;

        if (actData.available) {
          actionBox.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 8px;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="color: var(--mint); font-weight: bold;">[✓] Actuator Active (${actData.socket})</span>
                <span class="badge badge-lavender">Requires Approver Signature</span>
              </div>
              <div style="font-size: 12px; color: var(--dim);">
                Target host confirmation required. Type host name <code id="confirm-hostname-target">${window.location.hostname || 'localhost'}</code> to unlock:
              </div>
              <div style="display: flex; gap: 8px; align-items: center;">
                <input type="text" id="confirm-hostname-input" placeholder="Type host name to confirm" style="background: var(--surface-1); border: 1px solid var(--border); color: var(--fg); padding: 4px 8px; font-family: monospace; border-radius: 4px; font-size: 12px; flex: 1;" />
                <button id="submit-plan-apply-btn" disabled style="background: var(--surface-1); border: 1px solid var(--border); color: var(--dim); padding: 4px 12px; font-family: monospace; border-radius: 4px; cursor: not-allowed;">Submit to Actuator</button>
              </div>
            </div>
          `;

          const input = document.getElementById('confirm-hostname-input');
          const btn = document.getElementById('submit-plan-apply-btn');
          const target = (window.location.hostname || 'localhost').trim();

          input?.addEventListener('input', () => {
            if (input.value.trim() === target) {
              btn.disabled = false;
              btn.style.borderColor = 'var(--mint)';
              btn.style.color = 'var(--mint)';
              btn.style.cursor = 'pointer';
            } else {
              btn.disabled = true;
              btn.style.borderColor = 'var(--border)';
              btn.style.color = 'var(--dim)';
              btn.style.cursor = 'not-allowed';
            }
          });
        } else {
          actionBox.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="color: var(--dim); font-size: 12px;">Actuator daemon not detected on unix socket. Mutations disabled (Principle 2').</div>
              <button disabled title="Actuator not enabled" style="background: var(--surface-1); border: 1px solid var(--border); color: var(--dim); padding: 4px 12px; font-family: monospace; border-radius: 4px; cursor: not-allowed; opacity: 0.6;">Apply with approval (Actuator offline)</button>
            </div>
          `;
        }
      } catch (_) {
        // Leave disabled box
      }
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
    refreshBriefing();
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

  // Startup Initializer
  handleRoute();
  loadChecks();
  refreshAll();
  initSSE();

  setInterval(() => {
    refreshVerdict();
    refreshPulse();
    refreshBriefing();
  }, 5000);

})();

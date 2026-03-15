function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function riskClass(riskLabel) {
  if (riskLabel === 'CRITICAL' || riskLabel === 'HIGH') return 'danger';
  if (riskLabel === 'MEDIUM') return 'warning';
  return 'success';
}

const filterState = {
  search: '',
  category: 'all',
  status: 'all',
  suspiciousOnly: false,
  weakMismatchOnly: false
};

let latestResult = null;
let controlsInitialized = false;

function evidencePreview(evidence) {
  if (evidence === null || evidence === undefined) return 'n/a';
  if (typeof evidence === 'string') return evidence.slice(0, 90);
  if (typeof evidence === 'number' || typeof evidence === 'boolean') return String(evidence);
  if (Array.isArray(evidence)) return evidence.slice(0, 3).join(', ');
  return JSON.stringify(evidence).slice(0, 90);
}

function statusLabel(signal) {
  if (signal.state === 'unavailable') return 'UNAVAILABLE';
  if (signal.state === 'error') return 'ERROR';
  return signal.value ? 'SUSPICIOUS' : 'OK';
}

function matchesText(signal, text) {
  if (!text) return true;
  const haystack = [
    signal.key,
    signal.label,
    signal.category,
    signal.severity,
    JSON.stringify(signal.evidence)
  ].join(' ').toLowerCase();

  return haystack.includes(text);
}

function filteredSignals(signals) {
  return signals.filter(signal => {
    if (!matchesText(signal, filterState.search)) return false;
    if (filterState.category !== 'all' && signal.category !== filterState.category) return false;

    const computedStatus = signal.state === 'unavailable'
      ? 'unavailable'
      : signal.state === 'error'
        ? 'error'
        : signal.value
          ? 'suspicious'
          : 'ok';

    if (filterState.status !== 'all' && computedStatus !== filterState.status) return false;
    if (filterState.suspiciousOnly && !signal.value) return false;
    return true;
  });
}

function filteredWeakChecks(weakChecks) {
  if (!filterState.weakMismatchOnly) return weakChecks;
  return weakChecks.filter(check => !check.ok && check.state !== 'unavailable');
}

function updateKpis(result) {
  const summary = result.summary || {};

  const risk = document.getElementById('kpiRisk');
  const action = document.getElementById('kpiAction');
  const confidence = document.getElementById('kpiConfidence');
  const strong = document.getElementById('kpiStrong');
  const weak = document.getElementById('kpiWeak');
  const elapsed = document.getElementById('kpiElapsed');

  if (risk) risk.textContent = result.riskLabel;
  if (action) action.textContent = result.action;
  if (confidence) confidence.textContent = `${result.confidence}%`;
  if (strong) strong.textContent = `${summary.strongHits || 0}/${summary.strongTotal || 0}`;
  if (weak) weak.textContent = `${summary.weakMismatchCount || 0}/${summary.weakTotal || 0}`;
  if (elapsed) elapsed.textContent = `${result.elapsedMs} ms`;
}

function renderCategoryBreakdown(result) {
  const table = document.getElementById('categoryTable');
  if (!table) return;

  table.innerHTML = '<tr><th>Category</th><th>Score</th><th>Status</th></tr>';
  Object.entries(result.categoryBreakdown || {}).forEach(([category, score]) => {
    const row = table.insertRow();
    const status = score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low';
    const cssClass = status === 'high' ? 'danger' : status === 'medium' ? 'warning' : 'success';
    row.innerHTML = `
      <td>${escapeHtml(category)}</td>
      <td>
        <div class="score-cell">
          <span>${escapeHtml(score.toFixed(1))}</span>
          <div class="score-bar"><span style="width:${Math.max(0, Math.min(100, score)).toFixed(1)}%"></span></div>
        </div>
      </td>
      <td class="${cssClass}">${escapeHtml(status.toUpperCase())}</td>
    `;
  });
}

function renderExplanations(result) {
  const list = document.getElementById('explanationsList');
  if (!list) return;

  list.innerHTML = '';
  const explanations = result.explanations || [];
  if (!explanations.length) {
    const item = document.createElement('li');
    item.textContent = 'No suspicious signal cluster detected.';
    list.appendChild(item);
    return;
  }

  explanations.forEach(explanation => {
    const item = document.createElement('li');
    item.textContent = explanation;
    list.appendChild(item);
  });
}

function renderSummaryCard(result) {
  const node = document.getElementById('summaryCard');
  if (!node) return;

  const summary = result.summary || {};
  node.innerHTML = `
    <div><b>Detector:</b> ${escapeHtml(result.detectorVersion)} | <b>Schema:</b> ${escapeHtml(result.schemaVersion)}</div>
    <div><b>Run ID:</b> ${escapeHtml(result.runId)}</div>
    <div><b>Score:</b> ${escapeHtml(String(result.score100))}/100 (${escapeHtml(String(result.botScore))}/25) | <b>Confidence:</b> ${escapeHtml(String(result.confidence))}%</div>
    <div><b>Hard hits:</b> ${escapeHtml(String(summary.hardHits || 0))} | <b>Soft hits:</b> ${escapeHtml(String(summary.softHits || 0))}</div>
    <div><b>Unavailable signals:</b> ${escapeHtml(String(summary.unavailableSignals || 0))}</div>
    <div><b>Checksum:</b> <code>${escapeHtml(result.checksum || '')}</code></div>
  `;
}

function renderEvidence(signal) {
  const output = document.getElementById('evidenceOutput');
  if (!output) return;

  output.textContent = JSON.stringify({
    key: signal.key,
    label: signal.label,
    state: signal.state,
    value: signal.value,
    category: signal.category,
    severity: signal.severity,
    evidence: signal.evidence
  }, null, 2);
}

function renderSignalTable(result) {
  const table = document.getElementById('strongTable');
  if (!table) return;

  const signals = filteredSignals(result.signals)
    .sort((a, b) => {
      if (a.value === b.value) return (b.weight * b.confidence) - (a.weight * a.confidence);
      return a.value ? -1 : 1;
    });

  table.innerHTML = '<tr><th>Signal</th><th>Category</th><th>Status</th><th>Score</th><th>Evidence</th></tr>';

  signals.forEach((signal, index) => {
    const row = table.insertRow();
    const label = statusLabel(signal);
    const cssClass = signal.state === 'unavailable'
      ? 'warning'
      : signal.state === 'error'
        ? 'danger'
        : signal.value
          ? 'danger'
          : 'success';

    row.innerHTML = `
      <td>
        ${escapeHtml(signal.label)}
        <small>(${escapeHtml(signal.key)}, ${escapeHtml(signal.severity)})</small>
      </td>
      <td><span class="chip">${escapeHtml(signal.category)}</span></td>
      <td class="${cssClass}">${escapeHtml(label)}</td>
      <td>${escapeHtml(String(signal.weight))} × ${escapeHtml(String(signal.confidence))}</td>
      <td>
        <div class="evidence-cell">${escapeHtml(evidencePreview(signal.evidence))}</div>
        <button type="button" class="mini-btn" data-signal-index="${index}">Inspect</button>
      </td>
    `;
  });

  // Use event delegation on the table
  table.removeEventListener('click', handleInspectClick);
  table.addEventListener('click', handleInspectClick);

  function handleInspectClick(event) {
    const button = event.target.closest('button[data-signal-index]');
    if (!button) return;

    const index = parseInt(button.getAttribute('data-signal-index'), 10);
    const signal = signals[index];
    if (signal) renderEvidence(signal);
  }

  const meta = document.getElementById('signalFilterMeta');
  if (meta) {
    meta.textContent = `Showing ${signals.length} of ${result.signals.length} signals`;
  }
}

function renderWeakTable(result) {
  const table = document.getElementById('weakTable');
  if (!table) return;

  const weakChecks = filteredWeakChecks(result.weakChecks);

  table.innerHTML = '<tr><th>Check</th><th>Status</th><th>Category</th></tr>';
  weakChecks.forEach(check => {
    const row = table.insertRow();
    const text = check.state === 'unavailable' ? 'UNAVAILABLE' : check.ok ? 'CONSISTENT' : 'MISMATCH';
    const cssClass = check.state === 'unavailable' ? 'warning' : check.ok ? 'success' : 'warning';
    row.innerHTML = `
      <td>${escapeHtml(check.label)} <small>(${escapeHtml(check.key)})</small></td>
      <td class="${cssClass}">${escapeHtml(text)}</td>
      <td><span class="chip">${escapeHtml(check.category || 'consistency')}</span></td>
    `;
  });
}

function ensureCategoryFilterOptions(result) {
  const select = document.getElementById('signalCategoryFilter');
  if (!select) return;

  const categories = Array.from(new Set(result.signals.map(signal => signal.category))).sort();
  const prior = filterState.category;

  select.innerHTML = '<option value="all">All categories</option>';
  categories.forEach(category => {
    const option = document.createElement('option');
    option.value = category;
    option.textContent = category;
    select.appendChild(option);
  });

  if (categories.includes(prior)) {
    select.value = prior;
  } else {
    select.value = 'all';
    filterState.category = 'all';
  }
}

function bindControls() {
  if (controlsInitialized) return;
  controlsInitialized = true;

  const searchInput = document.getElementById('signalSearchInput');
  const categoryFilter = document.getElementById('signalCategoryFilter');
  const statusFilter = document.getElementById('signalStatusFilter');
  const suspiciousOnlyToggle = document.getElementById('suspiciousOnlyToggle');
  const weakMismatchOnlyToggle = document.getElementById('weakMismatchOnlyToggle');
  const clearFilters = document.getElementById('clearSignalFiltersBtn');
  const copyJsonBtn = document.getElementById('copyJsonBtn');
  const downloadJsonBtn = document.getElementById('downloadJsonBtn');
  const toggleJsonBtn = document.getElementById('toggleJsonBtn');

  const rerender = () => {
    if (!latestResult) return;
    renderSignalTable(latestResult);
    renderWeakTable(latestResult);
  };

  if (searchInput) {
    searchInput.addEventListener('input', event => {
      filterState.search = String(event.target.value || '').trim().toLowerCase();
      rerender();
    });
  }

  if (categoryFilter) {
    categoryFilter.addEventListener('change', event => {
      filterState.category = event.target.value || 'all';
      rerender();
    });
  }

  if (statusFilter) {
    statusFilter.addEventListener('change', event => {
      filterState.status = event.target.value || 'all';
      rerender();
    });
  }

  if (suspiciousOnlyToggle) {
    suspiciousOnlyToggle.addEventListener('change', event => {
      filterState.suspiciousOnly = !!event.target.checked;
      rerender();
    });
  }

  if (weakMismatchOnlyToggle) {
    weakMismatchOnlyToggle.addEventListener('change', event => {
      filterState.weakMismatchOnly = !!event.target.checked;
      rerender();
    });
  }

  if (clearFilters) {
    clearFilters.addEventListener('click', () => {
      filterState.search = '';
      filterState.category = 'all';
      filterState.status = 'all';
      filterState.suspiciousOnly = false;
      filterState.weakMismatchOnly = false;

      if (searchInput) searchInput.value = '';
      if (categoryFilter) categoryFilter.value = 'all';
      if (statusFilter) statusFilter.value = 'all';
      if (suspiciousOnlyToggle) suspiciousOnlyToggle.checked = false;
      if (weakMismatchOnlyToggle) weakMismatchOnlyToggle.checked = false;
      rerender();
    });
  }

  if (copyJsonBtn) {
    copyJsonBtn.addEventListener('click', async () => {
      if (!latestResult || !navigator.clipboard) return;
      try {
        await navigator.clipboard.writeText(JSON.stringify(latestResult, null, 2));
        copyJsonBtn.textContent = 'Copied';
      } catch (error) {
        copyJsonBtn.textContent = 'Clipboard blocked';
      }
      setTimeout(() => {
        copyJsonBtn.textContent = 'Copy JSON';
      }, 1100);
    });
  }

  if (downloadJsonBtn) {
    downloadJsonBtn.addEventListener('click', () => {
      if (!latestResult) return;
      const blob = new Blob([JSON.stringify(latestResult, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `anti-bot-result-${latestResult.runId || Date.now()}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    });
  }

  if (toggleJsonBtn) {
    toggleJsonBtn.addEventListener('click', () => {
      const panel = document.getElementById('jsonPanel');
      if (!panel) return;
      panel.open = !panel.open;
      toggleJsonBtn.textContent = panel.open ? 'Hide JSON' : 'Show JSON';
    });
  }
}

export function renderResults(result) {
  latestResult = result;
  bindControls();
  ensureCategoryFilterOptions(result);

  const scoreSection = document.getElementById('scoreSection');
  if (scoreSection) scoreSection.style.display = 'grid';

  const botScore = document.getElementById('botScore');
  if (botScore) botScore.textContent = `${result.botScore} (${result.score100}/100)`;

  const labelClass = riskClass(result.riskLabel);
  const riskLevel = document.getElementById('riskLevel');
  if (riskLevel) {
    riskLevel.innerHTML = `<span class="${labelClass}">${escapeHtml(result.riskLabel)} RISK</span> | Action: <b>${escapeHtml(result.action)}</b> | Confidence: ${escapeHtml(String(result.confidence))}%`;
  }

  updateKpis(result);
  renderSignalTable(result);
  renderWeakTable(result);
  renderCategoryBreakdown(result);
  renderExplanations(result);
  renderSummaryCard(result);

  const output = document.getElementById('jsonOutput');
  if (output) output.textContent = JSON.stringify(result, null, 2);

  const jsonPanel = document.getElementById('jsonPanel');
  if (jsonPanel && !jsonPanel.open) {
    const toggle = document.getElementById('toggleJsonBtn');
    if (toggle) toggle.textContent = 'Show JSON';
  }

  // Dispatch event to notify that results have been rendered
  if (typeof window !== 'undefined') {
    const event = new CustomEvent('resultsRendered', { detail: result });
    window.dispatchEvent(event);
  }
}

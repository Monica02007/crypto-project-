import { escapeHtml, formatPercent, getVerdictTheme, icons } from './utils.js';

export function renderHistoryView(container, state, handlers) {
  const { history, historySearchQuery } = state;

  const q = historySearchQuery.trim().toLowerCase();
  const filtered = q
    ? history.filter(
        (h) =>
          h.normalizedUrl.toLowerCase().includes(q) ||
          h.sha256.toLowerCase().includes(q) ||
          h.verdictLabel.toLowerCase().includes(q)
      )
    : history;

  let contentHtml = '';
  if (filtered.length === 0) {
    contentHtml = `
      <div class="alert-info empty-state" style="border-radius:var(--radius-md);border:1px solid var(--border);">
        ${
          history.length === 0
            ? 'No URLs have been analyzed yet. Submit a URL in the Pipeline Analyzer view to populate the audit log.'
            : 'No history records match your search query.'
        }
      </div>
    `;
  } else {
    const rows = filtered
      .map((entry, idx) => {
        const theme = getVerdictTheme(entry.verdict);
        const hashLabel =
          entry.hashStatus === 'MATCH'
            ? `<span class="tone-danger" style="font-weight:700;">MATCH (${escapeHtml(entry.sha256.slice(0, 10))}...)</span>`
            : `<span>MISS (${escapeHtml(entry.sha256.slice(0, 10))}...)</span>`;

        return `
          <tr>
            <td class="font-mono tabular-nums" style="color:var(--text-muted);white-space:nowrap;">${escapeHtml(new Date(entry.analyzedAt).toLocaleString())}</td>
            <td class="font-mono truncate-cell" title="${escapeHtml(entry.normalizedUrl)}">${escapeHtml(entry.normalizedUrl)}</td>
            <td class="font-mono" style="color:var(--text-secondary);white-space:nowrap;">${hashLabel}</td>
            <td class="font-mono text-right tabular-nums" style="font-weight:600;white-space:nowrap;">${formatPercent(entry.riskScore)}</td>
            <td class="${theme.toneClass}" style="font-weight:600;white-space:nowrap;">${escapeHtml(entry.verdictLabel)}</td>
            <td class="text-right" style="white-space:nowrap;">
              <button type="button" class="btn-table-action" data-inspect-id="${escapeHtml(entry.id)}" data-idx="${idx}">
                ${icons.eye}
                <span>Inspect</span>
              </button>
            </td>
          </tr>
        `;
      })
      .join('');

    contentHtml = `
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Normalized URL</th>
              <th>Module 1 Hash</th>
              <th class="text-right">Risk Score</th>
              <th>Final Verdict</th>
              <th class="text-right">Report</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    `;
  }

  container.innerHTML = `
    <section class="card card-padded stack-lg" style="gap:16px;">
      <div class="section-head-row" style="border-bottom:none;padding-bottom:0;margin-bottom:0;">
        <div>
          <h2 class="section-title">URL Scan Audit History</h2>
          <p class="section-desc tabular-nums">${history.length} recorded analyses across Module 1 and Module 2</p>
        </div>

        <div class="toolbar-inline">
          <div class="input-search-wrap" style="flex:0 0 auto;">
            <span class="input-search-icon" style="left:10px;">${icons.searchSm}</span>
            <input id="history-search-input" type="text" class="input-compact-search" value="${escapeHtml(historySearchQuery)}" placeholder="Search URL, hash, or verdict..." />
          </div>

          ${
            history.length > 0
              ? `<button type="button" id="clear-history-btn" class="btn btn-secondary btn-sm">${icons.trash}<span>Clear History</span></button>`
              : ''
          }
        </div>
      </div>

      ${contentHtml}
    </section>
  `;

  container.querySelector('#history-search-input')?.addEventListener('input', (e) => {
    handlers.onSearchHistory(e.target.value);
  });

  container.querySelector('#clear-history-btn')?.addEventListener('click', () => {
    handlers.onClearHistory();
  });

  container.querySelectorAll('[data-inspect-id]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-inspect-id');
      const found = history.find((h) => h.id === id);
      if (found) {
        handlers.onInspect(found.result);
      }
    });
  });
}

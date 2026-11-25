import { normalizeUrl } from '../core/normalizer.js';
import { escapeHtml, icons } from './utils.js';

export function renderThreatLedgerView(container, state, handlers) {
  const {
    threats,
    threatForm,
    threatFilterMode,
    threatSearchQuery,
    threatSubmitting,
    threatFormError,
    copiedThreatHash,
  } = state;

  const q = threatSearchQuery.trim().toLowerCase();
  const filtered = threats.filter((item) => {
    if (threatFilterMode === 'seeded' && !item.isSeeded) return false;
    if (threatFilterMode === 'custom' && item.isSeeded) return false;
    if (!q) return true;
    return (
      item.sha256.toLowerCase().includes(q) ||
      item.normalizedUrl.toLowerCase().includes(q) ||
      item.source.toLowerCase().includes(q) ||
      item.category.toLowerCase().includes(q) ||
      (item.targetBrand ?? '').toLowerCase().includes(q)
    );
  });

  const seededCount = threats.filter((t) => t.isSeeded).length;
  const customCount = threats.length - seededCount;

  const previewHtml = (() => {
    if (threatForm.entryMode !== 'url' || !threatForm.newUrl.trim()) return '';
    const norm = normalizeUrl(threatForm.newUrl);
    return norm.valid
      ? `<p id="live-norm-preview" class="font-mono" style="margin-top:6px;font-size:12px;color:var(--text-secondary);">Canonical preview: ${escapeHtml(norm.normalizedUrl)}</p>`
      : `<p id="live-norm-preview" class="font-mono" style="margin-top:6px;font-size:12px;color:var(--danger-dark);">Preview error: ${escapeHtml(norm.error)}</p>`;
  })();

  const tableRowsHtml =
    filtered.length === 0
      ? `<tr><td colspan="4" class="empty-state">No threat hash entries match your current filter.</td></tr>`
      : filtered
          .map(
            (item) => `
              <tr>
                <td class="truncate-cell">
                  <div class="font-mono" style="color:var(--text-primary);" title="${escapeHtml(item.normalizedUrl)}">${escapeHtml(item.normalizedUrl)}</div>
                  <div style="color:var(--text-muted);margin-top:2px;">
                    ${item.targetBrand ? `Target: ${escapeHtml(item.targetBrand)} · ` : ''}
                    ${item.isSeeded ? 'Starter Seed' : 'Custom Entry'}
                  </div>
                </td>
                <td class="font-mono" style="color:var(--text-secondary);white-space:nowrap;">
                  <div style="display:inline-flex;align-items:center;gap:8px;">
                    <span>${escapeHtml(item.sha256.slice(0, 18))}...${escapeHtml(item.sha256.slice(-8))}</span>
                    <button type="button" class="btn-link" data-copy-threat="${escapeHtml(item.sha256)}" title="Copy full SHA-256">
                      ${copiedThreatHash === item.sha256 ? `<span class="tone-success">${icons.check}</span>` : icons.copy}
                    </button>
                  </div>
                </td>
                <td style="white-space:nowrap;">
                  <div>${escapeHtml(item.source)}</div>
                  <div style="color:var(--text-muted);">${escapeHtml(item.category)}</div>
                </td>
                <td class="text-right" style="white-space:nowrap;">
                  <div style="display:inline-flex;align-items:center;gap:6px;">
                    ${
                      item.normalizedUrl.startsWith('http')
                        ? `<button type="button" class="btn-table-action" data-test-threat="${escapeHtml(item.normalizedUrl)}">${icons.play}<span>Test</span></button>`
                        : ''
                    }
                    <button type="button" class="btn-icon-danger" data-delete-threat="${escapeHtml(item.sha256)}" title="Remove entry">
                      ${icons.trash}
                    </button>
                  </div>
                </td>
              </tr>
            `
          )
          .join('');

  container.innerHTML = `
    <div class="stack-lg">
      <section class="card card-padded">
        <div class="section-head-row" style="border-bottom:none;padding-bottom:0;margin-bottom:16px;">
          <div>
            <h2 class="section-title">Add Known-Threat SHA-256 Entry</h2>
            <p class="section-desc">Seed custom phishing URLs (normalized &amp; SHA-256 hashed automatically) or raw 64-character SHA-256 digests for testing Module 1.</p>
          </div>
          <div class="segmented-group">
            <button type="button" class="segmented-btn ${threatForm.entryMode === 'url' ? 'active' : ''}" data-entry-mode="url">Add by URL</button>
            <button type="button" class="segmented-btn ${threatForm.entryMode === 'hash' ? 'active' : ''}" data-entry-mode="hash">Add Raw SHA-256</button>
          </div>
        </div>

        <form id="threat-add-form" class="stack-lg" style="gap:16px;">
          <div class="form-grid-2">
            <div class="col-span-2">
              <label class="field-label" for="threat-primary-input">
                ${
                  threatForm.entryMode === 'url'
                    ? 'Phishing URL (will be normalized before SHA-256 hashing)'
                    : 'SHA-256 Hex Digest (64 hexadecimal characters)'
                }
              </label>
              <input
                id="threat-primary-input"
                type="text"
                class="input-field font-mono"
                value="${escapeHtml(threatForm.entryMode === 'url' ? threatForm.newUrl : threatForm.newHash)}"
                placeholder="${threatForm.entryMode === 'url' ? 'http://malicious-login-portal.example.com/signin' : '64-character SHA-256 hex digest...'}"
                required
              />
              <div id="live-norm-container">${previewHtml}</div>
            </div>

            <div>
              <label class="field-label" for="threat-source-input">Feed / Source Label</label>
              <input id="threat-source-input" type="text" class="input-field" value="${escapeHtml(threatForm.newSource)}" />
            </div>

            <div class="form-grid-2" style="gap:12px;">
              <div>
                <label class="field-label" for="threat-category-input">Threat Category</label>
                <input id="threat-category-input" type="text" class="input-field" value="${escapeHtml(threatForm.newCategory)}" />
              </div>
              <div>
                <label class="field-label" for="threat-brand-input">Target Brand (Optional)</label>
                <input id="threat-brand-input" type="text" class="input-field" value="${escapeHtml(threatForm.newBrand)}" placeholder="e.g. Microsoft, PayPal" />
              </div>
            </div>
          </div>

          ${
            threatFormError
              ? `<div class="alert-box alert-error" style="margin-top:0;">${escapeHtml(threatFormError)}</div>`
              : ''
          }

          <div style="display:flex;justify-content:flex-end;">
            <button type="submit" class="btn btn-primary btn-sm" ${threatSubmitting ? 'disabled' : ''}>
              ${icons.plus}
              <span>${threatSubmitting ? 'Saving...' : 'Add to Threat Database'}</span>
            </button>
          </div>
        </form>
      </section>

      <section class="card card-padded">
        <div class="section-head-row" style="border-bottom:none;padding-bottom:0;margin-bottom:16px;">
          <div>
            <h3 class="section-title">Known-Threat SHA-256 Hash Database</h3>
            <p class="section-desc tabular-nums">${threats.length} total entries · ${seededCount} starter seed · ${customCount} custom</p>
          </div>

          <div class="toolbar-inline">
            <div class="input-search-wrap" style="flex:0 0 auto;">
              <span class="input-search-icon" style="left:10px;">${icons.searchSm}</span>
              <input id="threat-search-input" type="text" class="input-compact-search" value="${escapeHtml(threatSearchQuery)}" placeholder="Filter by URL, hash, or brand..." />
            </div>

            <div class="segmented-group">
              <button type="button" class="segmented-btn ${threatFilterMode === 'all' ? 'active' : ''}" data-filter-mode="all">All</button>
              <button type="button" class="segmented-btn ${threatFilterMode === 'seeded' ? 'active' : ''}" data-filter-mode="seeded">Seeded</button>
              <button type="button" class="segmented-btn ${threatFilterMode === 'custom' ? 'active' : ''}" data-filter-mode="custom">Custom</button>
            </div>

            <button type="button" id="reset-seed-btn" class="btn btn-secondary btn-sm">
              ${icons.rotateCcw}
              <span>Reset Starter Seed</span>
            </button>
          </div>
        </div>

        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Normalized URL / Label</th>
                <th>SHA-256 Digest</th>
                <th>Source &amp; Category</th>
                <th class="text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="threat-table-body">${tableRowsHtml}</tbody>
          </table>
        </div>
      </section>
    </div>
  `;

  // Wire listeners
  container.querySelectorAll('[data-entry-mode]').forEach((btn) => {
    btn.addEventListener('click', () => {
      handlers.onThreatFormChange({ entryMode: btn.getAttribute('data-entry-mode') }, true);
    });
  });

  const primaryInput = container.querySelector('#threat-primary-input');
  const normContainer = container.querySelector('#live-norm-container');
  if (primaryInput) {
    primaryInput.addEventListener('input', (e) => {
      const val = e.target.value;
      if (threatForm.entryMode === 'url') {
        handlers.onThreatFormChange({ newUrl: val }, false);
        if (normContainer) {
          if (!val.trim()) {
            normContainer.innerHTML = '';
          } else {
            const norm = normalizeUrl(val);
            normContainer.innerHTML = norm.valid
              ? `<p class="font-mono" style="margin-top:6px;font-size:12px;color:var(--text-secondary);">Canonical preview: ${escapeHtml(norm.normalizedUrl)}</p>`
              : `<p class="font-mono" style="margin-top:6px;font-size:12px;color:var(--danger-dark);">Preview error: ${escapeHtml(norm.error)}</p>`;
          }
        }
      } else {
        handlers.onThreatFormChange({ newHash: val }, false);
      }
    });
  }

  container.querySelector('#threat-source-input')?.addEventListener('input', (e) => {
    handlers.onThreatFormChange({ newSource: e.target.value }, false);
  });
  container.querySelector('#threat-category-input')?.addEventListener('input', (e) => {
    handlers.onThreatFormChange({ newCategory: e.target.value }, false);
  });
  container.querySelector('#threat-brand-input')?.addEventListener('input', (e) => {
    handlers.onThreatFormChange({ newBrand: e.target.value }, false);
  });

  container.querySelector('#threat-add-form')?.addEventListener('submit', (e) => {
    e.preventDefault();
    handlers.onSubmitThreat();
  });

  const searchInput = container.querySelector('#threat-search-input');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      handlers.onSearchThreat(e.target.value);
    });
  }

  container.querySelectorAll('[data-filter-mode]').forEach((btn) => {
    btn.addEventListener('click', () => {
      handlers.onFilterThreat(btn.getAttribute('data-filter-mode'));
    });
  });

  container.querySelector('#reset-seed-btn')?.addEventListener('click', () => {
    handlers.onResetSeed();
  });

  container.querySelectorAll('[data-copy-threat]').forEach((btn) => {
    btn.addEventListener('click', () => {
      handlers.onCopyThreatHash(btn.getAttribute('data-copy-threat'));
    });
  });

  container.querySelectorAll('[data-test-threat]').forEach((btn) => {
    btn.addEventListener('click', () => {
      handlers.onTestInAnalyzer(btn.getAttribute('data-test-threat'));
    });
  });

  container.querySelectorAll('[data-delete-threat]').forEach((btn) => {
    btn.addEventListener('click', () => {
      handlers.onDeleteThreat(btn.getAttribute('data-delete-threat'));
    });
  });
}

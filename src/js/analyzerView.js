import { renderGaugeHtml } from './gauge.js';
import { escapeHtml, formatPercent, getVerdictTheme, icons } from './utils.js';

const QUICK_SAMPLES = [
  {
    label: 'Known Threat (Hash Match)',
    url: 'http://login-secure-bank.xyz/update',
  },
  {
    label: 'Formatting Variant',
    url: '  HTTP://Login-Secure-Bank.XYZ:80/update/  ',
  },
  {
    label: 'Novel Phishing (ML)',
    url: 'http://198.51.100.42/auth//microsoft-office365-secure-login/verify?session=94820194&redirect=http://evil.example',
  },
  {
    label: 'Legitimate URL',
    url: 'https://github.com/settings/security?tab=sessions',
  },
];

function buildSignalRows(result) {
  const f = result.module2.lexicalFeatures;
  const kws = result.module2.matchedKeywords;

  const kwRow =
    kws.length >= 2
      ? {
          label: 'Suspicious Keywords',
          detail: kws.slice(0, 3).join(', '),
          status: 'High',
          toneClass: 'tone-danger',
          barClass: 'bg-danger',
          barPct: 90,
        }
      : kws.length === 1
        ? {
            label: 'Suspicious Keywords',
            detail: kws[0],
            status: 'Elevated',
            toneClass: 'tone-danger',
            barClass: 'bg-danger',
            barPct: 72,
          }
        : {
            label: 'Suspicious Keywords',
            detail: 'No lure terms matched',
            status: 'Clear',
            toneClass: 'tone-success',
            barClass: 'bg-success',
            barPct: 12,
          };

  const anomalyScore =
    f.hyphenCount + f.atSymbolPresent * 3 + f.doubleSlashRedirect * 3 + f.hasIpAddress * 3;
  const anomalyRow =
    anomalyScore >= 3 || f.hyphenCount >= 2
      ? {
          label: 'Lexical Anomalies',
          detail: `${f.hyphenCount} hyphens · ${f.specialCharCount} special chars`,
          status: 'High',
          toneClass: 'tone-danger',
          barClass: 'bg-danger',
          barPct: 86,
        }
      : anomalyScore >= 1
        ? {
            label: 'Lexical Anomalies',
            detail: `${f.hyphenCount} hyphens · ${f.dotCount} dots`,
            status: 'Moderate',
            toneClass: 'tone-warning',
            barClass: 'bg-warning',
            barPct: 52,
          }
        : {
            label: 'Lexical Anomalies',
            detail: `${f.hyphenCount} hyphens · ${f.dotCount} dots`,
            status: 'Normal',
            toneClass: 'tone-success',
            barClass: 'bg-success',
            barPct: 14,
          };

  const hostRow =
    f.hasIpAddress === 1 || f.subdomainDepth >= 2 || f.shannonEntropy >= 4.1
      ? {
          label: f.hasIpAddress === 1 ? 'IP-Address Host' : 'Host & Subdomains',
          detail:
            f.hasIpAddress === 1
              ? 'Direct IP literal host'
              : `${f.subdomainDepth} subdomains · ${f.shannonEntropy.toFixed(2)} entropy`,
          status: 'High',
          toneClass: 'tone-danger',
          barClass: 'bg-danger',
          barPct: 88,
        }
      : f.subdomainDepth === 1 || f.hostnameLength > 24
        ? {
            label: 'Host & Subdomains',
            detail: `${f.hostnameLength} chars · ${f.shannonEntropy.toFixed(2)} entropy`,
            status: 'Moderate',
            toneClass: 'tone-warning',
            barClass: 'bg-warning',
            barPct: 54,
          }
        : {
            label: 'Host & Subdomains',
            detail: `${f.hostnameLength} chars · ${f.shannonEntropy.toFixed(2)} entropy`,
            status: 'Normal',
            toneClass: 'tone-success',
            barClass: 'bg-success',
            barPct: 16,
          };

  const httpsRow =
    f.isHttps === 1
      ? {
          label: 'Transport Security',
          detail: 'HTTPS scheme present',
          status: 'HTTPS',
          toneClass: 'tone-success',
          barClass: 'bg-success',
          barPct: 20,
        }
      : {
          label: 'Transport Security',
          detail: 'Unencrypted HTTP scheme',
          status: 'HTTP Only',
          toneClass: 'tone-danger',
          barClass: 'bg-danger',
          barPct: 78,
        };

  return [kwRow, anomalyRow, hostRow, httpsRow];
}

function renderEvidenceContent(result, evidenceTab) {
  if (evidenceTab === 'features') {
    const rows = result.module2.featureContributions
      .slice(0, 10)
      .map((feat) => {
        const isPhish = feat.contribution >= 0;
        const widthPct = Math.min(100, Math.max(6, Math.abs(feat.contribution) * 38));
        const barClass =
          feat.direction === 'neutral'
            ? 'bg-neutral'
            : isPhish
              ? 'bg-danger'
              : 'bg-success';
        const valClass =
          feat.direction === 'neutral'
            ? 'tone-muted'
            : isPhish
              ? 'tone-danger'
              : 'tone-success';
        return `
          <div class="contrib-row">
            <div>
              <span style="font-weight:500;">${escapeHtml(feat.label)}</span>
              <span class="font-mono" style="margin-left:8px;color:var(--text-muted);">${escapeHtml(feat.formattedValue)}</span>
            </div>
            <div class="contrib-meta">
              <div class="contrib-bar-track">
                <div class="${barClass}" style="height:100%;border-radius:999px;width:${widthPct}%;"></div>
              </div>
              <span class="contrib-val tabular-nums ${valClass}">
                ${feat.contribution >= 0 ? '+' : ''}${feat.contribution.toFixed(2)}
              </span>
            </div>
          </div>
        `;
      })
      .join('');

    return `<div class="contrib-grid">${rows}</div>`;
  }

  if (evidenceTab === 'ngrams') {
    const rows = result.module2.topNGrams
      .map(
        (ng) => `
          <tr>
            <td class="font-mono">${escapeHtml(ng.token)}</td>
            <td class="font-mono text-right tabular-nums" style="color:var(--text-secondary);">${ng.tfidfWeight.toFixed(3)}</td>
            <td class="font-mono text-right tabular-nums ${ng.direction === 'phishing' ? 'tone-danger' : 'tone-success'}" style="font-weight:600;">
              ${ng.logOdds >= 0 ? '+' : ''}${ng.logOdds.toFixed(2)}
            </td>
            <td class="text-right" style="color:var(--text-secondary);">
              ${ng.direction === 'phishing' ? 'Phishing' : 'Legitimate'}
            </td>
          </tr>
        `
      )
      .join('');

    return `
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Token / Character N-Gram</th>
              <th class="text-right">TF-IDF Weight</th>
              <th class="text-right">Class Log-Odds</th>
              <th class="text-right">Direction</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    `;
  }

  const normRows = result.module1.normalization.steps
    .map(
      (step) => `
        <tr>
          <td style="font-weight:500;white-space:nowrap;">${escapeHtml(step.rule)}</td>
          <td style="white-space:nowrap;">
            ${
              step.applied
                ? '<span style="font-weight:600;color:var(--accent);">Applied</span>'
                : '<span style="color:#94a3b8;">Unchanged</span>'
            }
          </td>
          <td class="font-mono" style="color:var(--text-secondary);">${escapeHtml(step.detail)}</td>
        </tr>
      `
    )
    .join('');

  return `
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>Normalization Rule</th>
            <th>Outcome</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>${normRows}</tbody>
      </table>
    </div>
  `;
}

export function renderAnalyzerView(container, state, handlers) {
  const {
    urlInput,
    analysisResult: result,
    modelReport,
    analyzing,
    analyzeError,
    addingThreat,
    threatAddedNotice,
    evidenceTab,
    copiedHash,
  } = state;

  const corpusBadge = modelReport
    ? `Ensemble Accuracy ${(modelReport.metrics.ensemble.accuracy * 100).toFixed(1)}% · Corpus ${modelReport.dataset.totalSamples} URLs`
    : '';

  const presetsHtml = QUICK_SAMPLES.map(
    (sample, idx) => `
      <button type="button" class="preset-btn" data-sample-idx="${idx}" ${analyzing ? 'disabled' : ''}>
        ${escapeHtml(sample.label)}
      </button>
    `
  ).join('');

  const errorHtml = analyzeError
    ? `<div role="alert" class="alert-box alert-error">${icons.fileWarning}<span>${escapeHtml(analyzeError)}</span></div>`
    : '';

  let module1Body = `<div class="empty-state">Enter a URL above to compute its normalized SHA-256 digest.</div>`;
  let module2Body = `<div class="empty-state">Awaiting URL input for ML scoring.</div>`;
  let module3Body = `<div class="empty-state">Combined risk verdict will appear here.</div>`;

  if (result) {
    const matchPanel = result.module1.matchedThreat
      ? `
        <div class="status-panel status-panel-danger">
          <div class="status-panel-title">${icons.shieldAlert}<span>Database Match Found: Known Threat</span></div>
          <p class="status-panel-text">Exact digest match in ${escapeHtml(result.module1.matchedThreat.source)} (${escapeHtml(result.module1.matchedThreat.category)}).</p>
        </div>
      `
      : `
        <div class="status-panel">
          <div class="status-panel-title">${icons.database}<span>Database Match: Hash Miss</span></div>
          <p class="status-panel-text">A hash mismatch does not guarantee safety. Normalized URL passed to Module 2 ML classifiers.</p>
          <div>
            <button type="button" id="seed-hash-btn" class="btn-link" ${addingThreat ? 'disabled' : ''}>
              ${icons.plus}
              <span>${addingThreat ? 'Adding...' : 'Seed Hash to Threat DB'}</span>
            </button>
          </div>
          ${
            threatAddedNotice
              ? `<div style="font-size:12px;font-weight:600;color:var(--success-dark);">${escapeHtml(threatAddedNotice)}</div>`
              : ''
          }
        </div>
      `;

    module1Body = `
      <div style="display:flex;flex-direction:column;gap:12px;">
        <div>
          <div class="field-label"><span>Normalized Canonical URL</span></div>
          <div class="norm-box">${escapeHtml(result.module1.normalization.normalizedUrl)}</div>
        </div>
        <div>
          <div class="field-label">
            <span class="field-label-inline">${icons.hash}<span>SHA-256 Fingerprint</span></span>
            <button type="button" id="copy-hash-btn" class="btn-link">
              ${copiedHash ? `${icons.check}<span>Copied</span>` : `${icons.copy}<span>Copy</span>`}
            </button>
          </div>
          <div class="hash-box">${escapeHtml(result.module1.sha256)}</div>
        </div>
      </div>
      ${matchPanel}
    `;

    const signals = buildSignalRows(result);
    const signalsHtml = signals
      .map(
        (sig) => `
          <div class="signal-row">
            <div class="signal-left">
              <div class="signal-name">${escapeHtml(sig.label)}</div>
              <div class="signal-detail" title="${escapeHtml(sig.detail)}">${escapeHtml(sig.detail)}</div>
            </div>
            <div class="signal-right">
              <div class="signal-status ${sig.toneClass}">${escapeHtml(sig.status)}</div>
              <div class="signal-bar-track">
                <div class="signal-bar-fill ${sig.barClass}" style="width:${sig.barPct}%;"></div>
              </div>
            </div>
          </div>
        `
      )
      .join('');

    module2Body = `
      ${renderGaugeHtml(result.module2.ensembleProbability)}
      <div class="dual-model-grid">
        <div class="mini-metric">
          <div class="mini-metric-head">
            <span class="mini-metric-label">TF-IDF MNB</span>
            <span class="mini-metric-val tabular-nums">${formatPercent(result.module2.mnbProbability)}</span>
          </div>
          <div class="progress-track">
            <div class="progress-fill" style="width:${Math.max(4, result.module2.mnbProbability * 100)}%;"></div>
          </div>
        </div>
        <div class="mini-metric">
          <div class="mini-metric-head">
            <span class="mini-metric-label">LogReg</span>
            <span class="mini-metric-val tabular-nums">${formatPercent(result.module2.logregProbability)}</span>
          </div>
          <div class="progress-track">
            <div class="progress-fill" style="width:${Math.max(4, result.module2.logregProbability * 100)}%;"></div>
          </div>
        </div>
      </div>
      <div class="signal-list">${signalsHtml}</div>
    `;

    const v = getVerdictTheme(result.module3.verdict);
    const verdictIcon = icons[v.iconName] ?? icons.shieldCheck;
    const hashCheckTone =
      result.module1.hashLookupStatus === 'MATCH' ? 'tone-danger' : 'tone-muted';

    module3Body = `
      <div class="verdict-banner ${v.bannerClass}">
        <div class="verdict-kicker">${verdictIcon}<span>Final Verdict</span></div>
        <div class="verdict-headline">${escapeHtml(v.headline)}</div>
        <div class="verdict-sub tabular-nums">${escapeHtml(result.module3.confidenceLabel)}</div>
      </div>

      <div class="verdict-checks">
        <div class="verdict-check-item">
          <span class="${hashCheckTone}">${icons.checkCircle}</span>
          <div>
            <div class="verdict-check-title">Deterministic Check</div>
            <p class="verdict-check-desc">
              ${
                result.module1.hashLookupStatus === 'MATCH'
                  ? `Exact SHA-256 match found in ${escapeHtml(result.module1.matchedThreat?.source)}. Immediate threat confirmed.`
                  : 'No exact SHA-256 match in known-threat database; decision delegated to Module 2 ML.'
              }
            </p>
          </div>
        </div>

        <div class="verdict-check-item">
          <span class="${v.toneClass}">${icons.checkCircle}</span>
          <div>
            <div class="verdict-check-title">Probabilistic ML Check</div>
            <p class="verdict-check-desc">
              Ensemble scored <strong class="font-mono" style="color:var(--text-primary);">${formatPercent(result.module2.ensembleProbability)}</strong> across character n-grams and 18 lexical features.
            </p>
          </div>
        </div>

        <div class="verdict-check-item">
          <span class="${v.toneClass}">${icons.shieldCheck}</span>
          <div>
            <div class="verdict-check-title">Recommendation</div>
            <p class="verdict-check-desc">${escapeHtml(v.recommendation)}</p>
          </div>
        </div>
      </div>

      <div class="disclaimer-box">
        ${icons.info}
        <span>Predictions are probabilistic estimates, not absolute guarantees. Novel attacks can evade checks and legitimate URLs may occasionally trigger alerts.</span>
      </div>
    `;
  }

  const evidenceHtml = result
    ? `
      <section class="card card-padded">
        <div class="section-head-row">
          <div>
            <h3 class="section-title">Explainable Evidence Breakdown</h3>
            <p class="section-desc">Inspect why the URL received its classification across normalization, structural weights, and n-grams.</p>
          </div>
          <div class="segmented-group" role="tablist" aria-label="Evidence tabs">
            <button type="button" class="segmented-btn ${evidenceTab === 'features' ? 'active' : ''}" data-evidence-tab="features">Lexical Triggers</button>
            <button type="button" class="segmented-btn ${evidenceTab === 'ngrams' ? 'active' : ''}" data-evidence-tab="ngrams">TF-IDF N-Grams</button>
            <button type="button" class="segmented-btn ${evidenceTab === 'normalization' ? 'active' : ''}" data-evidence-tab="normalization">Normalization Audit</button>
          </div>
        </div>
        ${renderEvidenceContent(result, evidenceTab)}
      </section>
    `
    : '';

  container.innerHTML = `
    <div class="stack-lg">
      <section class="card card-padded">
        <div class="command-top">
          <div>
            <h1 class="page-title">Hybrid Phishing Website Detection System</h1>
            <p class="page-subtitle">Deterministic SHA-256 cryptographic lookup paired with TF-IDF Naive Bayes and Logistic Regression scoring.</p>
          </div>
          ${corpusBadge ? `<div class="corpus-meta">${escapeHtml(corpusBadge)}</div>` : ''}
        </div>

        <form id="analyze-url-form" class="command-form">
          <div class="input-search-wrap">
            <label for="url-analyzer-input" class="sr-only">Enter Suspicious URL</label>
            <span class="input-search-icon">${icons.search}</span>
            <input
              id="url-analyzer-input"
              type="text"
              class="input-url"
              value="${escapeHtml(urlInput)}"
              placeholder="Enter suspicious URL (e.g., http://login-secure-bank.xyz/update)..."
            />
          </div>
          <button type="submit" class="btn btn-primary btn-lg" ${analyzing || !urlInput.trim() ? 'disabled' : ''}>
            <span>${analyzing ? 'Analyzing...' : 'Analyze URL'}</span>
            ${icons.arrowRight}
          </button>
        </form>

        <div class="preset-row">
          <span class="preset-label">Quick presets:</span>
          ${presetsHtml}
        </div>
        ${errorHtml}
      </section>

      <section class="pipeline-grid" aria-label="Three-module hybrid phishing detection pipeline">
        <article class="module-card">
          <header class="module-header">
            <h2 class="module-title">01. Cryptographic Hash Lookup</h2>
            <span class="module-tag">SHA-256</span>
          </header>
          <div class="module-body">${module1Body}</div>
        </article>

        <div class="flow-arrow" aria-hidden="true">
          <div class="flow-circle">${icons.arrowRight}</div>
        </div>

        <article class="module-card">
          <header class="module-header">
            <h2 class="module-title">02. Classical ML &amp; Lexical Analysis</h2>
            <span class="module-tag">MNB + LogReg</span>
          </header>
          <div class="module-body">${module2Body}</div>
        </article>

        <div class="flow-arrow" aria-hidden="true">
          <div class="flow-circle">${icons.arrowRight}</div>
        </div>

        <article class="module-card">
          <header class="module-header">
            <h2 class="module-title">03. Combined Risk Report</h2>
            <span class="module-tag">Verdict</span>
          </header>
          <div class="module-body">${module3Body}</div>
        </article>
      </section>

      ${evidenceHtml}
    </div>
  `;

  // Wire events cleanly
  const form = container.querySelector('#analyze-url-form');
  const inputEl = container.querySelector('#url-analyzer-input');
  const submitBtn = form?.querySelector('button[type="submit"]');

  if (inputEl) {
    inputEl.addEventListener('input', (e) => {
      handlers.onUrlInputChange(e.target.value);
      if (submitBtn) {
        submitBtn.disabled = analyzing || !e.target.value.trim();
      }
    });
  }

  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const val = inputEl ? inputEl.value : urlInput;
      if (!val.trim() || analyzing) return;
      handlers.onAnalyze(val);
    });
  }

  container.querySelectorAll('[data-sample-idx]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const idx = Number(btn.getAttribute('data-sample-idx'));
      const sample = QUICK_SAMPLES[idx];
      if (!sample) return;
      handlers.onUrlInputChange(sample.url);
      handlers.onAnalyze(sample.url);
    });
  });

  const copyBtn = container.querySelector('#copy-hash-btn');
  if (copyBtn && result) {
    copyBtn.addEventListener('click', () => {
      handlers.onCopyHash(result.module1.sha256);
    });
  }

  const seedBtn = container.querySelector('#seed-hash-btn');
  if (seedBtn && result) {
    seedBtn.addEventListener('click', () => {
      handlers.onSeedThreat(result.module1.normalization.normalizedUrl);
    });
  }

  container.querySelectorAll('[data-evidence-tab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const tab = btn.getAttribute('data-evidence-tab');
      handlers.onEvidenceTabChange(tab);
    });
  });
}

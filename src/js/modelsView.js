import { escapeHtml, formatPercent, icons } from './utils.js';

function renderConfusionGrid(m) {
  return `
    <div class="confusion-card">
      <div style="display:flex;align-items:baseline;justify-content:space-between;gap:8px;">
        <div style="font-size:13px;font-weight:700;">${escapeHtml(m.modelName)}</div>
        <div class="font-mono tabular-nums" style="font-size:11px;color:var(--text-muted);">n = ${m.testSamples} test</div>
      </div>
      <div class="confusion-matrix">
        <div class="cm-cell">
          <div style="color:var(--text-muted);">True Positive (TP)</div>
          <div class="cm-num tone-success tabular-nums">${m.confusionMatrix.tp}</div>
          <div style="color:var(--text-muted);">Phishing caught</div>
        </div>
        <div class="cm-cell">
          <div style="color:var(--text-muted);">False Positive (FP)</div>
          <div class="cm-num tone-warning tabular-nums">${m.confusionMatrix.fp}</div>
          <div style="color:var(--text-muted);">Legit flagged</div>
        </div>
        <div class="cm-cell">
          <div style="color:var(--text-muted);">False Negative (FN)</div>
          <div class="cm-num tone-danger tabular-nums">${m.confusionMatrix.fn}</div>
          <div style="color:var(--text-muted);">Phishing missed</div>
        </div>
        <div class="cm-cell">
          <div style="color:var(--text-muted);">True Negative (TN)</div>
          <div class="cm-num tabular-nums">${m.confusionMatrix.tn}</div>
          <div style="color:var(--text-muted);">Legit cleared</div>
        </div>
      </div>
    </div>
  `;
}

export function renderModelsView(container, state, handlers) {
  const { modelReport: report, csvUploading, csvError, csvSuccess } = state;

  if (!report) {
    container.innerHTML = `<div class="card card-padded empty-state">Loading classical ML evaluation metrics...</div>`;
    return;
  }

  const modelsList = [
    report.metrics.mnb,
    report.metrics.logreg,
    report.metrics.ensemble,
  ];

  const metricsRows = modelsList
    .map(
      (m) => `
        <tr>
          <td style="font-weight:600;">${escapeHtml(m.modelName)}</td>
          <td class="font-mono text-right tabular-nums">${formatPercent(m.accuracy)}</td>
          <td class="font-mono text-right tabular-nums">${formatPercent(m.precision)}</td>
          <td class="font-mono text-right tabular-nums">${formatPercent(m.recall)}</td>
          <td class="font-mono text-right tabular-nums" style="font-weight:700;color:var(--accent);">${formatPercent(m.f1Score)}</td>
          <td class="font-mono text-right tabular-nums tone-warning">${formatPercent(m.falsePositiveRate)}</td>
        </tr>
      `
    )
    .join('');

  const confusionCards = modelsList.map(renderConfusionGrid).join('');

  const weightRows = report.globalFeatureWeights
    .map(
      (fw) => `
        <tr>
          <td style="font-weight:500;">${escapeHtml(fw.label)}</td>
          <td class="font-mono text-right tabular-nums ${fw.direction === 'phishing' ? 'tone-danger' : 'tone-success'}" style="font-weight:600;">
            ${fw.weight >= 0 ? '+' : ''}${fw.weight.toFixed(4)}
          </td>
          <td class="text-right" style="color:var(--text-secondary);">
            ${fw.direction === 'phishing' ? 'Phishing' : 'Legitimate'}
          </td>
        </tr>
      `
    )
    .join('');

  const phishNgramRows = report.topPhishingNGrams
    .slice(0, 6)
    .map(
      (item) => `
        <tr>
          <td class="font-mono">${escapeHtml(item.token)}</td>
          <td class="font-mono text-right tabular-nums tone-danger">+${item.logOdds.toFixed(2)}</td>
          <td class="font-mono text-right tabular-nums" style="color:var(--text-muted);">${item.phishDocFreq} / ${item.legitDocFreq}</td>
        </tr>
      `
    )
    .join('');

  const legitNgramRows = report.topLegitimateNGrams
    .slice(0, 6)
    .map(
      (item) => `
        <tr>
          <td class="font-mono">${escapeHtml(item.token)}</td>
          <td class="font-mono text-right tabular-nums tone-success">${item.logOdds.toFixed(2)}</td>
          <td class="font-mono text-right tabular-nums" style="color:var(--text-muted);">${item.phishDocFreq} / ${item.legitDocFreq}</td>
        </tr>
      `
    )
    .join('');

  container.innerHTML = `
    <div class="stack-lg">
      <section class="card card-padded">
        <div class="section-head-row" style="border-bottom:none;padding-bottom:0;margin-bottom:14px;">
          <div>
            <h2 class="section-title">Active Training &amp; Evaluation Dataset</h2>
            <p style="font-size:13px;color:var(--text-secondary);margin-top:4px;">${escapeHtml(report.dataset.name)}</p>
            <div class="tabular-nums" style="margin-top:6px;font-size:12px;color:var(--text-muted);">
              ${report.dataset.totalSamples} URLs total · ${report.dataset.phishingCount} phishing · ${report.dataset.legitimateCount} legitimate · 80/20 stratified split (${report.dataset.trainSize} train / ${report.dataset.testSize} test) · ${report.dataset.vocabSize} TF-IDF n-gram terms
            </div>
          </div>

          <div class="toolbar-inline">
            <input id="csv-dataset-upload" type="file" accept=".csv,text/csv" class="hidden" />
            <button type="button" id="trigger-csv-upload" class="btn btn-primary btn-sm" ${csvUploading ? 'disabled' : ''}>
              ${icons.upload}
              <span>${csvUploading ? 'Training...' : 'Upload Kaggle / PhishTank / URLhaus CSV'}</span>
            </button>
            ${
              report.dataset.sourceType === 'uploaded-csv'
                ? `<button type="button" id="revert-dataset-btn" class="btn btn-secondary btn-sm">${icons.rotateCcw}<span>Revert to Built-In Corpus</span></button>`
                : ''
            }
          </div>
        </div>

        <div class="alert-box alert-info">
          ${icons.spreadsheet}
          <span>CSV loader automatically detects <code class="font-mono">url,label</code> (Kaggle), <code class="font-mono">phish_id,url,verified</code> (PhishTank), and <code class="font-mono">url,threat</code> (URLhaus) schemas, normalizes URLs via Module 1, and recomputes all metrics live.</span>
        </div>

        ${csvError ? `<div class="alert-box alert-error">${icons.fileWarning}<span>${escapeHtml(csvError)}</span></div>` : ''}
        ${csvSuccess ? `<div class="alert-box alert-success"><span>${escapeHtml(csvSuccess)}</span></div>` : ''}
      </section>

      <section class="card card-padded stack-lg" style="gap:20px;">
        <div>
          <h3 class="section-title">Classical ML Evaluation &amp; Approach Comparison</h3>
          <p class="section-desc">Held-out test set performance comparing subword n-gram classification (TF-IDF + MNB) against engineered structural features (Logistic Regression) and their weighted ensemble.</p>
        </div>

        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Model Architecture</th>
                <th class="text-right">Accuracy</th>
                <th class="text-right">Precision</th>
                <th class="text-right">Recall</th>
                <th class="text-right">F1-Score</th>
                <th class="text-right">False Positive Rate</th>
              </tr>
            </thead>
            <tbody>${metricsRows}</tbody>
          </table>
        </div>

        <div class="confusion-grid-3">${confusionCards}</div>

        <div class="alert-box alert-info" style="margin-top:0;flex-direction:column;gap:4px;">
          <strong style="color:var(--text-primary);">False-Positive Awareness &amp; Complementary Model Rationale</strong>
          <span>
            <strong>TF-IDF + Multinomial Naive Bayes</strong> excels at capturing character-level subword deception patterns (e.g., <code class="font-mono">verify-</code>, <code class="font-mono">webscr</code>, <code class="font-mono">office365</code>) while remaining tolerant of long legitimate query parameters.
            <strong>Logistic Regression</strong> captures structural anomalies (IP-address hosts, <code class="font-mono">@</code> userinfo obfuscation, embedded <code class="font-mono">//</code> redirects, subdomain depth, Shannon entropy), though complex legitimate SaaS/OAuth URLs can raise structural scores. Combining both models mitigates single-model blind spots.
          </span>
        </div>
      </section>

      <section class="grid-2-cols">
        <div class="card card-padded stack-lg" style="gap:16px;">
          <div>
            <h3 class="section-title">Logistic Regression Learned Feature Weights</h3>
            <p class="section-desc">Standardized coefficients (positive increases phishing log-odds; negative decreases risk).</p>
          </div>
          <div class="table-wrap">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Engineered Feature</th>
                  <th class="text-right">Weight (w)</th>
                  <th class="text-right">Association</th>
                </tr>
              </thead>
              <tbody>${weightRows}</tbody>
            </table>
          </div>
        </div>

        <div class="card card-padded stack-lg" style="gap:16px;">
          <div>
            <h3 class="section-title">Highest-Signal TF-IDF N-Grams (Multinomial NB)</h3>
            <p class="section-desc">Top character/token patterns ranked by class log-odds ratio in the training corpus.</p>
          </div>

          <div>
            <div class="tone-danger" style="font-size:12px;font-weight:700;margin-bottom:8px;">Strongest Phishing Indicators</div>
            <div class="table-wrap">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Token</th>
                    <th class="text-right">Log-Odds</th>
                    <th class="text-right">Phish / Legit Docs</th>
                  </tr>
                </thead>
                <tbody>${phishNgramRows}</tbody>
              </table>
            </div>
          </div>

          <div>
            <div class="tone-success" style="font-size:12px;font-weight:700;margin-bottom:8px;">Strongest Legitimate Indicators</div>
            <div class="table-wrap">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Token</th>
                    <th class="text-right">Log-Odds</th>
                    <th class="text-right">Phish / Legit Docs</th>
                  </tr>
                </thead>
                <tbody>${legitNgramRows}</tbody>
              </table>
            </div>
          </div>
        </div>
      </section>
    </div>
  `;

  const fileInput = container.querySelector('#csv-dataset-upload');
  container.querySelector('#trigger-csv-upload')?.addEventListener('click', () => {
    fileInput?.click();
  });

  if (fileInput) {
    fileInput.addEventListener('change', async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;
      await handlers.onUploadCsv(file);
      fileInput.value = '';
    });
  }

  container.querySelector('#revert-dataset-btn')?.addEventListener('click', () => {
    handlers.onRevertDataset();
  });
}

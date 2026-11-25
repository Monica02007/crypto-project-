import { useRef, useState } from 'react';
import {
  AlertCircle,
  FileSpreadsheet,
  RotateCcw,
  Upload,
} from 'lucide-react';
import type { ModelComparisonReport, ModelMetrics } from '../core/types.ts';
import { formatPercent } from './VerdictStyles.ts';

interface ModelsEvaluationViewProps {
  report: ModelComparisonReport | null;
  onEvaluateCsv: (csvText: string, datasetName?: string) => Promise<void>;
  onRevertDataset: () => Promise<void>;
}

function ConfusionGrid({ m }: { m: ModelMetrics }) {
  return (
    <div className="border border-slate-200 rounded-md p-4 bg-slate-50/50 space-y-3">
      <div className="flex items-baseline justify-between gap-2">
        <div className="text-sm font-semibold text-slate-900">{m.modelName}</div>
        <div className="text-xs font-mono text-slate-500 tabular-nums">
          n = {m.testSamples} test
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="p-2.5 bg-white border border-slate-200 rounded">
          <div className="text-slate-500">True Positive (TP)</div>
          <div className="text-lg font-bold font-mono text-emerald-700 tabular-nums mt-0.5">
            {m.confusionMatrix.tp}
          </div>
          <div className="text-slate-500">Phishing caught</div>
        </div>
        <div className="p-2.5 bg-white border border-slate-200 rounded">
          <div className="text-slate-500">False Positive (FP)</div>
          <div className="text-lg font-bold font-mono text-amber-700 tabular-nums mt-0.5">
            {m.confusionMatrix.fp}
          </div>
          <div className="text-slate-500">Legit flagged</div>
        </div>
        <div className="p-2.5 bg-white border border-slate-200 rounded">
          <div className="text-slate-500">False Negative (FN)</div>
          <div className="text-lg font-bold font-mono text-red-700 tabular-nums mt-0.5">
            {m.confusionMatrix.fn}
          </div>
          <div className="text-slate-500">Phishing missed</div>
        </div>
        <div className="p-2.5 bg-white border border-slate-200 rounded">
          <div className="text-slate-500">True Negative (TN)</div>
          <div className="text-lg font-bold font-mono text-slate-900 tabular-nums mt-0.5">
            {m.confusionMatrix.tn}
          </div>
          <div className="text-slate-500">Legit cleared</div>
        </div>
      </div>
    </div>
  );
}

export function ModelsEvaluationView({
  report,
  onEvaluateCsv,
  onRevertDataset,
}: ModelsEvaluationViewProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);

  if (!report) {
    return (
      <div className="bg-white border border-slate-200 rounded-lg p-8 text-center text-sm text-slate-600">
        Loading classical ML evaluation metrics...
      </div>
    );
  }

  const modelsList = [
    report.metrics.mnb,
    report.metrics.logreg,
    report.metrics.ensemble,
  ];

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadError(null);
    setUploadSuccess(null);
    setUploading(true);
    try {
      const text = await file.text();
      await onEvaluateCsv(text, `Uploaded CSV: ${file.name}`);
      setUploadSuccess(
        `Trained and evaluated TF-IDF + Multinomial NB and Logistic Regression on "${file.name}".`
      );
    } catch (err) {
      setUploadError(
        err instanceof Error ? err.message : 'Failed to evaluate CSV dataset.'
      );
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  return (
    <div className="space-y-6">
      {/* Dataset & CSV Retraining Section */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-slate-900">
              Active Training &amp; Evaluation Dataset
            </h2>
            <p className="text-sm text-slate-600 mt-1">
              {report.dataset.name}
            </p>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500 tabular-nums">
              <span>{report.dataset.totalSamples} URLs total</span>
              <span aria-hidden="true">·</span>
              <span>{report.dataset.phishingCount} phishing</span>
              <span aria-hidden="true">·</span>
              <span>{report.dataset.legitimateCount} legitimate</span>
              <span aria-hidden="true">·</span>
              <span>
                80/20 stratified split ({report.dataset.trainSize} train / {report.dataset.testSize} test)
              </span>
              <span aria-hidden="true">·</span>
              <span>{report.dataset.vocabSize} TF-IDF n-gram terms</span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,text/csv"
              onChange={handleFileChange}
              className="hidden"
              id="csv-dataset-upload"
            />
            <button
              type="button"
              disabled={uploading}
              onClick={() => fileInputRef.current?.click()}
              className="px-4 py-2 bg-blue-700 hover:bg-blue-800 disabled:bg-slate-300 text-white text-xs font-medium rounded-md inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5" aria-hidden="true" />
              {uploading ? 'Training...' : 'Upload Kaggle / PhishTank / URLhaus CSV'}
            </button>

            {report.dataset.sourceType === 'uploaded-csv' && (
              <button
                type="button"
                onClick={() => {
                  setUploadError(null);
                  setUploadSuccess(null);
                  void onRevertDataset();
                }}
                className="px-3.5 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" aria-hidden="true" />
                Revert to Built-In Corpus
              </button>
            )}
          </div>
        </div>

        <div className="p-3 bg-slate-50 border border-slate-200 rounded-md text-xs text-slate-600 flex items-start gap-2">
          <FileSpreadsheet className="w-4 h-4 text-slate-500 mt-0.5 shrink-0" aria-hidden="true" />
          <span>
            CSV loader automatically detects <code className="font-mono text-slate-800">url,label</code> (Kaggle), <code className="font-mono text-slate-800">phish_id,url,verified</code> (PhishTank), and <code className="font-mono text-slate-800">url,threat</code> (URLhaus) column schemas, applies Module 1 URL normalization, and recomputes all evaluation metrics live.
          </span>
        </div>

        {uploadError && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-md text-xs text-red-800 flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-red-600 mt-0.5 shrink-0" aria-hidden="true" />
            <span>{uploadError}</span>
          </div>
        )}
        {uploadSuccess && (
          <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-md text-xs text-emerald-800">
            {uploadSuccess}
          </div>
        )}
      </section>

      {/* Model Comparison Metrics */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
        <div>
          <h3 className="text-lg font-semibold text-slate-900">
            Classical ML Evaluation &amp; Approach Comparison
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Held-out test set performance comparing subword n-gram classification (TF-IDF + MNB) against engineered structural features (Logistic Regression) and their weighted ensemble.
          </p>
        </div>

        <div className="overflow-x-auto border border-slate-200 rounded-md">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
              <tr>
                <th className="py-2.5 px-3 font-medium">Model Architecture</th>
                <th className="py-2.5 px-3 font-medium text-right">Accuracy</th>
                <th className="py-2.5 px-3 font-medium text-right">Precision</th>
                <th className="py-2.5 px-3 font-medium text-right">Recall</th>
                <th className="py-2.5 px-3 font-medium text-right">F1-Score</th>
                <th className="py-2.5 px-3 font-medium text-right">False Positive Rate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {modelsList.map((m) => (
                <tr key={m.modelKey} className="hover:bg-slate-50/70">
                  <td className="py-3 px-3 font-semibold text-slate-900">
                    {m.modelName}
                  </td>
                  <td className="py-3 px-3 font-mono text-right text-slate-900 tabular-nums">
                    {formatPercent(m.accuracy)}
                  </td>
                  <td className="py-3 px-3 font-mono text-right text-slate-900 tabular-nums">
                    {formatPercent(m.precision)}
                  </td>
                  <td className="py-3 px-3 font-mono text-right text-slate-900 tabular-nums">
                    {formatPercent(m.recall)}
                  </td>
                  <td className="py-3 px-3 font-mono text-right font-semibold text-blue-700 tabular-nums">
                    {formatPercent(m.f1Score)}
                  </td>
                  <td className="py-3 px-3 font-mono text-right text-amber-700 tabular-nums">
                    {formatPercent(m.falsePositiveRate)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {modelsList.map((m) => (
            <ConfusionGrid key={m.modelKey} m={m} />
          ))}
        </div>

        {/* False-Positive Awareness & Design Trade-offs */}
        <div className="p-4 bg-slate-50 border border-slate-200 rounded-md space-y-2">
          <h4 className="text-xs font-semibold text-slate-900">
            False-Positive Awareness &amp; Complementary Model Rationale
          </h4>
          <p className="text-xs text-slate-600 leading-relaxed">
            <strong>TF-IDF + Multinomial Naive Bayes</strong> excels at capturing character-level subword deception patterns (e.g., <code className="font-mono text-slate-800">verify-</code>, <code className="font-mono text-slate-800">webscr</code>, <code className="font-mono text-slate-800">office365</code> in unusual combinations) while remaining tolerant of long legitimate query parameters. <strong>Logistic Regression</strong> captures structural anomalies (IP-address hosts, <code className="font-mono text-slate-800">@</code> userinfo obfuscation, embedded <code className="font-mono text-slate-800">//</code> redirects, excessive subdomain depth, and Shannon entropy), though complex legitimate SaaS/OAuth URLs can raise structural scores. Combining both models mitigates single-model blind spots and keeps every decision factor inspectable.
          </p>
        </div>
      </section>

      {/* Global Learned Feature Weights & Top N-Grams */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
          <div>
            <h3 className="text-base font-semibold text-slate-900">
              Logistic Regression Learned Feature Weights
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Standardized coefficients (positive increases phishing log-odds; negative decreases risk).
            </p>
          </div>
          <div className="border border-slate-200 rounded-md overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
                <tr>
                  <th className="py-2 px-3 font-medium">Engineered Feature</th>
                  <th className="py-2 px-3 font-medium text-right">Weight (w)</th>
                  <th className="py-2 px-3 font-medium text-right">Association</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {report.globalFeatureWeights.map((fw) => (
                  <tr key={fw.key} className="hover:bg-slate-50/60">
                    <td className="py-2 px-3 font-medium text-slate-800">
                      {fw.label}
                    </td>
                    <td
                      className={`py-2 px-3 font-mono text-right tabular-nums font-semibold ${
                        fw.direction === 'phishing'
                          ? 'text-red-700'
                          : 'text-emerald-700'
                      }`}
                    >
                      {fw.weight >= 0 ? '+' : ''}
                      {fw.weight.toFixed(4)}
                    </td>
                    <td className="py-2 px-3 text-right text-slate-600">
                      {fw.direction === 'phishing' ? 'Phishing' : 'Legitimate'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
          <div>
            <h3 className="text-base font-semibold text-slate-900">
              Highest-Signal TF-IDF N-Grams (Multinomial NB)
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Top character/token patterns ranked by class log-odds ratio in the training corpus.
            </p>
          </div>

          <div className="space-y-4">
            <div>
              <div className="text-xs font-semibold text-red-700 mb-2">
                Strongest Phishing Indicators
              </div>
              <div className="border border-slate-200 rounded-md overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
                    <tr>
                      <th className="py-1.5 px-3 font-medium">Token</th>
                      <th className="py-1.5 px-3 font-medium text-right">Log-Odds</th>
                      <th className="py-1.5 px-3 font-medium text-right">Phish / Legit Docs</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {report.topPhishingNGrams.slice(0, 6).map((item) => (
                      <tr key={item.token}>
                        <td className="py-1.5 px-3 font-mono text-slate-900">
                          {item.token}
                        </td>
                        <td className="py-1.5 px-3 font-mono text-right text-red-700 tabular-nums">
                          +{item.logOdds.toFixed(2)}
                        </td>
                        <td className="py-1.5 px-3 font-mono text-right text-slate-500 tabular-nums">
                          {item.phishDocFreq} / {item.legitDocFreq}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div>
              <div className="text-xs font-semibold text-emerald-700 mb-2">
                Strongest Legitimate Indicators
              </div>
              <div className="border border-slate-200 rounded-md overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
                    <tr>
                      <th className="py-1.5 px-3 font-medium">Token</th>
                      <th className="py-1.5 px-3 font-medium text-right">Log-Odds</th>
                      <th className="py-1.5 px-3 font-medium text-right">Phish / Legit Docs</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {report.topLegitimateNGrams.slice(0, 6).map((item) => (
                      <tr key={item.token}>
                        <td className="py-1.5 px-3 font-mono text-slate-900">
                          {item.token}
                        </td>
                        <td className="py-1.5 px-3 font-mono text-right text-emerald-700 tabular-nums">
                          {item.logOdds.toFixed(2)}
                        </td>
                        <td className="py-1.5 px-3 font-mono text-right text-slate-500 tabular-nums">
                          {item.phishDocFreq} / {item.legitDocFreq}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

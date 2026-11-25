import { useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  Copy,
  Database,
  FileWarning,
  Hash,
  Info,
  Plus,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type {
  AnalysisResult,
  ModelComparisonReport,
  VerdictLevel,
} from '../core/types.ts';
import { SemiCircularGauge } from './SemiCircularGauge.tsx';
import { formatPercent } from './VerdictStyles.ts';

interface QuickSample {
  label: string;
  url: string;
}

const QUICK_SAMPLES: QuickSample[] = [
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

interface AnalyzerViewProps {
  urlInput: string;
  onUrlInputChange: (val: string) => void;
  onAnalyze: (url: string, forceMlInspection?: boolean) => Promise<void>;
  onAddHashToThreatDb: (url: string) => Promise<void>;
  result: AnalysisResult | null;
  modelReport: ModelComparisonReport | null;
  loading: boolean;
  error: string | null;
  addingThreat: boolean;
  threatAddedNotice: string | null;
}

interface SignalRow {
  label: string;
  detail: string;
  status: string;
  toneClass: string;
  barClass: string;
  barPct: number;
}

function buildSignalRows(result: AnalysisResult): SignalRow[] {
  const f = result.module2.lexicalFeatures;
  const kws = result.module2.matchedKeywords;

  const kwRow: SignalRow =
    kws.length >= 2
      ? {
          label: 'Suspicious Keywords',
          detail: kws.slice(0, 3).join(', '),
          status: 'High',
          toneClass: 'text-red-700',
          barClass: 'bg-red-500',
          barPct: 90,
        }
      : kws.length === 1
        ? {
            label: 'Suspicious Keywords',
            detail: kws[0],
            status: 'Elevated',
            toneClass: 'text-red-700',
            barClass: 'bg-red-500',
            barPct: 72,
          }
        : {
            label: 'Suspicious Keywords',
            detail: 'No lure terms matched',
            status: 'Clear',
            toneClass: 'text-emerald-700',
            barClass: 'bg-emerald-500',
            barPct: 12,
          };

  const anomalyScore =
    f.hyphenCount + f.atSymbolPresent * 3 + f.doubleSlashRedirect * 3 + f.hasIpAddress * 3;
  const anomalyRow: SignalRow =
    anomalyScore >= 3 || f.hyphenCount >= 2
      ? {
          label: 'Lexical Anomalies',
          detail: `${f.hyphenCount} hyphens · ${f.specialCharCount} special chars`,
          status: 'High',
          toneClass: 'text-red-700',
          barClass: 'bg-red-500',
          barPct: 86,
        }
      : anomalyScore >= 1
        ? {
            label: 'Lexical Anomalies',
            detail: `${f.hyphenCount} hyphens · ${f.dotCount} dots`,
            status: 'Moderate',
            toneClass: 'text-amber-700',
            barClass: 'bg-amber-500',
            barPct: 52,
          }
        : {
            label: 'Lexical Anomalies',
            detail: `${f.hyphenCount} hyphens · ${f.dotCount} dots`,
            status: 'Normal',
            toneClass: 'text-emerald-700',
            barClass: 'bg-emerald-500',
            barPct: 14,
          };

  const hostRow: SignalRow =
    f.hasIpAddress === 1 || f.subdomainDepth >= 2 || f.shannonEntropy >= 4.1
      ? {
          label: f.hasIpAddress === 1 ? 'IP-Address Host' : 'Host & Subdomains',
          detail:
            f.hasIpAddress === 1
              ? 'Direct IP literal host'
              : `${f.subdomainDepth} subdomains · ${f.shannonEntropy.toFixed(2)} entropy`,
          status: 'High',
          toneClass: 'text-red-700',
          barClass: 'bg-red-500',
          barPct: 88,
        }
      : f.subdomainDepth === 1 || f.hostnameLength > 24
        ? {
            label: 'Host & Subdomains',
            detail: `${f.hostnameLength} chars · ${f.shannonEntropy.toFixed(2)} entropy`,
            status: 'Moderate',
            toneClass: 'text-amber-700',
            barClass: 'bg-amber-500',
            barPct: 54,
          }
        : {
            label: 'Host & Subdomains',
            detail: `${f.hostnameLength} chars · ${f.shannonEntropy.toFixed(2)} entropy`,
            status: 'Normal',
            toneClass: 'text-emerald-700',
            barClass: 'bg-emerald-500',
            barPct: 16,
          };

  const httpsRow: SignalRow =
    f.isHttps === 1
      ? {
          label: 'Transport Security',
          detail: 'HTTPS scheme present',
          status: 'HTTPS',
          toneClass: 'text-emerald-700',
          barClass: 'bg-emerald-500',
          barPct: 20,
        }
      : {
          label: 'Transport Security',
          detail: 'Unencrypted HTTP scheme',
          status: 'HTTP Only',
          toneClass: 'text-red-700',
          barClass: 'bg-red-500',
          barPct: 78,
        };

  return [kwRow, anomalyRow, hostRow, httpsRow];
}

function getVerdictTheme(verdict: VerdictLevel) {
  if (verdict === 'HIGH_RISK_KNOWN_THREAT' || verdict === 'HIGH_RISK_ML') {
    return {
      headerBg: 'bg-red-600 text-white',
      accentText: 'text-red-700',
      headline: 'High Risk Phishing Site',
      recommendation:
        'Do not open or submit credentials. Block this URL at gateway or browser.',
      Icon: AlertOctagon,
    };
  }
  if (verdict === 'SUSPICIOUS') {
    return {
      headerBg: 'bg-amber-600 text-white',
      accentText: 'text-amber-700',
      headline: 'Suspicious / Potential Phishing',
      recommendation:
        'Treat with caution. Independently verify the destination domain before interacting.',
      Icon: AlertTriangle,
    };
  }
  return {
    headerBg: 'bg-emerald-600 text-white',
    accentText: 'text-emerald-700',
    headline: 'Low Risk / Likely Legitimate',
    recommendation:
      'No malicious signatures or strong lexical anomalies detected; verify sender context.',
    Icon: ShieldCheck,
  };
}

export function AnalyzerView({
  urlInput,
  onUrlInputChange,
  onAnalyze,
  onAddHashToThreatDb,
  result,
  modelReport,
  loading,
  error,
  addingThreat,
  threatAddedNotice,
}: AnalyzerViewProps) {
  const [copiedHash, setCopiedHash] = useState(false);
  const [evidenceTab, setEvidenceTab] = useState<
    'normalization' | 'features' | 'ngrams'
  >('features');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim() || loading) return;
    void onAnalyze(urlInput);
  };

  const handleCopyHash = async (hash: string) => {
    try {
      await navigator.clipboard.writeText(hash);
      setCopiedHash(true);
      window.setTimeout(() => setCopiedHash(false), 1800);
    } catch {
      // Ignore clipboard unavailability
    }
  };

  const signals = result ? buildSignalRows(result) : [];

  return (
    <div className="space-y-6">
      {/* Unified Command Bar */}
      <section className="bg-white border border-slate-200 rounded-xl shadow-xs p-5 sm:p-6 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          <div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900">
              Hybrid Phishing Website Detection System
            </h1>
            <p className="text-xs sm:text-sm text-slate-500 mt-0.5">
              Deterministic SHA-256 cryptographic lookup paired with TF-IDF Naive Bayes and Logistic Regression scoring.
            </p>
          </div>

          {modelReport && (
            <div className="text-xs text-slate-500 font-mono tabular-nums whitespace-nowrap shrink-0">
              Ensemble Accuracy {(modelReport.metrics.ensemble.accuracy * 100).toFixed(1)}% · Corpus {modelReport.dataset.totalSamples} URLs
            </div>
          )}
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <label htmlFor="url-analyzer-input" className="sr-only">
              Enter Suspicious URL
            </label>
            <Search
              className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
              aria-hidden="true"
            />
            <input
              id="url-analyzer-input"
              type="text"
              value={urlInput}
              onChange={(e) => onUrlInputChange(e.target.value)}
              placeholder="Enter suspicious URL (e.g., http://login-secure-bank.xyz/update)..."
              className="w-full h-11 pl-10 pr-4 text-sm font-mono bg-slate-50 border border-slate-300 rounded-lg text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-700 focus:border-blue-700 focus:bg-white transition-colors"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !urlInput.trim()}
            className="h-11 px-6 bg-blue-700 hover:bg-blue-800 disabled:bg-slate-300 text-white text-sm font-semibold rounded-lg inline-flex items-center justify-center gap-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {loading ? 'Analyzing...' : 'Analyze URL'}
            <ArrowRight className="w-4 h-4" aria-hidden="true" />
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-xs font-medium text-slate-500 mr-1">
            Quick presets:
          </span>
          {QUICK_SAMPLES.map((sample) => (
            <button
              key={sample.label}
              type="button"
              disabled={loading}
              onClick={() => {
                onUrlInputChange(sample.url);
                void onAnalyze(sample.url);
              }}
              className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-200 hover:bg-slate-100 hover:border-slate-300 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {sample.label}
            </button>
          ))}
        </div>

        {error && (
          <div
            role="alert"
            className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-800 flex items-start gap-2"
          >
            <FileWarning className="w-4 h-4 text-red-600 mt-0.5 shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}
      </section>

      {/* Three-Column Horizontal Pipeline */}
      <section
        aria-label="Three-module hybrid phishing detection pipeline"
        className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_28px_minmax(0,1fr)_28px_minmax(0,1fr)] gap-4 xl:gap-2 items-stretch"
      >
        {/* MODULE 1: HASH LOOKUP */}
        <article className="bg-white border border-slate-200 rounded-xl shadow-xs flex flex-col overflow-hidden">
          <header className="px-5 py-3.5 border-b border-slate-200 bg-slate-50/80 flex items-center justify-between gap-2">
            <h2 className="text-sm font-bold text-slate-900">
              01. Cryptographic Hash Lookup
            </h2>
            <span className="text-xs font-mono text-slate-500">SHA-256</span>
          </header>

          <div className="p-5 flex-1 flex flex-col justify-between gap-4">
            {result ? (
              <>
                <div className="space-y-3">
                  <div>
                    <div className="text-xs font-medium text-slate-500 mb-1">
                      Normalized Canonical URL
                    </div>
                    <div className="p-2.5 bg-slate-50 rounded-md font-mono text-xs text-slate-800 break-all">
                      {result.module1.normalization.normalizedUrl}
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium text-slate-500 inline-flex items-center gap-1">
                        <Hash className="w-3.5 h-3.5" aria-hidden="true" />
                        SHA-256 Fingerprint
                      </span>
                      <button
                        type="button"
                        onClick={() => void handleCopyHash(result.module1.sha256)}
                        className="text-xs font-medium text-blue-700 hover:text-blue-800 inline-flex items-center gap-1 cursor-pointer"
                      >
                        {copiedHash ? (
                          <>
                            <Check className="w-3 h-3" aria-hidden="true" />
                            Copied
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" aria-hidden="true" />
                            Copy
                          </>
                        )}
                      </button>
                    </div>
                    <div className="p-3 bg-slate-900 text-slate-100 rounded-md font-mono text-xs break-all leading-relaxed select-all">
                      {result.module1.sha256}
                    </div>
                  </div>
                </div>

                {/* Deterministic Match Outcome */}
                {result.module1.matchedThreat ? (
                  <div className="p-3.5 bg-red-50/90 border border-red-200 rounded-lg space-y-1.5">
                    <div className="flex items-center gap-2 text-xs font-bold text-red-800">
                      <ShieldAlert className="w-4 h-4 text-red-600 shrink-0" aria-hidden="true" />
                      Database Match Found: Known Threat
                    </div>
                    <p className="text-xs text-red-900 leading-relaxed">
                      Exact digest match in {result.module1.matchedThreat.source} ({result.module1.matchedThreat.category}).
                    </p>
                  </div>
                ) : (
                  <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg space-y-2">
                    <div className="flex items-center gap-2 text-xs font-semibold text-slate-800">
                      <Database className="w-4 h-4 text-slate-500 shrink-0" aria-hidden="true" />
                      Database Match: Hash Miss
                    </div>
                    <p className="text-xs text-slate-600 leading-relaxed">
                      A hash mismatch does not guarantee safety. Normalized URL passed to Module 2 ML classifiers.
                    </p>
                    <button
                      type="button"
                      disabled={addingThreat}
                      onClick={() =>
                        void onAddHashToThreatDb(
                          result.module1.normalization.normalizedUrl
                        )
                      }
                      className="text-xs font-medium text-blue-700 hover:text-blue-800 inline-flex items-center gap-1 cursor-pointer"
                    >
                      <Plus className="w-3.5 h-3.5" aria-hidden="true" />
                      {addingThreat ? 'Adding...' : 'Seed Hash to Threat DB'}
                    </button>
                    {threatAddedNotice && (
                      <div className="text-xs text-emerald-700 font-medium">
                        {threatAddedNotice}
                      </div>
                    )}
                  </div>
                )}
              </>
            ) : (
              <div className="py-12 text-center text-xs text-slate-500">
                Enter a URL above to compute its normalized SHA-256 digest.
              </div>
            )}
          </div>
        </article>

        {/* Flow Arrow 1 -> 2 */}
        <div
          className="hidden xl:flex items-center justify-center"
          aria-hidden="true"
        >
          <div className="w-7 h-7 rounded-full bg-white border border-slate-200 shadow-xs flex items-center justify-center text-blue-700">
            <ArrowRight className="w-4 h-4" />
          </div>
        </div>

        {/* MODULE 2: ML ANALYSIS */}
        <article className="bg-white border border-slate-200 rounded-xl shadow-xs flex flex-col overflow-hidden">
          <header className="px-5 py-3.5 border-b border-slate-200 bg-slate-50/80 flex items-center justify-between gap-2">
            <h2 className="text-sm font-bold text-slate-900">
              02. Classical ML &amp; Lexical Analysis
            </h2>
            <span className="text-xs font-mono text-slate-500">MNB + LogReg</span>
          </header>

          <div className="p-5 flex-1 flex flex-col justify-between gap-4">
            {result ? (
              <>
                <SemiCircularGauge
                  probability={result.module2.ensembleProbability}
                />

                {/* Dual Model Comparison Bars */}
                <div className="grid grid-cols-2 gap-3 pt-1">
                  <div className="p-2.5 bg-slate-50 rounded-md">
                    <div className="flex items-baseline justify-between text-xs">
                      <span className="font-medium text-slate-600">TF-IDF MNB</span>
                      <span className="font-mono font-bold text-slate-900 tabular-nums">
                        {formatPercent(result.module2.mnbProbability)}
                      </span>
                    </div>
                    <div className="mt-1.5 h-1.5 bg-slate-200 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-blue-700 rounded-full"
                        style={{
                          width: `${Math.max(4, result.module2.mnbProbability * 100)}%`,
                        }}
                      />
                    </div>
                  </div>

                  <div className="p-2.5 bg-slate-50 rounded-md">
                    <div className="flex items-baseline justify-between text-xs">
                      <span className="font-medium text-slate-600">LogReg</span>
                      <span className="font-mono font-bold text-slate-900 tabular-nums">
                        {formatPercent(result.module2.logregProbability)}
                      </span>
                    </div>
                    <div className="mt-1.5 h-1.5 bg-slate-200 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-blue-700 rounded-full"
                        style={{
                          width: `${Math.max(4, result.module2.logregProbability * 100)}%`,
                        }}
                      />
                    </div>
                  </div>
                </div>

                {/* Four Clean Explainable Feature Signals */}
                <div className="divide-y divide-slate-100 border-t border-slate-100 pt-1">
                  {signals.map((sig) => (
                    <div
                      key={sig.label}
                      className="py-2.5 flex items-center justify-between gap-3"
                    >
                      <div className="min-w-0">
                        <div className="text-xs font-medium text-slate-800">
                          {sig.label}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono truncate">
                          {sig.detail}
                        </div>
                      </div>
                      <div className="shrink-0 text-right">
                        <span className={`text-xs font-semibold ${sig.toneClass}`}>
                          {sig.status}
                        </span>
                        <div className="mt-1 w-14 h-1 bg-slate-200 rounded-full overflow-hidden ml-auto">
                          <div
                            className={`h-full ${sig.barClass} rounded-full`}
                            style={{ width: `${sig.barPct}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="py-12 text-center text-xs text-slate-500">
                Awaiting URL input for ML scoring.
              </div>
            )}
          </div>
        </article>

        {/* Flow Arrow 2 -> 3 */}
        <div
          className="hidden xl:flex items-center justify-center"
          aria-hidden="true"
        >
          <div className="w-7 h-7 rounded-full bg-white border border-slate-200 shadow-xs flex items-center justify-center text-blue-700">
            <ArrowRight className="w-4 h-4" />
          </div>
        </div>

        {/* MODULE 3: COMBINED RISK REPORT */}
        <article className="bg-white border border-slate-200 rounded-xl shadow-xs flex flex-col overflow-hidden">
          <header className="px-5 py-3.5 border-b border-slate-200 bg-slate-50/80 flex items-center justify-between gap-2">
            <h2 className="text-sm font-bold text-slate-900">
              03. Combined Risk Report
            </h2>
            <span className="text-xs font-mono text-slate-500">Verdict</span>
          </header>

          <div className="p-5 flex-1 flex flex-col justify-between gap-4">
            {result ? (
              (() => {
                const v = getVerdictTheme(result.module3.verdict);
                const VerdictIcon = v.Icon;
                return (
                  <>
                    <div className={`p-4 rounded-lg text-center ${v.headerBg}`}>
                      <div className="inline-flex items-center justify-center gap-1.5 text-xs font-medium opacity-90">
                        <VerdictIcon className="w-4 h-4" aria-hidden="true" />
                        Final Verdict
                      </div>
                      <div className="text-lg font-bold tracking-tight mt-0.5">
                        {v.headline}
                      </div>
                      <div className="text-xs opacity-90 mt-1 font-mono tabular-nums">
                        {result.module3.confidenceLabel}
                      </div>
                    </div>

                    <div className="divide-y divide-slate-100 text-xs">
                      <div className="py-2.5 flex items-start gap-2.5">
                        <CheckCircle2
                          className={`w-4 h-4 shrink-0 mt-0.5 ${
                            result.module1.hashLookupStatus === 'MATCH'
                              ? 'text-red-600'
                              : 'text-slate-400'
                          }`}
                          aria-hidden="true"
                        />
                        <div>
                          <div className="font-semibold text-slate-900">
                            Deterministic Check
                          </div>
                          <p className="text-slate-600 mt-0.5 leading-relaxed">
                            {result.module1.hashLookupStatus === 'MATCH'
                              ? `Exact SHA-256 match found in ${result.module1.matchedThreat?.source}. Immediate threat confirmed.`
                              : 'No exact SHA-256 match in known-threat database; decision delegated to Module 2 ML.'}
                          </p>
                        </div>
                      </div>

                      <div className="py-2.5 flex items-start gap-2.5">
                        <CheckCircle2
                          className={`w-4 h-4 shrink-0 mt-0.5 ${v.accentText}`}
                          aria-hidden="true"
                        />
                        <div>
                          <div className="font-semibold text-slate-900">
                            Probabilistic ML Check
                          </div>
                          <p className="text-slate-600 mt-0.5 leading-relaxed">
                            Ensemble scored{' '}
                            <span className="font-mono font-semibold text-slate-900">
                              {formatPercent(result.module2.ensembleProbability)}
                            </span>{' '}
                            across character n-grams and 18 lexical features.
                          </p>
                        </div>
                      </div>

                      <div className="py-2.5 flex items-start gap-2.5">
                        <ShieldCheck
                          className={`w-4 h-4 shrink-0 mt-0.5 ${v.accentText}`}
                          aria-hidden="true"
                        />
                        <div>
                          <div className="font-semibold text-slate-900">
                            Recommendation
                          </div>
                          <p className="text-slate-600 mt-0.5 leading-relaxed">
                            {v.recommendation}
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="p-3 bg-slate-50 rounded-md flex items-start gap-2 text-[11px] text-slate-600 leading-relaxed">
                      <Info
                        className="w-3.5 h-3.5 text-slate-500 shrink-0 mt-0.5"
                        aria-hidden="true"
                      />
                      <span>
                        Predictions are probabilistic estimates, not absolute guarantees. Novel attacks can evade checks and legitimate URLs may occasionally trigger alerts.
                      </span>
                    </div>
                  </>
                );
              })()
            ) : (
              <div className="py-12 text-center text-xs text-slate-500">
                Combined risk verdict will appear here.
              </div>
            )}
          </div>
        </article>
      </section>

      {/* Clean Tabbed Evidence Inspector */}
      {result && (
        <section className="bg-white border border-slate-200 rounded-xl shadow-xs p-5 sm:p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-100 pb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-900">
                Explainable Evidence Breakdown
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Inspect why the URL received its classification across normalization, structural weights, and n-grams.
              </p>
            </div>

            <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg self-start sm:self-auto">
              {[
                { id: 'features', label: 'Lexical Triggers' },
                { id: 'ngrams', label: 'TF-IDF N-Grams' },
                { id: 'normalization', label: 'Normalization Audit' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() =>
                    setEvidenceTab(
                      tab.id as 'normalization' | 'features' | 'ngrams'
                    )
                  }
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    evidenceTab === tab.id
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {evidenceTab === 'features' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-3">
              {result.module2.featureContributions.slice(0, 10).map((feat) => {
                const isPhish = feat.contribution >= 0;
                const widthPct = Math.min(
                  100,
                  Math.max(6, Math.abs(feat.contribution) * 38)
                );
                return (
                  <div
                    key={feat.key}
                    className="py-2 border-b border-slate-100 flex items-center justify-between gap-4 text-xs"
                  >
                    <div className="min-w-0">
                      <span className="font-medium text-slate-800">
                        {feat.label}
                      </span>
                      <span className="ml-2 font-mono text-slate-500">
                        {feat.formattedValue}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <div className="w-20 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            feat.direction === 'neutral'
                              ? 'bg-slate-400'
                              : isPhish
                                ? 'bg-red-500'
                                : 'bg-emerald-500'
                          }`}
                          style={{ width: `${widthPct}%` }}
                        />
                      </div>
                      <span
                        className={`font-mono font-semibold tabular-nums w-14 text-right ${
                          feat.direction === 'neutral'
                            ? 'text-slate-500'
                            : isPhish
                              ? 'text-red-700'
                              : 'text-emerald-700'
                        }`}
                      >
                        {feat.contribution >= 0 ? '+' : ''}
                        {feat.contribution.toFixed(2)}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {evidenceTab === 'ngrams' && (
            <div className="overflow-x-auto border border-slate-200 rounded-lg">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
                  <tr>
                    <th className="py-2 px-3 font-medium">Token / Character N-Gram</th>
                    <th className="py-2 px-3 font-medium text-right">TF-IDF Weight</th>
                    <th className="py-2 px-3 font-medium text-right">Class Log-Odds</th>
                    <th className="py-2 px-3 font-medium text-right">Direction</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {result.module2.topNGrams.map((ng) => (
                    <tr key={ng.token} className="hover:bg-slate-50/70">
                      <td className="py-2 px-3 font-mono text-slate-900">
                        {ng.token}
                      </td>
                      <td className="py-2 px-3 font-mono text-right text-slate-600 tabular-nums">
                        {ng.tfidfWeight.toFixed(3)}
                      </td>
                      <td
                        className={`py-2 px-3 font-mono text-right font-semibold tabular-nums ${
                          ng.direction === 'phishing'
                            ? 'text-red-700'
                            : 'text-emerald-700'
                        }`}
                      >
                        {ng.logOdds >= 0 ? '+' : ''}
                        {ng.logOdds.toFixed(2)}
                      </td>
                      <td className="py-2 px-3 text-right text-slate-600">
                        {ng.direction === 'phishing' ? 'Phishing' : 'Legitimate'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {evidenceTab === 'normalization' && (
            <div className="overflow-x-auto border border-slate-200 rounded-lg">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
                  <tr>
                    <th className="py-2 px-3 font-medium">Normalization Rule</th>
                    <th className="py-2 px-3 font-medium">Outcome</th>
                    <th className="py-2 px-3 font-medium">Detail</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {result.module1.normalization.steps.map((step) => (
                    <tr key={step.rule} className="hover:bg-slate-50/70">
                      <td className="py-2 px-3 font-medium text-slate-800 whitespace-nowrap">
                        {step.rule}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        {step.applied ? (
                          <span className="font-semibold text-blue-700">
                            Applied
                          </span>
                        ) : (
                          <span className="text-slate-400">Unchanged</span>
                        )}
                      </td>
                      <td className="py-2 px-3 font-mono text-slate-600">
                        {step.detail}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  );
}

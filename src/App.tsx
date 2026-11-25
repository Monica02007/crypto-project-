import { useCallback, useEffect, useState } from 'react';
import { Download, Menu, Shield, X } from 'lucide-react';
import type {
  AnalysisResult,
  ModelComparisonReport,
  ScanHistoryEntry,
  ThreatHashRecord,
} from './core/types.ts';
import { AnalyzerView } from './components/AnalyzerView.tsx';
import { ModelsEvaluationView } from './components/ModelsEvaluationView.tsx';
import { ScanHistoryView } from './components/ScanHistoryView.tsx';
import { ThreatLedgerView } from './components/ThreatLedgerView.tsx';

type ActiveTab = 'analyzer' | 'threats' | 'models' | 'history';

const DEFAULT_DEMO_URL = 'http://login-secure-bank.xyz/update';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('analyzer');
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const [urlInput, setUrlInput] = useState(DEFAULT_DEMO_URL);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(
    null
  );
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeError, setAnalyzeError] = useState<string | null>(null);
  const [addingThreat, setAddingThreat] = useState(false);
  const [threatAddedNotice, setThreatAddedNotice] = useState<string | null>(
    null
  );

  const [threats, setThreats] = useState<ThreatHashRecord[]>([]);
  const [modelReport, setModelReport] = useState<ModelComparisonReport | null>(
    null
  );
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);

  const fetchThreats = useCallback(async () => {
    const res = await fetch('/api/threats');
    if (res.ok) {
      const data = await res.json();
      setThreats(data.threats ?? []);
    }
  }, []);

  const fetchModels = useCallback(async () => {
    const res = await fetch('/api/models');
    if (res.ok) {
      const data = await res.json();
      setModelReport(data);
    }
  }, []);

  const fetchHistory = useCallback(async () => {
    const res = await fetch('/api/history');
    if (res.ok) {
      const data = await res.json();
      setHistory(data.history ?? []);
    }
  }, []);

  const handleAnalyze = useCallback(
    async (targetUrl: string, forceMlInspection = false) => {
      setAnalyzing(true);
      setAnalyzeError(null);
      setThreatAddedNotice(null);
      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: targetUrl, forceMlInspection }),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Analysis failed.');
        }
        setAnalysisResult(data);
        await fetchHistory();
      } catch (err) {
        setAnalyzeError(
          err instanceof Error ? err.message : 'Could not analyze URL.'
        );
      } finally {
        setAnalyzing(false);
      }
    },
    [fetchHistory]
  );

  useEffect(() => {
    void fetchThreats();
    void fetchModels();
    void fetchHistory();
    void handleAnalyze(DEFAULT_DEMO_URL);
  }, [fetchThreats, fetchModels, fetchHistory, handleAnalyze]);

  const handleAddHashFromAnalyzer = async (normalizedUrl: string) => {
    setAddingThreat(true);
    setThreatAddedNotice(null);
    try {
      const res = await fetch('/api/threats', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'url',
          url: normalizedUrl,
          source: 'Analyst Demo Addition',
          category: 'Flagged During Inspection',
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to add hash.');
      await fetchThreats();
      setThreatAddedNotice(
        'Added to Threat Ledger. Click Check URL Hash to observe Module 1 match.'
      );
    } catch (err) {
      setAnalyzeError(
        err instanceof Error ? err.message : 'Could not add hash.'
      );
    } finally {
      setAddingThreat(false);
    }
  };

  const handleAddByUrl = async (payload: {
    url: string;
    source: string;
    category: string;
    targetBrand?: string;
  }) => {
    const res = await fetch('/api/threats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'url', ...payload }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to add URL.');
    await fetchThreats();
  };

  const handleAddByHash = async (payload: {
    sha256: string;
    labelUrl?: string;
    source: string;
    category: string;
    targetBrand?: string;
  }) => {
    const res = await fetch('/api/threats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'hash', ...payload }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to add SHA-256.');
    await fetchThreats();
  };

  const handleDeleteThreat = async (sha256: string) => {
    const res = await fetch(`/api/threats/${encodeURIComponent(sha256)}`, {
      method: 'DELETE',
    });
    if (res.ok) {
      await fetchThreats();
    }
  };

  const handleResetSeed = async () => {
    const res = await fetch('/api/threats/reset', { method: 'POST' });
    if (res.ok) {
      const data = await res.json();
      setThreats(data.threats ?? []);
    }
  };

  const handleEvaluateCsv = async (csvText: string, datasetName?: string) => {
    const res = await fetch('/api/models/evaluate-csv', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csvText, datasetName }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to evaluate CSV.');
    setModelReport(data);
  };

  const handleRevertDataset = async () => {
    const res = await fetch('/api/models/revert', { method: 'POST' });
    if (res.ok) {
      const data = await res.json();
      setModelReport(data);
    }
  };

  const handleClearHistory = async () => {
    const res = await fetch('/api/history', { method: 'DELETE' });
    if (res.ok) {
      setHistory([]);
    }
  };

  const handleExportReport = () => {
    if (!analysisResult) return;
    const blob = new Blob([JSON.stringify(analysisResult, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `veriurl-report-${analysisResult.module1.sha256.slice(0, 12)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const navItems: { id: ActiveTab; label: string }[] = [
    { id: 'analyzer', label: 'Pipeline Analyzer' },
    { id: 'threats', label: 'Threat Ledger' },
    { id: 'models', label: 'ML Evaluation' },
    { id: 'history', label: 'Scan History' },
  ];

  return (
    <div className="min-h-screen bg-[#F4F6FA] text-slate-900 flex flex-col">
      {/* Three-Zone Top Bar */}
      <header className="bg-white border-b border-slate-200 shrink-0">
        <div className="max-w-[1400px] mx-auto px-4 sm:px-8 h-16 flex items-center justify-between gap-8">
          {/* Zone 1: Brand Wordmark */}
          <button
            type="button"
            onClick={() => setActiveTab('analyzer')}
            className="flex items-center gap-2 text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Shield className="w-5 h-5 text-blue-700" aria-hidden="true" />
            <span>VeriURL</span>
          </button>

          {/* Zone 2: Clean Single-Line Nav Links */}
          <nav
            aria-label="Primary navigation"
            className="hidden md:flex items-center gap-6"
          >
            {navItems.map((item) => {
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveTab(item.id)}
                  className={`text-sm font-medium py-1 border-b-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    active
                      ? 'text-blue-700 border-blue-700'
                      : 'text-slate-600 border-transparent hover:text-slate-900 hover:border-slate-300'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* Zone 3: Primary Action */}
          <div className="flex items-center gap-3 shrink-0">
            {analysisResult ? (
              <button
                type="button"
                onClick={handleExportReport}
                className="px-4 py-2 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer transition-colors"
              >
                <Download className="w-3.5 h-3.5" aria-hidden="true" />
                Export Report
              </button>
            ) : (
              <button
                type="button"
                onClick={() => {
                  setActiveTab('analyzer');
                  void handleAnalyze(DEFAULT_DEMO_URL);
                }}
                className="px-4 py-2 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md whitespace-nowrap shrink-0 cursor-pointer transition-colors"
              >
                Run Sample
              </button>
            )}

            <button
              type="button"
              onClick={() => setMobileNavOpen((prev) => !prev)}
              className="md:hidden p-2 text-slate-600 hover:text-slate-900 cursor-pointer"
              aria-label="Toggle navigation menu"
            >
              {mobileNavOpen ? (
                <X className="w-5 h-5" />
              ) : (
                <Menu className="w-5 h-5" />
              )}
            </button>
          </div>
        </div>

        {/* Mobile Nav Drawer */}
        {mobileNavOpen && (
          <nav className="md:hidden border-t border-slate-200 bg-white px-4 py-2 flex flex-col gap-1">
            {navItems.map((item) => {
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setActiveTab(item.id);
                    setMobileNavOpen(false);
                  }}
                  className={`px-3 py-2 text-left text-sm font-medium rounded-md cursor-pointer ${
                    active
                      ? 'bg-blue-50 text-blue-700'
                      : 'text-slate-700 hover:bg-slate-50'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>
        )}
      </header>

      {/* Main Viewport */}
      <main className="flex-1 max-w-[1400px] w-full mx-auto px-4 sm:px-8 py-6 sm:py-8">
        {activeTab === 'analyzer' && (
          <AnalyzerView
            urlInput={urlInput}
            onUrlInputChange={setUrlInput}
            onAnalyze={handleAnalyze}
            onAddHashToThreatDb={handleAddHashFromAnalyzer}
            result={analysisResult}
            modelReport={modelReport}
            loading={analyzing}
            error={analyzeError}
            addingThreat={addingThreat}
            threatAddedNotice={threatAddedNotice}
          />
        )}

        {activeTab === 'threats' && (
          <ThreatLedgerView
            threats={threats}
            onAddByUrl={handleAddByUrl}
            onAddByHash={handleAddByHash}
            onDelete={handleDeleteThreat}
            onResetSeed={handleResetSeed}
            onTestInAnalyzer={(testUrl) => {
              setUrlInput(testUrl);
              setActiveTab('analyzer');
              void handleAnalyze(testUrl);
            }}
          />
        )}

        {activeTab === 'models' && (
          <ModelsEvaluationView
            report={modelReport}
            onEvaluateCsv={handleEvaluateCsv}
            onRevertDataset={handleRevertDataset}
          />
        )}

        {activeTab === 'history' && (
          <ScanHistoryView
            history={history}
            onInspect={(res) => {
              setAnalysisResult(res);
              setUrlInput(res.module1.normalization.rawUrl);
              setActiveTab('analyzer');
            }}
            onClear={handleClearHistory}
          />
        )}
      </main>
    </div>
  );
}

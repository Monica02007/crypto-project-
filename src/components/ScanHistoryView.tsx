import { useMemo, useState } from 'react';
import { Eye, Search, Trash2 } from 'lucide-react';
import type { AnalysisResult, ScanHistoryEntry } from '../core/types.ts';
import { formatPercent, getVerdictStyle } from './VerdictStyles.ts';

interface ScanHistoryViewProps {
  history: ScanHistoryEntry[];
  onInspect: (result: AnalysisResult) => void;
  onClear: () => Promise<void>;
}

export function ScanHistoryView({
  history,
  onInspect,
  onClear,
}: ScanHistoryViewProps) {
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return history;
    return history.filter(
      (h) =>
        h.normalizedUrl.toLowerCase().includes(q) ||
        h.sha256.toLowerCase().includes(q) ||
        h.verdictLabel.toLowerCase().includes(q)
    );
  }, [history, query]);

  return (
    <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-900">
            URL Scan Audit History
          </h2>
          <p className="text-xs text-slate-500 mt-0.5 tabular-nums">
            {history.length} recorded analyses across Module 1 and Module 2
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search
              className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2"
              aria-hidden="true"
            />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search URL, hash, or verdict..."
              className="h-9 pl-8 pr-3 text-xs bg-slate-50 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white w-56"
            />
          </div>

          {history.length > 0 && (
            <button
              type="button"
              onClick={() => void onClear()}
              className="h-9 px-3 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
              Clear History
            </button>
          )}
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="p-8 text-center border border-slate-200 rounded-md bg-slate-50/50 text-xs text-slate-500">
          {history.length === 0
            ? 'No URLs have been analyzed yet. Submit a URL in the Analyzer view to populate the audit log.'
            : 'No history records match your search query.'}
        </div>
      ) : (
        <div className="overflow-x-auto border border-slate-200 rounded-md">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
              <tr>
                <th className="py-2.5 px-3 font-medium">Timestamp</th>
                <th className="py-2.5 px-3 font-medium">Normalized URL</th>
                <th className="py-2.5 px-3 font-medium">Module 1 Hash</th>
                <th className="py-2.5 px-3 font-medium text-right">Risk Score</th>
                <th className="py-2.5 px-3 font-medium">Final Verdict</th>
                <th className="py-2.5 px-3 font-medium text-right">Report</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filtered.map((entry) => {
                const style = getVerdictStyle(entry.verdict);
                return (
                  <tr key={entry.id} className="hover:bg-slate-50/70">
                    <td className="py-2.5 px-3 font-mono text-slate-500 whitespace-nowrap tabular-nums">
                      {new Date(entry.analyzedAt).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-900 max-w-xs truncate" title={entry.normalizedUrl}>
                      {entry.normalizedUrl}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-600 whitespace-nowrap">
                      {entry.hashStatus === 'MATCH' ? (
                        <span className="text-red-700 font-semibold">
                          MATCH ({entry.sha256.slice(0, 10)}...)
                        </span>
                      ) : (
                        <span>MISS ({entry.sha256.slice(0, 10)}...)</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-right font-semibold text-slate-900 tabular-nums whitespace-nowrap">
                      {formatPercent(entry.riskScore)}
                    </td>
                    <td className={`py-2.5 px-3 font-semibold whitespace-nowrap ${style.badgeTextClass}`}>
                      {entry.verdictLabel}
                    </td>
                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => onInspect(entry.result)}
                        className="px-2.5 py-1 text-xs font-medium text-blue-700 hover:bg-blue-50 rounded inline-flex items-center gap-1 cursor-pointer"
                      >
                        <Eye className="w-3.5 h-3.5" aria-hidden="true" />
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

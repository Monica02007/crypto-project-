import { useMemo, useState } from 'react';
import {
  Check,
  Copy,
  Play,
  Plus,
  RotateCcw,
  Search,
  Trash2,
} from 'lucide-react';
import { normalizeUrl } from '../core/normalizer.ts';
import type { ThreatHashRecord } from '../core/types.ts';

interface ThreatLedgerViewProps {
  threats: ThreatHashRecord[];
  onAddByUrl: (payload: {
    url: string;
    source: string;
    category: string;
    targetBrand?: string;
  }) => Promise<void>;
  onAddByHash: (payload: {
    sha256: string;
    labelUrl?: string;
    source: string;
    category: string;
    targetBrand?: string;
  }) => Promise<void>;
  onDelete: (sha256: string) => Promise<void>;
  onResetSeed: () => Promise<void>;
  onTestInAnalyzer: (url: string) => void;
}

export function ThreatLedgerView({
  threats,
  onAddByUrl,
  onAddByHash,
  onDelete,
  onResetSeed,
  onTestInAnalyzer,
}: ThreatLedgerViewProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterMode, setFilterMode] = useState<'all' | 'seeded' | 'custom'>('all');
  const [entryMode, setEntryMode] = useState<'url' | 'hash'>('url');

  const [newUrl, setNewUrl] = useState('');
  const [newHash, setNewHash] = useState('');
  const [newSource, setNewSource] = useState('Demo Threat Feed');
  const [newCategory, setNewCategory] = useState('Credential Phishing');
  const [newBrand, setNewBrand] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const liveNormPreview = useMemo(() => {
    if (entryMode !== 'url' || !newUrl.trim()) return null;
    return normalizeUrl(newUrl);
  }, [entryMode, newUrl]);

  const filteredThreats = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return threats.filter((item) => {
      if (filterMode === 'seeded' && !item.isSeeded) return false;
      if (filterMode === 'custom' && item.isSeeded) return false;
      if (!q) return true;
      return (
        item.sha256.toLowerCase().includes(q) ||
        item.normalizedUrl.toLowerCase().includes(q) ||
        item.source.toLowerCase().includes(q) ||
        item.category.toLowerCase().includes(q) ||
        (item.targetBrand ?? '').toLowerCase().includes(q)
      );
    });
  }, [threats, searchQuery, filterMode]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSubmitting(true);
    try {
      if (entryMode === 'url') {
        await onAddByUrl({
          url: newUrl,
          source: newSource,
          category: newCategory,
          targetBrand: newBrand || undefined,
        });
        setNewUrl('');
        setNewBrand('');
      } else {
        await onAddByHash({
          sha256: newHash,
          source: newSource,
          category: newCategory,
          targetBrand: newBrand || undefined,
        });
        setNewHash('');
        setNewBrand('');
      }
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : 'Failed to add threat hash.'
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleCopy = async (hash: string) => {
    try {
      await navigator.clipboard.writeText(hash);
      setCopiedHash(hash);
      window.setTimeout(() => setCopiedHash(null), 1500);
    } catch {
      // Ignore clipboard failure
    }
  };

  return (
    <div className="space-y-6">
      {/* Add Threat Hash Entry */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
          <div>
            <h2 className="text-lg font-semibold text-slate-900">
              Add Known-Threat SHA-256 Entry
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Seed custom phishing URLs (normalized &amp; SHA-256 hashed automatically) or raw 64-character SHA-256 digests for testing Module 1.
            </p>
          </div>
          <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-md self-start sm:self-auto">
            <button
              type="button"
              onClick={() => {
                setEntryMode('url');
                setFormError(null);
              }}
              className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                entryMode === 'url'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Add by URL
            </button>
            <button
              type="button"
              onClick={() => {
                setEntryMode('hash');
                setFormError(null);
              }}
              className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                entryMode === 'hash'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Add Raw SHA-256
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="lg:col-span-2">
              <label className="block text-xs font-medium text-slate-700 mb-1">
                {entryMode === 'url'
                  ? 'Phishing URL (will be normalized before SHA-256 hashing)'
                  : 'SHA-256 Hex Digest (64 lowercase/uppercase hex characters)'}
              </label>
              {entryMode === 'url' ? (
                <input
                  type="text"
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                  placeholder="http://malicious-login-portal.example.com/signin"
                  className="w-full h-10 px-3 text-sm font-mono bg-slate-50 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white"
                  required
                />
              ) : (
                <input
                  type="text"
                  value={newHash}
                  onChange={(e) => setNewHash(e.target.value)}
                  placeholder="64-character SHA-256 hex digest..."
                  className="w-full h-10 px-3 text-sm font-mono bg-slate-50 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white"
                  required
                />
              )}
              {liveNormPreview && (
                <p className="mt-1.5 text-xs text-slate-600 font-mono">
                  {liveNormPreview.valid
                    ? `Canonical preview: ${liveNormPreview.normalizedUrl}`
                    : `Preview error: ${liveNormPreview.error}`}
                </p>
              )}
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Feed / Source Label
              </label>
              <input
                type="text"
                value={newSource}
                onChange={(e) => setNewSource(e.target.value)}
                className="w-full h-10 px-3 text-sm bg-slate-50 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Threat Category
                </label>
                <input
                  type="text"
                  value={newCategory}
                  onChange={(e) => setNewCategory(e.target.value)}
                  className="w-full h-10 px-3 text-sm bg-slate-50 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Target Brand (Optional)
                </label>
                <input
                  type="text"
                  value={newBrand}
                  onChange={(e) => setNewBrand(e.target.value)}
                  placeholder="e.g. Microsoft, PayPal"
                  className="w-full h-10 px-3 text-sm bg-slate-50 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white"
                />
              </div>
            </div>
          </div>

          {formError && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-md text-xs text-red-800">
              {formError}
            </div>
          )}

          <div className="flex items-center justify-end">
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-2 bg-blue-700 hover:bg-blue-800 disabled:bg-slate-300 text-white text-xs font-medium rounded-md inline-flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Plus className="w-4 h-4" aria-hidden="true" />
              {submitting ? 'Saving...' : 'Add to Threat Database'}
            </button>
          </div>
        </form>
      </section>

      {/* Threat Database Table */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h3 className="text-lg font-semibold text-slate-900">
              Known-Threat SHA-256 Hash Database
            </h3>
            <p className="text-xs text-slate-500 mt-0.5 tabular-nums">
              {threats.length} total entries · {threats.filter((t) => t.isSeeded).length} starter seed · {threats.filter((t) => !t.isSeeded).length} custom
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
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by URL, hash, or brand..."
                className="h-9 pl-8 pr-3 text-xs bg-slate-50 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white w-56"
              />
            </div>

            <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-md">
              {(['all', 'seeded', 'custom'] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setFilterMode(mode)}
                  className={`px-2.5 py-1 text-xs font-medium rounded capitalize transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    filterMode === mode
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => void onResetSeed()}
              className="h-9 px-3 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" aria-hidden="true" />
              Reset Starter Seed
            </button>
          </div>
        </div>

        <div className="overflow-x-auto border border-slate-200 rounded-md">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
              <tr>
                <th className="py-2.5 px-3 font-medium">Normalized URL / Label</th>
                <th className="py-2.5 px-3 font-medium">SHA-256 Digest</th>
                <th className="py-2.5 px-3 font-medium">Source &amp; Category</th>
                <th className="py-2.5 px-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredThreats.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-500">
                    No threat hash entries match your current filter.
                  </td>
                </tr>
              ) : (
                filteredThreats.map((item) => (
                  <tr key={item.sha256} className="hover:bg-slate-50/70">
                    <td className="py-2.5 px-3 max-w-xs">
                      <div className="font-mono text-slate-900 truncate" title={item.normalizedUrl}>
                        {item.normalizedUrl}
                      </div>
                      <div className="text-slate-500 mt-0.5">
                        {item.targetBrand ? `Target: ${item.targetBrand} · ` : ''}
                        {item.isSeeded ? 'Starter Seed' : 'Custom Entry'}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-700 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <span>{item.sha256.slice(0, 18)}...{item.sha256.slice(-8)}</span>
                        <button
                          type="button"
                          onClick={() => void handleCopy(item.sha256)}
                          title="Copy full SHA-256"
                          className="text-slate-400 hover:text-slate-700 cursor-pointer"
                        >
                          {copiedHash === item.sha256 ? (
                            <Check className="w-3.5 h-3.5 text-emerald-600" aria-hidden="true" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="py-2.5 px-3 text-slate-700 whitespace-nowrap">
                      <div>{item.source}</div>
                      <div className="text-slate-500">{item.category}</div>
                    </td>
                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-2">
                        {item.normalizedUrl.startsWith('http') && (
                          <button
                            type="button"
                            onClick={() => onTestInAnalyzer(item.normalizedUrl)}
                            className="px-2.5 py-1 text-xs font-medium text-blue-700 hover:bg-blue-50 rounded inline-flex items-center gap-1 cursor-pointer"
                          >
                            <Play className="w-3 h-3" aria-hidden="true" />
                            Test
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => void onDelete(item.sha256)}
                          title="Remove entry"
                          className="p-1.5 text-slate-400 hover:text-red-600 rounded cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

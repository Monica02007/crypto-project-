import {
  ClientPhishingService,
  STATIC_PROJECT_PATHS,
  createClientZipBlob,
} from '../core/clientEngine.js';
import { renderAnalyzerView } from './analyzerView.js';
import { renderFilesView } from './filesView.js';
import { renderHistoryView } from './historyView.js';
import { renderModelsView } from './modelsView.js';
import { renderThreatLedgerView } from './threatLedgerView.js';
import { icons } from './utils.js';

const DEFAULT_DEMO_URL = 'http://login-secure-bank.xyz/update';
let clientService = null;
let backendMode = 'detecting'; // 'server' | 'client' | 'detecting'

function getClientService() {
  if (!clientService) {
    clientService = new ClientPhishingService();
  }
  return clientService;
}

async function detectBackendMode() {
  if (backendMode !== 'detecting') return backendMode;
  try {
    const res = await fetch('/api/health', { cache: 'no-store' });
    const ct = res.headers.get('content-type') || '';
    if (res.ok && ct.includes('application/json')) {
      const data = await res.json();
      if (data?.status === 'ok') {
        backendMode = 'server';
        return backendMode;
      }
    }
  } catch {
    // Static host (e.g. GitHub Pages)
  }
  backendMode = 'client';
  return backendMode;
}

const state = {
  activeTab: 'analyzer',
  mobileNavOpen: false,

  urlInput: DEFAULT_DEMO_URL,
  analysisResult: null,
  analyzing: false,
  analyzeError: null,
  addingThreat: false,
  threatAddedNotice: null,
  evidenceTab: 'features',
  copiedHash: false,

  threats: [],
  threatFilterMode: 'all',
  threatSearchQuery: '',
  threatSubmitting: false,
  threatFormError: null,
  copiedThreatHash: null,
  threatForm: {
    entryMode: 'url',
    newUrl: '',
    newHash: '',
    newSource: 'Demo Threat Feed',
    newCategory: 'Credential Phishing',
    newBrand: '',
  },

  modelReport: null,
  csvUploading: false,
  csvError: null,
  csvSuccess: null,

  history: [],
  historySearchQuery: '',

  projectFiles: [],
  filesUnavailableReason: null,
  selectedFilePath: 'index.html',
  copiedFilePath: null,
  downloadingZip: false,
};

const mainContainer = document.getElementById('main-content');
const headerActionBtn = document.getElementById('primary-header-action');
const downloadZipBtn = document.getElementById('download-zip-btn');
const mobileDrawer = document.getElementById('mobile-drawer');
const mobileMenuBtn = document.getElementById('mobile-menu-btn');
const brandBtn = document.getElementById('brand-btn');

function updateChrome() {
  document.querySelectorAll('[data-tab]').forEach((btn) => {
    const isCurrent = btn.getAttribute('data-tab') === state.activeTab;
    btn.classList.toggle('active', isCurrent);
  });

  if (mobileDrawer) {
    mobileDrawer.classList.toggle('hidden', !state.mobileNavOpen);
  }
  if (mobileMenuBtn) {
    mobileMenuBtn.setAttribute('aria-expanded', String(state.mobileNavOpen));
  }

  if (headerActionBtn) {
    if (state.analysisResult) {
      headerActionBtn.innerHTML = `${icons.download}<span>Export Report</span>`;
    } else {
      headerActionBtn.textContent = 'Run Sample';
    }
  }

  if (downloadZipBtn) {
    downloadZipBtn.disabled = state.downloadingZip;
    downloadZipBtn.innerHTML = `${icons.download}<span>${state.downloadingZip ? 'Preparing ZIP...' : 'Download ZIP'}</span>`;
  }
}

function renderActiveView() {
  updateChrome();
  if (!mainContainer) return;

  if (state.activeTab === 'analyzer') {
    renderAnalyzerView(mainContainer, state, {
      onUrlInputChange: (val) => {
        state.urlInput = val;
      },
      onAnalyze: analyzeUrl,
      onCopyHash: async (hash) => {
        try {
          await navigator.clipboard.writeText(hash);
          state.copiedHash = true;
          renderActiveView();
          window.setTimeout(() => {
            state.copiedHash = false;
            if (state.activeTab === 'analyzer') renderActiveView();
          }, 1800);
        } catch {
          // Ignore clipboard unavailability
        }
      },
      onSeedThreat: addHashFromAnalyzer,
      onEvidenceTabChange: (tab) => {
        state.evidenceTab = tab;
        renderActiveView();
      },
    });
    return;
  }

  if (state.activeTab === 'threats') {
    renderThreatLedgerView(mainContainer, state, {
      onThreatFormChange: (patch, shouldRerender) => {
        Object.assign(state.threatForm, patch);
        if (shouldRerender) {
          state.threatFormError = null;
          renderActiveView();
        }
      },
      onSubmitThreat: submitThreatEntry,
      onSearchThreat: (query) => {
        state.threatSearchQuery = query;
        const activeId = document.activeElement?.id;
        const selStart = document.activeElement?.selectionStart ?? query.length;
        renderActiveView();
        if (activeId === 'threat-search-input') {
          const el = document.getElementById('threat-search-input');
          if (el) {
            el.focus();
            el.setSelectionRange(selStart, selStart);
          }
        }
      },
      onFilterThreat: (mode) => {
        state.threatFilterMode = mode;
        renderActiveView();
      },
      onResetSeed: resetThreatSeed,
      onCopyThreatHash: async (hash) => {
        try {
          await navigator.clipboard.writeText(hash);
          state.copiedThreatHash = hash;
          renderActiveView();
          window.setTimeout(() => {
            state.copiedThreatHash = null;
            if (state.activeTab === 'threats') renderActiveView();
          }, 1500);
        } catch {
          // Ignore
        }
      },
      onTestInAnalyzer: (url) => {
        state.urlInput = url;
        state.activeTab = 'analyzer';
        analyzeUrl(url);
      },
      onDeleteThreat: deleteThreatEntry,
    });
    return;
  }

  if (state.activeTab === 'models') {
    renderModelsView(mainContainer, state, {
      onUploadCsv: uploadCsvDataset,
      onRevertDataset: revertDataset,
    });
    return;
  }

  if (state.activeTab === 'history') {
    renderHistoryView(mainContainer, state, {
      onSearchHistory: (query) => {
        state.historySearchQuery = query;
        const activeId = document.activeElement?.id;
        const selStart = document.activeElement?.selectionStart ?? query.length;
        renderActiveView();
        if (activeId === 'history-search-input') {
          const el = document.getElementById('history-search-input');
          if (el) {
            el.focus();
            el.setSelectionRange(selStart, selStart);
          }
        }
      },
      onClearHistory: clearHistory,
      onInspect: (result) => {
        state.analysisResult = result;
        state.urlInput = result.module1.normalization.rawUrl;
        state.activeTab = 'analyzer';
        renderActiveView();
      },
    });
    return;
  }

  if (state.activeTab === 'files') {
    renderFilesView(mainContainer, state, {
      onDownloadZip: downloadProjectZip,
      onSelectFile: (filePath) => {
        state.selectedFilePath = filePath;
        renderActiveView();
      },
      onCopyFile: async (file) => {
        try {
          await navigator.clipboard.writeText(file.content);
          state.copiedFilePath = file.path;
          renderActiveView();
          window.setTimeout(() => {
            state.copiedFilePath = null;
            if (state.activeTab === 'files') renderActiveView();
          }, 1500);
        } catch {
          // Ignore clipboard unavailability
        }
      },
      onDownloadSingleFile: (file) => {
        const blob = new Blob([file.content], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = file.path.split('/').pop() || 'file.txt';
        a.click();
        URL.revokeObjectURL(url);
      },
    });
  }
}

async function fetchThreats() {
  const mode = await detectBackendMode();
  if (mode === 'client') {
    state.threats = getClientService().getThreats();
    if (state.activeTab === 'threats') renderActiveView();
    return;
  }
  const res = await fetch('/api/threats');
  if (res.ok) {
    const data = await res.json();
    state.threats = data.threats ?? [];
    if (state.activeTab === 'threats') renderActiveView();
  }
}

async function fetchModels() {
  const mode = await detectBackendMode();
  if (mode === 'client') {
    state.modelReport = getClientService().getModelReport();
    if (state.activeTab === 'analyzer' || state.activeTab === 'models') {
      renderActiveView();
    }
    return;
  }
  const res = await fetch('/api/models');
  if (res.ok) {
    state.modelReport = await res.json();
    if (state.activeTab === 'analyzer' || state.activeTab === 'models') {
      renderActiveView();
    }
  }
}

async function fetchHistory() {
  const mode = await detectBackendMode();
  if (mode === 'client') {
    state.history = getClientService().getHistory();
    if (state.activeTab === 'history') renderActiveView();
    return;
  }
  const res = await fetch('/api/history');
  if (res.ok) {
    const data = await res.json();
    state.history = data.history ?? [];
    if (state.activeTab === 'history') renderActiveView();
  }
}

async function analyzeUrl(targetUrl) {
  state.analyzing = true;
  state.analyzeError = null;
  state.threatAddedNotice = null;
  renderActiveView();

  try {
    const mode = await detectBackendMode();
    if (mode === 'client') {
      state.analysisResult = getClientService().analyzeUrl(targetUrl);
      state.history = getClientService().getHistory();
      return;
    }

    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Analysis failed.');
    }
    state.analysisResult = data;
    await fetchHistory();
  } catch (err) {
    state.analyzeError =
      err instanceof Error ? err.message : 'Could not analyze URL.';
  } finally {
    state.analyzing = false;
    renderActiveView();
  }
}

async function addHashFromAnalyzer(normalizedUrl) {
  state.addingThreat = true;
  state.threatAddedNotice = null;
  renderActiveView();
  try {
    const mode = await detectBackendMode();
    if (mode === 'client') {
      getClientService().addThreat({
        mode: 'url',
        url: normalizedUrl,
        source: 'Analyst Demo Addition',
        category: 'Flagged During Inspection',
      });
      state.threats = getClientService().getThreats();
      state.threatAddedNotice =
        'Added to Threat Ledger. Click Analyze URL to observe deterministic Module 1 match.';
      return;
    }

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
    state.threatAddedNotice =
      'Added to Threat Ledger. Click Analyze URL to observe deterministic Module 1 match.';
  } catch (err) {
    state.analyzeError =
      err instanceof Error ? err.message : 'Could not add hash.';
  } finally {
    state.addingThreat = false;
    renderActiveView();
  }
}

async function submitThreatEntry() {
  state.threatSubmitting = true;
  state.threatFormError = null;
  renderActiveView();

  try {
    const payload =
      state.threatForm.entryMode === 'url'
        ? {
            mode: 'url',
            url: state.threatForm.newUrl,
            source: state.threatForm.newSource,
            category: state.threatForm.newCategory,
            targetBrand: state.threatForm.newBrand || undefined,
          }
        : {
            mode: 'hash',
            sha256: state.threatForm.newHash,
            source: state.threatForm.newSource,
            category: state.threatForm.newCategory,
            targetBrand: state.threatForm.newBrand || undefined,
          };

    const mode = await detectBackendMode();
    if (mode === 'client') {
      getClientService().addThreat(payload);
      state.threatForm.newUrl = '';
      state.threatForm.newHash = '';
      state.threatForm.newBrand = '';
      state.threats = getClientService().getThreats();
      return;
    }

    const res = await fetch('/api/threats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to add threat entry.');

    state.threatForm.newUrl = '';
    state.threatForm.newHash = '';
    state.threatForm.newBrand = '';
    await fetchThreats();
  } catch (err) {
    state.threatFormError =
      err instanceof Error ? err.message : 'Failed to add threat hash.';
  } finally {
    state.threatSubmitting = false;
    renderActiveView();
  }
}

async function deleteThreatEntry(sha256) {
  const mode = await detectBackendMode();
  if (mode === 'client') {
    getClientService().removeThreat(sha256);
    state.threats = getClientService().getThreats();
    renderActiveView();
    return;
  }
  const res = await fetch(`/api/threats/${encodeURIComponent(sha256)}`, {
    method: 'DELETE',
  });
  if (res.ok) {
    await fetchThreats();
  }
}

async function resetThreatSeed() {
  const mode = await detectBackendMode();
  if (mode === 'client') {
    state.threats = getClientService().resetThreats();
    renderActiveView();
    return;
  }
  const res = await fetch('/api/threats/reset', { method: 'POST' });
  if (res.ok) {
    const data = await res.json();
    state.threats = data.threats ?? [];
    renderActiveView();
  }
}

async function uploadCsvDataset(file) {
  state.csvUploading = true;
  state.csvError = null;
  state.csvSuccess = null;
  renderActiveView();

  try {
    const csvText = await file.text();
    const datasetName = `Uploaded CSV: ${file.name}`;
    const mode = await detectBackendMode();
    if (mode === 'client') {
      state.modelReport = getClientService().evaluateCsvDataset(csvText, datasetName);
      state.csvSuccess = `Trained and evaluated TF-IDF + Multinomial NB and Logistic Regression on "${file.name}".`;
      return;
    }

    const res = await fetch('/api/models/evaluate-csv', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csvText, datasetName }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to evaluate CSV.');
    state.modelReport = data;
    state.csvSuccess = `Trained and evaluated TF-IDF + Multinomial NB and Logistic Regression on "${file.name}".`;
  } catch (err) {
    state.csvError =
      err instanceof Error ? err.message : 'Failed to evaluate CSV dataset.';
  } finally {
    state.csvUploading = false;
    renderActiveView();
  }
}

async function revertDataset() {
  state.csvError = null;
  state.csvSuccess = null;
  const mode = await detectBackendMode();
  if (mode === 'client') {
    state.modelReport = getClientService().revertToBuiltInDataset();
    renderActiveView();
    return;
  }
  const res = await fetch('/api/models/revert', { method: 'POST' });
  if (res.ok) {
    state.modelReport = await res.json();
    renderActiveView();
  }
}

async function clearHistory() {
  const mode = await detectBackendMode();
  if (mode === 'client') {
    getClientService().clearHistory();
    state.history = [];
    renderActiveView();
    return;
  }
  const res = await fetch('/api/history', { method: 'DELETE' });
  if (res.ok) {
    state.history = [];
    renderActiveView();
  }
}

async function fetchProjectFiles() {
  const mode = await detectBackendMode();
  if (mode === 'server') {
    const res = await fetch('/api/files');
    if (res.ok) {
      const data = await res.json();
      state.projectFiles = data.files ?? [];
      state.filesUnavailableReason = null;
      if (state.activeTab === 'files') renderActiveView();
    }
    return;
  }

  // On static hosts (e.g. GitHub Pages root deployment), fetch source files directly via relative paths
  try {
    const probe = await fetch('./src/js/app.js', { cache: 'no-store' });
    const ct = probe.headers.get('content-type') || '';
    if (!probe.ok || ct.includes('text/html')) {
      state.filesUnavailableReason =
        'Running as a compiled static bundle (dist/). Source files and ZIP export are available on the repository or when running locally with npm run dev.';
      if (state.activeTab === 'files') renderActiveView();
      return;
    }

    const loaded = [];
    for (const filePath of STATIC_PROJECT_PATHS) {
      try {
        const res = await fetch(`./${filePath}`, { cache: 'no-store' });
        if (!res.ok) continue;
        const content = await res.text();
        loaded.push({
          path: filePath,
          size: new TextEncoder().encode(content).length,
          content,
        });
      } catch {
        // Skip optional hidden/workflow files blocked by host rules
      }
    }
    if (loaded.length > 0) {
      state.projectFiles = loaded.sort((a, b) => a.path.localeCompare(b.path));
      state.filesUnavailableReason = null;
    } else {
      state.filesUnavailableReason =
        'Source files are not exposed on this static host.';
    }
  } catch {
    state.filesUnavailableReason =
      'Source files are not exposed on this static host.';
  }
  if (state.activeTab === 'files') renderActiveView();
}

async function downloadProjectZip() {
  state.downloadingZip = true;
  renderActiveView();
  try {
    const mode = await detectBackendMode();
    let blob;
    if (mode === 'server') {
      const res = await fetch('/api/download-zip');
      if (!res.ok) throw new Error('Failed to generate ZIP.');
      blob = await res.blob();
    } else {
      if (state.projectFiles.length === 0) {
        await fetchProjectFiles();
      }
      if (state.projectFiles.length === 0) {
        state.activeTab = 'files';
        return;
      }
      blob = createClientZipBlob(state.projectFiles);
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'veriurl-phishing-detector.zip';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    state.analyzeError =
      err instanceof Error ? err.message : 'ZIP download failed.';
  } finally {
    state.downloadingZip = false;
    renderActiveView();
  }
}

function exportReport() {
  if (!state.analysisResult) return;
  const blob = new Blob([JSON.stringify(state.analysisResult, null, 2)], {
    type: 'application/json',
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `veriurl-report-${state.analysisResult.module1.sha256.slice(0, 12)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// Topbar & Navigation Events
document.querySelectorAll('[data-tab]').forEach((btn) => {
  btn.addEventListener('click', () => {
    state.activeTab = btn.getAttribute('data-tab');
    state.mobileNavOpen = false;
    if (
      state.activeTab === 'files' &&
      state.projectFiles.length === 0 &&
      !state.filesUnavailableReason
    ) {
      fetchProjectFiles();
    }
    renderActiveView();
  });
});

brandBtn?.addEventListener('click', () => {
  state.activeTab = 'analyzer';
  state.mobileNavOpen = false;
  renderActiveView();
});

mobileMenuBtn?.addEventListener('click', () => {
  state.mobileNavOpen = !state.mobileNavOpen;
  updateChrome();
});

downloadZipBtn?.addEventListener('click', () => {
  downloadProjectZip();
});

headerActionBtn?.addEventListener('click', () => {
  if (state.analysisResult) {
    exportReport();
  } else {
    state.activeTab = 'analyzer';
    analyzeUrl(DEFAULT_DEMO_URL);
  }
});

// Initial bootstrap
async function initApp() {
  renderActiveView();
  await detectBackendMode();
  await Promise.all([
    fetchThreats(),
    fetchModels(),
    fetchHistory(),
    fetchProjectFiles(),
  ]);
  await analyzeUrl(DEFAULT_DEMO_URL);
}

initApp();

import { getDefaultBuiltInDataset, parseUrlDatasetCsv } from './datasetData.js';
import { HybridMLEngine } from './mlEngine.js';
import { normalizeUrl } from './normalizer.js';
import { sha256Hex } from './sha256.js';
import { DISCLAIMER_TEXT, STARTER_THREAT_SEEDS } from './threatSeeds.js';

const THREATS_STORAGE_KEY = 'veriurl_threat_hashes_v1';
const HISTORY_STORAGE_KEY = 'veriurl_scan_history_v1';

function buildSeededThreatMap() {
  const baseDate = '2026-11-15T10:00:00.000Z';
  const map = new Map();
  for (const seed of STARTER_THREAT_SEEDS) {
    const norm = normalizeUrl(seed.url);
    if (!norm.valid) continue;
    const sha256 = sha256Hex(norm.normalizedUrl);
    map.set(sha256, {
      sha256,
      normalizedUrl: norm.normalizedUrl,
      source: seed.source,
      category: seed.category,
      targetBrand: seed.targetBrand,
      addedAt: baseDate,
      isSeeded: true,
    });
  }
  return map;
}

function generateId() {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  return `scan-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

export class ClientPhishingService {
  constructor() {
    this.threatRecords = this.loadThreats();
    const initial = getDefaultBuiltInDataset();
    this.mlEngine = new HybridMLEngine(initial.samples, initial.name, 'built-in');
    this.history = this.loadHistory();
  }

  loadThreats() {
    try {
      const raw = globalThis.localStorage?.getItem(THREATS_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.length > 0) {
          const map = new Map();
          for (const rec of parsed) {
            if (rec && typeof rec.sha256 === 'string') {
              map.set(rec.sha256.toLowerCase(), rec);
            }
          }
          if (map.size > 0) return map;
        }
      }
    } catch {
      // Fallback to starter seed
    }
    const seeded = buildSeededThreatMap();
    this.saveThreats(seeded);
    return seeded;
  }

  saveThreats(map = this.threatRecords) {
    try {
      globalThis.localStorage?.setItem(
        THREATS_STORAGE_KEY,
        JSON.stringify(Array.from(map.values()))
      );
    } catch {
      // Ignore storage quota errors
    }
  }

  loadHistory() {
    try {
      const raw = globalThis.localStorage?.getItem(HISTORY_STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.slice(0, 50) : [];
    } catch {
      return [];
    }
  }

  saveHistory() {
    try {
      globalThis.localStorage?.setItem(
        HISTORY_STORAGE_KEY,
        JSON.stringify(this.history.slice(0, 50))
      );
    } catch {
      // Ignore storage quota errors
    }
  }

  getThreats() {
    return Array.from(this.threatRecords.values()).sort((a, b) =>
      b.addedAt.localeCompare(a.addedAt)
    );
  }

  addThreat(payload) {
    if (payload.mode === 'hash') {
      const cleanHash = String(payload.sha256 ?? '').trim().toLowerCase();
      if (!/^[a-f0-9]{64}$/.test(cleanHash)) {
        throw new Error('SHA-256 hash must be exactly 64 hexadecimal characters.');
      }
      const record = {
        sha256: cleanHash,
        normalizedUrl: payload.labelUrl?.trim() || '(Raw SHA-256 Digest Entry)',
        source: payload.source?.trim() || 'Manual SHA-256 Entry',
        category: payload.category?.trim() || 'Imported Threat Digest',
        targetBrand: payload.targetBrand?.trim() || undefined,
        addedAt: new Date().toISOString(),
        isSeeded: false,
      };
      this.threatRecords.set(cleanHash, record);
      this.saveThreats();
      return record;
    }

    const norm = normalizeUrl(String(payload.url ?? ''));
    if (!norm.valid) {
      throw new Error(norm.error ?? 'Invalid URL provided.');
    }
    const sha256 = sha256Hex(norm.normalizedUrl);
    const record = {
      sha256,
      normalizedUrl: norm.normalizedUrl,
      source: payload.source?.trim() || 'Custom Demo Entry',
      category: payload.category?.trim() || 'Reported Phishing URL',
      targetBrand: payload.targetBrand?.trim() || undefined,
      addedAt: new Date().toISOString(),
      isSeeded: false,
    };
    this.threatRecords.set(sha256, record);
    this.saveThreats();
    return record;
  }

  removeThreat(sha256) {
    const deleted = this.threatRecords.delete(String(sha256).trim().toLowerCase());
    if (deleted) this.saveThreats();
    return deleted;
  }

  resetThreats() {
    this.threatRecords = buildSeededThreatMap();
    this.saveThreats();
    return this.getThreats();
  }

  getModelReport() {
    return this.mlEngine.report;
  }

  evaluateCsvDataset(csvText, datasetName) {
    const parsed = parseUrlDatasetCsv(csvText);
    const title = datasetName?.trim() || parsed.formatDetected;
    this.mlEngine = new HybridMLEngine(parsed.samples, title, 'uploaded-csv');
    return this.mlEngine.report;
  }

  revertToBuiltInDataset() {
    const initial = getDefaultBuiltInDataset();
    this.mlEngine = new HybridMLEngine(initial.samples, initial.name, 'built-in');
    return this.mlEngine.report;
  }

  getHistory() {
    return this.history;
  }

  clearHistory() {
    this.history = [];
    this.saveHistory();
  }

  analyzeUrl(rawUrl) {
    const normalization = normalizeUrl(rawUrl);
    if (!normalization.valid) {
      throw new Error(normalization.error ?? 'Invalid URL input.');
    }

    const sha256 = sha256Hex(normalization.normalizedUrl);
    const matchedThreat = this.threatRecords.get(sha256) ?? null;

    const module1 = {
      normalization,
      sha256,
      hashLookupStatus: matchedThreat ? 'MATCH' : 'MISS',
      matchedThreat,
      safetyNote: matchedThreat
        ? `Exact SHA-256 digest match found in Known-Threat Database (${matchedThreat.source}). Flagged immediately without relying on probabilistic ML.`
        : 'No exact SHA-256 match found in the local Known-Threat Database. A hash mismatch does not guarantee safety — passing normalized URL to Module 2 for ML & structural analysis.',
    };

    const mlPrediction = this.mlEngine.predict(normalization.normalizedUrl);

    const module2 = {
      executed: true,
      skippedReason: matchedThreat
        ? 'Module 1 matched an exact known-threat SHA-256 hash; Module 2 diagnostic ML analysis is shown alongside for verification.'
        : undefined,
      ensembleProbability: mlPrediction.ensembleProbability,
      mnbProbability: mlPrediction.mnbProbability,
      logregProbability: mlPrediction.logregProbability,
      ensembleWeights: this.mlEngine.report.ensembleWeights,
      lexicalFeatures: mlPrediction.lexicalFeatures,
      featureContributions: mlPrediction.featureContributions,
      topTriggers: mlPrediction.topTriggers,
      topNGrams: mlPrediction.topNGrams,
      matchedKeywords: mlPrediction.matchedKeywords,
    };

    let module3;
    if (matchedThreat) {
      module3 = {
        verdict: 'HIGH_RISK_KNOWN_THREAT',
        verdictLabel: 'High Risk Phishing Site',
        riskScore: 1.0,
        confidenceLabel: 'Deterministic Cryptographic Match (100%)',
        decisionBasis: 'DETERMINISTIC_HASH',
        summary: `Found an exact SHA-256 match in the known-threat database (${matchedThreat.source}). Machine learning models independently scored ${(mlPrediction.ensembleProbability * 100).toFixed(0)}% phishing probability.`,
        decisionSteps: [
          `Module 1 normalized input to "${normalization.normalizedUrl}".`,
          `Computed SHA-256 digest: ${sha256}.`,
          `Exact match confirmed in Known-Threat Hash Database (${matchedThreat.category}).`,
          `Diagnostic ML ensemble (TF-IDF MNB ${(mlPrediction.mnbProbability * 100).toFixed(1)}% + LogReg ${(mlPrediction.logregProbability * 100).toFixed(1)}%) scored ${(mlPrediction.ensembleProbability * 100).toFixed(1)}%.`,
        ],
        disclaimer: DISCLAIMER_TEXT,
      };
    } else {
      const score = mlPrediction.ensembleProbability;
      let verdict;
      let verdictLabel;
      let confidenceLabel;
      let summary;

      if (score >= 0.72) {
        verdict = 'HIGH_RISK_ML';
        verdictLabel = 'High Risk Phishing Site';
        confidenceLabel = `High ML Risk Estimate (${(score * 100).toFixed(1)}%)`;
        summary = `No exact hash match found, but Module 2 classical ML ensemble scored ${(score * 100).toFixed(1)}% phishing probability (TF-IDF + MNB: ${(mlPrediction.mnbProbability * 100).toFixed(1)}%, Logistic Regression: ${(mlPrediction.logregProbability * 100).toFixed(1)}%).`;
      } else if (score >= 0.4) {
        verdict = 'SUSPICIOUS';
        verdictLabel = 'Suspicious / Potential Phishing';
        confidenceLabel = `Moderate ML Risk Estimate (${(score * 100).toFixed(1)}%)`;
        summary = `No exact hash match found. Module 2 detected mixed or elevated risk indicators with an ensemble score of ${(score * 100).toFixed(1)}% (TF-IDF + MNB: ${(mlPrediction.mnbProbability * 100).toFixed(1)}%, Logistic Regression: ${(mlPrediction.logregProbability * 100).toFixed(1)}%). Manual verification advised.`;
      } else {
        verdict = 'LOW_RISK';
        verdictLabel = 'Low Risk / Likely Legitimate';
        confidenceLabel = `Low ML Risk Estimate (${(score * 100).toFixed(1)}%)`;
        summary = `No exact hash match found, and Module 2 scored ${(score * 100).toFixed(1)}% phishing probability across both TF-IDF character n-grams and structural lexical features.`;
      }

      module3 = {
        verdict,
        verdictLabel,
        riskScore: score,
        confidenceLabel,
        decisionBasis: 'PROBABILISTIC_ML',
        summary,
        decisionSteps: [
          `Module 1 normalized input to "${normalization.normalizedUrl}".`,
          `Computed SHA-256 digest: ${sha256}.`,
          'Hash DB returned a MISS (note: absence from hash list does not prove safety).',
          `TF-IDF + Multinomial Naive Bayes scored ${(mlPrediction.mnbProbability * 100).toFixed(1)}%.`,
          `Logistic Regression (18 lexical features) scored ${(mlPrediction.logregProbability * 100).toFixed(1)}%.`,
          `Weighted ML ensemble (${(this.mlEngine.report.ensembleWeights.mnb * 100).toFixed(0)}% MNB + ${(this.mlEngine.report.ensembleWeights.logreg * 100).toFixed(0)}% LR) = ${(mlPrediction.ensembleProbability * 100).toFixed(1)}% -> ${verdictLabel}.`,
        ],
        disclaimer: DISCLAIMER_TEXT,
      };
    }

    const result = {
      id: generateId(),
      analyzedAt: new Date().toISOString(),
      module1,
      module2,
      module3,
    };

    const historyEntry = {
      id: result.id,
      analyzedAt: result.analyzedAt,
      rawUrl: normalization.rawUrl,
      normalizedUrl: normalization.normalizedUrl,
      sha256,
      hashStatus: module1.hashLookupStatus,
      verdict: module3.verdict,
      verdictLabel: module3.verdictLabel,
      riskScore: module3.riskScore,
      mnbProbability: module2.mnbProbability,
      logregProbability: module2.logregProbability,
      result,
    };

    this.history = [
      historyEntry,
      ...this.history.filter((h) => h.id !== result.id),
    ].slice(0, 50);
    this.saveHistory();

    return result;
  }
}

// Pure-browser ZIP store builder (zero Node dependencies) for static hosts
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32Bytes(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function createClientZipBlob(files, prefixFolder = 'veriurl-phishing-detector') {
  const encoder = new TextEncoder();
  const localChunks = [];
  const centralChunks = [];
  let offset = 0;

  for (const file of files) {
    const nameBytes = encoder.encode(`${prefixFolder}/${file.path}`);
    const dataBytes = encoder.encode(file.content);
    const crc = crc32Bytes(dataBytes);

    const localHeader = new Uint8Array(30);
    const ldv = new DataView(localHeader.buffer);
    ldv.setUint32(0, 0x04034b50, true);
    ldv.setUint16(4, 20, true);
    ldv.setUint16(6, 0x0800, true);
    ldv.setUint16(8, 0, true); // Store (uncompressed) for universal compatibility
    ldv.setUint16(10, 0, true);
    ldv.setUint16(12, 0x5421, true);
    ldv.setUint32(14, crc, true);
    ldv.setUint32(18, dataBytes.length, true);
    ldv.setUint32(22, dataBytes.length, true);
    ldv.setUint16(26, nameBytes.length, true);
    ldv.setUint16(28, 0, true);

    localChunks.push(localHeader, nameBytes, dataBytes);

    const centralHeader = new Uint8Array(46);
    const cdv = new DataView(centralHeader.buffer);
    cdv.setUint32(0, 0x02014b50, true);
    cdv.setUint16(4, 20, true);
    cdv.setUint16(6, 20, true);
    cdv.setUint16(8, 0x0800, true);
    cdv.setUint16(10, 0, true);
    cdv.setUint16(12, 0, true);
    cdv.setUint16(14, 0x5421, true);
    cdv.setUint32(16, crc, true);
    cdv.setUint32(20, dataBytes.length, true);
    cdv.setUint32(24, dataBytes.length, true);
    cdv.setUint16(28, nameBytes.length, true);
    cdv.setUint16(30, 0, true);
    cdv.setUint16(32, 0, true);
    cdv.setUint16(34, 0, true);
    cdv.setUint16(36, 0, true);
    cdv.setUint32(38, 0, true);
    cdv.setUint32(42, offset, true);

    centralChunks.push(centralHeader, nameBytes);
    offset += localHeader.length + nameBytes.length + dataBytes.length;
  }

  let centralSize = 0;
  for (const chunk of centralChunks) centralSize += chunk.length;

  const eocd = new Uint8Array(22);
  const edv = new DataView(eocd.buffer);
  edv.setUint32(0, 0x06054b50, true);
  edv.setUint16(4, 0, true);
  edv.setUint16(6, 0, true);
  edv.setUint16(8, files.length, true);
  edv.setUint16(10, files.length, true);
  edv.setUint32(12, centralSize, true);
  edv.setUint32(16, offset, true);
  edv.setUint16(20, 0, true);

  return new Blob([...localChunks, ...centralChunks, eocd], {
    type: 'application/zip',
  });
}

export const STATIC_PROJECT_PATHS = [
  '.env.example',
  '.gitignore',
  '.nojekyll',
  'README.md',
  'index.html',
  'metadata.json',
  'package.json',
  'scripts/lint.js',
  'server.js',
  'src/core/clientEngine.js',
  'src/core/datasetData.js',
  'src/core/features.js',
  'src/core/mlEngine.js',
  'src/core/normalizer.js',
  'src/core/sha256.js',
  'src/core/threatSeeds.js',
  'src/css/styles.css',
  'src/js/analyzerView.js',
  'src/js/app.js',
  'src/js/filesView.js',
  'src/js/gauge.js',
  'src/js/historyView.js',
  'src/js/modelsView.js',
  'src/js/threatLedgerView.js',
  'src/js/utils.js',
  'src/server/analyzer.js',
  'src/server/dataset.js',
  'src/server/threatStore.js',
  'src/server/zipBuilder.js',
  'vite.config.js',
];

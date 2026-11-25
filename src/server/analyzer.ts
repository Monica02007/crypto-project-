import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { HybridMLEngine } from '../core/mlEngine.ts';
import { normalizeUrl } from '../core/normalizer.ts';
import type {
  AnalysisResult,
  ModelComparisonReport,
  Module1Report,
  Module2Report,
  Module3Report,
  ScanHistoryEntry,
  VerdictLevel,
} from '../core/types.ts';
import { loadLocalDatasetIfExists, parseUrlDatasetCsv } from './dataset.ts';
import { ThreatHashStore, computeSha256Hex } from './threatStore.ts';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const HISTORY_PATH = path.join(DATA_DIR, 'scan-history.json');

const DISCLAIMER_TEXT =
  'Probabilistic Assessment Disclaimer: Cryptographic hash matching only detects exact known normalized URLs, and classical ML predictions are statistical estimates rather than absolute guarantees. Novel zero-day phishing URLs can evade both checks, while complex legitimate URLs (e.g., long OAuth or tracking links) can occasionally trigger false positives.';

export class PhishingDetectionService {
  threatStore: ThreatHashStore;
  mlEngine: HybridMLEngine;
  private history: ScanHistoryEntry[];

  constructor() {
    this.threatStore = new ThreatHashStore();
    const initial = loadLocalDatasetIfExists();
    this.mlEngine = new HybridMLEngine(initial.samples, initial.name, 'built-in');
    this.history = this.loadHistory();
  }

  private ensureDataDir(): void {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  }

  private loadHistory(): ScanHistoryEntry[] {
    if (!fs.existsSync(HISTORY_PATH)) return [];
    try {
      const parsed = JSON.parse(fs.readFileSync(HISTORY_PATH, 'utf-8'));
      return Array.isArray(parsed) ? parsed.slice(0, 50) : [];
    } catch {
      return [];
    }
  }

  private saveHistory(): void {
    this.ensureDataDir();
    fs.writeFileSync(
      HISTORY_PATH,
      JSON.stringify(this.history.slice(0, 50), null, 2),
      'utf-8'
    );
  }

  getModelReport(): ModelComparisonReport {
    return this.mlEngine.report;
  }

  evaluateCsvDataset(
    csvText: string,
    datasetName?: string
  ): ModelComparisonReport {
    const parsed = parseUrlDatasetCsv(csvText);
    const title = datasetName?.trim() || parsed.formatDetected;
    this.mlEngine = new HybridMLEngine(parsed.samples, title, 'uploaded-csv');
    return this.mlEngine.report;
  }

  revertToBuiltInDataset(): ModelComparisonReport {
    const initial = loadLocalDatasetIfExists();
    this.mlEngine = new HybridMLEngine(initial.samples, initial.name, 'built-in');
    return this.mlEngine.report;
  }

  getHistory(): ScanHistoryEntry[] {
    return this.history;
  }

  clearHistory(): void {
    this.history = [];
    this.saveHistory();
  }

  analyzeUrl(
    rawUrl: string,
    options?: { forceMlInspection?: boolean }
  ): AnalysisResult {
    const normalization = normalizeUrl(rawUrl);
    if (!normalization.valid) {
      throw new Error(normalization.error ?? 'Invalid URL input.');
    }

    const sha256 = computeSha256Hex(normalization.normalizedUrl);
    const matchedThreat = this.threatStore.lookup(sha256);

    const module1: Module1Report = {
      normalization,
      sha256,
      hashLookupStatus: matchedThreat ? 'MATCH' : 'MISS',
      matchedThreat,
      safetyNote: matchedThreat
        ? `Exact SHA-256 digest match found in Known-Threat Database (${matchedThreat.source}). Flagged immediately without relying on probabilistic ML.`
        : 'No exact SHA-256 match found in the local Known-Threat Database. A hash mismatch does not guarantee safety — passing normalized URL to Module 2 for ML & structural analysis.',
    };

    const mlPrediction = this.mlEngine.predict(normalization.normalizedUrl);

    const module2: Module2Report = {
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

    let module3: Module3Report;

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
      let verdict: VerdictLevel;
      let verdictLabel: string;
      let confidenceLabel: string;
      let summary: string;

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

      const decisionSteps: string[] = [
        `Module 1 normalized input to "${normalization.normalizedUrl}".`,
        `Computed SHA-256 digest: ${sha256}.`,
        'Hash DB returned a MISS (note: absence from hash list does not prove safety).',
        `TF-IDF + Multinomial Naive Bayes scored ${(mlPrediction.mnbProbability * 100).toFixed(1)}%.`,
        `Logistic Regression (18 lexical features) scored ${(mlPrediction.logregProbability * 100).toFixed(1)}%.`,
        `Weighted ML ensemble (${(this.mlEngine.report.ensembleWeights.mnb * 100).toFixed(0)}% MNB + ${(this.mlEngine.report.ensembleWeights.logreg * 100).toFixed(0)}% LR) = ${(mlPrediction.ensembleProbability * 100).toFixed(1)}% -> ${verdictLabel}.`,
      ];

      module3 = {
        verdict,
        verdictLabel,
        riskScore: score,
        confidenceLabel,
        decisionBasis: 'PROBABILISTIC_ML',
        summary,
        decisionSteps,
        disclaimer: DISCLAIMER_TEXT,
      };
    }

    const result: AnalysisResult = {
      id: crypto.randomUUID(),
      analyzedAt: new Date().toISOString(),
      module1,
      module2,
      module3,
    };

    const historyEntry: ScanHistoryEntry = {
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

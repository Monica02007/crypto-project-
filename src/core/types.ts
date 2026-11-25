export type VerdictLevel =
  | 'HIGH_RISK_KNOWN_THREAT'
  | 'HIGH_RISK_ML'
  | 'SUSPICIOUS'
  | 'LOW_RISK';

export interface NormalizationStep {
  rule: string;
  applied: boolean;
  detail: string;
}

export interface NormalizationResult {
  rawUrl: string;
  normalizedUrl: string;
  scheme: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  steps: NormalizationStep[];
  valid: boolean;
  error?: string;
}

export interface ThreatHashRecord {
  sha256: string;
  normalizedUrl: string;
  source: string;
  category: string;
  targetBrand?: string;
  addedAt: string;
  isSeeded: boolean;
}

export interface LexicalFeatures {
  urlLength: number;
  hostnameLength: number;
  pathLength: number;
  dotCount: number;
  hyphenCount: number;
  underscoreCount: number;
  slashCount: number;
  questionCount: number;
  equalCount: number;
  atSymbolPresent: number;
  doubleSlashRedirect: number;
  isHttps: number;
  hasIpAddress: number;
  digitRatio: number;
  specialCharCount: number;
  subdomainDepth: number;
  suspiciousKeywordCount: number;
  shannonEntropy: number;
}

export interface FeatureMetadata {
  key: keyof LexicalFeatures;
  label: string;
  description: string;
  format: 'int' | 'ratio' | 'bool' | 'float';
}

export interface FeatureContribution {
  key: keyof LexicalFeatures;
  label: string;
  rawValue: number;
  formattedValue: string;
  standardizedValue: number;
  weight: number;
  contribution: number;
  direction: 'phishing' | 'legitimate' | 'neutral';
  triggerReason?: string;
}

export interface NGramContribution {
  token: string;
  tfidfWeight: number;
  logOdds: number;
  impact: number;
  direction: 'phishing' | 'legitimate';
}

export interface ConfusionMatrix {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export interface ModelMetrics {
  modelName: string;
  modelKey: 'mnb' | 'logreg' | 'ensemble';
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  confusionMatrix: ConfusionMatrix;
  trainSamples: number;
  testSamples: number;
}

export interface GlobalFeatureWeight {
  key: keyof LexicalFeatures;
  label: string;
  weight: number;
  direction: 'phishing' | 'legitimate';
}

export interface GlobalNGramIndicator {
  token: string;
  logOdds: number;
  phishDocFreq: number;
  legitDocFreq: number;
}

export interface DatasetSummary {
  name: string;
  sourceType: 'built-in' | 'uploaded-csv';
  totalSamples: number;
  phishingCount: number;
  legitimateCount: number;
  trainSize: number;
  testSize: number;
  vocabSize: number;
  trainedAt: string;
}

export interface ModelComparisonReport {
  dataset: DatasetSummary;
  ensembleWeights: {
    mnb: number;
    logreg: number;
  };
  metrics: {
    mnb: ModelMetrics;
    logreg: ModelMetrics;
    ensemble: ModelMetrics;
  };
  globalFeatureWeights: GlobalFeatureWeight[];
  topPhishingNGrams: GlobalNGramIndicator[];
  topLegitimateNGrams: GlobalNGramIndicator[];
}

export interface Module1Report {
  normalization: NormalizationResult;
  sha256: string;
  hashLookupStatus: 'MATCH' | 'MISS';
  matchedThreat: ThreatHashRecord | null;
  safetyNote: string;
}

export interface Module2Report {
  executed: boolean;
  skippedReason?: string;
  ensembleProbability: number;
  mnbProbability: number;
  logregProbability: number;
  ensembleWeights: {
    mnb: number;
    logreg: number;
  };
  lexicalFeatures: LexicalFeatures;
  featureContributions: FeatureContribution[];
  topTriggers: FeatureContribution[];
  topNGrams: NGramContribution[];
  matchedKeywords: string[];
}

export interface Module3Report {
  verdict: VerdictLevel;
  verdictLabel: string;
  riskScore: number;
  confidenceLabel: string;
  decisionBasis: 'DETERMINISTIC_HASH' | 'PROBABILISTIC_ML';
  summary: string;
  decisionSteps: string[];
  disclaimer: string;
}

export interface AnalysisResult {
  id: string;
  analyzedAt: string;
  module1: Module1Report;
  module2: Module2Report;
  module3: Module3Report;
}

export interface ScanHistoryEntry {
  id: string;
  analyzedAt: string;
  rawUrl: string;
  normalizedUrl: string;
  sha256: string;
  hashStatus: 'MATCH' | 'MISS';
  verdict: VerdictLevel;
  verdictLabel: string;
  riskScore: number;
  mnbProbability: number | null;
  logregProbability: number | null;
  result: AnalysisResult;
}

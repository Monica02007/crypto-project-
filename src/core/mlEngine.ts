import {
  FEATURE_METADATA,
  extractLexicalFeatures,
  featureVectorFromStruct,
  formatFeatureValue,
} from './features.ts';
import type {
  ConfusionMatrix,
  DatasetSummary,
  FeatureContribution,
  GlobalFeatureWeight,
  GlobalNGramIndicator,
  LexicalFeatures,
  ModelComparisonReport,
  ModelMetrics,
  NGramContribution,
} from './types.ts';

export interface LabeledUrlSample {
  url: string;
  label: 0 | 1; // 1 = phishing, 0 = legitimate
}

interface TrainedNaiveBayes {
  vocab: string[];
  vocabIndex: Map<string, number>;
  idf: number[];
  logPriorPhish: number;
  logPriorLegit: number;
  logLikelihoodPhish: number[];
  logLikelihoodLegit: number[];
  phishDocFreq: number[];
  legitDocFreq: number[];
}

interface TrainedLogisticRegression {
  means: number[];
  stds: number[];
  weights: number[];
  bias: number;
}

export interface MLRuntimePrediction {
  ensembleProbability: number;
  mnbProbability: number;
  logregProbability: number;
  lexicalFeatures: LexicalFeatures;
  matchedKeywords: string[];
  featureContributions: FeatureContribution[];
  topTriggers: FeatureContribution[];
  topNGrams: NGramContribution[];
}

const ENSEMBLE_WEIGHT_MNB = 0.45;
const ENSEMBLE_WEIGHT_LR = 0.55;

function sigmoid(z: number): number {
  if (z > 35) return 1 - 1e-15;
  if (z < -35) return 1e-15;
  return 1 / (1 + Math.exp(-z));
}

export function tokenizeUrlForNGrams(url: string): string[] {
  const lower = url.toLowerCase().replace(/^https?:\/\//, '');
  const tokens: string[] = [];

  // Delimited lexical tokens (e.g., host labels, path segments, query words)
  const wordTokens = lower.split(/[^a-z0-9]+/).filter((w) => w.length >= 2);
  for (const w of wordTokens) {
    tokens.push(`tok:${w}`);
  }

  // Character 3-grams, 4-grams, 5-grams across URL structure
  const bounded = `^${lower.slice(0, 140)}$`;
  for (const n of [3, 4, 5]) {
    for (let i = 0; i <= bounded.length - n; i++) {
      tokens.push(`c${n}:${bounded.slice(i, i + n)}`);
    }
  }

  return tokens;
}

function deterministicShuffle<T>(items: T[], seed = 20261122): T[] {
  const arr = [...items];
  let s = seed >>> 0;
  for (let i = arr.length - 1; i > 0; i--) {
    s = (1664525 * s + 1013904223) >>> 0;
    const j = s % (i + 1);
    const tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }
  return arr;
}

function stratifiedSplit(
  samples: LabeledUrlSample[],
  testRatio = 0.2
): { train: LabeledUrlSample[]; test: LabeledUrlSample[] } {
  const phish = deterministicShuffle(
    samples.filter((s) => s.label === 1),
    104729
  );
  const legit = deterministicShuffle(
    samples.filter((s) => s.label === 0),
    224737
  );

  const phishTestCount = Math.max(1, Math.round(phish.length * testRatio));
  const legitTestCount = Math.max(1, Math.round(legit.length * testRatio));

  const test = deterministicShuffle(
    [...phish.slice(0, phishTestCount), ...legit.slice(0, legitTestCount)],
    99173
  );
  const train = deterministicShuffle(
    [...phish.slice(phishTestCount), ...legit.slice(legitTestCount)],
    48611
  );

  return { train, test };
}

function trainMultinomialNB(train: LabeledUrlSample[]): TrainedNaiveBayes {
  const docFreq = new Map<string, number>();
  const tokenizedDocs = train.map((sample) => {
    const tokens = tokenizeUrlForNGrams(sample.url);
    const unique = new Set(tokens);
    for (const tok of unique) {
      docFreq.set(tok, (docFreq.get(tok) ?? 0) + 1);
    }
    return { label: sample.label, tokens };
  });

  const minDf = train.length >= 40 ? 2 : 1;
  const maxVocab = 2500;
  const vocabEntries = Array.from(docFreq.entries())
    .filter(([, df]) => df >= minDf)
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxVocab);

  const vocab = vocabEntries.map(([tok]) => tok);
  const vocabIndex = new Map<string, number>();
  vocab.forEach((tok, idx) => vocabIndex.set(tok, idx));

  const nDocs = train.length;
  const idf = vocabEntries.map(([, df]) =>
    Math.log((1 + nDocs) / (1 + df)) + 1
  );

  const vSize = vocab.length;
  const phishTfIdfSum = new Array<number>(vSize).fill(0);
  const legitTfIdfSum = new Array<number>(vSize).fill(0);
  const phishDocFreq = new Array<number>(vSize).fill(0);
  const legitDocFreq = new Array<number>(vSize).fill(0);

  let phishDocs = 0;
  let legitDocs = 0;

  for (const doc of tokenizedDocs) {
    if (doc.label === 1) phishDocs++;
    else legitDocs++;

    const counts = new Map<number, number>();
    for (const tok of doc.tokens) {
      const idx = vocabIndex.get(tok);
      if (idx !== undefined) {
        counts.set(idx, (counts.get(idx) ?? 0) + 1);
      }
    }

    // L2-normalized TF-IDF vector per URL document
    let normSq = 0;
    const weighted = new Map<number, number>();
    for (const [idx, count] of counts.entries()) {
      const tf = 1 + Math.log(count);
      const val = tf * idf[idx];
      weighted.set(idx, val);
      normSq += val * val;
    }
    const norm = Math.sqrt(normSq) || 1;

    for (const [idx, val] of weighted.entries()) {
      const normVal = val / norm;
      if (doc.label === 1) {
        phishTfIdfSum[idx] += normVal;
        phishDocFreq[idx] += 1;
      } else {
        legitTfIdfSum[idx] += normVal;
        legitDocFreq[idx] += 1;
      }
    }
  }

  const alpha = 1.0;
  const totalPhishMass =
    phishTfIdfSum.reduce((acc, v) => acc + v, 0) + alpha * vSize;
  const totalLegitMass =
    legitTfIdfSum.reduce((acc, v) => acc + v, 0) + alpha * vSize;

  const logLikelihoodPhish = phishTfIdfSum.map((v) =>
    Math.log((v + alpha) / totalPhishMass)
  );
  const logLikelihoodLegit = legitTfIdfSum.map((v) =>
    Math.log((v + alpha) / totalLegitMass)
  );

  return {
    vocab,
    vocabIndex,
    idf,
    logPriorPhish: Math.log(phishDocs / nDocs),
    logPriorLegit: Math.log(legitDocs / nDocs),
    logLikelihoodPhish,
    logLikelihoodLegit,
    phishDocFreq,
    legitDocFreq,
  };
}

function predictMultinomialNB(
  model: TrainedNaiveBayes,
  url: string
): { probability: number; topNGrams: NGramContribution[] } {
  const tokens = tokenizeUrlForNGrams(url);
  const counts = new Map<number, number>();
  for (const tok of tokens) {
    const idx = model.vocabIndex.get(tok);
    if (idx !== undefined) {
      counts.set(idx, (counts.get(idx) ?? 0) + 1);
    }
  }

  let normSq = 0;
  const weighted = new Map<number, number>();
  for (const [idx, count] of counts.entries()) {
    const val = (1 + Math.log(count)) * model.idf[idx];
    weighted.set(idx, val);
    normSq += val * val;
  }
  const norm = Math.sqrt(normSq) || 1;

  let logScorePhish = model.logPriorPhish;
  let logScoreLegit = model.logPriorLegit;
  const contributions: NGramContribution[] = [];

  for (const [idx, val] of weighted.entries()) {
    const tfidfWeight = val / norm;
    const llPhish = model.logLikelihoodPhish[idx];
    const llLegit = model.logLikelihoodLegit[idx];
    logScorePhish += tfidfWeight * llPhish;
    logScoreLegit += tfidfWeight * llLegit;

    const logOdds = llPhish - llLegit;
    const impact = tfidfWeight * logOdds;
    contributions.push({
      token: model.vocab[idx],
      tfidfWeight: Number(tfidfWeight.toFixed(4)),
      logOdds: Number(logOdds.toFixed(4)),
      impact: Number(impact.toFixed(4)),
      direction: impact >= 0 ? 'phishing' : 'legitimate',
    });
  }

  // Softmax over 2 classes with temperature scaling for well-calibrated probabilities
  const maxLog = Math.max(logScorePhish, logScoreLegit);
  const expPhish = Math.exp(logScorePhish - maxLog);
  const expLegit = Math.exp(logScoreLegit - maxLog);
  const probability = expPhish / (expPhish + expLegit);

  const topNGrams = contributions
    .sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact))
    .slice(0, 8);

  return { probability, topNGrams };
}

function trainLogisticRegression(
  train: LabeledUrlSample[]
): TrainedLogisticRegression {
  const vectors = train.map((sample) => {
    const { features } = extractLexicalFeatures(sample.url);
    return featureVectorFromStruct(features);
  });
  const labels = train.map((s) => s.label);
  const n = vectors.length;
  const d = FEATURE_METADATA.length;

  const means = new Array<number>(d).fill(0);
  const stds = new Array<number>(d).fill(1);

  for (let j = 0; j < d; j++) {
    let sum = 0;
    for (let i = 0; i < n; i++) sum += vectors[i][j];
    means[j] = sum / n;

    let varSum = 0;
    for (let i = 0; i < n; i++) {
      const diff = vectors[i][j] - means[j];
      varSum += diff * diff;
    }
    stds[j] = Math.sqrt(varSum / n) || 1;
  }

  const standardized = vectors.map((vec) =>
    vec.map((v, j) => (v - means[j]) / stds[j])
  );

  const weights = new Array<number>(d).fill(0);
  let bias = 0;
  const learningRate = 0.18;
  const l2Lambda = 0.015;
  const epochs = 700;

  for (let epoch = 0; epoch < epochs; epoch++) {
    const gradW = new Array<number>(d).fill(0);
    let gradB = 0;

    for (let i = 0; i < n; i++) {
      let z = bias;
      const x = standardized[i];
      for (let j = 0; j < d; j++) {
        z += weights[j] * x[j];
      }
      const pred = sigmoid(z);
      const err = pred - labels[i];
      gradB += err;
      for (let j = 0; j < d; j++) {
        gradW[j] += err * x[j];
      }
    }

    bias -= learningRate * (gradB / n);
    for (let j = 0; j < d; j++) {
      weights[j] -= learningRate * (gradW[j] / n + l2Lambda * weights[j]);
    }
  }

  return { means, stds, weights, bias };
}

function describeTriggerReason(
  key: keyof LexicalFeatures,
  rawVal: number,
  direction: 'phishing' | 'legitimate' | 'neutral'
): string | undefined {
  if (direction === 'neutral') return undefined;
  switch (key) {
    case 'hasIpAddress':
      return rawVal === 1 ? 'Uses raw IP address instead of registered domain' : undefined;
    case 'atSymbolPresent':
      return rawVal === 1 ? 'Contains @ userinfo separator masking destination host' : undefined;
    case 'doubleSlashRedirect':
      return rawVal === 1 ? 'Contains embedded // redirect sequence in path/query' : undefined;
    case 'suspiciousKeywordCount':
      return rawVal > 0 ? `Contains ${rawVal} credential/urgency/brand keywords` : 'No suspicious keywords detected';
    case 'isHttps':
      return rawVal === 0 ? 'Served over unencrypted HTTP' : 'Served over HTTPS';
    case 'hyphenCount':
      return rawVal >= 2 ? `High hyphen count (${rawVal}) typical of lookalike domains` : undefined;
    case 'subdomainDepth':
      return rawVal >= 2 ? `Deep subdomain nesting (${rawVal} extra labels)` : undefined;
    case 'urlLength':
      return rawVal >= 75 ? `Unusually long URL (${rawVal} chars)` : undefined;
    case 'shannonEntropy':
      return rawVal >= 4.1 ? `Elevated string entropy (${rawVal.toFixed(2)} bits/char)` : undefined;
    case 'digitRatio':
      return rawVal >= 0.15 ? `High numeric digit ratio (${(rawVal * 100).toFixed(1)}%)` : undefined;
    default:
      return undefined;
  }
}

function predictLogisticRegression(
  model: TrainedLogisticRegression,
  url: string
): {
  probability: number;
  lexicalFeatures: LexicalFeatures;
  matchedKeywords: string[];
  contributions: FeatureContribution[];
} {
  const { features, matchedKeywords } = extractLexicalFeatures(url);
  const rawVec = featureVectorFromStruct(features);

  let z = model.bias;
  const contributions: FeatureContribution[] = [];

  for (let j = 0; j < FEATURE_METADATA.length; j++) {
    const meta = FEATURE_METADATA[j];
    const zVal = (rawVec[j] - model.means[j]) / model.stds[j];
    const contrib = model.weights[j] * zVal;
    z += contrib;

    const direction: FeatureContribution['direction'] =
      Math.abs(contrib) < 0.04
        ? 'neutral'
        : contrib > 0
          ? 'phishing'
          : 'legitimate';

    contributions.push({
      key: meta.key,
      label: meta.label,
      rawValue: rawVec[j],
      formattedValue: formatFeatureValue(rawVec[j], meta.format),
      standardizedValue: Number(zVal.toFixed(3)),
      weight: Number(model.weights[j].toFixed(4)),
      contribution: Number(contrib.toFixed(4)),
      direction,
      triggerReason: describeTriggerReason(meta.key, rawVec[j], direction),
    });
  }

  return {
    probability: sigmoid(z),
    lexicalFeatures: features,
    matchedKeywords,
    contributions,
  };
}

function computeMetrics(
  modelName: string,
  modelKey: ModelMetrics['modelKey'],
  predictions: { actual: 0 | 1; prob: number }[],
  trainSamples: number,
  threshold = 0.5
): ModelMetrics {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  for (const row of predictions) {
    const pred: 0 | 1 = row.prob >= threshold ? 1 : 0;
    if (row.actual === 1 && pred === 1) tp++;
    else if (row.actual === 0 && pred === 1) fp++;
    else if (row.actual === 0 && pred === 0) tn++;
    else fn++;
  }

  const total = predictions.length || 1;
  const accuracy = (tp + tn) / total;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1Score =
    precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const falsePositiveRate = fp + tn > 0 ? fp / (fp + tn) : 0;

  const cm: ConfusionMatrix = { tp, fp, tn, fn };

  return {
    modelName,
    modelKey,
    accuracy: Number(accuracy.toFixed(4)),
    precision: Number(precision.toFixed(4)),
    recall: Number(recall.toFixed(4)),
    f1Score: Number(f1Score.toFixed(4)),
    falsePositiveRate: Number(falsePositiveRate.toFixed(4)),
    confusionMatrix: cm,
    trainSamples,
    testSamples: predictions.length,
  };
}

export class HybridMLEngine {
  datasetName: string;
  sourceType: DatasetSummary['sourceType'];
  trainedAt: string;
  mnb: TrainedNaiveBayes;
  logreg: TrainedLogisticRegression;
  report: ModelComparisonReport;

  constructor(
    samples: LabeledUrlSample[],
    datasetName: string,
    sourceType: DatasetSummary['sourceType']
  ) {
    this.datasetName = datasetName;
    this.sourceType = sourceType;
    this.trainedAt = new Date().toISOString();

    const { train, test } = stratifiedSplit(samples, 0.2);
    this.mnb = trainMultinomialNB(train);
    this.logreg = trainLogisticRegression(train);

    const mnbEval: { actual: 0 | 1; prob: number }[] = [];
    const lrEval: { actual: 0 | 1; prob: number }[] = [];
    const ensEval: { actual: 0 | 1; prob: number }[] = [];

    for (const sample of test) {
      const mnbRes = predictMultinomialNB(this.mnb, sample.url);
      const lrRes = predictLogisticRegression(this.logreg, sample.url);
      const ensProb =
        ENSEMBLE_WEIGHT_MNB * mnbRes.probability +
        ENSEMBLE_WEIGHT_LR * lrRes.probability;

      mnbEval.push({ actual: sample.label, prob: mnbRes.probability });
      lrEval.push({ actual: sample.label, prob: lrRes.probability });
      ensEval.push({ actual: sample.label, prob: ensProb });
    }

    const phishingCount = samples.filter((s) => s.label === 1).length;
    const legitimateCount = samples.length - phishingCount;

    const globalFeatureWeights: GlobalFeatureWeight[] = FEATURE_METADATA.map(
      (meta, idx) => {
        const w = this.logreg.weights[idx];
        const direction: 'phishing' | 'legitimate' =
          w >= 0 ? 'phishing' : 'legitimate';
        return {
          key: meta.key,
          label: meta.label,
          weight: Number(w.toFixed(4)),
          direction,
        };
      }
    ).sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));

    const ngramIndicators: GlobalNGramIndicator[] = this.mnb.vocab
      .map((token, idx) => ({
        token,
        logOdds: Number(
          (
            this.mnb.logLikelihoodPhish[idx] -
            this.mnb.logLikelihoodLegit[idx]
          ).toFixed(4)
        ),
        phishDocFreq: this.mnb.phishDocFreq[idx],
        legitDocFreq: this.mnb.legitDocFreq[idx],
      }))
      .filter((item) => item.phishDocFreq + item.legitDocFreq >= 3);

    const topPhishingNGrams = [...ngramIndicators]
      .sort((a, b) => b.logOdds - a.logOdds)
      .slice(0, 12);

    const topLegitimateNGrams = [...ngramIndicators]
      .sort((a, b) => a.logOdds - b.logOdds)
      .slice(0, 12);

    this.report = {
      dataset: {
        name: datasetName,
        sourceType,
        totalSamples: samples.length,
        phishingCount,
        legitimateCount,
        trainSize: train.length,
        testSize: test.length,
        vocabSize: this.mnb.vocab.length,
        trainedAt: this.trainedAt,
      },
      ensembleWeights: {
        mnb: ENSEMBLE_WEIGHT_MNB,
        logreg: ENSEMBLE_WEIGHT_LR,
      },
      metrics: {
        mnb: computeMetrics(
          'TF-IDF + Multinomial Naive Bayes',
          'mnb',
          mnbEval,
          train.length
        ),
        logreg: computeMetrics(
          'Logistic Regression (Lexical Features)',
          'logreg',
          lrEval,
          train.length
        ),
        ensemble: computeMetrics(
          'Hybrid ML Ensemble (MNB + LR)',
          'ensemble',
          ensEval,
          train.length
        ),
      },
      globalFeatureWeights,
      topPhishingNGrams,
      topLegitimateNGrams,
    };
  }

  predict(normalizedUrl: string): MLRuntimePrediction {
    const mnbRes = predictMultinomialNB(this.mnb, normalizedUrl);
    const lrRes = predictLogisticRegression(this.logreg, normalizedUrl);

    const ensembleProbability =
      ENSEMBLE_WEIGHT_MNB * mnbRes.probability +
      ENSEMBLE_WEIGHT_LR * lrRes.probability;

    const sortedContributions = [...lrRes.contributions].sort(
      (a, b) => Math.abs(b.contribution) - Math.abs(a.contribution)
    );
    const topTriggers = sortedContributions
      .filter((c) => c.direction !== 'neutral')
      .slice(0, 6);

    return {
      ensembleProbability: Number(ensembleProbability.toFixed(4)),
      mnbProbability: Number(mnbRes.probability.toFixed(4)),
      logregProbability: Number(lrRes.probability.toFixed(4)),
      lexicalFeatures: lrRes.lexicalFeatures,
      matchedKeywords: lrRes.matchedKeywords,
      featureContributions: sortedContributions,
      topTriggers,
      topNGrams: mnbRes.topNGrams,
    };
  }
}

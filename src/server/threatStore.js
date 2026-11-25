import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { normalizeUrl } from '../core/normalizer.js';
import { STARTER_THREAT_SEEDS } from '../core/threatSeeds.js';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const THREAT_DB_PATH = path.join(DATA_DIR, 'threat-hashes.json');

export function computeSha256Hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function buildSeededRecords() {
  const baseDate = '2026-11-15T10:00:00.000Z';
  const records = [];
  for (const seed of STARTER_THREAT_SEEDS) {
    const norm = normalizeUrl(seed.url);
    if (!norm.valid) continue;
    records.push({
      sha256: computeSha256Hex(norm.normalizedUrl),
      normalizedUrl: norm.normalizedUrl,
      source: seed.source,
      category: seed.category,
      targetBrand: seed.targetBrand,
      addedAt: baseDate,
      isSeeded: true,
    });
  }
  return records;
}

export class ThreatHashStore {
  constructor() {
    this.records = new Map();
    this.loadOrInitialize();
  }

  ensureDataDir() {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  }

  persist() {
    this.ensureDataDir();
    const list = Array.from(this.records.values());
    fs.writeFileSync(THREAT_DB_PATH, JSON.stringify(list, null, 2), 'utf-8');
  }

  loadOrInitialize() {
    if (fs.existsSync(THREAT_DB_PATH)) {
      try {
        const raw = fs.readFileSync(THREAT_DB_PATH, 'utf-8');
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.length > 0) {
          for (const rec of parsed) {
            if (rec && typeof rec.sha256 === 'string') {
              this.records.set(rec.sha256.toLowerCase(), rec);
            }
          }
          return;
        }
      } catch {
        // Re-seed if corrupted
      }
    }
    this.resetToStarterSeed();
  }

  resetToStarterSeed() {
    this.records.clear();
    for (const rec of buildSeededRecords()) {
      this.records.set(rec.sha256, rec);
    }
    this.persist();
    return this.getAll();
  }

  lookup(sha256Hex) {
    return this.records.get(sha256Hex.toLowerCase()) ?? null;
  }

  getAll() {
    return Array.from(this.records.values()).sort((a, b) =>
      b.addedAt.localeCompare(a.addedAt)
    );
  }

  addByUrl(params) {
    const norm = normalizeUrl(params.url);
    if (!norm.valid) {
      throw new Error(norm.error ?? 'Invalid URL provided.');
    }
    const sha256 = computeSha256Hex(norm.normalizedUrl);
    const record = {
      sha256,
      normalizedUrl: norm.normalizedUrl,
      source: params.source?.trim() || 'Custom Demo Entry',
      category: params.category?.trim() || 'Reported Phishing URL',
      targetBrand: params.targetBrand?.trim() || undefined,
      addedAt: new Date().toISOString(),
      isSeeded: false,
    };
    this.records.set(sha256, record);
    this.persist();
    return record;
  }

  addByHash(params) {
    const cleanHash = params.sha256.trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(cleanHash)) {
      throw new Error('SHA-256 hash must be exactly 64 hexadecimal characters.');
    }
    const record = {
      sha256: cleanHash,
      normalizedUrl: params.labelUrl?.trim() || '(Raw SHA-256 Digest Entry)',
      source: params.source?.trim() || 'Manual SHA-256 Entry',
      category: params.category?.trim() || 'Imported Threat Digest',
      targetBrand: params.targetBrand?.trim() || undefined,
      addedAt: new Date().toISOString(),
      isSeeded: false,
    };
    this.records.set(cleanHash, record);
    this.persist();
    return record;
  }

  remove(sha256) {
    const deleted = this.records.delete(sha256.trim().toLowerCase());
    if (deleted) {
      this.persist();
    }
    return deleted;
  }
}

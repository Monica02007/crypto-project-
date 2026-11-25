import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { normalizeUrl } from '../core/normalizer.js';

const STARTER_THREAT_SEEDS = [
  {
    url: 'http://login-secure-bank.xyz/update',
    source: 'PhishTank Seed',
    category: 'Banking Credential Phishing',
    targetBrand: 'Generic Banking',
  },
  {
    url: 'http://secure-paypal-login.verify-account-update.com/signin',
    source: 'PhishTank Seed',
    category: 'Credential Harvesting',
    targetBrand: 'PayPal',
  },
  {
    url: 'http://paypal-security-check.account-limit-resolve.net/webscr?cmd=_login-run',
    source: 'PhishTank Seed',
    category: 'Financial Phishing',
    targetBrand: 'PayPal',
  },
  {
    url: 'https://login-microsoftonline-verify.session-expired-auth.com/oauth2/authorize',
    source: 'OpenPhish Seed',
    category: 'OAuth / Enterprise SSO',
    targetBrand: 'Microsoft 365',
  },
  {
    url: 'http://office365-secure-portal.credential-update.info/auth/login.php',
    source: 'URLhaus Seed',
    category: 'Corporate Credential Theft',
    targetBrand: 'Microsoft Office 365',
  },
  {
    url: 'http://192.168.14.88/paypal/webscr/cmd-login-submit.html',
    source: 'URLhaus Seed',
    category: 'IP-Hosted Phish Kit',
    targetBrand: 'PayPal',
  },
  {
    url: 'https://appleid.apple.com.verify-device-lock.support-center-id.com/signin',
    source: 'PhishTank Seed',
    category: 'Subdomain Brand Impersonation',
    targetBrand: 'Apple ID',
  },
  {
    url: 'http://amazon-prime-billing-suspended.update-payment-now.org/ap/signin',
    source: 'PhishTank Seed',
    category: 'Billing & Card Theft',
    targetBrand: 'Amazon',
  },
  {
    url: 'https://chase-online-banking-alert.confirm-account-access.net/verify/user',
    source: 'OpenPhish Seed',
    category: 'Banking Phishing',
    targetBrand: 'Chase Bank',
  },
  {
    url: 'http://wellsfargo-security-department.unlock-card-access.com/login.jsp',
    source: 'PhishTank Seed',
    category: 'Banking Phishing',
    targetBrand: 'Wells Fargo',
  },
  {
    url: 'http://dhl-express-parcel-fee.confirm-delivery-address.com/track/pay',
    source: 'URLhaus Seed',
    category: 'Delivery Smishing Link',
    targetBrand: 'DHL',
  },
  {
    url: 'https://accounts-google-security-alert.recover-password-access.com/signin',
    source: 'OpenPhish Seed',
    category: 'Account Takeover',
    targetBrand: 'Google',
  },
  {
    url: 'http://www.paypal.com@198.51.100.19/webscr/secure-login-verify',
    source: 'URLhaus Seed',
    category: '@ Userinfo Obfuscation',
    targetBrand: 'PayPal',
  },
  {
    url: 'https://coinbase-wallet-verification.recover-seed-phrase.io/connect/auth',
    source: 'CryptoThreat Seed',
    category: 'Wallet Seed Phishing',
    targetBrand: 'Coinbase',
  },
  {
    url: 'http://docusign-pending-signature.review-contract-portal.net/signing',
    source: 'OpenPhish Seed',
    category: 'BEC / Document Lure',
    targetBrand: 'DocuSign',
  },
  {
    url: 'http://github-security-token-expired.renew-ssh-access.com/login/oauth',
    source: 'PhishTank Seed',
    category: 'Developer Credential Theft',
    targetBrand: 'GitHub',
  },
  {
    url: 'https://stripe-payout-hold.verify-merchant-bank.net/dashboard/login',
    source: 'OpenPhish Seed',
    category: 'Merchant Account Phishing',
    targetBrand: 'Stripe',
  },
  {
    url: 'http://185.220.101.44/wp-content/themes/secure-bank-login/verify.php',
    source: 'URLhaus Seed',
    category: 'Compromised Host Dropper',
    targetBrand: 'Generic Banking',
  },
  {
    url: 'http://ledger-live-firmware-update.verify-24-word-recovery.com/restore',
    source: 'CryptoThreat Seed',
    category: 'Hardware Wallet Phish',
    targetBrand: 'Ledger',
  },
];

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

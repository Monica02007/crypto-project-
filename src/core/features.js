export const SUSPICIOUS_KEYWORDS = [
  'login',
  'signin',
  'sign-in',
  'verify',
  'verification',
  'update',
  'secure',
  'security',
  'account',
  'banking',
  'confirm',
  'wallet',
  'suspend',
  'suspended',
  'locked',
  'unlock',
  'credential',
  'password',
  'recover',
  'recovery',
  'invoice',
  'billing',
  'payment',
  'paypal',
  'microsoft',
  'office365',
  'appleid',
  'amazon',
  'chase',
  'wellsfargo',
  'dhl',
  'fedex',
  'webscr',
  'cmd',
  'token',
  'auth',
];

export const FEATURE_METADATA = [
  {
    key: 'urlLength',
    label: 'Total URL Length',
    description: 'Total character length of the URL; obfuscated phishing links often pad paths and queries.',
    format: 'int',
  },
  {
    key: 'hostnameLength',
    label: 'Hostname Length',
    description: 'Length of the domain/host portion; multi-brand impersonation hosts tend to be abnormally long.',
    format: 'int',
  },
  {
    key: 'pathLength',
    label: 'Path & Query Length',
    description: 'Combined length of URL path and query parameters.',
    format: 'int',
  },
  {
    key: 'dotCount',
    label: 'Dot (.) Count',
    description: 'Total period characters; excessive dots often indicate deep deceptive subdomains.',
    format: 'int',
  },
  {
    key: 'hyphenCount',
    label: 'Hyphen (-) Count',
    description: 'Count of dashes used to mimic official domains (e.g., secure-login-brand.com).',
    format: 'int',
  },
  {
    key: 'underscoreCount',
    label: 'Underscore (_) Count',
    description: 'Count of underscores in path or parameters.',
    format: 'int',
  },
  {
    key: 'slashCount',
    label: 'Slash (/) Count',
    description: 'Path depth indicator via forward-slash separators.',
    format: 'int',
  },
  {
    key: 'questionCount',
    label: 'Question Mark (?) Count',
    description: 'Presence of query delimiter or nested redirect query strings.',
    format: 'int',
  },
  {
    key: 'equalCount',
    label: 'Equals (=) Count',
    description: 'Number of key-value parameter assignments.',
    format: 'int',
  },
  {
    key: 'atSymbolPresent',
    label: '@ Symbol Present',
    description: 'Presence of @ userinfo syntax, historically abused to mask the real destination host.',
    format: 'bool',
  },
  {
    key: 'doubleSlashRedirect',
    label: 'Embedded // Redirect',
    description: 'Occurrence of // inside path or query after the scheme, indicating open-redirect chaining.',
    format: 'bool',
  },
  {
    key: 'isHttps',
    label: 'HTTPS Scheme Used',
    description: 'Whether TLS (https://) is used. Note: modern phishing also uses HTTPS, so this alone is not safety.',
    format: 'bool',
  },
  {
    key: 'hasIpAddress',
    label: 'IP-Address Host',
    description: 'Direct IPv4/IPv6 host instead of a registered domain name.',
    format: 'bool',
  },
  {
    key: 'digitRatio',
    label: 'Digit Character Ratio',
    description: 'Proportion of numeric digits in the URL, elevated in generated tokens and IP hosts.',
    format: 'ratio',
  },
  {
    key: 'specialCharCount',
    label: 'Special Character Count',
    description: 'Aggregate count of @ ? = & % $ ! * , ; characters.',
    format: 'int',
  },
  {
    key: 'subdomainDepth',
    label: 'Subdomain Depth',
    description: 'Extra subdomain labels preceding the apex domain (e.g., login.secure.account.example.com).',
    format: 'int',
  },
  {
    key: 'suspiciousKeywordCount',
    label: 'Suspicious Keyword Hits',
    description: 'Matches against credential, urgency, and brand-impersonation terms.',
    format: 'int',
  },
  {
    key: 'shannonEntropy',
    label: 'URL Shannon Entropy',
    description: 'Character randomness (bits/char); high entropy reflects randomized DGA hosts or encoded payloads.',
    format: 'float',
  },
];

const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const HEX_IP_REGEX = /^0x[0-9a-f]+$/i;
const SPECIAL_CHARS_RE = /[@?=&%$!*,;]/g;

export function computeShannonEntropy(input) {
  if (!input.length) return 0;
  const counts = new Map();
  for (const ch of input) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = input.length;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

export function extractMatchedKeywords(url) {
  const lower = url.toLowerCase();
  const matched = [];
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (lower.includes(kw)) {
      matched.push(kw);
    }
  }
  return matched;
}

export function extractLexicalFeatures(targetUrl) {
  let scheme = 'http';
  let hostname = '';
  let pathname = '';
  let search = '';
  let hasAt = targetUrl.includes('@') ? 1 : 0;

  try {
    const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(targetUrl)
      ? targetUrl
      : `http://${targetUrl}`;
    const parsed = new URL(withScheme);
    scheme = parsed.protocol.replace(':', '').toLowerCase();
    hostname = parsed.hostname.toLowerCase();
    pathname = parsed.pathname || '/';
    search = parsed.search || '';
    if (parsed.username || parsed.password) {
      hasAt = 1;
    }
  } catch {
    const noScheme = targetUrl.replace(/^[a-zA-Z]+:\/\//, '');
    const parts = noScheme.split('/');
    hostname = (parts[0] ?? '').split(':')[0].toLowerCase();
    pathname = '/' + parts.slice(1).join('/');
  }

  const afterSchemeIndex = targetUrl.indexOf('://');
  const afterScheme =
    afterSchemeIndex >= 0 ? targetUrl.slice(afterSchemeIndex + 3) : targetUrl;
  const doubleSlashRedirect =
    afterScheme.includes('//') || afterScheme.toLowerCase().includes('%2f%2f')
      ? 1
      : 0;

  const digitMatches = targetUrl.match(/\d/g);
  const digitCount = digitMatches ? digitMatches.length : 0;
  const specialMatches = targetUrl.match(SPECIAL_CHARS_RE);
  const specialCharCount = specialMatches ? specialMatches.length : 0;

  const cleanHost = hostname.replace(/^\[|\]$/g, '');
  const hasIpAddress =
    IPV4_REGEX.test(cleanHost) ||
    HEX_IP_REGEX.test(cleanHost) ||
    cleanHost.includes(':')
      ? 1
      : 0;

  const hostLabels = hostname.split('.').filter(Boolean);
  const subdomainDepth = hasIpAddress
    ? 0
    : Math.max(0, hostLabels.length - 2);

  const matchedKeywords = extractMatchedKeywords(targetUrl);

  const features = {
    urlLength: targetUrl.length,
    hostnameLength: hostname.length,
    pathLength: pathname.length + search.length,
    dotCount: (targetUrl.match(/\./g) ?? []).length,
    hyphenCount: (targetUrl.match(/-/g) ?? []).length,
    underscoreCount: (targetUrl.match(/_/g) ?? []).length,
    slashCount: (targetUrl.match(/\//g) ?? []).length,
    questionCount: (targetUrl.match(/\?/g) ?? []).length,
    equalCount: (targetUrl.match(/=/g) ?? []).length,
    atSymbolPresent: hasAt,
    doubleSlashRedirect,
    isHttps: scheme === 'https' ? 1 : 0,
    hasIpAddress,
    digitRatio: targetUrl.length > 0 ? Number((digitCount / targetUrl.length).toFixed(4)) : 0,
    specialCharCount,
    subdomainDepth,
    suspiciousKeywordCount: matchedKeywords.length,
    shannonEntropy: computeShannonEntropy(hostname + pathname),
  };

  return { features, matchedKeywords };
}

export function featureVectorFromStruct(f) {
  return FEATURE_METADATA.map((meta) => f[meta.key]);
}

export function formatFeatureValue(value, format) {
  if (format === 'bool') return value >= 0.5 ? 'Yes (1)' : 'No (0)';
  if (format === 'ratio') return `${(value * 100).toFixed(1)}%`;
  if (format === 'float') return value.toFixed(2);
  return String(Math.round(value));
}

const CONTROL_AND_ZERO_WIDTH_RE = /[\u0000-\u001F\u007F\u200B-\u200D\uFEFF]/g;
const SCHEME_PREFIX_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;

export function normalizeUrl(rawInput) {
  const steps = [];
  const rawUrl = typeof rawInput === 'string' ? rawInput : '';

  const trimmed = rawUrl.trim();
  const whitespaceChanged = trimmed !== rawUrl;
  steps.push({
    rule: 'Trim Surrounding Whitespace',
    applied: whitespaceChanged,
    detail: whitespaceChanged
      ? 'Removed leading/trailing spaces, tabs, or line breaks.'
      : 'No leading or trailing whitespace present.',
  });

  const cleaned = trimmed.replace(CONTROL_AND_ZERO_WIDTH_RE, '');
  const controlStripped = cleaned !== trimmed;
  steps.push({
    rule: 'Strip Control & Zero-Width Characters',
    applied: controlStripped,
    detail: controlStripped
      ? 'Removed invisible zero-width or control characters.'
      : 'No hidden control characters detected.',
  });

  if (!cleaned) {
    return {
      rawUrl,
      normalizedUrl: '',
      scheme: '',
      hostname: '',
      port: '',
      pathname: '',
      search: '',
      steps,
      valid: false,
      error: 'URL input is empty after trimming whitespace.',
    };
  }

  let candidate = cleaned;
  let schemeInferred = false;
  if (!SCHEME_PREFIX_RE.test(candidate)) {
    candidate = `http://${candidate}`;
    schemeInferred = true;
  }
  steps.push({
    rule: 'Ensure Explicit URL Scheme',
    applied: schemeInferred,
    detail: schemeInferred
      ? 'Prepended default http:// scheme for canonical parsing.'
      : 'Explicit scheme already present.',
  });

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return {
      rawUrl,
      normalizedUrl: '',
      scheme: '',
      hostname: '',
      port: '',
      pathname: '',
      search: '',
      steps,
      valid: false,
      error: 'Input could not be parsed as a valid HTTP/HTTPS URL.',
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      rawUrl,
      normalizedUrl: '',
      scheme: parsed.protocol.replace(':', ''),
      hostname: parsed.hostname,
      port: parsed.port,
      pathname: parsed.pathname,
      search: parsed.search,
      steps,
      valid: false,
      error: `Unsupported URL scheme "${parsed.protocol}". Only http and https are analyzed.`,
    };
  }

  const originalSchemeAndHost = (() => {
    const afterScheme = candidate.split('://')[1] ?? '';
    const hostSegment = afterScheme.split(/[/?#]/)[0] ?? '';
    return {
      scheme: candidate.split('://')[0] ?? '',
      hostSegment,
    };
  })();

  const schemeLowercased =
    originalSchemeAndHost.scheme !== parsed.protocol.replace(':', '');
  const hostLowercased =
    originalSchemeAndHost.hostSegment.toLowerCase() !==
    originalSchemeAndHost.hostSegment;

  steps.push({
    rule: 'Lowercase Scheme & Canonicalize Hostname (IDNA/Punycode)',
    applied: schemeLowercased || hostLowercased || parsed.hostname.startsWith('xn--'),
    detail: `Canonical host resolved to "${parsed.hostname}" under "${parsed.protocol.replace(':', '')}".`,
  });

  const hadExplicitDefaultPort =
    (parsed.protocol === 'http:' && originalSchemeAndHost.hostSegment.endsWith(':80')) ||
    (parsed.protocol === 'https:' && originalSchemeAndHost.hostSegment.endsWith(':443'));
  const portPart = parsed.port ? `:${parsed.port}` : '';
  steps.push({
    rule: 'Remove Default Ports (:80 / :443)',
    applied: hadExplicitDefaultPort,
    detail: hadExplicitDefaultPort
      ? 'Stripped redundant default port number.'
      : parsed.port
        ? `Preserved non-default port :${parsed.port}.`
        : 'No default port present.',
  });

  const rawPathname = parsed.pathname || '/';
  let normalizedPathname = rawPathname.replace(/\/{2,}/g, '/');
  if (normalizedPathname.length > 1 && normalizedPathname.endsWith('/')) {
    normalizedPathname = normalizedPathname.slice(0, -1);
  }
  const pathNormalized = normalizedPathname !== rawPathname;
  steps.push({
    rule: 'Normalize Path Formatting',
    applied: pathNormalized,
    detail: pathNormalized
      ? `Standardized path "${rawPathname}" to "${normalizedPathname}".`
      : `Path "${normalizedPathname}" already canonical.`,
  });

  const hadFragment = parsed.hash.length > 0;
  steps.push({
    rule: 'Strip Client-Side Fragment (#)',
    applied: hadFragment,
    detail: hadFragment
      ? `Removed fragment "${parsed.hash}" (not sent to server).`
      : 'No URL fragment present.',
  });

  let normalizedSearch = parsed.search;
  let querySorted = false;
  if (parsed.search && parsed.searchParams.toString().length > 0) {
    const entries = Array.from(parsed.searchParams.entries());
    const sorted = [...entries].sort((a, b) => {
      if (a[0] !== b[0]) return a[0].localeCompare(b[0]);
      return a[1].localeCompare(b[1]);
    });
    const sortedSearch = `?${new URLSearchParams(sorted).toString()}`;
    if (sortedSearch !== parsed.search) {
      querySorted = true;
    }
    normalizedSearch = sortedSearch;
  }
  steps.push({
    rule: 'Canonicalize Query Parameter Ordering',
    applied: querySorted,
    detail: querySorted
      ? 'Sorted query string parameters lexicographically.'
      : parsed.search
        ? 'Query parameters already in canonical order.'
        : 'No query parameters present.',
  });

  const authSegment = parsed.username
    ? `${parsed.username}${parsed.password ? `:${parsed.password}` : ''}@`
    : '';
  const normalizedUrl = `${parsed.protocol}//${authSegment}${parsed.hostname}${portPart}${normalizedPathname}${normalizedSearch}`;

  return {
    rawUrl,
    normalizedUrl,
    scheme: parsed.protocol.replace(':', ''),
    hostname: parsed.hostname,
    port: parsed.port,
    pathname: normalizedPathname,
    search: normalizedSearch,
    steps,
    valid: true,
  };
}

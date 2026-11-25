import { normalizeUrl } from './normalizer.js';

export const BUILT_IN_LEGITIMATE_URLS = [
  'https://github.com/settings/security?tab=sessions',
  'https://github.com/openai/openai-node/issues?q=is%3Aopen',
  'https://docs.python.org/3/library/hashlib.html',
  'https://developer.mozilla.org/en-US/docs/Web/API/URL',
  'https://stackoverflow.com/questions/tagged/typescript',
  'https://en.wikipedia.org/wiki/Phishing',
  'https://www.nytimes.com/section/technology',
  'https://www.bbc.com/news/technology',
  'https://scholar.google.com/scholar?q=url+phishing+detection',
  'https://arxiv.org/abs/2304.01234',
  'https://accounts.google.com/v3/signin/identifier?flowName=GlifWebSignIn',
  'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=1234',
  'https://www.paypal.com/us/home',
  'https://www.paypal.com/myaccount/summary',
  'https://www.chase.com/personal/checking',
  'https://www.bankofamerica.com/online-banking/sign-in/',
  'https://www.wellsfargo.com/help/online-banking/',
  'https://www.amazon.com/dp/B09V3KXJPB',
  'https://www.amazon.com/gp/css/order-history',
  'https://www.apple.com/support/products/',
  'https://support.apple.com/en-us/102651',
  'https://support.microsoft.com/en-us/windows',
  'https://www.cloudflare.com/learning/security/what-is-phishing/',
  'https://owasp.org/www-community/attacks/Phishing',
  'https://csrc.nist.gov/publications/detail/sp/800-63/3/final',
  'https://www.irs.gov/payments/direct-pay',
  'https://www.usa.gov/scams-and-fraud',
  'https://www.mit.edu/academics/',
  'https://cs.stanford.edu/people/faculty',
  'https://www.ox.ac.uk/admissions/undergraduate',
  'https://www.stripe.com/docs/api/charges',
  'https://dashboard.stripe.com/login',
  'https://console.cloud.google.com/iam-admin/iam',
  'https://aws.amazon.com/documentation-overview/',
  'https://portal.azure.com/#home',
  'https://www.linkedin.com/feed/',
  'https://www.reddit.com/r/netsec/',
  'https://news.ycombinator.com/item?id=41002312',
  'https://www.npmjs.com/package/express',
  'https://pypi.org/project/scikit-learn/',
  'https://crates.io/crates/serde',
  'https://www.docker.com/products/docker-desktop/',
  'https://kubernetes.io/docs/concepts/overview/',
  'https://react.dev/reference/react/useState',
  'https://vitejs.dev/guide/features.html',
  'https://tailwindcss.com/docs/installation',
  'https://nodejs.org/api/crypto.html',
  'https://www.mozilla.org/en-US/firefox/new/',
  'https://www.eff.org/issues/privacy',
  'https://www.coursera.org/learn/cybersecurity-for-everyone',
  'https://www.khanacademy.org/computing/computers-and-internet',
  'https://www.dropbox.com/home/Documents',
  'https://drive.google.com/drive/my-drive',
  'https://mail.google.com/mail/u/0/#inbox',
  'https://outlook.live.com/mail/0/',
  'https://slack.com/workspace-signin',
  'https://zoom.us/join',
  'https://www.atlassian.com/software/jira',
  'https://www.notion.so/product',
  'https://www.figma.com/files/recent',
  'https://www.shopify.com/pricing',
  'https://www.etsy.com/listing/14231209/handmade-ceramic-mug',
  'https://www.target.com/c/electronics/-/N-5xtg6',
  'https://www.bestbuy.com/site/electronics/computers-pcs/abcat0500000.c',
  'https://www.walmart.com/browse/electronics/3944',
  'https://www.fedex.com/en-us/tracking.html',
  'https://www.ups.com/track?loc=en_US',
  'https://www.dhl.com/us-en/home/tracking.html',
  'https://www.usps.com/manage/informed-delivery.htm',
  'https://www.netflix.com/browse',
  'https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M',
  'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
  'https://vimeo.com/channels/staffpicks',
  'https://www.twitch.tv/directory',
  'https://www.airbnb.com/rooms/48291042?adults=2&check_in=2026-12-01',
  'https://www.booking.com/hotel/us/example-inn.html',
  'https://www.expedia.com/Flights',
  'https://www.weather.com/weather/today/l/USCA0987:1:US',
  'https://maps.google.com/?q=San+Francisco+CA',
  'https://translate.google.com/?sl=en&tl=es',
  'https://www.healthline.com/nutrition/healthy-eating-tips',
  'https://www.mayoclinic.org/diseases-conditions',
  'https://www.cdc.gov/flu/index.htm',
  'https://www.who.int/health-topics',
  'https://www.nasa.gov/mission_pages/webb/main/index.html',
  'https://www.nature.com/articles/s41586-024-07123-4',
  'https://www.sciencemag.org/journal/science',
  'https://www.bloomberg.com/markets',
  'https://www.reuters.com/world/',
  'https://www.economist.com/leaders',
  'https://www.forbes.com/innovation/',
  'https://www.wired.com/category/security/',
  'https://krebsonsecurity.com/',
  'https://www.bleepingcomputer.com/news/security/',
  'https://haveibeenpwned.com/',
  'https://urlhaus.abuse.ch/browse/',
  'https://phishtank.org/',
  'https://www.virustotal.com/gui/home/url',
  'https://letsencrypt.org/docs/',
  'https://www.postgresql.org/docs/current/index.html',
  'https://redis.io/docs/latest/',
  'https://www.gnu.org/software/bash/manual/',
  'https://linux.die.net/man/',
  'https://www.ubuntu.com/download/server',
  'https://www.redhat.com/en/topics/security',
  'https://www.cisco.com/c/en/us/products/security/index.html',
  'https://www.paloaltonetworks.com/cyberpedia/what-is-phishing',
  'https://www.okta.com/identity-101/what-is-mfa/',
  'https://www.twilio.com/docs/verify/api',
  'https://vercel.com/docs/deployments/overview',
];

export const BUILT_IN_PHISHING_URLS = [
  'http://login-secure-bank.xyz/update',
  'http://secure-paypal-login.verify-account-update.com/signin',
  'http://paypal-security-check.account-limit-resolve.net/webscr?cmd=_login-run',
  'https://login-microsoftonline-verify.session-expired-auth.com/oauth2/authorize',
  'http://office365-secure-portal.credential-update.info/auth/login.php',
  'http://192.168.14.88/paypal/webscr/cmd-login-submit.html',
  'http://198.51.100.42/auth//microsoft-office365-secure-login/verify?session=94820194&redirect=http://evil.example',
  'http://45.133.1.92:8080/banking/chase-verify-identity/login.php',
  'http://203.0.113.77/appleid-unlock/confirm-billing?token=9918231',
  'https://appleid.apple.com.verify-device-lock.support-center-id.com/signin',
  'http://amazon-prime-billing-suspended.update-payment-now.org/ap/signin',
  'https://chase-online-banking-alert.confirm-account-access.net/verify/user',
  'http://wellsfargo-security-department.unlock-card-access.com/login.jsp',
  'http://bankofamerica.secure-session-check.verify-info-now.com/auth',
  'https://netflix-payment-declined.update-billing-card.info/Login',
  'http://dhl-express-parcel-fee.confirm-delivery-address.com/track/pay',
  'http://fedex-customs-clearance.invoice-payment-portal.net/confirm?id=88412',
  'http://usps-redelivery-schedule.confirm-postal-fee.org/tracking/update',
  'https://accounts-google-security-alert.recover-password-access.com/signin',
  'http://drive-google-shared-doc.view-encrypted-invoice.net/login/auth',
  'http://www.paypal.com@198.51.100.19/webscr/secure-login-verify',
  'https://login.microsoftonline.com@auth-token-refresh.evil-host.net/signin',
  'http://secure-login.dropbox.com.verify-shared-file.tk/auth/index.html',
  'http://irs-tax-refund-claim.verify-ssn-direct-deposit.com/refund/form',
  'https://coinbase-wallet-verification.recover-seed-phrase.io/connect/auth',
  'http://metamask-security-sync.validate-recovery-wallet.xyz/unlock',
  'http://binance-withdrawal-alert.cancel-unauthorized-tx.top/verify',
  'http://steam-community-trade-offer.free-inventory-login.ru/openid/login',
  'https://instagram-copyright-appeal.verify-blue-badge-form.com/support',
  'http://facebook-account-disabled.appeal-review-center.net/checkpoint',
  'http://whatsapp-web-verify-device.session-qr-sync.info/auth',
  'http://linkedin-security-notice.confirm-work-email.org/uas/login',
  'http://github-security-token-expired.renew-ssh-access.com/login/oauth',
  'https://stripe-payout-hold.verify-merchant-bank.net/dashboard/login',
  'http://shopify-store-suspended.appeal-billing-verify.com/admin/auth',
  'http://zoom-meeting-recording.download-encrypted-client.info/join?pwd=8821',
  'http://slack-workspace-sso-expired.reauthenticate-token.net/signin',
  'http://adobe-acrobat-pdf-invoice.secure-document-view.com/auth/login',
  'http://docusign-pending-signature.review-contract-portal.net/signing',
  'http://outlook-owa-mailbox-full.upgrade-storage-quota.org/owa/auth',
  'http://webmail-corporate-password-expiry.keep-current-pass.com/login.cgi',
  'https://citi-bank-fraud-alert.verify-recent-wire-transfer.com/secure',
  'http://hsbc-internet-banking-token.resync-security-key.net/logon',
  'http://barclays-online-pin-sentry.confirm-card-details.org/auth',
  'http://santander-account-blocked.reactivate-online-banking.info/login',
  'http://tmobile-unpaid-bill-notice.pay-balance-online.com/account/login',
  'http://verizon-wireless-reward-claim.confirm-billing-zip.net/signin',
  'http://att-email-account-upgrade.verify-credentials-now.org/login',
  'http://comcast-xfinity-service-hold.update-autopay-card.com/auth',
  'http://ebay-seller-invoice-dispute.resolution-center-login.net/ws',
  'https://walmart-order-verification.confirm-giftcard-refund.info/account',
  'http://target-redcard-security-check.verify-pin-online.com/login',
  'http://bestbuy-geek-squad-renewal.cancel-auto-charge.net/invoice',
  'http://costco-membership-expired.claim-loyalty-rebate.org/verify',
  'http://185.220.101.44/wp-content/themes/secure-bank-login/verify.php',
  'http://91.214.124.88/include/office365/auth/login.htm',
  'http://172.16.45.201/confirm//paypal//account-update?id=991023481',
  'http://45.95.147.22/signin/amazon/verify-billing-address.php',
  'http://103.145.12.71/chase/auth/redirect//http://verify-chase.net',
  'http://secure-verify-019283.login-portal-update-9921.com/auth/step1',
  'http://auth-cdn-99418273.verify-user-session-0012.net/login/confirm',
  'https://support-ticket-849201.apple-id-locked-alert.com/unlock/step2',
  'http://x9k2m8p4q7z1.verify-banking-credentials-secure.top/login',
  'http://q7w8e9r0t1y2.account-suspension-appeal-form.xyz/confirm',
  'http://zxcvbnm99182.paypal-resolution-center-secure.icu/webscr',
  'http://verify.account.security.update.login.microsoft-support-desk.com/auth',
  'http://signin.confirm.billing.paypal.user-resolution-portal.net/cmd',
  'http://secure.banking.login.verify.chase-fraud-protection.org/step1',
  'http://update.payment.card.netflix.billing-support-desk.info/login',
  'http://account.locked.verify.amazon.order-protection-team.com/signin',
  'http://auth.session.expired.dropbox.shared-document-viewer.net/view',
  'http://login.portal.hr-payroll.workday-employee-bonus-claim.com/auth',
  'http://portal.sso.okta-verify-mfa-reset-token-device.net/login',
  'http://it-helpdesk-password-reset.corp-vpn-credential-sync.org/auth',
  'http://microsoft.com//secure-login//office365-verify-password.net/auth',
  'http://paypal.com.cgi-bin.webscr.cmd-login-submit.update-info.cc/login',
  'http://google.com-security-checkup.suspicious-signin-blocked.pw/verify',
  'http://apple.com-find-my-iphone-location.icloud-unlock-device.cc/auth',
  'http://icloud-activation-lock-alert.view-lost-device-map.com/signin',
  'http://binance-p2p-escrow-verify.confirm-wallet-signature.net/auth',
  'http://ledger-live-firmware-update.verify-24-word-recovery.com/restore',
  'http://trezor-suite-security-patch.validate-seed-backup.org/connect',
  'http://venmo-payment-pending-review.accept-transfer-funds.net/login',
  'http://zelle-instant-transfer-alert.confirm-recipient-bank.com/verify',
  'http://cashapp-security-verification.unlock-pending-deposit.info/auth',
  'http://americanexpress-account-alert.confirm-card-cvv-now.com/login',
  'http://capitalone-360-security-notice.verify-identity-code.net/signin',
  'http://discover-cashback-bonus-claim.confirm-card-account.org/login',
  'http://td-bank-easyweb-security-check.unlock-online-access.com/auth',
  'http://rbc-royal-bank-alert.verify-interac-etransfer.net/signin',
  'http://scotiabank-security-update.confirm-debit-card-pin.com/login',
  'http://royalmail-missed-parcel-fee.schedule-redelivery-pay.co.uk.info/pay',
  'http://canadapost-customs-duty-due.confirm-shipping-address.net/track',
  'http://auspost-parcel-delivery-hold.pay-redelivery-charge.com/verify',
  'http://hermes-evri-shipping-problem.update-delivery-slot.info/pay',
  'http://ups-express-freight-invoice.download-shipping-label.net/auth',
  'http://irs-stimulus-payment-portal.verify-bank-routing-number.org/claim',
  'http://ssa-gov-benefit-suspension.confirm-identity-details.com/login',
  'http://student-loan-forgiveness-app.verify-fsa-id-credentials.net/apply',
  'http://medicare-card-replacement-form.confirm-beneficiary-info.org/verify',
  'http://doc-share-00491.secure-invoice-download-portal.com/view?file=inv_8821&redirect=http://198.51.100.55/payload',
  'http://webscr-cmd-login.paypal-account-limited-9941.com/signin?token=88192038192',
  'http://auth-verify-user@secure-login-gateway.credential-check.net/confirm',
  'http://secure-mail-quarantine-release.view-blocked-messages.com/owa/login.php',
  'http://microsoft365-teams-voicemail-alert.listen-audio-message.net/auth',
  'http://sharepoint-confidential-salary-sheet.sign-in-to-view.org/login',
  'http://dropbox-encrypted-wire-instructions.verify-email-to-open.com/auth',
  'http://intuit-quickbooks-overdue-invoice.pay-or-dispute-now.net/login',
  'http://xero-accounting-remittance-advice.download-pdf-statement.com/auth',
  'http://zendesk-support-ticket-escalation.verify-admin-credentials.org/login',
  'http://cloudflare-ddos-verification-check.complete-wallet-auth.com/verify',
];

export function getBuiltInDataset() {
  const samples = [];
  for (const raw of BUILT_IN_LEGITIMATE_URLS) {
    const norm = normalizeUrl(raw);
    if (norm.valid) {
      samples.push({ url: norm.normalizedUrl, label: 0 });
    }
  }
  for (const raw of BUILT_IN_PHISHING_URLS) {
    const norm = normalizeUrl(raw);
    if (norm.valid) {
      samples.push({ url: norm.normalizedUrl, label: 1 });
    }
  }
  return samples;
}

export function getDefaultBuiltInDataset() {
  const samples = getBuiltInDataset();
  return {
    samples,
    name: `Curated Phishing & Legitimate URL Corpus (${samples.length} URLs)`,
  };
}

function parseCsvLine(line) {
  const fields = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      fields.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  fields.push(current.trim());
  return fields;
}

function interpretLabel(rawLabel) {
  const v = rawLabel.trim().toLowerCase();
  if (!v) return null;
  if (
    v === '1' ||
    v === 'phishing' ||
    v === 'bad' ||
    v === 'malicious' ||
    v === 'malware' ||
    v === 'defacement' ||
    v === 'spam' ||
    v === 'true' ||
    v === 'yes' ||
    v === 'online'
  ) {
    return 1;
  }
  if (
    v === '0' ||
    v === 'legitimate' ||
    v === 'benign' ||
    v === 'good' ||
    v === 'safe' ||
    v === 'clean' ||
    v === 'false' ||
    v === 'no'
  ) {
    return 0;
  }
  return null;
}

export function parseUrlDatasetCsv(csvText, maxRows = 5000) {
  const lines = csvText
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'));

  if (lines.length < 2) {
    throw new Error('CSV must include a header row and at least one data row.');
  }

  const header = parseCsvLine(lines[0]).map((h) => h.toLowerCase());
  const urlColIdx = header.findIndex((h) =>
    ['url', 'urls', 'domain', 'link', 'uri'].includes(h)
  );
  const labelColIdx = header.findIndex((h) =>
    ['label', 'class', 'status', 'type', 'is_phishing', 'target', 'result', 'verified', 'threat'].includes(h)
  );

  if (urlColIdx === -1) {
    throw new Error(
      'Could not find a "url" column in CSV header. Expected columns such as url,label or PhishTank/URLhaus url column.'
    );
  }

  let formatDetected = 'Generic Labeled URL CSV (url, label)';
  if (header.includes('phish_id')) {
    formatDetected = 'PhishTank CSV Feed';
  } else if (header.includes('urlhaus_link') || header.includes('threat')) {
    formatDetected = 'URLhaus CSV Feed';
  } else if (header.includes('type') || header.includes('label')) {
    formatDetected = 'Kaggle Phishing URL Dataset CSV';
  }

  const samples = [];
  let skippedRows = 0;

  for (let i = 1; i < lines.length && samples.length < maxRows; i++) {
    const cols = parseCsvLine(lines[i]);
    const rawUrl = cols[urlColIdx];
    if (!rawUrl) {
      skippedRows++;
      continue;
    }

    let label = null;
    if (labelColIdx >= 0) {
      label = interpretLabel(cols[labelColIdx] ?? '');
      if (label === null && header[labelColIdx] === 'threat' && cols[labelColIdx]) {
        label = 1;
      }
    } else if (header.includes('phish_id')) {
      label = 1;
    }

    if (label === null) {
      skippedRows++;
      continue;
    }

    const norm = normalizeUrl(rawUrl);
    if (!norm.valid) {
      skippedRows++;
      continue;
    }

    samples.push({ url: norm.normalizedUrl, label });
  }

  const phishCount = samples.filter((s) => s.label === 1).length;
  const legitCount = samples.length - phishCount;

  if (samples.length < 10) {
    throw new Error(
      `Only ${samples.length} valid labeled URLs parsed. At least 10 rows are required for train/test evaluation.`
    );
  }
  if (phishCount < 2 || legitCount < 2) {
    throw new Error(
      'Uploaded CSV must contain both phishing (at least 2) and legitimate (at least 2) labeled URLs to train and evaluate classifiers.'
    );
  }

  return { samples, formatDetected, skippedRows };
}

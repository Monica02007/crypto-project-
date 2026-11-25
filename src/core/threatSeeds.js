export const STARTER_THREAT_SEEDS = [
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

export const DISCLAIMER_TEXT =
  'Probabilistic Assessment Disclaimer: Cryptographic hash matching only detects exact known normalized URLs, and classical ML predictions are statistical estimates rather than absolute guarantees. Novel zero-day phishing URLs can evade both checks, while complex legitimate URLs (e.g., long OAuth or tracking links) can occasionally trigger false positives.';

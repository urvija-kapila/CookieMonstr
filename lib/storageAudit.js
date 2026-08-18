// Storage audit rules: detect sensitive data stored in plain text in localStorage/sessionStorage

const SENSITIVE_PATTERNS = [
  {
    id: 'api_key_exposed',
    severity: 'CRITICAL',
    keyPattern: /api[_-]?key|apikey|secret[_-]?key|secretkey|access[_-]?key|accesskey/i,
    title: 'API Key exposed in storage',
    explanation: 'API keys should never be stored in browser storage. They can be stolen via XSS attacks.',
    fix: 'Store API keys on the server. Use server-to-server authentication instead.'
  },
  {
    id: 'jwt_token_exposed',
    severity: 'CRITICAL',
    keyPattern: /jwt|auth[_-]?token|authtoken|access[_-]?token|accesstoken|bearer|token/i,
    valuePattern: /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/,
    title: 'JWT token exposed in storage',
    explanation: 'JWT tokens in localStorage are vulnerable to XSS. Store them in httpOnly cookies instead.',
    fix: 'Use httpOnly, Secure cookies for authentication tokens.'
  },
  {
    id: 'password_in_storage',
    severity: 'CRITICAL',
    keyPattern: /password|passwd|pwd|pass/i,
    title: 'Password stored in plain text',
    explanation: 'Passwords should never be stored in browser storage. They can be compromised via XSS or malware.',
    fix: 'Remove password storage. Use session tokens instead.'
  },
  {
    id: 'email_exposed',
    severity: 'HIGH',
    keyPattern: /email|mail|user|username|login/i,
    valuePattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    title: 'Email address stored in storage',
    explanation: 'Email addresses in localStorage can be harvested for phishing or social engineering attacks.',
    fix: 'Store user identifiers (UUIDs/IDs) instead of email addresses.'
  },
  {
    id: 'credit_card_exposed',
    severity: 'CRITICAL',
    valuePattern: /^[0-9]{13,19}$/,
    title: 'Possible credit card number in storage',
    explanation: 'Credit card numbers must never be stored in localStorage. Use PCI-compliant payment systems.',
    fix: 'Remove all credit card data. Use Stripe, Square, or similar compliant payment processors.'
  },
  {
    id: 'ssn_exposed',
    severity: 'CRITICAL',
    valuePattern: /^\d{3}-\d{2}-\d{4}$/,
    title: 'Possible SSN in storage',
    explanation: 'Social Security numbers should never be stored in browser storage.',
    fix: 'Remove all SSN data. Store only necessary identifiers.'
  },
  {
    id: 'session_id_exposed',
    severity: 'HIGH',
    keyPattern: /session|sid|sessionid|sess/i,
    title: 'Session ID in localStorage',
    explanation: 'Session IDs in localStorage are vulnerable to XSS attacks and can enable session hijacking.',
    fix: 'Use httpOnly cookies for session management.'
  },
  {
    id: 'private_key_exposed',
    severity: 'CRITICAL',
    valuePattern: /-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)/,
    title: 'Private key exposed in storage',
    explanation: 'Private keys should never be stored in browser storage. This is a severe security breach.',
    fix: 'Remove private keys immediately. Use server-side key management.'
  },
  {
    id: 'oauth_token_exposed',
    severity: 'CRITICAL',
    keyPattern: /oauth|bearer|refresh[_-]?token|access[_-]?token/i,
    title: 'OAuth token exposed in storage',
    explanation: 'OAuth tokens in localStorage can be stolen via XSS and used to access user accounts.',
    fix: 'Store OAuth tokens in httpOnly cookies. Use refresh token rotation.'
  }
];

/**
 * Audit a single storage item (key-value pair)
 */
function auditStorageItem(key, value, storageType) {
  const findings = [];

  SENSITIVE_PATTERNS.forEach((pattern) => {
    // Check key pattern
    const keyMatch = pattern.keyPattern && pattern.keyPattern.test(key);

    // Check value pattern (if defined)
    const valueMatch = pattern.valuePattern ? pattern.valuePattern.test(value) : false;

    // Report if key matches OR (both key and value patterns match)
    if (keyMatch || (pattern.keyPattern && keyMatch && value.length > 0) || valueMatch) {
      findings.push({
        id: pattern.id,
        severity: pattern.severity,
        title: pattern.title,
        explanation: pattern.explanation,
        fix: pattern.fix
      });
    }
  });

  return {
    key,
    value: value.length > 50 ? value.substring(0, 50) + '...' : value, // Truncate for display
    storageType, // 'localStorage' or 'sessionStorage'
    findings,
    riskLevel: findings.length > 0 ? findings[0].severity : 'SAFE'
  };
}

/**
 * Audit all storage items from localStorage and sessionStorage
 */
export function auditStorage(localStorageData, sessionStorageData) {
  const auditedItems = [];

  // Audit localStorage
  Object.entries(localStorageData).forEach(([key, value]) => {
    const audited = auditStorageItem(key, value, 'localStorage');
    if (audited.findings.length > 0) {
      auditedItems.push(audited);
    }
  });

  // Audit sessionStorage
  Object.entries(sessionStorageData).forEach(([key, value]) => {
    const audited = auditStorageItem(key, value, 'sessionStorage');
    if (audited.findings.length > 0) {
      auditedItems.push(audited);
    }
  });

  // Sort by severity
  const severityPriority = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  auditedItems.sort(
    (a, b) => severityPriority[b.riskLevel] - severityPriority[a.riskLevel]
  );

  return auditedItems;
}

/**
 * Generate storage summary
 */
export function generateStorageSummary(auditedItems) {
  const summary = {
    total: auditedItems.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    safe: 0
  };

  auditedItems.forEach((item) => {
    switch (item.riskLevel) {
      case 'CRITICAL':
        summary.critical++;
        break;
      case 'HIGH':
        summary.high++;
        break;
      case 'MEDIUM':
        summary.medium++;
        break;
      case 'LOW':
        summary.low++;
        break;
      case 'SAFE':
        summary.safe++;
        break;
    }
  });

  return summary;
}

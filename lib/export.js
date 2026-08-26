const PII_KEY_PATTERN = /ip|location|geo|lat|lon|postal|city|uuid|uid|token|session|auth|identity|userid/i;
const IP_PATTERN = /\b\d{1,3}(?:\.\d{1,3}){3}\b/;
const EMAIL_PATTERN = /[^\s@]+@[^\s@]+\.[^\s@]+/;

import { auditStorage } from './storageAudit.js';

const OWASP_CATEGORIES = [
  { id: 'A01:2021', name: 'Broken Access Control' },
  { id: 'A02:2021', name: 'Cryptographic Failures' },
  { id: 'A05:2021', name: 'Security Misconfiguration' },
  { id: 'A07:2021', name: 'Identification and Authentication Failures' }
];

function shannonEntropy(value) {
  const frequencies = {};

  for (const character of value) {
    frequencies[character] = (frequencies[character] || 0) + 1;
  }

  return Object.values(frequencies).reduce((entropy, frequency) => {
    const probability = frequency / value.length;
    return entropy - probability * Math.log2(probability);
  }, 0);
}

function isHighEntropyValue(value) {
  return typeof value === 'string' &&
    value.length > 40 &&
    shannonEntropy(value) > 4.5;
}

function containsPii(value) {
  return IP_PATTERN.test(value) || EMAIL_PATTERN.test(value) || isHighEntropyValue(value);
}

function redactValue(value, key = '') {
  if (typeof value === 'string') {
    if (PII_KEY_PATTERN.test(key) || containsPii(value)) {
      return '[REDACTED]';
    }

    try {
      const parsedValue = JSON.parse(value);
      if (parsedValue && typeof parsedValue === 'object') {
        return JSON.stringify(redactValue(parsedValue, key));
      }
    } catch {
      // Keep ordinary strings unchanged.
    }

    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, key));
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, childValue]) => [
        childKey,
        PII_KEY_PATTERN.test(childKey)
          ? '[REDACTED]'
          : redactValue(childValue, childKey)
      ])
    );
  }

  return value;
}

export function redactStorageValues(rawStorage) {
  return redactValue(rawStorage);
}

export function buildOwaspCoverage(allFindings) {
  return Object.fromEntries(OWASP_CATEGORIES.map((category) => {
    const matchingFindings = allFindings.filter(
      (finding) => finding.owasp?.id === category.id
    );

    return [category.id, {
      name: category.name,
      triggered: matchingFindings.length > 0,
      finding_count: matchingFindings.length
    }];
  }));
}

export function buildExportObject(auditData, { redact = true } = {}) {
  const storage = redact ? redactStorageValues(auditData.storage || {}) : auditData.storage || {};
  const cookies = auditData.cookies || [];
  const tracking = auditData.tracking || {};
  const auditedStorageItems = auditStorage(
    auditData.storage?.localStorage || {},
    auditData.storage?.sessionStorage || {}
  );
  const allFindings = [
    ...cookies.flatMap((cookie) => cookie.findings || []),
    ...auditedStorageItems.flatMap((item) => item.findings || [])
  ];

  return {
    version: '0.1',
    timestamp: new Date().toISOString(),
    url: auditData.url,
    summary: {
      totalCookies: cookies.length,
      totalStorageItems: Object.keys(auditData.storage?.localStorage || {}).length +
        Object.keys(auditData.storage?.sessionStorage || {}).length,
      totalTrackers: (tracking.trackers || []).length
    },
    cookies: {
      total: cookies.length,
      findings: cookies
    },
    storage: {
      items: storage,
      findings: auditedStorageItems
    },
    tracking: {
      summary: tracking.summary,
      trackers: tracking.trackers,
      suspicious: tracking.suspicious,
      overload: tracking.overload
    },
    owasp_coverage: buildOwaspCoverage(allFindings)
  };
}

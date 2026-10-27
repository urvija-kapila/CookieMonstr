
import { auditCookies } from "../lib/cookieAudit.js";

// Controlled cases for six cookie-security rules.
// Each label is defined for one specific rule.

const now = Date.now() / 1000;
const day = 24 * 60 * 60;

function cookie(overrides = {}) {
  return {
    name: "preferences",
    domain: "app.example.test",
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    session: true,
    ...overrides
  };
}

const cases = [
  // HttpOnly
  ["HTTP-01", "missing_httponly",
    { httpOnly: false }, true],
  ["HTTP-02", "missing_httponly",
    { httpOnly: true }, false],
  ["HTTP-03", "missing_httponly",
    { name: "session_id", httpOnly: false }, true],
  ["HTTP-04", "missing_httponly",
    { name: "session_id", httpOnly: true }, false],

  // Secure
  ["SEC-01", "missing_secure",
    { name: "session_id", secure: false }, true],
  ["SEC-02", "missing_secure",
    { name: "session_id", secure: true }, false],
  ["SEC-03", "missing_secure",
    { name: "auth_token", secure: false }, true],
  ["SEC-04", "missing_secure",
    { name: "preferences", secure: false }, false],

  // SameSite unspecified
  ["SAME-01", "samesite_missing",
    { sameSite: "unspecified" }, true],
  ["SAME-02", "samesite_missing",
    { sameSite: "lax" }, false],
  ["SAME-03", "samesite_missing",
    { sameSite: undefined }, true],
  ["SAME-04", "samesite_missing",
    { sameSite: "strict" }, false],

  // SameSite=None without Secure
  ["NONE-01", "samesite_none_without_secure",
    { sameSite: "no_restriction", secure: false }, true],
  ["NONE-02", "samesite_none_without_secure",
    { sameSite: "no_restriction", secure: true }, false],
  ["NONE-03", "samesite_none_without_secure",
    { sameSite: "lax", secure: false }, false],
  ["NONE-04", "samesite_none_without_secure",
    { sameSite: "strict", secure: true }, false],

  // Broad domain
  ["DOM-01", "broad_domain",
    { domain: ".example.test" }, true],
  ["DOM-02", "broad_domain",
    { domain: "app.example.test" }, false],
  ["DOM-03", "broad_domain",
    { domain: ".sub.example.test" }, true],
  ["DOM-04", "broad_domain",
    { domain: "example.test" }, false],

  // Long-lived session cookies
  ["LIFE-01", "long_lived_session",
    { name: "session_id", expirationDate: now + 200 * day }, true],
  ["LIFE-02", "long_lived_session",
    { name: "session_id", expirationDate: now + 30 * day }, false],
  ["LIFE-03", "long_lived_session",
    { name: "auth_token", expirationDate: now + 365 * day }, true],
  ["LIFE-04", "long_lived_session",
    { name: "preferences", expirationDate: now + 365 * day }, false]
];

function percent(a, b) {
  return b === 0 ? null : +(100 * a / b).toFixed(2);
}

const results = [];
const rules = [...new Set(cases.map(c => c[1]))];

for (const rule of rules) {
  const counts = { TP: 0, TN: 0, FP: 0, FN: 0 };

  for (const [id, targetRule, overrides, expected] of cases) {
    if (targetRule !== rule) continue;

    const audited = auditCookies([cookie(overrides)]);

    const detected = audited[0].findings.some(
      finding => finding.id === rule
    );

    const outcome = detected
      ? (expected ? "TP" : "FP")
      : (expected ? "FN" : "TN");

    counts[outcome]++;

    console.log(`${id}: ${outcome}`);
  }

  const { TP, TN, FP, FN } = counts;
  const precision = percent(TP, TP + FP);
  const recall = percent(TP, TP + FN);

  const f1 = precision === null || recall === null
    ? null
    : precision + recall === 0
      ? 0
      : +(2 * precision * recall / (precision + recall)).toFixed(2);

  results.push({
    rule,
    ...counts,
    precision,
    recall,
    f1,
    falsePositiveRate: percent(FP, FP + TN),
    falseNegativeRate: percent(FN, FN + TP)
  });
}

console.log("\n=== CookieMonstr Cookie Validation ===");
console.table(results);

const totals = results.reduce(
  (acc, row) => {
    for (const field of ["TP", "TN", "FP", "FN"]) {
      acc[field] += row[field];
    }
    return acc;
  },
  { TP: 0, TN: 0, FP: 0, FN: 0 }
);

console.log("\nCombined confusion matrix:");
console.table(totals);
console.log("Total cases:", cases.length);

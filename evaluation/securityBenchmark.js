
import { auditStorage } from "../lib/storageAudit.js";

// Controlled synthetic examples.
// Each expected label refers to one specific detection rule.
// Freeze these labels before making further rule changes.

const testCases = [
  // Password detection
  { rule: "password_in_storage", key: "adminPassword", value: "demoSecret123", expected: true },
  { rule: "password_in_storage", key: "db_pwd", value: "demoSecret456", expected: true },
  { rule: "password_in_storage", key: "account_passcode", value: "123456", expected: true },
  { rule: "password_in_storage", key: "passwordPolicy", value: "strict", expected: false },
  { rule: "password_in_storage", key: "passengerList", value: "empty", expected: false },
  { rule: "password_in_storage", key: "compass_direction", value: "east", expected: false },

  // API key detection
  { rule: "api_key_exposed", key: "api_key", value: "DEMO_KEY_VALUE", expected: true },
  { rule: "api_key_exposed", key: "secretKey", value: "DEMO_SECRET", expected: true },
  { rule: "api_key_exposed", key: "access_key", value: "DEMO_ACCESS", expected: true },
  { rule: "api_key_exposed", key: "api_key_enabled", value: "false", expected: false },
  { rule: "api_key_exposed", key: "keyboard_layout", value: "US", expected: false },
  { rule: "api_key_exposed", key: "api_version", value: "v2", expected: false },

  // Session identifier detection
  { rule: "session_id_exposed", key: "session_id", value: "demo-session-123", expected: true },
  { rule: "session_id_exposed", key: "user_session", value: "demo-session-456", expected: true },
  { rule: "session_id_exposed", key: "sessionid", value: "demo-session-789", expected: true },
  { rule: "session_id_exposed", key: "sessionTimeout", value: "3600", expected: false },
  { rule: "session_id_exposed", key: "session_enabled", value: "true", expected: false },
  { rule: "session_id_exposed", key: "theme", value: "dark", expected: false }
];

function percentage(n, d) {
  return d === 0 ? null : +(100 * n / d).toFixed(2);
}

function evaluate(rule) {
  const cases = testCases.filter(c => c.rule === rule);
  const counts = { TP: 0, TN: 0, FP: 0, FN: 0 };
  const details = [];

  for (const item of cases) {
    const audited = auditStorage(
      { [item.key]: item.value },
      {}
    );

    const detected = audited.some(entry =>
      entry.findings.some(finding => finding.id === rule)
    );

    const outcome = detected
      ? (item.expected ? "TP" : "FP")
      : (item.expected ? "FN" : "TN");

    counts[outcome]++;

    details.push({
      key: item.key,
      expected: item.expected,
      detected,
      outcome
    });
  }

  const { TP, TN, FP, FN } = counts;
  const precision = percentage(TP, TP + FP);
  const recall = percentage(TP, TP + FN);

  const f1 = precision === null || recall === null
    ? null
    : precision + recall === 0
      ? 0
      : +(2 * precision * recall / (precision + recall)).toFixed(2);

  return {
    rule,
    cases: cases.length,
    ...counts,
    accuracy: percentage(TP + TN, cases.length),
    precision,
    recall,
    f1,
    falsePositiveRate: percentage(FP, FP + TN),
    falseNegativeRate: percentage(FN, FN + TP),
    details
  };
}

const rules = [
  "password_in_storage",
  "api_key_exposed",
  "session_id_exposed"
];

const results = rules.map(evaluate);

console.log("\n=== CookieMonstr Security Benchmark ===");

console.table(results.map(({ details, ...metrics }) => metrics));

for (const result of results) {
  console.log(`\n${result.rule}`);
  console.table(result.details);
}

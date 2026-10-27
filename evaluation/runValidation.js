
import fs from "node:fs";
import { auditStorage } from "../lib/storageAudit.js";


const fixtureName = process.argv[2] || "storage-cases.json";

const allowedFixtures = [
  "storage-cases.json",
  "final-storage-cases.json"
];

if (!allowedFixtures.includes(fixtureName)) {
  throw new Error(`Unknown validation dataset: ${fixtureName}`);
}

const cases = JSON.parse(
  fs.readFileSync(
    new URL(`./validation/${fixtureName}`, import.meta.url),
    "utf8"
  )
);

console.log(`\nDataset: ${fixtureName}`);


function percent(a, b) {
  return b === 0 ? null : +(100 * a / b).toFixed(2);
}

function evaluateRule(ruleId, casesForRule) {
  const counts = { TP: 0, TN: 0, FP: 0, FN: 0 };
  const details = [];

  for (const item of casesForRule) {
    const audited = auditStorage(
      { [item.key]: item.value },
      {}
    );

    const detected = audited.some(entry =>
      entry.findings.some(f => f.id === ruleId)
    );

    const outcome = detected
      ? (item.expected ? "TP" : "FP")
      : (item.expected ? "FN" : "TN");

    counts[outcome]++;

    details.push({
      id: item.id,
      key: item.key,
      expected: item.expected,
      detected,
      outcome
    });
  }

  const { TP, TN, FP, FN } = counts;
  const precision = percent(TP, TP + FP);
  const recall = percent(TP, TP + FN);

  const f1 = precision === null || recall === null
    ? null
    : precision + recall === 0
      ? 0
      : +(2 * precision * recall / (precision + recall)).toFixed(2);

  return {
    rule: ruleId,
    cases: casesForRule.length,
    ...counts,
    accuracy: percent(TP + TN, casesForRule.length),
    precision,
    recall,
    f1,
    falsePositiveRate: percent(FP, FP + TN),
    falseNegativeRate: percent(FN, FN + TP),
    details
  };
}

// Validate fixture structure before calculating metrics.
const ids = new Set();

for (const item of cases) {
  if (
    !item.id ||
    !item.rule ||
    typeof item.key !== "string" ||
    typeof item.value !== "string" ||
    typeof item.expected !== "boolean" ||
    !item.reason ||
    ids.has(item.id)
  ) {
    throw new Error(`Invalid or duplicate test case: ${item.id}`);
  }

  ids.add(item.id);
}

const rules = [...new Set(cases.map(item => item.rule))];

const results = rules.map(rule =>
  evaluateRule(
    rule,
    cases.filter(item => item.rule === rule)
  )
);

console.log("\n=== CookieMonstr Validation Results ===");

console.table(
  results.map(({ details, ...metrics }) => metrics)
);

console.log("\n=== Individual Test Results ===");

for (const result of results) {
  console.log(`\nRule: ${result.rule}`);
  console.table(result.details);
}

const failures = results.flatMap(result =>
  result.details
    .filter(item => item.outcome === "FP" || item.outcome === "FN")
    .map(item => ({ rule: result.rule, ...item }))
);

console.log("\n=== Misclassified Cases ===");
console.table(failures);

console.log("Total cases:", cases.length);
console.log("Total misclassifications:", failures.length);

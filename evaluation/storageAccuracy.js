
import { auditStorage } from "../lib/storageAudit.js";

// Each case has a manually assigned expected outcome.
// These values are synthetic and contain no real credentials.

const testCases = [
  {
    key: "password",
    value: "example_password_123",
    expected: true
  },
  {
    key: "user_pwd",
    value: "example_secret_456",
    expected: true
  },
  {
    key: "passwd",
    value: "example_secret_789",
    expected: true
  },
  {
    key: "compass_mode",
    value: "north",
    expected: false
  },
  {
    key: "passenger_count",
    value: "4",
    expected: false
  },
  {
    key: "theme",
    value: "dark",
    expected: false
  },
  {
    key: "locale",
    value: "en-US",
    expected: false
  },
  {
    key: "display_name",
    value: "Alex",
    expected: false
  }
];

const results = {
  TP: 0,
  TN: 0,
  FP: 0,
  FN: 0
};

for (const testCase of testCases) {
  const findings = auditStorage(
    { [testCase.key]: testCase.value },
    {}
  );

  const detected = findings.some(item =>
    item.findings.some(
      finding => finding.id === "password_in_storage"
    )
  );

  let classification;

  if (detected && testCase.expected) {
    classification = "TP";
  } else if (!detected && !testCase.expected) {
    classification = "TN";
  } else if (detected && !testCase.expected) {
    classification = "FP";
  } else {
    classification = "FN";
  }

  results[classification]++;

  console.log(
    `${testCase.key}: ${classification}`
  );
}

function percentage(numerator, denominator) {
  return denominator === 0
    ? null
    : (numerator / denominator) * 100;
}

const precision = percentage(
  results.TP,
  results.TP + results.FP
);

const recall = percentage(
  results.TP,
  results.TP + results.FN
);

const falsePositiveRate = percentage(
  results.FP,
  results.FP + results.TN
);

const falseNegativeRate = percentage(
  results.FN,
  results.FN + results.TP
);

const f1 = (
  precision === null ||
  recall === null ||
  precision + recall === 0
)
  ? null
  : (2 * precision * recall) / (precision + recall);

function formatMetric(value) {
  return value === null
    ? "N/A"
    : `${value.toFixed(2)}%`;
}

console.log("\n--- Detection Accuracy Report ---");

console.table(results);

console.log("Test cases:", testCases.length);
console.log("Precision:", formatMetric(precision));
console.log("Recall:", formatMetric(recall));
console.log("False Positive Rate:", formatMetric(falsePositiveRate));
console.log("False Negative Rate:", formatMetric(falseNegativeRate));
console.log("F1 Score:", formatMetric(f1));

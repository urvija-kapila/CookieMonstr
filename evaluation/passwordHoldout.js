
import { auditStorage } from "../lib/storageAudit.js";

// New synthetic cases not used in the first evaluation.
// expected = true means we expect the password rule to flag it.

const testCases = [
  { key: "login_pass", value: "example123", expected: true },
  { key: "account_passwd", value: "example123", expected: true },
  { key: "admin_password", value: "example123", expected: true },
  { key: "userPass", value: "example123", expected: true },
  { key: "loginPwd", value: "example123", expected: true },
  { key: "passcode", value: "example123", expected: true },

  { key: "passportNumber", value: "A1234567", expected: false },
  { key: "passengerType", value: "adult", expected: false },
  { key: "compassHeading", value: "north", expected: false },
  { key: "bypassFlag", value: "true", expected: false },
  { key: "themeColor", value: "blue", expected: false },
  { key: "passwordResetEnabled", value: "false", expected: false }
];

const counts = { TP: 0, TN: 0, FP: 0, FN: 0 };
const details = [];

for (const item of testCases) {
  const audited = auditStorage(
    { [item.key]: item.value },
    {}
  );

  const detected = audited.some(entry =>
    entry.findings.some(
      finding => finding.id === "password_in_storage"
    )
  );

  let classification;

  if (detected && item.expected) classification = "TP";
  else if (!detected && !item.expected) classification = "TN";
  else if (detected && !item.expected) classification = "FP";
  else classification = "FN";

  counts[classification]++;

  details.push({
    key: item.key,
    expected: item.expected,
    detected,
    result: classification
  });
}

function percent(a, b) {
  return b === 0 ? null : (a / b) * 100;
}

const precision = percent(
  counts.TP,
  counts.TP + counts.FP
);

const recall = percent(
  counts.TP,
  counts.TP + counts.FN
);

const accuracy = percent(
  counts.TP + counts.TN,
  testCases.length
);

const fpr = percent(
  counts.FP,
  counts.FP + counts.TN
);

const fnr = percent(
  counts.FN,
  counts.FN + counts.TP
);

const f1 = precision === null || recall === null
  ? null
  : precision + recall === 0
    ? 0
    : 2 * precision * recall / (precision + recall);

const format = value =>
  value === null ? "N/A" : `${value.toFixed(2)}%`;

console.log("\n--- Held-Out Password Detection Evaluation ---");
console.table(details);

console.log("\nConfusion Matrix:");
console.table(counts);

console.log("Total cases:", testCases.length);
console.log("Accuracy:", format(accuracy));
console.log("Precision:", format(precision));
console.log("Recall:", format(recall));
console.log("False Positive Rate:", format(fpr));
console.log("False Negative Rate:", format(fnr));
console.log("F1 Score:", format(f1));

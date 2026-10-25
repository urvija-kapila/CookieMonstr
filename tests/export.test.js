import test from "node:test";
import assert from "node:assert/strict";

import { buildExportObject } from "../lib/export.js";

// Synthetic test value — not a real authentication token.
const TEST_TOKEN = "FAKE_AUTH_TOKEN_123456789";

// Create controlled browser audit data.
function createAuditData() {
  return {
    url: "https://example.com",
    cookies: [],
    storage: {
      localStorage: {
        auth_token: TEST_TOKEN
      },
      sessionStorage: {}
    },
    tracking: {
      trackers: [],
      suspicious: [],
      overload: [],
      summary: {}
    }
  };
}

// TEST 1: Redaction must protect the entire exported report.
test("redacted export does not expose authentication tokens", () => {
  const report = buildExportObject(
    createAuditData(),
    { redact: true }
  );

  const json = JSON.stringify(report);

  // Secret must not appear anywhere in the report.
  assert.equal(json.includes(TEST_TOKEN), false);

  // Original storage entry must be redacted.
  assert.equal(
    report.storage.items.localStorage.auth_token,
    "[REDACTED]"
  );

  // Security findings must still exist.
  assert.ok(report.storage.findings.length > 0);

  // Sensitive value in findings must also be redacted.
  assert.equal(
    report.storage.findings[0].value,
    "[REDACTED]"
  );
});

// TEST 2: Explicitly disabling redaction preserves data.
test("unredacted export preserves the original token", () => {
  const report = buildExportObject(
    createAuditData(),
    { redact: false }
  );

  assert.equal(
    report.storage.items.localStorage.auth_token,
    TEST_TOKEN
  );
});


test("credit card findings are redacted without losing detection", () => {
  const data = createAuditData();

  data.storage.localStorage = {
    checkout_data: "4111111111111111"
  };

  const report = buildExportObject(data, {
    redact: true
  });

  const json = JSON.stringify(report);

  // The synthetic card number must not appear in the report.
  assert.equal(
    json.includes("4111111111111111"),
    false
  );

  // Its original storage value must be hidden.
  assert.equal(
    report.storage.items.localStorage.checkout_data,
    "[REDACTED]"
  );

  // The detection must still be present.
  const finding = report.storage.findings.find(
    item => item.key === "checkout_data"
  );

  assert.ok(finding);

  assert.ok(
    finding.findings.some(
      issue => issue.id === "credit_card_exposed"
    )
  );

  assert.equal(finding.value, "[REDACTED]");
});

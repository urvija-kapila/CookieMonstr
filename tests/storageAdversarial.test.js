import test from "node:test";
import assert from "node:assert/strict";

import { auditStorage } from "../lib/storageAudit.js";

function detects(ruleId, key, value) {
  const result = auditStorage(
    { [key]: value },
    {}
  );

  return result.some(entry =>
    entry.findings.some(
      finding => finding.id === ruleId
    )
  );
}

// Baseline: harmless metadata should remain unflagged.
test("harmless session timeout is not detected", () => {
  assert.equal(
    detects("session_id_exposed", "sessionTimeout", "3600"),
    false
  );
});


test.todo(
  "Define supported value-based session formats and test detection under generic storage keys"
);


// Adversarial case: password-looking key containing metadata.
test("password configuration is not treated as credential", () => {
  assert.equal(
    detects("password_in_storage", "passwordPolicy", "strict"),
    false
  );
});

// Adversarial case: an ordinary identifier.
test("ordinary numeric identifier is not a session secret", () => {
  assert.equal(
    detects("session_id_exposed", "recordId", "12345"),
    false
  );
});

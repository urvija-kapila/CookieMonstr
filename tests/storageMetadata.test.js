
import test from "node:test";
import assert from "node:assert/strict";

import { auditStorage } from "../lib/storageAudit.js";

// Returns true if the specified rule detects the storage entry.
function fires(ruleId, key, value) {
  const audited = auditStorage(
    { [key]: value },
    {}
  );

  return audited.some(entry =>
    entry.findings.some(
      finding => finding.id === ruleId
    )
  );
}

// Regression tests for previously observed false positives.

test("password policy configuration is not flagged", () => {
  assert.equal(
    fires("password_in_storage", "passwordPolicy", "strict"),
    false
  );
});

test("API key enabled flag is not flagged", () => {
  assert.equal(
    fires("api_key_exposed", "api_key_enabled", "false"),
    false
  );
});

test("session timeout configuration is not flagged", () => {
  assert.equal(
    fires("session_id_exposed", "sessionTimeout", "3600"),
    false
  );
});

test("session enabled flag is not flagged", () => {
  assert.equal(
    fires("session_id_exposed", "session_enabled", "true"),
    false
  );
});

// Ensure valid detections still work.

test("password credential remains detectable", () => {
  assert.equal(
    fires("password_in_storage", "adminPassword", "demoSecret123"),
    true
  );
});

test("API key remains detectable", () => {
  assert.equal(
    fires("api_key_exposed", "api_key", "DEMO_KEY_VALUE"),
    true
  );
});

test("session identifier remains detectable", () => {
  assert.equal(
    fires("session_id_exposed", "session_id", "demo-session-123"),
    true
  );
});

import test from "node:test";
import assert from "node:assert/strict";

import { auditCookies } from "../lib/cookieAudit.js";

// Helper function: creates a secure cookie by default.
function createCookie(overrides = {}) {
  return {
    name: "preferences",
    domain: "app.example.com",
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    session: true,
    ...overrides
  };
}

// TEST 1: Secure cookie should not generate findings.
test("secure cookie produces no findings", () => {
  const result = auditCookies([createCookie()]);

  assert.equal(result.length, 1);
  assert.equal(result[0].findings.length, 0);
  assert.equal(result[0].riskScore, 0);
  assert.equal(result[0].riskLevel, "SAFE");
});

// TEST 2: Missing HttpOnly should generate a HIGH finding.
test("missing HttpOnly produces correct finding", () => {
  const result = auditCookies([
    createCookie({ httpOnly: false })
  ]);

  const cookie = result[0];

  assert.equal(cookie.findings.length, 1);
  assert.equal(cookie.findings[0].id, "missing_httponly");
  assert.equal(cookie.findings[0].severity, "HIGH");
  assert.equal(cookie.riskScore, 10);
  assert.equal(cookie.riskLevel, "MEDIUM");
});

// TEST 3: Higher-risk cookies appear first.
test("cookies are ordered by descending risk score", () => {
  const result = auditCookies([
    createCookie({ name: "safe_cookie" }),
    createCookie({
      name: "unsafe_cookie",
      httpOnly: false
    })
  ]);

  assert.equal(result[0].name, "unsafe_cookie");
  assert.equal(result[1].name, "safe_cookie");

  assert.ok(result[0].riskScore > result[1].riskScore);
});

// TEST 4: Findings include security references.
test("findings contain OWASP and CWE mappings", () => {
  const result = auditCookies([
    createCookie({ httpOnly: false })
  ]);

  const finding = result[0].findings[0];

  assert.equal(finding.cwe.id, "CWE-1004");
  assert.ok(finding.owasp.id);
  assert.ok(finding.fix);
});

// TEST 5: Document the current duplicate detection.
test("insecure session cookie is not double-counted", () => {
  const result = auditCookies([
    createCookie({
      name: "session_id",
      secure: false
    })
  ]);

  const cookie = result[0];

  // Missing Secure should be reported.
  const secureFindings = cookie.findings.filter(
    finding => finding.id === "missing_secure"
  );

  assert.equal(secureFindings.length, 1);

  // Redundant rule must not generate a second finding.
  const duplicateFindings = cookie.findings.filter(
    finding => finding.id === "sensitive_cookie_without_secure"
  );

  assert.equal(duplicateFindings.length, 0);

  // Only one HIGH finding should contribute to the score.
  assert.equal(cookie.findings.length, 1);
  assert.equal(cookie.riskScore, 10);
  assert.equal(cookie.riskLevel, "MEDIUM");
});


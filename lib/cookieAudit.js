import { COOKIE_RULES } from "./cookieRules.js";
import { calculateRisk, getRiskLevel } from "./riskScore.js";
import { enrichFinding } from "./mappings.js";

const SEVERITY_PRIORITY = {
CRITICAL: 4,
HIGH: 3,
MEDIUM: 2,
LOW: 1,
INFO: 0
};

export function getHighestSeverity(findings) {
  return findings.reduce((highest, finding) => {
    const severity = finding.severity || "INFO";
    return SEVERITY_PRIORITY[severity] > SEVERITY_PRIORITY[highest]
      ? severity
      : highest;
  }, "INFO");
}

export function auditCookies(cookies) {

  const auditedCookies = cookies.map((cookie) => {

    const findings = [];

    COOKIE_RULES.forEach((rule) => {

      if (rule.test(cookie)) {

        findings.push(enrichFinding({
          id: rule.id,
          severity: rule.severity,
          title: rule.title,
          explanation: rule.explanation,
          fix: rule.fix
        }));

      }

    });

    findings.sort((a, b) =>
      SEVERITY_PRIORITY[b.severity] - SEVERITY_PRIORITY[a.severity]
    );
    const highestSeverity = getHighestSeverity(findings);
    
    const riskScore = calculateRisk(findings);
    const riskLevel = getRiskLevel(riskScore);

    return {
      name: cookie.name,
      domain: cookie.domain,
      severity: highestSeverity,
      riskScore,
      riskLevel,
      findings
    };

  });

  auditedCookies.sort((a, b) => {
    if (a.riskScore !== b.riskScore) {
      return b.riskScore - a.riskScore;
    }

    return a.name.localeCompare(b.name);
  });

  return auditedCookies;
}
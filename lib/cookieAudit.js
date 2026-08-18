import { COOKIE_RULES } from "./cookieRules.js";
import { calculateRisk, getRiskLevel } from "./riskScore.js";

const SEVERITY_PRIORITY = {
HIGH: 3,
MEDIUM: 2,
LOW: 1,
INFO: 0
};

export function auditCookies(cookies) {

  const auditedCookies = cookies.map((cookie) => {

    const findings = [];

    COOKIE_RULES.forEach((rule) => {

      if (rule.test(cookie)) {

        findings.push({
          id: rule.id,
          severity: rule.severity,
          title: rule.title,
          explanation: rule.explanation,
          fix: rule.fix
        });

      }

    });

    findings.sort((a, b) =>
      SEVERITY_PRIORITY[b.severity] - SEVERITY_PRIORITY[a.severity]
    );
    const highestSeverity = findings.length > 0 ? findings[0].severity : "INFO";
    
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
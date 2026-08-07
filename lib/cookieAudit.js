import { COOKIE_RULES } from "./cookieRules.js";

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

    return {
      name: cookie.name,
      domain: cookie.domain,
      severity: highestSeverity,
      findings
    };

  });

  auditedCookies.sort((a, b) => {
    const severityDiff = SEVERITY_PRIORITY[b.severity] - SEVERITY_PRIORITY[a.severity];
    if (severityDiff !== 0) {
      return severityDiff;
    }
    return a.name.localeCompare(b.name);
  });

  return auditedCookies;
}
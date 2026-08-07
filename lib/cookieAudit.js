import { COOKIE_RULES } from "./cookieRules.js";

export function auditCookies(cookies) {
  return cookies.map((cookie) => {

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

    return {
      name: cookie.name,
      domain: cookie.domain,
      findings
    };

  });
}
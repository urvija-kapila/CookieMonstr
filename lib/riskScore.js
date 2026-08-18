const SEVERITY_POINTS = {
  HIGH: 10,
  MEDIUM: 5,
  LOW: 2,
  INFO: 0
};

export function calculateRisk(findings) {
  let score = 0;

  findings.forEach((finding) => {
    score += SEVERITY_POINTS[finding.severity] || 0;
  });

  return score;
}

export function getRiskLevel(score) {
  if (score === 0) {
    return "SAFE";
  } else if (score <= 9) {
    return "LOW";
  } else if (score <= 19) {
    return "MEDIUM";
  } else if (score <= 29) {
    return "HIGH";
  } else {
    return "CRITICAL";
  }
}

export function generateSummary(auditedCookies) {
  const summary = {
    total: auditedCookies.length,
    safe: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  };

  auditedCookies.forEach((cookie) => {
    switch (cookie.riskLevel) {
      case "SAFE":
        summary.safe++;
        break;
      case "LOW":
        summary.low++;
        break;
      case "MEDIUM":
        summary.medium++;
        break;
      case "HIGH":
        summary.high++;
        break;
      case "CRITICAL":
        summary.critical++;
        break;
    }
  });

  return summary;
}
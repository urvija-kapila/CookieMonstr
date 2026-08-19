// Tracking detector: identifies third-party trackers and suspicious tracking patterns

const KNOWN_TRACKER_DOMAINS = [
  // Analytics
  'google-analytics.com',
  'analytics.google.com',
  'googletagmanager.com',
  'doubleclick.net',
  'google.com',
  
  // Advertising
  'facebook.com',
  'fbcdn.net',
  'ads.twitter.com',
  'twitter.com',
  'linkedin.com',
  'criteo.com',
  'adroll.com',
  'chartbeat.net',
  'hotjar.com',
  'intercom.io',
  'sentry.io',
  'segment.com',
  
  // Marketing & Conversion
  'munchkin.marketo.net',
  'hubspot.com',
  'mailchimp.com',
  'klaviyo.com',
  'snapchat.com',
  'pinterest.com',
  'reddit.com',
  
  // Performance & Monitoring
  'mixpanel.com',
  'amplitude.com',
  'fullstory.com',
  'datadog.com',
  'newrelic.com',
  'loggly.com',
  
  // Email & CRM
  'pardot.com',
  'salesforce.com',
  'zoho.com',
  'pipedrive.com'
];

/**
 * Detect if a cookie is from a known third-party tracker
 */
export function detectThirdPartyTrackers(cookies, currentDomain) {
  const trackerCookies = [];

  cookies.forEach((cookie) => {
    // Check if cookie domain matches a known tracker
    const isTracker = KNOWN_TRACKER_DOMAINS.some((tracker) => {
      return cookie.domain.includes(tracker);
    });

    if (isTracker) {
      trackerCookies.push({
        ...cookie,
        trackingType: 'Third-Party Tracker',
        severity: 'HIGH'
      });
    }
  });

  return trackerCookies;
}

/**
 * Detect if a cookie has suspicious naming patterns (random-looking, no security flags)
 */
export function detectSuspiciousNaming(cookies) {
  const suspiciousCookies = [];
  const randomPattern = /^[a-z0-9]{16,}$|_[a-z0-9]{20,}|uuid|tracking|beacon|pixel/i;

  cookies.forEach((cookie) => {
    const hasRandomName = randomPattern.test(cookie.name);
    const lacksSecurity = !cookie.httpOnly && !cookie.secure;

    if (hasRandomName && lacksSecurity) {
      suspiciousCookies.push({
        ...cookie,
        trackingType: 'Suspicious Naming Pattern',
        severity: 'MEDIUM',
        explanation:
          'This cookie has a random-looking name and lacks security flags. It may be used for tracking.'
      });
    }
  });

  return suspiciousCookies;
}

/**
 * Detect cookie overload (too many cookies indicates poor hygiene or abuse)
 */
export function detectCookieOverload(cookies) {
  const threshold = 20; // More than 20 cookies is suspicious

  if (cookies.length > threshold) {
    return {
      severity: 'MEDIUM',
      count: cookies.length,
      message: `Page has ${cookies.length} cookies, which is above recommended threshold of ${threshold}.`,
      explanation:
        'A high number of cookies can indicate tracking abuse, poor site hygiene, or bloated third-party integrations.'
    };
  }

  return null;
}

/**
 * Generate tracking summary from all findings
 */
export function generateTrackingSummary(trackers, suspicious, overload) {
  return {
    totalTrackers: trackers.length,
    totalSuspicious: suspicious.length,
    cookieOverload: overload ? true : false,
    overloadMessage: overload ? overload.message : null,
    riskLevel: getRiskLevel(trackers.length, suspicious.length, overload)
  };
}

/**
 * Determine overall tracking risk level
 */
function getRiskLevel(trackerCount, suspiciousCount, overload) {
  const totalRiskFactors = trackerCount + suspiciousCount + (overload ? 1 : 0);

  if (totalRiskFactors === 0) {
    return 'SAFE';
  } else if (totalRiskFactors <= 2) {
    return 'LOW';
  } else if (totalRiskFactors <= 5) {
    return 'MEDIUM';
  } else {
    return 'HIGH';
  }
}

/**
 * Full tracking analysis
 */
export function analyzeTracking(cookies, currentDomain) {
  const trackers = detectThirdPartyTrackers(cookies, currentDomain);
  const suspicious = detectSuspiciousNaming(cookies);
  const overload = detectCookieOverload(cookies);
  const summary = generateTrackingSummary(trackers, suspicious, overload);

  return {
    trackers,
    suspicious,
    overload,
    summary
  };
}

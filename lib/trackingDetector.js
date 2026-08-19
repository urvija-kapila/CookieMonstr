// Tracking detector: identifies third-party trackers with categorization and confidence scoring

// Tracker database with categories and risk levels
const TRACKER_DATABASE = {
  analytics: {
    category: 'Analytics & Measurement',
    risk: 'MEDIUM',
    icon: '📊',
    description: 'Collects data about user behavior to analyze site performance',
    trackers: [
      'google-analytics.com',
      'analytics.google.com',
      'googletagmanager.com',
      'chartbeat.net',
      'amplitude.com',
      'mixpanel.com',
      'heap.io',
      'fullstory.com'
    ]
  },
  advertising: {
    category: 'Advertising & Retargeting',
    risk: 'HIGH',
    icon: '📢',
    description: 'Tracks your activity to show targeted ads across the web',
    trackers: [
      'doubleclick.net',
      'google.com',
      'ads.twitter.com',
      'twitter.com',
      'criteo.com',
      'adroll.com',
      'facebook.com',
      'fbcdn.net',
      'pinterest.com',
      'snapchat.com'
    ]
  },
  social: {
    category: 'Social Media Integration',
    risk: 'HIGH',
    icon: '👥',
    description: 'Social networks track you across websites for profiling',
    trackers: [
      'facebook.com',
      'fbcdn.net',
      'twitter.com',
      'ads.twitter.com',
      'linkedin.com',
      'reddit.com',
      'instagram.com',
      'tiktok.com'
    ]
  },
  performance: {
    category: 'Performance & Error Monitoring',
    risk: 'LOW',
    icon: '⚡',
    description: 'Monitors site performance and errors for developers',
    trackers: [
      'sentry.io',
      'datadog.com',
      'newrelic.com',
      'loggly.com',
      'raygun.io',
      'bugsnag.com'
    ]
  },
  marketing: {
    category: 'Marketing & CRM',
    risk: 'HIGH',
    icon: '💼',
    description: 'Collects data for marketing automation and email campaigns',
    trackers: [
      'hubspot.com',
      'mailchimp.com',
      'klaviyo.com',
      'munchkin.marketo.net',
      'intercom.io',
      'segment.com',
      'freshmarketer.com'
    ]
  },
  engagement: {
    category: 'User Engagement & Heatmaps',
    risk: 'MEDIUM',
    icon: '🔥',
    description: 'Records user interactions like clicks, scrolls, and form fills',
    trackers: ['hotjar.com', 'userreplay.com', 'crazy-egg.com', 'inspectlet.com']
  }
};

/**
 * Get tracker category and info by domain
 */
function getTrackerInfo(domain) {
  for (const [categoryKey, categoryData] of Object.entries(TRACKER_DATABASE)) {
    const found = categoryData.trackers.some((tracker) => domain.includes(tracker));
    if (found) {
      return {
        categoryKey,
        ...categoryData,
        confidence: calculateConfidence(domain)
      };
    }
  }
  return null;
}

/**
 * Calculate confidence score for a tracker detection (0-100)
 */
function calculateConfidence(domain) {
  // Exact match = high confidence
  if (domain.split('.').length === 2) {
    return 95;
  }
  // Subdomain of known tracker = high confidence
  if (domain.includes('analytics') || domain.includes('tracking') || domain.includes('pixel')) {
    return 85;
  }
  // Partial match = medium confidence
  return 75;
}

/**
 * Detect if a cookie is from a known third-party tracker
 */
export function detectThirdPartyTrackers(cookies, currentDomain) {
  const trackerCookies = [];

  cookies.forEach((cookie) => {
    const trackerInfo = getTrackerInfo(cookie.domain);

    if (trackerInfo) {
      trackerCookies.push({
        ...cookie,
        ...trackerInfo,
        trackingType: 'Third-Party Tracker',
        severity: trackerInfo.risk
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
        confidence: 70,
        category: 'Suspicious Pattern',
        icon: '⚠️',
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
      confidence: 90,
      message: `Page has ${cookies.length} cookies, which is above recommended threshold of ${threshold}.`,
      explanation:
        'A high number of cookies can indicate tracking abuse, poor site hygiene, or bloated third-party integrations.',
      category: 'Cookie Overload',
      icon: '🍪'
    };
  }

  return null;
}

/**
 * Categorize cookies by purpose
 */
export function categorizeCookies(cookies) {
  const categories = {
    essential: [],
    analytics: [],
    advertising: [],
    social: [],
    performance: [],
    unknown: []
  };

  const essentialKeywords = [
    'session',
    'csrf',
    'auth',
    'login',
    'csrf_token',
    'secure',
    'httponly'
  ];
  const analyticsKeywords = ['ga_', '_gid', '_ga', 'analytics'];
  const advertisingKeywords = ['doubleclick', 'google_ads', 'fbp', 'rdt_id'];
  const socialKeywords = ['facebook', 'twitter', 'linkedin', 'instagram', 'tiktok'];

  cookies.forEach((cookie) => {
    const nameLower = cookie.name.toLowerCase();

    if (essentialKeywords.some((kw) => nameLower.includes(kw))) {
      categories.essential.push(cookie);
    } else if (analyticsKeywords.some((kw) => nameLower.includes(kw))) {
      categories.analytics.push(cookie);
    } else if (advertisingKeywords.some((kw) => nameLower.includes(kw))) {
      categories.advertising.push(cookie);
    } else if (socialKeywords.some((kw) => nameLower.includes(kw))) {
      categories.social.push(cookie);
    } else if (
      cookie.domain.includes('sentry') ||
      cookie.domain.includes('datadog') ||
      cookie.domain.includes('newrelic')
    ) {
      categories.performance.push(cookie);
    } else {
      categories.unknown.push(cookie);
    }
  });

  return categories;
}

/**
 * Generate tracking summary from all findings
 */
export function generateTrackingSummary(trackers, suspicious, overload, cookies) {
  const categories = categorizeCookies(cookies);

  return {
    totalCookies: cookies.length,
    totalTrackers: trackers.length,
    totalSuspicious: suspicious.length,
    cookieOverload: overload ? true : false,
    overloadMessage: overload ? overload.message : null,
    riskLevel: getRiskLevel(trackers.length, suspicious.length, overload),
    byCategory: {
      essential: categories.essential.length,
      analytics: categories.analytics.length,
      advertising: categories.advertising.length,
      social: categories.social.length,
      performance: categories.performance.length,
      unknown: categories.unknown.length
    }
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
  const summary = generateTrackingSummary(trackers, suspicious, overload, cookies);

  return {
    trackers,
    suspicious,
    overload,
    summary
  };
}

/**
 * Export tracker database for whitelist/blacklist management
 */
export function getTrackerDatabase() {
  return TRACKER_DATABASE;
}


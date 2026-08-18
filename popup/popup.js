// ============================================================
// Global State
// ============================================================

let auditResults = {
  cookies: [],
  storage: {},
  tracking: {}
};

// ============================================================
// Tab Switching
// ============================================================

document.querySelectorAll('.tab-button').forEach((button) => {
  button.addEventListener('click', () => {
    const tabName = button.getAttribute('data-tab');

    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach((tab) => {
      tab.classList.remove('active');
    });

    // Deactivate all buttons
    document.querySelectorAll('.tab-button').forEach((btn) => {
      btn.classList.remove('active');
    });

    // Show active tab
    document.getElementById(`${tabName}-tab`).classList.add('active');
    button.classList.add('active');
  });
});

// ============================================================
// Export Feature
// ============================================================

function exportReport() {
  const report = {
    timestamp: new Date().toISOString(),
    url: auditResults.url,
    cookies: {
      total: auditResults.cookies.length,
      findings: auditResults.cookies
    },
    storage: {
      items: auditResults.storage
    },
    tracking: {
      summary: auditResults.tracking.summary,
      trackers: auditResults.tracking.trackers,
      suspicious: auditResults.tracking.suspicious,
      overload: auditResults.tracking.overload
    }
  };

  const reportJSON = JSON.stringify(report, null, 2);
  const blob = new Blob([reportJSON], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  // Create download link
  const a = document.createElement('a');
  a.href = url;
  a.download = `security-audit-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  console.log('Report exported:', report);
}

document.getElementById('export-button').addEventListener('click', exportReport);

// ============================================================
// Utility: Get Severity Icon
// ============================================================

function getSeverityIcon(severity) {
  switch (severity) {
    case 'CRITICAL':
      return '🔴';
    case 'HIGH':
      return '🟠';
    case 'MEDIUM':
      return '🟡';
    case 'LOW':
      return '🟢';
    case 'INFO':
      return '🔵';
    case 'SAFE':
      return '✅';
    default:
      return '⚪';
  }
}

// ============================================================
// Cookie Audit
// ============================================================

function renderCookieAudit(response) {
  if (!response || !response.cookies) {
    document.getElementById('cookie-results').innerHTML =
      '<div class="empty-state"><p>No cookies found.</p></div>';
    return;
  }

  auditResults.cookies = response.cookies;
  const summary = response.summary;

  const summaryHTML = `
    <h3>Security Summary</h3>
    <p>Cookies Audited: ${summary.total}</p>
    <p>🔴 Critical: ${summary.critical}</p>
    <p>🟠 High: ${summary.high}</p>
    <p>🟡 Medium: ${summary.medium}</p>
    <p>🟢 Low: ${summary.low}</p>
    <p>✅ Safe: ${summary.safe}</p>
  `;

  document.getElementById('cookie-summary').innerHTML = summaryHTML;

  const cookiesHTML = response.cookies
    .map(
      (cookie) => `
      <div class="cookie-card">
        <h3>${getSeverityIcon(cookie.severity)} ${cookie.name}</h3>
        <p><strong>Domain:</strong> ${cookie.domain}</p>
        <p><strong>Risk Score:</strong> ${cookie.riskScore} | <strong>Level:</strong> ${cookie.riskLevel}</p>

        <ul>
          ${
            cookie.findings.length === 0
              ? `<li>✅ No security issues found.</li>`
              : cookie.findings
                  .map(
                    (finding) => `
                <li>
                  <strong>${getSeverityIcon(finding.severity)} ${finding.severity}: ${finding.title}</strong><br>
                  ${finding.explanation}<br><br>
                  <strong>Recommendation:</strong> ${finding.fix}
                </li>
              `
                  )
                  .join('')
          }
        </ul>
      </div>
    `
    )
    .join('');

  document.getElementById('cookie-results').innerHTML = cookiesHTML;
}

// ============================================================
// Storage Audit
// ============================================================

function renderStorageAudit(response) {
  if (response && response.error) {
    document.getElementById('storage-results').innerHTML =
      `<div class="empty-state"><p>⚠️ Could not access storage: ${response.error}</p></div>`;
    return;
  }

  const localStorageData = response.localStorage || {};
  const sessionStorageData = response.sessionStorage || {};

  auditResults.storage = {
    localStorage: localStorageData,
    sessionStorage: sessionStorageData
  };

  const totalItems = Object.keys(localStorageData).length + Object.keys(sessionStorageData).length;

  if (totalItems === 0) {
    document.getElementById('storage-summary').innerHTML =
      '<h3>Storage Summary</h3><p>No localStorage or sessionStorage items found.</p>';
    document.getElementById('storage-results').innerHTML =
      '<div class="empty-state"><p>✅ No storage items detected.</p></div>';
    return;
  }

  // Basic suspicious pattern detection
  const suspiciousItems = [];
  const sensitiveKeywords = [
    'api_key',
    'apikey',
    'secret',
    'token',
    'password',
    'passwd',
    'auth',
    'jwt',
    'bearer',
    'session',
    'sid'
  ];

  Object.entries(localStorageData).forEach(([key, value]) => {
    const isSuspicious = sensitiveKeywords.some((keyword) =>
      key.toLowerCase().includes(keyword)
    );

    if (isSuspicious) {
      suspiciousItems.push({
        key,
        value: value.length > 50 ? value.substring(0, 50) + '...' : value,
        storageType: 'localStorage',
        severity: 'HIGH'
      });
    }
  });

  Object.entries(sessionStorageData).forEach(([key, value]) => {
    const isSuspicious = sensitiveKeywords.some((keyword) =>
      key.toLowerCase().includes(keyword)
    );

    if (isSuspicious) {
      suspiciousItems.push({
        key,
        value: value.length > 50 ? value.substring(0, 50) + '...' : value,
        storageType: 'sessionStorage',
        severity: 'HIGH'
      });
    }
  });

  // Render storage summary
  const summarySuspicious = suspiciousItems.length;
  const summaryHTML = `
    <h3>Storage Summary</h3>
    <p>localStorage items: ${Object.keys(localStorageData).length}</p>
    <p>sessionStorage items: ${Object.keys(sessionStorageData).length}</p>
    <p>🔴 Suspicious items: ${summarySuspicious}</p>
  `;

  document.getElementById('storage-summary').innerHTML = summaryHTML;

  // Render storage items
  if (suspiciousItems.length === 0) {
    document.getElementById('storage-results').innerHTML =
      '<div class="empty-state"><p>✅ No obviously sensitive data detected in storage.</p></div>';
    return;
  }

  const storageHTML = suspiciousItems
    .map(
      (item) => `
      <div class="storage-item-card">
        <h3>${getSeverityIcon(item.severity)} ${item.key}</h3>
        <p><strong>Storage Type:</strong> ${item.storageType}</p>
        <p><strong>Value:</strong> <code>${item.value}</code></p>
        <p>⚠️ This key name suggests sensitive data. Review and consider moving to httpOnly cookies or server-side storage.</p>
      </div>
    `
    )
    .join('');

  document.getElementById('storage-results').innerHTML = storageHTML;
}

// ============================================================
// Tracking Detection
// ============================================================

function renderTrackingAudit(cookies) {
  if (!cookies || cookies.length === 0) {
    document.getElementById('tracking-results').innerHTML =
      '<div class="empty-state"><p>No cookies found for tracking analysis.</p></div>';
    return;
  }

  // Simple inline tracking detection (full version would import trackingDetector.js)
  const KNOWN_TRACKERS = [
    'google-analytics.com', 'analytics.google.com', 'googletagmanager.com',
    'doubleclick.net', 'facebook.com', 'fbcdn.net', 'ads.twitter.com',
    'linkedin.com', 'criteo.com', 'hotjar.com', 'mixpanel.com',
    'amplitude.com', 'segment.com', 'sentry.io', 'datadog.com'
  ];

  const trackerCookies = [];
  const suspiciousCookies = [];
  const randomPattern = /^[a-z0-9]{16,}$|_[a-z0-9]{20,}|uuid|tracking|beacon|pixel/i;

  cookies.forEach((cookie) => {
    // Detect known trackers
    const isTracker = KNOWN_TRACKERS.some((tracker) =>
      cookie.domain.includes(tracker)
    );

    if (isTracker) {
      trackerCookies.push({
        ...cookie,
        trackingType: 'Third-Party Tracker'
      });
    }

    // Detect suspicious naming
    const hasRandomName = randomPattern.test(cookie.name);
    const lacksSecurity = !cookie.httpOnly && !cookie.secure;

    if (hasRandomName && lacksSecurity) {
      suspiciousCookies.push({
        ...cookie,
        trackingType: 'Suspicious Pattern'
      });
    }
  });

  const cookieOverload = cookies.length > 20;

  auditResults.tracking = {
    trackers: trackerCookies,
    suspicious: suspiciousCookies,
    cookieOverload: cookieOverload,
    summary: {
      totalTrackers: trackerCookies.length,
      totalSuspicious: suspiciousCookies.length,
      cookieCount: cookies.length,
      riskLevel:
        trackerCookies.length + suspiciousCookies.length > 5
          ? 'HIGH'
          : trackerCookies.length + suspiciousCookies.length > 2
          ? 'MEDIUM'
          : 'LOW'
    }
  };

  // Render summary
  const summaryHTML = `
    <h3>Tracking Analysis</h3>
    <p>Third-Party Trackers: ${trackerCookies.length}</p>
    <p>Suspicious Patterns: ${suspiciousCookies.length}</p>
    <p>Total Cookies: ${cookies.length}</p>
    <p>Risk Level: ${auditResults.tracking.summary.riskLevel}</p>
    ${cookieOverload ? `<p>⚠️ Cookie Overload: Page has ${cookies.length} cookies (threshold: 20)</p>` : ''}
  `;

  document.getElementById('tracking-summary').innerHTML = summaryHTML;

  // Render findings
  const allFindings = [...trackerCookies, ...suspiciousCookies];

  if (allFindings.length === 0) {
    document.getElementById('tracking-results').innerHTML =
      '<div class="empty-state"><p>✅ No tracking cookies detected.</p></div>';
    return;
  }

  const trackingHTML = allFindings
    .map(
      (cookie) => `
      <div class="cookie-card">
        <h3>${getSeverityIcon('HIGH')} ${cookie.name}</h3>
        <p><strong>Domain:</strong> ${cookie.domain}</p>
        <p><strong>Type:</strong> ${cookie.trackingType}</p>
        <p><strong>Tracking Risk:</strong> This cookie appears to be used for cross-site tracking or analytics.</p>
        <ul>
          <li><strong>Why it matters:</strong> Tracking cookies can monitor your browsing habits across multiple sites, enabling behavioral profiling and targeted advertising.</li>
          <li><strong>Recommendation:</strong> Consider using privacy-focused browsers or browser extensions to block third-party trackers. Review your privacy settings on websites you visit.</li>
        </ul>
      </div>
    `
    )
    .join('');

  document.getElementById('tracking-results').innerHTML = trackingHTML;
}

// ============================================================
// Main Audit Flow
// ============================================================

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const activeTab = tabs[0];
  const url = activeTab.url;

  auditResults.url = url;
  console.log('Active tab URL:', url);

  // Request cookies from service worker
  chrome.runtime.sendMessage({ action: 'GET_COOKIES', url }, (response) => {
    console.log('Popup got cookie response:', response);
    renderCookieAudit(response);

    // Once cookies are loaded, analyze for tracking
    if (response && response.cookies) {
      renderTrackingAudit(response.cookies);
    }
  });

  // Request storage from content script
  chrome.tabs.sendMessage(activeTab.id, { action: 'GET_STORAGE' }, (response) => {
    console.log('Popup got storage response:', response);
    renderStorageAudit(response);
  });
});



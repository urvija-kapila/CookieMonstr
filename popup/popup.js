// ============================================================
// COOKIEMONSTR - POPUP LOGIC
// Phase 4: Polish & Production - Robust Error Handling
// ============================================================

import { buildExportObject } from '../lib/export.js';

let auditResults = {
  cookies: [],
  storage: {},
  tracking: {},
  url: ''
};

// ============================================================
// UTILITY: Display Error Messages
// ============================================================

function showError(message, timeout = 5000) {
  const errorContainer = document.getElementById('error-container');
  errorContainer.textContent = `⚠️ ${message}`;
  errorContainer.classList.remove('hidden');

  if (timeout > 0) {
    setTimeout(() => {
      errorContainer.classList.add('hidden');
    }, timeout);
  }
}

function hideError() {
  document.getElementById('error-container').classList.add('hidden');
}

// ============================================================
// UTILITY: Loading Indicator
// ============================================================

function showLoading(show = true) {
  const indicator = document.getElementById('loading-indicator');
  if (show) {
    indicator.classList.remove('hidden');
  } else {
    indicator.classList.add('hidden');
  }
}

// ============================================================
// UTILITY: Get Severity Icon
// ============================================================

function getSeverityIcon(severity) {
  const icons = {
    CRITICAL: '🔴',
    HIGH: '🟠',
    MEDIUM: '🟡',
    LOW: '🟢',
    INFO: '🔵',
    SAFE: '✅'
  };
  return icons[severity] || '⚪';
}

function refreshBadge(url, tabId) {
  chrome.runtime.sendMessage({ action: 'UPDATE_BADGE', url, tabId }, (response) => {
    if (chrome.runtime.lastError) {
      console.warn('Could not refresh toolbar badge:', chrome.runtime.lastError);
      return;
    }

    if (response?.error) {
      console.warn('Toolbar badge update failed:', response.error);
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const activeTab = tabs?.[0];
    if (activeTab?.url && activeTab.id !== undefined) {
      refreshBadge(activeTab.url, activeTab.id);
    }
  });
});

// ============================================================
// TAB SWITCHING
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
      btn.setAttribute('aria-selected', 'false');
    });

    // Show active tab
    const activeTab = document.getElementById(`${tabName}-tab`);
    const activeBtn = button;

    if (activeTab && activeBtn) {
      activeTab.classList.add('active');
      activeBtn.classList.add('active');
      activeBtn.setAttribute('aria-selected', 'true');
    }
  });
});

// ============================================================
// EXPORT FEATURE WITH ERROR HANDLING
// ============================================================

function showExportModal() {
  if (!auditResults.url) {
    showError('No audit data available to export');
    return;
  }

  document.getElementById('export-modal').classList.remove('hidden');
}

function hideExportModal() {
  document.getElementById('export-modal').classList.add('hidden');
}

function exportReport(redact) {
  try {
    if (!auditResults.url) {
      showError('No audit data available to export');
      return;
    }

    const report = buildExportObject(auditResults, { redact });

    const reportJSON = JSON.stringify(report, null, 2);
    const blob = new Blob([reportJSON], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    // Create and trigger download
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-audit-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    // Clean up
    setTimeout(() => URL.revokeObjectURL(url), 100);

    console.log('✓ Report exported successfully');
    hideExportModal();
  } catch (error) {
    console.error('Export error:', error);
    showError('Failed to export report. See console for details.');
  }
}

// ============================================================
// RENDER COOKIE AUDIT
// ============================================================

function renderCookieAudit(response) {
  try {
    if (!response) {
      showError('No response from cookie audit');
      return;
    }

    if (!response.cookies || response.cookies.length === 0) {
      document.getElementById('cookie-summary').innerHTML =
        '<h3>Security Summary</h3><p>No cookies found on this page.</p>';
      document.getElementById('cookie-results').innerHTML =
        '<div class="empty-state"><p>✅ This page uses no cookies.</p></div>';
      return;
    }

    auditResults.cookies = response.cookies;
    const summary = response.summary || {};

    const summaryHTML = `
      <h3>Security Summary</h3>
      <p>Cookies Audited: <strong>${summary.total || 0}</strong></p>
      <p>🔴 Critical: <strong>${summary.critical || 0}</strong></p>
      <p>🟠 High: <strong>${summary.high || 0}</strong></p>
      <p>🟡 Medium: <strong>${summary.medium || 0}</strong></p>
      <p>🟢 Low: <strong>${summary.low || 0}</strong></p>
      <p>✅ Safe: <strong>${summary.safe || 0}</strong></p>
    `;

    document.getElementById('cookie-summary').innerHTML = summaryHTML;

    const cookiesHTML = response.cookies
      .map(
        (cookie) => `
        <div class="cookie-card">
          <h3>${getSeverityIcon(cookie.severity)} ${escapeHtml(cookie.name)}</h3>
          <p><strong>Domain:</strong> ${escapeHtml(cookie.domain)}</p>
          <p><strong>Risk Score:</strong> ${cookie.riskScore} | <strong>Level:</strong> ${cookie.riskLevel}</p>
          <ul>
            ${
              !cookie.findings || cookie.findings.length === 0
                ? '<li>✅ No security issues found.</li>'
                : cookie.findings
                    .map(
                      (finding) => `
                  <li>
                    <strong>${getSeverityIcon(finding.severity)} ${finding.severity}: ${escapeHtml(finding.title)}</strong><br>
                    ${escapeHtml(finding.explanation)}<br><br>
                    <strong>Recommendation:</strong> ${escapeHtml(finding.fix)}
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
  } catch (error) {
    console.error('Cookie render error:', error);
    showError('Error rendering cookie audit results');
  }
}

// ============================================================
// RENDER STORAGE AUDIT
// ============================================================

function renderStorageAudit(response) {
  try {
    if (!response) {
      showError('No response from storage audit');
      return;
    }

    if (response.error) {
      document.getElementById('storage-results').innerHTML =
        `<div class="empty-state"><p>⚠️ Could not access storage: ${escapeHtml(response.error)}</p></div>`;
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
        '<h3>Storage Summary</h3><p>No localStorage or sessionStorage items.</p>';
      document.getElementById('storage-results').innerHTML =
        '<div class="empty-state"><p>✅ No storage items detected.</p></div>';
      return;
    }

    // Detect suspicious storage items
    const suspiciousItems = [];
    const sensitiveKeywords = [
      'api_key', 'apikey', 'secret', 'token', 'password',
      'passwd', 'auth', 'jwt', 'bearer', 'session', 'sid'
    ];

    Object.entries(localStorageData).forEach(([key, value]) => {
      const isSuspicious = sensitiveKeywords.some((kw) =>
        key.toLowerCase().includes(kw)
      );

      if (isSuspicious && typeof value === 'string') {
        suspiciousItems.push({
          key,
          value: value.length > 50 ? value.substring(0, 50) + '...' : value,
          storageType: 'localStorage',
          severity: 'HIGH'
        });
      }
    });

    Object.entries(sessionStorageData).forEach(([key, value]) => {
      const isSuspicious = sensitiveKeywords.some((kw) =>
        key.toLowerCase().includes(kw)
      );

      if (isSuspicious && typeof value === 'string') {
        suspiciousItems.push({
          key,
          value: value.length > 50 ? value.substring(0, 50) + '...' : value,
          storageType: 'sessionStorage',
          severity: 'HIGH'
        });
      }
    });

    // Render summary
    const summaryHTML = `
      <h3>Storage Summary</h3>
      <p>localStorage items: <strong>${Object.keys(localStorageData).length}</strong></p>
      <p>sessionStorage items: <strong>${Object.keys(sessionStorageData).length}</strong></p>
      <p>🔴 Suspicious items: <strong>${suspiciousItems.length}</strong></p>
    `;

    document.getElementById('storage-summary').innerHTML = summaryHTML;

    // Render results
    if (suspiciousItems.length === 0) {
      document.getElementById('storage-results').innerHTML =
        '<div class="empty-state"><p>✅ No obviously sensitive data detected in storage.</p></div>';
      return;
    }

    const storageHTML = suspiciousItems
      .map(
        (item) => `
        <div class="storage-item-card">
          <h3>${getSeverityIcon(item.severity)} ${escapeHtml(item.key)}</h3>
          <p><strong>Storage Type:</strong> ${item.storageType}</p>
          <p><strong>Value:</strong> <code>${escapeHtml(item.value)}</code></p>
          <p>⚠️ This key suggests sensitive data. Consider moving to httpOnly cookies or server-side storage.</p>
        </div>
      `
      )
      .join('');

    document.getElementById('storage-results').innerHTML = storageHTML;
  } catch (error) {
    console.error('Storage render error:', error);
    showError('Error rendering storage audit results');
  }
}

// ============================================================
// RENDER TRACKING AUDIT
// ============================================================

function renderTrackingAudit(cookies) {
  try {
    if (!cookies || cookies.length === 0) {
      document.getElementById('tracking-results').innerHTML =
        '<div class="empty-state"><p>No cookies found for tracking analysis.</p></div>';
      return;
    }

    const KNOWN_TRACKERS = [
      'google-analytics.com', 'analytics.google.com', 'googletagmanager.com',
      'doubleclick.net', 'facebook.com', 'fbcdn.net', 'ads.twitter.com',
      'linkedin.com', 'criteo.com', 'hotjar.com', 'mixpanel.com',
      'amplitude.com', 'segment.com', 'sentry.io', 'datadog.com',
      'intercom.io', 'zendesk.com', 'drift.com'
    ];

    const trackerCookies = [];
    const suspiciousCookies = [];
    const randomPattern = /^[a-z0-9]{16,}$|_[a-z0-9]{20,}|uuid|tracking|beacon|pixel/i;

    cookies.forEach((cookie) => {
      // Check for known trackers
      const isTracker = KNOWN_TRACKERS.some((tracker) =>
        (cookie.domain || '').includes(tracker)
      );

      if (isTracker) {
        trackerCookies.push({
          ...cookie,
          trackingType: 'Third-Party Tracker'
        });
      }

      // Check for suspicious patterns
      const hasRandomName = randomPattern.test(cookie.name || '');
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
      <p>Third-Party Trackers: <strong>${trackerCookies.length}</strong></p>
      <p>Suspicious Patterns: <strong>${suspiciousCookies.length}</strong></p>
      <p>Total Cookies: <strong>${cookies.length}</strong></p>
      <p>Risk Level: <strong>${auditResults.tracking.summary.riskLevel}</strong></p>
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
          <h3>${getSeverityIcon('HIGH')} ${escapeHtml(cookie.name)}</h3>
          <p><strong>Domain:</strong> ${escapeHtml(cookie.domain)}</p>
          <p><strong>Type:</strong> ${cookie.trackingType}</p>
          <ul>
            <li><strong>Why it matters:</strong> Tracking cookies monitor your browsing habits across sites, enabling behavioral profiling and targeted advertising.</li>
            <li><strong>Recommendation:</strong> Use privacy-focused browsers or extensions to limit third-party trackers. Review website privacy settings.</li>
          </ul>
        </div>
      `
      )
      .join('');

    document.getElementById('tracking-results').innerHTML = trackingHTML;
  } catch (error) {
    console.error('Tracking render error:', error);
    showError('Error rendering tracking audit results');
  }
}

// ============================================================
// UTILITY: Escape HTML to prevent XSS
// ============================================================

function escapeHtml(unsafe) {
  if (typeof unsafe !== 'string') return '';
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ============================================================
// MAIN AUDIT FLOW WITH ERROR HANDLING
// ============================================================

document.getElementById('export-button').addEventListener('click', showExportModal);
document.getElementById('cancel-export-button').addEventListener('click', hideExportModal);
document.getElementById('download-export-button').addEventListener('click', () => {
  const selectedMode = document.querySelector('input[name="export-mode"]:checked')?.value;
  exportReport(selectedMode !== 'full');
});

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  try {
    if (!tabs || tabs.length === 0) {
      showError('Could not access active tab');
      showLoading(false);
      return;
    }

    const activeTab = tabs[0];
    const url = activeTab.url;

    if (!url) {
      showError('Could not determine page URL');
      showLoading(false);
      return;
    }

    // Don't audit chrome:// or extension pages
    if (url.startsWith('chrome://') || url.startsWith('moz-extension://')) {
      document.getElementById('cookie-results').innerHTML =
        '<div class="empty-state"><p>⚠️ Cannot audit browser extension or system pages.</p></div>';
      document.getElementById('storage-results').innerHTML =
        '<div class="empty-state"><p>⚠️ Cannot audit browser extension or system pages.</p></div>';
      document.getElementById('tracking-results').innerHTML =
        '<div class="empty-state"><p>⚠️ Cannot audit browser extension or system pages.</p></div>';
      showLoading(false);
      return;
    }

    auditResults.url = url;

    // Request cookies from service worker
    chrome.runtime.sendMessage({ action: 'GET_COOKIES', url }, (response) => {
      try {
        if (chrome.runtime.lastError) {
          console.warn('Service worker error:', chrome.runtime.lastError);
          showError('Could not communicate with service worker');
          return;
        }
        renderCookieAudit(response);
        if (response && response.cookies) {
          renderTrackingAudit(response.cookies);
        }
      } catch (error) {
        console.error('Error handling cookie response:', error);
        showError('Error processing cookie audit');
      }
    });

    // Request storage from content script
    chrome.tabs.sendMessage(activeTab.id, { action: 'GET_STORAGE' }, (response) => {
      try {
        if (chrome.runtime.lastError) {
          // Storage might not be accessible on some pages
          console.warn('Content script error:', chrome.runtime.lastError);
          document.getElementById('storage-results').innerHTML =
            '<div class="empty-state"><p>⚠️ Storage audit unavailable on this page (CSP restriction).</p></div>';
          return;
        }
        renderStorageAudit(response);
      } catch (error) {
        console.error('Error handling storage response:', error);
        showError('Error processing storage audit');
      } finally {
        showLoading(false);
      }
    });
  } catch (error) {
    console.error('Fatal error in popup:', error);
    showError('An unexpected error occurred. See console for details.');
    showLoading(false);
  }
});

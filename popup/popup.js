// ============================================================
// Global State
// ============================================================

let auditResults = {
  cookies: [],
  storage: {},
  tracking: {}
};

let preferences = {};
let whitelist = [];

// ============================================================
// Settings Management
// ============================================================

async function loadSettingsPanel() {
  preferences = await chrome.storage.local.get('cmPreferences').then((result) => {
    return result.cmPreferences || {};
  });

  whitelist = await chrome.storage.local.get('cmWhitelist').then((result) => {
    return result.cmWhitelist || [];
  });

  const stats = await chrome.storage.local.get('cmStats').then((result) => {
    return result.cmStats || { auditsRun: 0 };
  });

  // Populate preference checkboxes
  document.getElementById('pref-tracking').checked = preferences.enableTracking !== false;
  document.getElementById('pref-storage').checked = preferences.enableStorage !== false;
  document.getElementById('pref-privacy-mode').checked = preferences.privacyMode === true;

  // Populate whitelist
  const whitelistContainer = document.getElementById('whitelist-container');
  if (whitelist.length === 0) {
    whitelistContainer.innerHTML =
      '<p style="color: #a0a0a0; font-size: 11px;">No whitelisted trackers yet.</p>';
  } else {
    whitelistContainer.innerHTML = whitelist
      .map(
        (item) => `
      <div class="whitelist-item">
        <span class="whitelist-item-domain">${item.domain}</span>
        <button class="whitelist-item-remove" data-domain="${item.domain}">Remove</button>
      </div>
    `
      )
      .join('');

    // Add remove button listeners
    document.querySelectorAll('.whitelist-item-remove').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const domain = btn.getAttribute('data-domain');
        whitelist = whitelist.filter((item) => item.domain !== domain);
        await chrome.storage.local.set({ cmWhitelist: whitelist });
        loadSettingsPanel();
      });
    });
  }

  // Populate statistics
  const statsDisplay = document.getElementById('stats-display');
  statsDisplay.innerHTML = `
    <div class="stats-line">Audits run: <strong>${stats.auditsRun}</strong></div>
    ${stats.lastAudit ? `<div class="stats-line">Last audit: <strong>${new Date(stats.lastAudit).toLocaleString()}</strong></div>` : ''}
  `;

  // Add event listeners for preference changes
  document.getElementById('pref-tracking').addEventListener('change', (e) => {
    preferences.enableTracking = e.target.checked;
    chrome.storage.local.set({ cmPreferences: preferences });
  });

  document.getElementById('pref-storage').addEventListener('change', (e) => {
    preferences.enableStorage = e.target.checked;
    chrome.storage.local.set({ cmPreferences: preferences });
  });

  document.getElementById('pref-privacy-mode').addEventListener('change', (e) => {
    preferences.privacyMode = e.target.checked;
    chrome.storage.local.set({ cmPreferences: preferences });
  });

  document.getElementById('export-settings-btn').addEventListener('click', async () => {
    const backup = {
      preferences,
      whitelist,
      exportedAt: new Date().toISOString()
    };

    const json = JSON.stringify(backup, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `cookiemonstr-settings-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  document.getElementById('clear-data-btn').addEventListener('click', async () => {
    if (confirm('Are you sure? This will clear all settings, whitelist, and statistics.')) {
      await chrome.storage.local.clear();
      location.reload();
    }
  });
}

// ============================================================
// Tab Switching
// ============================================================

document.querySelectorAll('.tab-button').forEach((button) => {
  button.addEventListener('click', async () => {
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

    // Load settings panel when settings tab is opened
    if (tabName === 'settings') {
      await loadSettingsPanel();
    }
  });
});

// ============================================================
// Export Feature
// ============================================================

function exportReport() {
  const report = {
    timestamp: new Date().toISOString(),
    url: auditResults.url,
    privacyMode: preferences.privacyMode,
    cookies: {
      total: auditResults.cookies.length,
      findings: auditResults.cookies.map((c) => ({
        ...c,
        domain: c.domain,
        name: preferences.privacyMode ? '[REDACTED]' : c.name
      }))
    },
    storage: {
      items: preferences.privacyMode
        ? Object.keys(auditResults.storage).reduce((acc, type) => {
            acc[type] = Object.keys(auditResults.storage[type]).map((k) => ({
              key: '[REDACTED]',
              value: '[REDACTED]'
            }));
            return acc;
          }, {})
        : auditResults.storage
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
// Tracking Detection with Categorization
// ============================================================

function renderTrackingAudit(cookies) {
  if (!cookies || cookies.length === 0) {
    document.getElementById('tracking-results').innerHTML =
      '<div class="empty-state"><p>No cookies found for tracking analysis.</p></div>';
    return;
  }

  // Simple inline tracking detection with categorization
  const TRACKER_DATABASE = {
    analytics: {
      category: 'Analytics & Measurement',
      icon: '📊',
      domains: [
        'google-analytics.com',
        'analytics.google.com',
        'googletagmanager.com',
        'amplitude.com'
      ]
    },
    advertising: {
      category: 'Advertising & Retargeting',
      icon: '📢',
      domains: [
        'doubleclick.net',
        'criteo.com',
        'facebook.com',
        'fbcdn.net',
        'twitter.com',
        'ads.twitter.com'
      ]
    },
    social: {
      category: 'Social Media',
      icon: '👥',
      domains: ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com']
    },
    performance: {
      category: 'Performance Monitoring',
      icon: '⚡',
      domains: ['sentry.io', 'datadog.com', 'newrelic.com']
    }
  };

  const categorized = {
    analytics: [],
    advertising: [],
    social: [],
    performance: [],
    suspicious: []
  };

  const randomPattern = /^[a-z0-9]{16,}$|_[a-z0-9]{20,}|uuid|tracking|beacon|pixel/i;

  cookies.forEach((cookie) => {
    // Check known trackers
    let found = false;
    for (const [key, data] of Object.entries(TRACKER_DATABASE)) {
      if (data.domains.some((domain) => cookie.domain.includes(domain))) {
        categorized[key].push({ ...cookie, categoryData: data });
        found = true;
        break;
      }
    }

    // Check suspicious patterns
    if (
      !found &&
      randomPattern.test(cookie.name) &&
      !cookie.httpOnly &&
      !cookie.secure
    ) {
      categorized.suspicious.push(cookie);
    }
  });

  const totalTrackers =
    categorized.analytics.length +
    categorized.advertising.length +
    categorized.social.length +
    categorized.performance.length;

  // Render summary
  const summaryHTML = `
    <h3>Tracking Analysis</h3>
    <p>Total Trackers: ${totalTrackers}</p>
    <p>📊 Analytics: ${categorized.analytics.length}</p>
    <p>📢 Advertising: ${categorized.advertising.length}</p>
    <p>👥 Social Media: ${categorized.social.length}</p>
    <p>⚡ Performance: ${categorized.performance.length}</p>
    <p>⚠️ Suspicious: ${categorized.suspicious.length}</p>
  `;

  document.getElementById('tracking-summary').innerHTML = summaryHTML;

  // Render findings
  let trackingHTML = '';

  for (const [category, items] of Object.entries(categorized)) {
    if (items.length === 0) continue;

    const categoryLabel =
      category === 'suspicious'
        ? '⚠️ Suspicious Patterns'
        : items[0].categoryData?.category || category;

    trackingHTML += `<h4 style="margin-top: 12px; color: #7c6ef7; font-size: 12px;">${categoryLabel}</h4>`;

    trackingHTML += items
      .map(
        (cookie) => `
      <div class="cookie-card">
        <h3>${getSeverityIcon('HIGH')} ${cookie.name}</h3>
        <p><strong>Domain:</strong> ${cookie.domain}</p>
        <p>This cookie is used for ${category === 'suspicious' ? 'potentially suspicious' : category} tracking purposes.</p>
        <button class="whitelist-btn" data-domain="${cookie.domain}" style="margin-top: 8px; padding: 4px 8px; background-color: #7c6ef7; color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 11px;">✓ Trust this tracker</button>
      </div>
    `
      )
      .join('');
  }

  if (trackingHTML === '') {
    trackingHTML = '<div class="empty-state"><p>✅ No tracking cookies detected.</p></div>';
  }

  document.getElementById('tracking-results').innerHTML = trackingHTML;

  // Add whitelist button listeners
  document.querySelectorAll('.whitelist-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const domain = btn.getAttribute('data-domain');
      whitelist.push({ domain, reason: 'Trusted by user', addedAt: new Date().toISOString() });
      await chrome.storage.local.set({ cmWhitelist: whitelist });
      btn.textContent = '✓ Trusted';
      btn.disabled = true;
    });
  });

  auditResults.tracking = {
    trackers: categorized,
    summary: {
      totalTrackers,
      byCategory: categorized
    }
  };
}

// ============================================================
// Main Audit Flow
// ============================================================

async function initializePreferences() {
  preferences = await chrome.storage.local.get('cmPreferences').then((result) => {
    return result.cmPreferences || {};
  });

  whitelist = await chrome.storage.local.get('cmWhitelist').then((result) => {
    return result.cmWhitelist || [];
  });

  // Update statistics
  const stats = await chrome.storage.local.get('cmStats').then((result) => {
    return result.cmStats || { auditsRun: 0 };
  });

  stats.auditsRun++;
  stats.lastAudit = new Date().toISOString();
  await chrome.storage.local.set({ cmStats: stats });
}

chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
  const activeTab = tabs[0];
  const url = activeTab.url;

  await initializePreferences();

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




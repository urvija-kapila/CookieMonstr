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
    default:
      return '⚪';
  }
}

// ============================================================
// Cookie Audit
// ============================================================

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const activeTab = tabs[0];
  const url = activeTab.url;

  console.log('Active tab URL:', url);

  // Request cookies from service worker
  chrome.runtime.sendMessage({ action: 'GET_COOKIES', url }, (response) => {
    console.log('Popup got cookie response:', response);

    if (!response || !response.cookies) {
      document.getElementById('cookie-results').innerHTML =
        '<div class="empty-state"><p>No cookies found.</p></div>';
      return;
    }

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
  });

  // Request storage from content script
  chrome.tabs.sendMessage(activeTab.id, { action: 'GET_STORAGE' }, (response) => {
    console.log('Popup got storage response:', response);

    if (response && response.error) {
      document.getElementById('storage-results').innerHTML =
        `<div class="empty-state"><p>⚠️ Could not access storage: ${response.error}</p></div>`;
      return;
    }

    // Import storage audit functions (they're in the lib folder but we need to handle this in popup context)
    // For now, we'll handle storage rendering with basic checks
    const localStorageData = response.localStorage || {};
    const sessionStorageData = response.sessionStorage || {};

    const allItems = { ...localStorageData, ...sessionStorageData };
    const totalItems = Object.keys(localStorageData).length + Object.keys(sessionStorageData).length;

    if (totalItems === 0) {
      document.getElementById('storage-summary').innerHTML =
        '<h3>Storage Summary</h3><p>No localStorage or sessionStorage items found.</p>';
      document.getElementById('storage-results').innerHTML =
        '<div class="empty-state"><p>✅ No sensitive data detected in storage.</p></div>';
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

    Object.entries(allItems).forEach(([key, value]) => {
      const isSuspicious = sensitiveKeywords.some((keyword) =>
        key.toLowerCase().includes(keyword)
      );

      if (isSuspicious) {
        suspiciousItems.push({
          key,
          value: value.length > 50 ? value.substring(0, 50) + '...' : value,
          storageType: Object.keys(localStorageData).includes(key) ? 'localStorage' : 'sessionStorage',
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
  });
});


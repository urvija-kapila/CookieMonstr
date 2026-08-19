// ============================================================
// COOKIEMONSTR - SERVICE WORKER
// Background task orchestration for cookie auditing
// ============================================================

import { auditCookies } from "../lib/cookieAudit.js";
import { generateSummary } from "../lib/riskScore.js";

// ============================================================
// MESSAGE LISTENER - Cookie Audit Requests
// ============================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  try {
    if (!request || !request.action) {
      console.warn('[CookieMonstr] Invalid request received:', request);
      sendResponse({ error: 'Invalid request format' });
      return false;
    }

    if (request.action === 'GET_COOKIES') {
      handleCookieAudit(request, sendResponse);
      return true; // Keep channel open for async response
    }

    console.warn('[CookieMonstr] Unknown action:', request.action);
    sendResponse({ error: 'Unknown action' });
    return false;
  } catch (error) {
    console.error('[CookieMonstr] Unhandled error in message listener:', error);
    sendResponse({ error: 'Internal service worker error' });
    return false;
  }
});

// ============================================================
// Cookie Audit Handler
// ============================================================

function handleCookieAudit(request, sendResponse) {
  const url = request.url;

  if (!url || typeof url !== 'string') {
    console.warn('[CookieMonstr] Invalid URL provided:', url);
    sendResponse({ error: 'Invalid URL format' });
    return;
  }

  // Reject auditing of system/extension pages
  if (url.startsWith('chrome://') || url.startsWith('moz-extension://')) {
    console.log('[CookieMonstr] Skipping audit for restricted page:', url);
    sendResponse({
      cookies: [],
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        safe: 0
      },
      error: 'Cannot audit browser system or extension pages'
    });
    return;
  }

  try {
    chrome.cookies.getAll({ url }, (cookies) => {
      try {
        if (chrome.runtime.lastError) {
          console.error('[CookieMonstr] Chrome API error:', chrome.runtime.lastError);
          sendResponse({
            cookies: [],
            summary: null,
            error: `Chrome API error: ${chrome.runtime.lastError.message}`
          });
          return;
        }

        // Ensure cookies is an array
        if (!Array.isArray(cookies)) {
          cookies = [];
        }

        console.log(`[CookieMonstr] Retrieved ${cookies.length} cookies from ${url}`);

        // Audit the cookies
        const auditedCookies = auditCookies(cookies);
        const summary = generateSummary(auditedCookies);

        console.log('[CookieMonstr] Audit Summary:', summary);

        sendResponse({
          cookies: auditedCookies,
          summary,
          error: null
        });
      } catch (innerError) {
        console.error('[CookieMonstr] Error processing cookies:', innerError);
        sendResponse({
          cookies: [],
          summary: null,
          error: 'Error during cookie audit'
        });
      }
    });
  } catch (error) {
    console.error('[CookieMonstr] Error retrieving cookies:', error);
    sendResponse({
      cookies: [],
      summary: null,
      error: 'Failed to retrieve cookies'
    });
  }
}

// ============================================================
// Service Worker Lifecycle
// ============================================================

// Log when service worker is activated
console.log('[CookieMonstr] Service Worker initialized');

// Handle service worker unload (cleanup if needed)
self.addEventListener('unload', () => {
  console.log('[CookieMonstr] Service Worker unloading');
});

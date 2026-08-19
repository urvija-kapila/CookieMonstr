// Whitelist and preferences manager
// Stores user preferences and whitelisted trackers using chrome.storage API

const STORAGE_KEYS = {
  WHITELIST: 'cmWhitelist',
  PREFERENCES: 'cmPreferences',
  STATS: 'cmStats'
};

const DEFAULT_PREFERENCES = {
  enableTracking: true,
  enableStorage: true,
  enableExport: true,
  riskThreshold: 'MEDIUM', // Show only HIGH and CRITICAL by default
  ignoredTrackerCategories: [], // e.g., ['performance', 'analytics']
  privacyMode: false // Hide values in export for privacy
};

/**
 * Initialize storage with defaults
 */
export async function initializeStorage() {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS, (result) => {
      if (!result[STORAGE_KEYS.PREFERENCES]) {
        chrome.storage.local.set(
          {
            [STORAGE_KEYS.PREFERENCES]: DEFAULT_PREFERENCES,
            [STORAGE_KEYS.WHITELIST]: [],
            [STORAGE_KEYS.STATS]: { auditsRun: 0, lastAudit: null }
          },
          resolve
        );
      } else {
        resolve();
      }
    });
  });
}

/**
 * Get user preferences
 */
export async function getPreferences() {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.PREFERENCES, (result) => {
      resolve(result[STORAGE_KEYS.PREFERENCES] || DEFAULT_PREFERENCES);
    });
  });
}

/**
 * Update user preferences
 */
export async function updatePreferences(updates) {
  const current = await getPreferences();
  const updated = { ...current, ...updates };

  return new Promise((resolve) => {
    chrome.storage.local.set(
      { [STORAGE_KEYS.PREFERENCES]: updated },
      resolve
    );
  });
}

/**
 * Add domain to whitelist (trusted tracker)
 */
export async function whitelistDomain(domain, reason = '') {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.WHITELIST, (result) => {
      const whitelist = result[STORAGE_KEYS.WHITELIST] || [];

      // Check if already whitelisted
      if (!whitelist.find((item) => item.domain === domain)) {
        whitelist.push({
          domain,
          reason,
          addedAt: new Date().toISOString()
        });

        chrome.storage.local.set({ [STORAGE_KEYS.WHITELIST]: whitelist }, resolve);
      } else {
        resolve();
      }
    });
  });
}

/**
 * Remove domain from whitelist
 */
export async function removeFromWhitelist(domain) {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.WHITELIST, (result) => {
      const whitelist = result[STORAGE_KEYS.WHITELIST] || [];
      const filtered = whitelist.filter((item) => item.domain !== domain);

      chrome.storage.local.set({ [STORAGE_KEYS.WHITELIST]: filtered }, resolve);
    });
  });
}

/**
 * Get whitelist
 */
export async function getWhitelist() {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.WHITELIST, (result) => {
      resolve(result[STORAGE_KEYS.WHITELIST] || []);
    });
  });
}

/**
 * Check if domain is whitelisted
 */
export async function isWhitelisted(domain) {
  const whitelist = await getWhitelist();
  return whitelist.some((item) => domain.includes(item.domain));
}

/**
 * Get usage statistics
 */
export async function getStatistics() {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.STATS, (result) => {
      resolve(
        result[STORAGE_KEYS.STATS] || {
          auditsRun: 0,
          lastAudit: null
        }
      );
    });
  });
}

/**
 * Update statistics (called after each audit)
 */
export async function updateStatistics() {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.STATS, (result) => {
      const stats = result[STORAGE_KEYS.STATS] || { auditsRun: 0 };

      stats.auditsRun++;
      stats.lastAudit = new Date().toISOString();

      chrome.storage.local.set({ [STORAGE_KEYS.STATS]: stats }, resolve);
    });
  });
}

/**
 * Filter trackers based on whitelist and preferences
 */
export async function filterTrackers(trackers) {
  const whitelist = await getWhitelist();
  const preferences = await getPreferences();

  return trackers.filter((tracker) => {
    // Remove whitelisted domains
    const isWhitelisted = whitelist.some((item) => tracker.domain.includes(item.domain));
    if (isWhitelisted) return false;

    // Filter by ignored categories
    if (preferences.ignoredTrackerCategories.includes(tracker.categoryKey)) {
      return false;
    }

    return true;
  });
}

/**
 * Export all settings (for backup)
 */
export async function exportSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS, (result) => {
      resolve({
        preferences: result[STORAGE_KEYS.PREFERENCES],
        whitelist: result[STORAGE_KEYS.WHITELIST],
        stats: result[STORAGE_KEYS.STATS],
        exportedAt: new Date().toISOString()
      });
    });
  });
}

/**
 * Import settings (restore from backup)
 */
export async function importSettings(backup) {
  return new Promise((resolve) => {
    const updates = {};

    if (backup.preferences) {
      updates[STORAGE_KEYS.PREFERENCES] = backup.preferences;
    }
    if (backup.whitelist) {
      updates[STORAGE_KEYS.WHITELIST] = backup.whitelist;
    }

    chrome.storage.local.set(updates, resolve);
  });
}

/**
 * Clear all data (factory reset)
 */
export async function clearAllData() {
  return new Promise((resolve) => {
    chrome.storage.local.clear(resolve);
  });
}

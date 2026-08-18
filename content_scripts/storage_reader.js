// Content script: reads localStorage and sessionStorage from the page
// Listens for messages from the popup and sends back storage data

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'GET_STORAGE') {
    try {
      // Read localStorage
      const localStorageData = {};
      if (typeof window.localStorage !== 'undefined') {
        for (let i = 0; i < window.localStorage.length; i++) {
          const key = window.localStorage.key(i);
          const value = window.localStorage.getItem(key);
          localStorageData[key] = value;
        }
      }

      // Read sessionStorage
      const sessionStorageData = {};
      if (typeof window.sessionStorage !== 'undefined') {
        for (let i = 0; i < window.sessionStorage.length; i++) {
          const key = window.sessionStorage.key(i);
          const value = window.sessionStorage.getItem(key);
          sessionStorageData[key] = value;
        }
      }

      sendResponse({
        localStorage: localStorageData,
        sessionStorage: sessionStorageData,
        error: null
      });
    } catch (error) {
      // Storage might not be accessible on some pages
      console.warn('Could not access storage:', error);
      sendResponse({
        localStorage: {},
        sessionStorage: {},
        error: error.message
      });
    }
  }
});

import { auditCookies } from "../lib/cookieAudit.js";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'GET_COOKIES') {

    chrome.cookies.getAll({ url: request.url }, (cookies) => {
      const auditedCookies = auditCookies(cookies);
      sendResponse({
        cookies: auditedCookies
      });
      
    });
    return true; // keep channel open for async response
  }
});


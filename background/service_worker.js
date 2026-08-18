import { auditCookies } from "../lib/cookieAudit.js";
import { generateSummary } from "../lib/riskScore.js";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'GET_COOKIES') {

    chrome.cookies.getAll({ url: request.url }, (cookies) => {
      const auditedCookies = auditCookies(cookies);
      const summary = generateSummary(auditedCookies);

      console.log("Audit Summary:", summary);

      sendResponse({
        cookies: auditedCookies,
        summary
      });
      
    });
    return true; // keep channel open for async response
  }
});


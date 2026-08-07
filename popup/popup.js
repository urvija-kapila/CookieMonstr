chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  
  const activeTab = tabs[0];
  const url = activeTab.url;

  console.log("Active tab URL:", url);

  // Send message to service worker requesting cookies for this URL
  chrome.runtime.sendMessage({ action: "GET_COOKIES", url }, (response) => {
    console.log("Popup got response:", response);

    const resultsDiv = document.getElementById("audit-results");

    if (!response || !response.cookies) {
      resultsDiv.innerHTML = "<p>No cookies found.</p>";
      return;
    }

    resultsDiv.innerHTML = response.cookies
      .map(cookie => `
        <div class="cookie-card">
          <h3>${cookie.name}</h3>
          <p><strong>Domain:</strong> ${cookie.domain}</p>

          <ul>
            ${
              cookie.findings.length === 0
                ? "<li>✅ No security issues found.</li>"
                : cookie.findings
                    .map(
                      finding => `
                        <li>
                          <strong>${finding.severity}</strong> -
                          ${finding.title}
                        </li>
                      `
                    )
                    .join("")
            }
          </ul>
        </div>
      `)
      .join("");
      
  });
});

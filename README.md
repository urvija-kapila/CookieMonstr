# CookieMonstr

**Security audit extension for cookies, web storage, and tracking patterns**

A Chrome extension that analyzes the security posture of cookies and web storage on any webpage, detects third-party trackers, and generates comprehensive security reports.

---

## Features

### Cookie Security Audit
- **7-point security evaluation** of all cookies using industry best practices
- **Risk scoring system** (0-100 points) that categorizes cookies as SAFE, LOW, MEDIUM, HIGH, or CRITICAL
- **Detailed findings** for each security issue with actionable recommendations
- **Severity indicators** for quick risk assessment

**Security Rules Evaluated:**
1. Missing HttpOnly flag (HIGH severity)
2. Missing Secure flag (HIGH severity)
3. Missing SameSite attribute (MEDIUM severity)
4. SameSite=None without Secure flag (HIGH severity)
5. Sensitive cookie names without security flags (HIGH severity)
6. Overly broad domain scope (LOW severity)
7. Long-lived session cookies (MEDIUM severity)

### Web Storage Analysis
- Scans localStorage and sessionStorage for sensitive data
- Detects **9 sensitive data patterns**: API keys, JWT tokens, passwords, emails, credit cards, SSNs, session IDs, private keys, OAuth tokens
- Flags suspicious storage practices with security recommendations
- Safe enumeration that doesn't leak data

**Detected Patterns:**
- API credentials and keys
- Authentication tokens and sessions
- Personal identifiable information (PII)
- Financial data
- Private cryptographic keys

### Tracking Detection
- Identifies **30+ known third-party trackers** across 6 categories:
  - Analytics (Google Analytics, Mixpanel, Amplitude)
  - Advertising (DoubleClick, Facebook Ads, Criteo)
  - Social Media (Facebook, LinkedIn, Twitter)
  - Performance Monitoring (Sentry, Datadog)
  - Marketing Automation (HubSpot, Mailchimp)
  - Customer Communication (Intercom, Zendesk, Drift)
- Detects suspicious cookie naming patterns
- Flags cookie overload conditions (20+ cookies)
- Calculates tracking risk level (LOW, MEDIUM, HIGH)

### Reports & Export
- Generates comprehensive JSON security reports
- Includes timestamp, URL, and full audit details
- One-click export to file for record-keeping
- Complete audit history available for review

---

## Installation

### From Source (Development)

1. **Clone or extract** the CookieMonstr repository
	```bash
	cd CookieMonstr
	```

2. **Open Chrome Extension Management**
	- Navigate to: `chrome://extensions/`
	- Enable "Developer mode" (toggle in top-right corner)

3. **Load the extension**
	- Click "Load unpacked"
	- Select the CookieMonstr folder
	- The extension appears in your toolbar as 🛡️

### Verify Installation

- Extension icon appears in Chrome toolbar
- Click the icon to open the popup
- Navigate to any website and click the icon to run an audit

---

## Usage

### Running an Audit

1. **Navigate to any website** (except chrome:// system pages)
2. **Click the CookieMonstr icon** 🛡️ in your Chrome toolbar
3. **Wait for analysis** (loading indicator shows progress)
4. **Review results** across 3 tabs:
	- **Cookies Tab**: All cookies with risk assessment
	- **Storage Tab**: Suspicious localStorage/sessionStorage items
	- **Tracking Tab**: Detected third-party trackers

### Understanding Results

#### Severity Levels
- 🔴 **CRITICAL** - Immediate security risk; urgent attention required
- 🟠 **HIGH** - Significant security issue; should be fixed
- 🟡 **MEDIUM** - Notable risk; consider improvement
- 🟢 **LOW** - Minor concern; best practice recommendation
- 🔵 **INFO** - Informational; not a security risk
- ✅ **SAFE** - Meets security best practices

#### Risk Score
- **0 points**: SAFE ✅
- **1-9 points**: LOW risk 🟢
- **10-19 points**: MEDIUM risk 🟡
- **20-29 points**: HIGH risk 🟠
- **30+ points**: CRITICAL risk 🔴

### Exporting Results

1. **Click "📥 Export Report"** button
2. **Save the JSON file** to your computer
3. **Share or archive** the report for compliance/documentation

JSON report includes:
- Audit timestamp
- Page URL
- Cookie security findings
- Storage analysis results
- Tracking detection summary
- All detailed findings with recommendations

---

## Security & Privacy

### What CookieMonstr Does
- ✅ Analyzes cookies using the Chrome Cookies API
- ✅ Reads localStorage/sessionStorage values
- ✅ Does NOT transmit data to external servers
- ✅ Runs entirely locally in your browser
- ✅ No background data collection

### What CookieMonstr Does NOT Do
- ❌ Does NOT upload your data to any server
- ❌ Does NOT track your browsing
- ❌ Does NOT modify cookies or storage
- ❌ Does NOT access data on browser extension or system pages
- ❌ Does NOT require any user accounts or login

### Permissions Explained
- **`cookies`** - Required to access and analyze cookies
- **`activeTab`** - Required to determine which page you're on
- **`scripting`** - Required to inject content scripts for storage access
- **`<all_urls>`** - Required to audit cookies on all websites

---

## Development

### Project Structure
```
CookieMonstr/
├── manifest.json              # Extension configuration (MV3)
├── README.md                  # This file
├── popup/
│   ├── popup.html            # UI structure
│   ├── popup.css             # Styling (beige/brown elegant theme)
│   └── popup.js              # Popup logic & rendering
├── background/
│   └── service_worker.js     # Cookie audit orchestration
├── content_scripts/
│   └── storage_reader.js     # Storage access from page context
├── lib/
│   ├── cookieAudit.js        # Cookie evaluation engine
│   ├── cookieRules.js        # 7-point security rules
│   ├── riskScore.js          # Risk calculation logic
│   ├── storageAudit.js       # Storage pattern detection
│   └── trackingDetector.js   # Tracker identification
└── assets/
	 └── icons/                # Extension icons
```

### Tech Stack
- **Manifest V3** (Modern Chrome Extension API)
- **Vanilla JavaScript** (No frameworks)
- **CSS3** with elegant beige/brown color palette
- **Service Workers** for background tasks
- **Content Scripts** for page context access



### Future Enhancements (Planned)
- 📊 Historical audit trending
- 🌍 Tracking map visualization
- 📱 Responsive mobile-friendly UI
- 🔔 Real-time tracking alerts
- 📈 Compliance reporting (GDPR, CCPA)
- 🔐 Privacy mode for sensitive audits

---

## ⚙️ Configuration

### Manifest Settings
Edit `manifest.json` to customize:
- **`version`** - Extension version number
- **`permissions`** - Chrome APIs used (cookies, activeTab, scripting)
- **`host_permissions`** - Websites to audit (`<all_urls>`)
- **`action.default_popup`** - Popup file path
- **`background.service_worker`** - Background worker file

### CSS Theme Customization
Edit `popup/popup.css` CSS variables:
```css
:root {
  --bg-primary: #f5f1ed;      /* Main background */
  --text-primary: #5d4e47;    /* Main text */
  --accent: #a67c52;          /* Accent color */
  /* ... more variables ... */
}
```

---

## 🐛 Troubleshooting

### Extension Not Showing in Toolbar
- Verify "Developer mode" is enabled in `chrome://extensions/`
- Check that extension loaded without errors
- Try refreshing the extension or restarting Chrome

### Audit Runs But Shows No Cookies
- Some sites may not set cookies (check `Network` tab in DevTools)
- Certain pages may be restricted (chrome://, moz-extension://)
- Check console for error messages

### Storage Tab Shows "CSP Restriction"
- Content Security Policy blocks storage access
- This is a security feature of the website
- The extension cannot bypass this

### "Cannot Communicate with Service Worker"
- Refresh the extension in `chrome://extensions/`
- Reload the webpage and try again
- Check browser console for errors

---

## 📄 License

CookieMonstr is provided as-is for security research and educational purposes.

---

## 📚 Resources

### External Links
- [Chrome Extension Documentation](https://developer.chrome.com/docs/extensions/)
- [OWASP Cookie Security](https://owasp.org/www-community/controls/Cookie_Security)
- [MDN Web Storage API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API)
- [Privacy Guide](https://privacy.gov/)



## 👤 Author & Credits

**CookieMonstr** - Security Audit Extension
- 
- Built with Chrome Extension APIs (Manifest V3)
- Designed for privacy-conscious users
- Developed for educational and research purposes

---
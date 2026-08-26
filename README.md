# CookieMonstr

**Local-first browser security research tool for cookies, web storage, and tracking signals.**

CookieMonstr is a Manifest V3 Chrome extension for inspecting the client-side security posture of a webpage. It audits cookie attributes, identifies sensitive values in `localStorage` and `sessionStorage`, detects tracking-related cookie signals, and produces JSON reports enriched with OWASP Top 10 and CWE references.

The project is intended for security research, defensive testing, education, and responsible disclosure workflows. It does not exploit findings, modify browser state, or transmit audit data to a remote service.

## Research Focus

CookieMonstr helps answer practical questions during a client-side security review:

- Are authentication and session cookies protected with `HttpOnly`, `Secure`, and `SameSite` attributes?
- Is sensitive information being persisted in JavaScript-readable web storage?
- Are third-party or tracking-oriented cookie patterns present?
- Which OWASP Top 10 categories and CWE classes are associated with the findings?
- Can an audit be shared safely without exposing raw storage values?

It is a visibility and triage tool, not a replacement for application testing, source review, network inspection, or a full DAST/SAST platform.

## Capabilities

### Cookie Security Audit

The background service worker retrieves cookies for the active page through the Chrome Cookies API. Each cookie is evaluated against seven rules:

| Finding | Severity | Reference |
| --- | --- | --- |
| Missing `HttpOnly` | High | CWE-1004 |
| Missing `Secure` on likely session cookies | High | CWE-614 |
| Missing explicit `SameSite` | Medium | CWE-352 |
| `SameSite=None` without `Secure` | High | CWE-352 |
| Sensitive cookie without `Secure` | High | CWE-614 |
| Broad domain scope | Low | CWE-732 |
| Long-lived authentication cookie | Medium | CWE-613 |

Cookie risk scores use the current weights below:

- High: 10 points
- Medium: 5 points
- Low: 2 points
- Informational: 0 points

Risk levels are `SAFE`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.

### Web Storage Analysis

The content script reads page-local `localStorage` and `sessionStorage` and passes the values to the storage audit logic. Detection covers:

- API keys and secrets
- JWT, OAuth, bearer, and other authentication tokens
- Passwords and session identifiers
- Email addresses
- Credit card numbers and SSNs
- PEM private keys

Values displayed in the popup are truncated. Access may be unavailable on restricted browser pages or pages where the content script cannot run.

### Tracking Signals

The Tracking tab identifies known tracker domains and suspicious cookie naming patterns. It also reports cookie overload when a page has more than 20 cookies and assigns a tracking risk level based on detected signals.

This is heuristic detection. A tracker match does not prove malicious behavior, and the absence of a match does not prove that a page is free of tracking.

### Toolbar Severity Badge

After a page finishes loading, the extension silently audits its cookies and updates the toolbar badge with the highest finding severity:

| State | Badge | Color |
| --- | --- | --- |
| Critical finding | `CRIT` | Red |
| High finding | `HIGH` | Orange |
| Medium finding | `MED` | Amber |
| Low or informational finding | `LOW` | Green |
| No findings | `✓` | Grey |

Opening the popup also refreshes the badge for the active tab in case the service worker was idle during navigation.

### JSON Reporting

The export dialog provides two modes:

- **Redacted export**: the default. Redacts values associated with sensitive key names, IP addresses, email addresses, nested sensitive JSON keys, and high-entropy strings likely to be tokens or encoded identifiers.
- **Full export**: explicitly selected by the user and includes the raw storage dump.

Redaction is applied to a copy of the audit data at export time. It does not change the in-memory audit state. Reports include cookie findings, storage findings, tracking signals, timestamps, page URL, and OWASP coverage counts. Mapped findings also include CWE and OWASP metadata with attack scenarios.

## OWASP and CWE Mapping

Mapped findings currently cover these OWASP Top 10 categories:

- **A01:2021 - Broken Access Control**: SameSite and CSRF-related cookie exposure
- **A02:2021 - Cryptographic Failures**: Sensitive information and credentials in browser storage
- **A05:2021 - Security Misconfiguration**: Cookie configuration and domain-scope issues
- **A07:2021 - Identification and Authentication Failures**: Session and authentication cookie/token issues

Each mapped finding can include an OWASP category, CWE identifier, MITRE reference URL, and a concise attack scenario. These mappings describe vulnerability classes; they are not CVE identifiers and do not assert that a specific software vulnerability exists.

## Installation

CookieMonstr is currently installed from source as an unpacked extension.

1. Clone or download this repository.
2. Open `chrome://extensions/` in Chrome.
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Choose the project directory.
6. Pin CookieMonstr to the toolbar for badge visibility.

After code changes, use **Reload** on the extension card. Reload the target webpage when testing content-script behavior.

## Usage

1. Navigate to a permitted webpage.
2. Wait for the page to finish loading so the toolbar badge can update.
3. Open CookieMonstr from the toolbar.
4. Review the **Cookies**, **Storage**, and **Tracking** tabs.
5. Select **Export Report** to choose a redacted or full JSON report.
6. Use the OWASP and CWE reference badges to open authoritative documentation in a new tab.

Do not test systems without authorization. When using findings for disclosure, minimize collected data and prefer the redacted export unless raw values are strictly required for private analysis.

## Architecture

```text
Active webpage
    |
    | content_scripts/storage_reader.js
    v
Popup ----------------------------+
    |                             |
    | GET_COOKIES                 | GET_STORAGE
    v                             v
Service worker              Storage audit
    |                             |
    v                             v
Cookie audit + rules        Enriched findings
    |                             |
    +-------------+---------------+
                  v
       Popup rendering and export
                  |
                  v
        Redacted/full JSON report
```

## Repository Structure

```text
CookieMonstr/
├── manifest.json
├── README.md
├── assets/icons/
├── background/
│   └── service_worker.js       # Cookie retrieval, audit requests, toolbar badge
├── content_scripts/
│   └── storage_reader.js       # Page-local storage reader
├── lib/
│   ├── cookieAudit.js          # Cookie evaluation and severity ranking
│   ├── cookieRules.js          # Cookie security rules
│   ├── export.js               # JSON report construction and redaction
│   ├── mappings.js              # OWASP/CWE finding metadata
│   ├── riskScore.js             # Risk scoring and summary generation
│   ├── storageAudit.js          # Sensitive storage pattern detection
│   └── trackingDetector.js      # Tracking detection utilities
└── popup/
    ├── popup.html              # Popup structure
    ├── popup.css               # Popup presentation
    └── popup.js                 # Audit rendering and user interactions
```

## Permissions and Privacy

| Permission | Purpose |
| --- | --- |
| `cookies` | Read cookies associated with the active URL for analysis |
| `activeTab` | Identify the current page and support popup actions |
| `scripting` | Support page interaction required by the extension |
| `<all_urls>` | Allow audits across supported websites |

CookieMonstr is local-first:

- Audit processing runs in the browser.
- No audit data is uploaded to a CookieMonstr server.
- Cookies and storage are read but not modified.
- The extension does not create user accounts or collect browsing history.
- Chrome system and extension pages are excluded from auditing.

Because the extension can inspect sensitive browser data, use it only on systems and websites where you have permission. Treat full exports as sensitive artifacts and store them securely.

## Limitations and Interpretation

- Cookie findings are based on attributes exposed by the Chrome Cookies API and heuristic identification of likely session cookies.
- The storage reader can access only page contexts where the content script is allowed to run.
- Tracking detection is domain and naming based; it is not a complete network-level tracker inventory.
- A finding is a signal for investigation, not proof of exploitability or business impact.
- The extension does not inspect server-side session invalidation, application authorization logic, TLS configuration, or response bodies.
- The current project has no automated test suite in `tests/`; manual validation in Chrome remains important.

## Development

The project uses:

- Manifest V3
- Vanilla JavaScript with ES modules
- Chrome extension APIs
- CSS3

There are no runtime package dependencies or build steps. Edit the source files directly, reload the unpacked extension in Chrome, and inspect the extension service worker console for background errors.

Before submitting changes, check:

```bash
git diff --check
```

Then manually verify cookie findings, storage detection, badge states, external reference links, and both export modes on authorized test pages.

## Roadmap

Potential future work includes:

- Automated unit tests for cookie rules, redaction, mappings, and risk scoring
- Historical audit comparison and trend reporting
- Network-aware tracker discovery
- Compliance-oriented report formats
- Configurable detection rules and severity thresholds
- Additional browser support

## References

- [Chrome Extensions documentation](https://developer.chrome.com/docs/extensions/)
- [Chrome Cookies API](https://developer.chrome.com/docs/extensions/reference/api/cookies)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Cookie Security](https://owasp.org/www-community/controls/Cookie_Security)
- [MITRE CWE](https://cwe.mitre.org/)
- [MDN Web Storage API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API)

## License and Intended Use

CookieMonstr is provided as-is for security research and educational purposes. Use it responsibly, respect authorization boundaries, and follow applicable laws and disclosure policies.

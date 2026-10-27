# CookieMonstr

**Local-first Browser Security Auditor for cookies, web storage, and tracking signals.**

CookieMonstr is a Manifest V3 Chrome extension that audits cookie attributes, flags potentially sensitive data in `localStorage` and `sessionStorage`, identifies tracking-related signals, and generates OWASP/CWE-enriched JSON reports. Designed for defensive security research and authorized testing, it does not exploit findings, modify browser state, or automatically upload audit data.

## Key Features

- **Cookie security:** Checks six rules covering `HttpOnly`, `Secure`, `SameSite`, domain scope, and long-lived authentication cookies.
- **Storage auditing:** Detects suspicious key/value patterns associated with passwords, API keys, tokens, session IDs, personal data, payment-card-shaped values, and private-key markers.
- **Tracking indicators:** Identifies known tracker-domain matches, suspicious cookie names, and unusually high cookie counts.
- **Actionable findings:** Prioritizes results with heuristic risk scores, severity levels, OWASP Top 10/CWE mappings, and remediation guidance.
- **JSON reporting:** Offers redacted (default) and full exports; redaction is heuristic and reports should be reviewed before sharing.
- **Security testing:** Runs automated tests locally and via GitHub Actions on pushes and pull requests to `main`.

---

## Capabilities

### Cookie Security Audit

The background service worker retrieves cookies associated with the active webpage through the Chrome Cookies API. CookieMonstr evaluates cookie attributes using six heuristic security rules.

| Finding | Severity | Reference |
|---|---|---|
| Missing `HttpOnly` | High | CWE-1004 |
| Missing `Secure` on likely session cookies | High | CWE-614 |
| Missing explicit `SameSite` | Medium | CWE-352 |
| `SameSite=None` without `Secure` | High | CWE-352 |
| Broad cookie domain scope | Low | CWE-732 |
| Long-lived authentication cookie | Medium | CWE-613 |

The duplicate Secure-attribute detection was removed during regression testing to prevent multiple findings for the same underlying condition from inflating risk scores.

**Risk scoring**

CookieMonstr assigns weighted scores to findings:

- High: 10 points
- Medium: 5 points
- Low: 2 points
- Informational: 0 points

The resulting risk classifications are `SAFE`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.

These scores support prioritization of potential issues. They are not quantitative measurements of exploitability, attack probability, or business impact.

**Validation:** Six cookie-security rules were evaluated against 24 controlled scenarios, with 11 true positives, 13 true negatives, and no observed misclassifications on that dataset.

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

CookieMonstr generates structured JSON reports containing cookie findings, browser-storage observations, tracking indicators, risk classifications, timestamps, page URLs, and applicable OWASP/CWE references.

Two export modes are supported:

- **Redacted export (default):** Applies heuristic redaction to potentially sensitive browser-storage values and relevant storage findings. The implementation includes checks for sensitive key names, email addresses, IP addresses, nested JSON fields, and token-like values.
- **Full export:** An explicitly selected option that preserves raw browser-storage values for authorized private analysis.

**Security improvements:** Automated regression testing identified and addressed a data-disclosure issue where sensitive storage values could remain visible within exported security findings even when storage-item redaction was enabled.

The corrected export logic preserves security findings while redacting flagged values in the tested scenarios.

Redaction operates on a separate report representation without intentionally modifying the original audit state.

**Privacy limitation:** Redaction is heuristic and has not been exhaustively verified across every report field or sensitive-data format. Reports may contain sensitive URLs, identifiers, cookie metadata, or other contextual information. Users should review redacted reports before sharing them publicly and handle full exports as sensitive artifacts.

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

## Run Tests

```bash
npm test
node evaluation/cookieValidation.js
node evaluation/runValidation.js storage-cases.json
node evaluation/runValidation.js final-storage-cases.json
```

The GitHub Actions workflow automatically runs `npm test`. Evaluation scripts run separately; their outputs are not currently CI quality gates.

## Architecture

```text
Active webpage
   |                         Chrome Cookies API
   v                                 |
Content script                       v
(storage reader)               Background service worker
   |                                 |
   v                                 v
Storage auditing                 Cookie rules / audit
   |                                 |
   +---------------+-----------------+
                   v
       Popup: findings and tracking signals
                   |
                   v
          Redacted / full JSON report

Local tests (npm test) ---> GitHub Actions CI
Labeled fixtures --------> Evaluation scripts / metrics
```

Built using **JavaScript ES modules, Chrome Extension Manifest V3, HTML/CSS, Node.js tests, and GitHub Actions**. No frontend build step or runtime npm dependencies are required.


## Repository Structure

```text
CookieMonstr/
├── .github/
│   └── workflows/
│       └── security-tests.yml       # Automated GitHub Actions CI
│
├── assets/
│   ├── icons/                  # Extension icons
│   └── screenshots/            # Browser audit screenshots
│
├── background/
│   └── service_worker.js       # Cookie retrieval, audit requests, badge
│
├── content_scripts/
│   └── storage_reader.js       # Browser storage collection
│
├── lib/
│   ├── cookieAudit.js          # Cookie audit and severity ordering
│   ├── cookieRules.js          # Six cookie security rules
│   ├── export.js               # JSON reporting and redaction
│   ├── mappings.js             # OWASP/CWE metadata
│   ├── riskScore.js            # Risk scoring and aggregation
│   ├── storageAudit.js         # Sensitive storage detection
│   └── trackingDetector.js     # Tracking-related indicators
│
├── popup/
│   ├── popup.html              # Extension interface
│   ├── popup.css               # Popup styling
│   └── popup.js                # Audit rendering and interactions
│
├── tests/
│   ├── cookieRules.test.js     # Cookie-rule unit tests
│   ├── cookieAudit.test.js     # Cookie-audit integration tests
│   ├── export.test.js          # Export redaction regression tests
│   ├── storageMetadata.test.js # Storage false-positive regression tests
│   └── storageAdversarial.test.js
│                               # Storage edge-case tests
│
├── evaluation/
│   ├── validation/
│   │   ├── storage-cases.json       # Storage development fixtures
│   │   └── final-storage-cases.json # Additional storage fixtures
│   │
│   ├── storageAccuracy.js      # Initial password-rule evaluation
│   ├── passwordHoldout.js      # Additional password development cases
│   ├── securityBenchmark.js    # Multi-rule development benchmark
│   ├── runValidation.js        # Labeled storage evaluation runner
│   └── cookieValidation.js     # Cookie rule-conformance evaluation
│
├── docs/
│   ├── VALIDATION.md
│   └── CASE_STUDIES.md
├── manifest.json              # Chrome extension configuration
├── package.json               # Node.js test configuration
└── README.md                  # Documentation and validation results
```
## Security Testing & Detection Performance

**25 automated regression tests** passed in the latest verified local run, using Node.js's built-in test runner. The suite covers cookie rules, selected scoring behavior, storage false-positive regressions, and JSON redaction.

Across **40 additional controlled, synthetic, rule-specific evaluation cases** (24 cookie and 16 storage), results were:

| Metric | Result |
|---|---:|
| Accuracy | **87.50%** |
| Precision | **81.82%** |
| Recall | **94.74%** |
| F1 score | **87.80%** |
| False-positive rate | 19.05% |
| False-negative rate | 5.26% |
| TP / TN / FP / FN | 18 / 17 / 4 / 1 |

The 24 cookie-rule cases matched all specified expected outcomes. The 16 additional storage cases exposed four false positives and one false negative. Separately, refinement of three storage detectors reduced false positives from **4 to 0** on an 18-case *development* benchmark.

**Interpretation:** These are measurements on small, manually labeled synthetic fixtures—not independently sampled real-world vulnerability-detection accuracy. Some cases resemble development examples. See [validation methodology and per-rule results](docs/VALIDATION.md).

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

## Case Studies

Recorded browser audits of a news website and a banking webpage illustrate how CookieMonstr displays findings under different observed conditions. They **do not establish confirmed vulnerabilities or prove a site is secure**. See [screenshots and audit observations](docs/CASE_STUDIES.md).

## Limitations & Responsible Use

- Rule matches and risk scores are **triage signals**, not proof of exploitability, credential validity, or business impact.
- Generic or misleading storage keys can conceal secrets; benign identifiers and configuration flags can be misclassified.
- Extension access is limited by browser permissions and content-script execution contexts. CookieMonstr does not inspect server-side controls, TLS configurations, or HTTP response bodies.
- Tracker detection is heuristic rather than a complete network inventory; absence of findings is not proof of security.
- Redaction is not exhaustively verified against all secrets or report fields; **review exports before sharing**. Full reports can contain sensitive browser data.
- The reported evaluation results are limited to synthetic test cases and are not representative real-world performance claims.

Use CookieMonstr only on systems and pages you are authorized to assess.

## Future Improvements

- Broader independently sourced and adversarial validation datasets
- Better secret-format recognition under unconventional storage keys
- Stronger payment-card and credential validation
- Historical audit comparison and trends
- Network-aware tracking discovery
- Configurable detection rules and severity thresholds

## Author

**Urvija Kapila** — B.Tech CSE (Cyber Security), Dayananda Sagar University  
Email: kapila.urvija@gmail.com

*Independent defensive security research and education project.*
# CookieMonstr — Recorded Browser Audit Case Studies

These examples come from browser audits described in the project's original README. They illustrate the extension's user-facing output in two different browsing contexts. **They are historical observations, not confirmed vulnerability disclosures, a penetration test of either organization, or an independent benchmark of accuracy.** The site configurations and extension detection logic may have changed since capture.

## 1. The Indian Express (`indianexpress.com`)

<p float="left">
  <img src="../assets/screenshots/iexp_ss1.png" width="200" alt="CookieMonstr Indian Express screenshot 1" />
  <img src="../assets/screenshots/iexp_ss2.png" width="200" alt="CookieMonstr Indian Express screenshot 2" />
  <img src="../assets/screenshots/iexp_ss3.png" width="200" alt="CookieMonstr Indian Express screenshot 3" />
  <img src="../assets/screenshots/iexp_ss4.png" width="200" alt="CookieMonstr Indian Express screenshot 4" />
</p>

| Metric | Observed result |
|---|---:|
| Cookies audited | 35 |
| Critical-scored cookies | 2 |
| Medium-scored cookies | 33 |
| `localStorage` items | 46 |
| `sessionStorage` items | 10 |
| Suspicious storage items | 15 |
| Known third-party tracker matches | 0 |
| Suspicious tracking patterns | 3 |
| Toolbar badge | HIGH |

**Cookies.** The recorded audit assigned Critical scores to two cookies. One example, `ev_user_state`, was reported missing `HttpOnly` and `Secure`. Those attributes can affect script access and transport protection, but an exploitable session compromise cannot be inferred without knowing the cookie's role, application context, and other safeguards. Historical risk scores can also differ from today's software after scoring/deduplication changes.

**Storage.** One entry, `_cb_expires`, contained the value `1821875187948`, which matched the tool's 13–19 digit card-number heuristic. **This must not be described as a confirmed credit-card number.** A numeric expiration timestamp or identifier can match the same pattern; the key name itself suggests an expiration-related value. The result is useful evidence of a possible false positive and a reason to validate formats more carefully. No evidence here establishes actual payment-data exposure or PCI-DSS noncompliance.

**Tracking.** The recorded output had three suspicious naming matches, including `bounceClientVisit7834v`, but no known domain-list tracker matches. The 35-cookie count also exceeded the tool's configured threshold of 20. These are indicators for review rather than conclusions about malicious tracking.

**Export.** The extension offers a default redacted report mode. Testing has since verified redaction of selected synthetic secret values in both storage entries and findings. Any real report still needs review before disclosure, because other fields may contain sensitive information.

## 2. SBI Net Banking (recorded banking webpage)

<p float="left">
  <img src="../assets/screenshots/sbi_ss1.png" width="200" alt="CookieMonstr SBI screenshot 1" />
  <img src="../assets/screenshots/sbi_ss2.png" width="200" alt="CookieMonstr SBI screenshot 2" />
  <img src="../assets/screenshots/sbi_ss3.png" width="200" alt="CookieMonstr SBI screenshot 3" />
  <img src="../assets/screenshots/sbi_ss4.png" width="200" alt="CookieMonstr SBI screenshot 4" />
</p>

| Metric | Observed result |
|---|---:|
| Cookies audited | 4 |
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 2 |
| Safe | 2 |
| `localStorage` items | 0 |
| `sessionStorage` items | 0 |
| Known third-party tracker matches | 0 |
| Suspicious tracking patterns | 0 |
| Toolbar badge | MED |

**Observed behavior.** The recorded scan listed four cookies, two designated SAFE and two with minor/medium heuristic risk scores. The cookies `TS0151e286` and `TS93b20f13027` were reported without explicitly configured SameSite attributes. Such findings can prompt configuration review, but **missing explicit SameSite does not by itself demonstrate CSRF**: browser defaults and the application's anti-CSRF controls matter.

**Interpretation and consistency note.** The historical metric table labels two cookies Low while the recorded toolbar badge is `MED`; the original narrative also described the SameSite gaps as Medium. These are preserved as recorded observations rather than reconciled without a fresh audit or source report. A scanner showing few findings does **not** establish that a banking application is secure or tracker-free.

## What These Examples Demonstrate

The examples show that CookieMonstr can display cookie configuration findings, local/session-storage matches, tracking indicators, and reportable results across different browser states. They are **qualitative UI demonstrations**, not a source for precision, recall, or false-positive-rate claims.

For measured outcomes on synthetic, labeled cases, see [Security Testing & Detection Validation](VALIDATION.md). Only audit pages and systems you are authorized to assess, and avoid publishing raw browser credentials or session data.

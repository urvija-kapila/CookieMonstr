# CookieMonstr — Security Testing & Detection Validation

This document records the controlled test methodology, measurements, limitations, and commands used for evaluating CookieMonstr. All test fixtures are synthetic. A detection means a rule emitted a finding, not that a vulnerability or usable credential has been confirmed.

## Automated Regression Tests and CI

The latest user-verified local run completed **25 tests passing, 0 failures, 0 TODOs** using Node.js's built-in test runner (`npm test`). Tests include cookie rule behavior, audit ordering and selected risk scores, storage-detection regressions, duplicate-finding prevention, and redaction of selected synthetic sensitive values. This is not exhaustive coverage of all code paths.

The workflow in `.github/workflows/security-tests.yml` runs `npm test` on pushes and pull requests to `main`. The evaluation scripts below are separate and are **not** executed by this workflow.

## Evaluation Design

Each labeled case supplies one synthetic storage key/value or cookie configuration and a target rule ID with an expected Boolean outcome. The runner executes CookieMonstr's actual audit function and checks whether that specific rule fires. This counts **rule-case classifications**, not distinct real-world vulnerabilities or user sessions. Some cases were used to tune the heuristics; hence the development dataset is reported separately.

Definitions:

- **TP:** Expected rule finding reported
- **TN:** Expected non-finding not reported
- **FP:** Rule finding reported where not expected
- **FN:** Expected rule finding missed
- **Accuracy:** `(TP + TN) / (TP + TN + FP + FN)`
- **Precision:** `TP / (TP + FP)`
- **Recall:** `TP / (TP + FN)`
- **F1:** `2TP / (2TP + FP + FN)`
- **False-positive rate:** `FP / (FP + TN)`
- **False-negative rate:** `FN / (FN + TP)`

Rates are computed only when their denominators are nonzero. Aggregated metrics below use sums of counts (*micro-aggregation*), not averages of per-rule percentages.

## 1. Cookie Rule-Conformance Evaluation

**Script:** `evaluation/cookieValidation.js`  
**Scope:** 24 controlled cookie configurations against six target rules.

| Rule | Cases | TP | TN | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| Missing `HttpOnly` | 4 | 2 | 2 | 0 | 0 | 100% | 100% |
| Missing `Secure` | 4 | 2 | 2 | 0 | 0 | 100% | 100% |
| Unspecified `SameSite` | 4 | 2 | 2 | 0 | 0 | 100% | 100% |
| `SameSite=None` without `Secure` | 4 | 1 | 3 | 0 | 0 | 100% | 100% |
| Broad cookie domain | 4 | 2 | 2 | 0 | 0 | 100% | 100% |
| Long-lived authentication cookie | 4 | 2 | 2 | 0 | 0 | 100% | 100% |
| **Total** | **24** | **11** | **13** | **0** | **0** | **100%** | **100%** |

**F1:** 100%; **accuracy:** 100% on these cases. These tests check conformance with the selected rule definitions, not whether a particular webpage has an exploitable vulnerability.

## 2. Storage Detection Development Benchmark

**Dataset:** `evaluation/validation/storage-cases.json` (18 cases across password, API-key, and session-identifier detectors). The before/after comparison was measured on the same cases and informed rule refinements.

| Metric | Before refinement | After refinement |
|---|---:|---:|
| Cases | 18 | 18 |
| TP | 9 | 9 |
| TN | 5 | 9 |
| FP | 4 | 0 |
| FN | 0 | 0 |
| Accuracy | 77.78% | 100% |
| Precision | 69.23% | 100% |
| Recall | 100% | 100% |
| F1 | 81.82% | 100% |

The observed reduction from four false positives to zero measures **development-set improvement**, not performance on new, representative traffic. Earlier exploratory password datasets (8 and 12 cases) were also used during tuning and are not added to the headline totals.

## 3. Additional Storage Detection Evaluation

**Dataset:** `evaluation/validation/final-storage-cases.json` (16 synthetic cases across four rules). The original results were retained rather than altering detection rules to force perfect scores.

| Rule | Cases | TP | TN | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| JWT/token exposure | 4 | 2 | 1 | 1 | 0 | 66.67% | 100% | 80% |
| Credit-card exposure | 4 | 2 | 1 | 1 | 0 | 66.67% | 100% | 80% |
| Private-key marker exposure | 4 | 1 | 2 | 0 | 1 | 100% | 50% | 66.67% |
| Email exposure | 4 | 2 | 0 | 2 | 0 | 50% | 100% | 66.67% |
| **Total** | **16** | **7** | **4** | **4** | **1** | **63.64%** | **87.50%** | **73.68%** |

**Combined accuracy:** 68.75%; **false-positive rate:** 50%; **false-negative rate:** 12.50% on these 16 cases.

### Observed Misclassifications

| Case | Target detector | Observation | Error |
|---|---|---|---|
| `JWT-04` | JWT/token | `tokenRefreshEnabled=false` flagged | FP |
| `CARD-03` | Credit-card | 16-digit `orderId` flagged | FP |
| `KEY-02` | Private-key | Encrypted private-key PEM marker not detected | FN |
| `EMAIL-03` | Email | `username=guest` flagged | FP |
| `EMAIL-04` | Email | `emailNotifications=false` flagged | FP |

The JWT/token cases mix token-key indicators and JWT-shaped strings; they should not be presented as JWT-parser performance. Private-key fixtures are **PEM markers**, not complete keys. The payment-card fixtures are synthetic numbers and identifiers, not proof of financial data exposure.

## 4. Summary: Additional Controlled Evaluation (40 Cases)

The 24 cookie-rule cases and 16 additional storage cases yield the following **combined, synthetic rule-case** result. This excludes the separately tuned 18-case development benchmark.

| Metric | Result |
|---|---:|
| Cases | 40 |
| TP / TN / FP / FN | 18 / 17 / 4 / 1 |
| Accuracy | **87.50%** |
| Precision | **81.82%** |
| Recall | **94.74%** |
| F1 score | **87.80%** |
| False-positive rate | **19.05%** |
| False-negative rate | **5.26%** |

**Interpretation:** This combination mixes relatively simple cookie rule-conformance cases with harder storage heuristic cases. The 40-case set is small, manually labeled, and not independently sourced or representative of production sites. Its metrics are descriptive of those fixtures, **not** an overall real-world accuracy estimate.

For completeness, including the 18 tuned development cases produces **58 cases** with TP=27, TN=26, FP=4, FN=1, accuracy **91.38%**, precision **87.10%**, recall **96.43%**, and F1 **91.53%**. This larger aggregate is *not* the preferred headline because it includes a dataset optimized during development.

## Reproduce the Results

From the project root with Node.js installed:

```bash
npm test
node evaluation/cookieValidation.js
node evaluation/runValidation.js storage-cases.json
node evaluation/runValidation.js final-storage-cases.json
```

The scripts display per-rule counts and case classifications in the terminal. Their output is not yet stored as a versioned machine-readable results artifact. Git commit history can be used to identify the evaluated version.

## Threats to Validity and Known Limitations

1. **Selection bias:** Fixtures are hand-curated; some overlap with the cases used while designing detectors.
2. **Limited sample size:** Four cases per rule for many evaluated rules; percentages can change substantially with one additional case.
3. **Key-name heuristics:** Configuration entries can trigger false positives, and credentials under generic or misleading names can be missed.
4. **Format vs. semantics:** A JWT-shaped string, PEM header, card-shaped number, or email-like value is not necessarily a valid credential, complete key, payment card, or security vulnerability.
5. **No real-world baseline:** Results do not establish production detection rates, vulnerability severity, exploitability, or business impact.
6. **Incomplete code coverage:** Regression tests focus on selected functions; browser lifecycle behaviors, tracking detection, UI, and all redaction paths have not been exhaustively tested.
7. **Heuristic risk scores:** Weighted severity supports triage rather than measuring exploit probability.

The evaluation is intended to be transparent, reproducible, and appropriately scoped, not a claim of universal security effectiveness.

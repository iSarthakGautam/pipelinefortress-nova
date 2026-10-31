# R5 Joint Adjudication Evidence Review

**Status:** Reviewer A and Reviewer B have confirmed agreement with the six final labels shown below. This record reflects that joint agreement as communicated by the project coordinator. The reviewer identity and agreement-date fields remain to be completed in the adjudication CSV; do not invent names or dates.

**Adjudication method:** Joint review by Reviewer A and Reviewer B. No third reviewer was used.

**Scope:** This document records the evidence basis and agreed outcomes for the six direct Reviewer A / Reviewer B disagreements. It does not adjudicate the 49 Reviewer B cases retained as `UNRESOLVED`.

| Finding ID | Reviewer A original label | Reviewer B original label | Agreed final label | Evidence basis |
|---|---|---|---|---|
| `7edad2159c0a938b` | TRUE_POSITIVE | FALSE_POSITIVE | **FALSE_POSITIVE** | The reported location `.github/workflows/baseline-pipeline.yml:518` is a shell health-check failure branch, not a GitHub Actions `uses:` reference. The workflow uses action references elsewhere at lines 50 and 57, both pinned to full commit SHAs. The reported location does not support the mutable-action-tag claim. |
| `f784acaf3ff96df4` | TRUE_POSITIVE | FALSE_POSITIVE | **TRUE_POSITIVE** | The repository custom rule explicitly defines this as a planted CWE-798 hard-coded-credential finding and intentionally catches credential-named literals even when the value is an AWS documented example. Rule tests also mark fake/example-looking literals as matches. This is a true positive for the project-defined rule/class, not proof that the value is an active AWS credential. |
| `42b2e412c7dcd110` | TRUE_POSITIVE | FALSE_POSITIVE | **TRUE_POSITIVE** | The same project-defined rule semantics apply to the AWS_SECRET finding: it is a credential-named hard-coded literal, and the custom rule intentionally detects this planted CWE-798 class regardless of whether the value is a live credential. This does not establish that the value is an active secret. |
| `2128a2868176d25c` | TRUE_POSITIVE | FALSE_POSITIVE | **TRUE_POSITIVE** | Line 40 is the user-input source; lines 42–44 build SQL by interpolating that input into a query and execute it with `cursor.execute`. The vulnerable flow and sink are present immediately below the reported source line. |
| `f41e34d448227f61` | TRUE_POSITIVE | FALSE_POSITIVE | **FALSE_POSITIVE** | In the supplied application snapshot, the Express process is a proxy and the Flask app shows no cookie-backed session or browser-authentication mechanism. The payment POST route is unauthenticated. On this evidence, missing `csurf` middleware does not establish a CSRF vulnerability in the current application. Revisit if authentication via ambient cookies or sessions is introduced. |
| `045726bfc4b033fd` | TRUE_POSITIVE | FALSE_POSITIVE | **TRUE_POSITIVE** | The container `securityContext` is present at line 20, but `allowPrivilegeEscalation` is not set to `false`. `runAsNonRoot` is a separate control and does not satisfy the `allowPrivilegeEscalation` requirement. |

## Source locations for reproducibility

- `7edad2159c0a938b`: `.github/workflows/baseline-pipeline.yml:518–521`; compare `uses:` references at lines 50 and 57.
- `f784acaf3ff96df4`: `apps/vulnshop-api/config.py:11–12`; `scanners/semgrep/rules/python-hardcoded-credential.yaml`; `tests/semgrep/python-hardcoded-credential.py`.
- `42b2e412c7dcd110`: `apps/vulnshop-api/config.py:11–13`; `scanners/semgrep/rules/python-hardcoded-credential.yaml`; `tests/semgrep/python-hardcoded-credential.py`.
- `2128a2868176d25c`: `apps/vulnshop-api/routes/search.py:40–44`; file header identifies intentionally planted CWE-89 SQL injection.
- `f41e34d448227f61`: `apps/vulnshop-api/server.js:1–5, 26–58`; `apps/vulnshop-api/app.py`; `apps/vulnshop-api/routes/pay.py:10–30`; repository search showed no session/cookie authentication implementation in the supplied snapshot.
- `045726bfc4b033fd`: `infra/k8s/deployment.yaml:20–21`; compare `infra/k8s/deployment.hardened.yaml:34–38`, which explicitly sets `allowPrivilegeEscalation: false`.

## Adjudication record

- **Adjudication method:** Joint review and agreement by Reviewer A and Reviewer B.
- **Reviewer A name/identifier:** Sarthak Gautam
- **Reviewer B name/identifier:** Rajdeep Kaur
- **Date/time of joint agreement (UTC):**  2026-10-30T17:18:03Z
- **Adjudication CSV:** `adjudication_review_draft.csv`. Ensure its final labels, rationales, adjudicators, date, and status fields match this document.
- **Original labels:** Preserve both reviewers' original independent labels; do not overwrite them with adjudicated outcomes.

## Remaining unresolved cases and limitations

- The 49 Reviewer B cases labelled `UNRESOLVED` are retained unchanged, as requested. They are outside the scope of this six-case adjudication and must remain visible in the dataset and limitations statement.
- The supplied task instruction describes binary reviewer outcomes (`TRUE_POSITIVE` / `FALSE_POSITIVE`). Retaining `UNRESOLVED` therefore requires explicit project-owner acceptance or a documented protocol exception before freeze approval.
- The provisional agreement calculation used 49 paired binary labels and excluded the 49 Reviewer B `UNRESOLVED` rows. Preserve the kappa and raw-agreement report as an independent-review statistic; do not recalculate agreement using post-adjudication labels.
- This document records the six agreed outcomes. It does not by itself establish that the remaining dataset checks, time-split/leakage review, checksum manifest, or required freeze sign-offs are complete. Keep freeze approval `NOT_APPROVED` until those requirements are satisfied.

# Security gate: tuning and false-fail analysis

Owner: R2. Measured 2026-10-27 from two sources:

- **Every CI run so far**: 71 runs from 2026-10-09 to 2026-10-27, made up of 59 runs of the
  pipeline and 12 of the legacy `Security scan + gate` workflow. Each run is labelled in
  [`data/gate-tuning-2026-10-27/gate-history.csv`](data/gate-tuning-2026-10-27/gate-history.csv),
  with its run id, finding counts, outcome, cause and a one-line reason.
- **Main's findings after #24, #29 and #27 merged** (commit `1bb3381`, run 40358495428):
  [`findings-main-1bb3381.json`](data/gate-tuning-2026-10-27/findings-main-1bb3381.json) holds all
  162 normalized findings, without messages or snippets. Section 3's tables come from
  [`threshold_sim.py`](data/gate-tuning-2026-10-27/threshold_sim.py) run on that file.

**Scope.** One repo, one target app, three weeks of CI. A *false fail* means the gate went red on
a change that introduced nothing a reviewer should have had to act on. A *false pass* means it
went green when it should have blocked.

## Answers

1. **How often was the gate wrong? 7 false fails and 1 false pass, out of 49 runs that reached a
   security verdict.** All 8 had root causes that are fixed on main now (section 2). The other 22
   red runs were 20 pipeline or scanner errors that stopped before any verdict, plus 2 runs
   cancelled when a newer merge started its own run.
2. **Is HIGH the right threshold? Yes, keep `--fail-on HIGH`.**
   - CRITICAL blocks none of the 7 planted vulnerabilities.
   - MEDIUM blocks no extra planted vulnerability over tuned HIGH, but adds 82 findings (25
     distinct issues), mostly Kubernetes and Docker hygiene checks. It would also fail R3's
     *hardened* manifest on 5 of them.
   - HIGH blocks neither negative control.
3. **Did HIGH miss anything it should block? Yes, two planted classes, now fixed.**
   - The planted XSS (PLANT-008, expected P1) was rated MEDIUM.
   - The root pod (PLANT-007) was MEDIUM in both tools that flag it. It only blocked because of
     other HIGH checks on the same manifest.

   This PR raises both to HIGH. With that, every planted vulnerability a scanner detects would
   block if it were introduced again. The one left over, PLANT-005 (lodash), is detected by no
   scanner at all (section 5).
4. **What will cause the next false fail?** In order of likelihood:
   - a vulnerability database update flagging an unchanged dependency;
   - a PR that changes a scanner without rebaselining;
   - all exceptions expiring on the same day;
   - a scanner outage.

   Section 4 has the mitigations. This PR adds a warning before exceptions expire.

## 1. What the gate decides

`baseline.py check` fails when either of these holds:

- a finding is **new** (not in `security-baseline.json`), rated **HIGH or above**, and has no
  valid exception;
- any exception is expired, malformed, or set to expire more than 90 days out.

Matching ignores line numbers (`tool|rule|file|package`), so moving code does not make its
findings new. The gate job fails closed: it fails unless `baseline.py` exited 0, and since #24 it
also fails if the scan stage did not finish.

## 2. Run history

| Outcome | Runs | Cause | Status |
|---|---|---|---|
| Pass | 33 | | |
| **Correct block**: something new that needed a decision | 2 | Real CVEs in the new scanner lockfile (`r2/checkov-bandit`): accepted with dated exceptions. `curl \| sh` in the new pipeline (`r1/pipelinefortress-ci`): fixed by hash-pinning in #24 | resolved |
| **Correct block**: main carrying debt it never accepted | 3 | After R3's #17 merged the planted app, main reported its 29 planted findings as new | resolved: rebaselined in #24 |
| **Expected block**: a scanner change | 3 | #24 restored Checkov and OSV output that had been silently dropped (141 "new"). #27 added custom rules (6). #29 upgraded Grype (3). Each was old debt seen for the first time, and each PR rebaselined in the same change | by design |
| **False fail**: test data flagged | 1 | gitleaks flagged R4's canary token and a test JWT. Eight *example* exception lines in docs and tests were parsed as real, malformed exceptions | fixed: exact-value allowlist in `.gitleaks.toml`; annotations must follow a comment leader |
| **False fail**: inherited red | 6 | PRs from R5, R4 and R2 (#25, #26, #28) failed on main's 29 unbaselined findings, which none of them touched. Four of them also had 6 gitleaks hits on `match_key` hashes in the baseline file | fixed: main green since #24; `match_key` allowlisted (one rule, one file, 16-hex format) |
| **False pass** | 1 | #17's own run: the baseline step said FAIL (29 blocking), but triage was cancelled, so `50-security-gate` was **skipped**. GitHub counts a skipped required check as passing, and the PR merged | fixed in #24: the gate needs only the baseline job and runs `if: !cancelled()` |
| Error before any verdict | 20 | 14 in the legacy pipeline: gitleaks diffing commits missing from a shallow clone, and gitleaks-action lacking PR permissions. 2 Trivy DB download failures. 2 setup mistakes (a missing lockfile, an action pinned to a SHA that doesn't exist). 2 unit-test failures | legacy pipeline retired; Trivy now tries ghcr.io first |
| Cancelled | 2 | Superseded by the next merge to main | |

**What the false fails have in common.** None was a severity or threshold problem. Each time,
something other than the PR under test was being judged: test data, main's debt, or the
baseline file itself. The false pass was the dangerous one. It let the inherited-red episode
happen: main stayed red for about 27 hours (2026-10-25 12:51 to 2026-10-26 16:22) and every PR in
that window failed for it. A required `50-security-gate` check with branch protection would have
stopped #17 from merging. The repo still has no branch protection (section 5).

## 3. Threshold, from main's real findings

Every finding is treated as new (an empty baseline). "Planted TPs" are the 7 static true positives
in `ground_truth/planted.yaml`, each matched by the finding for the planted condition itself.
Negative controls are PLANT-002 (parameterised query) and PLANT-009 (helmet frameguard).

**Before this PR:**

| fail on | findings | distinct issues | planted TPs blocked | negative controls blocked | hardened manifest blocked |
|---|---|---|---|---|---|
| CRITICAL | 4 | 2 | 0/7 | 0/2 | 0 |
| **HIGH** | 56 | 29 | **4/7** | 0/2 | 0 |
| MEDIUM | 141 | 56 | 6/7 | 0/2 | 5 |
| LOW | 162 | 61 | 6/7 | 0/2 | 6 |

**After this PR:**

| fail on | findings | distinct issues | planted TPs blocked | negative controls blocked | hardened manifest blocked |
|---|---|---|---|---|---|
| CRITICAL | 4 | 2 | 0/7 | 0/2 | 0 |
| **HIGH** | 59 | 31 | **6/7** | 0/2 | 0 |
| MEDIUM | 141 | 56 | 6/7 | 0/2 | 5 |
| LOW | 162 | 61 | 6/7 | 0/2 | 6 |

- **CRITICAL is too loose.** Its only findings are two dependency advisories in vulnshop-api's
  `requirements.txt`: PyYAML 5.3.1 (CVE-2020-14343, reported by three tools) and certifi
  (GHSA-6q48-6c7w-9gw2, OSV only).
- **MEDIUM adds noise, not recall.** Over tuned HIGH it adds 82 findings (25 distinct issues):
  25 Checkov Kubernetes and Docker hygiene checks (probes, resource limits, image digest, network
  policy, …) and medium-rated CVEs. It would block the hardened manifest on
  `CKV_K8S_15/21/38/43` and `CKV2_K8S_6`.
- **Duplication.** The 59 HIGH findings are 31 distinct issues. `routes/pay.py:22` alone produces
  5 findings: 4 Semgrep rules and Bandit. This doesn't change the verdict, but it makes the PR
  comment noisier.

### Changes in this PR

| Change | Why | Effect on main |
|---|---|---|
| `pf-jinja-autoescape-bypass`: WARNING → **ERROR** (HIGH) | The planted P1 XSS rated MEDIUM, so a new `\| safe` on user input passed. In this repo the rule has exactly one hit, the planted one | none: already in the baseline |
| `CKV_K8S_23` (Checkov) and `KSV-0012` (Trivy) → **HIGH** | A root container rated HIGH in a Dockerfile (`DS-0002`, `CKV_DOCKER_3`) but MEDIUM in a pod spec. Same risk, same rating. Neither fires on the hardened manifest | none: already in the baseline |
| `--warn-expiring-days` (default 14) | All 6 current exceptions expire on 2027-01-15. On that day every open PR fails at once, whatever it changes. Each one is now reported as a warning (`warning: exception … expires … (in N days)`) for 14 days beforehand, and counted as `exceptions_expiring` in `gate-report.json`. It does not fail the gate | none today |

Replaying the gate on main's findings with these changes still gives PASS: 162 findings, 152
known, 10 new, all covered by exceptions, 0 blocking. The ratings only matter for findings that
are new.

## 4. False-fail risks that remain

| Risk | Seen? | What happens | Mitigation |
|---|---|---|---|
| **Vulnerability database drift**: a new advisory against an unchanged dependency | Not yet: main (2026-10-26 16:22) and #26 (13 h later) had the same 162 findings | Every PR fails the same day for something none of them changed | Fix or except it in one small PR. **Suggestion for R1:** a nightly scheduled run on main, so drift turns main red, not a contributor's PR |
| **Scanner change without a rebaseline** | 3 times (#24, #27, #29), each handled correctly | The scanner PR goes red on old debt | Rule: a PR that adds, upgrades or reconfigures a scanner or rule includes `baseline.py create` and explains the diff in its description |
| **All exceptions expiring on the same day** | All 6 expire on 2027-01-15 | All PRs fail on 2027-01-16 | This PR's 14-day warning. Spread out expiry dates when renewing |
| **File renames** | No | `match_key` includes the path, so a moved file's findings count as new | Rebaseline in the rename PR. Accepted: matching across renames would need a content hash |
| **Scanner outage** | 2 (Trivy DB) | Fail-closed, so the run goes red with no verdict | Re-run. Trivy tries ghcr.io first; Grype refuses a database more than 5 days old instead of silently missing CVEs |

## 5. Not fixed here

- **No branch protection** (@R1). Without a required `50-security-gate` check the gate is advice,
  not a gate. #17's false pass was a skipped check that nothing required. On this plan that needs
  the repo to be public or a paid upgrade.
- **PLANT-005 (lodash 4.17.15) is detected by no scanner** (@R3). `apps/vulnshop-api` has a
  `package.json` but no `package-lock.json`, and Trivy, Grype and OSV read lockfiles. Committing a
  lockfile would make it detectable (CVE-2020-8203, the planted advisory, is rated HIGH).
- **Cross-tool duplicates** (section 3). The fix is to link GHSA and CVE aliases in
  `scanners/crosscheck/`. That is a schema change, so it needs an ADR (follow-up, after the
  freeze).

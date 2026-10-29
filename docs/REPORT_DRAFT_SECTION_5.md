# Capstone Report Contribution — R2 (Scanners and Policy)

Draft text for **Section 5** (pipeline implementation and why baseline diffing, 2 pages; plan §12)
and R2's rows for **Section 3** (threat model, pipeline side). R1 owns the pipeline YAML and should
review 5.1; R5 integrates. Every number comes from a committed file:

- `docs/metrics/GATE_TUNING.md`: gate run history and threshold simulation (PR #30).
- `docs/metrics/DETECTOR_OVERLAP.md`: detector overlap and planted-vuln coverage (PR #28).
- `scanners/baseline/security-baseline.json` and the CI workflow `.github/workflows/baseline-pipeline.yml`.

Measured on main at `1bb3381` (2026-10-27) unless stated otherwise.

---

## Section 5: Pipeline Implementation and Baseline Diffing

### 5.1 Stages
One workflow, seven jobs. Each scanner writes raw output; everything downstream reads one schema.

| Job | What it does | Fails the build? |
|---|---|---|
| `00-build-and-test` | unit and contract tests | yes |
| `10-security-scanners` | 7 scanners (below), raw output uploaded | only if a scanner cannot run |
| `20-normalize-and-baseline` | raw output → `findings.json` (schema v1.0.0) → new vs known → gate verdict | on bad input or a crash (exit 2) |
| `30-triage-ai`, `40-pr-comment` | R4's local-model triage and the PR comment (§7) | no: degrade, don't block |
| `50-security-gate` | reads the baseline verdict | **yes: the only security verdict** |
| `60-staging-smoke-test` | staging deploy, smoke test, ZAP baseline (R1) | smoke test only; ZAP is advisory |

| Category | Tool (pinned) | Scope |
|---|---|---|
| Secrets | gitleaks 8.30.1 | whole repo, plus a pre-commit hook on staged changes |
| SAST | Semgrep 1.179.0 (`p/default` + 4 custom rules), Bandit | application code |
| SCA | Trivy 0.75.0, Grype 0.120.1, OSV-Scanner 2.6.0 | dependency manifests |
| IaC / config | Checkov, Trivy misconfiguration | Dockerfile, Kubernetes, GitHub Actions |

Two design rules govern this stage:

- **The scanners are supply chain too.** Every binary is checked against a SHA-256 pinned in the
  workflow; Semgrep, Bandit and Checkov install from hash-locked requirement files. A tampered
  release fails the job instead of running with the job's token.
- **Fail closed.** A missing scanner output is an error, not "zero findings". The normalizer
  requires all seven inputs, and the gate job runs even when an earlier job failed
  (`if: !cancelled()`) and fails unless the baseline step returned an explicit 0. We learned this
  the hard way: Checkov and OSV output was being silently dropped, and the gate passed on fewer
  findings than the scanners produced. Restoring them (#24) surfaced 141 findings the gate had
  never seen.

The gate does not wait for the AI stage. The security verdict is deterministic code; the model's
output informs the human reviewer, and nothing the model says can turn the gate red or green.

### 5.2 One schema for seven tools
`scanners/normalize/normalize.py` maps SARIF and native JSON into the schema agreed with R4 in
ADR-001 (`scanners/schema/finding.schema.json`). Every finding is validated against the schema,
gets a stable 16-hex `finding_id`, and the output is byte-identical for the same input. The schema
assigns each block one writer: the normalizer writes the scanner facts, the baseline step writes
`baseline`, and only R4's validator may write `triage`. So the model cannot alter what a scanner
reported.

**Severity is not comparable across tools**, so it is mapped explicitly in
`scanners/normalize/severity_map.yaml`, and changing it needs a PR:

- Semgrep has no CRITICAL, so its ERROR maps to HIGH, not to Trivy's top level.
- OSS Checkov reports every failure as `error`, which carries no information. Checkov failures are
  MEDIUM unless a per-rule override says otherwise (privileged containers, host namespaces, a
  container running as root: HIGH, matching Trivy's rating of the same check).
- OSV-Scanner severity comes from the CVSS score, bucketed with CVSS v3 ranges.
- A gitleaks hit is always HIGH; a low-confidence Bandit result drops one level.
- A vulnerability with no score yet (`UNKNOWN`, often a CVE published days ago) is HIGH, so it
  needs a decision. It used to be INFO, which meant it could never block (#30).

### 5.3 Why baseline diffing
Main carries **162 findings, 56 of them HIGH or CRITICAL**: the planted vulnerabilities in
vulnshop-api, plus real CVEs in dependencies we pin. A gate that fails on any HIGH finding would fail
every PR, regardless of its content. Developers then learn to ignore it. The plan named this
risk ("noise drowns the gate") and gave R2 the counter: the gate fails only on what a PR **adds**.

- **The baseline** (`security-baseline.json`, 152 entries) is accepted existing debt. It is
  created by a command and changed only in a reviewed PR, like code.
- **Matching ignores line numbers, but not code.** Findings are grouped by
  `tool|rule|file|package`, so inserting a line above a known finding does not make it "new". A
  moved finding keeps its baseline slot only if its line still has the same text. The baseline
  stores a hash of it (`line_sha`), ignoring whitespace. Without that, fixing one known SQL
  injection and adding another elsewhere in the file let the new one take the old one's slot.
  A code review found this hole, and #30 closed it.
- **The verdict:** fail if a new finding is HIGH or above and has no valid exception. A known
  finding also blocks if it was accepted below HIGH and has since been re-rated to HIGH or above:
  the debt accepted was not that severe.
- **Exceptions** are comments next to the finding:
  `security-exception: <rule or id> expires:<date> owner:<name>`. They need an owner and an expiry
  at most 90 days out. An expired or malformed exception fails the gate, so accepted risk cannot
  quietly become permanent. Main has 6, all on the scanners' own dependencies, and each states why
  the vulnerable code is not reachable in CI.

Baseline diffing does **not** hide the debt. All 162 findings are still in `findings.json`, still
triaged by §7, and still on the dashboard. It only decides what may block a merge.

### 5.4 Tuning the gate from real data
After three weeks, we labelled all 71 CI runs (`GATE_TUNING.md` §2). Of the 49 runs that reached a
verdict:

| Outcome | Runs | What it was |
|---|---|---|
| Pass | 33 | |
| Correct block | 5 | 2 real issues in new changes, 3 debt main had never accepted |
| Expected block | 3 | a scanner change surfacing old debt, rebaselined in the same PR |
| **False fail** | **7** | 1 test fixture flagged as a secret; 6 PRs failing on main's unbaselined debt |
| **False pass** | **1** | the gate job was *skipped*, which GitHub counts as passing |

The false pass was the most damaging event of the project. On #17 the baseline step said FAIL
(29 blocking), but a cancelled upstream job skipped the gate, and the PR merged. Main stayed red
for about 27 hours, and that caused all six inherited false fails. The fix is the `!cancelled()`
rule in 5.1. The remaining gap is that the repository has no branch protection, so the gate is
still advisory (§5.6).

**Threshold.** We replayed main's findings against each threshold, using the 7 planted true
positives and 2 planted negative controls in `ground_truth/planted.yaml`:

| Fail on | Planted vulns blocked | Negative controls blocked | Hardened manifest blocked |
|---|---|---|---|
| CRITICAL | 0/7 | 0/2 | no |
| **HIGH** (chosen) | **6/7** | 0/2 | no |
| MEDIUM | 6/7 | 0/2 | yes (5 hygiene checks) |

HIGH blocked only 4/7 at first. The planted Jinja XSS was rated MEDIUM, and a root pod was MEDIUM
in Kubernetes while a root Dockerfile was HIGH. Raising those two ratings (#30) fixed both, with no
change to main's verdict. MEDIUM adds 82 findings and no extra planted vulnerability.

Since R3's #42 committed the app's `package-lock.json`, PLANT-005 (lodash CVE-2020-8203, HIGH in
all three SCA tools) is detected as well, so **HIGH now blocks 7/7**. #42 also repeated #17's
mistake. It surfaced 112 new dependency findings, 32 of them blocking, and merged with the gate
red, so main stayed red until #30 accepted them as target-app debt.

### 5.5 Detector overlap
On the SCA side, three tools found 29 distinct vulnerabilities, and 19 of those were found by all three
(`DETECTOR_OVERLAP.md`, measured 2026-10-26, before the app had a lockfile). Every disagreement had a mechanical cause, not a data-quality one:

- OSV-Scanner resolves transitive dependencies; the other two do not.
- Trivy only parses files named `requirements.txt`, so it never scanned our scanner lockfiles.
- Grype missed every CVE published after 2026-03-09. Its pinned version could only download a
  vulnerability database built on that date, and it gave no warning.

Grype found nothing unique. We upgraded it (#29) instead of dropping it, and it now refuses a
database older than five days. We added that check because **a stale vulnerability database is a
silent false pass**.

On static coverage, our four custom Semgrep rules raised detection of the planted vulnerabilities
from 4/7 to 6/7. They are the only detector for the hard-coded AWS key (gitleaks missed it) and
the Jinja XSS. The seventh, PLANT-005, needed a lockfile rather than a rule: once #42 committed
one, all three SCA tools found it, so static detection is 7/7. Each rule has a `semgrep --test` fixture that runs in CI.

### 5.6 Limitations
- **No branch protection.** A red gate does not stop a merge; reviewers do. It happened twice:
  #17 merged through a skipped gate, and #42 merged with the gate red. Both left main red for
  every PR that followed. Protection needs a public repository or a paid plan.
- **We knew what we planted.** The custom rules were written for the planted classes. 7/7 is a bound
  on this app, not a detection rate. Static detection is also not runtime detection: the DAST
  stage has not yet caught a planted vulnerability (see §6).
- **Matching by line text has edge cases.** A known finding that is moved *and* edited in the same
  change counts as new, which is a false fail. A new finding whose line is an exact copy of a fixed
  one takes the fixed one's slot. A renamed file makes all its findings new.
- **Database drift.** A new advisory against an unchanged dependency fails the next PR, whatever it
  changes. We first saw it on 2026-10-29: 6 newly published CVEs against Semgrep's own
  dependencies. They did not block only because they are MEDIUM. A nightly scan of main would
  surface drift before a contributor's PR does.
- **Duplicates.** One vulnerable line can produce up to 5 findings from different tools. The verdict
  is unaffected, but the PR comment is noisier than it needs to be.
- **Inline suppressions don't count.** A `nosemgrep` or `checkov:skip` comment does not waive a
  finding; only a dated, owned exception does. That is deliberate (the same rule CI applies to
  gitleaks), but it means more findings to triage than the tools' defaults.
- **Two versions of one package.** A finding's ID has no package version, so the same CVE in two
  versions in one lockfile is counted once. Putting the version in the ID made it change on
  every upgrade, so we kept the limitation. None of today's findings is affected.
- **Scanners disagree on line breaks.** Checkov and YAML parsers treat form feeds and `\u2028` as
  line breaks; Python's parser and Semgrep don't. In a file containing them, an exception can sit
  one line off its finding. No file in the repository contains them.
- **Rebaselining from the wrong checkout.** `baseline.py create` fingerprints each flagged line in
  the checkout it is given. It warns when a line doesn't exist there (#44), but not when lines have
  only shifted; it must run at the scanned commit.

---

## Section 3 (threat model): R2's pipeline rows

Threats to the scanning and gating stage itself. R5 owns the threat model and may merge these
into the overall table.

| Threat | Example | Control | Evidence | Residual risk |
|---|---|---|---|---|
| Gate silently fails open | a scanner crashes or is skipped; the gate passes on fewer findings | every scanner output is required; gate runs `!cancelled()` and fails unless exit 0 | #24; the #17 false pass in `GATE_TUNING.md` §2 | no branch protection, so a red gate is advisory |
| Tampered scanner | a compromised release runs with the CI token | SHA-256-pinned binaries, hash-locked Python installs, Actions pinned by commit SHA in the scan and gate jobs | workflow install step; `requirements-*.txt` | the pins themselves must be reviewed when bumped |
| Stale detector | an old vulnerability database misses new CVEs | Grype refuses a database older than 5 days | #29; `DETECTOR_OVERLAP.md` §1 | Trivy and OSV have no equivalent age check |
| Risk accepted forever | an exception with no owner or end date | exceptions need an owner and an expiry at most 90 days out; expired or malformed fails the gate; 14-day warning (#30) | `baseline.py`; `tests/test_gate_tuning.py` | all 6 current exceptions expire on one day |
| Debt laundered into the baseline | a PR rebaselines to hide a new finding | baseline changes only in a reviewed PR; its diff shows every accepted finding | `security-baseline.json` history | relies on the reviewer reading the diff |
| New finding hidden as old | fix one known finding and add another of the same rule in the same file; or a known CVE re-rated from LOW to CRITICAL | a moved finding must keep its line text (`line_sha`); a known finding re-rated across the threshold blocks again; an unscored CVE is HIGH | #30; `tests/test_gate_tuning.py` | an exact copy of a fixed line still inherits its slot |
| Secret committed | a developer commits a key | gitleaks pre-commit hook (staged changes) and gitleaks in CI | `scripts/install_hooks.py`, `.gitleaks.toml` | the hook is opt-in per clone; the custom Semgrep rule is the only detector for the planted AWS key |
| Scanner input evaluates code | a PR adds a Terraform file that Checkov evaluates with `asteval` | Checkov limited to Dockerfile, Kubernetes and GitHub Actions | workflow comment; exception rationale in `requirements-scanners.txt` | re-enable other frameworks only after an `asteval` fix |
| Model alters the verdict | prompt injection makes the model clear a finding | the gate reads only `baseline.py`'s exit code; the model writes only `triage` | ADR-001; gate job `needs` | none known for the gate; see §7 for the comment |

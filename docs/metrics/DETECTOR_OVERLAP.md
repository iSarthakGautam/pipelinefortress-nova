# Detector overlap: which scanners agree, and can we drop one?

Owner: R2. Measured 2026-10-26 on one CI run of the full pipeline (run 40279942757, PR #27 head
`f73f0fb` = main + #24 scanner fixes + #27 custom Semgrep rules), against R3's
`ground_truth/planted.yaml`. Evidence snapshot (CI artifacts expire after 7 days):
[`data/detector-overlap-2026-10-26/`](data/detector-overlap-2026-10-26/): `sca-crosscheck.json`
(output of `scanners/crosscheck/crosscheck.py`) and `findings-index.csv` (all 152 normalized
findings, without snippets or messages).

**Scope and limits.** One target app, one run, 29 distinct SCA vulnerabilities and 7 planted true
positives. These are observations about *this* repo and *these pinned versions*, not general claims
about the tools. ZAP (DAST, staging job) is not included.

## Answers

1. **Can we drop a redundant SCA tool? Yes: Grype, as currently pinned.** It found nothing the
   others missed (0 unique of 29), it is the slowest scanner (26–29 s vs Trivy 9–10 s, OSV 2–4 s),
   and **its vulnerability database is frozen at 2026-03-09**. Every CVE published before that date
   was found by Grype; every one published after it was missed (table below). Grype 0.86.1 reads DB
   schema v5; it downloaded a fresh copy in CI, and the newest v5 database it could get was built
   on 2026-03-09. It printed no warning. Either upgrade Grype to a
   release on the current DB schema and re-measure, or remove it. Keeping it as-is adds runtime and
   a false sense of a third opinion.
2. **Trivy and OSV disagree mainly on *what they read*, not on vulnerability data.** OSV-Scanner v2
   resolves transitive dependencies (it reported `certifi` and `idna`, which our requirements file
   does not pin), and Trivy never scanned `requirements-scanners.txt` (our own scanner supply chain)
   or `requirements-dev.txt`: neither is in its target list, and its pip analyzer looks for files
   named `requirements.txt`. Where both read the same pinned
   package, they agreed on every vulnerability.
3. **No SCA tool detected the planted npm vulnerability (PLANT-005, lodash 4.17.15).** All three
   resolve npm dependencies from a lockfile, and `apps/vulnshop-api/` has `package.json` only.
   *Update 2026-10-29:* R3 committed `package-lock.json` in #42. Trivy, Grype and OSV now all
   report lodash CVE-2020-8203 (HIGH), so static detection is 7/7. The rest of this document is
   the 2026-10-26 snapshot.
4. **Static detection of the 7 planted true positives: 6/7 with our custom Semgrep rules, 4/7
   without them.** The custom rules are the only detector for PLANT-003 (hard-coded AWS key; gitleaks
   misses it) and PLANT-008 (Jinja `| safe` XSS). Neither negative control (PLANT-002, PLANT-009)
   was flagged by any tool for its vulnerability class.
5. **IaC: Checkov covers every Kubernetes control Trivy does, and more** (18 controls vs 12), but
   the tools report the same weakness on different lines (Checkov: line 1; Trivy: line 16; Semgrep:
   line 20). Nothing location-based can merge them.

## 1. SCA: Trivy vs Grype vs OSV-Scanner

| Tool (pinned) | Found | Only this tool | Runtime in CI (3 runs) |
|---|---|---|---|
| Trivy 0.75.0 | 23 | 0 | 9–10 s |
| Grype 0.86.1 | 20 | 0 | 26–29 s |
| OSV-Scanner 2.6.0 | 29 | 5 | 2–4 s |

29 distinct vulnerabilities; 19 found by all three. Pairwise Jaccard: Trivy+Grype 0.79,
Trivy+OSV 0.79, Grype+OSV 0.69. On this data Trivy ⊂ OSV and Grype ⊂ Trivy ∪ OSV.
Linking rule (crosscheck.py): same manifest, same normalized package name, any shared ID (CVE or
GHSA alias), transitively.

**Why each disagreement happened.** Every one of the 10 non-unanimous vulnerabilities has one of
three causes:

| Cause | Vulnerabilities | Effect |
|---|---|---|
| Grype's stale DB (built 2026-03-09) | requests CVE-2026-25645 (published 2026-03-25); urllib3 CVE-2026-44431 (05-13), CVE-2026-97687, CVE-2026-97689 (09-29) | Grype misses 4 |
| OSV resolves transitive deps of `apps/vulnshop-api/requirements.txt` | certifi GHSA-6q48-6c7w-9gw2; idna CVE-2024-3651, CVE-2026-45409 | OSV-only, 3 |
| Trivy does not parse `requirements-scanners.txt` | asteval CVE-2026-102734, CVE-2026-55244 (OSV only: also not in Grype's DB); ecdsa CVE-2024-23342 (Grype + OSV) | Trivy misses 3 |

Grype's cut-off is exact: all 19 CVEs Trivy reported with a publish date up to 2026-02-21 were
found by Grype; all 4 published after 2026-03-09 were not (`descriptor.db.built` in Grype's JSON).

**Caveat on OSV's transitive findings.** `certifi 2026.7.22` and `idna 2.9.0` are versions OSV's
resolver *chose*; the requirements file does not pin them. As PyPI changes, these findings will
change between runs with no code change. That is useful signal (pip would install *some* version),
but it is a source of gate churn. See "Consequences for the gate".

**Severity disagreements (3).** jinja2 CVE-2024-56201 and CVE-2024-56326: OSV HIGH, Trivy and Grype
MEDIUM. flask CVE-2026-27205: OSV MEDIUM, others LOW. OSV's severity comes from the CVSS score
bucket (`normalize.cvss_bucket`); Trivy and Grype report a vendor/ecosystem rating. Fix
availability agreed in every case.

## 2. Planted vulnerabilities × detector

✓ = the tool flagged the planted weakness; ✗ = expected or plausible detector, not flagged.
Code findings count within ±2 lines of the catalogued line. Manifest, Dockerfile and Kubernetes
findings count by matching control (see section 3), because those tools report at the resource
(line 0/1), not at the planted line.

| Planted | Class | Semgrep p/default | Semgrep custom | Bandit | gitleaks | Trivy | Grype | OSV | Checkov |
|---|---|---|---|---|---|---|---|---|---|
| PLANT-001 SQLi | CWE-89 | ✓ | ✓ | ✓ (B608, LOW) | | | | | |
| PLANT-003 AWS key | CWE-798 | ✗ | ✓ | ✗ ¹ | ✗ ² | | | | |
| PLANT-004 cmd injection | CWE-78 | ✓ | ✓ | ✓ (B602) | | | | | |
| PLANT-005 lodash | CWE-1321 | | | | | ✗ ³ | ✗ ³ | ✗ ³ | |
| PLANT-006 Dockerfile root/latest | CWE-250 | ✓ (missing-user) | | | | ✓ (DS-0002, DS-0001) | | | ✓ (CKV_DOCKER_3, _7) |
| PLANT-007 k8s runAsNonRoot: false | CWE-276 | ✗ ⁴ | | | | ✓ (KSV-0012, -0020) | | | ✓ (CKV_K8S_23, _40) |
| PLANT-008 Jinja `\| safe` | CWE-79 | ✗ | ✓ | | | | | | |
| PLANT-002 (neg. control) | CWE-89 | – | – | – | | | | | |
| PLANT-009 (neg. control) | CWE-1021 | – ⁵ | | | | | | | |

– = correctly not flagged.
1. Bandit B105 flags `SECRET_KEY` (line 10) and `AWS_SECRET` (line 13), but not `AWS_KEY` (line 12):
   its name heuristic has no "key".
2. The planted value is AWS's documented example key (`…EXAMPLE`). gitleaks' default rules do not
   flag it; the same rule does flag a non-EXAMPLE `AKIA…` key (`tests/test_install_hooks.py`
   end-to-end test).
3. No `package-lock.json`. All three resolve npm packages from lockfiles.
4. Semgrep flags `allowPrivilegeEscalation` on the same container (line 20), a different control.
5. Semgrep's `server.js` finding is a missing-CSRF-middleware check (CWE-352), not clickjacking.

**Static detection of the 7 true positives:** 6/7 with custom rules (all but PLANT-005), 4/7
without. **Detectors per planted item:** SQLi and command injection are each caught by 3 detectors;
the secret and the XSS by exactly one (our own rule); the npm dependency by none.

## 3. IaC: Checkov vs Trivy (vs Semgrep)

`docker/Dockerfile`: the same 3 controls from Checkov and Trivy: root user (CKV_DOCKER_3 = DS-0002,
also Semgrep `missing-user`), `:latest` tag (CKV_DOCKER_7 = DS-0001), no HEALTHCHECK
(CKV_DOCKER_2 = DS-0026).

`infra/k8s/deployment.yaml`: 36 findings (Checkov 19, Trivy 16, Semgrep 1) for **18 distinct
controls**:

| Control | Checkov | Trivy |
|---|---|---|
| Privilege escalation (also Semgrep) | CKV_K8S_20 | KSV-0001 |
| Runs as root | CKV_K8S_23 | KSV-0012 |
| Low UID / GID | CKV_K8S_40 | KSV-0020, KSV-0021 |
| Root filesystem writable | CKV_K8S_22 (MEDIUM) | KSV-0014 (HIGH) |
| CPU / memory requests and limits (4) | CKV_K8S_10, 11, 12, 13 | KSV-0015, 0011, 0016, 0018 |
| Seccomp | CKV_K8S_31 | KSV-0030, KSV-0104 |
| Capabilities | CKV_K8S_37, CKV_K8S_28 | KSV-0003, 0004, 0106 |
| Default namespace | CKV_K8S_21 | KSV-0110 |
| Security context | CKV_K8S_29 (MEDIUM) | KSV-0118 (HIGH) |
| NetworkPolicy, pull policy, SA token mount, image digest, liveness, readiness (6) | CKV2_K8S_6, CKV_K8S_15, 38, 43, 8, 9 | – |

Trivy's Kubernetes controls ⊂ Checkov's on this manifest. The hardened variants confirm both are
measuring the same thing: `deployment.hardened.yaml` drops to 5 Checkov / 1 Trivy findings (all
namespace/policy level), and Trivy reports 0 for `Dockerfile.hardened`.

Trivy should stay anyway: it is the brief's SCA default and its misconfig scan costs nothing
extra (same 9–10 s run). Dropping it from IaC would not be worth a second configuration.

## 4. Consequences for the gate and for triage

- **Effective severity is the maximum across tools.** Each tool's finding is gated on its own, so
  OSV's HIGH on the jinja2 CVEs and Trivy's HIGH on KSV-0014/-0118 block even though the other tools
  rate them MEDIUM. Adding a scanner can only add blocks.
- **One weakness, many findings.** PLANT-001's two injection sites produce 11 findings (Semgrep
  p/default 7, custom 2, Bandit 2); PLANT-004's single line produces 5. The 18 Kubernetes controls
  produce 36. R4's clustering keys on `rule_id`, so none of these merge across tools. Input for the
  noise-reduction metric (R4/R5); a cross-tool merge would need a control map like the table above,
  since Checkov's SARIF carries no CWE.
- **OSV's transitive resolution is a false-fail risk.** A new PyPI release can change which version
  OSV resolves and add a "new" HIGH with no code change. It hasn't happened yet; watch for it in the
  false-fail analysis.
- **Silent coverage loss is the real risk, not overlap.** Grype's frozen DB and Trivy's filename
  rule both reduce coverage without any error. Neither shows up unless tools are compared like this.

## Follow-ups

| What | Owner |
|---|---|
| ~~Upgrade Grype to a current-DB release and re-run this, or remove it~~ Done in #29 (see Update below) | R2 |
| Add `apps/vulnshop-api/package-lock.json` so PLANT-005 is detectable, or record it as an expected miss | R3 |
| Make Trivy read `requirements-scanners.txt` / `requirements-dev.txt` (or accept OSV+Grype covering them) | R2 |
| ~~asteval 1.0.6 → 1.0.9~~ Not possible (checkov pins it); made unreachable in #29 | R2 |
| Link findings across GHSA/CVE aliases in crosscheck (the schema keeps only CVE ids) | R2 |
| PLANT-003 is catalogued for gitleaks, which cannot see the example key: retarget to the custom Semgrep rule or plant a non-example key | R3 |
| Cross-tool control map for the noise-reduction metric | R4 / R5 |

## Update: Grype upgraded (#29)

Grype 0.120.1 (DB schema v6, built 2026-10-25) re-run with the same Trivy/OSV results:
found by all three **19 → 23**; Grype now matches Trivy on all 23 CVEs in
`apps/vulnshop-api/requirements.txt`; pairwise Jaccard Trivy+Grype 0.79 → 0.89, Grype+OSV
0.69 → 0.83. Grype still has **0 unique findings**: its one apparent unique (asteval
`GHSA-9w56-46f6-3qhx`) is OSV's `CVE-2026-102734`, which crosscheck cannot link because the
normalized schema keeps only CVE aliases. The remaining disagreements are all about which files a
tool reads (OSV's transitive resolution; Trivy skipping `requirements-scanners.txt`).

**Cost:** the Grype step went from 26–29 s to ~61 s, because the v6 DB download is larger. Grype is
now a working second opinion, but on this repo it is still redundant with OSV. Whether to keep it for
the three-way disagreement metric or drop it to save a minute per run is the team's call.

The upgrade also surfaced two asteval 1.0.6 sandbox escapes in `requirements-scanners.txt`. Checkov
pins `asteval==1.0.6` in every release through 3.3.30, so #29 makes them unreachable instead:
Checkov now runs only the `dockerfile kubernetes github_actions` frameworks, and asteval is only
used by its terraform/cloudformation rendering.

## Reproduce

```sh
gh run download 40279942757 -n normalized-findings -D artifacts/
python scanners/crosscheck/crosscheck.py --findings artifacts/findings.json \
    -o artifacts/sca-crosscheck.json --markdown artifacts/sca-crosscheck.md
```
Grype's DB date is `descriptor.db.built` in the raw `grype.json` (artifact `raw-scans`); CVE publish
dates are Trivy's `PublishedDate`; step runtimes are from the GitHub Actions jobs API for runs
40274765896, 40279343627 and 40279942757.

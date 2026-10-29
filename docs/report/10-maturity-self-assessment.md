# 10. DevSecOps maturity self-assessment

Scored against the OWASP DevSecOps Maturity Model (DSOMM) levels 1 (basic) to 4 (advanced), by the team, from what the repository evidences. A level is claimed only if an artifact exists.

| DSOMM dimension | Level | Evidence | What stops the next level |
|---|:---:|---|---|
| Static depth (SAST) | 3 | Semgrep with our own rules (`scanners/semgrep/rules/`, tested with `semgrep --test` in CI) plus Bandit | No taint-level analysis or IDE integration |
| Dynamic depth (DAST) | 2 | ZAP baseline against staging, advisory | Passive scan only; not gating; no authenticated scan |
| Dependencies / SCA | 3 | Trivy, Grype and OSV-Scanner cross-checked; detector-overlap metric; exceptions with owner and expiry | No reachability analysis; EPSS/KEV tables are a sample |
| Secrets | 3 | gitleaks in CI and pre-commit, suppressions only as exact values, inline allow ignored | The planted example key is invisible to it; no secret rotation drill |
| Infrastructure as code | 3 | Checkov + Rego policy mapped to CIS; hardened manifest; a test that the bad manifest fails | Admission control (Kyverno) not built |
| Build and deployment | 3 | SHA-pinned actions, hash-pinned scanners, least-privilege permissions, kind deploy stage | No signing or provenance (cosign/SLSA) |
| Hardening of images | 2 | Non-root multi-stage image, digest-pinned base, SBOM (CycloneDX + SPDX), image scan | Not yet signed; scan results advisory |
| Test and verification (gate) | 4 | Baseline diffing, fail-closed gate, expiring exceptions, gate tuned from 71 real runs | The known baseline-slot weakness (§11) |
| Monitoring and metrics | 2 | Prometheus + Grafana dashboard, catch rate, anti-vanity catalogue | No push from CI; no trend over time |
| AI-assisted triage (extension) | 3 | Redaction, grounding validator, injection defence, replay log, bake-off with ablations | Evaluation set too small to claim accuracy |
| Governance and process | 2 | ADRs, evidence index, AI-disclosure log, local branch protection | Server-side branch protection unavailable; reviews were not always recorded on GitHub |

**Overall: level 2-3.** The weakest honest spots are runtime (Falco not built), signing, and an evaluation set large enough to support a quality claim.

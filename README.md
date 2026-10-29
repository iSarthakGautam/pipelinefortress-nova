# PipelineFortress

**Secure CI/CD with GenAI-Assisted Triage**

## Project Overview

PipelineFortress is a reference shift-left CI/CD pipeline designed to catch vulnerabilities before they are merged. It incorporates a suite of DevSecOps tools and leverages a GenAI assistant for intelligent triage of security findings. 

The core target is a deliberately vulnerable application (OWASP Juice Shop) combined with a custom `vulnshop-api` that we will wrap in our secure CI/CD pipeline.

**Core Grading Rubric Constraint:**
*Anyone can rebuild this from the repo in under an hour, and every claim the model makes is checkable against evidence we also ship.*

---

## The Async Contract
We are a team of 5 working full-time. We build for async by default:
- **Tuesday 30 min sync**: Unblock. What will stop you shipping by the weekend?
- **Saturday 30 min sync**: Demo and plan. Teach-backs.
- **One contract**: We agree on a unified `findings.json` schema on Day 1.
- **Stub first**: Don't block others. Ship stubs (e.g., `stub_triage.py`) so consumers can build their parts immediately.

## The Five Roles

| Role | Focus |
|---|---|
| **R1 (Pipeline & Team Lead)** | CI/CD workflows, kind cluster, gating logic, repo governance. |
| **R2 (Scanners & Policy)** | SAST, SCA, secrets, unified schema, baseline diffing, cross-check metrics. |
| **R3 (Container & Supply Chain)** | Hardened Dockerfile, SBOM, IaC policies, builds the planted vulnerabilities. |
| **R4 (AI & GenAI Lead)** | Local open-weight LLM triage, redaction layers, grounding validator, auto-PR bot. |
| **R5 (Data, Metrics, Report)** | Ground truth, Grafana dashboard, evidence trail, final report integration. |

---

## Quickstart (rebuild check, target: under an hour)

Needs Python 3.12+ and `make`. Docker is only needed for `lab-up` and `dash`; Ollama only for the model-backed targets.

```bash
make bootstrap        # pip install (hash-pinned dev deps) + install the git hooks
make test             # 190+ unit and contract tests, no network, no model needed
make eval-report      # rebuild eval/results.md from the frozen runs in eval/results/ (no model call)
make demo-local       # stub scanner input -> real local model -> PR comment, metrics, trace (needs Ollama + llama3)
make catch-rate       # pre-merge catch rate vs the planted vulnerabilities (needs artifacts/findings.json from CI or make normalize)
make policy           # Rego policy-as-code check with conftest (hardened manifest must pass, bad one must fail)
make report           # assemble docs/report/ into build/report.md and build/report.html
make runtime-baseline # probe the lab app on loopback and rewrite docs/BASELINE_VULNERABILITY_REPORT.md (needs Flask)
make demo-prep        # build the offline results dashboard + report and open every demo window (see demo/DEMO_SCRIPT.md)
make demo-slides      # the 20-slide animated demo deck (also: open demo/index.html); script in demo/DEMO_SCRIPT.md
make dash             # Prometheus + Pushgateway + Grafana on http://localhost:3001 (admin/admin unless GRAFANA_ADMIN_PASSWORD is set; bound to 127.0.0.1)
```

Scanning (`make scan`, `make normalize`, `make gate`) needs the scanner binaries, which CI installs with pinned versions
and sha256 checks (`.github/workflows/baseline-pipeline.yml`, job `10-security-scanners`). The CI run is the reference.

## Project Structure

- `apps/`: vulnerable targets: `vulnshop-api` (our service, planted vulns) and `juice-shop` (pointer + pinned SHA/digest).
- `ground_truth/planted.yaml`: the planted vulnerabilities (R3). `eval/ground_truth.jsonl`: the 10-row synthetic smoke set.
- `.github/workflows/`: the pipeline: build/test, scanners, normalize + baseline gate, AI triage, PR comment, security gate, staging + ZAP.
- `scanners/`: normalizer, baseline diffing + exceptions, SCA cross-check, custom Semgrep rules, finding schema.
- `ai/`: triage subsystem (redaction L1-L4, egress guard, injection defence, grounding validator, PR bot, `models.lock.yaml`).
- `eval/`, `tests/`: evaluation harness with frozen results, ground-truth tooling (`eval/ground_truth/`), unit and contract tests.
- `docker/`, `infra/`: vulnerable and hardened Dockerfiles, staging compose, Kubernetes manifests (bad and hardened).
- `dashboards/`: Grafana + Prometheus + Pushgateway stack and the committed dashboard JSON.
- `docs/`: ADRs, metrics catalogue, report drafts, `AI_DISCLOSURE.md`, `LICENSES.md`; `artifacts/evidence/INDEX.md`: evidence index.

---

## Local Branch Protection (Mandatory)
Because we are using a private repository on a free GitHub account, server-side branch protection rules are disabled. To fulfill the rubric requirement of "no direct pushes to main", **every team member must run this command immediately after cloning the repo**. 

This installs local git hooks: a pre-push hook that refuses any push to `main`, and a gitleaks pre-commit hook that blocks staged secrets. It works on Windows (Git Bash), macOS and Linux:

```bash
python scripts/install_hooks.py
```

If you installed the older copy-paste hook from this README, run the command anyway: it replaces it. That hook checked the checked-out branch, so `git push origin feature:main` from a feature branch got through.

---

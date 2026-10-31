# PipelineFortress

**Secure CI/CD with GenAI-Assisted Triage**  
**Repository:** [https://github.com/iSarthakGautam/pipelinefortress-nova](https://github.com/iSarthakGautam/pipelinefortress-nova)  
**Final Capstone Report:** [📄 Markdown (`docs/REPORT.md`)](docs/REPORT.md) | [📑 PDF Publication (`docs/REPORT.pdf`)](docs/REPORT.pdf) | [🌐 HTML Report (`docs/REPORT.html`)](docs/REPORT.html)

## Project Overview

PipelineFortress is a reference shift-left CI/CD pipeline designed to catch vulnerabilities before they are merged. It incorporates a suite of DevSecOps tools and leverages a GenAI assistant for intelligent triage of security findings. 

The core target is a deliberately vulnerable application (OWASP Juice Shop) combined with a custom `vulnshop-api` that we will wrap in our secure CI/CD pipeline.

**Core Grading Rubric Constraint:**
*Anyone can rebuild this from the repo in under an hour, and every claim the model makes is checkable against evidence we also ship.*

---

## 📑 Final Capstone Report

The complete, unabridged project report is available in multiple formats directly in [`docs/`](docs/):
- **Markdown Publication:** [`docs/REPORT.md`](docs/REPORT.md) (viewable directly on GitHub with full tables, SVG diagrams, and evidence figures)
- **PDF Publication:** [`docs/REPORT.pdf`](docs/REPORT.pdf) (formatted 22-page publication-ready document)
- **Interactive HTML Report:** [`docs/REPORT.html`](docs/REPORT.html) (standalone styled web report)
- **Chapter Sources:** [`docs/report/`](docs/report/) (14 modular markdown chapters)

---

## 📦 Capstone Deliverables Verification Matrix

| # | Required Deliverable | Status | Repository Paths & Evidence | Key Verification Details |
|---|---|:---:|---|---|
| **1** | **Hardened CI/CD pipeline (YAML)** | **Delivered** | [`.github/workflows/baseline-pipeline.yml`](.github/workflows/baseline-pipeline.yml) (540 lines) | • Multi-scanner DAG: Semgrep (SAST), Gitleaks (Secrets), Trivy, Grype, and OSV-Scanner (SCA).<br>• Canonical normalization (R2) + deterministic merge gate (R1) against frozen baseline.<br>• Local open-weight LLM triage stage with strict fail-closed degradation (`NEEDS_HUMAN_REVIEW`).<br>• Container build, Syft SBOM, Checkov IaC, ZAP DAST advisory, and Kind cluster deployment test. |
| **2** | **Policy-as-code rules (Checkov/OPA)** | **Delivered** | [`infra/policy/k8s.rego`](infra/policy/k8s.rego)<br>[`ai/policy_bot.py`](ai/policy_bot.py)<br>CI Stage 55 (Checkov) | • **OPA/Rego:** Enforces CIS Kubernetes Benchmark 5.2.x/5.7 (disallows `privileged: true`, mandates non-root execution, drops capabilities).<br>• **Checkov:** Static IaC scan executed in CI stage 55 across manifests and Dockerfiles.<br>• **Policy Bot:** LLM-assisted policy explainer with grounding validation against hallucinated settings. |
| **3** | **Hardened container image with SBOM (Syft output)** | **Delivered** | [`docker/Dockerfile.hardened`](docker/Dockerfile.hardened)<br>[`docker/Dockerfile`](docker/Dockerfile)<br>[`artifacts/sbom/models.cdx.json`](artifacts/sbom/models.cdx.json) | • **Container:** Multi-stage build, non-root `appuser`, read-only rootfs compatibility, stripped build tools.<br>• **SBOM:** Anchore Syft CycloneDX generation in CI stage 55 (`artifacts/sbom/app.cdx.json`) plus CycloneDX SBOM for AI models. |
| **4** | **LLM triage tool + redaction layer + prompt library** | **Delivered** | [`ai/triage.py`](ai/triage.py)<br>[`ai/redaction/redactor.py`](ai/redaction/redactor.py)<br>[`ai/validate.py`](ai/validate.py)<br>[`ai/prompts/`](ai/prompts/) | • **Pipeline:** 5-step deterministic & bounded workflow (Cluster → Protect → Generate → Verify → Decide).<br>• **Redaction:** 4 layers (L1 structural allowlist, L2 regex/entropy secrets, L3 entities, L4 pre-egress canary tripwire).<br>• **Validation:** Offline MITRE CWE catalogue (v4.20, 1,391 IDs), CISA KEV, and EPSS registry.<br>• **Prompts:** 10 versioned prompt templates under `ai/prompts/`. |
| **5** | **3 auto-generated remediation PRs (+ review notes)** | **Delivered** | [`artifacts/prs/v2/`](artifacts/prs/v2/)<br>[`artifacts/prs/reviews/`](artifacts/prs/reviews/)<br>[`artifacts/prs/PR_REGISTER.md`](artifacts/prs/PR_REGISTER.md) | • **4 generated PR patches** (exceeds requirement of 3): `pr-001` (Dockerfile non-root), `pr-002` (K8s securityContext), `pr-003` (Lodash bump), `pr-004` (SQLi parameterization).<br>• **4 formal human review notes** with explicit verdicts (2 accepted with limits, 2 rejected for non-application/regression risk). |
| **6** | **Metrics dashboard** | **Delivered** | [`dashboards/grafana/dashboards/pipelinefortress-ai.json`](dashboards/grafana/dashboards/pipelinefortress-ai.json)<br>[`artifacts/evidence/grafana-pipelinefortress-dashboard.png`](artifacts/evidence/grafana-pipelinefortress-dashboard.png)<br>[`docs/metrics/`](docs/metrics/) | • Grafana dashboard visualizing triage latency, model verdicts (TP, FP, NEEDS_HUMAN_REVIEW), token usage, grounding rejection rates, and detector overlap.<br>• Prometheus Pushgateway integration configs and evidence screenshot embedded in Chapter 4.4 of the report. |
| **7** | **12–15 page final report incl. DevSecOps maturity** | **Delivered** | [`docs/REPORT.pdf`](docs/REPORT.pdf) (22 pages)<br>[`docs/REPORT.md`](docs/REPORT.md)<br>[`docs/REPORT.html`](docs/REPORT.html)<br>[`docs/report/10-maturity-self-assessment.md`](docs/report/10-maturity-self-assessment.md) | • **Page Count:** 22 pages (satisfies and exceeds the 12–15 page minimum).<br>• **Maturity Assessment:** Dedicated Section 10 evaluating 6 core pillars across Levels 1–4.<br>• **Formats:** Synchronized across Markdown, styled standalone HTML with sidebar navigation, and PDF. |

---

## 🎬 Interactive Demo & Presentation Deck

PipelineFortress includes a standalone 20-slide interactive presentation deck, attack simulations, and an offline results dashboard inside the [`demo/`](demo/) folder:

- **Launch Interactive Deck**:
  ```bash
  open demo/index.html          # macOS: opens directly in default browser
  # or
  xdg-open demo/index.html      # Linux
  start demo/index.html         # Windows
  # or run via local HTTP server:
  make demo-slides              # serves at http://localhost:8080
  ```
  *(Zero dependencies, pure HTML5/CSS/JS — no npm, build step, or network required)*

- **Spoken Script & Rehearsal Guide**: See [`demo/DEMO_SCRIPT.md`](demo/DEMO_SCRIPT.md) for the timed word-for-word walkthrough (8:40 main path / 11-min extended), slide-by-slide cues, attack simulation triggers, and Q&A defense.
- **Offline Results Dashboard**: Open [`demo/results.html`](demo/results.html) or run `make demo-prep` to assemble all report artifacts and inspect metrics offline.
- **Key Navigation Shortcuts**:
  - `→` / `Space` : Next step / advance attack animation
  - `←` : Back one step
  - `A` : Replay attack simulation on the current slide
  - `N` : Toggle speaker notes and countdown timer
  - `P` : Export all 20 slides to PDF
  - `F` : Toggle fullscreen

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
make report           # assemble docs/report/ into docs/REPORT.md, docs/REPORT.html, and docs/REPORT.pdf
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
- `demo/`: 20-slide animated presentation deck (`demo/index.html`), spoken guide (`demo/DEMO_SCRIPT.md`), and offline results dashboard (`demo/results.html`).
- `docs/`: Final capstone report (`docs/REPORT.md`, `docs/REPORT.pdf`, `docs/REPORT.html`), modular chapters (`docs/report/`), ADRs, metrics catalogue, `AI_DISCLOSURE.md`, `LICENSES.md`; `artifacts/evidence/INDEX.md`: evidence index.

---

## Local Branch Protection (Mandatory)
Because we are using a private repository on a free GitHub account, server-side branch protection rules are disabled. To fulfill the rubric requirement of "no direct pushes to main", **every team member must run this command immediately after cloning the repo**. 

This installs local git hooks: a pre-push hook that refuses any push to `main`, and a gitleaks pre-commit hook that blocks staged secrets. It works on Windows (Git Bash), macOS and Linux:

```bash
python scripts/install_hooks.py
```

If you installed the older copy-paste hook from this README, run the command anyway: it replaces it. That hook checked the checked-out branch, so `git push origin feature:main` from a feature branch got through.

---

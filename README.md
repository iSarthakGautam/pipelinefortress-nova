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

## Project Structure (WIP)

- `apps/`: Vulnerable target apps (`juice-shop` fork, `vulnshop-api`).
- `.github/workflows/`: CI/CD pipeline definitions.
- `infra/` & `docker/`: Kubernetes configurations and hardened Dockerfiles.
- `scanners/`: Tool configurations and the baseline/security-baseline.json.
- `ai/`: The GenAI triage subsystem (models.lock.yaml, llm_client, redaction, prompts).
- `eval/`, `tests/`, `dashboards/`: Evaluation harnesses, test suites, and Grafana JSONs.
- `docs/`: Project documentation, architecture decisions (ADRs), and evidence.

---

## Local Git Hooks (Mandatory)
Because we are using a private repository on a free GitHub account, server-side branch protection rules are disabled. **Every team member must run this once after cloning** (Windows Git Bash, macOS or Linux):

```bash
python scripts/install_hooks.py
```

It installs two hooks:
- **pre-push** refuses direct pushes to `main`. This is the team contract hook; the old copy-paste version is upgraded in place.
- **pre-commit** runs gitleaks 8.30.1 on your *staged* changes and blocks the commit if it finds a secret. The binary is downloaded into `.git/hooks/bin/` and checked against SHA-256 values pinned in the script.

If a commit is blocked:
- A **real** secret gets removed and **rotated**, and you tell the team the same day.
- A **known fake** (test fixture, canary) gets its exact value allowlisted in `.gitleaks.toml` through a PR. Inline `gitleaks:allow` comments are ignored, locally and in CI.
- A **deliberately planted** secret (R3) is committed with `git commit --no-verify` and never allowlisted, because CI is meant to catch it.

Re-run the script any time to update the hooks. `--uninstall` removes them.

---

## Getting Started (Week 1 Foundation)
- **R1**: Setup the `make bootstrap` process and basic `.github/workflows`.
- **R2**: Propose the unified JSON finding schema.
- **R3**: Pin the Juice Shop fork and start `vulnshop-api`.
- **R4**: Ship `stub_triage.py` returning fake JSON data matching R2's schema.
- **R5**: Setup `WEEKLOG.md` and report skeletons.

Check `docs/CONTRIBUTIONS.md` (to be created by R1) to track progress.

# PipelineFortress

**Secure CI/CD with GenAI-Assisted Triage**

## Project Overview

PipelineFortress is a reference shift-left CI/CD pipeline designed to catch vulnerabilities before they are merged. It incorporates a suite of DevSecOps tools and leverages a GenAI assistant for intelligent triage of security findings. 

Our core target is a deliberately vulnerable application (e.g., OWASP Juice Shop) that we will wrap in our secure CI/CD pipeline.

## Project Structure

- `target-app/`: The vulnerable target application we are deploying and scanning.
- `.github/workflows/`: CI/CD pipeline definitions.
- `scripts/`: Deployment scripts and utility tools (e.g., local `kind` cluster setup).
- `llm-triage/`: The GenAI triage tool, redaction layer, and automation scripts.
- `docs/`: Project documentation, reports, and team findings.

## Phase 1: Baseline Pipeline (Week 1)
- [ ] Add the target application (OWASP Juice Shop).
- [ ] Establish a baseline pipeline to build, test, and deploy to a local `kind` cluster.
- [ ] Integrate foundational security gates:
  - **SAST**: Semgrep
  - **SCA**: Trivy
  - **Secrets Scanning**: gitleaks

## Phase 2: Shift-Left Coverage (Week 2)
- [ ] Integrate IaC scanning (Checkov).
- [ ] Build and scan container images (Trivy), generate SBOM (Syft).
- [ ] Integrate baseline DAST scanning (OWASP ZAP).
- [ ] Build a metrics dashboard to visualize vulnerabilities by stage.

## Phase 3: GenAI Triage (Week 3)
- [ ] Build the LLM triage tool to deduplicate and prioritize findings.
- [ ] Implement a **Redaction Layer** to strip secrets/proprietary info before it reaches the LLM.
- [ ] Automate GenAI-drafted Pull Requests with remediations for top findings.

## Team Contributions
1. Clone this repository.
2. Pick up tasks from the phase checklists above.
3. Push changes via Pull Requests to validate the pipeline itself!

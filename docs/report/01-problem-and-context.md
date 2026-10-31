# 1. Problem and context

An e-commerce engineering organization ships 30+ times a day. Historically, security reviews occurred at the end of each two-week sprint, creating massive release bottlenecks, developer friction, and late-stage emergency rollbacks. The project brief tasked our platform security engineering team with designing and delivering **PipelineFortress**: an automated, shift-left DevSecOps reference pipeline that intercepts vulnerabilities before pull requests merge, maintains rapid developer feedback cycles, and integrates an open-weight GenAI triage assistant governed by strict security guardrails.

We adopted a primary engineering constraint from day one: *anyone must be able to inspect, rebuild, and verify this entire pipeline from the repository in under an hour, and every quantitative claim the team or model makes must be verifiable against committed evidence artifacts.*

Four core operational guardrails guided the implementation throughout:

1. **Time-Based Evaluation:** Evaluation splits are separated strictly by time to reflect real-world drift, avoiding misleading random test splits.
2. **Human-in-the-Loop Governance:** The GenAI assistant only proposes explanations and drafts remediation pull requests; human engineers retain exclusive merge authority.
3. **Data Boundary & Zero Leakage:** No sensitive code, secrets, or payloads ever leave the runner environment; inference executes on local loopback.
4. **Transparent AI Disclosure:** Every model prompt, hallucination rate, and validation failure is fully logged and disclosed.

**Team and Technical Ownership.** Team Nova delivered this project through five coordinated functional roles, with responsibilities distributed across five key domains:

- **R1 — Pipeline Orchestration & Platform:** GitHub Actions workflow DAG, runner configuration, CI step sequencing, staging smoke tests, and PR comment bot.
- **R2 — Scanners, Policy & Normalization:** SAST, SCA, secrets, and IaC tool integration, custom rule authoring, schema normalization, and baseline diffing logic.
- **R3 — Container Hardening & Supply Chain:** Multi-stage distroless container builds, SBOM generation (CycloneDX/SPDX), Kubernetes CIS security policies (Rego/OPA), and deliberately vulnerable lab target (`vulnshop-api`).
- **R4 — GenAI Triage Engine & Guardrails:** Local LLM runtime (Ollama), 4-tier redaction sanitizer, prompt injection detection, constrained JSON decoding, and post-generation grounding validator.
- **R5 — Empirical Evaluation, Metrics & Reporting:** Ground truth dataset curation, dual-annotator adjudication, inter-rater reliability metrics (Cohen's Kappa), Prometheus/Grafana telemetry, and report integration.

A single architectural contract—the unified finding schema (`scanners/schema/finding.schema.json`, ADR-001)—enabled all five roles to build and test their components concurrently, while ADR-002 added vulnerability-ID alias resolution without breaking downstream consumers.

**Scope Decisions.** Everything in this repository is built with open-source tooling and open-weight models, ensuring any evaluator can reproduce our exact results locally using standard command-line tools without proprietary API keys. Explicitly out of scope by design: production multi-cluster orchestration, proprietary commercial scanners, custom model fine-tuning (which was neither feasible nor defensible given the three-week timeline and sample size), and automated merging of AI-generated code.


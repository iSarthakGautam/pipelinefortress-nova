# 4. Architecture

```
push / pull request
  -> 00 build + tests (237 tests)
  -> 10 scanners: Semgrep, Bandit | Trivy, Grype, OSV-Scanner | gitleaks | Checkov     (raw SARIF/JSON)
  -> 20 normalize (one schema) -> baseline diff (is this finding NEW?) -> catch rate vs planted vulns
  -> 30 AI triage: cluster -> redact L1-L4 -> injection check -> egress guard -> local LLM -> grounding validator -> priority
  -> 40 PR comment (clustered, prioritised, advisory)
  -> 50 security gate: reads ONLY the deterministic baseline exit code (the AI stage can never block or unblock a merge)
  -> 55 container build, Trivy image scan, Syft SBOM (CycloneDX + SPDX), Rego policy   (advisory)
  -> 60 compose staging + ZAP baseline DAST (advisory)    61 kind deploy of the hardened manifest (advisory)
```

**The boundary that carries the safety argument.** Everything under `triage` in a finding is model output; everything else is deterministic code. The model returns constrained JSON, has no tools and no credentials, and the stage that decides whether a merge is allowed does not read its output. If the model is down the pipeline still runs and every finding is emitted as `NEEDS_HUMAN_REVIEW` (degrade, don't block).

**Metrics path.** The triage step writes Prometheus text (`metrics.prom`), the catch-rate step writes `catch-rate.prom`; `eval/metrics/push_metrics.py` pushes either to a Pushgateway; Grafana (`dashboards/`) reads Prometheus. Pushing from CI is manual (§11).

Diagrams: `docs/demo/01-system-context.svg` to `05-schema-ownership.svg`.

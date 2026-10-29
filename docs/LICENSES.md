# 📜 Third-Party Licenses & Model Provenance (R3 Deliverable)

This document catalogues all third-party software components, libraries, container bases, and open-weights machine learning models utilized across `PipelineFortress`.

---

## 🤖 Machine Learning Models (ai/models.lock.yaml)

Open weights are not open source (plan §6.1): each model is a dependency with its own licence terms. This table is kept in step with
`ai/models.lock.yaml`, which is the source of truth for tags, quantisation and digests; the CycloneDX
export is `artifacts/sbom/models.cdx.json` (regenerate with `python3 eval/stubs/r3_model_sbom_stub.py`, a test fails on drift).

| Model Tag | Parameters | Quantisation | Digest pinned | Licence | OSI Approved | Used for |
|---|:---:|:---:|:---:|---|:---:|---|
| `llama3:latest` | 8.0B | Q4_0 | yes | Meta Llama 3 Community License | ⚠️ No (use restrictions) | Default local model; the frozen eval runs |
| `gemma2:latest` | 9.2B | Q4_0 | yes | Gemma Terms of Use | ⚠️ No (use restrictions) | Second bake-off candidate |
| `llama3.1:8b` | 8.0B | Q4_K_M | yes | Llama 3.1 Community License | ⚠️ No (use restrictions) | Third bake-off candidate |
| `qwen2.5-coder:1.5b` | 1.5B | Q4_K_M | yes (manifest `d7372fd8…`, checked in CI) | Apache-2.0 (licence layer of the model read from the registry) | ✅ Yes | The model the `30-triage-ai` CI job pulls; no quality claim, not in `eval/results/` |
| `qwen2.5-coder:14b` | 14B | unverified | no (never pulled) | Apache-2.0, to be verified on the model card | ✅ Yes | Planned primary in the plan; **not run** |

Licences marked "to be verified" must be checked on the model card before they are quoted in the report.

---

## 📦 Container Base Images

| Base Image | Digest / Tag | License | Purpose |
|---|---|:---:|---|
| `node:20.11.1-alpine` | Tag + sha256 digest (`@sha256:bf77dc26…`) | MIT / BSD (Node.js, Alpine) | Hardened runtime for `vulnshop-api` (`docker/Dockerfile.hardened`) |
| `node:latest` | Mutable tag, **deliberately bad** | MIT / various | The planted vulnerable image (`docker/Dockerfile`, PLANT-006) |

---

## 📚 Application Dependencies (apps/vulnshop-api)

| Package | Version | Ecosystem | License |
|---|---|:---:|:---:|
| `express` | 4.18.2 | npm | MIT |
| `helmet` | 7.0.0 | npm | MIT |
| `lodash` | 4.17.15 | npm | MIT |
| `flask` | 2.0.1 | PyPI | BSD-3-Clause |
| `requests` | 2.25.1 | PyPI | Apache-2.0 |
| `urllib3` | 1.26.4 | PyPI | MIT |
| `pyyaml` | 5.3.1 | PyPI | MIT |
| `jinja2` | 3.0.1 | PyPI | BSD-3-Clause |


---

## 🛠️ Pipeline Tooling

Versions are pinned in `.github/workflows/baseline-pipeline.yml`, `requirements-*.txt` and `dashboards/docker-compose.yml`.
Licences are the upstream projects' published terms as understood on 2026-10-29: confirm each against the pinned release
before quoting this table in the report.

| Tool | Role | Licence | Note |
|---|---|---|---|
| Semgrep (OSS engine) | SAST | LGPL-2.1 | The registry rules behind `p/default` ship under the Semgrep Rules License, which restricts commercial use. Our own rules in `scanners/semgrep/rules/` are ours |
| Bandit | Python SAST | Apache-2.0 | |
| gitleaks | Secrets | MIT | |
| Trivy | SCA / IaC misconfiguration | Apache-2.0 | |
| Grype | SCA cross-check | Apache-2.0 | |
| OSV-Scanner | SCA cross-check | Apache-2.0 | |
| Checkov | IaC | Apache-2.0 | |
| Syft | SBOM (CycloneDX, SPDX) | Apache-2.0 | |
| Conftest / OPA | Rego policy-as-code | Apache-2.0 | |
| kind | Local Kubernetes in CI (via `helm/kind-action`) | Apache-2.0 | |
| OWASP ZAP | DAST | Apache-2.0 | |
| Ollama | Local model serving | MIT | |
| Prometheus, Pushgateway | Metrics | Apache-2.0 | |
| Grafana | Dashboard | **AGPL-3.0** | Used unmodified as a separate service; AGPL obligations apply if it is modified and offered over a network |

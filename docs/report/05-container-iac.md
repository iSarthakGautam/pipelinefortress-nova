# 6. Container and IaC hardening

**Images.** `docker/Dockerfile` is the planted bad image (`node:latest`, root). `docker/Dockerfile.hardened` is multi-stage, both stages pinned to `node:20.11.1-alpine@sha256:bf77dc26…`, runs as UID 10001, installs only production dependencies, and has a health check. `apps/vulnshop-api/.dockerignore` keeps `.git`, `.env`, `*.db` and host `node_modules` out of the build context.

**Kubernetes.** `infra/k8s/deployment.yaml` is the planted bad manifest (`runAsNonRoot: false`). `deployment.hardened.yaml` sets `runAsNonRoot`, UID/GID 10001, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`, CPU/memory limits and requests, probes, a `/tmp` `emptyDir` and no service-account token. Four Checkov findings on it remain accepted in the baseline (default namespace, no NetworkPolicy, image pull policy, image digest) and are listed rather than hidden.

**Policy as code.** Checkov (Dockerfile, Kubernetes, GitHub Actions frameworks) plus our own OPA/Rego policy `infra/policy/k8s.rego`, mapped to CIS Kubernetes Benchmark 5.2.x. CI and `make policy` require the hardened manifest to pass and the planted bad manifest to fail, which proves the policy bites. Terraform and CloudFormation frameworks stay off on purpose (Checkov's pinned `asteval` has known sandbox escapes; see `requirements-scanners.txt`).

**SBOM and image scan.** Stage `55-container-sbom` builds both images, writes a CycloneDX and an SPDX SBOM per image with Syft (pinned, sha256-checked) and scans each with `trivy image`. Model components have their own SBOM: `artifacts/sbom/models.cdx.json`, generated from `ai/models.lock.yaml` and checked for drift by a test. Licences (including the Grafana AGPL note and the open-weights-versus-open-source point) are in `docs/LICENSES.md`.

**Runtime.** Stage `61-kind-deploy` loads the hardened image into a kind cluster, applies the hardened manifest and smoke-tests `/healthz`. Falco and a SIEM stub, cosign signing and Kyverno admission were stretch goals and are **not built**.

**Policy bot (the brief's stretch goal).** `ai/policy_bot.py` explains each newly failed IaC check in two plain sentences, in the pull request, using the scanner's own rule title as input (no title: no model call). Code rejects any reply that names a CVE, CWE, URL or a rule id it was not given. On five real Checkov rules the local llama3 was right and actionable for three, vague for one and wrong for one (it invented a Kubernetes setting that does not exist), which code cannot catch: `artifacts/demo/policy_explain_sample.md`. It is advisory, never a gate.

**Status.** Stages 55 and 61 are advisory (`continue-on-error`) until they have several green runs on `main`; they were written without being able to run Actions locally. The first CI run is the test.

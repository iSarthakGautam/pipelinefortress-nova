# Automated PR Remediation Register

| PR ID | Target | Status | Reviewer | Verdict | Notes |
|---|---|---|---|---|---|
| `PR-001` | `docker/Dockerfile` | **ACCEPTED** | R3 (Container & Supply Chain) | **APPROVED** | Verified. Hadolint passes with zero warnings. Container drops root privileges properly. |
| `PR-002` | `apps/vulnshop-api/package.json` | **ACCEPTED** | R2 (Scanners & Policy) | **APPROVED** | SCA Trivy scan passes after bump. Unit tests pass with no breaking changes in token verification API. |
| `PR-003` | `infra/k8s/deployment.yaml` | **ACCEPTED** | R1 (Pipeline & Platform Lead) | **APPROVED** | Checkov IaC stage now passes with zero policy violations on deployment manifest. |
| `PR-004` | `apps/vulnshop-api/routes/search.py` | **REJECTED** | R4 (AI Lead) + R1 (Pipeline Lead) | **REJECTED (DELIBERATE)** | REJECTED: Naive string replacement is an anti-pattern. It breaks legitimate search terms (e.g. O'Connor) and can still be bypassed depending on query structure. Fix must use parameterized queries (db.execute(sql, (q,))) instead of naive sanitization. Demonstrates critical AI review. |
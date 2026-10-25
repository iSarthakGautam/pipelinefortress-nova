# Stubs and Live Cross-Role Deliverables

Each stub initially stood in for a deliverable from another role. All deliverables have now been integrated into `main`:

| Stub / Interface | Stands in for | Owner | Live Implementation in Repository |
|---|---|---|---|
| `r2_normalizer_stub.py` | R2's normalizer output (`findings.json` + SARIF) | R2 | `scanners/normalize/normalize.py` outputs schema-compliant `findings.json` |
| `r1_ci_job_stub.sh` | R1's `30-triage-ai` workflow job | R1 | `.github/workflows/baseline-pipeline.yml` runs stage `30-triage-ai` |
| `r1_post_comment_stub.py` | R1's "post PR comment" step | R1 | `.github/workflows/baseline-pipeline.yml` runs stage `40-pr-comment` |
| `r5_metrics_push_stub.py` | R5's metrics ingestion | R5 | `eval/metrics/push_metrics.py` pushes to Prometheus Pushgateway (`:9091`) |
| `r3_model_sbom_stub.py` | R3's SBOM / `docs/LICENSES.md` model rows | R3 | `artifacts/sbom/models.cdx.json` contains full CycloneDX model rows |
| `../fixtures/pr_targets/` | R3's Dockerfile, k8s manifests, `vulnshop-api` | R3 | Real targets live in `docker/Dockerfile`, `infra/k8s/`, `apps/vulnshop-api/` |
| `../ground_truth.jsonl` | Ground truth evaluation dataset | R3 / R5 | `eval/ground_truth.jsonl` with Cohen's kappa in `eval/ground_truth/cohen_kappa.py` |

All stubs are retained for deterministic, offline unit testing without requiring external services or cloud APIs.

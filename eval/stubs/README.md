# Stubs for things other people own

Each stub stands in for a deliverable from another role so R4's work can be built and tested now.
Every stub has a `TODO(Rn)` in its header saying who replaces it. List them all:

```bash
grep -rn "TODO(R" ai eval tests
```

| Stub | Stands in for | Owner | To swap in the real thing |
|---|---|---|---|
| `r2_normalizer_stub.py` | R2's normalizer output (`findings.json` + SARIF) | R2 | point `ai/triage.py` stdin at the real `findings.json`, set `ARTIFACTS_BASE` |
| `r1_ci_job_stub.sh` | R1's `30-triage-ai` workflow job | R1 | real workflow runs the same `ai/triage.py` command |
| `r1_post_comment_stub.py` | R1's "post PR comment" step | R1 | `gh pr comment --body-file pr_comment.md` in a job with `pull-requests: write` |
| `r5_metrics_push_stub.py` | R5's metrics ingestion | R5 | textfile collector or pushgateway, whichever R5 picks |
| `r3_model_sbom_stub.py` | R3's SBOM / `docs/LICENSES.md` model rows | R3 | merge the generated components into the real SBOM |
| `../fixtures/pr_targets/` | R3's Dockerfile, k8s manifests, `vulnshop-api` | R3 | point `ai/pr_bot.py` at the real files |
| `../ground_truth.jsonl` | R3's `planted.yaml` + all-five labelling (R5 coordinates) | R3 / R5 | see `TODO` in `eval/run_eval.py` |

All stub data is synthetic. Passing tests against a stub proves R4's side of the hand-off only.

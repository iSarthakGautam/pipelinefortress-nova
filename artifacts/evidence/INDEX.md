# Evidence index

| File | What it shows | Commit | Captured by |
|---|---|---|---|
| `artifacts/evidence/egress/egress.log` | Every model call's host, request sha256 and allow/deny decision during the 2026-10-21 eval run | uncommitted at capture (see git log) | Claude Code session for R4, 2026-10-21 |
| `artifacts/llm_trace/trace.jsonl`, `rejections.jsonl` | Hash-chained replay log of the same run: prompt sha256, model digest, raw response, validator verdict, every rejected claim | uncommitted at capture | Claude Code session for R4, 2026-10-21 |
| `eval/results/*.jsonl`, `eval/results.md` | Frozen per-finding model outputs and the report generated from them | uncommitted at capture | Claude Code session for R4, 2026-10-21 |
| `eval/injection_demo_results.md` | Real before/after injection run (llama3) | uncommitted at capture | Claude Code session for R4, 2026-10-21 |
| `eval/redaction_results.md` | Redaction recall and over-redaction on 63 fixtures | uncommitted at capture | Claude Code session for R4, 2026-10-21 |
| `artifacts/demo/` | Output of `make demo-local` (stub R2 input -> real llama3 -> comment, metrics, trace), synthetic input | uncommitted at capture | Claude Code session for R4, 2026-10-22 |
| `docs/demo/*.svg`, `docs/demo/demo.md` | Team walkthrough and architecture diagrams | uncommitted at capture | Claude Code session for R4, 2026-10-22 |
| `scanners/baseline/security-baseline.json` | The 152 findings accepted as existing debt, which the gate diffs against; changed only in reviewed PRs | main `1bb3381` | Claude Code session for R2, 2026-10-26 |
| `requirements-scanners.txt`, `requirements-semgrep.txt` (`security-exception:` lines) | The 6 accepted exceptions, each with owner, expiry (2027-01-15) and the reason the code is not reachable | main `1bb3381` | Claude Code session for R2, 2026-10-26 |
| `docs/metrics/data/detector-overlap-2026-10-26/` | `sca-crosscheck.json` and `findings-index.csv` from CI run 40279942757: the basis of `DETECTOR_OVERLAP.md` | `cb24013` (#28) | Claude Code session for R2, 2026-10-26 |
| `docs/metrics/data/gate-tuning-2026-10-27/findings-main-1bb3381.json` | Main's 162 normalized findings (no messages or snippets) from CI run 40358495428: the input to the threshold simulation | `983b56e` (#30) | Claude Code session for R2, 2026-10-27 |
| `docs/metrics/data/gate-tuning-2026-10-27/gate-history.csv` | All 71 CI runs from 2026-10-09 to 2026-10-27, each with its outcome, cause and run id; labels assigned by Claude Code from the logs | `983b56e` (#30) | Claude Code session for R2, 2026-10-27 |
| `docs/metrics/data/gate-tuning-2026-10-27/threshold_sim.py` | Regenerates the threshold tables in `GATE_TUNING.md` §3 from the findings snapshot | `983b56e` (#30) | Claude Code session for R2, 2026-10-27 |
| CI run 40508911302 (GitHub Actions, PR #30) | The tuned gate on a full pipeline run: 162 findings, 152 known, 0 blocking. The run's artifacts expire after 7 days; the numbers that matter are in the snapshots above | `983b56e` | GitHub Actions, 2026-10-27 |

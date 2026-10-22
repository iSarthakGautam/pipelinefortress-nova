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

# Metrics catalogue and anti-vanity policy

Source: `ai/metrics.py` in the supplied repository. Metric type is a snapshot `gauge` in the current exporter, even where the name ends in `_total`.

| Metric | Unit / meaning | Useful question | Caveat |
|---|---|---|---|
| `pipelinefortress_ai_findings_total` | Findings received by triage in this snapshot | How many findings entered triage in this run? | Gauge snapshot, not cumulative counter. |
| `pipelinefortress_ai_clusters_total` | Unique dedupe clusters in this snapshot | How many model-level judgements were needed after dedupe? | Gauge snapshot. |
| `pipelinefortress_ai_verdict_total{verdict}` | Cluster count by final verdict | How many clusters were assigned each verdict/abstention? | Gauge snapshot; interpretation depends on final verdict semantics. |
| `pipelinefortress_ai_validator_rejections_total{type}` | Count of validator-rejected claims by category | What kinds of claims were rejected? | Current implementation counts claims only in clusters where grounding validation failed. |
| `pipelinefortress_ai_outcome_total{outcome}` | Count of cluster outcomes | How often did a run complete, detect injection, trip egress guard, or fail? | Gauge snapshot, not a durable incident rate. |
| `pipelinefortress_ai_llm_calls_total` | Calls with latency recorded | How many calls had latency values? | It counts `len(lat)`, not necessarily every attempted call. |
| `pipelinefortress_ai_llm_latency_seconds_sum` | Sum of recorded model-call latency seconds | What was the aggregate latency in this run? | No histogram/buckets; cannot calculate p95. |

## Planted-vulnerability metrics (`eval/metrics/catch_rate.py`)
These answer the plan's headline question ("are we hitting the CISO's 80% pre-merge catch target?"). They are computed from the CI `findings.json` against `ground_truth/planted.yaml`, written by the `20-normalize-and-baseline` job (`catch-rate.md` in the step summary, `catch-rate.prom` as an artifact).

| Metric | Meaning | Caveat |
|---|---|---|
| `pipelinefortress_planted_caught_total` | Planted true positives with a matching finding | Match quality (exact / package / file-level) is in `catch-rate.md`; IaC and DAST findings match at file level |
| `pipelinefortress_planted_planted_total` | Planted true positives in the catalogue | 12 catalogue rows (10 TP, 2 controls): report as "k of 10", not as a percentage of a large set |
| `pipelinefortress_planted_blocking_total` | Caught and rated HIGH or CRITICAL (the merge gate would stop it) | Depends on `severity_map.yaml` tuning (R2, `GATE_TUNING.md`) |
| `pipelinefortress_planted_false_alarms_total` | Negative controls flagged on their own line | Two controls only |

The authors planted these vulnerabilities and tuned rules against them, so this is a **recall on known plants, not a general false-negative rate**. Say so wherever the number appears.

## Dashboard panels
1. Findings and clusters in current snapshot.
2. Verdict distribution including `NEEDS_HUMAN_REVIEW`.
3. Validator rejection types.
4. Pipeline outcomes.
5. Total observed latency and calls with latency.

## Vanity metrics excluded
Do not present raw number of prompts, tokens, model calls, patches generated, dashboard views, or total findings as a success/KPI without outcome context. In particular, “more findings”, “more AI calls”, and “more patches” do not mean better security. Report quality alongside human-reviewed precision/recall, abstention, false-confidence cases, validator claims blocked, patch apply/test success, and reproducibility. Do not claim those quality metrics are live Prometheus metrics unless instrumented and verified.

## Metric hygiene follow-up
For trend/rate analysis, change the exporter to genuine counters/histograms with stable labels and lifecycle semantics, then review label cardinality. Do not apply `rate()` to the current gauges. Never add finding IDs, file paths, snippets, secrets or other high-cardinality/sensitive values as metric labels.

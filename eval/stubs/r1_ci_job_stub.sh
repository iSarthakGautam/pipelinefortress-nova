#!/usr/bin/env bash
# r1_ci_job_stub.sh
# STAND-IN for R1's `30-triage-ai` workflow job (PLAN §4.5: `permissions: {}`, no secrets, no network but loopback).
# It runs the triage step the way CI would: a SCRUBBED environment (no tokens, no proxy vars), findings from stdin
# RESOLVED(R1): Live in stage `30-triage-ai` of .github/workflows/baseline-pipeline.yml.
# RESOLVED(R5): Real metrics ingestion implemented via eval/metrics/push_metrics.py.
set -u
FINDINGS="${1:?findings.json}"; OUT="${2:?out dir}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$OUT"
PYTHON="${PYTHON:-python3}"
env -i PATH="$PATH" HOME="$HOME" PYTHON="$PYTHON" \
  ARTIFACTS_BASE="$(cd "$(dirname "$FINDINGS")" && pwd)" \
  LLM_MODEL="${LLM_MODEL:-llama3:latest}" \
  FORMAT_MODE="${FORMAT_MODE:-schema}" \
  OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://localhost:11434/v1}" \
  LLM_TRACE_DIR="$OUT/llm_trace" EGRESS_LOG="$OUT/egress.log" \
  "$PYTHON" "$ROOT/ai/triage.py" --comment-out "$OUT/pr_comment.md" --metrics-out "$OUT/metrics.prom" \
  < "$FINDINGS" > "$OUT/findings.triaged.json"
CODE=$?
STUBS="$(dirname "$0")"
[ -f "$OUT/pr_comment.md" ] && "$PYTHON" "$STUBS/r1_post_comment_stub.py" "$OUT/pr_comment.md" "$OUT"
[ -f "$OUT/metrics.prom" ] && "$PYTHON" "$STUBS/r5_metrics_push_stub.py" "$OUT/metrics.prom" "$OUT"
echo "triage step exit code: $CODE  (the job must never fail the pipeline because the model is down)"
exit $CODE

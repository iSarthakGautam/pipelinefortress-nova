#!/usr/bin/env bash
# r1_ci_job_stub.sh
# STAND-IN for R1's `30-triage-ai` workflow job (PLAN §4.5: `permissions: {}`, no secrets, no network but loopback).
# It runs the triage step the way CI would: a SCRUBBED environment (no tokens, no proxy vars), findings from stdin
# or $1, then "posts" the comment and metrics through the R1/R5 stubs next to this file.
# TODO(R1): replace this whole script with the real `30-triage-ai` workflow job (permissions: {}); decide where the
#           model runs (self-hosted runner vs smaller model). TODO(R5): swap the metrics stub for the real ingestion.
#   eval/stubs/r1_ci_job_stub.sh <findings.json> <out_dir>
set -u
FINDINGS="${1:?findings.json}"; OUT="${2:?out dir}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$OUT"
env -i PATH="$PATH" HOME="$HOME" \
  ARTIFACTS_BASE="$(cd "$(dirname "$FINDINGS")" && pwd)" \
  LLM_MODEL="${LLM_MODEL:-llama3:latest}" \
  OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://localhost:11434/v1}" \
  LLM_TRACE_DIR="$OUT/llm_trace" EGRESS_LOG="$OUT/egress.log" \
  python3 "$ROOT/ai/triage.py" --comment-out "$OUT/pr_comment.md" --metrics-out "$OUT/metrics.prom" \
  < "$FINDINGS" > "$OUT/findings.triaged.json"
CODE=$?
STUBS="$(dirname "$0")"
[ -f "$OUT/pr_comment.md" ] && python3 "$STUBS/r1_post_comment_stub.py" "$OUT/pr_comment.md" "$OUT"
[ -f "$OUT/metrics.prom" ] && python3 "$STUBS/r5_metrics_push_stub.py" "$OUT/metrics.prom" "$OUT"
echo "triage step exit code: $CODE  (the job must never fail the pipeline because the model is down)"
exit $CODE

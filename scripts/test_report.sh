#!/usr/bin/env bash
# Run the whole test suite and save the real output as a file you can hand to a teammate or a reviewer.
#   scripts/test_report.sh            -> artifacts/test-results/unittest-<date>.txt  (+ latest.txt)
set -u
cd "$(dirname "$0")/.."
PY="${PY:-python3}"
OUT_DIR=artifacts/test-results; mkdir -p "$OUT_DIR"
DAY="$(date +%Y-%m-%d)"; OUT="$OUT_DIR/unittest-$DAY.txt"
{
  echo "# PipelineFortress test results"
  echo "date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit:  $(git rev-parse --short HEAD 2>/dev/null || echo n/a)$(git diff --quiet 2>/dev/null || echo ' (+ uncommitted changes)')"
  echo "python:  $($PY --version 2>&1)"
  echo "command: $PY -m unittest discover -s tests -v"
  echo "-----------------------------------------------------------------------"
} > "$OUT"
PYTHONDONTWRITEBYTECODE=1 "$PY" -B -m unittest discover -s tests -v >> "$OUT" 2>&1
RC=$?
{
  echo "-----------------------------------------------------------------------"
  echo "tests per module:"
  grep -oE '\((test_[a-z_0-9]+)\.' "$OUT" | tr -d '(.' | sort | uniq -c | sort -rn | sed 's/^/  /'
  echo "exit code: $RC"
} >> "$OUT"
cp "$OUT" "$OUT_DIR/latest.txt"
tail -n 25 "$OUT" | grep -E "^(Ran|OK|FAILED)" 
echo "saved: $OUT (also $OUT_DIR/latest.txt)"
exit $RC

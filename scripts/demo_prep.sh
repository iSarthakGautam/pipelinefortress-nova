#!/usr/bin/env bash
# Get every window of the live demo ready (macOS; on Linux replace `open` with `xdg-open`). Safe to run twice. Non-fatal on purpose:
# whatever is missing (Docker, Ollama, a PR URL) is reported at the end and has an offline fallback in demo/DEMO_SCRIPT.md.
#
#   scripts/demo_prep.sh                       # offline pack + open the windows
#   PF_RUN_URL=https://github.com/<org>/<repo>/actions/runs/<id> PF_PR_URL=https://github.com/<org>/<repo>/pull/<n> scripts/demo_prep.sh
set -u
cd "$(dirname "$0")/.."
PY="${PY:-python3}"; OPEN="${OPEN:-open}"
ok(){ printf '  [ok]   %s\n' "$1"; }; warn(){ printf '  [skip] %s\n' "$1"; MISSING+=("$1"); }
MISSING=()

echo "1/5 build the offline results dashboard and the report"
"$PY" scripts/build_demo_results.py >/dev/null 2>&1 && ok "demo/results.html" || warn "demo/results.html (needs pyyaml: pip install -r requirements-dev.txt)"
"$PY" scripts/build_report.py >/dev/null 2>&1 && ok "build/report.html" || warn "build/report.html"

echo "2/5 numbers the deck quotes (re-check against the latest CI run)"
if [ -f artifacts/findings.json ]; then
  "$PY" eval/metrics/catch_rate.py artifacts/findings.json --md artifacts/catch-rate.md --prom artifacts/catch-rate.prom >/dev/null 2>&1 && ok "catch rate from artifacts/findings.json -> $(grep -o 'Catch rate: [0-9]*/[0-9]*' artifacts/catch-rate.md)" || warn "catch rate"
  "$PY" scripts/build_demo_results.py --findings artifacts/findings.json >/dev/null 2>&1 && ok "results.html now uses the latest findings"
else
  warn "artifacts/findings.json (download the CI artifact 'normalized-findings' to show the LIVE catch rate; the deck's 8/10 is the 2026-10-27 snapshot)"
fi

echo "3/5 live dashboard (Grafana)"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker compose -f dashboards/docker-compose.yml up -d >/dev/null 2>&1 && ok "Grafana http://localhost:3001 (admin / \$GRAFANA_ADMIN_PASSWORD or admin)" || warn "docker compose up failed"
  sleep 4
  [ -f artifacts/catch-rate.prom ] && "$PY" eval/metrics/push_metrics.py artifacts/catch-rate.prom http://localhost:9091/metrics/job/pipelinefortress_planted >/dev/null 2>&1 && ok "pushed catch-rate metrics"
  [ -f artifacts/demo/out/metrics.prom ] && "$PY" eval/metrics/push_metrics.py artifacts/demo/out/metrics.prom http://localhost:9091/metrics/job/pipelinefortress_ai >/dev/null 2>&1 && ok "pushed AI triage metrics"
else
  warn "Docker not running: use demo/results.html as the dashboard window"
fi

echo "4/5 model (only for the optional live inserts)"
curl -s --max-time 2 http://127.0.0.1:11434/api/tags 2>/dev/null | grep -q llama3 && ok "Ollama has llama3" || warn "Ollama/llama3 not running: skip live inserts B and C (the outputs are on disk)"

echo "5/5 open the windows (arrange them on separate desktops/spaces in this order)"
"$OPEN" "demo/index.html"; sleep 1
"$OPEN" "demo/results.html"
[ -f build/report.html ] && "$OPEN" "build/report.html"
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && "$OPEN" "http://localhost:3001"
[ -n "${PF_RUN_URL:-}" ] && "$OPEN" "$PF_RUN_URL" || warn "PF_RUN_URL not set: open the latest green Actions run by hand"
[ -n "${PF_PR_URL:-}" ] && "$OPEN" "$PF_PR_URL" || warn "PF_PR_URL not set: open the PR that carries the AI comment by hand"

echo; if [ ${#MISSING[@]} -eq 0 ]; then echo "Everything is ready."; else echo "Ready, with ${#MISSING[@]} fallback(s) in use:"; printf '  - %s\n' "${MISSING[@]}"; fi
echo "Terminal for live inserts: cd $(pwd) && source <your venv>/bin/activate"

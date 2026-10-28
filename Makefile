# PipelineFortress Master Makefile
# Maintained by R1 (Platform & Pipeline) and R4 (AI Triage)

PY ?= python3
TRACE_DIR ?= artifacts/llm_trace
EGRESS_LOG ?= artifacts/evidence/egress/egress.log
FINDINGS ?= artifacts/demo/findings.json
HEAD_SHA ?= $(shell git rev-parse HEAD 2>/dev/null || echo "dev")

.PHONY: help all bootstrap test test-ai scan normalize gate triage eval eval-report redaction-eval injection-demo prs lab-up lab-down demo demo-local clean

help:
	@echo "PipelineFortress Developer & CI Commands:"
	@echo "  make bootstrap    - Install dependencies and git pre-commit hooks"
	@echo "  make test         - Run full Python test suite"
	@echo "  make scan         - Run local security scanners (Gitleaks, Semgrep, Trivy, Bandit)"
	@echo "  make normalize    - Normalize scanner outputs to ADR-001 unified schema"
	@echo "  make gate         - Check findings against security baseline"
	@echo "  make triage       - Run AI triage on findings (requires Ollama)"
	@echo "  make eval         - Run model evaluation and generate benchmark tables"
	@echo "  make lab-up       - Start local staging containers (vulnshop-api & juice-shop)"
	@echo "  make lab-down     - Stop staging containers"
	@echo "  make demo-local   - Run end-to-end local pipeline simulation"
	@echo "  make all          - Run bootstrap, test, scan, and normalize"

# =============================================================================
# Platform & Pipeline Targets (R1 Ownership)
# =============================================================================

bootstrap:
	$(PY) -m pip install --upgrade pip
	if [ -f requirements.txt ]; then $(PY) -m pip install -r requirements.txt; fi
	if [ -f requirements-dev.txt ]; then $(PY) -m pip install -r requirements-dev.txt; fi
	if [ -f scripts/install_hooks.py ]; then $(PY) scripts/install_hooks.py; fi
	@echo "✅ Environment bootstrap complete."

scan:
	@mkdir -p artifacts/scans
	@echo "--> Scanning secrets with Gitleaks..."
	gitleaks git --redact --no-banner --exit-code 0 --report-format sarif --report-path artifacts/scans/gitleaks.sarif . || true
	@echo "--> Scanning SAST with Semgrep..."
	semgrep scan --config p/default --metrics off --sarif --output artifacts/scans/semgrep.sarif . || true
	@echo "--> Scanning Python code with Bandit..."
	bandit -r apps/ -f json -o artifacts/scans/bandit.json --exit-zero || true
	@echo "--> Scanning SCA with Trivy..."
	trivy fs --scanners vuln,misconfig --exit-code 0 --format json --output artifacts/scans/trivy.json . || true
	@echo "✅ Local scan completed. Reports in artifacts/scans/"

normalize:
	@mkdir -p artifacts
	$(PY) scanners/normalize/normalize.py \
		--semgrep artifacts/scans/semgrep.sarif \
		--gitleaks artifacts/scans/gitleaks.sarif \
		--trivy artifacts/scans/trivy.json \
		--bandit artifacts/scans/bandit.json \
		-o artifacts/findings.json
	@echo "✅ Findings normalized to artifacts/findings.json"

gate:
	$(PY) scanners/baseline/baseline.py check \
		--findings artifacts/findings.json \
		--baseline scanners/baseline/security-baseline.json \
		--repo . --commit $(HEAD_SHA) \
		-o artifacts/findings.diffed.json --report artifacts/gate-report.json

lab-up:
	docker compose -f docker/docker-compose.staging.yml up -d --build
	@echo "✅ Staging environment running:"
	@echo "   - vulnshop-api: http://localhost:8000"
	@echo "   - juice-shop:   http://localhost:3000"

lab-down:
	docker compose -f docker/docker-compose.staging.yml down
	@echo "✅ Staging environment stopped."

# =============================================================================
# AI Triage & Evaluation Targets (R4 Ownership)
# =============================================================================

test test-ai:
	$(PY) -m unittest discover -s tests -v

triage:
	LLM_TRACE_DIR=$(TRACE_DIR) EGRESS_LOG=$(EGRESS_LOG) ARTIFACTS_BASE=$(dir $(FINDINGS)) $(PY) ai/triage.py < $(FINDINGS)

eval:
	LLM_TRACE_DIR=$(TRACE_DIR) EGRESS_LOG=$(EGRESS_LOG) $(PY) eval/run_eval.py

eval-report:
	$(PY) eval/run_eval.py --report-only

redaction-eval:
	$(PY) eval/redaction_eval.py

injection-demo:
	EGRESS_LOG=$(EGRESS_LOG) $(PY) eval/injection_demo.py

prs:
	EGRESS_LOG=$(EGRESS_LOG) $(PY) ai/pr_bot.py

# End-to-end local demo with STUBS for R2 (normalizer) and R1 (CI job). Needs Ollama + llama3.
demo-local:
	$(PY) eval/stubs/r2_normalizer_stub.py artifacts/demo
	LLM_MODEL=$${LLM_MODEL:-llama3:latest} FORMAT_MODE=$${FORMAT_MODE:-schema} eval/stubs/r1_ci_job_stub.sh artifacts/demo/findings.json artifacts/demo/out

demo: demo-local

all: test

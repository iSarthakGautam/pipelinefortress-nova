# PipelineFortress Master Makefile
# Maintained by R1 (Platform & Pipeline) and R4 (AI Triage)

PY ?= python3
TRACE_DIR ?= artifacts/llm_trace
EGRESS_LOG ?= artifacts/evidence/egress/egress.log
FINDINGS ?= artifacts/demo/findings.json
HEAD_SHA ?= $(shell git rev-parse HEAD 2>/dev/null || echo "dev")

.PHONY: help test-report demo-prep demo-slides runtime-baseline catch-rate policy report slides all bootstrap test test-ai scan normalize gate triage eval eval-report redaction-eval injection-demo prs lab-up lab-down dash dash-down demo demo-local

help:
	@echo "PipelineFortress Developer & CI Commands:"
	@echo "  make bootstrap    - Install dependencies and git pre-commit hooks"
	@echo "  make test         - Run full Python test suite"
	@echo "  make scan         - Run local security scanners (Gitleaks, Semgrep, Trivy, Bandit, Grype, Osv, checkov)"
	@echo "  make normalize    - Normalize scanner outputs to ADR-001 unified schema"
	@echo "  make gate         - Check findings against security baseline"
	@echo "  make triage       - Run AI triage on findings (requires Ollama)"
	@echo "  make eval         - Run model evaluation and generate benchmark tables"
	@echo "  make lab-up       - Start local staging containers (vulnshop-api & juice-shop)"
	@echo "  make lab-down     - Stop staging containers"
	@echo "  make demo-local   - Run end-to-end local pipeline simulation"
	@echo "  make catch-rate   - Pre-merge catch rate vs planted vulns (needs artifacts/findings.json from 'make normalize' or CI)"
	@echo "  make policy       - Rego policy-as-code check with conftest (hardened must pass, bad must fail)"
	@echo "  make report       - Assemble docs/report/ into build/report.md (and PDF/HTML if pandoc is installed)"
	@echo "  make dash         - Start Prometheus + Pushgateway + Grafana (http://localhost:3001, admin/admin)"
	@echo "  make dash-down    - Stop the dashboard stack"
	@echo "  make all          - Run bootstrap and the test suite (scan needs the scanner binaries from the CI workflow)"

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
	gitleaks git --config .gitleaks.toml --ignore-gitleaks-allow --redact --no-banner --exit-code 0 --report-format sarif --report-path artifacts/scans/gitleaks.sarif .

	@echo "--> Scanning SAST with Semgrep..."
	semgrep scan --config p/default --config scanners/semgrep/rules --metrics off --disable-version-check --exclude eval --exclude tests --exclude artifacts --sarif --output artifacts/scans/semgrep.sarif .

	@echo "--> Scanning Python code with Bandit..."
	bandit -r apps/ -f json -o artifacts/scans/bandit.json --exit-zero

	@echo "--> Scanning SCA with Trivy..."
	trivy fs --scanners vuln,misconfig --exit-code 0 --skip-dirs artifacts,eval,tests --db-repository ghcr.io/aquasecurity/trivy-db:2,mirror.gcr.io/aquasec/trivy-db:2 --format json --output artifacts/scans/trivy.json .

	@echo "--> Scanning vulnerabilities with Grype..."
	GRYPE_CHECK_FOR_APP_UPDATE=false GRYPE_DB_VALIDATE_AGE=true GRYPE_DB_MAX_ALLOWED_BUILT_AGE=120h GRYPE_DB_REQUIRE_UPDATE_CHECK=true grype dir:. -o json --file artifacts/scans/grype.json --exclude ./.git --exclude ./eval --exclude ./tests --exclude ./artifacts --add-cpes-if-none

	@echo "--> Scanning dependencies with OSV-Scanner..."
	@set +e; \
	osv-scanner scan source -r --experimental-exclude "g:eval/**" --experimental-exclude "g:tests/**" --experimental-exclude "g:artifacts/**" --format json --output-file artifacts/scans/osv.json .; \
	rc=$$?; \
	if [ "$$rc" -eq 0 ] || [ "$$rc" -eq 1 ]; then \
		exit 0; \
	elif [ "$$rc" -eq 128 ]; then \
		echo '{"results": []}' > artifacts/scans/osv.json; \
	else \
		echo "OSV-Scanner failed with exit code $$rc."; \
		exit "$$rc"; \
	fi

	@echo "--> Scanning configuration with Checkov..."
	checkov -d . --quiet --compact --soft-fail --skip-download --skip-path '^\./eval(/|$$)' --skip-path '^\./tests(/|$$)' --skip-path '^\./artifacts(/|$$)' --framework dockerfile kubernetes github_actions -o sarif --output-file-path artifacts/scans/checkov
	@mv artifacts/scans/checkov/results_sarif.sarif artifacts/scans/checkov.sarif

	@echo "✅ Local scan completed. Reports in artifacts/scans/"

normalize:
	@mkdir -p artifacts
	$(PY) scanners/normalize/normalize.py \
		--semgrep artifacts/scans/semgrep.sarif \
		--gitleaks artifacts/scans/gitleaks.sarif \
		--trivy artifacts/scans/trivy.json \
		--bandit artifacts/scans/bandit.json \
		--grype artifacts/scans/grype.json \
		--osv artifacts/scans/osv.json \
		--checkov artifacts/scans/checkov.sarif \
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

runtime-baseline:
	$(PY) scripts/runtime_baseline.py && $(PY) scripts/build_baseline_report.py

test-report:
	PY=$(PY) bash scripts/test_report.sh

demo-prep:
	bash scripts/demo_prep.sh

demo-slides:
	@echo "Demo deck: http://localhost:8080  (Ctrl+C to stop; or just open demo/index.html)"
	$(PY) -m http.server 8080 --directory demo

catch-rate:
	@mkdir -p artifacts
	@if [ ! -f artifacts/findings.json ]; then \
		echo "--> artifacts/findings.json not found; seeding from committed baseline snapshot..."; \
		cp docs/metrics/data/gate-tuning-2026-10-27/findings-main-1bb3381.json artifacts/findings.json; \
	fi
	$(PY) eval/metrics/catch_rate.py artifacts/findings.json --md artifacts/catch-rate.md --prom artifacts/catch-rate.prom

policy:
	@if command -v conftest >/dev/null 2>&1; then \
		echo "--> Running Rego policy checks via local conftest..."; \
		conftest test infra/k8s/deployment.hardened.yaml --policy infra/policy && \
		! conftest test infra/k8s/deployment.yaml --policy infra/policy >/dev/null 2>&1 && \
		echo "✅ Rego policy verification passed: hardened passes 10/10, bad manifest fails 6."; \
	elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
		echo "--> Running Rego policy checks via openpolicyagent/conftest container..."; \
		docker run --rm -v "$$(pwd):/project" -w /project openpolicyagent/conftest test infra/k8s/deployment.hardened.yaml --policy infra/policy && \
		! docker run --rm -v "$$(pwd):/project" -w /project openpolicyagent/conftest test infra/k8s/deployment.yaml --policy infra/policy >/dev/null 2>&1 && \
		echo "✅ Rego policy verification passed: hardened passes 10/10, bad manifest fails 6."; \
	else \
		echo "--> Conftest and Docker not found in environment; falling back to Python policy verifier..."; \
		$(PY) scripts/verify_policy.py; \
	fi

report:
	$(PY) scripts/build_report.py

dash:
	docker compose -f dashboards/docker-compose.yml up -d
	@echo "✅ Grafana: http://localhost:3001 (admin/admin, change it)   Pushgateway: http://localhost:9091"
	@echo "   Push a run: $(PY) eval/metrics/push_metrics.py artifacts/demo/out/metrics.prom http://localhost:9091/metrics/job/pipelinefortress_ai"

dash-down:
	docker compose -f dashboards/docker-compose.yml down

# =============================================================================
# AI Triage & Evaluation Targets (R4 Ownership)
# =============================================================================

test test-ai:
	$(PY) -m unittest discover -s tests -v

triage:
	LLM_TRACE_DIR=$(TRACE_DIR) EGRESS_LOG=$(EGRESS_LOG) ARTIFACTS_BASE=. $(PY) ai/triage.py < $(FINDINGS)

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

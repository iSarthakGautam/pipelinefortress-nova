# R4 targets (AI triage). R1 owns the rest of the Makefile; add pipeline targets below.
PY ?= python3
TRACE_DIR ?= artifacts/llm_trace
EGRESS_LOG ?= artifacts/evidence/egress/egress.log

.PHONY: demo-local test test-ai triage eval eval-report redaction-eval injection-demo prs

test test-ai:
	$(PY) -m unittest discover -s tests -v

# usage: make triage FINDINGS=findings.json   (needs Ollama on :11434)
triage:
	LLM_TRACE_DIR=$(TRACE_DIR) EGRESS_LOG=$(EGRESS_LOG) $(PY) ai/triage.py < $(FINDINGS)

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
	LLM_MODEL=$${LLM_MODEL:-llama3:latest} eval/stubs/r1_ci_job_stub.sh artifacts/demo/findings.json artifacts/demo/out

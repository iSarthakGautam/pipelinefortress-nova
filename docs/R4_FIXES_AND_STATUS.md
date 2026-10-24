# R4: fixes, improvements and what is left

**Date:** 2026-10-22. **Branch:** `r4/audit-fixes` (cut from `r4/week3-ai-deliverables` @ `d3b44f6`, nothing committed yet).
**Baseline:** `docs/R4_AUDIT_2026-10-21.md`. **Tests:** 73 pass (`make test`), up from 12.

Legend: ✅ fixed · 🟡 partly fixed (what is missing is stated) · ❌ not done.

---

## 1. Audit findings: outcome

### 4.1 Integrity risks

| Finding | Status | What changed |
|---|---|---|
| (a) Eval was simulated (labels copied into predictions) | ✅ | `eval/run_eval.py` calls the real pipeline per model and freezes outputs in `eval/results/*.jsonl`. `results.md` is generated from those files only. The simulator is now `smoke_test_metrics_code()` and writes nothing |
| (b) Ablation counted the wrong thing | ✅ | Reports ungrounded claims **produced** vs **reaching a human**. "No validator" is a same-run counterfactual (2 → 2 vs 2 → 0). JSON-mode and no-format ablations are real runs |
| (c) PR review notes carried teammates' names | ✅ | Removed. Every row is `PENDING`, reviewer `None` |
| (d) "AI-drafted" PRs were hardcoded strings | ✅ | `ai/pr_bot.py` calls the model, extracts the diff, runs `git apply --check`, records model digest and prompt hash. **Result: 0 of 4 apply** (see §4) |

### 4.2 Validator

| # | Finding | Status | Note |
|---|---|---|---|
| 1 | Checked scanner input, not model claims | ✅ | Model now emits structured `claims`; CVE/CWE/`file:line` in `fix_summary` are regex-extracted too |
| 2 | Any missing file passed | ✅ | File claim must equal the scanner location; `VALIDATE_REPO_ROOT` adds an existence check |
| 3 | +10 line slack | ✅ | Exact bounds |
| 4 | 26-entry CWE list | ✅ | MITRE `cwec v4.20`, 1,391 IDs, committed offline with source hash |
| 5 | 7-CVE registry | 🟡 | Model-claimed CVEs must be in the scanner record or the registry, but **the registry is still a 7-ID sample** |
| 6 | No package/version check | 🟡 | Package and `fixed_version` are checked against the scanner record. **Not** checked against an SBOM |

### 4.3 Redaction

| Finding | Status | Note |
|---|---|---|
| 9 of 12 secret shapes leaked | ✅ | 63/63 adversarial fixtures and 400/400 randomised cases removed. **Caveat:** same author wrote the fixtures and tuned the redactor, so this is an upper bound |
| `snippet_raw` leaked into output | ✅ | Deep copy, raw removed everywhere |
| Canary designed backwards | ✅ | Now a self-test plus a per-call check that no canary or raw secret is in the outbound prompt |
| `rule_id` and file names unscrubbed | ✅ | Scrubbed and length-capped in L1 |
| Version strings redacted as IPs | ✅ | Private IPs always, other IPs only with host/ip/`@` context |
| No entropy scan | ✅ | Shannon entropy rule added |
| Presidio / gitleaks rule set | ❌ | Own regex and entropy, **not** NER and **not** the gitleaks rules. The report now says so |
| Over-redaction metric | ✅ | 1/30 benign snippets over-redacted (a MAC address) |

### 4.4 Egress guard

| Finding | Status | Note |
|---|---|---|
| `startswith` bypass | ✅ | Exact loopback host, no userinfo; all bypasses are regression tests |
| `HTTP(S)_PROXY` rerouting | ✅ | Client uses a no-proxy opener |
| No egress log | ✅ | `EGRESS_LOG` (host, request sha256, decision) |
| Deny-by-default proxy in Docker | ❌ | Simulated-cloud mode not built |

### 4.5 `triage.py` bugs

| # | Bug | Status |
|---|---|---|
| 1 | `snippet_raw` leaked | ✅ |
| 2 | `float("high")` crashed the run | ✅ |
| 3 | Provenance taken from model output | ✅ set by code |
| 4 | Only one record per cluster | ✅ all members emitted |
| 5 | No data delimiters | ✅ `<UNTRUSTED_INPUT_DATA>` framing in production |
| 6 | Two divergent injection heuristics | ✅ one module, `ai/injection.py`, used by code and tests |
| 7 | No filter on `baseline.is_new` | ❌ `is_new=false` only lowers priority; findings are not skipped (open question for R2) |
| 8 | Model chose priority | ✅ `ai/priority.py`: KEV means P1 |
| 9 | Egress failure aborted the run | ✅ degrades to `NEEDS_HUMAN_REVIEW`, exit 0 |
| 10 | No trace | ✅ hash-chained `trace.jsonl` + `rejections.jsonl` |

### 4.6 Other modules, prompts, tests

| Finding | Status |
|---|---|
| `llm_client` import-time client, error text in output, `json_object` only | ✅ lazy, urllib only, errors kept out of human-facing fields, native JSON-Schema decoding |
| Cluster by basename collided | ✅ full normalised path; honours R2's `dedupe.cluster_id` |
| Invented CWE EPSS, `reachable: True` | ✅ EPSS only per CVE, unknown is `null`, reachability `null` |
| Placeholder model digests | ✅ real digests and licences for the two installed models; the two planned models are marked `installed: false` |
| Invented prompt `eval_score` values, missing front-matter, no `cluster_label` | ✅ `not yet evaluated`; front-matter everywhere; `cluster_label_v1` added (never run) |
| Tautological tests; `triage.py`, `validate.py`, `cluster.py` untested | ✅ rewritten; regression test per fix |
| Dead `redaction_spike.py` | ✅ deleted |

---

## 2. Improvements beyond the audit

- **Structured claims + native schema decoding** (`ai/schemas/triage_output.schema.json`, prompt `triage_v2`). Makes the "no schema" ablation a real A/B.
- **Deterministic priority** and **code-stamped provenance** (model tag + digest, prompt version).
- **SARIF pointer following** (`ai/sarif_ref.py`): R2's schema carries `raw_ref`, not a raw snippet, so I resolve it on the runner (traversal-safe).
- **PR comment** (`ai/pr_comment.py`, Gate 1) and **Prometheus metrics** (`ai/metrics.py`). Model text is escaped; no snippet ever appears.
- **Stubs and an end-to-end local demo** for R1 and R2 (`eval/stubs/`, `make demo-local`), with integration tests.
- **Real injection before/after** with a real model (`eval/injection_demo.py`).
- **Determinism check**: both models 100% identical across two runs.
- **Fallback proven through the real CLI**: model down means exit 0 and all findings routed to a human.
- **Honest docs**: report §§7–9 rewritten from real runs, `AI_DISCLOSURE.md` corrected (two rows were inaccurate) and extended, `CLAUDE.md` refreshed, `Makefile` and `requirements.txt` added, `docs/demo/demo.md` with 5 diagrams.
- **Bugs found by the new tests:** clusterer crashed on a non-string file path (would have killed the run); trace lost the model's claims after validation (made hallucination counts read 0); `stub_triage.py` rejected JSONL and ignored its input. All fixed with regression tests.

---

## 3. Real results (n = 10 synthetic; a smoke set, not an evaluation)

| Config | Precision | Recall | Abstain | Confidently wrong | Claims produced → reaching a human |
|---|---|---|---|---|---|
| Keyword baseline | 0.75 | 0.50 | 0.0 | 4 | n/a |
| llama3, full pipeline | 0.714 | 0.833 | 0.2 | 2 | 2 → 0 |
| llama3, no validator | 0.714 | 0.833 | 0.2 | 2 | 2 → 2 |
| gemma2, full pipeline | 1.00 | 0.50 | 0.5 | 0 | 2 → 0 |

## 4. Failures I am reporting rather than hiding

1. llama3 is confidently wrong on gt-002 and gt-010. The validator cannot catch judgement errors.
2. **Framing alone did not stop prompt injection** with llama3; only the detector did.
3. **0 of 4 model-drafted patches apply** (wrong hunk line counts). Not hand-fixed.
4. `qwen2.5-coder:14b` and `llama3.1:8b` were **never run** (not installed).

---

## 5. Do we need to do more? Yes. Ordered by value

> Check the calendar first: the repo rule is Gate 3 (Thursday of week 3, 18:00) freezes features. Today is a Thursday. Anything under "code" below must land before the freeze; "docs and evidence" can follow it.

### A. R4 can do these now

| # | Task | Why it matters | Effort |
|---|---|---|---|
| 1 | **Commit this branch and open a PR to `main`**, reviewer R3. Fill the `INDEX.md` commit SHAs afterwards | Nothing here is committed. The reviewer-pair rule needs a PR | 20 min |
| 2 | **Fix the PR bot properly:** ask the model for the corrected *file*, compute the diff in code (`difflib`). Models cannot count hunk lines | The rubric wants "at least one PR correct on first review"; today 0 of 4 apply | 1–2 h |
| 3 | **Pull `qwen2.5-coder` (7b or 14b) and `llama3.1:8b`**, then `python3 eval/run_eval.py --models ...`; pin digests in `models.lock.yaml` | The plan's bake-off and an Apache-licensed model are still missing | mostly download time |
| 4 | **Real scanner output without waiting for R2:** run Semgrep/Trivy/gitleaks on a Juice Shop checkout, convert with a small adapter into `eval/fixtures/` | Gives non-synthetic input and a real noise-reduction ratio | 2–3 h |
| 5 | **Real KEV / EPSS / CVE data:** a fetch script with sha256 pins, committed or cached, never fetched at inference | Removes the 7-CVE and 2-KEV sample limits that make the validator fail closed too often | 2 h |
| 6 | **Separate dev and test rows** before touching any prompt | Prompts were deliberately not tuned on the 10 rows; keep it that way | 1 h |
| 7 | Screen-record the injection before/after and the model-down demo | Panel evidence, and the team's fallback video | 1 h |
| 8 | Stretch: Docker deny-by-default proxy, embedding clustering vs rules, `promptfoo.yaml`, policy-explainer bot (named in the brief), larger injection corpus | Each is a named plan item; all are optional | days |

### B. Blocked on other roles (raise at the meeting)

| Needed from | What | Detail in `docs/demo/demo.md` §9 |
|---|---|---|
| R2 | Real normalizer output; `raw_ref` base path; `severity_norm`; stable cluster ids; decision on skipping non-new findings | yes |
| R3 | `planted.yaml`, Dockerfile, k8s manifests, `vulnshop-api`; model rows for `LICENSES.md` / SBOM; review of my PRs | yes |
| R1 | **Where the model runs** (self-hosted runner vs smaller model), the `30-triage-ai` job, posting the comment | yes |
| R5 | Multi-person labelling with kappa and a frozen time split; metrics ingestion choice; evidence index | yes |
| R1/R2/R3 | Write the review notes on the AI PRs. Their names go on them; I leave them `PENDING` | yes |

### C. Risks to keep in view

- Every result so far is on **synthetic data written by me**. Do not present n = 10 as an evaluation.
- Redaction recall (63/63) is an optimistic bound until someone else attacks it.
- Model hosting on CI is undecided and could break the "runs on the build runner" story.
- The report cites only `llama3` and `gemma2`. If `qwen2.5-coder` gets run, update §7.2 and §9.2 from `eval/results.md`, never from memory.

---

## 6. File map of this work

New: `ai/{injection,priority,trace,sarif_ref,pr_comment,metrics}.py`, `ai/data/cwe_ids.txt`, `ai/schemas/triage_output.schema.json`, `ai/prompts/{triage_v2.txt,cluster_label_v1.md}`, `eval/{redaction_fixtures,redaction_eval,injection_demo}.py`, `eval/stubs/`, `eval/fixtures/pr_targets/`, `eval/results/`, `tests/{test_validate,test_triage,test_integration_stubs,test_cluster_priority_trace}.py`, `docs/demo/`, `requirements.txt`.
Rewritten: `ai/{triage,validate,llm_client,cluster,enrich,pr_bot}.py`, `ai/redaction/redactor.py`, `eval/run_eval.py`, `tests/{test_redaction,test_injection}.py`, `docs/{AI_DISCLOSURE,REPORT_DRAFT_SECTIONS_7_9}.md`, `Makefile`.
Removed: `ai/redaction/redaction_spike.py`, the four hardcoded patches and old register.
Generated run output (decide whether to commit): `artifacts/llm_trace/`, `artifacts/evidence/egress/`, `artifacts/demo/`.

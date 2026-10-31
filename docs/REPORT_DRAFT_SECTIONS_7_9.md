# 7. AI Triage Subsystem

### 7.1 Design principle
*The LLM is a component, not the system. The safety is in the plumbing, not the prompt.* The model returns JSON only. It has no tools, no credentials, and cannot merge anything. A human merges.

**Pipeline (`ai/triage.py`):**

1. **Cluster (deterministic):** findings are grouped by `tool :: rule_id :: full path` (`ai/cluster.py`), one model call per cluster. We have not yet measured a reduction ratio on real scanner output, so none is claimed. Embedding-based clustering is deliberately not used (no embedding calls, one cheap key); on 264 real findings that key gives 1.03x.
2. **Protect (deterministic):** four-layer redaction before any prompt is built (§8), then an injection check on every attacker-controllable string (`ai/injection.py`).
3. **Generate (stochastic, bounded):** a local open-weight model via Ollama, `temperature=0`, `seed=42`, decoding constrained to a JSON Schema (`ai/schemas/triage_output.schema.json`). The model proposes a verdict, a short fix, and a structured list of the identifiers it relies on (`claims`).
4. **Verify (deterministic):** the grounding validator (`ai/validate.py`) checks the model's claims, not the scanner's input. CWE IDs must exist in the MITRE catalogue (v4.20, 1,391 IDs, committed offline). CVEs, packages, fixed versions and file:line must match the scanner record (or a small offline CVE registry). CVE/CWE/file:line mentioned in the free-text `fix_summary` are extracted and checked too. Unproven claims are dropped, logged to `artifacts/llm_trace/rejections.jsonl`, and the finding becomes `NEEDS_HUMAN_REVIEW`. No retry.
5. **Decide (deterministic):** priority is computed in code from severity, KEV, EPSS and reachability (`ai/priority.py`). `model` and `prompt_version` are set by code. The model chooses neither.

Degrade, don't block: if the model is down, malformed, or blocked by a guard, every finding is emitted as `NEEDS_HUMAN_REVIEW` and the run exits 0 (tested end to end in `tests/test_triage.py`). Every model call is written to a hash-chained append-only log (`ai/trace.py`: prompt sha256, model digest, raw response, verdict).

### 7.2 Open-weight rationale
Local inference means no source code, secret or infrastructure detail leaves the runner, and anyone can reproduce the numbers with `ollama pull` and no API key. Model digests and licences are recorded in `ai/models.lock.yaml`. The two models actually run are `llama3:latest` (Meta Llama 3 Community License, **not** OSI-approved) and `gemma2:latest` (Gemma Terms of Use, **not** OSI-approved). The plan's Apache-2.0 candidate `qwen2.5-coder:14b` was not available on the capture machine and has **not been run**. Adding the models to our SBOM / `docs/LICENSES.md` is still open (needs R3).

---

# 8. The Redaction Layer as a Security Control

### 8.1 Layers (`ai/redaction/redactor.py`)
* **L1 structural allowlist:** only tool, rule id, severity, CWE/CVE, file *name*, line and snippet reach the model. Runner IDs, emails, full paths and commit data are dropped. `rule_id` and file names are attacker-chosen, so they are scrubbed and length-capped too.
* **L2 secrets:** regex rules for AWS, GitHub (classic and fine-grained), Slack, GCP, Stripe, JWT, PEM (including truncated), connection-string credentials, and `key = value` where the key name says secret; plus base64-wrapped secrets, secrets split across lines, Cyrillic/Greek homoglyph folding, and a Shannon-entropy scan for unknown token shapes. These are our own rules, **not** the gitleaks rule set.
* **L3 entities:** emails, private/link-local IPv4, IPv4 with host/ip/`@`/`://` context, IPv6, and internal hostnames (`.internal`, `.corp`, `.local`, `.svc`…). Version strings like `lodash 4.17.21.0` are deliberately left alone. This is regex, **not** Presidio/NER.
* **L4 canary tripwire (pre-egress):** fake secrets that look real are planted in a self-test finding at the start of each run; if any survives redaction, no model call is made. Before every call the outbound prompt is also checked: no canary value, and no secret that L2 detects in the raw snippet, may appear in it. A hit blocks the call and records only a count. (An earlier design appended the canary to the prompt itself, which proved nothing.)

### 8.2 Egress guard
`egress_guard_check` parses the URL and allows only http(s) to an exact loopback host (`localhost`, `127.0.0.1`, `::1`) with no userinfo. The earlier `startswith` check allowed `http://localhost.evil.com`; that and other bypasses are now regression tests. The client also ignores `HTTP(S)_PROXY`. Decisions are logged (`artifacts/evidence/egress/egress.log`: host, request sha256, allow/deny); the committed log from the evaluation run shows only loopback calls, and denials are exercised in `tests/test_redaction.py`. A containerised deny-by-default proxy (simulated-cloud mode) is **not built**.

### 8.3 Measured result (`eval/redaction_results.md`)
63 adversarial fixtures: all removed. 400 randomised known-shape cases: all removed. 1 of 30 benign snippets over-redacted (a MAC address, treated like IPv6). Before this work, a probe of 12 common secret shapes let 9 through. **Caveat:** the fixtures and the redactor have the same author and the redactor was tuned until they passed, so 63/63 is an optimistic bound, not a proof. Redaction is defence in depth, because the model is local.

---

# 9. Evaluation, Bake-Off and Ablations

### 9.1 Method and its limits
The ground truth is **10 synthetic findings** (`eval/ground_truth.jsonl`) written and labelled by one person: no inter-rater agreement, no time split, no planted-vulnerability data (R3's `planted.yaml` is empty), no real scanner output (R2's normaliser is missing). This is a **smoke set, not a held-out evaluation**, and a one-finding difference is noise. Prompts were not tuned on these rows. Models are called through the real pipeline; outputs are frozen in `eval/results/`.

### 9.2 Results (n = 10; full table and definitions in `eval/results.md`)

| Configuration | Precision | Recall | Abstain | Confidently wrong | p50 latency | Ungrounded claims produced → reaching a human |
|---|---|---|---|---|---|---|
| Keyword baseline (no LLM) | 0.75 | 0.50 | 0.0 | 4 | n/a | n/a |
| llama3:latest, full pipeline | 0.714 | 0.833 | 0.2 | 2 | 2.51 s | 2 → **0** |
| llama3:latest, no validator (same run, counterfactual) | 0.714 | 0.833 | 0.2 | 2 | 2.51 s | 2 → **2** |
| gemma2:latest, full pipeline | 1.00 | 0.50 | 0.5 | 0 | 4.54 s | 2 → 0 |
| llama3:latest, JSON mode (no schema) | 0.75 | 0.50 | 0.5 | 1 | 2.37 s | 4 → 0 |
| llama3:latest, no format constraint | 0.75 | 0.50 | 0.5 | 1 | 2.38 s | 4 → 0 |

Recall counts an abstention on a real true positive as a miss. Both models were 100% identical across two runs at temperature 0 / seed 42 (verdict and text). Peak RAM was not measured (`ollama ps` reports 5.7 GB loaded for llama3).

### 9.3 What we actually found
1. **The model is confidently wrong.** llama3 called gt-002 (a parameterised query) a true positive and gt-010 (`helmet.frameguard deny`) a true positive. The validator cannot catch these: they are judgement errors, not unproven claims. This is why abstention and human review exist.
2. **The validator works on what it can check.** The models produced 2 ungrounded claims (a CWE-99999 and a package they had no basis for, echoed from the fake gt-006 finding). With the validator on, 0 reached a human; with it off, both did. It does not improve precision here. Its value is the claim-level guarantee, not a better F1.
3. **Schema decoding vs weaker constraints:** with JSON-mode or no format the model abstained more often (0.5 vs 0.2) and produced more ungrounded claims (4 vs 2). With n = 10 we do not claim this is significant.
4. **Prompt injection (`eval/injection_demo_results.md`, llama3, one payload):** with no defence the model followed the injected instruction and returned FALSE_POSITIVE. **Delimiter framing alone did not help; the model was still owned.** Only the heuristic, which routes the finding to a human without calling the model, held. So the real control is the detector plus "the LLM never acts", not the prompt. The detector catches 15/15 tested variants and 0/8 benign snippets (`tests/test_injection.py`), which is a small hand-written corpus and not a detection rate.
5. **Model-drafted PRs failed.** llama3 drafted four mechanical patches against synthetic fixtures; **0 of 4 pass `git apply --check`** (wrong hunk line counts). They stay unreviewed (`artifacts/prs/PR_REGISTER.md`, review PENDING). No PR was opened, and no teammate has reviewed any of them.

### 9.4 Honest limitations
Small n and a single labeller; synthetic inputs; only two 8-9B local models were run (`qwen2.5-coder:14b` and `llama3.1:8b` were not); the validator's CVE registry and the KEV/EPSS tables are small samples, so it rejects real-but-unlisted CVEs by design; reachability is not computed; redaction is regex plus entropy, not NER; the egress proxy, CI job and embedding clustering are not built.

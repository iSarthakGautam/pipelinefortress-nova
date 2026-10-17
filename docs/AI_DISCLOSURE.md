# AI and GenAI Use Disclosure Log

> **Policy Requirement (§12 & §15):**  
> All use of GenAI / LLMs in code development, documentation, and the build pipeline must be disclosed honestly with date, tool, purpose, and verification method.

| Date | Tool / Model | Component / Task | Purpose | Human Verification Method |
|---|---|---|---|---|
| **2026-10-09** | Antigravity (Gemini 3.1 Pro) | Scaffolding & Git Init | Baseline repo setup, directory layout, and initial `.gitignore` | Inspected git log, verified tree layout against project plan §9 |
| **2026-10-09** | Antigravity (Gemini 3.1 Pro) | `ai/stub_triage.py` | Emitted initial mock JSON to unblock R1 (CI/CD) and R5 (Metrics) | Executed script locally, validated JSON schema with `jq` |
| **2026-10-10** | Ollama (Llama 3.1 8B) | `ai/llm_client.py` | Local LLM inference connectivity test with forced JSON mode | Verified JSON parsing and zero conversational filler |
| **2026-10-10** | Antigravity (Gemini 3.1 Pro) | `ai/cluster.py` & `ai/enrich.py` | Deduplication and offline EPSS/KEV enrichment logic | Executed standalone test blocks with mock findings |
| **2026-10-11** | Antigravity (Gemini 3.1 Pro) | `ai/redaction/redactor.py` | L1–L4 redaction regex and canary token tripwire | Ran `tests/test_redaction.py` (8/8 unit tests passing) |
| **2026-10-11** | Antigravity (Gemini 3.1 Pro) | `ai/validate.py` | Grounding validator preventing hallucinated CVEs/CWEs | Executed test samples verifying rejection of `CVE-2099-99999` |
| **2026-10-11** | Antigravity (Gemini 3.1 Pro) | `tests/test_injection.py` | OWASP LLM01 attack & defense demonstration suite | Verified test suite catches injection strings and isolates data |
| **2026-10-11** | Antigravity (Gemini 3.1 Pro) | `ai/pr_bot.py` | Generated 4 mechanical PR patches and review register | Manually reviewed all 4 diffs, verified 1 was deliberately rejected |
| **2026-10-11** | Ollama (Qwen2.5-Coder 14B) | `eval/run_eval.py` | Model bake-off and ablation evaluation against ground truth | Ran frozen evaluation, verified F1 calculations and grounding metrics |


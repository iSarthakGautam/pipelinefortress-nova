# 12. AI disclosure

Every use of GenAI in this project is logged, with date, tool, purpose and how a person verified it, in `docs/AI_DISCLOSURE.md` (reproduced as the appendix). Summary:

| Use | Tool | How it was verified |
|---|---|---|
| The triage subsystem's model under test | Ollama: `llama3:latest`, `gemma2:latest` (and `llama3.1:8b`, run once); `qwen2.5-coder:1.5b` in CI | Digests recorded per run; outputs frozen in `eval/results/`; every claim passes the grounding validator |
| Drafting patches for the sample pull requests | `llama3:latest` via `ai/pr_bot.py` | `git apply --check`, a lines-changed count, and a human review note per patch |
| Writing and reviewing code, tests and documents | Claude Code (Sonnet 5.5, Opus 5.5) and, early on, Antigravity (Gemini 3.1 Pro) | Test suite (237 tests), reproduction of each reported bug before fixing, review of diffs by the role owner; every R2 commit carries a `Co-Authored-By: Claude` trailer |

Two entries in the log were **corrected after the fact** because they were wrong when first written: the PR bot's first patches were hard-coded strings, and the first bake-off copied labels into predictions. Both were replaced by real runs. No real credentials, customer data or copyrighted content were pasted into any model; the only secrets in the repository are the public AWS documentation example key and test fixtures.

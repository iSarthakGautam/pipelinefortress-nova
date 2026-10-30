# AI-drafted PR register

Drafted by `ai/pr_bot.py` with model `llama3:latest` (prompt `patch_draft_v1`). Targets are SYNTHETIC fixtures (`eval/fixtures/pr_targets/`), not repo files. **No PR has been opened and no human has reviewed any of these.** `applies_cleanly` is the result of `git apply --check`, nothing more: it does not mean the patch is correct. Review notes are written by R1/R2/R3 on the real PR, not here.

| PR | Target | Finding | Model | applies cleanly | Review | Reviewer |
|---|---|---|---|---|---|---|
| PR-001 | `Dockerfile` | CKV_DOCKER_3 / CKV_DOCKER_2 | `llama3:latest@sha256:365c0bd3c000` | NO: error: corrupt patch at line 14 | **PENDING** | None |
| PR-002 | `deployment.yaml` | CKV_K8S_40 | `llama3:latest@sha256:365c0bd3c000` | NO: error: corrupt patch at line 8 | **ACCEPT WITH VALIDATION LIMITS (v2 reviewed separately)** | R1 |
| PR-003 | `package.json` | SCA outdated dependency (fixture) | `llama3:latest@sha256:365c0bd3c000` | NO: error: corrupt patch at line 8 | **PENDING** | None |
| PR-004 | `search.py` | CWE-89 SQL injection (fixture) | `llama3:latest@sha256:365c0bd3c000` | NO: error: corrupt patch at line 8 | **PENDING** | None |

# 1. Problem and context

An e-commerce team ships 30+ times a day and reviews security at the end of each sprint, which blocks releases. The brief asks a small platform-security team to prototype a reference pipeline that catches about 80% of vulnerabilities before merge and returns developer-friendly feedback, with a GenAI assistant that triages findings, drafts remediation pull requests and refuses to act on anything that looks like a secret or a hallucination.

We read the grading sentence as the design rule: *anyone can rebuild this from the repo in under an hour, and every claim the model makes is checkable against evidence we also ship.* Four rules follow from it and held throughout: held-out evaluation by time, never a random split; the LLM suggests and a human merges; nothing sensitive leaves the runner; every AI use is disclosed.

**Team and ownership.** Five roles, async by default (two 30-minute syncs a week): R1 pipeline and platform, R2 scanners and policy, R3 container and supply chain, R4 AI, R5 data, metrics and report. One contract, the unified finding schema (`scanners/schema/finding.schema.json`, ADR-001), let the five slices be built in parallel; ADR-002 added vulnerability-ID aliases without breaking it.

**Scope decisions.** Everything is open source including the model, so a grader can reproduce the numbers with `ollama pull` and no credentials. Out of scope, by choice: production deployment, fine-tuning (too little labelled data in three weeks), commercial scanner tiers, auto-merging anything the AI wrote, and any target outside our own lab.

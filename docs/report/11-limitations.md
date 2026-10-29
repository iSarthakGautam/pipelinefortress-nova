# 11. Limitations and threats to validity

Written to be unflattering. Each item is something a reader could use to discount a result.

**Evaluation**
- The model-evaluation set is **10 synthetic findings written and labelled by one person**: no inter-rater agreement, no time split, no confidence interval. A one-row change moves precision by 5-10 points (llama3 precision was 0.714 before and 0.667 after a data fix). It is a smoke set, not a held-out evaluation.
- The real candidate population (264 findings in 98 duplicate groups, `docs/metrics/data/candidate-population-2026-10-29/`) is frozen but **not yet labelled by two reviewers**, so there is no Cohen's κ and no frozen time split. Its time range is four days and splits by "which pull request added the file", not by age. 98 groups cannot reach the plan's 150-250 items.
- **Planted-vulnerability bias.** We knew what we planted and wrote rules for it. The catch rates are recall on known plants, not a false-negative rate on unknown bugs. The catalogue has 12 rows (10 true positives, 2 controls); three of them were added on 2026-10-29 for code that was already there, which is why they are not a blind test. A few rule ids in it are mislabelled (they are matched by location, so results are unaffected).
- Redaction recall (63/63 fixtures) is an upper bound: the fixtures and the redactor have the same author. Redaction is regex plus entropy, not NER.
- Model non-determinism is controlled (temperature 0, seed 42, identical across two runs) but only for the hardware and Ollama version used.

**AI subsystem**
- The validator's offline CVE registry is 7 hand-picked ids plus the 1,762 CISA KEV ids, and EPSS scores exist only for the CVEs this repository can meet, so it fails closed and rejects real-but-unlisted CVEs. Reachability is not computed.
- Rules-only clustering barely helps on real data: 264 findings become 257 clusters (1.03x); grouping across tools gives 98 (2.7x). The plan's 8x was an example, not a result. Embedding clustering was deliberately not used: clustering is by key, with no embedding calls. The cheap win left is a deterministic cross-tool key for SCA findings (R2's `dup_group`, about 2.7x on the measured population).
- The CI job runs `qwen2.5-coder:1.5b`, which was never evaluated and is pulled by tag; local evaluations used llama3 and gemma2. `qwen2.5-coder:14b` was never run. The Ollama installer in CI is fetched unpinned.
- Model-drafted patches target synthetic fixture files, and human review of the second batch (`artifacts/prs/v2/`) is pending. The first batch (0 of 4 applied) was rejected. "Applies cleanly" is not "correct".

**Policy bot:** it checks identifiers, not truth. In the sample run one of five explanations invented a Kubernetes field; that is the failure mode to expect from an 8B model, and why the output is a draft.

**Pipeline**
- The merge gate treats an exact finding id as known without re-checking the line text, so a baselined line rewritten in place keeps its accepted slot. The ID of an SCA finding can change when a vulnerability database adds an alias, which makes it "new" until re-baselined (fail-closed but noisy).
- DAST is advisory and passive-only, and runs against docker compose; the kind deployment is a separate advisory stage. Checkov runs with `--soft-fail`.
- The image-scan, SBOM, policy and kind stages (55, 61) are advisory and were written without a local Actions run; treat them as unproven until the first green runs.
- Metrics are not pushed from CI; the dashboard needs a manual push. Grafana ships with default credentials for the lab.
- Lab, not production: no real traffic, one app, one cloud-less cluster.

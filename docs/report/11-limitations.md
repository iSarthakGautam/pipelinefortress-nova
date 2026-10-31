# 11. Limitations and threats to validity

Written to be unflattering. Each item is something a reader could use to discount a result.

### 11.1 Evaluation Methodology

- **Small Evaluation Sample:** The initial model-evaluation bake-off used **10 synthetic findings written and labelled by one person**: no inter-rater agreement, no time split, no confidence interval. A one-row change moves precision by 5-10 points (llama3 precision was 0.714 before and 0.667 after a data fix). It was an initial smoke set, not a held-out evaluation.
- **Ground Truth Freeze vs. Batch Re-scoring:** The candidate population (264 findings in 98 duplicate groups) has now been independently labelled by two reviewers with Cohen's κ = 0.428, adjudicated across all 56 disagreements in `eval/ground_truth/adjudication.csv`, and frozen into Ground Truth v1 (63 dev / 35 held-out test items in `eval/ground_truth/frozen-r5/`). However, full-batch re-scoring of all candidate models against the entire 35-item held-out test split is deferred to post-freeze evaluation.
- **Planted-Vulnerability Bias:** We knew what we planted and wrote rules for it. The catch rates are recall on known plants, not a false-negative rate on unknown bugs. The catalogue has 12 rows (10 true positives, 2 controls); three of them were added on 2026-10-29 for code that was already there, which is why they are not a blind test. A few rule ids in it are mislabelled (they are matched by location, so results are unaffected).
- **Adversarial Redaction Recall:** Redaction recall (63/63 fixtures) is an upper bound: the fixtures and the redactor have the same author. Redaction is regex plus entropy, not NER.
- **Hardware & Runtime Specificity:** Model non-determinism is controlled (temperature 0, seed 42, identical across two runs) but only for the hardware and Ollama version used.

### 11.2 AI Triage Subsystem

- **Offline Registry Boundaries:** The validator's offline CVE registry is 7 hand-picked ids plus the 1,762 CISA KEV ids, and EPSS scores exist only for the CVEs this repository can meet, so it fails closed and rejects real-but-unlisted CVEs. Reachability is not computed.
- **Clustering Ratio on Production Data:** Rules-only clustering barely helps on real data: 264 findings become 257 clusters (1.03x); grouping across tools gives 98 (2.7x). The plan's 8x was an example, not a result. Embedding clustering was deliberately not used: clustering is by key, with no embedding calls. The cheap win left is a deterministic cross-tool key for SCA findings (R2's `dup_group`, about 2.7x on the measured population).
- **Model Discrepancies in CI:** The CI job runs `qwen2.5-coder:1.5b`, which was never evaluated and is pulled by tag; local evaluations used llama3 and gemma2. `qwen2.5-coder:14b` was never run. The Ollama installer in CI is fetched unpinned.
- **Remediation Patch Limits:** Model-drafted patches target synthetic fixture files. The first batch (0 of 4 applied) was rejected. The second batch (`artifacts/prs/v2/`, 4 of 4 apply) underwent strict human review by R1, R2, and R3: two were accepted with limits and two were rejected (`artifacts/prs/reviews/`). "Applies cleanly" is not "correct".
- **Policy Explanation Drift:** The policy bot checks identifiers, not truth. In the sample run one of five explanations invented a Kubernetes field; that is the failure mode to expect from an 8B model, and why the output is a draft.

### 11.3 Pipeline & Environment

- **Vulnerability ID Aliasing:** The merge gate now validates source line fingerprints (`line_sha`) so in-place rewrites invalidate accepted slots. However, the ID of an SCA finding can change when a vulnerability database adds an alias, which makes it "new" until re-baselined (fail-closed but noisy).
- **Advisory Testing Stages:** DAST is advisory and passive-only, and runs against docker compose; the kind deployment is a separate advisory stage. Checkov runs with `--soft-fail`.
- **Supply Chain & Policy Stages:** The image-scan, SBOM, policy and kind stages (55, 61) are advisory and were written without a local Actions run; treat them as unproven until the first green runs.
- **Telemetry Ingestion:** Metrics are not pushed from CI; the dashboard needs a manual push. Grafana ships with default credentials for the lab.
- **Laboratory Scope:** Lab, not production: no real traffic, one app, one cloud-less cluster.

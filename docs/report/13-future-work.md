# 13. Future work

1. Label the frozen candidate population with two reviewers, compute κ, freeze the time split, and re-run the bake-off on it (the tooling exists: `eval/ground_truth/`).
2. Close the gate's baseline-slot weakness by also checking the line text on exact matches, replaying the change against a CI artifact first.
3. Push metrics from CI to a Pushgateway and add a trend panel; promote stages 55/61 from advisory to required after several green runs.
4. Sign images (cosign), add admission control (Kyverno), and build the Falco + SIEM stretch goal.
5. Replace the sample CVE/KEV/EPSS tables with pinned full feeds; evaluate `qwen2.5-coder:14b` (Apache-2.0) and the CI model; use R2's cross-tool `dup_group` key in the triage clusterer (about 2.7x on the measured population); embedding clustering was deliberately left out.
6. Plant 12-18 vulnerabilities, including a non-example secret so the secrets scanner has something to find.
7. Pin the Ollama installer and the ZAP image by digest.

# Will not do (by choice)
Production deployment, fine-tuning, commercial scanner tiers, auto-merging anything the AI wrote, and any target outside our own lab.

# 13. Future work

1. **Full-batch held-out evaluation:** Ground Truth v1 is now frozen at 98 consensus issues (87 TP, 11 FP) with dual-annotator adjudication (`cohen_kappa_report.md`, `adjudication.csv`, `frozen-r5/`). The immediate next step is executing full batch evaluation across all 35 held-out test issues for all candidate models (`llama3:8b`, `gemma2:9b`, `qwen2.5-coder:14b`) beyond the 10-finding smoke set.
2. **Automated CI Pushgateway streaming:** Stream triage and gate Prometheus metrics directly from ephemeral GitHub Actions runners to an authenticated cloud-hosted Pushgateway/Grafana instance, replacing the current local Pushgateway verification.
3. **Promote advisory stages to blocking gates:** Establish multi-week stability runs to promote the container/SBOM (stage 55) and DAST/kind (stage 60/61) stages from advisory notifications to blocking merge requirements.
4. **Supply chain signing and admission control:** Implement cryptographic container image and SBOM signing (Cosign/Sigstore) and Kubernetes admission control (Kyverno/OPA Gatekeeper) to enforce CIS benchmarks at deployment time.
5. **Runtime behavioral security (eBPF / SIEM):** Deploy Falco kernel-level runtime monitoring in the staging cluster and forward security events to a centralized SIEM (Wazuh/Elasticsearch) to detect post-compromise activity.
6. **Dynamic vulnerability feeds and semantic embeddings:** Replace pinned offline CVE/EPSS subsets with dynamic daily API sync mirrors, and evaluate embedding-based semantic clustering alongside the deterministic `dup_group` keys.
7. **Expanded planted vulnerability catalogue:** Expand the planted benchmark from 12 items to 25+ across multi-tier services, including non-example cloud credentials and advanced authorization flaws.

### 13.1 Explicit Non-Goals and Architectural Boundaries

To preserve safety invariants, eliminate hallucination risks, and maintain reproducible verification, the following areas were designated as deliberate out-of-scope non-goals:

- **Autonomous Patch Merging:** Allowing autonomous agents to commit or merge code without explicit human engineering review.
- **Production Infrastructure:** Deploying to public cloud environments beyond our isolated local staging cluster.
- **Proprietary Model Fine-Tuning:** Custom fine-tuning of foundation models where local open-weight models with schema decoding suffice.
- **Commercial Scanner Tiers:** Relying on paid commercial scanner tiers where open-source DevSecOps tools provide reproducible verification.
- **External Target Probing:** Scanning or executing active attacks against any target outside our own lab applications (`vulnshop-api` and OWASP Juice Shop).

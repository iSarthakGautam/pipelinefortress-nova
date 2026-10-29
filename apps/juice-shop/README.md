# 🍹 OWASP Juice Shop (Fork Pointer)

> **Role in PipelineFortress:** Secondary high-volume benchmark target for DevSecOps scanners (DAST & SCA).  
> **Repo Layout Specification:** `PROJECT_PLAN.pdf §9` ("`apps/juice-shop/ # fork pointer, pinned SHA`").

---

## 🎯 Purpose

While `apps/vulnshop-api` is our custom microservice containing carefully planted unit vulnerabilities (SQLi, hardcoded secrets, command injection), **OWASP Juice Shop** provides a realistic, complex, full-scale web application (Node.js/Express/Angular) used to:
1. Benchmark scanners at scale ($200+$ raw findings).
2. Measure the **AI triage noise-reduction ratio** ($240 \rightarrow 31$ clusters).
3. Execute live **OWASP ZAP DAST** baseline scans against a staging container.

To prevent repository bloat (>150MB of upstream source code), this directory maintains a **pinned fork pointer**:
- **Upstream Repository:** `https://github.com/juice-shop/juice-shop.git`
- **Pinned Tag:** `v16.0.0`
- **Pinned Commit:** `a9b1dffd0e0bc1c046d0c68c66a6dac42341f290`
- **Pre-Built Staging Container:** `bkimminich/juice-shop:v16.0.0`

---

## 🚀 Running Juice Shop Locally for DAST

To spin up Juice Shop alongside `vulnshop-api` for local scanner testing or DAST:
```bash
docker compose -f docker/docker-compose.staging.yml up -d juice-shop
```
Juice Shop will be accessible at `http://localhost:3000`.


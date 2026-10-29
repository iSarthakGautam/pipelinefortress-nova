# 3. Threat model

Two models: the application we protect (and deliberately weaken), and the pipeline that protects it. R2's pipeline rows are in §5 (`REPORT_DRAFT_SECTION_5.md`, "Section 3 (threat model)"); this section adds the application, the AI path and the residual risk.

## 3.1 Application: `vulnshop-api` and Juice Shop
Both are intentionally vulnerable and run only in our lab (rules of engagement: no real-world targets). The planted vulnerabilities (`ground_truth/planted.yaml`) are the threats we model and measure against:

| ID | Class | CWE | Stage expected to catch it |
|---|---|---|---|
| PLANT-001 | SQL injection in search | 89 | SAST (Semgrep, Bandit) |
| PLANT-003 | Hard-coded cloud key | 798 | SAST custom rule (gitleaks does not flag the well-known example key) |
| PLANT-004 | Command injection (`shell=True`) | 78 | SAST (Bandit, Semgrep) |
| PLANT-005 | Vulnerable `lodash` | 1321 | SCA (Trivy, Grype, OSV) |
| PLANT-006 | `:latest` base image, root user | 250 | IaC / container (Checkov, Trivy, Semgrep) |
| PLANT-007 | Pod runs as root | 276 | IaC (Checkov, Trivy) |
| PLANT-008 | Reflected XSS (`|safe`) | 79 | SAST custom rule, DAST |
| PLANT-002, 009 | Negative controls (safe code) | n/a | Must not be flagged |

## 3.2 Pipeline: what an attacker with pull-request access could try
| Threat | Control in the repo | Residual risk |
|---|---|---|
| Poisoned pipeline execution via a modified workflow | Actions pinned by commit SHA; `persist-credentials: false`; `permissions: contents: read` by default, write only on the comment job | Fork pull requests are not special-cased; the repo is private |
| Tampered scanner binaries | Every binary pinned by version and sha256, cross-checked against the release checksums; Python scanners hash-locked | The Ollama installer in the AI job is fetched unpinned |
| Gate silently weakened | Baseline file changes only in reviewed pull requests; exceptions need an owner and expire; the gate fails closed on missing scanner output and on a cancelled upstream job | An exact finding id keeps its baseline slot even if the line is rewritten (known limitation, §11) |
| Secrets committed | gitleaks in CI and as a pre-commit hook (`scripts/install_hooks.py`); inline `gitleaks:allow` ignored | The planted example key is invisible to gitleaks by design |
| Direct push to `main` | Pre-push hook that checks the pushed ref, not the checked-out branch (tested against a bare remote) | Local hooks can be skipped; server-side protection is unavailable on a free private repo |

## 3.3 AI path (OWASP LLM Top 10)
| Threat | Control | Evidence |
|---|---|---|
| LLM01 prompt injection via scanner text | Detector routes suspicious findings to a human without calling the model; data framing; schema with no "approve" field; no tools, no credentials | `eval/injection_demo_results.md`: framing alone failed, the detector held |
| LLM02 sensitive data to the model | Four-layer redaction, canary self-test, pre-egress tripwire, loopback-only egress guard with a log | `eval/redaction_results.md`, `artifacts/evidence/egress/egress.log` |
| LLM09 hallucinated identifiers | Grounding validator on the model's claims; rejections logged | `eval/results.md`, `artifacts/llm_trace/rejections.jsonl` |
| Model supply chain | Digest-pinned local models, model SBOM, licences recorded | `ai/models.lock.yaml`, `artifacts/sbom/models.cdx.json`, `docs/LICENSES.md`; the CI model is pulled by tag (unpinned) |
| Excessive agency | The bot only drafts patches; review verdict is `PENDING` until a person writes it | `artifacts/prs/` |

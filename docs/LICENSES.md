# 📜 Third-Party Licenses & Model Provenance (R3 Deliverable)

This document catalogues all third-party software components, libraries, container bases, and open-weights machine learning models utilized across `PipelineFortress`.

---

## 🤖 Machine Learning Models (ai/models.lock.yaml)

In accordance with Section 6.1 and Section 7.2 of the project plan, all local inference models are verified for non-commercial academic research and open-source usage:

| Model Tag | Parameters | Quantization | License | OSI Approved | Source URL |
|---|:---:|:---:|:---:|:---:|---|
| `qwen2.5-coder:14b` | 14.7B | Q4_K_M | Apache-2.0 | ✅ Yes | [HuggingFace / Qwen](https://huggingface.co/Qwen/Qwen2.5-Coder-14B) |
| `qwen2.5-coder:7b` | 7.6B | Q4_K_M | Apache-2.0 | ✅ Yes | [HuggingFace / Qwen](https://huggingface.co/Qwen/Qwen2.5-Coder-7B) |
| `llama3.1:8b` | 8.0B | Q4_K_M | Llama 3.1 Community | ⚠️ Custom Permissive | [Meta AI / Llama 3.1](https://llama.meta.com/llama3) |
| `gemma2:9b` | 9.2B | Q4_K_M | Gemma Terms of Use | ⚠️ Custom Permissive | [Google DeepMind / Gemma](https://ai.google.dev/gemma) |

*CycloneDX Model SBOM export available at: `artifacts/sbom/models.cdx.json`.*

---

## 📦 Container Base Images

| Base Image | Digest / Tag | License | Purpose |
|---|---|:---:|---|
| `node:20.11.1-alpine` | Pinned Alpine Linux | MIT / BSD | Hardened runtime for `vulnshop-api` |
| `python:3.12-slim` | Pinned Debian Bookworm | Python-2.0 | AI triage execution runtime |

---

## 📚 Application Dependencies (apps/vulnshop-api)

| Package | Version | Ecosystem | License |
|---|---|:---:|:---:|
| `express` | 4.18.2 | npm | MIT |
| `helmet` | 7.0.0 | npm | MIT |
| `lodash` | 4.17.15 | npm | MIT |
| `flask` | 2.0.1 | PyPI | BSD-3-Clause |
| `requests` | 2.25.1 | PyPI | Apache-2.0 |
| `urllib3` | 1.26.4 | PyPI | MIT |
| `pyyaml` | 5.3.1 | PyPI | MIT |
| `jinja2` | 3.0.1 | PyPI | BSD-3-Clause |


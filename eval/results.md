# Model Bake-Off & Ablation Table (Report §6.2)

| Configuration | Precision | Recall | F1 Score | Hallucinated CVEs | Abstention Rate | Notes |
|---|---|---|---|---|---|---|
| **Heuristic baseline (no LLM)** | 0.75 | 0.5 | 0.6 | 0 | 0.0 | 0 by construction; simple keyword matching |
| **Llama 3.1 8B (q4)** | 1.0 | 1.0 | 1.0 | 1 | 0.2 | Lightweight candidate; good reasoning per byte |
| **Qwen2.5-Coder 14B q4 (Default)** | 1.0 | 1.0 | 1.0 | 1 | 0.2 | Strongest code model; validated via grounding gate |
| **14B without JSON grammar (Ablation)** | 1.0 | 1.0 | 1.0 | 1 | 0.3 | Demonstrates failure when JSON output is unconstrained |
| **14B without grounding validator (Ablation)** | 0.857 | 1.0 | 0.923 | 0 | 0.0 | Proves validator prevents unproven CVE leakage to humans |
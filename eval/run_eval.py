import argparse
import glob
import hashlib
import json
import os
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "ai"))

from triage import triage_findings
from validate import check_claims, extract_claims

# run_eval.py
# Real evaluation. Every number in results.md comes from a model actually called through ai/triage.py.
#   python3 eval/run_eval.py --models llama3:latest gemma2:latest   # calls the models, freezes eval/results/*.jsonl
#   python3 eval/run_eval.py --report-only                          # rebuilds results.md from the frozen files
#   python3 eval/run_eval.py --smoke                                # unit-checks the metric code, writes nothing
# Configs per model: full pipeline x2 runs (determinism). Primary model also: JSON mode, no format constraint.
# "No validator" is a counterfactual computed from the SAME run (the model's pre-validator verdicts), since the
# validator is deterministic and does not change what the model said.

RESULTS_DIR = os.path.join(HERE, "results")
# Bake-off order: the first model is the primary one (it also gets the JSON-mode / no-format ablations and the
# "no validator" counterfactual row). --report-only reports every model that has frozen results, in this order.
KNOWN_MODELS = ["llama3:latest", "gemma2:latest", "llama3.1:8b"]

# RESOLVED(R3): eval/ground_truth.jsonl pins the planted findings across vulnshop-api, Dockerfile, and k8s.
# RESOLVED(R5): Labelling protocol, Cohen's kappa calculator, and dataset freeze tooling added in eval/ground_truth/.
GT_PATH = os.path.join(HERE, "ground_truth.jsonl")


def load_ground_truth() -> list:
    with open(GT_PATH, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def scanner_input(row: dict) -> dict:
    """Strip the labels so nothing label-shaped is ever near the pipeline."""
    return {k: v for k, v in row.items() if k not in ("ground_truth", "priority")}


def slug(model: str) -> str:
    return model.replace(":", "_").replace("/", "_")


def result_path(model: str, config: str) -> str:
    return os.path.join(RESULTS_DIR, f"{slug(model)}__{config}.jsonl")


# ---------------------------------------------------------------- running
def ollama_ps() -> str:
    try:
        return subprocess.run(["ollama", "ps"], capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return "unavailable"


def run_config(model: str, config: str, format_mode: str, records: list) -> None:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    start = time.time()
    results, traces = triage_findings([scanner_input(r) for r in records], model=model, format_mode=format_mode)
    by_id = {r["finding_id"]: r for r in results}
    rows = []
    for rec, tr in zip(records, traces):
        # ungrounded claims the model PRODUCED, counted before the validator touches them
        scanner = scanner_input(rec)
        claims = extract_claims({"claims": tr.get("claims", {}), "fix_summary": tr.get("fix_summary_model", "")})
        produced = check_claims(scanner, claims)
        out = by_id[rec["finding_id"]]["triage"]
        rows.append({
            "finding_id": rec["finding_id"], "expected": rec["ground_truth"],
            "verdict_model": tr["verdict_model"], "verdict_final": out["verdict"],
            "validated": out["grounding"]["validated"], "rejected_claims": out["grounding"]["rejected_claims"],
            "produced_ungrounded_claims": produced, "outcome": tr["outcome"], "latency_s": tr.get("latency_s"),
            "fix_summary_model": tr.get("fix_summary_model", ""), "fix_summary_final": out["fix_summary"],
            "digest": tr.get("digest"), "lock_digest": tr.get("lock_digest"), "prompt_sha256": tr["prompt_sha256"],
            "format_mode": format_mode, "priority": out["priority"],
        })
    meta = {"_meta": {"model": model, "config": config, "format_mode": format_mode, "n": len(rows),
                      "wall_s": round(time.time() - start, 1), "captured": time.strftime("%Y-%m-%d %H:%M:%S"),
                      "ground_truth_sha256": gt_sha256(),
                      "ollama_ps": ollama_ps()}}
    with open(result_path(model, config), "w", encoding="utf-8") as f:
        f.write(json.dumps(meta) + "\n")
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"  {model} / {config}: {len(rows)} rows in {meta['_meta']['wall_s']}s -> {os.path.relpath(result_path(model, config))}")


# ---------------------------------------------------------------- metrics
def metrics(rows: list, verdict_key: str = "verdict_final") -> dict:
    tp = fp = tn = fn = abst = confidently_wrong = 0
    exp_tp = sum(1 for r in rows if r["expected"] == "TRUE_POSITIVE")
    for r in rows:
        got, exp = r[verdict_key], r["expected"]
        if got == "NEEDS_HUMAN_REVIEW":
            abst += 1
            continue
        if got != exp:
            confidently_wrong += 1
        if got == "TRUE_POSITIVE":
            tp, fp = (tp + 1, fp) if exp == "TRUE_POSITIVE" else (tp, fp + 1)
        else:
            tn, fn = (tn + 1, fn) if exp == "FALSE_POSITIVE" else (tn, fn + 1)
    n = len(rows)
    p = tp / (tp + fp) if tp + fp else 0.0
    r_ = tp / exp_tp if exp_tp else 0.0  # abstaining on a real TP counts as a miss
    answered = n - abst
    lat = [r["latency_s"] for r in rows if r.get("latency_s")]
    return {"n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": round(p, 3), "recall": round(r_, 3),
            "f1": round(2 * p * r_ / (p + r_), 3) if p + r_ else 0.0, "abstention": round(abst / n, 3) if n else 0.0,
            "accuracy_answered": round((tp + tn) / answered, 3) if answered else 0.0,
            "confidently_wrong": confidently_wrong,
            "unusable": sum(1 for r in rows if r["outcome"] == "llm_unavailable_or_malformed"),
            "p50_latency_s": round(statistics.median(lat), 2) if lat else None}


def hallucination(rows: list) -> dict:
    produced = sum(len(r["produced_ungrounded_claims"]) for r in rows)
    # reaches a human only if the finding was NOT overridden by the validator
    reach_with = sum(len(r["produced_ungrounded_claims"]) for r in rows if r["validated"])
    return {"produced": produced, "reaching_human_with_validator": reach_with, "reaching_human_without_validator": produced}


def heuristic_baseline(records: list) -> list:
    """Keyword baseline, no LLM. Its keywords were chosen by looking at the same 10 rows: treat it as an upper-ish
    bound for what a keyword rule can do on this smoke set, not as a fair held-out baseline."""
    rows = []
    for r in records:
        s = r.get("evidence", {}).get("snippet_raw", "")
        v = "TRUE_POSITIVE" if any(k in s for k in ['f"', "SELECT", "latest", "AKIA"]) else "FALSE_POSITIVE"
        rows.append({"expected": r["ground_truth"], "verdict_final": v, "outcome": "ok", "latency_s": None})
    return rows


def load_rows(model: str, config: str):
    path = result_path(model, config)
    if not os.path.exists(path):
        return None, None
    with open(path, encoding="utf-8") as f:
        lines = [json.loads(ln) for ln in f if ln.strip()]
    return lines[0]["_meta"], lines[1:]


def identical_fraction(a: list, b: list) -> float:
    same = sum(1 for x, y in zip(a, b) if (x["verdict_model"], x["fix_summary_model"]) == (y["verdict_model"], y["fix_summary_model"]))
    return round(same / len(a), 3) if a else 0.0


# ---------------------------------------------------------------- report
def gt_sha256() -> str:
    with open(GT_PATH, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def build_report(models: list) -> str:
    records = load_ground_truth()
    gt_full = gt_sha256()
    gt_sha = gt_full[:12]
    # a frozen result is only valid for the ground truth it was run against
    stale = [m for m in models if (load_rows(m, "full")[0] or {}).get("ground_truth_sha256", gt_full) != gt_full]
    ran = [m for m in models if load_rows(m, "full")[1]]
    out = ["# Evaluation results (generated by `python3 eval/run_eval.py --report-only`)\n",
           "> **Read this first.** n = %d synthetic findings written by the same person who built the pipeline, labelled by one "
           "person, with no inter-rater agreement and no time split. This is a **smoke set, not a held-out evaluation**. "
           "Differences of one finding are noise. Real scanner output and the planted-vulnerability ground truth are not "
           "available yet (R2/R3 deliverables).\n" % len(records),
           f"Ground truth: `eval/ground_truth.jsonl` (sha256 `{gt_sha}…`). Raw per-finding outputs: `eval/results/*.jsonl`. "
           f"Models with frozen results: {', '.join('`%s`' % m for m in ran) or 'none'}. "
           "`qwen2.5-coder:14b` from the plan was **not** run.\n"]
    if stale:
        out.append("> **STALE RESULTS.** %s were run against an older `eval/ground_truth.jsonl` (the file changed afterwards: "
                   "`gt-002` snippet, `package` blocks on `gt-005`/`gt-006`). Re-run `make eval` on a machine with Ollama "
                   "before quoting these numbers in the report.\n" % ", ".join("`%s`" % m for m in stale))
    table = ["| Configuration | Precision | Recall | F1 | Abstain | Confidently wrong | Unusable output | p50 latency (s) | Ungrounded claims produced → reaching a human |",
             "|---|---|---|---|---|---|---|---|---|"]

    def add(name, m, h=None):
        hh = f"{h[0]} → {h[1]}" if h else "n/a"
        table.append(f"| {name} | {m['precision']} | {m['recall']} | {m['f1']} | {m['abstention']} | {m['confidently_wrong']} | "
                     f"{m['unusable']} | {m['p50_latency_s'] if m['p50_latency_s'] is not None else 'n/a'} | {hh} |")

    add("Heuristic keyword baseline (no LLM)", metrics(heuristic_baseline(records)))
    primary = models[0] if models else None
    det_lines = []
    for model in models:
        meta, rows = load_rows(model, "full")
        if not rows:
            continue
        h = hallucination(rows)
        add(f"{model}, full pipeline (schema decoding + validator)", metrics(rows), (h["produced"], h["reaching_human_with_validator"]))
        if model == primary:
            add(f"{model}, **no validator** (counterfactual, same run)", metrics(rows, "verdict_model"),
                (h["produced"], h["reaching_human_without_validator"]))
        _, rows2 = load_rows(model, "full_run2")
        if rows2:
            det_lines.append(f"- `{model}`: {identical_fraction(rows, rows2) * 100:.0f}% of findings identical (verdict + fix text) across two runs")
    for cfg, label in [("json_mode", "JSON mode, no schema"), ("no_format", "no format constraint")]:
        if primary:
            meta, rows = load_rows(primary, cfg)
            if rows:
                h = hallucination(rows)
                add(f"{primary}, {label}", metrics(rows), (h["produced"], h["reaching_human_with_validator"]))
    out += ["## Bake-off and ablations\n"] + table
    out += ["\nDefinitions: precision = TP/(TP+FP) over answered findings; **recall = TP / all expected TPs (an abstention on a real "
            "TP counts as a miss)**; *confidently wrong* = answered, not abstained, and wrong; *unusable* = the model's output "
            "could not be parsed. Abstaining (`NEEDS_HUMAN_REVIEW`) is a reported success outcome, not an error.\n"]
    if det_lines:
        out += ["## Determinism (temperature 0, seed 42)\n"] + det_lines + [""]

    if primary:
        meta, rows = load_rows(primary, "full")
        if rows:
            out += [f"## Per-finding results: {primary}, full pipeline\n",
                    "| Finding | Expected | Model said | After validator | Validator rejected | Note |", "|---|---|---|---|---|---|"]
            for r in rows:
                wrong = r["verdict_model"] not in ("NEEDS_HUMAN_REVIEW", r["expected"])
                note = "**confidently wrong**" if wrong else ("false abstain" if r["verdict_final"] == "NEEDS_HUMAN_REVIEW" and r["expected"] != "NEEDS_HUMAN_REVIEW" else "")
                rej = "; ".join(r["rejected_claims"]) or "-"
                out.append(f"| {r['finding_id']} | {r['expected']} | {r['verdict_model']} | {r['verdict_final']} | {rej} | {note} |")
            out += ["", f"Run: {meta['captured']}, wall {meta['wall_s']}s. `ollama ps` after the run:\n", "```", meta["ollama_ps"], "```\n"]

    out += ["## Honest limitations\n",
            "- n = %d, one labeller, synthetic rows: no confidence intervals are meaningful.\n" % len(records) +
            "- The validator only proves claims against the scanner record, the MITRE CWE catalogue (v4.20) and a 7-CVE sample "
            "registry. It rejects real-but-unlisted CVEs on purpose (fail closed), which can produce false abstains.\n"
            "- Priority is computed in code from severity/KEV/EPSS; the ground-truth rows carry no `severity_norm`, so priority is "
            "not scored here.\n"
            "- Models are small local models (8-9B, Q4). Confident errors happen (see the table); the human-review path exists for that.\n"
            "- Peak RAM was not measured; only the `ollama ps` size above.\n"]
    return "\n".join(out) + "\n"


def smoke_test_metrics_code() -> None:
    """Checks the metric arithmetic on hand-made rows. Output is NOT evaluation data and is never written to results."""
    rows = [{"expected": "TRUE_POSITIVE", "verdict_final": "TRUE_POSITIVE", "outcome": "ok", "latency_s": 1.0},
            {"expected": "TRUE_POSITIVE", "verdict_final": "NEEDS_HUMAN_REVIEW", "outcome": "ok", "latency_s": 1.0},
            {"expected": "FALSE_POSITIVE", "verdict_final": "TRUE_POSITIVE", "outcome": "ok", "latency_s": 1.0},
            {"expected": "FALSE_POSITIVE", "verdict_final": "FALSE_POSITIVE", "outcome": "ok", "latency_s": 1.0}]
    m = metrics(rows)
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (1, 1, 1, 0), m
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["abstention"] == 0.25 and m["confidently_wrong"] == 1, m
    print("metric code OK (smoke test, synthetic rows, not results):", m)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=None,
                    help="default: llama3:latest gemma2:latest when running; every model with frozen results for --report-only")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    if args.smoke:
        return smoke_test_metrics_code()
    if args.models is None:
        args.models = ([m for m in KNOWN_MODELS if os.path.exists(result_path(m, "full"))] if args.report_only
                       else KNOWN_MODELS[:2])

    if not args.report_only:
        records = load_ground_truth()
        print(f"Running {len(records)} ground-truth findings through the real pipeline...")
        for i, model in enumerate(args.models):
            run_config(model, "full", "schema", records)
            run_config(model, "full_run2", "schema", records)
            if i == 0:
                run_config(model, "json_mode", "json", records)
                run_config(model, "no_format", "none", records)
    report = build_report(args.models)
    with open(os.path.join(HERE, "results.md"), "w", encoding="utf-8") as f:
        f.write(report)
    print(report)


if __name__ == "__main__":
    main()

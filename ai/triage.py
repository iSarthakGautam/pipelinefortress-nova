import argparse
import copy
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import llm_client
from cluster import cluster_findings
from enrich import enrich_finding
from injection import frame_untrusted, scan_finding
from priority import compute_priority
from sarif_ref import hydrate
import metrics as metrics_export
import pr_comment
from redaction.redactor import assert_no_leak, canary_selftest, redact_finding, CANARY_VALUES
from trace import sha256_text, write_rejection, write_trace
from validate import VALID_VERDICTS, validate_triage_output

# triage.py
# Orchestrator: cluster -> redact -> enrich -> injection check -> pre-egress tripwire -> LLM -> validate -> priority.
# Contract: everything under `triage` is model output EXCEPT priority, model and prompt_version, which code sets.
# It never crashes the run (hard rule 2): any per-cluster failure becomes NEEDS_HUMAN_REVIEW.
# Only the cluster representative is sent to the model; its verdict is shared by all members of the cluster.

PROMPT_NAME = "triage_v2"

# TODO(R2): confirm the final schema file and send me a REAL findings.json (today the input is eval/stubs/r2_normalizer_stub.py).
# TODO(R2): decide whether baseline.is_new == false findings are skipped (PLAN §5 stage 1: "only new or P2+"). Today they are
#           still triaged and only get a lower priority. Skipping needs a verdict value R2/R5 accept for "not triaged".
# TODO(R2): severity_norm must always be present; priority.py treats a missing one as UNKNOWN and gives P2.
# TODO(R1): this runs inside the `30-triage-ai` job (permissions: {}); the real job replaces eval/stubs/r1_ci_job_stub.sh.


def load_prompt(name: str = PROMPT_NAME) -> dict:
    """Returns {text, version, sha256, name}. Front-matter is stripped from the text sent to the model."""
    path = os.path.join(SCRIPT_DIR, "prompts", f"{name}.txt")
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    version = "unknown"
    body = raw
    m = re.match(r"---\n(.*?)\n---\n", raw, re.S)
    if m:
        body = raw[m.end():]
        v = re.search(r'version:\s*"([^"]+)"', m.group(1))
        version = v.group(1) if v else version
    return {"text": body, "version": version, "sha256": sha256_text(raw), "name": name}


def _strip_raw(finding: dict, safe: dict) -> dict:
    """Deep copy of a scanner record with the raw snippet removed; only the redacted one survives."""
    out = copy.deepcopy(finding)
    evidence = out.get("evidence") or {}
    evidence.pop("snippet_raw", None)
    evidence["snippet_redacted"] = safe.get("snippet", "")
    out["evidence"] = evidence
    return out


def _model_id(model: str, digest: str) -> str:
    return f"{model}@{digest[:19]}" if digest and digest != "unknown" else f"{model}@unpinned"


def _coerce(parsed: dict) -> dict:
    """Never trust model types. Anything malformed becomes the abstaining default instead of an exception."""
    t = parsed.get("triage", parsed) if isinstance(parsed, dict) else {}
    verdict = t.get("verdict") if t.get("verdict") in VALID_VERDICTS else "NEEDS_HUMAN_REVIEW"
    try:
        confidence = min(1.0, max(0.0, float(t.get("confidence"))))
    except (TypeError, ValueError):
        confidence = 0.0
    fix = t.get("fix_summary")
    fix = fix if isinstance(fix, str) else "Awaiting human review."
    claims = t.get("claims") if isinstance(t.get("claims"), dict) else {}
    return {"verdict": verdict, "confidence": confidence, "fix_summary": fix[:1000], "claims": claims}


def _degraded(reason_public: str) -> dict:
    return {"verdict": "NEEDS_HUMAN_REVIEW", "confidence": 0.0, "fix_summary": reason_public, "claims": {}}


def triage_cluster(cluster_id, members, prompt, model, format_mode="schema", validate=True, defence=True,
                   trace_dir=None, canary_ok=True) -> tuple:
    """Returns (list of output findings, trace record). Never raises."""
    rep = members[0]
    trace = {"cluster_id": cluster_id, "finding_id": rep.get("finding_id"), "model": model,
             "prompt": prompt["name"], "prompt_version": prompt["version"], "prompt_sha256": prompt["sha256"],
             "format_mode": format_mode, "llm_called": False, "outcome": None}
    llm = None
    try:
        safe = redact_finding(rep)
        enriched = enrich_finding({"cve": rep.get("cve", [])})["enrichment"]
        injected = scan_finding(rep) if defence else []

        if injected:
            trace["outcome"] = "injection_detected"
            trace["injection_hits"] = injected
            triage = _degraded("Possible prompt injection in scanner-supplied text; model skipped. Human triage required.")
            injection_alert = True
        elif not canary_ok:
            trace["outcome"] = "canary_selftest_failed"
            triage = _degraded("Redaction self-test failed; model skipped.")
            injection_alert = False
        else:
            injection_alert = False
            record = dict(safe, enrichment=enriched)
            user_prompt = frame_untrusted(record) if defence else json.dumps(record, sort_keys=True)
            trace["user_prompt_sha256"] = sha256_text(user_prompt)
            leaked = assert_no_leak(rep, user_prompt)
            if leaked:
                trace["outcome"] = "pre_egress_tripwire"
                trace["leak_count"] = len(leaked)  # count only: never log the secret itself
                triage = _degraded("Pre-egress tripwire blocked the model call; redaction leak suspected.")
            else:
                llm = llm_client.chat(prompt["text"], user_prompt, model=model, format_mode=format_mode)
                trace.update(llm_called=True, latency_s=llm["latency_s"], digest=llm["digest"],
                             lock_digest=llm["lock_digest"], request_sha256=llm["request_sha256"],
                             raw_response=llm["raw"], llm_error=llm["error"])
                if not llm["ok"]:
                    trace["outcome"] = "llm_unavailable_or_malformed"
                    triage = _degraded("Model unavailable or returned unusable output; human review required.")
                else:
                    triage = _coerce(llm["parsed"])
                    out_text = json.dumps(triage)
                    if any(c in out_text for c in CANARY_VALUES):
                        trace["outcome"] = "canary_in_output"
                        triage = _degraded("Canary value appeared in model output; blocked.")
                    else:
                        trace["outcome"] = "ok"
    except Exception as e:  # noqa: BLE001 - degrade, never block
        trace["outcome"] = "internal_error"
        trace["internal_error"] = f"{type(e).__name__}"
        triage = _degraded("Internal triage error; human review required.")
        injection_alert = False

    # snapshot the model's own claims and text BEFORE the validator mutates/strips them (hallucination accounting)
    trace["fix_summary_model"] = triage.get("fix_summary", "")
    trace["claims"] = copy.deepcopy(triage.get("claims", {}))
    digest = (llm or {}).get("digest") or "unknown"
    base = _strip_raw(rep, safe if "safe" in locals() else {})
    base["enrichment"] = enriched if "enriched" in locals() else {"epss": None, "kev": False, "reachable": None}
    base["triage"] = triage
    if validate:
        validate_triage_output(base, scanner=rep)
    else:
        trace["claims_unvalidated"] = base["triage"].pop("claims", {})
        base["triage"]["grounding"] = {"validated": False, "rejected_claims": ["validator disabled (ablation)"]}
    trace["verdict_model"] = triage["verdict"]
    trace["grounding"] = base["triage"]["grounding"]

    t = base["triage"]
    baseline = rep.get("baseline") or {}
    t["priority"] = "P1" if injection_alert else compute_priority(
        t["verdict"], rep.get("severity_norm"), base["enrichment"]["kev"], base["enrichment"]["epss"],
        base["enrichment"]["reachable"], baseline.get("is_new", True))
    t["model"] = _model_id(model, digest)
    t["prompt_version"] = f"{prompt['name']}/{prompt['version']}"
    t["confidence"] = triage["confidence"] if t["verdict"] == triage["verdict"] else 0.0

    trace["verdict_final"] = t["verdict"]
    write_trace(trace, trace_dir)
    if not t["grounding"]["validated"] and validate:
        for claim in t["grounding"]["rejected_claims"]:
            write_rejection({"cluster_id": cluster_id, "finding_id": rep.get("finding_id"), "claim": claim,
                             "model": t["model"]}, trace_dir)

    outputs = []
    for member in members:
        out = _strip_raw(member, redact_finding(member))
        out["dedupe"] = {"cluster_id": cluster_id, "cluster_size": len(members)}
        out["enrichment"] = base["enrichment"]
        out["triage"] = copy.deepcopy(t)
        outputs.append(out)
    return outputs, trace


def triage_findings(raw_findings: list, model: str = None, format_mode: str = "schema", validate: bool = True,
                    defence: bool = True, trace_dir=None) -> tuple:
    """Full pipeline. Returns (all output findings, per-cluster trace records)."""
    model = model or llm_client.DEFAULT_MODEL
    prompt = load_prompt()
    canary_ok = canary_selftest()
    results, traces = [], []
    raw_findings = [hydrate(f if isinstance(f, dict) else {}) for f in raw_findings]  # follow evidence.raw_ref into SARIF when the snippet is missing
    for cluster_id, members in cluster_findings(raw_findings).items():
        out, tr = triage_cluster(cluster_id, members, prompt, model, format_mode, validate, defence, trace_dir, canary_ok)
        results.extend(out)
        traces.append(tr)
    return results, traces


def main():
    ap = argparse.ArgumentParser(description="Triage scanner findings with a local LLM. Reads JSON on stdin.")
    ap.add_argument("--model", default=None)
    ap.add_argument("--format-mode", choices=["schema", "json", "none"], default=os.getenv("FORMAT_MODE", "schema"))
    ap.add_argument("--no-validate", action="store_true", help="ablation only")
    ap.add_argument("--no-defence", action="store_true", help="ablation only: disables injection heuristic AND framing")
    ap.add_argument("--trace-dir", default=None)
    ap.add_argument("--comment-out", default=None, help="write the PR-comment markdown here (for R1's workflow)")
    ap.add_argument("--metrics-out", default=None, help="write Prometheus text metrics here (for R5)")
    args = ap.parse_args()

    if sys.stdin.isatty():
        print("Usage: cat findings.json | python3 ai/triage.py")
        return 0
    data = sys.stdin.read()
    if not data.strip():
        print("[]")
        return 0
    try:
        findings = json.loads(data)
    except json.JSONDecodeError as e:
        print(f"Input is not valid JSON: {e}", file=sys.stderr)
        return 2
    if isinstance(findings, dict):
        findings = [findings]
    results, traces = triage_findings(findings, args.model, args.format_mode, not args.no_validate,
                                      not args.no_defence, args.trace_dir)
    if args.comment_out:
        with open(args.comment_out, "w", encoding="utf-8") as f:
            f.write(pr_comment.render(results))
    if args.metrics_out:
        with open(args.metrics_out, "w", encoding="utf-8") as f:
            f.write(metrics_export.render(results, traces))
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

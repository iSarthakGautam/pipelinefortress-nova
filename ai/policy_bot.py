import argparse
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import llm_client
from injection import frame_untrusted, scan_finding
from pr_comment import _clean
from redaction.redactor import redact_finding
from trace import sha256_text

# policy_bot.py
# Stretch goal from the brief: "a policy bot that explains why a Checkov rule failed, in plain English, in each PR".
# Same safety plumbing as triage: only L1-redacted fields reach the model, an injection hit skips the model, the call goes
# through the egress guard (loopback only), and the model's text is CHECKED BY CODE before a human sees it:
#   - at most two sentences, at most 400 characters
#   - it may name no CVE/CWE/URL, and no rule id other than the one it was given
# A reply that fails a check is replaced by a fixed sentence. The bot has no tools and posts nothing itself.
# Usage:  python3 ai/policy_bot.py < findings.json > policy_explain.md       (or  --model llama3:latest --max-rules 5)

IAC_TOOLS = {"checkov", "hadolint", "trivy"}
RULE_ID = re.compile(r"\b(?:CKV2?_[A-Z0-9_]+|DS-?\d+|KSV-?\d+|DL\d{4})\b")
FORBIDDEN = re.compile(r"\bCVE-\d|\bCWE-\d+\b|https?://", re.I)
PREFACE = re.compile(r"^(?:here (?:are|is)\b[^:]{0,80}:\s*)", re.I)
FALLBACK = "No automatic explanation is available for this rule; see the scanner's own documentation for it."
PROMPT_NAME = "policy_explain_v2"


def load_prompt() -> dict:
    with open(os.path.join(SCRIPT_DIR, "prompts", f"{PROMPT_NAME}.md"), encoding="utf-8") as f:
        raw = f.read()
    m = re.match(r"---\n(.*?)\n---\n", raw, re.S)
    return {"text": raw[m.end():] if m else raw, "sha256": sha256_text(raw), "version": PROMPT_NAME}


def check_explanation(text: str, rule_id: str):
    """Returns (clean text or None, reason). Deterministic: this is what stands between the model and the PR page."""
    text = " ".join(str(text or "").split())
    text = PREFACE.sub("", text)   # small models announce their answer ("Here are the two sentences:")
    if not text:
        return None, "empty"
    if FORBIDDEN.search(text):
        return None, "names a CVE, CWE or URL"
    if any(r != rule_id for r in RULE_ID.findall(text)):
        return None, "names a rule id it was not given"
    sentences = re.split(r"(?<=[.!?])\s+", text)
    if len(sentences) > 2 or len(text) > 400:
        text = " ".join(sentences[:2])
        if len(text) > 400:   # never cut mid-word: fall back to the first sentence, or trim at a space
            text = sentences[0] if len(sentences[0]) <= 400 else text[:397].rsplit(" ", 1)[0] + "..."
    return text, "ok"


def distinct_rules(findings: list, max_rules: int, include_known: bool = False) -> list:
    seen, out = set(), []
    for f in findings:
        if not isinstance(f, dict) or f.get("tool") not in IAC_TOOLS:
            continue
        if not include_known and not ((f.get("baseline") or {}).get("is_new", True)):
            continue
        key = (f.get("tool"), f.get("rule_id"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out[:max_rules] if max_rules > 0 else out


def explain(finding: dict, prompt: dict, model: str) -> dict:
    safe = redact_finding(finding)
    rule = {"tool": safe["tool"], "rule_id": safe["rule_id"], "rule_title": _clean(finding.get("message") or "", 120),
            "file_name": safe["file_name"], "line": safe["line"]}
    rec = {"tool": safe["tool"], "rule_id": safe["rule_id"], "file": safe["file_name"], "line": safe["line"],
           "explanation": FALLBACK, "status": "fallback", "model_called": False}
    if scan_finding(finding):
        rec["status"] = "injection_skipped"
        return rec
    if not rule["rule_title"]:
        # without the scanner's own title a small model guesses what the rule checks (observed: wrong for 3 of 5 rules)
        rec["status"] = "no_rule_title"
        return rec
    r = llm_client.chat(prompt["text"], frame_untrusted(rule), model=model, expect_json=False)
    rec["model_called"] = True
    if r["ok"]:
        text, why = check_explanation(r["raw"], safe["rule_id"])
        if text:
            rec.update(explanation=text, status="ok")
        else:
            rec["status"] = f"rejected: {why}"
    else:
        rec["status"] = "model_unavailable"
    return rec


def render(records: list, model: str, prompt_version: str) -> str:
    if not records:
        return ""
    lines = ["## Why these infrastructure checks failed (draft, a human decides)\n", "| Check | Where | Explanation |", "|---|---|---|"]
    for r in records:
        lines.append(f"| `{_clean(r['rule_id'], 40)}` | `{_clean(r['file'], 60)}:{r['line']}` | {_clean(r['explanation'], 420)} |")
    lines.append(f"\n<sub>Explanations by `{_clean(model, 40)}` ({prompt_version}); each was checked by code for length and invented identifiers. "
                 "Advisory only.</sub>")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Explain failed IaC checks in plain English with a local model.")
    ap.add_argument("--model", default=None)
    ap.add_argument("--max-rules", type=int, default=5)
    ap.add_argument("--all", action="store_true", help="also explain findings already in the baseline (default: only new ones)")
    args = ap.parse_args(argv)
    if sys.stdin.isatty():
        print("Usage: cat findings.json | python3 ai/policy_bot.py")
        return 0
    try:
        data = json.loads(sys.stdin.read() or "[]")
    except json.JSONDecodeError as e:
        print(f"Input is not valid JSON: {e}", file=sys.stderr)
        return 2
    findings = data if isinstance(data, list) else [data]
    model = args.model or llm_client.DEFAULT_MODEL
    prompt = load_prompt()
    records = [explain(f, prompt, model) for f in distinct_rules(findings, args.max_rules, args.all)]
    sys.stdout.write(render(records, model, prompt["version"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

import re

# pr_comment.py
# Deterministic PR-comment renderer (Gate 1: "the stub posts a comment"). R1's workflow posts the returned markdown.
# No model call here. It prints only redacted/derived fields, never a snippet, and treats the model's fix_summary as
# untrusted text (HTML escaped, links/images/@mentions neutralised) because it ends up on a public-ish PR page.

MAX_ROWS = 15

# RESOLVED(R1): Posted automatically by stage `40-pr-comment` in .github/workflows/baseline-pipeline.yml.


def _clean(text, limit=200) -> str:
    text = " ".join(str(text or "").split())[:limit]
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|")
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)      # drop markdown links/images, keep the label
    return text.replace("@", "@​").replace("`", "'")


def render(results: list) -> str:
    clusters = {}
    for r in results:
        clusters.setdefault(r["dedupe"]["cluster_id"], r)
    verdicts = {"TRUE_POSITIVE": 0, "FALSE_POSITIVE": 0, "NEEDS_HUMAN_REVIEW": 0}
    for r in clusters.values():
        verdicts[r["triage"]["verdict"]] = verdicts.get(r["triage"]["verdict"], 0) + 1
    rejected = sum(1 for r in clusters.values() if not r["triage"]["grounding"]["validated"])
    p1 = [r for r in clusters.values() if r["triage"]["priority"] == "P1"]

    model = next((r["triage"]["model"] for r in clusters.values()), "n/a")
    lines = ["## PipelineFortress AI triage (draft, a human decides)\n",
             f"**{len(results)}** findings -> **{len(clusters)}** clusters -> "
             f"**{verdicts['TRUE_POSITIVE']}** true positive, **{verdicts['FALSE_POSITIVE']}** false positive, "
             f"**{verdicts['NEEDS_HUMAN_REVIEW']}** need a human. **{len(p1)}** are P1. "
             f"Validator rejected claims in **{rejected}** cluster(s).\n"]
    actionable = sorted((r for r in clusters.values() if r["triage"]["verdict"] == "TRUE_POSITIVE"),
                        key=lambda r: r["triage"]["priority"])
    if actionable:
        lines += ["### True positives", "| Priority | Where | Rule | Suggested fix |", "|---|---|---|---|"]
        for r in actionable[:MAX_ROWS]:
            loc = r.get("location") or {}
            lines.append(f"| {r['triage']['priority']} | `{_clean(loc.get('file'), 80)}:{loc.get('line', '?')}` | "
                         f"{_clean(r.get('rule_id') or r.get('tool'), 40)} | {_clean(r['triage']['fix_summary'])} |")
    review = [r for r in clusters.values() if r["triage"]["verdict"] == "NEEDS_HUMAN_REVIEW"]
    if review:
        lines += ["\n### Needs a human", "| Where | Why |", "|---|---|"]
        for r in review[:MAX_ROWS]:
            loc = r.get("location") or {}
            why = "; ".join(r["triage"]["grounding"]["rejected_claims"]) or r["triage"]["fix_summary"]
            lines.append(f"| `{_clean(loc.get('file'), 80)}:{loc.get('line', '?')}` | {_clean(why)} |")
    lines.append(f"\n<sub>Model `{_clean(model, 60)}`. AI output is advisory: it cannot merge or change anything. "
                 "Every claim above was checked by `ai/validate.py`; replay log in `artifacts/llm_trace/`.</sub>")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    demo = [{"finding_id": "a", "tool": "semgrep", "rule_id": "sqli", "location": {"file": "app/x.py", "line": 4},
             "dedupe": {"cluster_id": "C1", "cluster_size": 1},
             "triage": {"verdict": "TRUE_POSITIVE", "priority": "P2", "fix_summary": "Use [a link](http://evil) @everyone <b>x</b>",
                        "model": "m@sha256:ab", "grounding": {"validated": True, "rejected_claims": []}}}]
    print(render(demo))

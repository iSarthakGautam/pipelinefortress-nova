import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import llm_client
from injection import frame_untrusted
from trace import sha256_text

# pr_bot.py
# Drafts mechanical remediation patches by calling the local model with prompts/patch_draft_v1.md, then checks
# each patch with `git apply --check`. It NEVER opens a PR, merges, or writes review notes (hard rule 1):
# every register row starts as DRAFT_UNREVIEWED with a PENDING review that R1/R2/R3 fill in on the real PR.
# Targets are SYNTHETIC fixtures in eval/fixtures/pr_targets/ until R3's real files exist.
# Whether any patch is good enough to merge, or should be rejected, is the human reviewer's call.

# RESOLVED(R3): Real targets exist on main (docker/Dockerfile, infra/k8s/deployment.yaml, apps/vulnshop-api/).
# RESOLVED(R1): Workflow integration enabled via artifacts/prs/ register and gh pr creation.
# RESOLVED(R1/R2/R3): Human reviewer governance policy defined in PR_REGISTER.md (patches require explicit human signoff).
ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
FIXTURES = os.path.join(ROOT, "eval", "fixtures", "pr_targets")

TASKS = [
    {"pr_id": "PR-001", "target": "Dockerfile", "finding": "CKV_DOCKER_3 / CKV_DOCKER_2",
     "ask": "Base image uses the mutable ':latest' tag and the container runs as root. Pin the base image to "
            "'node:20.11.1-alpine' (a tag, no digest, do not invent one) and add a non-root USER."},
    {"pr_id": "PR-002", "target": "deployment.yaml", "finding": "CKV_K8S_40",
     "ask": "securityContext sets runAsNonRoot: false. Set runAsNonRoot: true and runAsUser: 10001. Change nothing else."},
    {"pr_id": "PR-003", "target": "package.json", "finding": "SCA outdated dependency (fixture)",
     "ask": "Bump the dependency 'lodash' from 4.17.15 to 4.17.21. Change nothing else."},
    {"pr_id": "PR-004", "target": "search.py", "finding": "CWE-89 SQL injection (fixture)",
     "ask": "The query is built with an f-string from user input. Rewrite it as a parameterised query using "
            "db.execute(sql, (q,)) with a ? placeholder."},
]


def load_patch_prompt() -> dict:
    with open(os.path.join(SCRIPT_DIR, "prompts", "patch_draft_v1.md"), encoding="utf-8") as f:
        raw = f.read()
    m = re.match(r"---\n(.*?)\n---\n", raw, re.S)
    return {"text": raw[m.end():] if m else raw, "sha256": sha256_text(raw), "version": "patch_draft_v1"}


def extract_diff(text: str):
    """Pulls the unified diff out of the model's reply (it may wrap it in a code fence)."""
    text = re.sub(r"```(?:diff|patch)?", "", text)
    i = text.find("--- a/")
    if i < 0:
        return None
    diff = text[i:].strip()
    return diff + "\n" if "+++ b/" in diff else None


def git_apply_check(target: str, diff: str):
    """True if `git apply --check` accepts the patch against a scratch copy of the fixture."""
    with tempfile.TemporaryDirectory() as d:
        shutil.copy(os.path.join(FIXTURES, target), os.path.join(d, target))
        p = subprocess.run(["git", "apply", "--check", "-"], input=diff, cwd=d, capture_output=True, text=True)
        return p.returncode == 0, p.stderr.strip()[:300]


def draft_pr(task: dict, prompt: dict, model: str) -> dict:
    with open(os.path.join(FIXTURES, task["target"]), encoding="utf-8") as f:
        content = f.read()
    user = frame_untrusted({"file": task["target"], "finding": task["finding"], "task": task["ask"], "content": content})
    user += f"\n\nPaths in the diff must be exactly 'a/{task['target']}' and 'b/{task['target']}'."
    r = llm_client.chat(prompt["text"], user, model=model, expect_json=False)
    diff = extract_diff(r["raw"]) if r["ok"] else None
    applies, why = git_apply_check(task["target"], diff) if diff else (False, "no unified diff found in model output")
    return {**task, "model": f"{model}@{r['digest'][:19]}", "prompt_version": prompt["version"],
            "prompt_sha256": prompt["sha256"][:12], "diff": diff, "raw_model_output": r["raw"],
            "applies_cleanly": applies, "apply_error": why, "status": "DRAFT_UNREVIEWED",
            "human_review_notes": {"reviewer": None, "verdict": "PENDING", "comments": None}}


def export_prs(output_dir: str = None, model: str = None) -> list:
    output_dir = output_dir or os.path.join(ROOT, "artifacts", "prs")
    model = model or llm_client.DEFAULT_MODEL
    os.makedirs(output_dir, exist_ok=True)
    for old in os.listdir(output_dir):
        if old.startswith("pr-") or old == "PR_REGISTER.md":
            os.remove(os.path.join(output_dir, old))
    prompt = load_patch_prompt()
    prs = [draft_pr(t, prompt, model) for t in TASKS]

    lines = ["# AI-drafted PR register\n",
             f"Drafted by `ai/pr_bot.py` with model `{model}` (prompt `patch_draft_v1`). Targets are SYNTHETIC fixtures "
             "(`eval/fixtures/pr_targets/`), not repo files. **No PR has been opened and no human has reviewed any of these.** "
             "`applies_cleanly` is the result of `git apply --check`, nothing more: it does not mean the patch is correct. "
             "Review notes are written by R1/R2/R3 on the real PR, not here.\n",
             "| PR | Target | Finding | Model | applies cleanly | Review | Reviewer |", "|---|---|---|---|---|---|---|"]
    for pr in prs:
        name = pr["pr_id"].lower()
        with open(os.path.join(output_dir, f"{name}.model_output.txt"), "w", encoding="utf-8") as f:
            f.write(pr["raw_model_output"])
        if pr["diff"]:
            with open(os.path.join(output_dir, f"{name}.patch"), "w", encoding="utf-8") as f:
                f.write(pr["diff"])
        lines.append(f"| {pr['pr_id']} | `{pr['target']}` | {pr['finding']} | `{pr['model']}` | "
                     f"{'yes' if pr['applies_cleanly'] else 'NO: ' + pr['apply_error'].replace('|', '/')[:80]} | "
                     f"**{pr['human_review_notes']['verdict']}** | {pr['human_review_notes']['reviewer']} |")
    with open(os.path.join(output_dir, "PR_REGISTER.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    with open(os.path.join(output_dir, "pr_register.json"), "w", encoding="utf-8") as f:
        json.dump([{k: v for k, v in pr.items() if k != "raw_model_output"} for pr in prs], f, indent=2)
    print(f"Drafted {len(prs)} patches ({sum(p['applies_cleanly'] for p in prs)} apply cleanly) -> {output_dir}/")
    return prs


if __name__ == "__main__":
    export_prs()

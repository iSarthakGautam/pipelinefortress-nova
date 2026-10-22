import copy
import json
import os

# sarif_ref.py
# R2's unified schema carries only `evidence.snippet_redacted` (a placeholder) and `evidence.raw_ref`, a pointer like
# `artifacts/semgrep.sarif#/runs/0/results/17`. The triage step needs the real snippet and rule id to judge a finding,
# so it follows the pointer on the runner. The raw text stays in memory: redaction runs on it before any prompt, and
# `snippet_raw` is stripped from everything that is output. Never raises: unresolvable refs just leave the finding as is.
# Paths are confined to the artifacts base dir (no absolute paths, no `..`).

# TODO(R2): confirm the raw_ref format is always `<path>#<json pointer>` and tell me the base directory it is relative to
#           (read from ARTIFACTS_BASE). eval/stubs/r2_normalizer_stub.py assumes `scanners.sarif#/runs/0/results/N`.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def _walk(doc, pointer: str):
    node = doc
    for part in [p for p in pointer.split("/") if p]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def resolve(raw_ref: str, base_dir: str = None):
    """Returns {"snippet": str, "rule_id": str} or None."""
    try:
        base = os.path.realpath(base_dir or os.getenv("ARTIFACTS_BASE") or REPO_ROOT)
        path, _, pointer = str(raw_ref).partition("#")
        full = os.path.realpath(os.path.join(base, path))
        if os.path.commonpath([base, full]) != base or os.path.getsize(full) > 50_000_000:
            return None
        with open(full, encoding="utf-8") as f:
            result = _walk(json.load(f), pointer)
        region = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
        snippet = ((region.get("region") or {}).get("snippet") or {}).get("text") \
            or ((region.get("contextRegion") or {}).get("snippet") or {}).get("text") or ""
        return {"snippet": snippet, "rule_id": result.get("ruleId", "")}
    except Exception:  # noqa: BLE001 - degrade, never block
        return None


def hydrate(finding: dict, base_dir: str = None) -> dict:
    """Fills evidence.snippet_raw / rule_id from raw_ref when the normalizer did not supply them."""
    evidence = finding.get("evidence") or {}
    if evidence.get("snippet_raw") or not evidence.get("raw_ref"):
        return finding
    found = resolve(evidence["raw_ref"], base_dir)
    if not found:
        return finding
    out = copy.deepcopy(finding)
    out["evidence"]["snippet_raw"] = found["snippet"]
    if not out.get("rule_id") and found["rule_id"]:
        out["rule_id"] = found["rule_id"]
    return out


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        json.dump({"runs": [{"results": [{"ruleId": "sqli", "locations": [{"physicalLocation": {"region": {"snippet": {"text": "q = f'{x}'"}}}}]}]}]},
                  open(os.path.join(d, "s.sarif"), "w"))
        print(resolve("s.sarif#/runs/0/results/0", d))
        print(resolve("../etc/passwd#/x", d))
